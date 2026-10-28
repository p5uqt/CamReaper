"""Standalone gallery builder: capture frames for a list of RTSP URLs and emit
an index.html gallery (click-to-copy, double-click fullscreen).

Used by two CLI flags:
  * ``--scan-channels`` — after a scan, re-capture every channel of every
    confirmed stream;
  * ``--gallery-html``   — same output but from a user-supplied file of
    ``rtsp://`` URLs, without scanning at all.
"""

import asyncio
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

from CamReaper import report, screenshot
from CamReaper.rtsp import RTSPClient
from CamReaper.scanner import probe_all_routes

# Hikvision expands /Streaming/Channels/101/ to channels 101..1601.
_CHANNELS_MARKER = "/Streaming/Channels/101/"
# Common Dahua/ONVIF devices expose up to 8 physical channels.
_MAX_DAHUA_CH = 8

_RE_DAHUA_CH = re.compile(r"/h264/ch(\d+)/main/av_stream")
_RE_ONVIF_CH = re.compile(r"channel=(\d+)")
# The subtype that a variant fills in, so an existing one has to be cut out of
# the tail first - otherwise every variant is "?channel=N&subtype=0&subtype=1".
_RE_SUBTYPE = re.compile(r"&?subtype=\d+")
# A route/URL is ONVIF when it carries a channel/subtype parameter or a
# realmonitor/.sdp path.  Probing is kept ONVIF-scoped, so non-ONVIF cameras
# never pick up unrelated route aliases (which was causing duplicate shots).
_RE_ONVIF_ROUTE = re.compile(r"channel\s*=|subtype\s*=|/realmonitor|stream=[\d.]+\.sdp")

_DEFAULT_PORT = 554


def _split_url(url: str):
    """Parse ``rtsp://[user:pass@]host[:port]/route``.

    Returns ``(host, port, creds, route)``.  ``creds`` is ``"user:pass"`` when
    present (``"user:"`` for a username without a password), else ``":"`` (no
    auth).  ``port`` defaults to 554, ``route`` to ``/``.
    """
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        try:
            port = parts.port or _DEFAULT_PORT
        except ValueError:
            port = _DEFAULT_PORT
        if parts.username:
            user = unquote(parts.username)
            password = unquote(parts.password) if parts.password is not None else ""
            creds = f"{user}:{password}"
        else:
            creds = ":"
        route = parts.path or "/"
        if parts.query:
            route = f"{route}?{parts.query}"
        if host:
            return host, port, creds, route
    except ValueError:
        pass

    # Fallback for malformed authorities urlsplit refuses.
    s = url[len("rtsp://"):] if url.lower().startswith("rtsp://") else url
    authority, sep, route = s.partition("/")
    route = "/" + route if sep else "/"
    userinfo = ""
    if "@" in authority:
        userinfo, _, authority = authority.partition("@")
    if authority.startswith("["):
        host, _, tail = authority.partition("]")
        host = host[1:]
        port_s = tail.lstrip(":")
    else:
        host, _, port_s = authority.partition(":")
    port = int(port_s) if port_s.isdigit() else _DEFAULT_PORT
    if userinfo:
        creds = unquote(userinfo) if ":" in userinfo else f"{unquote(userinfo)}:"
    else:
        creds = ":"
    return host, port, creds, route


async def _probe_host_routes(host, port, creds, routes, route_parallel):
    """Probe ``routes`` on one camera; return the list of open routes."""
    client = RTSPClient(host, port, 2.0, creds)
    try:
        return await probe_all_routes(client, routes, creds, route_parallel)
    finally:
        # probe_all_routes works off the coordinates only, but the client still
        # owns a socket: never leave it dangling per camera.
        client.close()


async def build_probed_urls(urls, routes, route_parallel: int = 0):
    """Return every candidate RTSP URL to capture for the confirmed streams.

    Combines two sources per camera and de-duplicates:

      * pattern-expanded variants of each recorded URL (`channel_variants`), and
      * ONVIF routes from ``routes`` that probe open on that camera, so channels
        of more than one physical cam (including bare-rooted ONVIF boxes) are
        still discovered.

    Routes that answer 200 but are *not* ONVIF-style (``channel=``/``subtype=``/
    ``realmonitor``/``.sdp``) are dropped, so non-ONVIF cameras only ever yield
    their own recorded URL(s) — no more duplicate screenshots from unrelated
    route aliases.

    Returns a de-duplicated, sorted list of full ``rtsp://`` URLs.
    """
    cands: dict = {}  # (host,port) -> set[url]
    host_creds: dict = {}  # (host,port) -> set[creds]

    def url_for(host, port, creds, route):
        prefix = f"{creds}@" if creds != ":" else ""
        h = f"[{host}]" if ":" in host and not host.startswith("[") else host
        return f"rtsp://{prefix}{h}:{port}{route}"

    for u in urls:
        try:
            host, port, creds, _ = _split_url(u)
        except Exception:
            continue
        k = (host, port)
        host_creds.setdefault(k, set()).add(creds)
        cands.setdefault(k, set()).update(channel_variants(u))

    if routes:
        # Probe cameras concurrently: a large scan can have thousands of
        # confirmed streams, and doing one host after another made the
        # post-scan channel pass take hours.  Each camera's routes are still
        # probed with the caller's route_parallel.
        async def _probe_camera(key, creds_set):
            host, port = key
            opened: set = set()
            for creds in creds_set:
                try:
                    for route in await _probe_host_routes(
                        host, port, creds, routes, route_parallel
                    ):
                        if _RE_ONVIF_ROUTE.search(route):
                            opened.add((creds, route))
                except Exception:
                    continue
            for creds, route in opened:
                cands[(host, port)].add(url_for(host, port, creds, route))

        sem = asyncio.Semaphore(8)

        async def _guarded(key, creds_set):
            async with sem:
                await _probe_camera(key, creds_set)

        await asyncio.gather(
            *(_guarded(k, v) for k, v in host_creds.items()),
            return_exceptions=True,
        )

    flat = {u for urls in cands.values() for u in urls}
    return sorted(flat)


def channel_variants(url: str):
    """Yield the concrete RTSP URLs to capture for one stream.

    Recognised multi-channel formats are expanded; anything else is captured
    as-is (a single stream URL):

      * Hikvision  ``/Streaming/Channels/101/``  -> channels 101..1601
      * Dahua      ``/h264/ch1/main/av_stream``  -> ch1..ch8
      * ONVIF      ``?channel=1&subtype=0``      -> channel 1..8, sub 0..1
    """
    if _CHANNELS_MARKER in url:
        for i in range(1, 17):
            yield url.replace(_CHANNELS_MARKER, f"/Streaming/Channels/{i}01/")
        return

    m = _RE_DAHUA_CH.search(url)
    if m:
        # .../h264/ch1/main/av_stream  ->  .../h264/chN/main/av_stream
        for n in range(1, _MAX_DAHUA_CH + 1):
            yield url.replace(m.group(0), f"/h264/ch{n}/main/av_stream")
        return

    m = _RE_ONVIF_CH.search(url)
    if m:
        # ?channel=N&subtype=T  ->  channel 1..8 x subtype 0..1 (main+sub)
        start, end = m.start(), m.end()  # the "channel=N" span
        prefix = url[:start]
        # Drop the original subtype: leaving it in place produced URLs with
        # two subtype parameters ("subtype=0&subtype=1"), i.e. a bogus route.
        suffix = _RE_SUBTYPE.sub("", url[end:], count=1)
        for n in range(1, _MAX_DAHUA_CH + 1):
            for sub in (0, 1):
                yield f"{prefix}channel={n}&subtype={sub}{suffix}"
        return

    yield url


async def build_from_urls(
    urls,
    pics_dir,
    html_file,
    timeout: float = 10.0,
    concurrency: int = 20,
    routes=None,
    route_parallel: int = 0,
    progress=None,
) -> int:
    """Capture a frame for every channel variant of ``urls`` and emit an
    index.html gallery grouped by camera (one section per base stream).
    Returns the number of successful captures.

    When ``routes`` is given, each camera is also probed against that route list
    (via ``build_probed_urls``) so channels the scan stored only as a bare root
    ``/`` get discovered too.  ``pics_dir`` must already exist.  Concurrency is
    bounded so a large list does not spawn thousands of subprocesses at once.

    ``progress`` is an optional ``async callable(done, total)`` invoked after
    every capture attempt, useful for driving a progress bar.
    """
    if routes:
        candidates = await build_probed_urls(urls, routes, route_parallel)
    else:
        candidates = [v for u in urls for v in channel_variants(u)]
    if not candidates:
        await report.write_gallery_sections([], html_file)
        return 0

    # Capture in a bounded worker pool instead of one task per candidate: a
    # large URL list expands to tens of thousands of channels (16 per Hikvision
    # camera, 16 per ONVIF camera), and a task object per channel is pure
    # memory overhead with no extra throughput.
    screenshot.install_executor(concurrency)
    total = len(candidates)
    workers = min(max(1, concurrency), total)
    pics: list = []
    cursor = 0
    done = 0

    async def _worker():
        nonlocal cursor, done
        while True:
            index = cursor
            if index >= total:
                return
            cursor = index + 1
            url = candidates[index]
            pic = await screenshot.capture(url, pics_dir, timeout)
            if pic:
                pics.append((url, f"pics/{Path(pic).name}"))
            done += 1
            if progress is not None:
                try:
                    await progress(done, total)
                except Exception:
                    pass

    # One failing candidate must not cost the whole gallery.
    await asyncio.gather(
        *(asyncio.create_task(_worker()) for _ in range(workers)),
        return_exceptions=True,
    )
    await report.write_gallery_sections(pics, html_file)
    return len(pics)


def iter_url_list(path: Path):
    """Yield non-empty, non-comment ``rtsp://`` lines from a list file.

    Lines that are not RTSP URLs are dropped instead of being handed to the
    capture pipeline, where they would waste a slot (and produce an empty
    "camera" section) for every ``http://`` or plain-IP line in the file.
    """
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if not line.lower().startswith("rtsp://"):
                continue
            yield line
