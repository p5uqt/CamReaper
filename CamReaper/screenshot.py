"""Screenshot capture via PyAV with a hard kill bound.

Decoding frames is CPU/FFmpeg bound and, worse, a misbehaving camera can hang
FFmpeg indefinitely.  To guarantee the pipeline can never stall, each capture
runs in a freshly spawned subprocess that is hard-terminated after a timeout —
the hung worker is killed outright instead of leaking into the pool and
blocking interpreter exit.
"""

import asyncio
import hashlib
import multiprocessing
import re
from functools import partial
from pathlib import Path

ctx = multiprocessing.get_context("spawn")

# Longest file name we produce.  ext4 allows 255 bytes, but a 120-char cap
# keeps the names usable on FAT/exFAT (255 *bytes* with 8.3 constraints) and
# well below the shell/glob limits.
_MAX_NAME = 120
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")


def filename_for(rtsp_url: str) -> str:
    """Return a safe, collision-free file name (without extension) for a URL.

    ``str.lstrip("rtsp://")`` - the obvious one-liner - is a character *set*,
    not a prefix: it also eats the leading 'r' of ``router.local`` and the
    'r' of ``outer.local``, so two different cameras wrote to the same file.
    Truncation is disambiguated with a hash of the full URL for the same reason.
    """
    body = rtsp_url[len("rtsp://"):] if rtsp_url.lower().startswith("rtsp://") else rtsp_url
    name = _UNSAFE.sub("_", body)
    if len(name) > _MAX_NAME:
        digest = hashlib.sha1(rtsp_url.encode("utf-8", "replace")).hexdigest()[:10]
        name = f"{name[:_MAX_NAME - 11]}_{digest}"
    return name or "stream"


def _capture(rtsp_url: str, out_dir: str, timeout: float, out_q) -> None:
    """Runs inside a child process; never returns a non-str."""
    try:
        import av  # lazy so the tool works without av for brute-only mode

        with av.open(
            rtsp_url,
            timeout=timeout,
            options={"rtsp_transport": "tcp", "stimeout": str(int(timeout * 1_000_000))},
        ) as container:
            stream = container.streams.video[0]
            if (
                stream.profile is None
                or stream.start_time is None
                or stream.codec_context.format is None
            ):
                out_q.put("")
                return
            stream.thread_type = "AUTO"
            for frame in container.decode(video=0):
                path = Path(out_dir) / f"{filename_for(rtsp_url)}.jpg"
                frame.to_image().save(str(path))
                out_q.put(str(path))
                return
        out_q.put("")
    except Exception:
        out_q.put("")


def _do_capture(url: str, out_dir: str, timeout: float) -> str:
    """Blocking screenshot: spawn a hardened subprocess, wait bounded, kill
    on timeout.  Never runs on the event loop thread."""
    out_q = ctx.Queue()
    proc = ctx.Process(target=_capture, args=(url, str(out_dir), timeout, out_q))
    proc.start()
    try:
        path = out_q.get(timeout=timeout + 5.0)
    except Exception:
        path = ""
    finally:
        if proc.is_alive():
            proc.terminate()
            proc.join(timeout=2)
        if proc.is_alive():
            proc.kill()
            # Reap the killed child: without this it lingers as a zombie for
            # as long as the scan runs.
            proc.join(timeout=2)
        try:
            out_q.close()
        except Exception:
            pass
    return path


async def capture(url: str, out_dir: str, timeout: float = 10.0) -> str:
    """Capture one screenshot; returns absolute path or empty string.

    The whole blocking subprocess lifecycle runs in a worker thread so the
    event loop - and the network scanner with it - is never stalled.
    """
    loop = asyncio.get_running_loop()
    try:
        return await loop.run_in_executor(
            None, partial(_do_capture, url, str(out_dir), timeout)
        )
    except Exception:
        return ""
