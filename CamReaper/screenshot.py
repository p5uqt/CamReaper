"""Screenshot capture via PyAV with a hard kill bound.

Decoding frames is CPU/FFmpeg bound and, worse, a misbehaving camera can hang
FFmpeg indefinitely.  To guarantee the pipeline can never stall, each capture
runs in a freshly spawned subprocess that is hard-terminated after a timeout —
the hung worker is killed outright instead of leaking into the pool and
blocking interpreter exit.
"""

import asyncio
import multiprocessing
from functools import partial
from pathlib import Path

from CamReaper.report import escape_chars

ctx = multiprocessing.get_context("spawn")


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
                path = Path(out_dir) / f"{escape_chars(rtsp_url.lstrip('rtsp://'))}.jpg"
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
