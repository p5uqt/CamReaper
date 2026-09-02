import asyncio
import time

import pytest

pytestmark = pytest.mark.asyncio


async def _heartbeat(events):
    while True:
        events.append(time.monotonic())
        await asyncio.sleep(0.05)


@pytest.mark.parametrize("mode", ["silent"])
async def test_capture_is_bounded_and_loop_stays_responsive(mode):
    """A camera that accepts but never answers must not stall the pipeline:
    the capture is hard-killed after a short bound and the event loop keeps
    running while it is in flight (host scanning is never frozen)."""
    from CamReaper import screenshot
    from CamReaper.screenshot import _do_capture
    from tests.mock_rtsp import make_server

    srv = await make_server(mode)
    try:
        url = f"rtsp://{srv.host}:{srv.port}/"
        beats = []
        hb = asyncio.create_task(_heartbeat(beats))

        start = time.monotonic()
        path = await screenshot.capture(url, "/tmp", timeout=1.0)
        elapsed = time.monotonic() - start

        hb.cancel()
        await asyncio.gather(hb, return_exceptions=True)

        assert path == ""
        assert elapsed < 9.0, f"capture not bounded: {elapsed:.2f}s"
        ticks_during = [t for t in beats if start - 0.05 <= t <= start + elapsed + 0.05]
        assert len(ticks_during) >= 2, "event loop frozen while capture in flight"
    finally:
        await srv.stop()
