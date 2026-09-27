import asyncio
import time
from pathlib import Path

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


async def test_filename_for_does_not_collide():
    """str.lstrip('rtsp://') eats leading r/s/t/p chars, so 'router.local' and
    'outer.local' used to write the very same file."""
    from CamReaper.screenshot import filename_for

    assert filename_for("rtsp://router.local:554/") != filename_for("rtsp://outer.local:554/")
    assert filename_for("rtsp://1.2.3.4:554/").startswith("1.2.3.4")


async def test_filename_for_is_safe_and_bounded():
    from CamReaper.screenshot import filename_for

    name = filename_for("rtsp://user:pass@1.2.3.4:554/cam/realmonitor?channel=1&subtype=1")
    assert set(name) <= set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")

    long_a = filename_for("rtsp://1.2.3.4/" + "a" * 400)
    long_b = filename_for("rtsp://1.2.3.4/" + "b" * 400)
    assert len(long_a) <= 120 and len(long_b) <= 120
    assert long_a != long_b, "truncated names must stay unique"


class _Sink:
    """Stands in for the child process queue: ``_capture`` only calls ``put``."""

    def __init__(self):
        self.items = []

    def put(self, item):
        self.items.append(item)


def _fake_av(monkeypatch, *, frames=1, has_video=True, raises=False, **meta):
    """Install a stand-in ``av`` module so ``_capture`` can be driven without a
    camera.  ``_capture`` imports ``av`` lazily, so patching sys.modules is
    enough.  ``meta`` becomes the stream attributes the old pre-check looked
    at, so tests can reproduce exactly what a real camera reports."""
    import sys
    import types

    class _Stream:
        profile = meta.get("profile")
        start_time = meta.get("start_time")
        thread_type = None
        codec_context = types.SimpleNamespace(format=meta.get("format"))

    class _Image:
        def save(self, target):
            with open(target, "wb") as fh:
                fh.write(b"jpeg")

    class _Frame:
        def to_image(self):
            return _Image()

    class _Container:
        streams = types.SimpleNamespace(video=[_Stream()] if has_video else [])

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def decode(self, video=0):
            return [_Frame() for _ in range(frames)]

    def _open(*a, **kw):
        if raises:
            raise RuntimeError("no video")
        return _Container()

    module = types.ModuleType("av")
    module.open = _open
    monkeypatch.setitem(sys.modules, "av", module)


async def test_capture_accepts_stream_without_timestamps(monkeypatch, tmp_path):
    """A camera streaming raw Annex B H.264 has no timestamps in the SDP, so
    PyAV reports ``start_time=None``.  The old pre-check treated that as
    "undecodable" and dropped the camera before reading a single frame, even
    though its frames decode fine - which is why runs showed fewer screenshots
    than found cameras."""
    from CamReaper import screenshot

    _fake_av(monkeypatch, profile="High", start_time=None, format=None)
    sink = _Sink()
    screenshot._capture("rtsp://1.2.3.4:554/stream", str(tmp_path), 5.0, sink)

    assert len(sink.items) == 1 and sink.items[0].endswith(".jpg")
    assert (tmp_path / Path(sink.items[0]).name).is_file()


@pytest.mark.parametrize(
    "meta",
    [
        {"profile": None, "start_time": 0, "format": None},
        {"profile": "Baseline", "start_time": None, "format": None},
        {"profile": None, "start_time": None, "format": None},
        {"profile": "High", "start_time": None, "format": None},
    ],
)
async def test_capture_accepts_any_metadata_gap(monkeypatch, tmp_path, meta):
    """Whichever metadata field a given camera happens to omit, the decision
    must come from decoding, never from a pre-check."""
    from CamReaper import screenshot

    _fake_av(monkeypatch, **meta)
    sink = _Sink()
    screenshot._capture("rtsp://1.2.3.4:554/stream", str(tmp_path), 5.0, sink)

    assert len(sink.items) == 1 and sink.items[0].endswith(".jpg")


async def test_capture_returns_empty_when_container_opens_faithfully_but_yields_nothing(
    monkeypatch, tmp_path
):
    from CamReaper import screenshot

    _fake_av(monkeypatch, frames=0, profile="High", start_time=0, format=None)
    sink = _Sink()
    screenshot._capture("rtsp://1.2.3.4:554/stream", str(tmp_path), 5.0, sink)

    assert sink.items == [""]


async def test_capture_returns_empty_for_container_without_video(monkeypatch, tmp_path):
    """An audio-only container is not a stream we can screenshot."""
    from CamReaper import screenshot

    _fake_av(monkeypatch, has_video=False)
    sink = _Sink()
    screenshot._capture("rtsp://1.2.3.4:554/stream", str(tmp_path), 5.0, sink)

    assert sink.items == [""]


async def test_capture_returns_empty_when_open_raises(monkeypatch, tmp_path):
    """An unreadable stream must be reported as failure, not raised - the
    worker counts it and keeps going."""
    from CamReaper import screenshot

    _fake_av(monkeypatch, raises=True)
    sink = _Sink()
    screenshot._capture("rtsp://1.2.3.4:554/stream", str(tmp_path), 5.0, sink)

    assert sink.items == [""]
