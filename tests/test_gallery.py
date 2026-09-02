from pathlib import Path

import pytest

from CamReaper import report
from CamReaper.gallery import (
    _split_url,
    build_from_urls,
    build_probed_urls,
    channel_variants,
    iter_url_list,
)


def test_channel_variants_single_url():
    assert list(channel_variants("rtsp://1.1.1.1:554/stream1")) == [
        "rtsp://1.1.1.1:554/stream1"
    ]


def test_channel_variants_hikvision():
    base = "rtsp://2.2.2.2:554/Streaming/Channels/101/"
    variants = list(channel_variants(base))
    assert len(variants) == 16
    assert variants[0] == "rtsp://2.2.2.2:554/Streaming/Channels/101/"
    assert variants[-1] == "rtsp://2.2.2.2:554/Streaming/Channels/1601/"


def test_channel_variants_dahua_h264():
    url = "rtsp://admin:admin@3.3.3.3:554/h264/ch1/main/av_stream"
    variants = list(channel_variants(url))
    assert len(variants) == 8
    assert variants[0] == "rtsp://admin:admin@3.3.3.3:554/h264/ch1/main/av_stream"
    assert variants[-1] == "rtsp://admin:admin@3.3.3.3:554/h264/ch8/main/av_stream"


def test_channel_variants_onvif():
    url = "rtsp://4.4.4.4:554/cam/realmonitor?channel=1&subtype=0"
    variants = list(channel_variants(url))
    assert len(variants) == 16  # 8 channels x main/sub
    assert "?channel=1&subtype=0" in variants[0]
    assert "?channel=1&subtype=1" in variants[1]
    assert "?channel=8&subtype=1" in variants[-1]


def test_channel_variants_unknown_path_kept_as_is():
    assert list(channel_variants("rtsp://5.5.5.5:554/superstream")) == [
        "rtsp://5.5.5.5:554/superstream"
    ]


def test_split_url():
    assert _split_url("rtsp://1.2.3.4:554/") == ("1.2.3.4", 554, ":", "/")
    assert _split_url("rtsp://admin:pass@2.3.4.5:8554/h264/ch1/main/av_stream") == (
        "2.3.4.5",
        8554,
        "admin:pass",
        "/h264/ch1/main/av_stream",
    )
    assert _split_url("rtsp://6.7.8.9") == ("6.7.8.9", 554, ":", "/")


async def test_build_probed_urls_keeps_only_onvif_routes():
    """Route probing adds only ONVIF-style routes, never unrelated aliases.

    The mock answers 200 on every route, but a bare-root camera must NOT gain
    /h264.., /superstream etc. (those were the duplicate shots).  Only ONVIF
    channel/subtype routes are added.
    """
    from tests.mock_rtsp import make_server

    srv = await make_server("open")  # answers 200 on every route
    try:
        urls = [f"rtsp://{srv.host}:{srv.port}/"]
        routes = [
            "/h264/ch1/main/av_stream",
            "/superstream",
            "/cam/realmonitor?channel=1&subtype=1&unicast=true&proto=Onvif",
            "/user=admin&password=&channel=1&stream=0.sdp?",
        ]
        got = await build_probed_urls(urls, routes, route_parallel=4)
    finally:
        await srv.stop()
    # its own recorded URL is kept (screenshot of the camera itself)
    assert f"rtsp://{srv.host}:{srv.port}/" in got
    # non-ONVIF aliases are dropped -> no duplicates
    assert f"rtsp://{srv.host}:{srv.port}/h264/ch1/main/av_stream" not in got
    assert f"rtsp://{srv.host}:{srv.port}/superstream" not in got
    # ONVIF-style routes ARE added
    assert (
        f"rtsp://{srv.host}:{srv.port}/cam/realmonitor?channel=1&subtype=1"
        "&unicast=true&proto=Onvif" in got
    )
    assert (
        f"rtsp://{srv.host}:{srv.port}/user=admin&password=&channel=1&stream=0.sdp?"
        in got
    )


def test_iter_url_list_skips_blank_and_comments(tmp_path):
    f = tmp_path / "list.txt"
    f.write_text("# comment\n\nrtsp://1.1.1.1/\n\nrtsp://2.2.2.2/s\n")
    assert list(iter_url_list(f)) == ["rtsp://1.1.1.1/", "rtsp://2.2.2.2/s"]


@pytest.mark.asyncio
async def test_build_from_urls_counts_success(tmp_path, monkeypatch):
    """build_from_urls returns the number of successful captures and appends a
    gallery entry per frame (screenshot.capture is stubbed to avoid spawning
    subprocesses / requiring PyAV)."""
    from CamReaper import gallery

    pics = tmp_path / "pics"
    pics.mkdir()

    async def fake_capture(url, out_dir, timeout):
        # simulate a successful frame -> a fake file
        target = pics / f"{url.split('/')[-1] or 'root'}.jpg"
        target.write_bytes(b"x")
        return str(target)

    monkeypatch.setattr(gallery.screenshot, "capture", fake_capture)

    report.HTML_FILE = tmp_path / "index.html"
    report.init_html(report.HTML_FILE)

    urls = ["rtsp://1.1.1.1:554/stream1", "rtsp://1.1.1.1:554/stream2"]
    n = await build_from_urls(urls, pics, report.HTML_FILE, timeout=1.0, concurrency=2)
    await report.close_report_files()  # flush buffered writer before reading
    assert n == 2
    # two gallery entries appended after the header
    assert report.HTML_FILE.read_text().count('class="responsive"') == 2


async def test_write_gallery_sections_groups_channels(tmp_path):
    """Channels of one camera share a group header; distinct cameras are split."""
    html = tmp_path / "index.html"
    entries = [
        ("rtsp://6.6.6.6:554/h264/ch8/main/av_stream", "pics/ch8.jpg"),
        ("rtsp://6.6.6.6:554/h264/ch1/main/av_stream", "pics/ch1.jpg"),
        ("rtsp://admin:admin@7.7.7.7/sub", "pics/sub.jpg"),
    ]
    await report.write_gallery_sections(entries, html)
    await report.close_report_files()  # flush
    content = html.read_text()
    # two distinct camera bases -> two group headers; headers never leak creds
    assert content.count('class="cam-head"') == 2
    assert "6.6.6.6:554 [Dahua h264]" in content
    assert "7.7.7.7" in content
    # the header label strips credentials (but <img alt> keeps the full URL to copy)
    head = content.split('class="cam-head"')[1]
    assert "admin:admin@" not in head
    assert content.count('div class="camgroup"') == 2
