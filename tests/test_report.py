import json

import pytest

from CamReaper import report


@pytest.fixture
def paths(tmp_path):
    result = tmp_path / "result.txt"
    html = tmp_path / "index.html"
    result.touch()
    report.RESULT_FILE = result
    report.HTML_FILE = html
    report.init_html(html)
    return result, html


async def test_record_url(paths):
    result, _ = paths
    await report.record_url("rtsp://1.2.3.4:554/")
    await report.close_report_files()  # flush the buffered writer
    assert result.read_text() == "rtsp://1.2.3.4:554/\n"


async def test_record_gallery(paths):
    _, html = paths
    await report.record_gallery("rtsp://1.2.3.4:554/", "pics/a.jpg")
    await report.close_report_files()  # flush the buffered writer
    content = html.read_text()
    assert 'src="pics/a.jpg"' in content
    assert 'alt="rtsp://1.2.3.4:554/"' in content
    # single click copies the RTSP link, double click opens fullscreen
    assert 'onclick="clickOrDouble(this,event)"' in content
    assert "viewerClick(event)" in content
    assert 'href="rtsp://1.2.3.4:554/"' not in content


async def test_record_gallery_escapes_attributes(paths):
    """A URL with '&' or a quote must not break (or inject into) the markup."""
    _, html = paths
    await report.record_gallery(
        'rtsp://a"b:c@1.2.3.4:554/cam?channel=1&subtype=1', "pics/1.2.3.4.jpg"
    )
    await report.close_report_files()
    content = html.read_text()
    assert 'src="pics/1.2.3.4.jpg"' in content
    assert "&amp;subtype=1" in content
    assert "&quot;" in content
    assert 'alt="rtsp://a"b' not in content


async def test_record_gallery_shows_address_port_and_login(paths):
    """Under each screenshot the gallery shows address, port and login:password."""
    _, html = paths
    await report.record_gallery(
        "rtsp://admin:admin@192.168.1.64:8554/h264/ch1/main/av_stream",
        "pics/a.jpg",
    )
    await report.close_report_files()
    content = html.read_text()
    assert 'class="cap"' in content
    assert "192.168.1.64" in content  # address
    assert "8554" in content  # port
    assert "admin:admin" in content  # login with password


async def test_record_gallery_caption_marks_missing_auth(paths):
    """A stream with no credentials says so instead of an empty login line."""
    _, html = paths
    await report.record_gallery("rtsp://1.2.3.4:554/", "pics/a.jpg")
    await report.close_report_files()
    content = html.read_text()
    assert "no auth" in content
    assert "1.2.3.4" in content and "554" in content


async def test_record_gallery_caption_escapes_credentials(paths):
    """A password with quotes/& must not break out of the caption markup."""
    _, html = paths
    await report.record_gallery('rtsp://us"er:p&ss@1.2.3.4:554/s', "pics/a.jpg")
    await report.close_report_files()
    content = html.read_text()
    assert "us&quot;er:p&amp;ss" in content
    assert 'us"er' not in content


def test_gallery_copy_dropdown_has_three_modes(paths):
    """'Copy on click' offers: bare address, ffplay+TCP, and the full rtsp link."""
    _, html = paths
    report.init_html(html)
    content = html.read_text()
    # the dropdown itself is back
    assert '<select id="copyMode"' in content
    assert 'setCopyMode()' in content
    # 1. bare address (host:port)
    assert 'value="addr"' in content
    assert "function streamAddress(url){" in content
    # 2. ffplay, forced over TCP
    assert 'value="ffplay"' in content
    assert '"ffplay -rtsp_transport tcp "' in content
    # 3. the full rtsp stream, with credentials and route
    assert 'value="rtsp"' in content
    assert "t=img.alt;" in content


def test_writers_work_on_a_second_event_loop(tmp_path):
    """A module-level asyncio.Lock would bind to the first loop and break every
    later run; the writers must be usable from any loop."""
    import asyncio

    result = tmp_path / "result.txt"
    report.RESULT_FILE = result

    async def _write(tag):
        await report.record_url(f"rtsp://10.0.0.{tag}:554/")
        await report.close_report_files()

    try:
        asyncio.run(_write(0))
        asyncio.run(_write(1))
    finally:
        report.RESULT_FILE = None
    assert result.read_text() == "rtsp://10.0.0.0:554/\nrtsp://10.0.0.1:554/\n"


def test_escape_chars():
    assert (
        report.escape_chars("rtsp://1.2.3.4:554/a b_-.x")
        == "rtsp___1.2.3.4_554_a b_-.x"
    )


def test_write_m3u_copy(tmp_path):
    result = tmp_path / "result.txt"
    result.write_text("rtsp://1.2.3.4/\nrtsp://5.6.7.8/stream1\n")
    m3u = tmp_path / "streams.m3u"
    report.write_m3u(result, m3u)
    assert m3u.read_text() == result.read_text()


def test_write_summary(tmp_path):
    summary = tmp_path / "summary.json"
    stats = {
        "checked": 10,
        "found": 3,
        "screenshots": 2,
        "found_no_frame": 1,
        "vendors": {"Hikvision": 2, "Generic": 1},
        "ports": {"554": 3},
    }
    report.write_summary(summary, stats, 42.5)
    data = json.loads(summary.read_text())
    assert data["elapsed"] == 42.5
    assert data["statistics"] == {
        "checked": 10,
        "found": 3,
        "screenshots": 2,
        "found_no_frame": 1,
            "cve_found": 0,
            "cve_tested": 0,
            "http_checked": 0,
            "http_found": 0,
            "errors": 0,
        }
    assert data["vendors"] == {"Hikvision": 2, "Generic": 1}
    assert data["ports"] == {"554": 3}
    assert data["mode"] == "brute"


def test_summary_keeps_error_samples(tmp_path):
    """error_samples must reach summary.json - it is the only place a silently
    dropped host can be explained from after the fact."""
    report.RESULT_FILE = None
    report.HTML_FILE = None
    summary = tmp_path / "summary.json"
    report.write_summary(
        summary,
        {
            "checked": 3, "found": 0, "screenshots": 0, "found_no_frame": 0,
            "cve_found": 0, "cve_tested": 0, "http_checked": 0, "http_found": 0,
            "errors": 1,
            "error_samples": ["10.0.0.1: TypeError: boom"],
        },
        1.0,
    )
    data = json.loads(summary.read_text())
    assert data["error_samples"] == ["10.0.0.1: TypeError: boom"]
    assert data["statistics"]["errors"] == 1
