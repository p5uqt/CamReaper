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
        }
    assert data["vendors"] == {"Hikvision": 2, "Generic": 1}
    assert data["ports"] == {"554": 3}
    assert data["mode"] == "brute"
