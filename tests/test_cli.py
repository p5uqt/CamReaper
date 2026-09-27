import argparse

import pytest

from CamReaper.cli import port, parser


def test_single_port():
    assert port("554") == [554]


def test_port_range():
    assert port("8000-8008") == [8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008]


def test_single_port_range():
    assert port("8554-8554") == [8554]


def test_full_range_bounds():
    assert port("1-65535") == list(range(1, 65536))


@pytest.mark.parametrize("value", ["0", "65536", "99999", "abc", "80-90,95", "-1"])
def test_invalid_ports_rejected(value):
    with pytest.raises(argparse.ArgumentTypeError):
        port(value)


def test_reversed_range_rejected():
    with pytest.raises(argparse.ArgumentTypeError):
        port("8008-8000")


def test_args_ports_default():
    assert parser.parse_args([]).ports == [554]


def test_args_ports_range(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("1.2.3.4\n")
    args = parser.parse_args(["-t", str(f), "-p", "8000-8002"])
    assert args.ports == [8000, 8001, 8002]


def test_args_ports_mixed_and_deduped(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("1.2.3.4\n")
    args = parser.parse_args(["-t", str(f), "-p", "554", "8000-8002", "8001", "8554"])
    assert args.ports == [554, 8000, 8001, 8002, 8554]


def test_full_port_range_parses_quickly(tmp_path):
    """Dedup used a list scan, so '1-65535' burned ~18s before the scan began."""
    import time

    f = tmp_path / "t.txt"
    f.write_text("1.2.3.4\n")
    start = time.monotonic()
    args = parser.parse_args(["-t", str(f), "-p", "1-65535", "554", "1-65535"])
    elapsed = time.monotonic() - start
    assert len(args.ports) == 65535
    assert args.ports[:2] == [1, 2] and args.ports[-1] == 65535
    assert elapsed < 1.0, f"port list parsing is O(n^2): {elapsed:.2f}s"


def test_args_http_ports_default():
    assert parser.parse_args([]).http_ports == [80, 443, 8080]


def test_args_http_ports_range(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("1.2.3.4\n")
    args = parser.parse_args(["-t", str(f), "--http-ports", "8080-8082"])
    assert args.http_ports == [8080, 8081, 8082]


def test_args_bad_range_exits(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("1.2.3.4\n")
    with pytest.raises(SystemExit):
        parser.parse_args(["-t", str(f), "-p", "8008-8000"])


def _run_main(monkeypatch, tmp_path, argv):
    """Call the real entry point with argv, in a clean report environment."""
    from CamReaper import report

    for attr in ("FAILED_FILE", "NO_AUTH_FILE", "CVE_LOG_FILE", "HTTP_CVE_FILE"):
        setattr(report, attr, None)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.argv", ["CamReaper", *argv])
    from CamReaper.__main__ import main

    main()
    runs = sorted(p for p in tmp_path.glob("reports/*") if p.is_dir())
    return runs[-1]


def test_gallery_html_records_urls_in_reports(monkeypatch, tmp_path):
    """--gallery-html must not just build the site: its input list is also the
    run's stream list, so result.txt / streams.m3u / summary.json stay consistent
    (regression: the recording used to run outside the coroutine)."""
    import json

    urls = tmp_path / "urls.txt"
    urls.write_text(
        "rtsp://admin:admin@127.0.0.1:1/stream1\n"
        "\n"
        "# a comment\n"
        "http://127.0.0.1:1/stream\n"
        "garbage\n"
    )
    run = _run_main(
        monkeypatch, tmp_path,
        ["--gallery-html", "urls.txt", "--screenshot-timeout", "0.2"],
    )
    assert (run / "result.txt").read_text() == (
        "rtsp://admin:admin@127.0.0.1:1/stream1\n"
    )
    assert (run / "streams.m3u").read_text() == (
        "rtsp://admin:admin@127.0.0.1:1/stream1\n"
    )
    summary = json.loads((run / "summary.json").read_text())
    assert summary["mode"] == "gallery"
    assert summary["statistics"]["found"] == 1


def test_gallery_html_without_urls_does_not_crash(monkeypatch, tmp_path):
    """An empty/garbage-only list must warn and exit cleanly."""
    urls = tmp_path / "urls.txt"
    urls.write_text("nonsense\n\n# only comments\n")
    run = _run_main(monkeypatch, tmp_path, ["--gallery-html", "urls.txt"])
    assert run.is_dir()
    assert not (run / "result.txt").exists() or not (
        run / "result.txt"
    ).read_text()


def test_scan_mode_reports_route_and_cred_counts(monkeypatch, tmp_path, capsys):
    """Blank lines and comments must not inflate the wordlists, and the
    summary must report the errors counter (regression: report.RESULT_FILE /
    HTML_FILE wiring used to crash on the removed Settings fields)."""
    import json

    (tmp_path / "t.txt").write_text("127.0.0.1\n")
    (tmp_path / "routes.txt").write_text("/\n\n# comment\n/stream1\n")
    (tmp_path / "creds.txt").write_text("admin:admin\n\n# comment\nroot:root\n")
    run = _run_main(
        monkeypatch, tmp_path,
        ["-t", "t.txt", "-r", "routes.txt", "-c", "creds.txt",
         "--no-screenshots", "-T", "0.2"],
    )
    out = capsys.readouterr().out
    assert "routes=2 creds=2" in out
    summary = json.loads((run / "summary.json").read_text())
    assert summary["statistics"]["errors"] == 0
    assert summary["statistics"]["checked"] == 1
