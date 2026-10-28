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


def test_targets_accepts_an_inline_cidr():
    """`-t 192.168.1.0/24` (as used in the README) must parse instead of
    failing with "is not a valid path"."""
    from CamReaper.cli import target_arg

    assert target_arg("192.168.1.0/24") == "192.168.1.0/24"
    assert target_arg("10.0.0.1-10.0.0.9") == "10.0.0.1-10.0.0.9"
    assert target_arg("1.1.1.1,8.8.8.8") == "1.1.1.1,8.8.8.8"


def test_targets_rejects_a_typo():
    from CamReaper.cli import target_arg

    with pytest.raises(argparse.ArgumentTypeError):
        target_arg("192.168.1.0/33")


def test_readme_example_parses(tmp_path):
    """The exact command from the README must be accepted end to end."""
    monkey = tmp_path / "targets.txt"
    monkey.write_text("127.0.0.1\n")
    args = parser.parse_args(
        ["-t", "192.168.1.0/24", "-p", "554", "8554", "--no-screenshots"]
    )
    assert args.targets == "192.168.1.0/24"
    assert args.ports == [554, 8554]


# --- help output -------------------------------------------------------------


def _help_text() -> str:
    return parser.format_help()


def _help_flat() -> str:
    """Help text with runs of whitespace collapsed.

    argparse wraps the help column, so a phrase like "(default: brute)" can be
    split across a line boundary; searching the raw text would make these
    assertions depend on the terminal width.
    """
    return " ".join(_help_text().split())


def test_help_has_no_line_longer_than_the_formatter_width():
    """Long unwrapped lines are what made the old help hard to scan."""
    from CamReaper.cli import _terminal_width

    width = _terminal_width()
    too_long = [ln for ln in _help_text().splitlines() if len(ln) > width]
    assert too_long == []


def test_help_groups_options_by_purpose():
    """One flat ~30-entry list was the main readability problem."""
    text = _help_text()
    for group in (
        "targets and wordlists",
        "exploits: CVE and ONVIF",
        "pacing and robustness",
        "screenshots and gallery",
        "extra output files",
        "checkpoint and resume",
    ):
        assert group in text, f"missing group: {group}"


def test_help_states_the_default_of_every_valued_option():
    """The help used to name some defaults inline and silently omit others, so
    it could not be trusted to describe what a run would do."""
    text = _help_flat()
    for expected in (
        "(default: 554)",
        "(default: 80 443 8080)",
        "(default: 5.0)",
        "(default: 2.0)",
        "(default: 300)",
        "(default: 4)",
        "(default: brute)",
    ):
        assert expected in text, f"missing default in help: {expected}"


def test_help_omits_defaults_for_boolean_flags():
    """"default: False" on every store_true flag is noise."""
    text = _help_text()
    assert "(default: False)" not in text
    assert "(default: True)" not in text


def test_help_renders_path_defaults_as_file_names():
    """A full package path is noise; the file name is what the user needs."""
    text = _help_flat()
    assert "(default: defcreds)" in text
    assert "(default: defroutes)" in text
    assert "/CamReaper/defcreds" not in text


def test_help_keeps_option_and_value_on_one_line():
    """argparse's default invocation formatting splits "-t, --targets SPEC"
    across three rows when both spellings exist."""
    text = _help_flat()
    assert "-t, --targets SPEC" in text
    assert "-ct, --check-concurrency N" in text


def test_help_includes_examples_with_line_breaks():
    """The epilog is a usage cheat-sheet, so its layout must survive."""
    lines = _help_text().splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.startswith("examples:"))
    block = lines[start:]
    for example in (
        "CamReaper -t 192.168.1.0/24 -p 554 8554 8000",
        "CamReaper -t targets.txt --mode combined",
        "CamReaper -t targets.txt --onvif",
        "CamReaper --capture reports/latest/result.txt",
    ):
        # Each example must survive as its own line, not be re-wrapped into the
        # surrounding paragraph.
        assert any(example in ln for ln in block), f"missing example: {example}"


def test_terminal_width_is_clamped_to_a_readable_range():
    from CamReaper.cli import _terminal_width
    from unittest import mock

    with mock.patch("shutil.get_terminal_size",
                    return_value=mock.Mock(columns=40)):
        assert _terminal_width() >= 70
    with mock.patch("shutil.get_terminal_size",
                    return_value=mock.Mock(columns=500)):
        assert _terminal_width() <= 100


# --- scan profiles -----------------------------------------------------------


def _targets_file(tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("127.0.0.1\n")
    return f


def test_profile_defaults_to_fast():
    args = parser.parse_args([])
    assert args.profile == "fast"
    # Profile-sensitive flags are unresolved until _apply_profile().
    assert args.deep_auth is None
    assert args.deep_auth_routes is None
    assert args.host_timeout is None
    assert args.port_parallel is None
    assert args.port_pipeline_parallel is None


def test_apply_profile_fast_restores_pre_profile_defaults(tmp_path):
    from CamReaper import FAST_CREDENTIALS, FAST_ROUTES
    from CamReaper.__main__ import _apply_profile

    target = _targets_file(tmp_path)
    args = parser.parse_args(["-t", str(target), "--profile", "fast"])
    info = _apply_profile(args)

    assert args.routes == FAST_ROUTES
    assert args.credentials == FAST_CREDENTIALS
    assert args.deep_auth is False
    assert args.host_timeout == 0.0
    assert args.port_parallel == 4
    assert args.port_pipeline_parallel == 1
    assert args.deep_auth_routes == 40
    assert info["onvif"] is False
    from CamReaper.__main__ import PROFILES
    assert PROFILES["fast"]["all_ports"] is False
    assert PROFILES["fast"]["any_status_live"] is False
    assert PROFILES["fast"]["retry_after_404"] is False


def test_apply_profile_max_uses_big_lists_ports_and_combined(tmp_path):
    from CamReaper.__main__ import (
        COMMON_RTSP_PORTS,
        _BIG_CREDENTIALS,
        _BIG_ROUTES,
        _apply_profile,
    )

    target = _targets_file(tmp_path)
    args = parser.parse_args(["-t", str(target), "--profile", "max"])
    info = _apply_profile(args)

    assert args.routes == (_BIG_ROUTES if _BIG_ROUTES.is_file() else args.routes)
    assert args.credentials == (
        _BIG_CREDENTIALS if _BIG_CREDENTIALS.is_file() else args.credentials
    )
    assert args.mode == "combined"
    assert args.ports == COMMON_RTSP_PORTS
    assert args.host_timeout == 300.0
    assert args.port_parallel == 16
    assert args.port_pipeline_parallel == 16
    assert args.deep_auth_routes == 64
    assert args.onvif_profiles == 8
    assert info["onvif"] is True


def test_apply_profile_keeps_explicit_flags(tmp_path):
    from CamReaper.__main__ import _apply_profile

    target = _targets_file(tmp_path)
    routes = tmp_path / "routes.txt"
    routes.write_text("/stream1\n")
    creds = tmp_path / "creds.txt"
    creds.write_text("admin:admin\n")
    args = parser.parse_args(
        [
            "-t", str(target),
            "--profile", "balanced",
            "-r", str(routes),
            "-c", str(creds),
            "--no-onvif",
            "--host-timeout", "0",
            "--port-parallel", "12",
            "--port-pipeline-parallel", "3",
            "--deep-auth-routes", "7",
            "--no-deep-auth",
        ]
    )
    info = _apply_profile(args)
    assert args.routes == routes
    assert args.credentials == creds
    assert info["onvif"] is False
    assert args.host_timeout == 0.0
    assert info["host_timeout_explicit"] is True
    assert args.port_parallel == 12
    assert args.port_pipeline_parallel == 3
    assert args.deep_auth_routes == 7
    assert args.deep_auth is False


def test_max_profile_does_not_override_explicit_ports(tmp_path):
    from CamReaper.__main__ import _apply_profile

    target = _targets_file(tmp_path)
    args = parser.parse_args(
        ["-t", str(target), "--profile", "max", "-p", "554"]
    )
    _apply_profile(args)
    assert args.ports == [554]


def test_max_profile_does_not_override_explicit_mode(tmp_path):
    from CamReaper.__main__ import _apply_profile

    target = _targets_file(tmp_path)
    args = parser.parse_args(
        ["-t", str(target), "--profile", "max", "--mode", "brute"]
    )
    _apply_profile(args)
    assert args.mode == "brute"


def test_main_wires_fast_profile_into_settings(monkeypatch, tmp_path):
    """The profile must reach Settings, not just the argparse namespace."""
    from CamReaper import __main__ as entry

    captured = {}

    async def fake_run(iter_targets, settings, on_counter=None, on_status=None):
        captured["settings"] = settings
        async for _ip in iter_targets:
            pass
        return {
            "checked": 1, "found": 0, "screenshots": 0,
            "found_no_frame": 0, "vendors": {}, "ports": {},
            "cve_found": 0, "cve_tested": 0, "onvif_found": 0,
            "http_checked": 0, "http_found": 0, "errors": 0,
            "error_samples": [],
        }

    monkeypatch.setattr(entry, "run", fake_run)
    target = _targets_file(tmp_path)
    _run_main(
        monkeypatch, tmp_path,
        ["-t", str(target), "-p", "1", "--profile", "fast",
         "--no-screenshots", "-T", "0.2"],
    )
    settings = captured["settings"]
    assert settings.onvif is False
    assert settings.deep_auth is False
    assert settings.all_ports is False
    assert settings.any_status_live is False
    assert settings.retry_after_404 is False
    assert settings.port_parallel == 4
    assert settings.port_pipeline_parallel == 1
    assert settings.host_timeout == 0.0
    assert len(settings.routes) == 11
    assert len(settings.credentials) == 11
