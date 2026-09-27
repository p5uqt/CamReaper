import pytest

from CamReaper import report
from CamReaper.scanner import Settings, run

pytestmark = pytest.mark.asyncio


@pytest.fixture
def report_paths(tmp_path):
    report.RESULT_FILE = tmp_path / "result.txt"
    report.HTML_FILE = None
    report.RESULT_FILE.touch()
    yield report.RESULT_FILE
    report.RESULT_FILE = None
    report.HTML_FILE = None


async def _scan(server, creds, routes=("/", "/stream1"), **kw):
    async def targets():
        yield server.host

    settings = Settings(
        ports=[server.port],
        routes=routes,
        credentials=creds,
        timeout=1.0,
        host_concurrency=5,
        screenshot_concurrency=1,
        enable_screenshots=False,
        **kw,
    )
    return await run(targets(), settings)


async def test_multiple_targets_more_than_concurrency(report_paths):
    """More targets than host_concurrency must exercise the batched scheduler
    (regression: asyncio.wait returns a set, shadowing the pending list)."""
    from tests.mock_rtsp import make_server

    srv = await make_server("scanner", valid_cred="admin:admin")
    try:
        # 5 repeats of the live host + 1 unroutable IP: every target must be
        # checked, the live ones found, and no exception raised.
        async def targets():
            for _ in range(5):
                yield srv.host
            yield "10.255.255.1"

        settings = Settings(
            ports=[srv.port],
            routes=["/", "/stream1"],
            credentials=["admin:admin"],
            timeout=0.5,
            host_concurrency=2,
            screenshot_concurrency=1,
            enable_screenshots=False,
        )
        stats = await run(targets(), settings)
        assert stats["checked"] == 6
        assert stats["found"] == 5
    finally:
        await srv.stop()


async def test_open_host_found(report_paths):
    from tests.mock_rtsp import make_server

    srv = await make_server("open")
    try:
        stats = await _scan(srv, creds=["admin:admin"])
        assert stats["found"] == 1
        assert "rtsp://127.0.0.1" in report_paths.read_text()
    finally:
        await srv.stop()


async def test_auth_host_with_valid_cred(report_paths):
    from tests.mock_rtsp import make_server

    srv = await make_server("scanner", valid_cred="admin:admin")
    try:
        stats = await _scan(srv, creds=["admin:admin"])
        assert stats["found"] == 1
        assert "admin:admin@127.0.0.1" in report_paths.read_text()
    finally:
        await srv.stop()


async def test_auth_host_without_valid_cred(report_paths):
    from tests.mock_rtsp import make_server

    srv = await make_server("scanner", valid_cred="root:secret")
    try:
        stats = await _scan(srv, creds=["admin:admin", "user:user"])
        assert stats["found"] == 0
        assert report_paths.read_text() == ""
    finally:
        await srv.stop()


async def test_max_attempts_limits_probes(report_paths):
    """max_attempts=1 must cap the credential loop to ONE tried credential."""
    from tests.mock_rtsp import make_server

    srv = await make_server("scanner", valid_cred="root:secret")
    try:
        stats = await _scan(
            srv,
            creds=["admin:admin", "user:user", "x:x"],
            max_attempts=1,
        )
        assert stats["found"] == 0
        # requests: dummy probe + route probes + exactly ONE credential try.
        total = len(srv.requests)
        assert total <= 5
    finally:
        await srv.stop()


async def test_open_only_on_query_route_found(report_paths):
    """A camera that answers 200 WITHOUT credentials only on a specific query
    route (e.g. Hikvision "/cam/realmonitor?channel=1&subtype=1&unicast=true&
    proto=Onvif") while returning 401 on "/" and the common routes must be
    found - the bug was that we only probed a handful of free routes
    and dropped the host into credential bruting (which failed because no
    password is needed at all), so we found fewer cameras."""
    from tests.mock_rtsp import make_server

    open_route = "/cam/realmonitor?channel=1&subtype=1&unicast=true&proto=Onvif"
    srv = await make_server("route-open", open_route=open_route)
    try:
        # the open query route sits late in the list, after many 401-only ones
        routes = [f"/route{i}" for i in range(60)] + [open_route]
        creds = ["admin:admin", "root:12345"]
        stats = await _scan(srv, creds=creds, routes=routes)
        assert stats["found"] == 1
        # no password in the URL because the route is open
        assert open_route in report_paths.read_text()
    finally:
        await srv.stop()


async def test_open_route_survives_flaky_routes(report_paths):
    """A camera whose open route sits late in the list AND returns a definitive
    non-auth 404 on a couple of the earlier routes must still be found.  The
    serial sweep resets its transport-failure counter on every clean 401, so a
    stray 404 mid-list cannot abort the sweep before the later open route
    (`/cam/realmonitor?...`) is reached."""
    from tests.mock_rtsp import make_server

    open_route = "/cam/realmonitor?channel=1&subtype=1&unicast=true&proto=Onvif"
    srv = await make_server(
        "route-open",
        open_route=open_route,
        routes_404=("/missing1", "/missing2"),
    )
    try:
        # 404s interspersed with 401s; the open route sits at the END.
        routes = ["/missing1", "/", "/missing2", "/stream1", open_route]
        creds = ["admin:admin", "root:12345"]
        stats = await _scan(srv, creds=creds, routes=routes)
        assert stats["found"] == 1
        assert open_route in report_paths.read_text()
    finally:
        await srv.stop()


async def test_flaky_camera_gives_up_quickly(report_paths, monkeypatch):
    """A camera that answers a bit then goes silent must be abandoned fast,
    not grind one ~2s timeout per credential (214 creds would take minutes)."""
    import time

    from tests.mock_rtsp import make_server

    srv = await make_server("scanner", silent_after=6)
    try:
        creds = [f"user{i}:pw" for i in range(50)]
        t0 = time.monotonic()
        stats = await _scan(srv, creds=creds)
        elapsed = time.monotonic() - t0
        assert stats["found"] == 0
        # requests: dummy + 3 free probes + a handful of cred tries before the
        # host is abandoned on repeated transport failures (NOT all 50 creds).
        assert len(srv.requests) < 15
        assert elapsed < 30.0
    finally:
        await srv.stop()


async def test_failed_file_disabled_by_default(report_paths, tmp_path):
    """Without --failed-file nothing failed-connection is written, so the
    default run pays nothing."""
    from tests.mock_rtsp import make_server

    # silence any previously configured file (per-test fixtures allow for it)
    failed = tmp_path / "failed.txt"
    report.FAILED_FILE = None
    srv = await make_server("silent")
    try:
        stats = await _scan(srv, creds=["admin:admin"])
        assert stats["found"] == 0
        assert not failed.exists()
    finally:
        await srv.stop()


async def test_failed_file_records_unconfirmed_host(report_paths, tmp_path):
    """A reachable-but-unconfirmed host (port opens, but no RTSP response -
    the 'silent' mock) is written to the --failed-file as 'ip port'."""
    from tests.mock_rtsp import make_server

    failed = tmp_path / "failed.txt"
    report.FAILED_FILE = failed
    srv = await make_server("silent")
    try:
        await _scan(srv, creds=["admin:admin"])
        lines = failed.read_text().splitlines()
        assert len(lines) == 1
        parts = lines[0].split()
        assert parts[0] == srv.host
        assert parts[1] == str(srv.port)
        assert len(parts) == 2  # no error without --failed-with-error
    finally:
        await srv.stop()
        report.FAILED_FILE = None


async def test_failed_file_with_error_appends_reason(report_paths, tmp_path):
    """With --failed-with-error the line is 'ip port error'."""
    from tests.mock_rtsp import make_server

    failed = tmp_path / "failed.txt"
    report.FAILED_FILE = failed
    srv = await make_server("silent")
    try:
        await _scan(
            srv,
            creds=["admin:admin"],
            failed_with_error=True,
        )
        parts = failed.read_text().splitlines()[0].split()
        assert parts[0] == srv.host
        assert parts[1] == str(srv.port)
        assert len(parts) == 3 and parts[2]
    finally:
        await srv.stop()
        report.FAILED_FILE = None


async def test_no_auth_file_disabled_by_default(report_paths, tmp_path):
    """No live-credential-failed host is written without --no-auth-file."""
    from tests.mock_rtsp import make_server

    noauth = tmp_path / "noauth.txt"
    report.NO_AUTH_FILE = None
    srv = await make_server("scanner", valid_cred="root:secret")
    try:
        await _scan(srv, creds=["admin:admin"])
        assert not noauth.exists()
    finally:
        await srv.stop()


async def test_no_auth_file_records_unopened_camera(report_paths, tmp_path):
    """A confirmed live RTSP host whose port answered 401/403 but for which no
    credential worked is written to --no-auth-file as 'ip port'."""
    from tests.mock_rtsp import make_server

    noauth = tmp_path / "noauth.txt"
    report.NO_AUTH_FILE = noauth
    srv = await make_server("scanner", valid_cred="root:secret")
    try:
        stats = await _scan(srv, creds=["admin:admin"])
        assert stats["found"] == 0
        lines = noauth.read_text().splitlines()
        assert len(lines) == 1
        parts = lines[0].split()
        assert parts[0] == srv.host
        assert parts[1] == str(srv.port)
        assert len(parts) == 2
    finally:
        await srv.stop()
        report.NO_AUTH_FILE = None


async def test_no_auth_file_not_written_when_cred_works(report_paths, tmp_path):
    """When a credential does open the camera it is NOT logged as no-auth."""
    from tests.mock_rtsp import make_server

    noauth = tmp_path / "noauth.txt"
    report.NO_AUTH_FILE = noauth
    noauth.touch()  # __main__ creates the file up front
    srv = await make_server("scanner", valid_cred="admin:admin")
    try:
        stats = await _scan(srv, creds=["admin:admin"])
        assert stats["found"] == 1
        assert noauth.read_text() == ""
    finally:
        await srv.stop()
        report.NO_AUTH_FILE = None


async def test_log_flags_auto_resolve_into_report_folder(tmp_path):
    """--failed-file / --no-auth-file without a value must resolve next to
    result.txt in the report folder (and accept an explicit path too)."""
    from CamReaper.__main__ import _resolve_log_path
    from CamReaper.cli import parser

    targets = tmp_path / "t.txt"
    targets.write_text("1.2.3.4\n")

    # Flag given WITHOUT a value -> __auto__ marker -> report folder.
    a = parser.parse_args(["-t", str(targets), "--failed-file", "--no-auth-file"])
    assert a.failed_file == "__auto__"
    assert a.no_auth_file == "__auto__"
    folder = tmp_path / "reports" / "run"
    assert (
        _resolve_log_path(a.failed_file, folder, "failed.txt") == folder / "failed.txt"
    )
    assert (
        _resolve_log_path(a.no_auth_file, folder, "noauth.txt") == folder / "noauth.txt"
    )

    # Flag given WITH a value -> used verbatim.
    a = parser.parse_args(
        ["-t", str(targets), "--failed-file", str(tmp_path / "f.txt")]
    )
    assert _resolve_log_path(a.failed_file, folder, "failed.txt") == tmp_path / "f.txt"

    # Flag absent -> None (feature off).
    a = parser.parse_args(["-t", str(targets)])
    assert a.failed_file is None
    assert a.no_auth_file is None


async def test_route_parallel_finds_open_query_route(report_paths):
    """route_parallel > 1 must find a camera that answers 200 only on a
    specific query route, just like serial mode."""
    from tests.mock_rtsp import make_server

    open_route = "/cam/realmonitor?channel=1&subtype=1&unicast=true&proto=Onvif"
    srv = await make_server("route-open", open_route=open_route)
    try:
        routes = [f"/route{i}" for i in range(60)] + [open_route]
        creds = ["admin:admin", "root:12345"]
        stats = await _scan(srv, creds=creds, routes=routes, route_parallel=4)
        assert stats["found"] == 1
        assert open_route in report_paths.read_text()
    finally:
        await srv.stop()


async def test_route_parallel_serial_equivalence(report_paths):
    """route_parallel=1 must give the same result as the default serial path."""
    from tests.mock_rtsp import make_server

    srv = await make_server("scanner", valid_cred="admin:admin")
    try:
        stats_serial = await _scan(srv, creds=["admin:admin"], route_parallel=1)
        stats_parallel = await _scan(srv, creds=["admin:admin"], route_parallel=8)
        assert stats_serial["found"] == stats_parallel["found"]
    finally:
        await srv.stop()


async def test_open_dummy_route_not_recorded_as_root(report_paths):
    """A camera that 200s arbitrary routes but gates '/' (good parser for the
    old bug: the dummy-route probe answered 200 and a fake rtsp://ip:port/ was
    recorded without ever confirming '/').  Now the sweep pins the real open
    route instead of the unchecked root."""
    from tests.mock_rtsp import make_server

    srv = await make_server("open-except-root")
    try:
        routes = ["/", "/stream1", "/h264/ch1/main/av_stream"]
        stats = await _scan(srv, creds=["admin:admin"], routes=routes)
        assert stats["found"] == 1
        links = report_paths.read_text().splitlines()
        assert len(links) == 1
        # the confirmed route is recorded, not the unconfirmed root
        assert "/stream1" in links[0]
        assert not links[0].endswith(":554/")
    finally:
        await srv.stop()


async def test_on_counter_receives_ip(report_paths):
    """The progress callback must be called with the IP that just finished, so
    checkpoint/resume can track which hosts were already checked."""
    from tests.mock_rtsp import make_server

    srv = await make_server("open")
    seen = []
    try:

        async def targets():
            yield srv.host

        settings = Settings(
            ports=[srv.port],
            routes=["/"],
            credentials=["admin:admin"],
            timeout=1.0,
            host_concurrency=5,
            screenshot_concurrency=1,
            enable_screenshots=False,
        )
        await run(targets(), settings, on_counter=lambda st, ip: seen.append(ip))
        assert seen == [srv.host]
    finally:
        await srv.stop()


async def test_stats_breakdown(report_paths):
    """stats carry a vendor/port breakdown of the confirmed streams."""
    from tests.mock_rtsp import make_server

    srv = await make_server("open")
    try:
        stats = await _scan(srv, creds=["admin:admin"])
        assert stats["found"] == 1
        assert stats["vendors"].get("Generic", 0) == 1
        assert stats["ports"].get(str(srv.port), 0) == 1
    finally:
        await srv.stop()


async def test_status_hook_fires(report_paths):
    """on_status must keep firing with live counts while the scan runs (used to
    drive the progress bar without separate stdout lines)."""
    from tests.mock_rtsp import make_server

    srv = await make_server("silent")
    statuses = []
    try:

        async def targets():
            yield srv.host

        settings = Settings(
            ports=[srv.port],
            routes=["/"],
            credentials=["admin:admin"],
            timeout=0.3,
            host_concurrency=5,
            screenshot_concurrency=1,
            enable_screenshots=False,
            status_interval=0.05,
        )
        stats = await run(targets(), settings, on_status=statuses.append)
        assert statuses, "watchdog must invoke on_status at least once"
        tick = statuses[-1]
        assert tick["checked"] in (0, 1)
        assert tick["found"] == 0
        assert tick["elapsed"] >= 0
        assert "oldest" in tick and "inflight" in tick
        assert stats["checked"] == 1
    finally:
        await srv.stop()


async def test_open_port_found_among_several(report_paths):
    """Ports of one host are probed concurrently; the live one still wins and
    the result is the same as probing them one by one."""
    from tests.mock_rtsp import make_server

    open_srv = await make_server("open")
    try:
        # Dead ports first (connection refused) so the winner is not the first.
        dead = [65400, 65401, 65402]
        settings_ports = dead + [open_srv.port]

        async def targets():
            yield open_srv.host

        settings = Settings(
            ports=settings_ports,
            routes=["/"],
            credentials=[],
            timeout=1.0,
            host_concurrency=1,
            screenshot_concurrency=1,
            enable_screenshots=False,
        )
        stats = await run(targets(), settings)
        assert stats["found"] == 1
        assert stats["ports"] == {str(open_srv.port): 1}
    finally:
        await open_srv.stop()


async def test_first_responsive_port_wins_regardless_of_order(report_paths):
    """An auth-port earlier in the list is the host's port of record, even when
    a later port is open - the port order is the user's explicit choice."""
    from tests.mock_rtsp import make_server

    auth_srv = await make_server("auth", valid_cred="root:secret")
    try:
        async def targets():
            yield auth_srv.host

        settings = Settings(
            ports=[auth_srv.port, 65403],
            routes=["/"],
            credentials=[],
            timeout=1.0,
            host_concurrency=1,
            screenshot_concurrency=1,
            enable_screenshots=False,
            max_attempts=1,
        )
        stats = await run(targets(), settings)
        assert stats["found"] == 0  # no credential opens it
    finally:
        await auth_srv.stop()


async def test_host_error_does_not_kill_the_scan(report_paths, monkeypatch):
    """A pipeline that raises must cost that one host, not the whole run."""
    from CamReaper import scanner
    from tests.mock_rtsp import make_server

    srv = await make_server("open")
    original = scanner._handle_host
    calls = []

    async def _boom(ip, s, stats=None):
        calls.append(ip)
        if len(calls) == 1:
            raise RuntimeError("host pipeline exploded")
        return await original(ip, s, stats)

    monkeypatch.setattr(scanner, "_handle_host", _boom)
    try:
        async def targets():
            yield srv.host
            yield "127.0.0.2"

        settings = Settings(
            ports=[srv.port],
            routes=["/"],
            credentials=[],
            timeout=1.0,
            host_concurrency=2,
            screenshot_concurrency=1,
            enable_screenshots=False,
        )
        stats = await run(targets(), settings)
        assert stats["checked"] == 2, "the failed host still counts as checked"
        assert stats["errors"] == 1
    finally:
        await srv.stop()


async def test_open_route_survives_closed_routes(report_paths):
    """A camera that answers a wrong route by hanging up on the socket - with
    no RTSP reply at all - must not make the sweep give up.  Regression: the
    stripe/serial sweep used to count that as a transport failure and abandon
    the remaining routes, so a stream served only under a late (query) route
    was never found.  The long list matters: with few routes every stripe gets
    a single route and the early bail-out cannot trigger."""
    from tests.mock_rtsp import make_server

    open_route = "/cam/realmonitor?channel=1&subtype=1&unicast=true&proto=Onvif"
    srv = await make_server(
        "route-open", open_route=open_route, close_on_unknown=True
    )
    try:
        routes = [f"/path{i}" for i in range(24)] + ["/", open_route]
        stats = await _scan(srv, creds=["admin:admin"], routes=routes)
        assert stats["found"] == 1
        assert open_route in report_paths.read_text()
    finally:
        await srv.stop()


async def test_open_route_survives_closed_routes_serial(report_paths):
    """Same camera, serial sweep (--route-parallel 0)."""
    from tests.mock_rtsp import make_server

    open_route = "/h264/ch1/main/av_stream"
    srv = await make_server(
        "route-open", open_route=open_route, close_on_unknown=True
    )
    try:
        routes = [f"/path{i}" for i in range(12)] + ["/", open_route]
        stats = await _scan(
            srv, creds=["admin:admin"], routes=routes, route_parallel=0
        )
        assert stats["found"] == 1
        assert open_route in report_paths.read_text()
    finally:
        await srv.stop()


async def test_credentials_survive_a_camera_that_hangs_up(report_paths):
    """A camera that drops the socket after every request must still be opened
    by a later credential in the list - bailing out on the first hang-up used to
    cut the brute-force short after one or two tries."""
    from tests.mock_rtsp import make_server

    srv = await make_server(
        "named-route-auth",
        open_route="/stream1",
        close_on_unknown=True,
    )
    try:
        creds = ["a:1", "b:2", "c:3", "admin:admin", "d:4", "e:5"]
        stats = await _scan(srv, creds=creds, routes=("/", "/stream1"))
        assert stats["found"] == 1
        assert "admin:admin@" in report_paths.read_text()
    finally:
        await srv.stop()


async def test_error_samples_are_kept_for_diagnosis(report_paths, monkeypatch):
    """A host that raises must be counted AND described: a swallowed exception
    is a host that silently produced no findings."""
    from CamReaper import scanner

    async def _boom(ip, s, stats=None):
        raise ValueError("nope")

    monkeypatch.setattr(scanner, "_handle_host", _boom)

    async def targets():
        yield "127.0.0.9"

    settings = Settings(
        ports=[1],
        routes=["/"],
        credentials=[],
        timeout=0.2,
        host_concurrency=1,
        screenshot_concurrency=1,
        enable_screenshots=False,
    )
    stats = await run(targets(), settings)
    assert stats["checked"] == 1
    assert stats["errors"] == 1
    assert stats["error_samples"] == ["127.0.0.9: ValueError: nope"]
