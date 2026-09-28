import json
from pathlib import Path

import pytest

from CamReaper import report
from CamReaper.cve import (
    CVEDatabase,
    find_backdoor_stream,
    try_backdoor_creds,
    run_cve_stage,
    try_http_probe,
    probe_http_host,
)
from CamReaper.vendor import detect_vendor_http
from CamReaper.scanner import Settings, run
from CamReaper.rtsp import RTSPClient

pytestmark = pytest.mark.asyncio


@pytest.fixture
def report_paths(tmp_path):
    report.RESULT_FILE = tmp_path / "result.txt"
    report.HTML_FILE = None
    report.RESULT_FILE.touch()
    yield report.RESULT_FILE
    report.RESULT_FILE = None
    report.HTML_FILE = None
    report.CVE_LOG_FILE = None


@pytest.fixture
def sample_db(tmp_path):
    db = {
        "cves": [
            {
                "id": "CVE-2017-7921",
                "vendor": "Hikvision",
                "type": "backdoor_creds",
                "description": "Hikvision backdoor",
                "credentials": ["admin:Hik@2014", "root:himaster"],
                "severity": "critical",
            },
            {
                "id": "CVE-2021-36260",
                "vendor": "Dahua",
                "type": "backdoor_creds",
                "description": "Dahua backdoor",
                "credentials": ["admin:admin"],
                "severity": "critical",
            },
            {
                "id": "CVE-2017-7921-http",
                "vendor": "Hikvision",
                "type": "http_probe",
                "description": "Hikvision config download",
                "url_path": "/SDK/config",
                "method": "GET",
                "success_patterns": ["<Configuration>"],
                "severity": "high",
            },
        ]
    }
    p = tmp_path / "cve_db.json"
    p.write_text(json.dumps(db), encoding="utf-8")
    return p


async def test_database_loads_entries(sample_db):
    db = CVEDatabase(sample_db)
    assert len(db.entries) == 3
    assert set(db.by_vendor.keys()) == {"Hikvision", "Dahua"}


async def test_get_for_vendor(sample_db):
    db = CVEDatabase(sample_db)
    hik = db.get_for_vendor("Hikvision")
    assert len(hik) == 2
    assert all(e.vendor == "Hikvision" for e in hik)


async def test_get_all_creds(sample_db):
    db = CVEDatabase(sample_db)
    creds = db.get_all_creds("Hikvision")
    assert "admin:Hik@2014" in creds
    assert "root:himaster" in creds
    # no backdoor creds from the http_probe entry
    assert len(db.get_all_creds("Hikvision")) == 2


async def test_database_missing_file(tmp_path):
    db = CVEDatabase(tmp_path / "nonexistent.json")
    assert len(db.entries) == 0
    assert db.get_for_vendor("Hikvision") == []


async def test_get_all_creds_all_vendors(sample_db):
    db = CVEDatabase(sample_db)
    all_creds = db.get_all_creds()
    assert "admin:Hik@2014" in all_creds
    assert "admin:admin" in all_creds


async def test_backdoor_creds_success(report_paths, sample_db):
    """A camera whose valid credential matches a backdoor_creds CVE entry must
    be crackable via the CVE stage."""
    from tests.mock_rtsp import make_server

    srv = await make_server("scanner", valid_cred="admin:Hik@2014")
    try:
        db = CVEDatabase(sample_db)
        client = RTSPClient(srv.host, srv.port, 1.0, ":")
        await client.connect()
        # Hikvision backdoor_creds entry
        entry = db.get_for_vendor("Hikvision")[0]
        cred = await try_backdoor_creds(client, entry)
        assert cred == "admin:Hik@2014"
        client.close()
    finally:
        await srv.stop()


async def test_backdoor_creds_failure(report_paths, sample_db):
    """A camera whose valid credential is NOT in the CVE db must fail."""
    from tests.mock_rtsp import make_server

    srv = await make_server("scanner", valid_cred="root:secret")
    try:
        db = CVEDatabase(sample_db)
        client = RTSPClient(srv.host, srv.port, 1.0, ":")
        await client.connect()
        entry = db.get_for_vendor("Hikvision")[0]
        cred = await try_backdoor_creds(client, entry)
        assert cred is None
        client.close()
    finally:
        await srv.stop()


async def test_run_cve_stage_finds_stream(report_paths, sample_db):
    """run_cve_stage must return a Found stream when a backdoor cred works."""
    from tests.mock_rtsp import make_server

    srv = await make_server("scanner", valid_cred="admin:Hik@2014")
    try:
        db = CVEDatabase(sample_db)
        client = RTSPClient(srv.host, srv.port, 1.0, ":")
        await client.connect()
        report.CVE_LOG_FILE = None
        found = await run_cve_stage(srv.host, client, "Hikvision", db)
        assert len(found) == 1
        assert found[0].credentials == "admin:Hik@2014"
        assert found[0].vendor == "Hikvision"
        assert found[0].port == srv.port
        client.close()
    finally:
        await srv.stop()


async def test_run_cve_stage_unknown_vendor(report_paths, sample_db):
    """An unknown vendor should get no CVE exploits and return nothing."""
    from tests.mock_rtsp import make_server

    srv = await make_server("scanner", valid_cred="admin:Hik@2014")
    try:
        db = CVEDatabase(sample_db)
        client = RTSPClient(srv.host, srv.port, 1.0, ":")
        # Don't connect: for an unknown vendor run_cve_stage returns [] before
        # ever using the connection, so no stranded handler task holds stop().
        found = await run_cve_stage(srv.host, client, "UnknownVendor", db)
        assert found == []
        client.close()
    finally:
        await srv.stop()


async def test_http_probe_success(sample_db):
    """An http_probe entry that matches should return True."""
    server = None
    try:
        import asyncio

        def _fake_server(reader, writer):
            async def _handle():
                try:
                    await reader.read(65536)
                    writer.write(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n"
                        b"<Configuration><Version>4.0</Version></Configuration>"
                    )
                    await writer.drain()
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

            asyncio.ensure_future(_handle())

        server = await asyncio.start_server(_fake_server, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        db = CVEDatabase(sample_db)
        entry = db.get_for_vendor("Hikvision")[1]  # http_probe entry
        assert entry.type == "http_probe"
        ok = await try_http_probe("127.0.0.1", port, entry)
        assert ok is True
    finally:
        if server:
            server.close()
            await server.wait_closed()


async def test_http_probe_no_match(sample_db):
    """An http_probe entry with no matching pattern should return False."""
    server = None
    try:
        import asyncio

        def _fake_server(reader, writer):
            async def _handle():
                try:
                    await reader.read(65536)
                    writer.write(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found"
                    )
                    await writer.drain()
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

            asyncio.ensure_future(_handle())

        server = await asyncio.start_server(_fake_server, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        db = CVEDatabase(sample_db)
        entry = db.get_for_vendor("Hikvision")[1]
        ok = await try_http_probe("127.0.0.1", port, entry)
        assert ok is False
    finally:
        if server:
            server.close()
            await server.wait_closed()


async def test_http_probe_connection_refused():
    """Connection refused should return False gracefully."""
    db = CVEDatabase()
    # Use a real entry from the built-in db
    entries = db.get_for_vendor("Hikvision")
    http_entries = [e for e in entries if e.type == "http_probe"]
    if http_entries:
        ok = await try_http_probe("127.0.0.1", 1, http_entries[0])
        assert ok is False


async def test_cve_mode_scanner_integration(report_paths, sample_db):
    """A scan in cve mode with a camera whose cred matches a backdoor CVE."""
    from tests.mock_rtsp import make_server

    mocks = await make_server("scanner", valid_cred="admin:Hik@2014", server_header="Hikvision")
    try:
        db = CVEDatabase(sample_db)

        async def targets():
            yield mocks.host

        settings = Settings(
            ports=[mocks.port],
            routes=["/"],
            credentials=["admin:admin", "root:root"],
            timeout=1.0,
            host_concurrency=5,
            screenshot_concurrency=1,
            enable_screenshots=False,
            mode="cve",
            cve_db=db,
        )
        stats = await run(targets(), settings)
        # found because the CVE backdoor cred matches (admin:Hik@2014)
        assert stats["found"] == 1
        assert "admin:Hik@2014@127.0.0.1" in report_paths.read_text()
    finally:
        await mocks.stop()


async def test_combined_mode_cve_first(report_paths, sample_db):
    """In combined mode, a camera whose backdoor CVE matches is found via CVE,
    without falling through to the (failing) credential brute-force."""
    from tests.mock_rtsp import make_server

    mocks = await make_server("scanner", valid_cred="admin:Hik@2014", server_header="Hikvision")
    try:
        db = CVEDatabase(sample_db)

        async def targets():
            yield mocks.host

        settings = Settings(
            ports=[mocks.port],
            routes=["/"],
            credentials=["user:wrong", "nope:wrong"],
            timeout=1.0,
            host_concurrency=5,
            screenshot_concurrency=1,
            enable_screenshots=False,
            mode="combined",
            cve_db=db,
        )
        stats = await run(targets(), settings)
        # CVE found it before brute-force was tried
        assert stats["found"] == 1
        assert "admin:Hik@2014@127.0.0.1" in report_paths.read_text()
    finally:
        await mocks.stop()


async def test_brute_mode_ignores_cve(report_paths, sample_db):
    """In default brute mode, the CVE stage is skipped."""
    from tests.mock_rtsp import make_server

    mocks = await make_server("scanner", valid_cred="admin:Hik@2014")
    try:
        db = CVEDatabase(sample_db)

        async def targets():
            yield mocks.host

        settings = Settings(
            ports=[mocks.port],
            routes=["/"],
            credentials=["user:wrong", "nope:wrong"],
            timeout=1.0,
            host_concurrency=5,
            screenshot_concurrency=1,
            enable_screenshots=False,
            mode="brute",
            cve_db=db,
        )
        stats = await run(targets(), settings)
        # creds list doesn't contain admin:Hik@2014, so not found in brute mode
        assert stats["found"] == 0
    finally:
        await mocks.stop()


async def test_cve_log_records_success(report_paths, sample_db, tmp_path):
    """cve_log.txt must record SUCCESS when a backdoor CVE matches."""
    from tests.mock_rtsp import make_server

    log = tmp_path / "cve_log.txt"
    report.CVE_LOG_FILE = log
    mocks = await make_server("scanner", valid_cred="admin:Hik@2014")
    try:
        db = CVEDatabase(sample_db)
        client = RTSPClient(mocks.host, mocks.port, 1.0, ":")
        await client.connect()
        await run_cve_stage(mocks.host, client, "Hikvision", db)
        client.close()
        await report.close_report_files()
        text = log.read_text()
        assert "CVE-2017-7921" in text
        assert "SUCCESS" in text
        assert mocks.host in text
    finally:
        await mocks.stop()
        report.CVE_LOG_FILE = None


async def test_detect_vendor_http_header_and_body():
    """detect_vendor_http must fingerprint from the body and Server header."""
    assert detect_vendor_http("", "<html>Hikvision web panel</html>") == "Hikvision"
    assert detect_vendor_http("Dahua", "") == "Dahua"
    assert detect_vendor_http("nginx", "") == "Generic"


async def test_probe_http_host_finds_hit(report_paths, sample_db, tmp_path):
    """probe_http_host returns an HTTP CVE hit when the panel is vulnerable."""
    from tests.mock_http import make_server

    report.HTTP_CVE_FILE = tmp_path / "http_cve.txt"
    report.HTTP_CVE_FILE.touch()
    srv = await make_server({
        "/SDK/config": (200, "<Configuration>Hikvision panel</Configuration>"),
        "/": (200, "Hikvision web"),
    })
    try:
        db = CVEDatabase(sample_db)
        found = await probe_http_host("127.0.0.1", srv.port, db)
        assert any(f.is_http_cve for f in found)
        hit = [f for f in found if f.is_http_cve][0]
        assert hit.cve_id == "CVE-2017-7921-http"
        assert hit.port == srv.port
    finally:
        await srv.stop()
        report.HTTP_CVE_FILE = None


async def test_probe_http_host_no_match(report_paths, sample_db):
    """A panel with no matching patterns yields no hits."""
    from tests.mock_http import make_server

    srv = await make_server({
        "/SDK/config": (200, "nothing useful here"),
        "/": (200, "Hikvision web"),
    })
    try:
        db = CVEDatabase(sample_db)
        found = await probe_http_host("127.0.0.1", srv.port, db)
        assert found == []
    finally:
        await srv.stop()


async def test_probe_http_host_connection_refused(report_paths, sample_db):
    """No HTTP server -> no hits, graceful."""
    db = CVEDatabase(sample_db)
    found = await probe_http_host("127.0.0.1", 1, db)
    assert found == []


async def test_http_fallback_end_to_end(report_paths, sample_db, tmp_path):
    """When the RTSP port is dead but HTTP is vulnerable, the scanner must log
    the HTTP CVE hit in http_cve.txt (not result.txt) and count http_found."""
    from tests.mock_http import make_server

    http = await make_server({
        "/SDK/config": (200, "<Configuration>Hikvision panel</Configuration>"),
        "/": (200, "Hikvision web"),
    })
    report.HTTP_CVE_FILE = tmp_path / "http_cve.txt"
    report.HTTP_CVE_FILE.touch()
    report.CVE_LOG_FILE = tmp_path / "cve_log.txt"
    report.CVE_LOG_FILE.touch()
    try:
        db = CVEDatabase(sample_db)

        async def targets():
            yield "127.0.0.1"

        settings = Settings(
            # no RTSP port open on this host
            ports=[1],
            routes=["/"],
            credentials=["a:b"],
            timeout=1.0,
            host_concurrency=5,
            screenshot_concurrency=1,
            enable_screenshots=False,
            mode="combined",
            cve_db=db,
            http_ports=[http.port],
        )
        stats = await run(targets(), settings)
        assert stats["found"] == 0  # no RTSP stream
        assert stats["http_found"] >= 1
        assert stats["http_checked"] >= 1
        await report.close_report_files()
        assert "CVE-2017-7921-http" in report.HTTP_CVE_FILE.read_text()
        # the substring must NOT be in result.txt
        assert "CVE" not in report_paths.read_text()
    finally:
        await http.stop()
        report.HTTP_CVE_FILE = None
        report.CVE_LOG_FILE = None


async def test_no_http_flag_disables_fallback(report_paths, sample_db, tmp_path):
    """With no_http=True the scanner must not probe HTTP at all."""
    from tests.mock_http import make_server

    http = await make_server({
        "/SDK/config": (200, "<Configuration>Hikvision panel</Configuration>"),
        "/": (200, "Hikvision web"),
    })
    try:
        db = CVEDatabase(sample_db)

        async def targets():
            yield "127.0.0.1"

        settings = Settings(
            ports=[1],
            routes=["/"],
            credentials=["a:b"],
            timeout=1.0,
            host_concurrency=5,
            screenshot_concurrency=1,
            enable_screenshots=False,
            mode="combined",
            cve_db=db,
            http_ports=[http.port],
            no_http=True,
        )
        stats = await run(targets(), settings)
        assert stats["http_checked"] == 0
        assert stats["http_found"] == 0
    finally:
        await http.stop()


async def test_http_cve_hit_does_not_skip_brute_force(
    report_paths, sample_db, tmp_path, monkeypatch
):
    """A vulnerable web panel on a host that also answers RTSP must not stop
    the credential brute-force: only a confirmed RTSP stream ends stage 3."""
    from CamReaper import cve as cve_mod
    from tests.mock_http import make_server
    from tests.mock_rtsp import make_server as make_rtsp

    rtsp = await make_rtsp("scanner", valid_cred="admin:admin", server_header="Hikvision")
    http = await make_server({
        "/SDK/config": (200, "<Configuration>Hikvision panel</Configuration>"),
        "/": (200, "Hikvision web"),
    })
    report.HTTP_CVE_FILE = tmp_path / "http_cve.txt"
    report.HTTP_CVE_FILE.touch()
    report.CVE_LOG_FILE = None
    try:
        db = CVEDatabase(sample_db)

        async def targets():
            yield rtsp.host

        settings = Settings(
            ports=[rtsp.port],
            routes=["/"],
            credentials=["admin:admin"],
            timeout=1.0,
            host_concurrency=1,
            screenshot_concurrency=1,
            enable_screenshots=False,
            mode="combined",
            cve_db=db,
            http_ports=[http.port],
        )
        stats = await run(targets(), settings)
        # The HTTP panel is vulnerable...
        assert stats["http_found"] == 1
        # ...and the plain credential still opens RTSP, because stage 3 fell
        # through to the brute-force.
        assert stats["found"] == 1
        assert stats["cve_found"] == 0, "an HTTP hit is not a CVE-found stream"
        assert "admin:admin@127.0.0.1" in report_paths.read_text()
    finally:
        await rtsp.stop()
        await http.stop()
        report.HTTP_CVE_FILE = None


async def test_rtsp_cve_hit_still_stops_the_host(report_paths, sample_db, tmp_path):
    """A backdoor credential that opens RTSP ends the host pipeline: the
    brute-force is skipped and the hit is counted as a CVE stream."""
    from tests.mock_rtsp import make_server

    rtsp = await make_server(
        "scanner", valid_cred="admin:Hik@2014", server_header="Hikvision"
    )
    report.CVE_LOG_FILE = None
    try:
        db = CVEDatabase(sample_db)

        async def targets():
            yield rtsp.host

        settings = Settings(
            ports=[rtsp.port],
            routes=["/"],
            credentials=["admin:admin"],
            timeout=1.0,
            host_concurrency=1,
            screenshot_concurrency=1,
            enable_screenshots=False,
            mode="combined",
            cve_db=db,
        )
        stats = await run(targets(), settings)
        assert stats["found"] == 1
        assert stats["cve_found"] == 1
        assert stats["http_found"] == 0
        assert "admin:Hik@2014@127.0.0.1" in report_paths.read_text()
    finally:
        await rtsp.stop()


# --- shipped database integrity ---------------------------------------------


async def test_every_cve_vendor_is_detectable():
    """A CVE entry whose vendor has no signature in vendors.json is dead code:
    detect_vendor can never return that name, so the entry is never reached."""
    from CamReaper.vendor import _load_vendors

    vendors, _compiled = _load_vendors()
    known = {v["vendor"] for v in vendors}
    db = CVEDatabase()
    unreachable = sorted({
        e.vendor for e in db.entries if e.vendor not in known
    })
    assert unreachable == []


async def test_generic_vendor_is_last_in_signature_table():
    """Generic matches unconditionally, so evaluating it before a real
    signature would swallow every host."""
    from CamReaper.vendor import _load_vendors

    _vendors, compiled = _load_vendors()
    names = [row[0] for row in compiled]
    assert names[-1] == "Generic"
    assert names.count("Generic") == 1


async def test_shipped_db_has_generic_backdoor_entry():
    """An unidentified camera must still be checked against factory defaults."""
    db = CVEDatabase()
    generic = [
        e for e in db.get_for_vendor("Generic") if e.type == "backdoor_creds"
    ]
    assert len(generic) == 1
    assert len(generic[0].credentials) > 5
    assert "admin:admin" in generic[0].credentials


# --- credential de-duplication ----------------------------------------------


async def test_find_backdoor_stream_skips_already_tried_credentials(report_paths,
                                                                 sample_db):
    """The same default password is listed by many CVE entries; re-sending it
    costs RTSP round-trips and cannot change the outcome."""
    from tests.mock_rtsp import make_server

    srv = await make_server("scanner", valid_cred="nobody:nothing")
    try:
        db = CVEDatabase(sample_db)
        client = RTSPClient(srv.host, srv.port, 1.0, ":")
        await client.connect()
        entry = db.get_for_vendor("Hikvision")[0]
        # admin:admin is Dahua's credential, not this entry's - pre-tried.
        assert await find_backdoor_stream(
            client, entry, skip={"admin:admin"}
        ) is None
        client.close()
    finally:
        await srv.stop()


async def test_run_cve_stage_never_retries_a_credential(report_paths, tmp_path):
    """Across the whole entry list each credential must be sent at most once."""
    from tests.mock_rtsp import make_server

    db_path = tmp_path / "cve_db.json"
    db_path.write_text(json.dumps({"cves": [
        {"id": "A", "vendor": "Hikvision", "type": "backdoor_creds",
         "description": "", "severity": "high",
         "credentials": ["a:1", "b:2"]},
        {"id": "B", "vendor": "Hikvision", "type": "backdoor_creds",
         "description": "", "severity": "high",
         "credentials": ["b:2", "c:3"]},
    ]}), encoding="utf-8")

    srv = await make_server("scanner", valid_cred="nobody:nothing")
    seen = []
    original = RTSPClient.connect

    def _spy(self):
        seen.append(self.credentials)
        return original(self)

    RTSPClient.connect = _spy
    try:
        db = CVEDatabase(db_path)
        client = RTSPClient(srv.host, srv.port, 1.0, ":")
        await client.connect()
        report.CVE_LOG_FILE = None
        seen.clear()
        await run_cve_stage(srv.host, client, "Hikvision", db, 8, 0.05, {},
                            http_ports=[], routes=["/"])
        creds = [c for c in seen if c]
        assert creds == ["a:1", "b:2", "c:3"]
        assert len(creds) == len(set(creds))
        client.close()
    finally:
        RTSPClient.connect = original
        await srv.stop()


async def test_run_cve_stage_generic_fallback_for_vendor_without_backdoor(
    report_paths, tmp_path,
):
    """A vendor with no backdoor entry of its own still gets the shared
    factory-default list instead of being skipped."""
    from tests.mock_rtsp import make_server

    db_path = tmp_path / "cve_db.json"
    db_path.write_text(json.dumps({"cves": [
        {"id": "A", "vendor": "Hikvision", "type": "backdoor_creds",
         "description": "", "severity": "high",
         "credentials": ["root:toor"]},
        {"id": "GEN", "vendor": "Generic", "type": "backdoor_creds",
         "description": "", "severity": "high",
         "credentials": ["admin:defaultpw"]},
    ]}), encoding="utf-8")

    srv = await make_server("scanner", valid_cred="admin:defaultpw")
    try:
        db = CVEDatabase(db_path)
        client = RTSPClient(srv.host, srv.port, 1.0, ":")
        await client.connect()
        report.CVE_LOG_FILE = None
        # "Axis" has no entry at all -> must fall back to the Generic list.
        found = await run_cve_stage(
            srv.host, client, "Axis", db, 8, 0.05, {},
            http_ports=[], routes=["/"],
        )
        assert len(found) == 1
        assert found[0].credentials == "admin:defaultpw"
        client.close()
    finally:
        await srv.stop()


async def test_run_cve_stage_own_backdoor_wins_over_generic(report_paths, tmp_path):
    """A vendor that does ship backdoor credentials must not also get the
    generic list appended - its own list is the authoritative one."""
    from tests.mock_rtsp import make_server

    db_path = tmp_path / "cve_db.json"
    db_path.write_text(json.dumps({"cves": [
        {"id": "A", "vendor": "Hikvision", "type": "backdoor_creds",
         "description": "", "severity": "high",
         "credentials": ["root:toor"]},
        {"id": "GEN", "vendor": "Generic", "type": "backdoor_creds",
         "description": "", "severity": "high",
         "credentials": ["admin:defaultpw"]},
    ]}), encoding="utf-8")

    srv = await make_server("scanner", valid_cred="admin:defaultpw")
    seen = []
    original = RTSPClient.connect
    RTSPClient.connect = lambda self: (seen.append(self.credentials),
                                       original(self))[1]
    try:
        db = CVEDatabase(db_path)
        client = RTSPClient(srv.host, srv.port, 1.0, ":")
        await client.connect()
        report.CVE_LOG_FILE = None
        seen.clear()
        found = await run_cve_stage(
            srv.host, client, "Hikvision", db, 8, 0.05, {},
            http_ports=[], routes=["/"],
        )
        assert found == []
        assert "admin:defaultpw" not in seen
        client.close()
    finally:
        RTSPClient.connect = original
        await srv.stop()
