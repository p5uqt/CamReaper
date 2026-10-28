"""Tests for the large-scan helpers: sharding, slicing, exclusion, counting,
rate limiting, structured findings and the CVE HTTP framing fixes."""

import asyncio
import hashlib
import json
import time

import pytest

from CamReaper import onvif, ratelimit, report
from CamReaper.cve import _read_chunked
from CamReaper.targets import (
    estimate_targets,
    iter_excluding,
    iter_shard,
    iter_slice,
    parse_exclusions,
)


async def _gen(values):
    for value in values:
        yield value


# --- target arithmetic / scheduling -----------------------------------------


def test_estimate_targets_is_arithmetic(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text(
        "1.2.3.4\n192.168.0.0/30\n10.0.0.1 - 10.0.0.3\ngarbage\n10.0.0.0/8\n"
    )
    # 1 + 4 + 3 + 16_777_216, and an /8 is counted without expanding it.
    assert estimate_targets(f) == 1 + 4 + 3 + 16777216


def test_estimate_targets_inline():
    assert estimate_targets("192.168.1.5/24") == 256
    assert estimate_targets("10.0.0.9-10.0.0.1") == 0  # reversed range


async def test_iter_shard_is_disjoint_and_complete():
    values = [str(i) for i in range(10)]
    shards = [
        [ip async for ip in iter_shard(_gen(values), index, 3)]
        for index in range(3)
    ]
    assert shards == [
        ["0", "3", "6", "9"],
        ["1", "4", "7"],
        ["2", "5", "8"],
    ]
    assert sorted(sum(shards, [])) == sorted(values)


async def test_iter_shard_single_is_passthrough():
    values = ["1", "2", "3"]
    assert [ip async for ip in iter_shard(_gen(values), 0, 1)] == values


async def test_iter_slice_skips_and_limits():
    values = [str(i) for i in range(10)]
    got = [ip async for ip in iter_slice(_gen(values), skip=3, limit=4)]
    assert got == ["3", "4", "5", "6"]
    assert [ip async for ip in iter_slice(_gen(values), skip=0, limit=0)] == values
    assert [ip async for ip in iter_slice(_gen(values), skip=99, limit=5)] == []


async def test_exclusions_cover_cidr_range_and_address():
    excluder = parse_exclusions(
        ["10.0.0.0/30", "192.168.5.5", "172.16.0.1-172.16.0.3"]
    )
    assert excluder  # non-empty
    values = [
        "10.0.0.0", "10.0.0.3", "10.0.0.4",
        "192.168.5.5", "192.168.5.6",
        "172.16.0.2", "172.16.0.4",
    ]
    kept = [ip async for ip in iter_excluding(_gen(values), excluder)]
    assert kept == ["10.0.0.4", "192.168.5.6", "172.16.0.4"]


async def test_exclusion_file_source(tmp_path):
    f = tmp_path / "exclude.txt"
    f.write_text("10.1.0.0/16\n# comment\n")
    excluder = parse_exclusions([f])
    assert "10.1.2.3" in excluder
    assert "10.2.0.1" not in excluder


# --- global rate limit -------------------------------------------------------


async def test_token_bucket_paces_after_the_burst():
    bucket = ratelimit.TokenBucket(rate=40.0, burst=1.0)
    start = time.monotonic()
    for _ in range(3):
        await bucket.acquire()
    elapsed = time.monotonic() - start
    # Two tokens beyond the burst need ~2/40s = 50ms.
    assert elapsed >= 0.035, f"not paced: {elapsed:.3f}s"
    assert elapsed < 1.0


async def test_configure_and_clear_global_limiter():
    ratelimit.configure(0)
    assert ratelimit.current() is None
    await ratelimit.acquire()  # no-op
    ratelimit.configure(10)
    assert ratelimit.current() is not None
    ratelimit.configure(0)
    assert ratelimit.current() is None


# --- CLI ---------------------------------------------------------------------


def test_cli_scale_flags_parse(tmp_path):
    from CamReaper.cli import parser

    f = tmp_path / "t.txt"
    f.write_text("1.2.3.4\n")
    args = parser.parse_args(
        [
            "-t", str(f),
            "--shard", "2/4",
            "--skip", "10",
            "--limit", "100",
            "--count-only",
            "--exclude", "10.0.0.0/8",
            "--rate-limit", "50",
            "--https-ports", "443", "9443",
        ]
    )
    assert args.shard == (1, 4)
    assert (args.skip, args.limit, args.count_only) == (10, 100, True)
    assert args.exclude == ["10.0.0.0/8"]
    assert args.rate_limit == 50.0
    assert args.https_ports == [443, 9443]


def test_cli_rejects_bad_shard():
    import argparse

    from CamReaper.cli import shard_arg

    with pytest.raises(argparse.ArgumentTypeError):
        shard_arg("0/4")
    with pytest.raises(argparse.ArgumentTypeError):
        shard_arg("5/4")
    with pytest.raises(argparse.ArgumentTypeError):
        shard_arg("2")


# --- structured findings -----------------------------------------------------


async def test_record_finding_writes_jsonl(tmp_path):
    findings = tmp_path / "findings.jsonl"
    report.FINDINGS_FILE = findings
    try:
        await report.record_finding(
            ip="10.0.0.1",
            port=554,
            route="/stream1",
            credentials="admin:admin",
            vendor="Hikvision",
            url="rtsp://admin:admin@10.0.0.1:554/stream1",
            cve_id="CVE-2017-7921",
        )
        await report.close_report_files()
    finally:
        report.FINDINGS_FILE = None
    record = json.loads(findings.read_text().strip())
    assert record["ip"] == "10.0.0.1"
    assert record["vendor"] == "Hikvision"
    assert record["cve_id"] == "CVE-2017-7921"
    assert record["url"].startswith("rtsp://")
    assert record["ts"].endswith("Z")


async def test_record_finding_disabled_by_default(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    report.FINDINGS_FILE = None
    await report.record_finding(
        ip="1.1.1.1", port=554, route="/", credentials=":",
        vendor="Generic", url="rtsp://1.1.1.1:554/",
    )
    assert not (tmp_path / "findings.jsonl").exists()


async def test_scan_writes_structured_findings(tmp_path):
    """The real pipeline must populate findings.jsonl, not just result.txt."""
    from CamReaper.scanner import Settings, run
    from tests.mock_rtsp import make_server

    srv = await make_server("open")
    report.RESULT_FILE = tmp_path / "result.txt"
    report.HTML_FILE = None
    report.FINDINGS_FILE = tmp_path / "findings.jsonl"
    try:
        async def targets():
            yield srv.host

        settings = Settings(
            ports=[srv.port],
            routes=["/"],
            credentials=[],
            timeout=1.0,
            host_concurrency=1,
            screenshot_concurrency=1,
            enable_screenshots=False,
        )
        stats = await run(targets(), settings)
        await report.close_report_files()
        assert stats["found"] == 1
        record = json.loads(
            (tmp_path / "findings.jsonl").read_text().strip().splitlines()[0]
        )
        assert record["ip"] == srv.host
        assert record["port"] == srv.port
        assert record["vendor"] == "Generic"
        assert record["url"].startswith("rtsp://")
    finally:
        report.RESULT_FILE = None
        report.FINDINGS_FILE = None
        await srv.stop()


def test_count_only_creates_no_report(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "sys.argv", ["CamReaper", "-t", "10.0.0.0/24", "--count-only"]
    )
    from CamReaper.__main__ import main

    main()
    out = capsys.readouterr().out
    assert "ips=256" in out
    assert not (tmp_path / "reports").exists()


def test_report_folders_never_collide(tmp_path):
    """Two runs started in the same second must not overwrite each other."""
    from CamReaper.__main__ import _new_report_folder

    root = tmp_path / "reports"
    first = _new_report_folder(root, "2026.01.01-00.00.00")
    second = _new_report_folder(root, "2026.01.01-00.00.00")
    assert first != second
    assert first.is_dir() and second.is_dir()
    assert second.name.endswith("-2")


# --- CVE HTTP chunked decoding ----------------------------------------------


class _Reader:
    def __init__(self, data: bytes):
        self.data = data

    async def read(self, n: int) -> bytes:
        chunk, self.data = self.data[:n], self.data[n:]
        return chunk


async def test_chunked_body_already_partly_read_is_parsed():
    """The first bytes after the headers are chunk data, not decoded body.

    Regression: ``_read_chunked`` was passed ``len(rest)`` instead of ``rest``,
    so a chunked response whose first chunk arrived with the headers was
    decoded from a zero-filled buffer and every pattern match missed.
    """
    body = await _read_chunked(
        _Reader(b""), 1.0, b"5\r\nhello\r\n0\r\n\r\n"
    )
    assert body == b"hello"


async def test_chunked_body_split_across_reads():
    body = await _read_chunked(
        _Reader(b"lo\r\n6\r\n world\r\n0\r\n\r\n"), 1.0, b"5\r\nhel"
    )
    assert body == b"hello world"


async def test_chunked_extensions_and_cap():
    body = await _read_chunked(
        _Reader(b""), 1.0, b"5;foo=bar\r\nhello\r\n0\r\n\r\n"
    )
    assert body == b"hello"
    # A declared size far beyond the body cap must not make us read forever.
    capped = await _read_chunked(_Reader(b""), 1.0, b"FFFFFF\r\nshort")
    assert capped == b"short"


async def test_http_request_decodes_chunked_body_end_to_end():
    """Regression: the body often starts in the same read as the headers."""
    from CamReaper.cve import _http_request

    async def handler(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Server: MockPanel\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
                b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
            )
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        status, server_header, body = await _http_request(
            "127.0.0.1", port, "/", timeout=1.0
        )
    finally:
        server.close()
        await server.wait_closed()
    assert status == "200"
    assert server_header == "MockPanel"
    assert body == "hello world"


# --- ONVIF digest algorithms -------------------------------------------------


def test_digest_response_supports_sha512_256():
    params = onvif._parse_digest_challenge(
        'Digest realm="r", nonce="n1", qop="auth", algorithm=SHA-512-256'
    )
    got = onvif._digest_response(params, "admin", "pw", "POST", "/x")
    cnonce = got.split('cnonce="')[1].split('"')[0]
    try:
        h = lambda b: hashlib.new("sha512_256", b).hexdigest()
    except ValueError:  # pragma: no cover - old OpenSSL
        h = lambda b: hashlib.sha512(b).hexdigest()[:64]
    ha1 = h(b"admin:r:pw")
    ha2 = h(b"POST:/x")
    want = h(f"{ha1}:n1:00000001:{cnonce}:auth:{ha2}".encode())
    assert f'response="{want}"' in got


def test_digest_response_supports_sess_algorithm():
    params = onvif._parse_digest_challenge(
        'Digest realm="r", nonce="n1", qop="auth", algorithm=MD5-sess'
    )
    got = onvif._digest_response(params, "admin", "pw", "POST", "/x")
    cnonce = got.split('cnonce="')[1].split('"')[0]
    base = hashlib.md5(b"admin:r:pw").hexdigest()
    ha1 = hashlib.md5(f"{base}:n1:{cnonce}".encode()).hexdigest()
    ha2 = hashlib.md5(b"POST:/x").hexdigest()
    want = hashlib.md5(
        f"{ha1}:n1:00000001:{cnonce}:auth:{ha2}".encode()
    ).hexdigest()
    assert f'response="{want}"' in got
    assert "algorithm=MD5-SESS" in got


def test_digest_response_does_not_claim_auth_int():
    """auth-int needs a body hash; using qop=auth for it would be wrong."""
    params = onvif._parse_digest_challenge(
        'Digest realm="r", nonce="n1", qop="auth-int", algorithm=MD5'
    )
    got = onvif._digest_response(params, "admin", "pw", "POST", "/x")
    assert "qop=" not in got


# --- gallery / report URL parsing -------------------------------------------


def test_split_url_keeps_username_only_credentials():
    from CamReaper.gallery import _split_url

    assert _split_url("rtsp://admin@1.2.3.4:554/stream") == (
        "1.2.3.4", 554, "admin:", "/stream"
    )


def test_split_url_handles_ipv6():
    from CamReaper.gallery import _split_url

    assert _split_url("rtsp://admin:pw@[2001:db8::1]:8554/s") == (
        "2001:db8::1", 8554, "admin:pw", "/s"
    )
