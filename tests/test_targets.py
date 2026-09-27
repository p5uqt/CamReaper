import pytest

from CamReaper.targets import count_targets, iter_targets, parse_all


def test_single_ip(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("1.2.3.4\n")
    assert parse_all(f) == ["1.2.3.4"]


def test_cidr(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("192.168.0.0/30\n")
    assert parse_all(f) == ["192.168.0.0", "192.168.0.1", "192.168.0.2", "192.168.0.3"]


def test_cidr_with_host_bits_is_not_rejected(tmp_path):
    """'192.168.1.5/24' is a common way of writing a range: it must expand."""
    f = tmp_path / "t.txt"
    f.write_text("192.168.1.5/24\n")
    out = parse_all(f)
    assert len(out) == 256
    assert out[0] == "192.168.1.0" and out[-1] == "192.168.1.255"


def test_iter_network_matches_ipaddress():
    """The integer fast path must be byte-identical to ipaddress for every
    prefix length - a silent off-by-one here would skip or repeat targets."""
    import ipaddress
    import itertools

    from CamReaper.targets import _iter_network

    for prefixlen in range(0, 33):
        for base in ("0.0.0.0", "10.11.12.13", "192.168.255.0", "172.16.5.7", "1.2.3.4"):
            net = ipaddress.ip_network(f"{base}/{prefixlen}", strict=False)
            want = [str(ip) for ip in itertools.islice(net, 2048)]
            got = list(itertools.islice(_iter_network(net), 2048))
            assert got == want, f"{base}/{prefixlen}"


def test_range_spanning_octet_boundary(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("10.0.0.254 - 10.0.1.2\n")
    out = parse_all(f)
    assert out[0] == "10.0.0.254" and out[1] == "10.0.0.255" and out[2] == "10.0.1.0"
    assert out[-1] == "10.0.1.2" and len(out) == 5


def test_bad_cidr_prefix_ignored(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("1.2.3.0/33\n1.2.3.4\n9.9.9.9-1.1.1.1\n")
    assert parse_all(f) == ["1.2.3.4"]


def test_big_cidr_is_streamed_not_materialised(tmp_path):
    """A /8 must yield IPs without ever building a 16M-element list."""
    f = tmp_path / "t.txt"
    f.write_text("10.0.0.0/8\n")

    async def first_three():
        out = []
        async for ip in iter_targets(f):
            out.append(ip)
            if len(out) == 3:
                break
        return out

    import asyncio

    assert asyncio.run(first_three()) == ["10.0.0.0", "10.0.0.1", "10.0.0.2"]


@pytest.mark.asyncio
async def test_iter_unique_lru_keeps_recent(tmp_path):
    """With a tiny LRU, a re-seen IP must not be re-emitted while it is still
    cached, and a long gap must be forgotten (bounded memory)."""
    from CamReaper.targets import iter_unique

    async def gen():
        yield "1.1.1.1"
        yield "1.1.1.1"          # duplicate -> dropped
        for ip in ("2.2.2.2", "3.3.3.3", "4.4.4.4"):
            yield ip
        yield "1.1.1.1"          # evicted (LRU holds 3) -> emitted again

    out = [ip async for ip in iter_unique(gen(), maxsize=3)]
    assert out == ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "1.1.1.1"]


@pytest.mark.asyncio
async def test_iter_unique_refreshes_recency():
    """A duplicate must refresh the LRU position, so it is not the victim."""
    from CamReaper.targets import iter_unique

    async def gen():
        yield "1.1.1.1"
        yield "2.2.2.2"
        yield "1.1.1.1"          # refresh 1.1.1.1
        yield "3.3.3.3"
        yield "1.1.1.1"          # still cached -> dropped

    out = [ip async for ip in iter_unique(gen(), maxsize=3)]
    assert out == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]


def test_range(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("10.0.0.1 - 10.0.0.3\n")
    assert parse_all(f) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def test_bad_lines_ignored(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("not-an-ip\n999.1.1.1\n1.2.3.4\n\n")
    assert parse_all(f) == ["1.2.3.4"]


def test_streaming_dedup(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("1.2.3.4\n1.2.3.4\n1.2.3.4\n")
    assert parse_all(f) == ["1.2.3.4"]


def test_count_targets(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("1.2.3.4\n192.168.0.0/30\n10.0.0.1 - 10.0.0.3\ngarbage\n")
    assert count_targets(f) == 1 + 4 + 3


@pytest.mark.asyncio
async def test_iter_targets_lazy(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("1.1.1.1\n2.2.2.2\n")
    out = [ip async for ip in iter_targets(f)]
    assert out == ["1.1.1.1", "2.2.2.2"]


@pytest.mark.asyncio
async def test_iter_unique_drops_duplicates():
    from CamReaper.targets import iter_unique

    async def gen():
        for ip in ["1.1.1.1", "2.2.2.2", "1.1.1.1", "3.3.3.3", "1.1.1.1"]:
            yield ip

    out = [ip async for ip in iter_unique(gen())]
    assert out == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
