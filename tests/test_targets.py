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
