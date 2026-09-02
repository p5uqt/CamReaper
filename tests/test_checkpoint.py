import json
import time

import pytest

from CamReaper.__main__ import (
    CHECKPOINT_EVERY,
    _ips_path,
    _latest_checkpoint,
    _load_checkpoint,
    _resumed_targets,
    _write_checkpoint,
)


def test_ips_path():
    p = __import__("pathlib").Path("/x/check.json")
    assert _ips_path(p) == __import__("pathlib").Path("/x/check.json.ips")


async def test_resumed_targets_skips_checked(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("1.1.1.1\n2.2.2.2\n3.3.3.3\n")
    checked = {"2.2.2.2"}
    out = [ip async for ip in _resumed_targets(f, checked)]
    assert out == ["1.1.1.1", "3.3.3.3"]


def test_write_load_roundtrip(tmp_path):
    ck = tmp_path / "checkpoint.json"
    stats = {"checked": 7, "found": 2, "screenshots": 1}
    _write_checkpoint(ck, ["1.1.1.1", "2.2.2.2"], stats)
    _write_checkpoint(ck, ["3.3.3.3"], {"checked": 8, "found": 2, "screenshots": 1})
    loaded, ips = _load_checkpoint(ck)
    assert ips == {"1.1.1.1", "2.2.2.2", "3.3.3.3"}
    assert loaded["checked"] == 8
    # JSON only ever stores stats, IPs live in the companion file
    data = json.loads(ck.read_text())
    assert "checked_ips" not in data


def test_load_missing_degrades_gracefully(tmp_path):
    ck = tmp_path / "nope.json"
    stats, ips = _load_checkpoint(ck)
    assert stats == {"checked": 0, "found": 0, "screenshots": 0}
    assert ips == set()


def test_latest_checkpoint(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    reports = tmp_path / "reports"
    old = reports / "2026.01.01" / "checkpoint.json"
    new = reports / "2026.06.06" / "checkpoint.json"
    old.parent.mkdir(parents=True)
    new.parent.mkdir(parents=True)
    old.write_text("{}")
    new.write_text("{}")
    time.sleep(0.01)
    assert _latest_checkpoint() == new
    assert _latest_checkpoint().stat().st_mtime >= old.stat().st_mtime


def test_write_checkpoint_drains_pending(tmp_path):
    ck = tmp_path / "checkpoint.json"
    pending = ["1.1.1.1"]
    _write_checkpoint(ck, pending, {"checked": 1, "found": 0, "screenshots": 0})
    assert pending == []  # flushed once, not duplicated on a second flush
