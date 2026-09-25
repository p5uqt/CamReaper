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
