"""Streaming target generation.

Unlike materialising every resolved IP into a deque (a memory bomb on big
CIDRs), this module yields targets lazily as an async generator.  Only a
bounded pool of active host-tasks is kept in flight.
"""

import ipaddress
from collections import OrderedDict
from pathlib import Path
from typing import AsyncIterator, List


def _parse_line(line: str) -> List[str]:
    """Return a list of IP strings for one input line.

    Supported forms:
        1) 1.2.3.4
        2) 192.168.0.0/24
        3) 1.2.3.4 - 5.6.7.8
    Any non-IP value is ignored.
    """
    line = line.strip()
    if not line:
        return []
    try:
        if "-" in line:
            left, right = line.split("-", 1)
            ranges = ipaddress.summarize_address_range(
                ipaddress.IPv4Address(left.strip()),
                ipaddress.IPv4Address(right.strip()),
            )
            return [str(ip) for r in ranges for ip in r]
        if "/" in line:
            network = ipaddress.ip_network(line)
            return [str(ip) for ip in network]
        return [str(ipaddress.ip_address(line))]
    except ValueError:
        return []


async def iter_targets(path: Path) -> AsyncIterator[str]:
    """Yield each target IP string lazily (streaming, never fully in RAM)."""
    with path.open("r", encoding="utf-8") as handle:
        for raw in handle:
            for ip in _parse_line(raw):
                yield ip


async def iter_unique(
    agen: AsyncIterator[str], maxsize: int = 1_000_000
) -> AsyncIterator[str]:
    """Stream ``agen`` but drop duplicate IPs, bounded by an LRU of ``maxsize``.

    Overlapping CIDRs / ranges would otherwise scan the same IP twice (which
    duplicates both scan time and report lines).  The cache is size-bounded so
    an unbounded target list never grows memory without limit; once an IP falls
    out of the LRU it may be emitted again, which is a fine trade-off for a
    soft-dedup.
    """
    seen = OrderedDict()
    async for ip in agen:
        if ip in seen:
            continue
        seen[ip] = None
        if len(seen) > maxsize:
            seen.popitem(last=False)
        yield ip


def parse_all(path: Path) -> List[str]:
    """Non-async helper used by tests / introspection (builds a full list)."""
    seen = set()
    out = []
    for ip in _parse_each_line(path):
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def count_targets(path: Path) -> int:
    """Count the IPs the scanner will actually process (no dedup, streaming)."""
    return sum(1 for _ in _parse_each_line(path))


def _parse_each_line(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        for raw in handle:
            yield from _parse_line(raw)
