"""Streaming target generation.

Unlike materialising every resolved IP into a deque (a memory bomb on big
CIDRs), this module yields targets lazily as an async generator.  Only a
bounded pool of active host-tasks is kept in flight.
"""

import ipaddress
import re
from collections import OrderedDict
from pathlib import Path
from typing import AsyncIterator, Iterator, List, Union

# One target token of an inline ``-t`` spec: an IP, an IP/CIDR, or a range.
# The range part allows zero whitespace so both ``1.2.3.4-5.6.7.8`` and
# ``1.2.3.4 - 5.6.7.8`` stay a single token when the shell splits the argument.
# ``/`` belongs to the token: "192.168.1.0/24" must not be cut into an address
# and a stray "24".
_SPEC_RE = re.compile(r"[0-9A-Za-z.:/%]+(?:\s*-\s*[0-9A-Za-z.:/%]+)?")

# A ``-t`` argument is either a file with one target per line or an inline spec.
TargetSource = Union[Path, str]


def _iter_network(network) -> Iterator[str]:
    """Yield every address of ``network`` as a string, lazily.

    IPv4 addresses are plain 32-bit integers, so the text is built from
    integer arithmetic instead of one ``IPv4Address`` object per address -
    ~40% faster when counting a /8 and, more importantly, constant memory.
    The output is byte-identical to ``str(ip) for ip in network``.
    """
    if isinstance(network, ipaddress.IPv6Network):
        for ip in network:
            yield str(ip)
        return
    prefixlen = network.prefixlen
    base = int(network.network_address)
    count = network.num_addresses
    if prefixlen == 32:
        yield str(network.network_address)
        return
    if count <= 65536:
        # /16 and narrower-but-small: the top two octets are pinned, the low
        # 16 bits walk (covers every /16../31).
        head = base >> 16
        head_text = f"{head >> 8}.{head & 255}."
        low = base & 0xFFFF
        for value in range(low, low + count):
            yield f"{head_text}{value >> 8}.{value & 255}"
    else:
        # /15 and wider: format all four octets per address.
        for value in range(base, base + count):
            a, rest = divmod(value, 1 << 24)
            b, rest = divmod(rest, 1 << 16)
            c, d = divmod(rest, 256)
            yield f"{a}.{b}.{c}.{d}"


def _iter_line(line: str) -> Iterator[str]:
    """Yield the IP strings of one input line, one at a time.

    Supported forms:
        1) 1.2.3.4
        2) 192.168.0.0/24  (also ``192.168.1.5/24`` - host bits are ignored)
        3) 1.2.3.4 - 5.6.7.8
    Any non-IP value yields nothing.

    Iteration is lazy on purpose: a ``/8`` line must not be turned into a
    16-million-element list of strings (~1 GB) just to be scanned.
    """
    line = line.strip()
    if not line:
        return
    try:
        if "-" in line:
            left, right = line.split("-", 1)
            ranges = ipaddress.summarize_address_range(
                ipaddress.IPv4Address(left.strip()),
                ipaddress.IPv4Address(right.strip()),
            )
            for r in ranges:
                for ip in _iter_network(r):
                    yield ip
        elif "/" in line:
            # strict=False: "192.168.1.5/24" is a common way to write a range
            # and used to be rejected outright as "not a network".
            yield from _iter_network(ipaddress.ip_network(line, strict=False))
        else:
            yield str(ipaddress.ip_address(line))
    except ValueError:
        return


def _parse_line(line: str) -> List[str]:
    """Eager variant of :func:`_iter_line` (test / introspection helper)."""
    return list(_iter_line(line))


def inline_specs(spec: str) -> List[str]:
    """Split an inline ``-t`` spec into target tokens.

    ``"192.168.1.0/24, 10.0.0.5"`` -> ``["192.168.1.0/24", "10.0.0.5"]`` and
    ``"10.0.0.1 - 10.0.0.9"`` -> ``["10.0.0.1 - 10.0.0.9"]`` (the range keeps
    its spaces, so it is still one token to :func:`_iter_line`).
    """
    return _SPEC_RE.findall(spec)


def is_valid_spec(spec: str) -> bool:
    """True when ``spec`` yields at least one IP - i.e. it is a usable inline
    target list rather than a typo that should be reported as a bad path."""
    for token in inline_specs(spec):
        # Consume the generator: _iter_line() returns an iterator object, which
        # is always truthy, so "any(...)" here would accept any word at all.
        for _ip in _iter_line(token):
            return True
    return False


def is_file_source(source: TargetSource) -> bool:
    return isinstance(source, Path)


def describe(source: TargetSource) -> str:
    """Short label for the "targets=..." progress line (a file keeps its name,
    an inline spec is shown as typed, trimmed)."""
    if isinstance(source, Path):
        return source.name
    text = str(source).strip()
    return text if len(text) <= 48 else text[:45] + "..."


def _iter_source_lines(source: TargetSource) -> Iterator[str]:
    """Yield the raw target lines of a file source or an inline spec."""
    if isinstance(source, Path):
        with source.open("r", encoding="utf-8") as handle:
            for raw in handle:
                yield raw
    else:
        yield from inline_specs(str(source))


async def iter_targets(source: TargetSource) -> AsyncIterator[str]:
    """Yield each target IP string lazily (streaming, never fully in RAM).

    ``source`` is a file with one target per line *or* an inline spec such as
    ``192.168.1.0/24`` / ``10.0.0.1-10.0.0.9`` / ``1.1.1.1, 8.8.8.8``.
    """
    for raw in _iter_source_lines(source):
        for ip in _iter_line(raw):
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
            # Refresh recency: a cache entry evicted while the IP was still
            # coming back is exactly what makes the bound safe.
            seen.move_to_end(ip, last=True)
            continue
        seen[ip] = None
        if len(seen) > maxsize:
            seen.popitem(last=False)
        yield ip


def parse_all(source: TargetSource) -> List[str]:
    """Non-async helper used by tests / introspection (builds a full list)."""
    seen = set()
    out = []
    for ip in _iter_source(source):
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def count_targets(source: TargetSource) -> int:
    """Count the IPs the scanner will actually process (no dedup, streaming)."""
    return sum(1 for _ in _iter_source(source))


def _iter_source(source: TargetSource) -> Iterator[str]:
    for raw in _iter_source_lines(source):
        yield from _iter_line(raw)
