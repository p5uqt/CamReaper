"""Streaming target generation.

Unlike materialising every resolved IP into a deque (a memory bomb on big
CIDRs), this module yields targets lazily as an async generator.  Only a
bounded pool of active host-tasks is kept in flight.
"""

import ipaddress
import re
from bisect import bisect_right
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


def _count_line(line: str) -> int:
    """Number of addresses in one input line, without expanding it.

    Used by :func:`estimate_targets` so a ``/8`` can be counted in constant
    time.  Returns 0 for anything :func:`_iter_line` would ignore.
    """
    line = line.strip()
    if not line:
        return 0
    try:
        if "-" in line:
            left, right = line.split("-", 1)
            low = ipaddress.IPv4Address(left.strip())
            high = ipaddress.IPv4Address(right.strip())
            if int(high) < int(low):
                return 0
            return int(high) - int(low) + 1
        if "/" in line:
            return ipaddress.ip_network(line, strict=False).num_addresses
        ipaddress.ip_address(line)
        return 1
    except ValueError:
        return 0


def estimate_targets(source: TargetSource) -> int:
    """Count the addresses of ``source`` with arithmetic instead of iteration.

    ``count_targets`` has to walk every address, which costs ~10s of pure CPU
    for a ``/8`` before a single packet is sent.  Every supported form (single
    address, CIDR, IPv4 range) has a closed-form size, so the progress bar can
    be set up immediately even for multi-million-host input.
    """
    return sum(_count_line(raw) for raw in _iter_source_lines(source))


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
        # errors="replace": one stray non-UTF-8 byte in a generated target list
        # must not abort a scan that may already be hours in.
        with source.open("r", encoding="utf-8", errors="replace") as handle:
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


# ---------------------------------------------------------------------------
# Large-scan scheduling helpers: sharding, slicing and exclusion
# ---------------------------------------------------------------------------


async def iter_shard(
    agen: AsyncIterator[str], index: int, total: int
) -> AsyncIterator[str]:
    """Yield every ``total``-th target, starting at ``index`` (0-based).

    Lets one big range be split across several machines *without* any of them
    holding the range in memory: shard ``i`` of ``n`` takes addresses
    ``i, i+n, i+2n, ...`` of the (already deduplicated) stream.  Each shard
    sees a deterministic, disjoint subset.
    """
    if total <= 1:
        async for ip in agen:
            yield ip
        return
    index %= total
    position = 0
    async for ip in agen:
        if position % total == index:
            yield ip
        position += 1


async def iter_slice(
    agen: AsyncIterator[str], skip: int = 0, limit: int = 0
) -> AsyncIterator[str]:
    """Skip the first ``skip`` targets and yield at most ``limit`` (0 = all).

    This is the "scan it in chunks" primitive: ``--skip 1000000 --limit 1000000``
    scans the second million hosts of a list.  It stays lazy, so the skipped
    prefix is never materialised.
    """
    if skip < 0:
        skip = 0
    position = 0
    emitted = 0
    async for ip in agen:
        if position < skip:
            position += 1
            continue
        if limit and emitted >= limit:
            return
        emitted += 1
        yield ip


class Excluder:
    """Membership test for ``--exclude`` networks/addresses.

    Exclusions are collapsed with :func:`ipaddress.collapse_addresses` and the
    remaining networks are stored as sorted integer intervals, so a membership
    test is a binary search instead of a scan over every excluded CIDR - which
    matters when a million hosts are checked against a long exclusion list.
    """

    __slots__ = ("_v4_starts", "_v4_ends", "_v6_starts", "_v6_ends", "_addresses")

    def __init__(self, networks=(), addresses=()):
        nets = list(networks)
        self._v4_starts, self._v4_ends = _intervals(
            [n for n in nets if n.version == 4]
        )
        self._v6_starts, self._v6_ends = _intervals(
            [n for n in nets if n.version == 6]
        )
        self._addresses = set(addresses)

    def __bool__(self) -> bool:
        return bool(
            self._v4_starts
            or self._v6_starts
            or self._addresses
        )

    def __contains__(self, ip: str) -> bool:
        return self.excludes(ip)

    def excludes(self, ip: str) -> bool:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if address in self._addresses:
            return True
        value = int(address)
        if address.version == 4:
            return _in_intervals(value, self._v4_starts, self._v4_ends)
        return _in_intervals(value, self._v6_starts, self._v6_ends)


def _intervals(networks):
    """Collapse ``networks`` and return sorted start/end integer lists."""
    if not networks:
        return [], []
    collapsed = sorted(
        ipaddress.collapse_addresses(networks), key=lambda n: int(n.network_address)
    )
    starts = [int(n.network_address) for n in collapsed]
    ends = [int(n.broadcast_address) for n in collapsed]
    return starts, ends


def _in_intervals(value: int, starts, ends) -> bool:
    index = bisect_right(starts, value) - 1
    return index >= 0 and value <= ends[index]


def _exclusion_line(line: str):
    """Parse one exclusion token into ``(networks, addresses)`` without expanding."""
    nets: list = []
    addrs: set = set()
    line = line.strip()
    if not line:
        return nets, addrs
    try:
        if "-" in line:
            left, right = line.split("-", 1)
            nets.extend(
                ipaddress.summarize_address_range(
                    ipaddress.ip_address(left.strip()),
                    ipaddress.ip_address(right.strip()),
                )
            )
        elif "/" in line:
            nets.append(ipaddress.ip_network(line, strict=False))
        else:
            addrs.add(ipaddress.ip_address(line))
    except ValueError:
        pass
    return nets, addrs


def parse_exclusions(specs) -> Excluder:
    """Build an :class:`Excluder` from files and/or inline specs.

    Each entry follows the same syntax as ``-t`` (IP, CIDR, range, or a file of
    those), so a large scan can be pared down with the list it already has.
    """
    networks: list = []
    addresses: set = set()
    for source in specs or ():
        for raw in _iter_source_lines(source):
            nets, addrs = _exclusion_line(raw)
            networks.extend(nets)
            addresses.update(addrs)
    return Excluder(networks, addresses)


async def iter_excluding(
    agen: AsyncIterator[str], excluder: Excluder
) -> AsyncIterator[str]:
    """Stream ``agen`` while dropping every address matched by ``excluder``."""
    if not excluder:
        async for ip in agen:
            yield ip
        return
    async for ip in agen:
        if ip not in excluder:
            yield ip
