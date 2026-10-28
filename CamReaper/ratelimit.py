"""Global connection-rate limiting shared by every probe of a scan.

``--attempts-per-sec`` throttles *one host* at a time, which is the right
knob for dodging a camera's login lockout.  A large scan needs a second,
global knob: thousands of hosts in flight would otherwise open and brute-force
them all at full speed against a shared upstream link (or a border device that
starts dropping packets).  :class:`TokenBucket` is that knob - one bucket for
the whole process, acquired right before a new socket is opened.

The bucket is deliberately tiny and dependency-free.  It is re-bound to each
running event loop (the test suite creates a fresh loop per test) and refills
continuously instead of sleeping on a fixed interval, so a fast host is never
throttled to a slow host's cadence.
"""

import asyncio


class TokenBucket:
    """Async token bucket: ``rate`` tokens per second, ``burst`` capacity."""

    __slots__ = ("rate", "burst", "_tokens", "_updated", "_lock", "_loop")

    def __init__(self, rate: float, burst: float = None) -> None:
        self.rate = float(rate)
        if self.rate <= 0:
            raise ValueError("rate must be > 0")
        # Allow a small burst so squaring up at the start of a scan does not
        # serialise the first few connections.
        self.burst = float(burst) if burst is not None else max(1.0, self.rate)
        self._tokens = self.burst
        self._updated = None
        self._lock = None
        self._loop = None

    def reset(self) -> None:
        """Forget the loop binding (used when a scan starts on a new loop)."""
        self._lock = None
        self._loop = None
        self._tokens = self.burst
        self._updated = None

    async def acquire(self, tokens: float = 1.0) -> None:
        loop = asyncio.get_running_loop()
        if self._loop is not loop:
            # A lock is bound to the loop that first waited on it; a fresh scan
            # (or a test) may run on a different one.
            self._loop = loop
            self._lock = asyncio.Lock()
            self._tokens = self.burst
            self._updated = loop.time()
        lock = self._lock
        async with lock:
            while True:
                now = loop.time()
                elapsed = now - self._updated
                self._updated = now
                if elapsed > 0:
                    self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                # Sleep only as long as needed for the debt to be paid off.
                await asyncio.sleep((tokens - self._tokens) / self.rate)


_limiter = None


def configure(rate: float, burst: float = None) -> None:
    """Install (or clear, with ``rate <= 0``) the process-wide limiter."""
    global _limiter
    if rate and rate > 0:
        _limiter = TokenBucket(rate, burst)
    else:
        _limiter = None


def current() -> "TokenBucket | None":
    return _limiter


async def acquire(tokens: float = 1.0) -> None:
    """Take one token from the global bucket, if one is configured."""
    limiter = _limiter
    if limiter is not None:
        await limiter.acquire(tokens)
