"""Asynchronous minimal RTSP client.

A thin asyncio wrapper that:

* opens connections without blocking the event loop;
* reuses a live TCP connection across attempts (keep-alive) instead of
  reconnecting every time;
* reads until the HTTP-style header terminator so a response is never
  truncated;
* retries only genuine transient failures with bounded jitter.
"""

import asyncio
import re
from enum import Enum

# Read `User-Agent` / WWW-Authenticate headers up to this many bytes at most.
MAX_HEADER_BYTES = 64 * 1024

_STATUS_RE = re.compile(r"RTSP/(\d+\.\d+) (\d{3})")
_REALM_RE = re.compile(r'realm="([^"]*)"', re.IGNORECASE)
_NONCE_RE = re.compile(r'nonce="([^"]*)"', re.IGNORECASE)


class Status(Enum):
    NONE = -1
    CONNECTED = 0
    TIMEOUT = 1
    UNIDENTIFIED = 100


class RTSPClient:
    __slots__ = (
        "ip",
        "port",
        "credentials",
        "timeout",
        "reader",
        "writer",
        "status",
        "realm",
        "nonce",
        "cseq",
        "data",
        "last_error",
    )

    def __init__(
        self, ip: str, port: int = 554, timeout: float = 2.0, credentials: str = ":"
    ) -> None:
        self.ip = ip
        self.port = port
        self.credentials = credentials
        self.timeout = timeout
        self.reader = None
        self.writer = None
        self.status = Status.NONE
        self.realm = ""
        self.nonce = ""
        self.cseq = 0
        self.data = ""
        # Why the last attempt failed ("timeout", "closed", "refused", ...);
        # kept across close() so the scanner can report an accurate reason.
        self.last_error = ""

    # ------------------------------------------------------------------ I/O

    async def connect(self, port: int = None) -> bool:
        """Open (or reuse) a TCP connection.  Returns True when usable."""
        if port is None:
            port = self.port

        if (
            self.writer is not None
            and not self.writer.is_closing()
            and port == self.port
        ):
            # Already have a live connection on this port - reuse it.
            self.status = Status.CONNECTED
            return True

        self.port = port
        self.reader = self.writer = None
        self.cseq = 0
        self.data = ""
        try:
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(self.ip, port), timeout=self.timeout
            )
        except (asyncio.TimeoutError, OSError) as exc:
            self.status = Status.TIMEOUT
            self.last_error = "timeout" if isinstance(exc, asyncio.TimeoutError) else "refused"
            self.reader = self.writer = None
            return False
        except Exception:
            self.status = Status.UNIDENTIFIED
            self.last_error = "error"
            self.reader = self.writer = None
            return False

        self.status = Status.CONNECTED
        self.last_error = ""
        return True

    def close(self) -> None:
        if self.writer is not None:
            try:
                self.writer.close()
            except Exception:
                pass
        self.writer = None
        self.reader = None
        self.status = Status.NONE
        self.data = ""

    @property
    def is_connected(self) -> bool:
        return (
            self.writer is not None
            and not self.writer.is_closing()
            and self.status is Status.CONNECTED
        )

    async def _read_response(self) -> None:
        """Read RTSP headers (up to ``\r\n\r\n``) into ``self.data``.

        Raises ConnectionError if the peer closed before sending a complete
        header block, so the caller can drop this socket and retry.  The reason
        is recorded in ``self.last_error`` for the scanner's failure log.
        """
        head = bytearray()
        while b"\r\n\r\n" not in head:
            try:
                chunk = await asyncio.wait_for(
                    self.reader.read(4096), timeout=self.timeout
                )
            except asyncio.TimeoutError:
                self.last_error = "timeout"
                raise ConnectionError("timed out reading response") from None
            if not chunk:
                self.last_error = "closed"
                raise ConnectionError("connection closed early")
            head += chunk
            if len(head) > MAX_HEADER_BYTES:
                self.last_error = "headers-too-large"
                raise ConnectionError("response headers too large")
        self.data = bytes(head).decode("utf-8", errors="replace")

    # ------------------------------------------------------------- parsing

    @property
    def status_line(self) -> str:
        """First line of the RTSP response (the status line)."""
        if not self.data:
            return ""
        return self.data.split("\r\n", 1)[0]

    @property
    def status_code(self) -> str:
        """Three-digit status code, e.g. ``"200"``, or ``""`` if unknown."""
        m = _STATUS_RE.search(self.status_line)
        return m.group(2) if m else ""

    # ---------------------------------------------------------------- auth

    async def authorize(self, port=None, route="", credentials=None) -> bool:
        """Send a DESCRIBE and, if challenged with Digest, complete the
        two-step handshake on the same connection.  Returns True when the
        final response was read.

        On success ``self.status_code`` holds the definitive result
        (``200``/``401``/``403``/``404``).  On connection failure returns False.
        """
        if not self.is_connected and not await self.connect(port):
            return False

        if credentials is None:
            credentials = self.credentials

        if not await self._exchange(port, route, credentials):
            return False

        # If the server challenges us with Digest auth and we have real
        # credentials, rerun the exchange so the caller sees the real answer.
        # Some cameras close the socket right after issuing a challenge - in
        # that case honor the 401 we already read instead of surfacing this
        # attempt as a transport failure (which would make the caller give up
        # on a perfectly healthy host after a couple of credentials).
        if (
            self.status_code == "401"
            and self.realm
            and self.nonce
            and credentials != ":"
        ):
            # The 401 we got is the verdict for this attempt.  Rerun the
            # exchange so a valid credential can land a 200; if the camera
            # drops the socket right after the challenge, keep the 401 we
            # already read instead of surfacing a transport failure (which
            # would make the caller give up on a healthy host).
            saved_data, saved_status = self.data, self.status
            if not await self._exchange(port, route, credentials):
                self.data = saved_data
                self.status = saved_status
        return True

    async def _exchange(self, port, route, credentials) -> bool:
        from CamReaper.packet import describe

        self.cseq += 1
        self.last_error = ""
        try:
            # Built inside the guard: a malformed credential / route must never
            # escape as an exception and abort the whole scan.
            request = describe(
                self.ip, port, route, self.cseq, credentials, self.realm, self.nonce
            )
            self.writer.write(request.encode("utf-8", "replace"))
            await asyncio.wait_for(self.writer.drain(), timeout=self.timeout)
            await self._read_response()
        except (ConnectionError, asyncio.TimeoutError, OSError) as exc:
            # Fresh connection needed: the camera dropped the socket (common).
            # _read_response already recorded the precise reason before raising
            # ("closed" / "timeout" / "headers-too-large"); fill in only what it
            # could not know, e.g. a write/drain timeout.
            if not self.last_error:
                if isinstance(exc, asyncio.TimeoutError):
                    self.last_error = "timeout"
                elif isinstance(exc, ConnectionError):
                    self.last_error = "closed"
                else:
                    self.last_error = "refused"
            self.close()
            return False
        except Exception:
            self.close()
            self.last_error = "error"
            return False

        realm, nonce = self._extract_challenge(self.data)
        if realm is not None:
            self.realm = realm
        if nonce is not None:
            self.nonce = nonce
        return True

    @staticmethod
    def _extract_challenge(data: str):
        """Pull realm/nonce from a WWW-Authenticate header, if present."""
        m = _REALM_RE.search(data)
        realm = m.group(1) if m else None
        m = _NONCE_RE.search(data)
        nonce = m.group(1) if m else None
        return realm, nonce

    # --------------------------------------------------------------- meta

    @staticmethod
    def get_rtsp_url(ip, port=554, credentials=":", route="/") -> str:
        prefix = f"{credentials}@" if credentials and credentials != ":" else ""
        return f"rtsp://{prefix}{ip}:{port}{route}"
