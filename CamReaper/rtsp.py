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

from CamReaper import ratelimit

# Read `User-Agent` / WWW-Authenticate headers up to this many bytes at most.
MAX_HEADER_BYTES = 64 * 1024

_STATUS_RE = re.compile(r"RTSP/(\d+\.\d+) (\d{3})", re.IGNORECASE)
_CONTENT_LENGTH_RE = re.compile(rb"content-length:\s*(\d+)", re.IGNORECASE)

# One ``WWW-Authenticate`` header line.  A server may send several (one per
# scheme) and may put more than one challenge on a single line.
_AUTH_HDR_RE = re.compile(r"(?im)^WWW-Authenticate:\s*(.*?)\s*$")
_AUTH_SCHEME_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9_-]*)")
_AUTH_SPLIT_RE = re.compile(
    r",\s*(?=(?:Basic|Digest|Bearer|Negotiate)\b)", re.IGNORECASE
)
_AUTH_PARAM_RE = re.compile(
    r"([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(?:\"((?:[^\"\\]|\\.)*)\"|([^,\s]+))"
)


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
        "auth_scheme",
        "auth_schemes",
        "opaque",
        "algorithm",
        "qop",
        "nc",
        "cseq",
        "data",
        "last_error",
    )

    def __init__(
        self, ip: str, port: int = 554, timeout: float = 2.0, credentials: str = ":"
    ) -> None:
        self.ip = ip
        self.port = port
        # Empty and ":" both mean "no credentials"; normalising here keeps a
        # caller that passes "" (ONVIF's anonymous case) from sending a Basic
        # header with an empty login.
        self.credentials = credentials or ":"
        self.timeout = timeout
        self.reader = None
        self.writer = None
        self.status = Status.NONE
        self.realm = ""
        self.nonce = ""
        # Which challenge the server actually sent.  Kept across close() so a
        # new socket can authenticate pre-emptively (many cameras reject a
        # second unauthenticated request).
        self.auth_scheme = ""
        self.auth_schemes = set()
        self.opaque = ""
        self.algorithm = "MD5"
        self.qop = ""
        self.nc = 1
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
            # Global pacing (--rate-limit): one token per *new* connection.
            # Reusing a keep-alive socket is free, which is the point - a scan
            # that can stay on one connection is not penalised.
            await ratelimit.acquire()
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

    def adopt_auth(self, other: "RTSPClient") -> None:
        """Copy the auth challenge learned by ``other`` onto this fresh socket.

        A route sweep opens several connections; without this each one would
        have to rediscover Basic vs Digest, and cameras that hang up on an
        unauthenticated request would never get the password at all.
        """
        self.auth_scheme = other.auth_scheme
        self.auth_schemes = set(other.auth_schemes)
        self.realm = other.realm
        self.nonce = other.nonce
        self.opaque = other.opaque
        self.algorithm = other.algorithm
        self.qop = other.qop
        self.nc = other.nc

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
        """Read one RTSP response header block into ``self.data``.

        Raises ConnectionError if the peer closed before sending a complete
        header block, so the caller can drop this socket and retry.  The reason
        is recorded in ``self.last_error`` for the scanner's failure log.

        Any response body announced by ``Content-Length`` is drained from the
        socket (and discarded).  Without that drain, the SDP body of a
        ``200 OK`` DESCRIBE stays queued and the *next* request on this
        keep-alive connection reads it as if it were a status line - which made
        a reused connection look like a dead host.
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
        end = head.index(b"\r\n\r\n") + 4
        header_bytes = bytes(head[:end])
        self.data = header_bytes.decode("utf-8", errors="replace")

        match = _CONTENT_LENGTH_RE.search(header_bytes)
        if not match:
            return
        try:
            remaining = int(match.group(1)) - (len(head) - end)
        except ValueError:
            return
        while remaining > 0:
            try:
                chunk = await asyncio.wait_for(
                    self.reader.read(min(remaining, 65536)), timeout=self.timeout
                )
            except (asyncio.TimeoutError, OSError):
                # The header we already parsed is still valid; only the socket
                # is unusable for another request, so drop it without losing
                # the status code.
                self.reader = self.writer = None
                self.last_error = "timeout"
                return
            if not chunk:
                self.reader = self.writer = None
                self.last_error = "closed"
                return
            remaining -= len(chunk)

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
        credentials = credentials or ":"

        # No credentials: a single request is all we can do.  The challenge it
        # returns is still parsed so a later credentialed attempt can use it.
        if credentials == ":":
            return await self._exchange(port, route, credentials, scheme="")

        # If this socket has not seen a challenge yet, ask once without
        # credentials.  This learns Basic vs Digest before a password is sent
        # (some strict servers close the socket on a wrongly-shaped header) and
        # costs a single request per fresh connection, not per credential.
        if not self.auth_scheme:
            probed = await self._exchange(port, route, ":", scheme="")
            if probed and self.status_code == "200":
                return True
            if not probed:
                # Some cameras hang up on an unauthenticated request instead of
                # challenging it.  Ask an unlikely dummy path once: a camera
                # that closes real routes usually still challenges the dummy,
                # which tells us Basic vs Digest.
                self.close()
                if not await self.connect(port):
                    return False
                probed = await self._exchange(
                    port, "/0x8b6c42", ":", scheme=""
                )
            # Cameras commonly close the socket right after issuing the
            # challenge.  Start the credentialed request on a fresh connection
            # so the challenge we just learned can actually be used.
            self.close()
            if not await self.connect(port):
                return False

        # Start with whatever the server already told us, otherwise send Basic
        # pre-emptively: Basic panels accept it at once, while Digest panels
        # answer 401 with a challenge and the loop retries with the right
        # scheme.  The old code always assumed Digest as soon as *any* realm was
        # seen, so a Basic-only camera rejected every password we sent it.
        scheme = self.auth_scheme or "basic"
        tried = set()
        for _attempt in range(4):
            used_scheme = scheme
            used_nonce = self.nonce
            if not await self._exchange(port, route, credentials, scheme):
                return False
            if self.status_code != "401":
                return True

            # _exchange parsed the new challenge into self.auth_scheme.
            next_scheme = self.auth_scheme
            if next_scheme == "digest":
                if used_scheme != "digest" or self.nonce != used_nonce:
                    # Digest was not tried yet, or the server rotated nonce.
                    scheme = "digest"
                    tried.add("digest")
                    continue
                # Digest with this nonce was rejected.  If the same response
                # also offered Basic, give it one chance.
                if "basic" in self.auth_schemes and "basic" not in tried:
                    scheme = "basic"
                    tried.add("basic")
                    continue
            elif next_scheme == "basic" and used_scheme != "basic":
                scheme = "basic"
                tried.add("basic")
                continue
            # Either the credential is wrong or the server keeps repeating the
            # same challenge; return the definitive 401 to the caller.
            break
        return True

    async def _exchange(self, port, route, credentials, scheme=None) -> bool:
        from CamReaper.packet import describe

        self.cseq += 1
        self.last_error = ""
        if scheme is None:
            scheme = self.auth_scheme
        try:
            # Built inside the guard: a malformed credential / route must never
            # escape as an exception and abort the whole scan.
            request = describe(
                self.ip,
                port,
                route,
                self.cseq,
                credentials,
                self.realm,
                self.nonce,
                scheme=scheme,
                opaque=self.opaque,
                algorithm=self.algorithm,
                qop=self.qop,
                nc=self.nc,
            )
            if scheme == "digest":
                self.nc += 1
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

        self._update_challenge(self.data)
        return True

    @classmethod
    def _parse_auth_challenges(cls, data: str) -> dict:
        """Return ``{scheme: {param: value}}`` from every challenge header.

        Handles one header per scheme, several schemes on one line, quoted and
        unquoted values - firmware is inconsistent about all three.
        """
        challenges: dict = {}
        for header in _AUTH_HDR_RE.finditer(data):
            for part in _AUTH_SPLIT_RE.split(header.group(1)):
                match = _AUTH_SCHEME_RE.match(part)
                if not match:
                    continue
                scheme = match.group(1).lower()
                if scheme not in ("basic", "digest"):
                    continue
                params: dict = {}
                for pm in _AUTH_PARAM_RE.finditer(part[match.end():]):
                    key = pm.group(1).lower()
                    value = pm.group(2) if pm.group(2) is not None else pm.group(3)
                    params[key] = value
                challenges[scheme] = params
        return challenges

    def _update_challenge(self, data: str) -> None:
        challenges = self._parse_auth_challenges(data)
        if not challenges:
            return
        self.auth_schemes = set(challenges)
        if "digest" in challenges:
            params = challenges["digest"]
            self.auth_scheme = "digest"
            if "realm" in params:
                self.realm = params.get("realm", "")
            if params.get("nonce") is not None:
                nonce = params["nonce"]
                if nonce != self.nonce:
                    self.nc = 1
                self.nonce = nonce
            if params.get("opaque"):
                self.opaque = params["opaque"]
            if params.get("algorithm"):
                self.algorithm = params["algorithm"]
            offered = [
                token.strip().lower()
                for token in params.get("qop", "").split(",")
            ]
            if "auth" in offered:
                self.qop = "auth"
            elif "auth-int" in offered:
                # DESCRIBE has no body, so auth-int is computable (empty
                # entity hash); some firmware offers only this variant.
                self.qop = "auth-int"
            else:
                self.qop = ""
        elif "basic" in challenges:
            params = challenges["basic"]
            self.auth_scheme = "basic"
            if "realm" in params:
                self.realm = params.get("realm", "")
            # A Basic challenge carries no nonce; clear a stale Digest one.
            self.nonce = ""
            self.qop = ""

    @staticmethod
    def _extract_challenge(data: str):
        """Pull realm/nonce from a WWW-Authenticate header, if present."""
        challenges = RTSPClient._parse_auth_challenges(data)
        params = challenges.get("digest") or challenges.get("basic") or {}
        return params.get("realm"), params.get("nonce")

    # --------------------------------------------------------------- meta

    @staticmethod
    def get_rtsp_url(ip, port=554, credentials=":", route="/") -> str:
        prefix = f"{credentials}@" if credentials and credentials != ":" else ""
        # IPv6 literals must be bracketed in a URL authority.
        host = f"[{ip}]" if ":" in str(ip) and not str(ip).startswith("[") else ip
        return f"rtsp://{prefix}{host}:{port}{route}"
