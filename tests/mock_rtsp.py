"""In-process async mock RTSP server helpers for tests & smoke testing."""

import asyncio
import base64
import hashlib
import re
import weakref


def _status_line(code: str) -> str:
    return f"RTSP/1.0 {code} OK\r\n"


def _md5(s: str) -> str:
    return hashlib.md5(s.encode("ascii")).hexdigest()


def _verify_digest(auth_line: str, describe_line: str, valid_cred: str) -> bool:
    """Verify an RFC-2617 style Digest response against ``valid_cred``."""
    fields = dict(re.findall(r'(\w+)="([^"]*)"', auth_line))
    username, realm, nonce, uri, response = (
        fields.get("username", ""),
        fields.get("realm", ""),
        fields.get("nonce", ""),
        fields.get("uri", ""),
        fields.get("response", ""),
    )
    v_user, _, v_pass = valid_cred.partition(":")
    ha1 = _md5(f"{v_user}:{realm}:{v_pass}")
    ha2 = _md5(f"DESCRIBE:{uri}")
    expected = _md5(f"{ha1}:{nonce}:{ha2}")
    return response == expected and username == v_user


class MockRTSPServer:
    """Minimal configurable RTSP server.

    ``mode`` choices:
      * "open"         -> any DESCRIBE answers 200
      * "open-except-root" -> 200 on every route except "/" (404): an "open"
                          camera that gates the root route
      * "auth-401"     -> always 401 with a Digest challenge
      * "digest-auth"  -> 401 until a valid Authorization header, then 200
      * "scanner"      -> 200 only when a *valid* credential is supplied
                          (Basic or Digest), otherwise 401 with a challenge
    """

    def __init__(
        self,
        mode="open",
        valid_cred="admin:admin",
        silent_after=None,
        open_route=None,
        routes_404=None,
        server_header="Mock",
    ):
        self.mode = mode
        self.valid_cred = valid_cred
        self.silent_after = silent_after
        self.open_route = open_route
        self.routes_404 = routes_404 or ()
        self.server_header = server_header
        self.host = "127.0.0.1"
        self.port = None
        self.server = None
        self.requests = []
        self._session_poisoned = weakref.WeakKeyDictionary()

    async def start(self):
        self._tasks = set()
        self.server = await asyncio.start_server(self._on_conn, self.host, 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def stop(self):
        server, self.server = self.server, None
        # Cancel handler tasks BEFORE wait_closed(): a silent/flaky handler may
        # sleep for a long time while holding its connection, and wait_closed()
        # waits for those connections to finish - cancelling first makes teardown
        # immediate instead of blocking for the whole sleep duration.
        tasks = list(getattr(self, "_tasks", ()))
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._tasks = set()
        if server:
            server.close()
            await server.wait_closed()

    async def _on_conn(self, reader, writer):
        task = asyncio.ensure_future(self._handler(reader, writer))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _handler(self, reader, writer):
        try:
            if (
                self.silent_after is not None
                and len(self.requests) >= self.silent_after
            ):
                # "Flaky" camera: answer a few times, then go silent forever
                # (accept the socket, never respond) - reproduces the stall that
                # used to burn one timeout per credential.
                await asyncio.sleep(60)
                return
            if self.mode == "silent":
                # Accept but never respond: makes the client hang until its timeout.
                await asyncio.sleep(60)
                return
            try:
                data = await asyncio.wait_for(reader.read(65536), timeout=5)
                text = data.decode("utf-8", "replace")
                self.requests.append(text)
                valid = self._creds_ok(text)
                # "session poisoning": a route-open camera that already answered
                # 401 on THIS socket refuses even its open route afterwards, until
                # the client opens a brand-new connection.
                if self.mode == "route-open":
                    if self._session_poisoned.get(writer):
                        await self._send(writer, "401")
                        return
                    route = self._extract_route(text)
                    if route in self.routes_404:
                        # Definitive "no such route" (NOT an auth challenge): the
                        # client surfaces this as a non-auth status, not a 401.
                        await self._send(writer, "404", body="Not Found\r\n")
                        return
                    was_open = route == self.open_route
                    if not was_open:
                        self._session_poisoned[writer] = True
                    await self._send(writer, "200" if was_open else "401")
                    return
                await self._respond(writer, valid, text)
            except Exception:
                pass
        finally:
            # Always release the connection so the server teardown (wait_closed)
            # does not block waiting for this handler to finish.
            try:
                writer.close()
            except Exception:
                pass
            try:
                await writer.wait_closed()
            except BaseException:
                pass

    def _extract_route(self, text: str) -> str:
        describe_line = next(
            (l for l in text.split("\r\n") if l.startswith("DESCRIBE")), ""
        )
        if not describe_line:
            return ""
        parts = describe_line.split(" ")
        if len(parts) < 2:
            return ""
        # Request-URI is "rtsp://host:port/path" - return only the path part.
        uri = parts[1]
        marker = uri.find("/", uri.find("//") + 2)
        return uri[marker:] if marker != -1 else uri

    def _creds_ok(self, text: str) -> bool:
        if "Authorization" not in text:
            return False
        describe_line = next(
            (l for l in text.split("\r\n") if l.startswith("DESCRIBE")), ""
        )
        for line in text.split("\r\n"):
            if line.startswith("Authorization: Basic "):
                try:
                    decoded = base64.b64decode(line.split(" ", 2)[2]).decode(
                        "utf-8", "replace"
                    )
                except Exception:
                    return False
                return decoded.strip() == self.valid_cred
            if line.startswith("Authorization: Digest "):
                return _verify_digest(line, describe_line, self.valid_cred)
        return False

    async def _respond(self, writer, creds_ok, text=""):
        if self.mode == "open":
            await self._send(writer, "200", body="v=0\r\n")
        elif self.mode == "open-except-root":
            if self._extract_route(text) == "/":
                await self._send(writer, "404", body="Not Found\r\n")
            else:
                await self._send(writer, "200", body="v=0\r\n")
        elif self.mode == "route-open":
            # Hikvision-style: 200 on one specific (query) route without any
            # credentials, 401 everywhere else.
            if self._extract_route(text) == self.open_route:
                await self._send(writer, "200", body="v=0\r\n")
            else:
                await self._send(writer, "401")
        elif self.mode == "auth-401":
            await self._send(writer, "401")
        elif self.mode == "named-route-auth":
            # Needs a valid password AND the stream lives only on a named
            # (non-'/') route: '/' returns 401 even with the right password.
            if creds_ok and self._extract_route(text) == self.open_route:
                await self._send(writer, "200", body="v=0\r\n")
            else:
                await self._send(writer, "401")
        elif self.mode in ("digest-auth", "scanner"):
            if creds_ok:
                await self._send(writer, "200", body="v=0\r\n")
            else:
                await self._send(writer, "401")

    async def _send(self, writer, code, body=""):
        resp = (
            _status_line(code)
            + f"Server: {self.server_header}\r\n"
            + 'WWW-Authenticate: Digest realm="r", nonce="n1"\r\n'
            + f"Content-Length: {len(body)}\r\n"
            + "\r\n"
            + f"{body}"
        )
        writer.write(resp.encode())
        await writer.drain()


async def make_server(
    mode, valid_cred="admin:admin", silent_after=None, open_route=None,
    routes_404=None, server_header="Mock",
):
    srv = MockRTSPServer(
        mode=mode,
        valid_cred=valid_cred,
        silent_after=silent_after,
        open_route=open_route,
        routes_404=routes_404,
        server_header=server_header,
    )
    await srv.start()
    return srv
