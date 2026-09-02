"""In-process async mock HTTP server helper for testing the HTTP CVE-probe stage."""

import asyncio

from CamReaper.cve import _http_request


class MockHTTPServer:
    """Minimal configurable HTTP server for exercising probe_http_host().

    ``routes`` maps an exact URL path to a (status, body) tuple.  Any path not
    present answers 404 with an empty body.
    """

    def __init__(self, routes=None):
        self.routes = routes or {}
        self.server = None
        self.port = 0
        self._stop_event = asyncio.Event()

    async def start(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def _handle(self, reader, writer):
        try:
            request_line = await reader.readline()
            text = request_line.decode("utf-8", errors="replace")
            path = text.split(" ")[1] if len(text.split(" ")) > 1 else "/"
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
            status, body = self.routes.get(path, (404, ""))
            resp = (
                f"HTTP/1.1 {status} OK\r\n"
                f"Content-Type: text/plain\r\n"
                f"Content-Length: {len(body)}\r\n"
                "\r\n"
                f"{body}"
            )
            writer.write(resp.encode())
            await writer.drain()
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()


# Re-export so tests can call the probe with the same signature they use in
# production code without reaching into a private module path.
probe_http_request = _http_request


async def make_server(routes=None):
    srv = MockHTTPServer(routes=routes)
    await srv.start()
    return srv
