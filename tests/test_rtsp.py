import asyncio

import pytest

from CamReaper.rtsp import RTSPClient

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def mock(request):
    from tests.mock_rtsp import MockRTSPServer

    mode = getattr(request, "param", "open")
    srv = MockRTSPServer(mode=mode)
    await srv.start()
    yield srv
    await srv.stop()


@pytest.mark.parametrize("mock", ["open"], indirect=True)
async def test_connect_and_read_status(mock):
    c = RTSPClient(mock.host, mock.port, timeout=2, credentials=":")
    assert await c.connect()
    assert c.is_connected
    await c.authorize()
    assert c.status_code == "200"


@pytest.mark.parametrize("mock", ["open"], indirect=True)
async def test_new_connection_takes_a_global_rate_limit_token(monkeypatch, mock):
    calls = []

    async def fake_acquire(tokens=1.0):
        calls.append(tokens)

    monkeypatch.setattr("CamReaper.rtsp.ratelimit.acquire", fake_acquire)
    c = RTSPClient(mock.host, mock.port, timeout=2, credentials=":")
    assert await c.connect()
    assert calls  # one token for the new socket
    n = len(calls)
    assert await c.connect()  # keep-alive reuse is free
    assert len(calls) == n


async def test_response_body_is_drained_for_keepalive():
    """A DESCRIBE 200 carries an SDP body.  It must be consumed, otherwise the
    next response on the same socket starts with leftover SDP and the reused
    connection looks dead."""

    class _Reader:
        def __init__(self, data):
            self.data = data

        async def read(self, n):
            n = min(n, 10)  # small chunks: the response arrives in pieces
            chunk, self.data = self.data[:n], self.data[n:]
            return chunk

    first = (
        b"RTSP/1.0 200 OK\r\n"
        b"Server: Cam\r\n"
        b"Content-Length: 23\r\n\r\n"
        b"v=0\r\no=- 1 1 IN IP4 1\r\n"
    )
    second = b"RTSP/1.0 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"
    client = RTSPClient("127.0.0.1", 554, timeout=1, credentials=":")
    client.reader = _Reader(first + second)

    await client._read_response()
    assert client.status_code == "200"
    assert client.reader.data == second

    await client._read_response()
    assert client.status_code == "401"


@pytest.mark.parametrize("mock", ["auth-401"], indirect=True)
async def test_auth_required_returns_401(mock):
    c = RTSPClient(mock.host, mock.port, timeout=2, credentials=":")
    await c.connect()
    await c.authorize()
    assert c.status_code == "401"
    assert c.realm == "r"
    assert c.nonce == "n1"


@pytest.mark.parametrize("mock", ["digest-auth"], indirect=True)
async def test_digest_two_step(mock):
    c = RTSPClient(mock.host, mock.port, timeout=2, credentials="admin:admin")
    await c.connect()
    await c.authorize(route="/")
    # after the two-step handshake the real answer (200) is visible
    assert c.status_code == "200"


@pytest.mark.parametrize("mock", ["digest-auth"], indirect=True)
async def test_digest_without_creds_stays_401(mock):
    c = RTSPClient(mock.host, mock.port, timeout=2, credentials=":")
    await c.connect()
    await c.authorize(route="/")
    assert c.status_code == "401"


@pytest.mark.parametrize("mock", ["open"], indirect=True)
async def test_connection_reuse(mock):
    c = RTSPClient(mock.host, mock.port, timeout=2, credentials=":")
    await c.connect()
    sock1 = c.writer
    # reuse - no reconnect
    assert await c.connect()
    assert c.writer is sock1
    c.close()
    assert not c.is_connected


@pytest.mark.parametrize("mode", ["silent", "open", "auth-401"])
async def test_server_stop_is_fast(mode):
    """Regression: teardown of a connection that never answers must not block
    for the whole handler sleep - cancellation must happen before wait_closed."""
    import time

    from tests.mock_rtsp import make_server

    srv = await make_server(mode)
    try:
        reader, writer = await asyncio.open_connection(srv.host, srv.port)
        if mode == "silent":
            # server never responds; leave the socket open like a hung camera
            pass
        else:
            writer.write(b"DESCRIBE rtsp://x/ RTSP/1.0\r\nCSeq: 1\r\n\r\n")
            await asyncio.wait_for(writer.drain(), 2.0)
        await asyncio.sleep(0.05)
        t0 = time.monotonic()
        await srv.stop()
        assert time.monotonic() - t0 < 5.0
    finally:
        srv.server = None  # already stopped above
        try:
            writer.close()
        except Exception:
            pass
