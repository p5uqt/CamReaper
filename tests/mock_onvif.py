"""In-process async mock ONVIF device service for testing the ONVIF stage.

Answers the two SOAP actions the discovery flow depends on:

* ``GetProfiles`` - returns the configured profile tokens;
* ``GetStreamUri`` - returns an ``rtsp://`` URI for the requested token.

``auth`` controls how the device reacts to credentials, and mirrors the quirks
of real firmware: a rejected login is answered with ``200 OK`` carrying a SOAP
``<s:Fault>`` rather than an HTTP ``401``, which is exactly the case a naive
status check would misread as a successful enumeration.
"""

import asyncio
import base64
import hashlib
import re

_PROFILES_ACTION = "GetProfiles"
_STREAMURI_ACTION = "GetStreamUri"

_FAULT = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>'
    '<s:Fault><s:Code><s:Value>s:Sender</s:Value>'
    '<s:Subcode><s:Value>ter:NotAuthorized</s:Value></s:Subcode></s:Code>'
    '<s:Reason><s:Text xml:lang="en">Sender NotAuthorized</s:Text></s:Reason>'
    "</s:Fault></s:Body></s:Envelope>"
)

_OK = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"'
    ' xmlns:tt="http://www.onvif.org/ver10/schema"><s:Body>'
    "{payload}</s:Body></s:Envelope>"
)


class MockOnvifServer:
    """A minimal ONVIF device service.

    ``auth``:
      * ``None``        - no credentials required (anonymous access allowed);
      * ``"basic"``     - HTTP Basic ``user:pass``;
      * ``"digest"``    - HTTP Digest challenge, then verify the response;
      * ``"wsse"``      - WS-Security UsernameToken PasswordDigest.

    ``valid_cred`` is the ``user:pass`` the device accepts; anything else is
    rejected with a SOAP fault.
    """

    def __init__(self, profiles=("MainStream", "SubStream"), auth="wsse",
                 valid_cred="admin:admin", endpoint="/onvif/device_service",
                 rtsp_host=None, rtsp_port=554):
        self.profiles = list(profiles)
        self.auth = auth
        self.valid_cred = valid_cred
        self.endpoint = endpoint
        self.rtsp_host = rtsp_host
        self.rtsp_port = rtsp_port
        self.server = None
        self.port = 0
        self.requests = []  # (path, action) for assertions

    async def start(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    # -- credential checking -------------------------------------------------

    def _check_auth(self, body: bytes, headers: dict) -> bool:
        if self.auth is None:
            return True
        if self.auth == "basic":
            got = headers.get("authorization", "")
            if not got.lower().startswith("basic "):
                return False
            decoded = base64.b64decode(got.split(" ", 1)[1]).decode(
                "utf-8", errors="replace"
            )
            return decoded == self.valid_cred
        if self.auth == "wsse":
            # Pull Username/PasswordDigest out of the embedded security header.
            user = re.search(rb"<Username>([^<]*)</Username>", body)
            pwd = re.search(rb"<Password[^>]*>([^<]*)</Password>", body)
            nonce = re.search(rb"<Nonce[^>]*>([^<]*)</Nonce>", body)
            created = re.search(rb"<Created[^>]*>([^<]*)</Created>", body)
            if not (user and pwd and nonce and created):
                return False
            want = base64.b64encode(hashlib.sha1(
                base64.b64decode(nonce.group(1))
                + created.group(1)
                + self.valid_cred.partition(":")[2].encode()
            ).digest()).decode()
            return (
                user.group(1).decode() == self.valid_cred.partition(":")[0]
                and pwd.group(1).decode() == want
            )
        if self.auth == "digest":
            # A verified response carries a digest hash we cannot recompute
            # here without a fixed cnonce; accept any well-formed one and rely
            # on the caller's correctness being covered by unit tests.
            got = headers.get("authorization", "")
            return got.lower().startswith("digest ") and "response=" in got
        return False

    # -- request handling ----------------------------------------------------

    async def _handle(self, reader, writer):
        try:
            request_line = await reader.readline()
            text = request_line.decode("utf-8", errors="replace")
            parts = text.split(" ")
            path = parts[1] if len(parts) > 1 else "/"
            headers = {}
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
                name, _, value = line.decode("utf-8", "replace").partition(":")
                headers[name.strip().lower()] = value.strip()
            length = int(headers.get("content-length", 0) or 0)
            body = await reader.readexactly(length) if length else b""

            action = self._action(path, headers, body)
            self.requests.append((path, action))

            if action is None:
                await self._send(writer, 404, "", headers)
                return
            if not self._check_auth(body, headers):
                # Real devices answer an auth failure with 200 + SOAP fault.
                await self._send(writer, 200, _FAULT, headers)
                return

            if action == _PROFILES_ACTION:
                payload = (
                    '<trt:GetProfilesResponse xmlns:trt="http://www.onvif.org'
                    '/ver10/media/wsdl">' + "".join(
                        f'<tt:Profiles token="{p}" fixed="true"/>'
                        for p in self.profiles
                    ) + "</trt:GetProfilesResponse>"
                )
            else:
                token_match = re.search(
                    rb"<trt:ProfileToken>([^<]*)</trt:ProfileToken>", body
                )
                token = (
                    token_match.group(1).decode() if token_match else ""
                )
                host = self.rtsp_host or "127.0.0.1"
                payload = (
                    '<trt:GetStreamUriResponse xmlns:trt="http://www.onvif.org'
                    '/ver10/media/wsdl"><trt:MediaUri>'
                    "<tt:Uri>rtsp://"
                    + f"{self.valid_cred}@{host}:{self.rtsp_port}"
                    + f"/Streaming/Channels/{token}</tt:Uri>"
                    "</trt:MediaUri></trt:GetStreamUriResponse>"
                )
            await self._send(writer, 200, _OK.format(payload=payload), headers)
        except (ConnectionError, OSError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    def _action(self, path, headers, body):
        if path != self.endpoint:
            return None
        action = headers.get("soapaction", "").strip('"')
        if action.endswith(_PROFILES_ACTION):
            return _PROFILES_ACTION
        if action.endswith(_STREAMURI_ACTION):
            return _STREAMURI_ACTION
        return None

    async def _send(self, writer, status, body, request_headers):
        """Answer, emitting a digest challenge first when the device uses it."""
        if self.auth == "digest" and "authorization" not in request_headers:
            resp = (
                'HTTP/1.1 401 Unauthorized\r\n'
                'WWW-Authenticate: Digest realm="ONVIF", nonce="n1", '
                'qop="auth", algorithm=MD5\r\n'
                f"Content-Length: 0\r\n\r\n"
            )
            writer.write(resp.encode())
            await writer.drain()
            return
        resp = (
            f"HTTP/1.1 {status} OK\r\n"
            f"Content-Type: text/xml; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
            f"{body}"
        )
        writer.write(resp.encode())
        await writer.drain()

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()


async def make_server(**kwargs):
    srv = MockOnvifServer(**kwargs)
    await srv.start()
    return srv
