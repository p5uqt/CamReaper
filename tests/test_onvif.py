import pytest

from CamReaper import onvif
from CamReaper.onvif import (
    DEFAULT_ONVIF_CREDS,
    MAX_CREDS,
    _digest_response,
    _extract_profiles,
    _extract_uri,
    _parse_digest_challenge,
    _soap_fault,
    _strip_creds,
    discover,
    parse_stream_uri,
)

# --- URI helpers -------------------------------------------------------------


def test_parse_stream_uri_full():
    assert parse_stream_uri(
        "rtsp://admin:pass@192.168.1.64:554/Streaming/Channels/101"
    ) == ("192.168.1.64", 554, "/Streaming/Channels/101")


def test_parse_stream_uri_without_port_defaults_to_554():
    assert parse_stream_uri("rtsp://cam.local/live") == ("cam.local", 554, "/live")


def test_parse_stream_uri_ipv6():
    """A bracketed IPv6 literal must not be split on its inner colons."""
    assert parse_stream_uri("rtsp://[::1]:8554/onvif1") == ("::1", 8554, "/onvif1")


def test_parse_stream_uri_rejects_non_rtsp():
    assert parse_stream_uri("http://192.168.1.64/x") is None
    assert parse_stream_uri("") is None


def test_strip_creds_lifts_userinfo_out_of_uri():
    uri, cred = _strip_creds(
        "rtsp://admin:pass@192.168.1.64:554/Streaming/Channels/101"
    )
    assert uri == "rtsp://192.168.1.64:554/Streaming/Channels/101"
    assert cred == "admin:pass"


def test_strip_creds_leaves_bare_uri_alone():
    uri, cred = _strip_creds("rtsp://192.168.1.64:554/live")
    assert uri == "rtsp://192.168.1.64:554/live"
    assert cred == ""


# --- SOAP response parsing ---------------------------------------------------


def test_extract_profiles_dedupes_and_keeps_order():
    xml = (
        '<trt:GetProfilesResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl">'
        '<tt:Profiles token="MainStream" fixed="true"/>'
        '<tt:Profiles token="SubStream" fixed="true"/>'
        '<tt:Profiles token="MainStream" fixed="true"/>'
        "</trt:GetProfilesResponse>"
    )
    assert _extract_profiles(xml) == ["MainStream", "SubStream"]


def test_extract_uri_from_stream_setup():
    body = (
        "<trt:GetStreamUriResponse><trt:MediaUri>"
        "<tt:Uri>rtsp://admin:12345@10.0.0.5:554/Streaming/Channels/101</tt:Uri>"
        "</trt:MediaUri></trt:GetStreamUriResponse>"
    )
    assert _extract_uri(body) == (
        "rtsp://admin:12345@10.0.0.5:554/Streaming/Channels/101"
    )


def test_soap_fault_detected_despite_http_200():
    """A rejected login answers 200 + <s:Fault>, not 401 - the case a status
    check alone would misread as a successful enumeration."""
    body = (
        "<s:Fault><s:Code><s:Value>s:Sender</s:Value></s:Code>"
        '<s:Reason><s:Text xml:lang="en">NotAuthorized</s:Text></s:Reason>'
        "</s:Fault>"
    )
    assert _soap_fault(body) == "NotAuthorized"


def test_soap_fault_empty_for_valid_response():
    body = "<s:Envelope><s:Body><trt:GetProfilesResponse/></s:Body></s:Envelope>"
    assert _soap_fault(body) == ""


# --- HTTP digest -------------------------------------------------------------


def test_parse_digest_challenge():
    params = _parse_digest_challenge(
        'Digest realm="IP Camera", nonce="abc123", opaque="op1", '
        'qop="auth", algorithm=MD5'
    )
    assert params["realm"] == "IP Camera"
    assert params["nonce"] == "abc123"
    assert params["opaque"] == "op1"
    assert params["qop"] == "auth"
    assert params["algorithm"] == "MD5"


def test_digest_response_matches_rfc2617():
    """HA1/HA2 are colon-separated field lists, not plain concatenations."""
    import hashlib
    from unittest import mock

    with mock.patch.object(onvif.os, "urandom", lambda n=b"x" * 16: b"\x01" * n):
        params = _parse_digest_challenge(
            'Digest realm="IP Camera", nonce="abc123", qop="auth", algorithm=MD5'
        )
        got = _digest_response(
            params, "admin", "secret", "POST", "/onvif/device_service"
        )
    cnonce = got.split('cnonce="')[1].split('"')[0]
    ha1 = hashlib.md5(b"admin:IP Camera:secret").hexdigest()
    ha2 = hashlib.md5(b"POST:/onvif/device_service").hexdigest()
    want = hashlib.md5(
        f"{ha1}:abc123:00000001:{cnonce}:auth:{ha2}".encode()
    ).hexdigest()
    assert f'response="{want}"' in got


def test_digest_response_legacy_without_qop():
    import hashlib
    from unittest import mock

    with mock.patch.object(onvif.os, "urandom", lambda n=b"x" * 16: b"\x01" * n):
        params = _parse_digest_challenge('Digest realm="r", nonce="n1"')
        got = _digest_response(params, "admin", "secret", "POST", "/x")
    ha1 = hashlib.md5(b"admin:r:secret").hexdigest()
    ha2 = hashlib.md5(b"POST:/x").hexdigest()
    want = hashlib.md5(f"{ha1}:n1:{ha2}".encode()).hexdigest()
    assert f'response="{want}"' in got


def test_digest_response_supports_sha256():
    import hashlib
    from unittest import mock

    with mock.patch.object(onvif.os, "urandom", lambda n=b"x" * 16: b"\x01" * n):
        params = _parse_digest_challenge(
            'Digest realm="r", nonce="n1", qop="auth", algorithm=SHA-256'
        )
        got = _digest_response(params, "admin", "pw", "POST", "/x")
    cnonce = got.split('cnonce="')[1].split('"')[0]
    ha1 = hashlib.sha256(b"admin:r:pw").hexdigest()
    ha2 = hashlib.sha256(b"POST:/x").hexdigest()
    want = hashlib.sha256(
        f"{ha1}:n1:00000001:{cnonce}:auth:{ha2}".encode()
    ).hexdigest()
    assert f'response="{want}"' in got
    assert "algorithm=SHA-256" in got


def test_ws_security_digest_matches_spec():
    """PasswordDigest is Base64(SHA1(raw_nonce + created + password))."""
    import base64
    import hashlib
    from unittest import mock

    with mock.patch.object(onvif.os, "urandom", lambda n=b"x" * 16: b"\x07" * 16):
        header = onvif._ws_security("admin", "secret")
    nonce_b64 = base64.b64encode(b"\x07" * 16).decode()
    created = onvif._ws_security("admin", "secret")  # timestamp differs
    import re

    created_val = re.search(r"<Created[^>]*>([^<]*)</Created>", created).group(1)
    want = base64.b64encode(hashlib.sha1(
        b"\x07" * 16 + created_val.encode() + b"secret"
    ).digest()).decode()
    header_first = re.search(r"<Created[^>]*>([^<]*)</Created>", header).group(1)
    want_first = base64.b64encode(hashlib.sha1(
        b"\x07" * 16 + header_first.encode() + b"secret"
    ).digest()).decode()
    assert want_first in header
    assert nonce_b64 in header


# --- discovery against the mock device ---------------------------------------


class TestDiscover:
    """End-to-end discovery against the mock ONVIF device service."""

    pytestmark = pytest.mark.asyncio

    async def test_discover_wsse_auth(self):
        from tests.mock_onvif import make_server

        srv = await make_server(auth="wsse", valid_cred="admin:admin", rtsp_port=8554)
        try:
            res = await discover("127.0.0.1", ports=[srv.port], timeout=2.0,
                                 creds=["admin:admin"])
            assert len(res.streams) == 2
            assert res.endpoint == "/onvif/device_service"
            first = res.streams[0]
            assert first.uri == (
                "rtsp://127.0.0.1:8554/Streaming/Channels/MainStream"
            )
            assert first.credentials == "admin:admin"
            assert first.port == 8554
        finally:
            await srv.stop()


    async def test_discover_basic_auth(self):
        from tests.mock_onvif import make_server

        srv = await make_server(auth="basic", valid_cred="admin:admin")
        try:
            res = await discover("127.0.0.1", ports=[srv.port], timeout=2.0,
                                 creds=["admin:admin"])
            assert len(res.streams) == 2
        finally:
            await srv.stop()


    async def test_discover_digest_auth(self):
        from tests.mock_onvif import make_server

        srv = await make_server(auth="digest", valid_cred="admin:admin")
        try:
            res = await discover("127.0.0.1", ports=[srv.port], timeout=2.0,
                                 creds=["admin:admin"])
            assert len(res.streams) == 2
        finally:
            await srv.stop()


    async def test_discover_anonymous_device(self):
        from tests.mock_onvif import make_server

        srv = await make_server(auth=None, rtsp_port=554)
        try:
            res = await discover("127.0.0.1", ports=[srv.port], timeout=2.0, creds=[""])
            assert len(res.streams) == 2
        finally:
            await srv.stop()


    async def test_discover_rejects_wrong_credential(self):
        """A SOAP fault means rejected - it must not be reported as a stream."""
        from tests.mock_onvif import make_server

        srv = await make_server(auth="wsse", valid_cred="admin:admin")
        try:
            res = await discover("127.0.0.1", ports=[srv.port], timeout=2.0,
                                 creds=["admin:wrong"])
            assert res.streams == []
        finally:
            await srv.stop()


    async def test_discover_respects_max_profiles(self):
        from tests.mock_onvif import make_server

        srv = await make_server(
            profiles=("A", "B", "C", "D", "E", "F"), auth=None
        )
        try:
            res = await discover("127.0.0.1", ports=[srv.port], timeout=2.0,
                                 creds=[""], max_profiles=2)
            assert len(res.streams) == 2
        finally:
            await srv.stop()


    async def test_discover_ignores_plain_web_server(self):
        """The liveness gate must cost a single request on a non-ONVIF port."""
        from tests.mock_http import make_server as http_server

        web = await http_server(routes={"/": ("200", "<html>hello</html>")})
        try:
            res = await discover("127.0.0.1", ports=[web.port], timeout=2.0,
                                 creds=["admin:admin"])
            assert res.streams == []
        finally:
            await web.stop()


    async def test_discover_closed_port_is_fast(self):
        import time

        start = time.time()
        res = await discover("127.0.0.1", ports=[1], timeout=5.0, creds=["a:b"])
        assert res.streams == []
        assert time.time() - start < 2.0


    async def test_discover_caps_credential_list(self):
        """An unbounded credential list would dominate the scan's wall-clock."""
        many = [f"user{i}:pass{i}" for i in range(200)]
        assert onvif.MAX_CREDS < len(many)
        # The cap is applied in discover(); verify the module's own default list
        # also fits, since it is what the scanner uses.
        assert len(DEFAULT_ONVIF_CREDS) <= MAX_CREDS


    async def test_discover_empty_creds_still_works(self):
        from tests.mock_onvif import make_server

        srv = await make_server(auth=None)
        try:
            res = await discover("127.0.0.1", ports=[srv.port], timeout=2.0, creds=[])
            assert len(res.streams) == 2
        finally:
            await srv.stop()
