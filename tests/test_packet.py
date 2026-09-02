from CamReaper import packet

BASIC = "Authorization: Basic YWRtaW46YWRtaW4="
DIGEST = (
    "Authorization: Digest "
    'username="user", '
    'realm="realm", '
    'nonce="nonce", '
    'uri="rtsp://0.0.0.0:554", '
    'response="03183d81a44f1e402bd7983108917856"'
)


def test_basic_auth_cached():
    packet._basic_auth.cache_clear()
    assert packet._basic_auth("admin:admin") == BASIC
    packet._basic_auth("admin:admin")
    assert packet._basic_auth.cache_info().hits == 1


def test_ha1():
    packet._ha1.cache_clear()
    assert packet._ha1("user", "realm", "user") == "54cdcbe980ed379cae3e478ac29c67dc"


def test_no_auth():
    assert packet.describe("0.0.0.0", 554, "/", 1, ":") == (
        "DESCRIBE rtsp://0.0.0.0:554/ RTSP/1.0\r\n"
        "CSeq: 1\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Accept: application/sdp\r\n"
        "\r\n"
    )


def test_basic_auth_packet():
    assert packet.describe("0.0.0.0", 554, "/", 1, "admin:admin") == (
        "DESCRIBE rtsp://0.0.0.0:554/ RTSP/1.0\r\n"
        "CSeq: 1\r\n"
        f"{BASIC}\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Accept: application/sdp\r\n"
        "\r\n"
    )


def test_digest_auth_packet():
    assert packet.describe("0.0.0.0", 554, "", 1, "user:user", "realm", "nonce") == (
        "DESCRIBE rtsp://0.0.0.0:554 RTSP/1.0\r\n"
        "CSeq: 1\r\n"
        f"{DIGEST}\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Accept: application/sdp\r\n"
        "\r\n"
    )


def test_credential_with_extra_colon_in_password():
    packet._ha1.cache_clear()
    packet.describe("1.2.3.4", 554, "/", 1, "admin:pa:ss", "realm", "nonce")
    # password should be "pa:ss", not just "ss" - ensure no exception and
    # ha1 cache key includes the full password.
    digest = packet._digest_auth(
        "DESCRIBE", "1.2.3.4", 554, "/", "admin:pa:ss", "realm", "nonce"
    )
    assert 'username="admin"' in digest
