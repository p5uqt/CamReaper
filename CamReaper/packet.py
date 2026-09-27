"""RTSP request packet construction with cached digest primitives."""

import base64
import functools
import hashlib


@functools.lru_cache(maxsize=1024)
def _basic_auth(credentials: str) -> str:
    # utf-8, not ascii: a non-ASCII password must not raise and kill the scan
    encoded = base64.b64encode(credentials.encode("utf-8"))
    return f"Authorization: Basic {str(encoded, 'utf-8')}"


@functools.lru_cache(maxsize=4096)
def _ha1(username: str, realm: str, password: str) -> str:
    return hashlib.md5(f"{username}:{realm}:{password}".encode("utf-8")).hexdigest()


def _digest_auth(option, ip, port, path, credentials, realm, nonce):
    # partition (not split): a credential line without ":" must still produce a
    # request instead of raising ValueError and aborting the whole scan.
    username, _, password = credentials.partition(":")
    uri = f"rtsp://{ip}:{port}{path}"
    ha1 = _ha1(username, realm, password)
    ha2 = hashlib.md5(f"{option}:{uri}".encode("utf-8")).hexdigest()
    response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode("utf-8")).hexdigest()
    return (
        "Authorization: Digest "
        f'username="{username}", '
        f'realm="{realm}", '
        f'nonce="{nonce}", '
        f'uri="{uri}", '
        f'response="{response}"'
    )


def describe(ip, port, path, cseq, credentials, realm=None, nonce=None) -> str:
    """Build a DESCRIBE request.

    `credentials == ":"` means "no credentials" → no Authorization header.
    """
    if credentials == ":":
        auth = ""
    elif realm:
        auth = (
            f"{_digest_auth('DESCRIBE', ip, port, path, credentials, realm, nonce)}\r\n"
        )
    else:
        auth = f"{_basic_auth(credentials)}\r\n"

    return (
        f"DESCRIBE rtsp://{ip}:{port}{path} RTSP/1.0\r\n"
        f"CSeq: {cseq}\r\n"
        f"{auth}"
        "User-Agent: Mozilla/5.0\r\n"
        "Accept: application/sdp\r\n"
        "\r\n"
    )
