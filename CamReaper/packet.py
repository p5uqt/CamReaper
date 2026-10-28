"""RTSP request packet construction with cached digest primitives.

RTSP servers challenge with either ``Basic`` or ``Digest``.  Real cameras use
both, and many Digest implementations require RFC 2617 ``qop=auth``, an
``opaque`` value or a non-MD5 algorithm - all of which used to be ignored.  The
helpers here build a request for whichever scheme the server actually
advertised, instead of always guessing Digest whenever a realm was present.
"""

import base64
import functools
import hashlib
import secrets


@functools.lru_cache(maxsize=1024)
def _basic_auth(credentials: str) -> str:
    # utf-8, not ascii: a non-ASCII password must not raise and kill the scan
    encoded = base64.b64encode(credentials.encode("utf-8"))
    return f"Authorization: Basic {str(encoded, 'utf-8')}"


@functools.lru_cache(maxsize=4096)
def _ha1(username: str, realm: str, password: str) -> str:
    """Legacy MD5 HA1 helper (kept for callers/tests)."""
    return hashlib.md5(
        f"{username}:{realm}:{password}".encode("utf-8")
    ).hexdigest()


def _hash(algorithm: str, data: bytes) -> str:
    """Hash ``data`` with the RFC 7616 algorithm named by ``algorithm``.

    ``-SESS`` variants are handled by the caller (they hash the HA1 again);
    here the base algorithm is enough.  Unknown algorithms fall back to MD5,
    which is what virtually every camera speaks.
    """
    name = (algorithm or "MD5").upper()
    if name.endswith("-SESS"):
        name = name[:-5]
    if name in ("SHA-256", "SHA256"):
        return hashlib.sha256(data).hexdigest()
    if name in ("SHA-512-256", "SHA512-256"):
        try:
            return hashlib.new("sha512_256", data).hexdigest()
        except (ValueError, TypeError):  # old/limited OpenSSL build
            return hashlib.sha512(data).hexdigest()[:64]
    return hashlib.md5(data).hexdigest()


def _digest_auth(
    option,
    ip,
    port,
    path,
    credentials,
    realm,
    nonce,
    opaque="",
    algorithm="MD5",
    qop="",
    nc=1,
    cnonce=None,
):
    """Build a Digest ``Authorization`` header.

    The parameter list is deliberately backwards compatible: with the original
    seven positional arguments the output is byte-identical to the old
    RFC 2069 form (no ``qop``, no ``opaque``, no ``algorithm``), so existing
    firmware that only understands that form is not disturbed.
    """
    # partition (not split): a credential line without ":" must still produce a
    # request instead of raising ValueError and aborting the whole scan.
    username, _, password = credentials.partition(":")
    host = f"[{ip}]" if ":" in str(ip) and not str(ip).startswith("[") else ip
    uri = f"rtsp://{host}:{port}{path}"

    algo = (algorithm or "MD5").upper()
    if algo not in (
        "MD5",
        "MD5-SESS",
        "SHA-256",
        "SHA-256-SESS",
        "SHA-512-256",
        "SHA-512-256-SESS",
    ):
        algo = "MD5"

    ha1 = _hash(algo, f"{username}:{realm}:{password}".encode("utf-8"))
    if algo.endswith("-SESS"):
        cnonce = cnonce or secrets.token_hex(8)
        ha1 = _hash(algo, f"{ha1}:{nonce}:{cnonce}".encode("utf-8"))
    if qop == "auth-int":
        # DESCRIBE has no request body, so the entity hash is of the empty
        # string.  Some older firmware advertises auth-int only.
        entity = _hash(algo, b"")
        ha2 = _hash(algo, f"{option}:{uri}:{entity}".encode("utf-8"))
    else:
        ha2 = _hash(algo, f"{option}:{uri}".encode("utf-8"))

    if qop:
        cnonce = cnonce or secrets.token_hex(8)
        nc_value = f"{int(nc):08x}"
        response = _hash(
            algo,
            f"{ha1}:{nonce}:{nc_value}:{cnonce}:{qop}:{ha2}".encode("utf-8"),
        )
    else:
        response = _hash(algo, f"{ha1}:{nonce}:{ha2}".encode("utf-8"))

    fields = [
        f'username="{username}"',
        f'realm="{realm}"',
        f'nonce="{nonce}"',
        f'uri="{uri}"',
        f'response="{response}"',
    ]
    if opaque:
        fields.append(f'opaque="{opaque}"')
    if qop:
        fields.extend([f"qop={qop}", f"nc={nc_value}", f'cnonce="{cnonce}"'])
    elif algo.endswith("-SESS"):
        # Session algorithms need the cnonce even in the legacy (no-qop) form.
        fields.append(f'cnonce="{cnonce}"')
    if algo != "MD5":
        fields.append(f"algorithm={algo}")
    return "Authorization: Digest " + ", ".join(fields)


def describe(
    ip,
    port,
    path,
    cseq,
    credentials,
    realm=None,
    nonce=None,
    scheme=None,
    opaque="",
    algorithm="MD5",
    qop="",
    nc=1,
    cnonce=None,
) -> str:
    """Build a DESCRIBE request.

    ``credentials == ":"`` means "no credentials" -> no Authorization header.
    ``scheme`` is the challenge type learned from ``WWW-Authenticate``:
    ``"basic"``, ``"digest"`` or ``None``.  ``None`` keeps the historical
    behaviour (Digest when a realm is known, Basic otherwise) so small callers
    and old firmware keep working.
    """
    host = f"[{ip}]" if ":" in str(ip) and not str(ip).startswith("[") else ip
    if credentials == ":":
        auth = ""
    elif scheme == "basic":
        auth = f"{_basic_auth(credentials)}\r\n"
    elif scheme == "digest" or (scheme is None and realm):
        header = _digest_auth(
            "DESCRIBE",
            ip,
            port,
            path,
            credentials,
            realm,
            nonce,
            opaque=opaque,
            algorithm=algorithm,
            qop=qop,
            nc=nc,
            cnonce=cnonce,
        )
        auth = f"{header}\r\n"
    else:
        auth = f"{_basic_auth(credentials)}\r\n"

    return (
        f"DESCRIBE rtsp://{host}:{port}{path} RTSP/1.0\r\n"
        f"CSeq: {cseq}\r\n"
        f"{auth}"
        "User-Agent: Mozilla/5.0\r\n"
        "Accept: application/sdp\r\n"
        "\r\n"
    )
