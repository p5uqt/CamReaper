"""ONVIF stream discovery (SOAP ``GetProfiles`` / ``GetStreamUri``).

Why this module exists
----------------------
``CamReaper`` used to only ever reach an RTSP stream by guessing paths against
the RTSP port.  That works for the vendors whose routes are well known, but a
large share of modern cameras speak ONVIF and will hand out their *exact*
stream URL - including the correct channel and the correct sub-stream - if you
just ask properly.  The ONVIF device service is served over **HTTP**, on a port
that is usually not the RTSP port, which is why the existing HTTP-CVE probing
never found it either.

The flow implemented here is the standard ONVIF discovery dance:

1. ``POST`` a ``GetProfiles`` request to the device/media service endpoint;
2. collect every ``<Profiles token="...">`` (one per channel, main + sub);
3. ``POST`` a ``GetStreamUri`` request for each token, which returns the
   device's own ``rtsp://...`` URL for that channel;
4. strip the credentials the device echoes back into the URL, so the resulting
   ``Found`` is authenticated the same way as every other result.

Authentication, in the order it is attempted (each is cheap and many devices
accept more than one):

* no credentials at all - a fair number of devices expose ``GetProfiles``
  unauthenticated;
* WS-Security ``UsernameToken`` with ``PasswordDigest`` (the ONVIF standard);
* WS-Security ``PasswordText`` (older firmware);
* HTTP Basic, then HTTP Digest - both are common on ONVIF panels.

Everything is plain asyncio + the shared native HTTP client from
:mod:`CamReaper.cve`; no XML parser dependency is needed because the responses
are simple enough to extract with a namespace-tolerant tag regex.
"""

import asyncio
import base64
import hashlib
import os
import re
import xml.sax.saxutils as saxutils
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from CamReaper.cve import _http_request_full

# Web ports that commonly serve the ONVIF device service.  Deliberately wider
# than the CVE web-panel list: ONVIF lives on vendor-specific ports far more
# often than the vulnerable panel does.
ONVIF_PORTS = (80, 8000, 8080, 8899, 2020, 34567, 5000, 81, 8081, 9000, 8082)

# Candidate service endpoints, tried in order.  ``device_service`` is first
# because most firmware serves the media actions there too; the rest cover
# vendors that split device and media services.
DEVICE_ENDPOINTS = (
    "/onvif/device_service",
    "/onvif/media_service",
    "/onvif/media",
    "/onvif/Media",
    "/onvif/services",
    "/onvif/device",
)

# Elements carry the ONVIF namespace, but firmware is inconsistent about
# declaring it, so both prefixed and unprefixed tags are accepted.
_TOKEN_RE = re.compile(
    rb"<(?:[A-Za-z0-9_.-]+:)?Profiles\b[^>]*?\btoken=\"([^\"]+)\"", re.IGNORECASE
)
_URI_RE = re.compile(
    rb"<(?:[A-Za-z0-9_.-]+:)?Uri\b[^>]*>(.*?)</(?:[A-Za-z0-9_.-]+:)?Uri>",
    re.IGNORECASE | re.DOTALL,
)

_SOAP_HEAD = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"'
    ' xmlns:tt="http://www.onvif.org/ver10/schema"'
    ' xmlns:tds="http://www.onvif.org/ver10/device/wsdl"'
    ' xmlns:timg="http://www.onvif.org/ver10/image/wsdl"'
    ' xmlns:trt="http://www.onvif.org/ver10/media/wsdl">'
    "<s:Header>"
    "{security}"
    "</s:Header>"
    "<s:Body>"
)
_SOAP_TAIL = "</s:Body></s:Envelope>"

# Common factory defaults, tried when the caller supplies no credential list.
DEFAULT_ONVIF_CREDS = (
    "admin:admin",
    "admin:password",
    "admin:12345",
    "admin:1234",
    "root:root",
    "supervisor:supervisor",
    "operator:operator",
    "guest:guest",
    "user:user",
)

# Cap on profiles turned into stream URIs.  A 64-channel NVR answers
# GetProfiles with dozens of tokens; converting all of them is a burst of SOAP
# calls for a result nobody will ever look at, so the first few are enough to
# prove the stream exists and let the RTSP stage take over.
MAX_PROFILES = 4

# Cap on credentials tried per port.  Every credential costs several SOAP
# round-trips per endpoint, so an unbounded list would make a single hostile or
# slow host dominate the scan's wall-clock time.
MAX_CREDS = 12


@dataclass
class OnvifStream:
    """One RTSP URL recovered from an ONVIF device."""

    uri: str
    profile: str = ""
    port: int = 0
    credentials: str = ""  # "" when the device needed none
    endpoint: str = ""


@dataclass
class OnvifResult:
    """Outcome of an ONVIF probe against one host."""

    streams: list = field(default_factory=list)
    endpoint: str = ""
    port: int = 0
    credentials: str = ""


def _get_profiles_body() -> bytes:
    return b"<trt:GetProfiles/>"


def _get_stream_uri_body(token: str) -> bytes:
    return (
        '<trt:GetStreamUri><trt:StreamSetup>'
        '<tt:Stream xmlns="http://www.onvif.org/ver10/schema">'
        "<tt:RTP-Unicast/></tt:Stream>"
        "</trt:StreamSetup><trt:ProfileToken>"
        + saxutils.escape(token)
        + "</trt:ProfileToken></trt:GetStreamUri>"
    ).encode()


def _ws_security(user: str, password: str) -> str:
    """WS-Security UsernameToken header (PasswordDigest).

    Digest form is ``Base64(SHA1(nonce + created + password))`` with the same
    nonce and timestamp echoed in the header - the standard ONVIF requirement.
    A few old firmware builds want ``PasswordText`` instead, so a text variant
    is kept alongside and tried when the digest one is rejected.
    """
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce = os.urandom(16)
    digest = base64.b64encode(
        hashlib.sha1(nonce + created.encode() + password.encode()).digest()
    ).decode()
    return (
        "<s:Security s:mustUnderstand=\"1\""
        ' xmlns="http://docs.oasis-open.org/wss/2004/01/'
        'oasis-200401-wss-wssecurity-secext-1.0.xsd">'
        "<UsernameToken>"
        f"<Username>{saxutils.escape(user)}</Username>"
        '<Password Type="http://docs.oasis-open.org/wss/2004/01/'
        'oasis-200401-wss-username-token-profile-1.0#PasswordDigest">'
        f"{digest}</Password>"
        '<Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/'
        'oasis-200401-wss-soap-message-security-1.0#Base64Binary">'
        f"{base64.b64encode(nonce).decode()}</Nonce>"
        f"<Created xmlns=\"http://docs.oasis-open.org/wss/2004/01/"
        f'oasis-200401-wss-wssecurity-utility-1.0.xsd">{created}</Created>'
        "</UsernameToken></s:Security>"
    )


def _ws_security_text(user: str, password: str) -> str:
    """WS-Security UsernameToken header with a cleartext password."""
    return (
        "<s:Security s:mustUnderstand=\"1\""
        ' xmlns="http://docs.oasis-open.org/wss/2004/01/'
        'oasis-200401-wss-wssecurity-secext-1.0.xsd">'
        "<UsernameToken>"
        f"<Username>{saxutils.escape(user)}</Username>"
        '<Password Type="http://docs.oasis-open.org/wss/2004/01/'
        'oasis-200401-wss-username-token-profile-1.0#PasswordText">'
        f"{saxutils.escape(password)}</Password>"
        "</UsernameToken></s:Security>"
    )


def _basic_auth(user: str, password: str) -> str:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return f"Basic {token}"


def _parse_digest_challenge(value: str) -> dict:
    """Parse a ``WWW-Authenticate: Digest ...`` challenge into a params dict."""
    params = {}
    _, _, rest = value.partition("Digest")
    for part in re.findall(r'(\w+)\s*=\s*(?:"([^"]*)"|([^,\s]+))', rest):
        key, quoted, bare = part
        params[key.lower()] = quoted or bare
    return params


def _digest_response(
    params: dict, user: str, password: str, method: str, uri: str,
) -> str:
    """Build the RFC 7616/2617 ``Authorization`` value for a digest challenge."""
    realm = params.get("realm", "")
    nonce = params.get("nonce", "")
    algorithm = params.get("algorithm", "MD5").upper()
    qop_raw = params.get("qop", "")
    qop = ""
    # qop may be a comma separated list; auth-int cannot be satisfied with a
    # password hash, so pick the first supported token.
    for token in qop_raw.split(","):
        token = token.strip().lower()
        if token in ("auth", "auth-int"):
            qop = "auth"
            break
    cnonce = base64.b64encode(os.urandom(8)).decode()
    nc = "00000001"

    # Each algorithm maps to a function returning a lowercase hex digest.
    # SHA-512-256 is SHA-512 truncated to 32 bytes, which hashlib has no
    # dedicated constructor for.
    def _md5(data: bytes) -> str:
        return hashlib.md5(data).hexdigest()

    def _sha256(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _sha512_256(data: bytes) -> str:
        return hashlib.sha512(data).hexdigest()[:64]

    hashers = {
        "MD5": _md5,
        "MD5-SESS": _md5,
        "SHA-256": _sha256,
        "SHA-256-SESS": _sha256,
        "SHA-512-256": _sha512_256,
    }
    h = hashers.get(algorithm, _md5)

    # HA1/HA2/response are all colon-separated field lists, not a plain
    # concatenation, so each one is joined explicitly.
    ha1 = h(f"{user}:{realm}:{password}".encode())
    ha2 = h(f"{method}:{uri}".encode())
    if qop:
        response = h(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode())
    else:
        # RFC 2069 legacy form, still used by older panels.
        response = h(f"{ha1}:{nonce}:{ha2}".encode())
    fields = [
        f'username="{user}"',
        f'realm="{realm}"',
        f'nonce="{nonce}"',
        f'uri="{uri}"',
        f'response="{response}"',
    ]
    if "opaque" in params:
        fields.append(f'opaque="{params["opaque"]}"')
    if qop:
        fields.extend([f"qop={qop}", f"nc={nc}", f'cnonce="{cnonce}"'])
    if algorithm != "MD5":
        fields.append(f"algorithm={algorithm}")
    return "Digest " + ", ".join(fields)


def _envelope(payload, security: str = "") -> bytes:
    """Wrap a SOAP body fragment in an Envelope, optionally with a WS-Security
    token in the header.  ``payload`` may be str or bytes."""
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8")
    return (
        _SOAP_HEAD.format(security=security) + payload + _SOAP_TAIL
    ).encode()


def _action_headers(action: str) -> list:
    return [
        ("Content-Type", 'text/xml; charset="utf-8"'),
        ("SOAPAction", f'"{action}"'),
        ("X-Forwarded-For", "127.0.0.1"),
    ]


def _strip_creds(uri: str) -> tuple:
    """Split ``rtsp://user:pass@host:port/path`` into ``(uri_without_creds, cred)``.

    ONVIF echoes the credentials used for the SOAP call back into the stream
    URI.  Keeping them would produce a result file line that works but looks
    unlike every other entry, so they are lifted out into the separate
    ``credentials`` field the scanner already uses everywhere else.
    """
    if not uri.lower().startswith("rtsp://"):
        return uri, ""
    rest = uri[7:]
    at = rest.find("@")
    if at < 0:
        return uri, ""
    userinfo = rest[:at]
    remainder = "rtsp://" + rest[at + 1:]
    if ":" in userinfo:
        user, _, password = userinfo.partition(":")
        return remainder, f"{user}:{password}"
    return remainder, userinfo


def _extract_profiles(body: str) -> list:
    """Return the profile tokens from a GetProfiles response, in document order.

    De-duplicated while preserving order: firmware commonly repeats a token
    across ``Profiles`` and the encoder extensions, and a repeated token would
    cost a redundant ``GetStreamUri`` call.
    """
    seen = []
    for match in _TOKEN_RE.finditer(body.encode("utf-8", errors="replace")):
        token = match.group(1).decode("utf-8", errors="replace").strip()
        if token and token not in seen:
            seen.append(token)
    return seen


def _extract_uri(body: str) -> str:
    match = _URI_RE.search(body.encode("utf-8", errors="replace"))
    if not match:
        return ""
    return match.group(1).decode("utf-8", errors="replace").strip()


def _soap_fault(body: str) -> str:
    """Return the fault string of a SOAP response, or "" if it is not a fault.

    A device answering a wrong credential replies ``200 OK`` carrying a
    ``<s:Fault>`` with ``NotAuthorized``, not a ``401`` - so a status check alone
    would treat every rejected login as a successful enumeration.  The leaf text
    is pulled out rather than the whole element so the value is loggable.
    """
    raw = body.encode("utf-8", errors="replace")
    if not re.search(rb"<(?:[A-Za-z0-9_.-]+:)?Fault\b", raw, re.IGNORECASE):
        return ""
    # FaultString is the standard element; Reason/s:Text is what most firmware
    # actually sends.  Both are leaf elements, so capture up to the next "<".
    for tag in (b"FaultString", b"Text"):
        match = re.search(
            rb"<(?:[A-Za-z0-9_.-]+:)?" + tag + rb"\b[^>]*>([^<]*)<",
            raw, re.IGNORECASE,
        )
        if match:
            text = match.group(1).decode("utf-8", errors="replace").strip()
            if text:
                return text[:120]
    return "fault"


async def _soap_post(ip, port, path, action, payload, timeout, extra=None):
    """POST one SOAP action. Returns ``(status, body, resp_headers)``."""
    headers = _action_headers(action)
    if extra:
        headers.extend(extra)
    status, _server, body, resp_headers = await _http_request_full(
        ip, port, path, method="POST",
        content_type='text/xml; charset="utf-8"',
        content=_envelope(payload).decode("utf-8"),
        timeout=timeout, headers=headers,
    )
    return status, body, resp_headers


async def _try_endpoint(ip, port, path, action, payload, timeout, cred) -> tuple:
    """One SOAP round-trip, walking the authentication strategies in order.

    Returns ``(body, resp_headers)``; ``body`` is "" when the device refused.
    """
    user = password = ""
    if cred and ":" in cred:
        user, _, password = cred.partition(":")
    elif cred:
        user, password = cred, ""

    # Anonymous first - a notable share of devices need no credentials for
    # GetProfiles, and it costs a single request.
    if not cred:
        status, body, hdrs = await _soap_post(ip, port, path, action, payload, timeout)
        if status == "200" and body and not _soap_fault(body):
            return body, hdrs
        return "", hdrs

    # A device that answers with a Digest challenge has told us exactly which
    # scheme it wants, and the WS-Security/Basic attempts before it are pure
    # waste - so the challenge is captured from the first response and reused
    # for the digest attempt at the end of the list.
    challenge = ""

    def _ok(status, body):
        return status == "200" and bool(body) and not _soap_fault(body)

    # WS-Security digest, then cleartext: the two forms ONVIF firmware accepts.
    # The security token lives *inside* the SOAP envelope, so these go through
    # _soap_post_security rather than as an HTTP header.
    for security in (_ws_security(user, password), _ws_security_text(user, password)):
        status, body, hdrs = await _soap_post_security(
            ip, port, path, action, payload, timeout, security,
        )
        challenge = challenge or hdrs.get("www-authenticate", "")
        if _ok(status, body):
            return body, hdrs

    # HTTP Basic.
    status, body, hdrs = await _soap_post(
        ip, port, path, action, payload, timeout,
        extra=[("Authorization", _basic_auth(user, password))],
    )
    challenge = challenge or hdrs.get("www-authenticate", "")
    if _ok(status, body):
        return body, hdrs

    # HTTP Digest, using the challenge captured above.
    if "digest" in challenge.lower():
        params = _parse_digest_challenge(challenge)
        auth = _digest_response(params, user, password, "POST", path)
        status, body, hdrs = await _soap_post(
            ip, port, path, action, payload, timeout,
            extra=[("Authorization", auth)],
        )
        if _ok(status, body):
            return body, hdrs
    return "", hdrs


async def _soap_post_security(ip, port, path, action, payload, timeout, security):
    """POST a SOAP action whose WS-Security token is embedded in the envelope."""
    headers = _action_headers(action)
    status, _server, body, resp_headers = await _http_request_full(
        ip, port, path, method="POST",
        content_type='text/xml; charset="utf-8"',
        content=_envelope(payload, security).decode("utf-8"),
        timeout=timeout, headers=headers,
    )
    return status, body, resp_headers


def _looks_onvif(status: str, body: str) -> bool:
    """Cheap "is this port an ONVIF device service?" test.

    A scanner probes a dozen ports per host and the overwhelming majority of
    them are either refused outright or an ordinary web panel.  Walking the full
    endpoint x credential matrix against those would cost dozens of requests
    each, so the port is gated first with a single anonymous ``GetProfiles``.

    Anything that answers with a SOAP envelope, an ONVIF namespace, or an
    ``Unauthorized`` challenge passes; a ``404``/empty answer from a plain web
    server does not.
    """
    if status == "401":
        return True
    if not body:
        return False
    low = body[:4096].lower()
    return "envelope" in low or "onvif" in low


async def _probe_port(ip, port, timeout, creds, max_profiles) -> OnvifResult:
    """Try every endpoint and credential against one port.

    Gated by a single anonymous request first, so a port that is not serving
    ONVIF costs one round-trip instead of ``len(creds) * len(DEVICE_ENDPOINTS)``.
    """
    payload = _get_profiles_body()
    result = OnvifResult(port=port)
    action_profiles = "http://www.onvif.org/ver10/media/wsdl/GetProfiles"

    try:
        status, body, _hdrs = await _soap_post(
            ip, port, DEVICE_ENDPOINTS[0], action_profiles, payload, timeout,
        )
    except Exception:
        return result
    if not _looks_onvif(status, body):
        return result

    for cred in creds:
        for path in DEVICE_ENDPOINTS:
            try:
                body, _hdrs = await _try_endpoint(
                    ip, port, path, action_profiles, payload, timeout, cred,
                )
            except Exception:
                continue
            if not body:
                continue
            tokens = _extract_profiles(body)
            if not tokens:
                continue
            streams = await _resolve_tokens(
                ip, port, path, tokens[:max_profiles], timeout, cred,
            )
            if streams:
                result.streams = streams
                result.endpoint = path
                result.credentials = cred or ""
                return result
    return result


async def _resolve_tokens(ip, port, path, tokens, timeout, cred) -> list:
    """Turn profile tokens into RTSP URIs via GetStreamUri."""
    streams = []
    for token in tokens:
        try:
            body, _hdrs = await _try_endpoint(
                ip, port, path,
                "http://www.onvif.org/ver10/media/wsdl/GetStreamUri",
                _get_stream_uri_body(token),
                timeout, cred,
            )
        except Exception:
            continue
        if not body:
            continue
        raw_uri = _extract_uri(body)
        if not raw_uri:
            continue
        if not raw_uri.lower().startswith("rtsp://"):
            continue
        uri, found_cred = _strip_creds(raw_uri)
        streams.append(OnvifStream(
            uri=uri,
            profile=token,
            port=_uri_port(uri, port),
            credentials=found_cred or (cred or ""),
            endpoint=path,
        ))
    return streams


def _uri_port(uri: str, fallback: int) -> int:
    """Best-effort port extraction from an ``rtsp://host:port/path`` URI."""
    match = re.search(r"rtsp://(?:\S*@)?(?:\[[^\]]+\]|[^/:]+):(\d+)", uri, re.IGNORECASE)
    if match:
        try:
            return int(match.group(1))
        except ValueError:
            return fallback
    return fallback


async def discover(
    ip: str,
    ports=None,
    timeout: float = 5.0,
    creds=None,
    max_profiles: int = MAX_PROFILES,
) -> OnvifResult:
    """Probe ``ip`` for an ONVIF device service and return its stream URIs.

    Ports are tried concurrently: the common ones (80/8080) usually answer or
    refuse instantly, and a wrong port costs one full timeout.  The first port
    that yields a stream short-circuits the rest.

    ``creds`` defaults to :data:`DEFAULT_ONVIF_CREDS`; pass an empty list to
    only try the anonymous request.  The list is truncated to
    :data:`MAX_CREDS` and de-duplicated: each credential costs several SOAP
    round-trips, so an unbounded list would turn a single host into minutes of
    wall-clock time.
    """
    port_list = list(ports) if ports else list(ONVIF_PORTS)
    cred_list = list(creds) if creds is not None else [""] + list(DEFAULT_ONVIF_CREDS)
    # De-duplicate while keeping the caller's ordering, then bound the cost.
    seen = set()
    trimmed = []
    for cred in cred_list:
        if cred not in seen:
            seen.add(cred)
            trimmed.append(cred)
    cred_list = trimmed[:MAX_CREDS] or [""]

    async def _one(port):
        try:
            return await _probe_port(ip, port, timeout, cred_list, max_profiles)
        except Exception:
            return OnvifResult(port=port)

    tasks = [asyncio.create_task(_one(p)) for p in port_list]
    try:
        for coro in asyncio.as_completed(tasks):
            res = await coro
            if res.streams:
                for t in tasks:
                    if not t.done():
                        t.cancel()
                return res
    except Exception:
        pass
    return OnvifResult()


def parse_stream_uri(uri: str, credentials: str = "") -> Optional[tuple]:
    """Turn an ONVIF ``rtsp://`` URI into a ``(host, port, route)`` triple.

    ``route`` keeps the leading slash and everything after it, matching the
    convention used by :class:`CamReaper.scanner.Found` elsewhere, so an
    ONVIF-discovered stream plugs straight into the normal result pipeline.
    """
    if not uri or not uri.lower().startswith("rtsp://"):
        return None
    rest = uri[7:]
    if "/" in rest:
        authority, _, path = rest.partition("/")
        route = "/" + path
    else:
        authority, route = rest, "/"
    if "@" in authority:
        authority = authority.rsplit("@", 1)[1]
    if authority.startswith("["):
        host, _, tail = authority.partition("]")
        host = host[1:]
        port_str = tail.lstrip(":")
    else:
        host, _, port_str = authority.partition(":")
    try:
        port = int(port_str) if port_str else 554
    except ValueError:
        port = 554
    return host, port, route or "/"
