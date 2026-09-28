import pytest

from CamReaper.vendor import _load_vendors, detect_vendor, detect_vendor_http


def _rtsp(server=None, realm=None):
    """Build a minimal RTSP 401 response with an optional Server/realm header."""
    lines = ["RTSP/1.0 401 Unauthorized", "CSeq: 1"]
    if server is not None:
        lines.append(f"Server: {server}")
    if realm is not None:
        lines.append(f'WWW-Authenticate: Digest realm="{realm}"')
    return "\r\n".join(lines) + "\r\n\r\n"


# --- Server header fingerprinting --------------------------------------------


@pytest.mark.parametrize("server,expected", [
    ("Hikvision-Webs/1.0", "Hikvision"),
    ("DahuaTech", "Dahua"),
    ("V380", "V380"),
    ("AVTECH", "AVTECH"),
    ("Zosi", "Zosi"),
    ("Sony RTSP Server", "Sony"),
    ("PTZOptics", "PTZOptics"),
    ("Netwave", "Netwave"),
    ("Tapo", "TP-Link"),
    ("Axis Communications", "Axis"),
])
def test_detect_vendor_from_server_header(server, expected):
    assert detect_vendor(_rtsp(server=server)) == expected


# --- realm fingerprinting ---------------------------------------------------
# A large share of real cameras send no Server header at all and identify
# themselves only through the WWW-Authenticate realm.


@pytest.mark.parametrize("realm,expected", [
    ("IP Camera", "Hikvision"),
    ("IP Camera(2069)", "Hikvision"),
    ("dahua", "Dahua"),
    ("Login to host", "Dahua"),
    ("Xiongmai", "Xiongmai"),
    ("XMEye", "Xiongmai"),
    ("V380", "V380"),
    ("AVTECH", "AVTECH"),
    ("Zosi", "Zosi"),
    ("Netwave", "Netwave"),
    ("PTZOptics", "PTZOptics"),
])
def test_detect_vendor_from_realm_only(realm, expected):
    assert detect_vendor(_rtsp(realm=realm)) == expected


def test_realm_alone_identifies_device_without_server_header():
    """The exact case that used to be classified as Generic, which made the
    scanner skip the whole CVE stage for those hosts."""
    data = _rtsp(realm="IP Camera")
    assert "Server:" not in data
    assert detect_vendor(data) == "Hikvision"


# --- Generic fallthrough -----------------------------------------------------


def test_unknown_device_is_generic():
    assert detect_vendor(_rtsp(server="Mock", realm="r")) == "Generic"


def test_empty_response_is_generic():
    assert detect_vendor("") == "Generic"


def test_generic_never_shadows_a_specific_signature():
    """Generic matches unconditionally; it must be evaluated last."""
    _vendors, compiled = _load_vendors()
    assert compiled[-1][0] == "Generic"
    assert detect_vendor(_rtsp(server="DahuaTech", realm="IP Camera")) == "Dahua"


# --- XMEye / Xiongmai name mismatch -------------------------------------------


def test_xiongmai_covered_under_the_cve_db_vendor_name():
    """vendors.json used to say "XMEye" while cve_db.json says "Xiongmai", so
    the Xiongmai CVE entries were unreachable."""
    vendors, _compiled = _load_vendors()
    names = {v["vendor"] for v in vendors}
    assert "Xiongmai" in names
    assert "XMEye" not in names
    assert detect_vendor(_rtsp(server="XMEye")) == "Xiongmai"


# --- HTTP fingerprinting -----------------------------------------------------


@pytest.mark.parametrize("header,expected", [
    ("Dahua", "Dahua"),
    ("nginx", "Generic"),
    ("", "Generic"),
])
def test_detect_vendor_http_from_server_header(header, expected):
    assert detect_vendor_http(header) == expected


def test_detect_vendor_http_falls_back_to_body():
    assert detect_vendor_http("nginx", "<html>Hikvision web panel</html>") == (
        "Hikvision"
    )
