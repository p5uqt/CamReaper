"""Vendor fingerprinting from vendors.json.

The signature table is parsed once and cached: ``detect_vendor`` runs for every
live host and ``detect_vendor_http`` for every probed web panel, so re-reading
vendors.json per call was pure overhead.

Two independent signals are matched per vendor:

* ``server_contains``  - substrings of the RTSP ``Server`` header / HTTP
  ``Server`` header;
* ``realm_contains``   - substrings of the ``WWW-Authenticate`` realm.

The realm matters because a large share of real cameras send **no** ``Server``
header at all and identify themselves only through ``realm="IP Camera"``
(Hikvision) or ``realm="dahua"``.  Matching on the ``Server`` header alone
called every one of those devices "Generic", and the scanner then skipped the
whole CVE stage for them.
"""

import json
import re
from functools import lru_cache
from pathlib import Path

_VENDORS_PATH = Path(__file__).parent / "vendors.json"

# realm pattern compiled once, per vendor, on load.
_REALM_RE_CACHE: dict = {}

# The catch-all vendor matches everything (it has no needles), so it must always
# be tried last - otherwise it would swallow every host before a real signature
# is checked.  Enforced on load rather than trusted to the file's order.
_GENERIC = "Generic"


@lru_cache(maxsize=1)
def _load_vendors() -> tuple:
    """Return ``(vendors, compiled)``, both loaded once per process.

    ``compiled`` is a tuple of ``(vendor, server_needles, realm_re, realm_needles)``
    with every needle already lower-cased, so matching is a plain substring test.
    """
    with open(_VENDORS_PATH, "r", encoding="utf-8") as f:
        vendors = json.load(f)
    compiled = []
    for vendor in vendors:
        name = vendor["vendor"]
        patterns = vendor.get("patterns", {})
        needles = tuple(p.lower() for p in patterns.get("server_contains", ()))
        realm_needles = tuple(
            p.lower() for p in patterns.get("realm_contains", ())
        )
        realm_regex = patterns.get("realm_regex")
        realm_re = None
        if realm_regex:
            key = (realm_regex, re.IGNORECASE)
            realm_re = _REALM_RE_CACHE.get(key)
            if realm_re is None:
                realm_re = re.compile(realm_regex, re.IGNORECASE)
                _REALM_RE_CACHE[key] = realm_re
        compiled.append((name, needles, realm_re, realm_needles))
    # Generic matches unconditionally, so it has to be evaluated last.
    compiled.sort(key=lambda row: row[0] == _GENERIC)
    return tuple(vendors), tuple(compiled)


def _match(needles, realm_needles, realm_re, text: str, realm: str) -> bool:
    """True when the vendor's configured signals match.

    A vendor is identified when **any** of its signals fires; a vendor that
    configures no signal at all (Generic) matches unconditionally.
    """
    if needles or realm_needles or realm_re is None:
        # Something was configured, so something has to match.
        if not (
            (needles and any(n in text for n in needles))
            or (realm_needles and any(n in realm.lower() for n in realm_needles))
            or (realm_re is not None and realm_re.match(realm))
        ):
            return False
    return True


def detect_vendor(data: str) -> str:
    """Detect camera vendor from RTSP response ``data``.

    Matches the ``Server`` header and ``WWW-Authenticate`` realm
    against signatures in ``vendors.json``.
    Returns the vendor name (e.g. ``"Hikvision"``) or ``"Generic"``.
    """
    _, compiled = _load_vendors()
    if not data:
        return _GENERIC
    server_match = re.search(r"Server:\s*(.+)", data, re.IGNORECASE)
    server_line = server_match.group(1).strip().lower() if server_match else ""
    realm_match = re.search(r'realm="([^"]*)"', data, re.IGNORECASE)
    realm = realm_match.group(1) if realm_match else ""

    for vendor, needles, realm_re, realm_needles in compiled:
        if _match(needles, realm_needles, realm_re, server_line, realm):
            return vendor
    return _GENERIC


def detect_vendor_http(server_header: str, response_body: str = "") -> str:
    """Detect camera vendor from an HTTP response.

    Unlike the RTSP path there is no ``realm`` challenge; we match the
    ``Server`` header (and, as a fallback, the response body) against the same
    ``vendors.json`` signatures.  Returns a vendor name or ``"Generic"``.
    """
    _, compiled = _load_vendors()
    server_line = server_header.strip().lower()
    body = response_body.lower()

    # One pass matching the Server header against the vendor patterns.
    for vendor, needles, _re, _rn in compiled:
        if needles and any(n in server_line for n in needles):
            return vendor

    # Fallback: some HTTP panels don't advertise a vendor in the Server header
    # but do in the response body (e.g. a <title> or meta tag).
    for vendor, needles, _re, _rn in compiled:
        if needles and any(n in body for n in needles):
            return vendor
    return _GENERIC
