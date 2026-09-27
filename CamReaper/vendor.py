"""Vendor fingerprinting from vendors.json.

The signature table is parsed once and cached: ``detect_vendor`` runs for every
live host and ``detect_vendor_http`` for every probed web panel, so re-reading
vendors.json per call was pure overhead.
"""

import json
import re
from functools import lru_cache
from pathlib import Path

_VENDORS_PATH = Path(__file__).parent / "vendors.json"

# realm pattern compiled once, per vendor, on load.
_REALM_RE_CACHE: dict = {}


@lru_cache(maxsize=1)
def _load_vendors() -> tuple:
    """Return ``(vendors, compiled)``, both loaded once per process.

    ``compiled`` is a tuple of ``(vendor, server_needles, realm_re)`` with the
    needles already lower-cased, so matching is a plain substring test.
    """
    with open(_VENDORS_PATH, "r", encoding="utf-8") as f:
        vendors = json.load(f)
    compiled = []
    for vendor in vendors:
        patterns = vendor.get("patterns", {})
        needles = tuple(p.lower() for p in patterns.get("server_contains", ()))
        realm_regex = patterns.get("realm_regex")
        realm_re = None
        if realm_regex:
            key = (realm_regex, re.IGNORECASE)
            realm_re = _REALM_RE_CACHE.get(key)
            if realm_re is None:
                realm_re = re.compile(realm_regex, re.IGNORECASE)
                _REALM_RE_CACHE[key] = realm_re
        compiled.append((vendor["vendor"], needles, realm_re))
    return tuple(vendors), tuple(compiled)


def _match(needles, realm_re, text: str, realm: str) -> bool:
    """True when every configured signature matches its field."""
    if needles and not any(n in text for n in needles):
        return False
    if realm_re is not None and not realm_re.match(realm):
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
        return "Generic"
    server_match = re.search(r"Server:\s*(.+)", data, re.IGNORECASE)
    server_line = server_match.group(1).strip().lower() if server_match else ""
    realm_match = re.search(r'realm="([^"]*)"', data, re.IGNORECASE)
    realm = realm_match.group(1) if realm_match else ""

    for vendor, needles, realm_re in compiled:
        if _match(needles, realm_re, server_line, realm):
            return vendor
    return "Generic"


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
    for vendor, needles, _ in compiled:
        if needles and any(n in server_line for n in needles):
            return vendor

    # Fallback: some HTTP panels don't advertise a vendor in the Server header
    # but do in the response body (e.g. a <title> or meta tag).
    for vendor, needles, _ in compiled:
        if needles and any(n in body for n in needles):
            return vendor
    return "Generic"
