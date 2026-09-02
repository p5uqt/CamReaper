"""Vendor fingerprinting from vendors.json."""

import json
import re
from pathlib import Path

_VENDORS_PATH = Path(__file__).parent / "vendors.json"


def _load_vendors():
    with open(_VENDORS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def detect_vendor(data: str) -> str:
    """Detect camera vendor from RTSP response ``data``.

    Matches the ``Server`` header and ``WWW-Authenticate`` realm
    against signatures in ``vendors.json``.
    Returns the vendor name (e.g. ``"Hikvision"``) or ``"Generic"``.
    """
    vendors = _load_vendors()
    server_match = re.search(r"Server:\s*(.+)", data, re.IGNORECASE)
    server_line = server_match.group(1).strip() if server_match else ""
    realm_match = re.search(r'realm="([^"]*)"', data, re.IGNORECASE)
    realm = realm_match.group(1) if realm_match else ""

    for vendor in vendors:
        patterns = vendor["patterns"]
        if _matches(patterns, server_line, realm):
            return vendor["vendor"]
    return "Generic"


def detect_vendor_http(server_header: str, response_body: str = "") -> str:
    """Detect camera vendor from an HTTP response.

    Unlike the RTSP path there is no ``realm`` challenge; we match the
    ``Server`` header (and, as a fallback, the response body) against the same
    ``vendors.json`` signatures.  Returns a vendor name or ``"Generic"``.
    """
    vendors = _load_vendors()
    server_line = server_header.strip()

    # One pass matching the Server header against the vendor patterns.
    for vendor in vendors:
        patterns = vendor["patterns"]
        if patterns.get("server_contains") and any(
            p.lower() in server_line.lower() for p in patterns["server_contains"]
        ):
            return vendor["vendor"]

    # Fallback: some HTTP panels don't advertise a vendor in the Server header
    # but do in the response body (e.g. a <title> or meta tag).
    for vendor in vendors:
        patterns = vendor["patterns"]
        if patterns.get("server_contains") and any(
            p.lower() in response_body.lower() for p in patterns["server_contains"]
        ):
            return vendor["vendor"]
    return "Generic"


def _matches(patterns, server_line: str, realm: str) -> bool:
    matched = True
    if patterns.get("server_contains"):
        if not any(
            p.lower() in server_line.lower() for p in patterns["server_contains"]
        ):
            matched = False
    if patterns.get("realm_regex") and matched:
        if not re.match(patterns["realm_regex"], realm, re.IGNORECASE):
            matched = False
    return matched


def get_vendors():
    """Return the list of known vendor definitions."""
    return _load_vendors()
