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
        matched = True
        if patterns.get("server_contains"):
            if not any(
                p.lower() in server_line.lower() for p in patterns["server_contains"]
            ):
                matched = False
        if patterns.get("realm_regex") and matched:
            if not re.match(patterns["realm_regex"], realm, re.IGNORECASE):
                matched = False
        if matched:
            return vendor["vendor"]
    return "Generic"


def get_vendors():
    """Return the list of known vendor definitions."""
    return _load_vendors()
