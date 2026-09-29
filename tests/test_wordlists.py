"""The shipped route wordlists must stay consistent with each other.

Regression: ``routecreds/routes.big.txt`` used to stop at channel 4 and carried
``unicast=true&proto=Onvif`` for channel 1 only, while
``routes4onvif2screen.txt`` held channels 1-16 of that form.  Someone hit the
multi-channel wall, made a dedicated file, and never merged it back - so a
16-channel NVR yielded one stream from the big list and up to sixteen from the
small one, and which list looked "better" depended purely on file choice.
"""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
ROUTE_DIR = ROOT / "routecreds"

# The hand-maintained defaults.  Every derived wordlist must contain all of
# them, otherwise a longer list is not a superset and can only ever find less.
CURATED = (
    ROOT / "CamReaper" / "defroutes",
    ROUTE_DIR / "routes4onvif2screen.txt",
)

DERIVED = (
    ROUTE_DIR / "routes.big.txt",
    ROUTE_DIR / "routes.txt",
)

CHANNELS = tuple(range(1, 17))


def _load(path: Path) -> list:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]


def _channels(routes, form: str) -> set:
    found = set()
    for r in routes:
        if not r.startswith("/cam/realmonitor?channel=") or form not in r:
            continue
        try:
            found.add(int(r.split("channel=")[1].split("&")[0]))
        except ValueError:
            continue
    return found


@pytest.mark.parametrize("path", DERIVED, ids=lambda p: p.name)
def test_derived_wordlist_is_superset_of_curated(path):
    have = set(_load(path))
    missing = [r for src in CURATED for r in _load(src) if r not in have]
    assert not missing, f"{path.name} drops {len(missing)} curated route(s): {missing[:5]}"


@pytest.mark.parametrize("path", DERIVED, ids=lambda p: p.name)
def test_derived_wordlist_has_no_duplicates(path):
    routes = _load(path)
    assert len(routes) == len(set(routes)), (
        f"{path.name} has {len(routes) - len(set(routes))} duplicate route(s)"
    )


@pytest.mark.parametrize("path", DERIVED, ids=lambda p: p.name)
@pytest.mark.parametrize(
    "form",
    (
        "subtype=0&unicast=true&proto=Onvif",
        "subtype=1&unicast=true&proto=Onvif",
    ),
)
def test_derived_wordlist_covers_every_channel(path, form):
    """A multi-channel NVR must be reachable on each of its channels.

    This is the exact gap that made a 271-entry list score worse than a
    16-entry one: the long list simply did not contain channels 5-16.
    """
    missing = sorted(set(CHANNELS) - _channels(_load(path), form))
    assert not missing, f"{path.name} misses {form} for channels {missing}"


@pytest.mark.parametrize("path", CURATED + DERIVED)
def test_wordlist_lines_are_usable_routes(path):
    """Every entry must be a bare path: a space would split the DESCRIBE request
    line, and a CR/LF would let a wordlist inject RTSP headers."""
    for route in _load(path):
        assert route.startswith("/"), f"{path.name}: {route!r} is not a path"
        assert not any(c.isspace() for c in route), (
            f"{path.name}: {route!r} contains whitespace"
        )
        assert route.isascii(), f"{path.name}: {route!r} is not ASCII"
