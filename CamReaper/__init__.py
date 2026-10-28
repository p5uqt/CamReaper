from pathlib import Path

__version__ = "4.4.0"
# Balanced/max defaults (the larger curated lists).
DEFAULT_ROUTES = Path(__file__).parent / "defroutes"
DEFAULT_CREDENTIALS = Path(__file__).parent / "defcreds"
# The original small wordlists, used by --profile fast.  Fast is meant to
# behave like the pre-profile scanner: a handful of routes/credentials and no
# expensive discovery stages.
FAST_ROUTES = Path(__file__).parent / "defroutes.fast"
FAST_CREDENTIALS = Path(__file__).parent / "defcreds.fast"
