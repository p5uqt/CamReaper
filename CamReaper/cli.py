import argparse
from pathlib import Path
from typing import Any

from CamReaper import DEFAULT_CREDENTIALS, DEFAULT_ROUTES, __version__


class CustomHelpFormatter(argparse.HelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, max_help_position=40, width=99)

    def _format_action_invocation(self, action):
        if not action.option_strings or action.nargs == 0:
            return super()._format_action_invocation(action)
        default = self._get_default_metavar_for_optional(action)
        args_string = self._format_args(action, default)
        return ", ".join(action.option_strings) + " " + args_string


def file_path(value: Any):
    p = Path(value)
    if p.is_file():
        return p
    raise argparse.ArgumentTypeError(f"{value} is not a valid path")


def port(value: Any):
    if int(value) in range(65536):
        return int(value)
    raise argparse.ArgumentTypeError(f"{value} is not a valid port")


def positive_int(value: Any):
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError(f"{value} must be >= 1")
    return n


parser = argparse.ArgumentParser(
    prog="CamReaper",
    description="Asynchronous RTSP stream scanner with screenshots and gallery.",
    formatter_class=lambda prog: CustomHelpFormatter(prog),
)
parser.add_argument(
    "-t",
    "--targets",
    type=file_path,
    required=False,
    help="targets file (IPs, CIDRs and IP ranges, one per line)",
)
parser.add_argument(
    "-p",
    "--ports",
    nargs="+",
    default=[554],
    type=port,
    help=(
        "RTSP ports to scan (default: 554). Recommended: "
        "554 8554 5554 10554 8000 6800. Many cameras/DVRs also listen on "
        "8554/5554/10554/8000 in addition to 554."
    ),
)
parser.add_argument(
    "-r",
    "--routes",
    type=file_path,
    default=DEFAULT_ROUTES,
    help="path to custom route list",
)
parser.add_argument(
    "-c",
    "--credentials",
    type=file_path,
    default=DEFAULT_CREDENTIALS,
    help="path to custom credential list (user:pass per line)",
)
parser.add_argument(
    "-ct",
    "--check-concurrency",
    default=300,
    type=positive_int,
    metavar="N",
    help="max concurrent host pipelines (network connections)",
)
parser.add_argument(
    "-st",
    "--screenshot-concurrency",
    default=20,
    type=positive_int,
    metavar="N",
    help="max concurrent screenshot workers (decoding subprocesses)",
)
parser.add_argument(
    "--screenshot-timeout",
    default=10.0,
    type=float,
    metavar="S",
    help="seconds to wait for one screenshot frame (default: 10.0)",
)
parser.add_argument(
    "-T", "--timeout", default=2.0, type=float, help="socket timeout in seconds"
)
parser.add_argument(
    "--max-attempts",
    default=0,
    type=int,
    metavar="N",
    help=(
        "max credential attempts per host before giving up (0 = unlimited). "
        "Use this to avoid triggering the camera's failed-login lockout."
    ),
)
parser.add_argument(
    "--max-transport-fails",
    default=2,
    type=positive_int,
    metavar="N",
    help=(
        "max consecutive transport failures (timeouts, dropped sockets) "
        "before abandoning a host (default: 2). Increase for large credential "
        "lists where cameras may temporarily refuse connections."
    ),
)
parser.add_argument(
    "--attempts-per-sec",
    default=0.0,
    type=float,
    metavar="N",
    help=(
        "cap credential attempts per host per second (0 = no rate limit). "
        "Slows down brute force against a single host to dodge lockouts."
    ),
)
parser.add_argument(
    "--host-timeout",
    default=0.0,
    type=float,
    metavar="S",
    help=(
        "wall-clock budget (seconds) for one host's whole pipeline, "
        "0 = unlimited.  Stops flaky cameras from occupying a slot for minutes."
    ),
)
parser.add_argument(
    "--route-parallel",
    default=8,
    type=int,
    metavar="N",
    help=(
        "routes probed in parallel per host when hunting an open route "
        "(default: 8; 0 = serial). No creds are sent, so it can't trip "
        "login lockouts."
    ),
)
parser.add_argument(
    "--dedup",
    action="store_true",
    help=(
        "skip IPs already seen earlier in the scan (bounded LRU cache). "
        "Overlapping CIDRs and ranges would otherwise be scanned twice."
    ),
)
parser.add_argument(
    "--dedup-size",
    default=1_000_000,
    type=positive_int,
    metavar="N",
    help="LRU cache size for --dedup (default: 1000000)",
)
parser.add_argument(
    "--no-screenshots",
    action="store_true",
    help="skip screenshot capture (pure brute-force, fastest)",
)
parser.add_argument(
    "--scan-channels",
    action="store_true",
    help=(
        "after the scan, re-capture every channel of every confirmed stream "
        "(Hikvision 101..1601, Dahua h264/chN.., ONVIF ?channel=&subtype=) into "
        "the gallery index.html. Slower, but surfaces all camera channels."
    ),
)
parser.add_argument(
    "--scan-routes",
    type=file_path,
    default=DEFAULT_ROUTES,
    help=(
        "route list used ONLY by --scan-channels to probe every confirmed "
        "camera for all its open streams/channels (default: same as --routes). "
        "Does not affect the main scan."
    ),
)
parser.add_argument(
    "--gallery-html",
    type=file_path,
    metavar="FILE",
    help=(
        "build a gallery index.html (click-to-copy, double-click fullscreen) "
        "from a file of rtsp:// URLs, without scanning. Channels are expanded "
        "as in --scan-channels. Skips the scan."
    ),
)
parser.add_argument(
    "--capture",
    type=file_path,
    metavar="RESULTS.TXT",
    help=(
        "build a gallery site from a file of rtsp:// links (e.g. a result.txt "
        "of a previous run) WITHOUT brute-forcing: takes exactly ONE screenshot "
        "per link, writes images/ and index.html next to the file, with a "
        "progress bar. No scanning."
    ),
)
parser.add_argument(
    "--failed-file",
    nargs="?",
    type=str,
    const="__auto__",
    metavar="PATH",
    help=(
        "also write hosts whose port opened but whose RTSP could not be "
        "confirmed, one 'ip port' per line. PATH is optional: with no value "
        "the file lands in the report folder as 'failed.txt' next to "
        "result.txt. Only reachable-but-unconfirmed hosts are logged (never "
        "the millions of closed TCP ports), so it does not slow the scan. "
        "Off by default."
    ),
)
parser.add_argument(
    "--failed-with-error",
    action="store_true",
    help=(
        "with --failed-file, append a short error reason so lines read "
        "'ip port error'. The reason is already computed by the scan, so "
        "it adds no meaningful work."
    ),
)
parser.add_argument(
    "--no-auth-file",
    nargs="?",
    type=str,
    const="__auto__",
    metavar="PATH",
    help=(
        "also write hosts with a live RTSP port (it answered 401/403 and "
        "requires a password) for which NO credential in the list worked, one "
        "'ip port' per line. PATH is optional: with no value the file lands in "
        "the report folder as 'noauth.txt' next to result.txt. These are "
        "reachable cameras we could not open, so there are relatively few of "
        "them and it does not slow the scan. Off by default."
    ),
)
parser.add_argument(
    "--checkpoint",
    nargs="?",
    type=str,
    const="__auto__",
    metavar="PATH",
    help=(
        "save scan progress to PATH for later resumption. "
        "With no value the file lands in the report folder as 'checkpoint.json' "
        "(finished IPs are appended to PATH+'.ips')."
    ),
)
parser.add_argument(
    "--resume",
    nargs="?",
    type=str,
    const="__auto__",
    metavar="PATH",
    help=(
        "resume from a previous checkpoint file, skipping already-checked IPs. "
        "PATH is optional: with no value the newest reports/*/checkpoint.json "
        "is used."
    ),
)
parser.add_argument(
    "--mode",
    choices=["brute", "cve", "combined"],
    default="brute",
    help=(
        "scan mode: 'brute' = credential brute-force only (default), "
        "'cve' = CVE exploits only, 'combined' = CVE first then brute-force "
        "for unfound hosts."
    ),
)
parser.add_argument(
    "--cve-db",
    type=file_path,
    default=None,
    metavar="PATH",
    help=(
        "path to custom CVE database JSON file "
        "(default: built-in cve_db.json inside the package)."
    ),
)
parser.add_argument(
    "--http-ports",
    nargs="+",
    default=[80, 443, 8080],
    type=port,
    help=(
        "HTTP/HTTPS ports probed for CVE exploits when no RTSP port answers "
        "(default: 80 443 8080). Only checked in 'cve' or 'combined' mode, "
        "and only for hosts whose RTSP ports are all closed."
    ),
)
parser.add_argument(
    "--no-http",
    action="store_true",
    help="disable the HTTP CVE-probe fallback for hosts with no live RTSP port",
)
parser.add_argument(
    "-v", "--version", action="version", version=f"%(prog)s {__version__}"
)
