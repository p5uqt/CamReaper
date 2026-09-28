import argparse
import shutil
from pathlib import Path
from typing import Any

from CamReaper import DEFAULT_CREDENTIALS, DEFAULT_ROUTES, __version__
from CamReaper import targets


def positive_int(value: Any):
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError(f"{value} must be >= 1")
    return n


# --- help rendering ----------------------------------------------------------


def _terminal_width(default: int = 100) -> int:
    """Usable help width, clamped so the option column stays readable.

    argparse hardcodes a 80-column default that wraps the help text into a
    narrow ribbon, while an unbounded width produces very long lines on a wide
    terminal.  The column holding the flag names is what actually needs a bound.
    """
    try:
        columns = shutil.get_terminal_size(fallback=(default, 24)).columns
    except (OSError, ValueError):
        return default
    return max(70, min(columns - 2, default))


class CustomHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Wider option column, and an epilog that keeps its own line breaks.

    ``RawDescriptionHelpFormatter`` only preserves line breaks in the
    description/epilog; everything else is still wrapped, which is what we want
    for the long per-option explanations.
    """

    def __init__(self, prog):
        super().__init__(
            prog, max_help_position=32, width=_terminal_width()
        )

    def _format_action_invocation(self, action):
        # Same as the base class, except that the option strings are joined with
        # ", " on one line instead of argparse's default (which puts each
        # spelling on its own line and makes "-t, --targets SPEC" three rows).
        if not action.option_strings or action.nargs == 0:
            return super()._format_action_invocation(action)
        default = self._get_default_metavar_for_optional(action)
        args_string = self._format_args(action, default)
        return ", ".join(action.option_strings) + " " + args_string


def _render_default(value: Any) -> str:
    """Render a default value for the help text."""
    if isinstance(value, Path):
        # A full package path is noise; the file name is what the user needs.
        return value.name
    if isinstance(value, (list, tuple)):
        return " ".join(str(v) for v in value)
    return str(value)


def _with_default(kwargs: dict) -> dict:
    """Append the option's default to its help text, in place.

    Nearly every flag in this CLI has a meaningful default, and the help output
    used to state some of them inline and silently omit others - so ``--help``
    could not be trusted to say what a run would actually do.  Rendering it from
    the same object argparse uses removes that whole class of drift.
    """
    help_text = kwargs.get("help")
    default = kwargs.get("default")
    if help_text is None or default in (None, argparse.SUPPRESS):
        return kwargs
    # store_true/store_false flags: "default: False" is pure noise.
    if isinstance(default, bool):
        return kwargs
    kwargs["help"] = (
        f"{help_text.rstrip()} (default: {_render_default(default)})"
    )
    return kwargs


class _HelpGroup(argparse._ArgumentGroup):
    """An argument group that renders defaults like :class:`HelpParser`.

    ``add_argument_group`` builds a plain ``_ArgumentGroup``, which has its own
    ``add_argument`` and would otherwise bypass the parser's rendering entirely -
    i.e. every grouped option would silently lose its default.
    """

    def add_argument(self, *args, **kwargs):
        return super().add_argument(*args, **_with_default(kwargs))


class HelpParser(argparse.ArgumentParser):
    """``ArgumentParser`` that appends each option's default to its help text."""

    def add_argument(self, *args, **kwargs):
        return super().add_argument(*args, **_with_default(kwargs))

    def add_argument_group(self, *args, **kwargs):
        group = _HelpGroup(self, *args, **kwargs)
        self._action_groups.append(group)
        return group


def file_path(value: Any):
    p = Path(value)
    if p.is_file():
        return p
    raise argparse.ArgumentTypeError(f"{value} is not a valid path")


def target_arg(value: str):
    """Resolve ``-t`` into a targets *file* or an inline target spec.

    Both forms are documented (and used in the README examples):
      * a file with one target per line - ``-t targets.txt``;
      * a literal list on the command line - ``-t 192.168.1.0/24``,
        ``-t 10.0.0.1-10.0.0.9``, ``-t 1.1.1.1,8.8.8.8``.

    A real file always wins, so a stray name that happens to look like a spec
    cannot be mistaken for one.
    """
    p = Path(value)
    if p.is_file():
        return p
    if targets.is_valid_spec(value):
        return value
    raise argparse.ArgumentTypeError(
        f"{value!r} is neither an existing targets file nor a target spec "
        "(e.g. 192.168.1.0/24, 10.0.0.1-10.0.0.9, 1.1.1.1)"
    )


def _check_port(number: int, value: Any) -> int:
    if 1 <= number <= 65535:
        return number
    raise argparse.ArgumentTypeError(f"{value} is not a valid port")


def port(value: Any) -> list:
    """Parse one port spec into a list of ports.

    Accepted forms: ``554``, ``8000-8008`` (inclusive range) and
    ``8554-8554`` (single-port range).  A reversed range such as
    ``8008-8000`` is rejected instead of silently returning nothing.
    """
    text = str(value).strip()
    if "-" in text:
        low_s, _, high_s = text.partition("-")
        try:
            low = _check_port(int(low_s), value)
            high = _check_port(int(high_s), value)
        except ValueError:
            raise argparse.ArgumentTypeError(
                f"{value} is not a valid port range"
            ) from None
        if low > high:
            raise argparse.ArgumentTypeError(f"{value} is not a valid port range")
        return list(range(low, high + 1))
    try:
        return [_check_port(int(text), value)]
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value} is not a valid port") from None


class PortList(argparse.Action):
    """Collect ``nargs="+"`` port specs into one flat, de-duplicated list.

    A range spec such as ``8000-8008`` expands to several ports, so the specs
    are flattened here, keeping the order the user asked for and dropping
    duplicates.  Bad specs are reported as a normal argparse error.

    Membership is tracked in a set: ``"1-65535" not in ports`` is a linear scan
    of the whole list, which made the full port range take ~18s of pure CPU
    before the scan even started.
    """

    def __call__(self, parser, namespace, values, option_string=None):
        if isinstance(values, (str, bytes)):
            values = [values]
        ports: list = []
        seen: set = set()
        for value in values:
            try:
                expanded = port(value)
            except argparse.ArgumentTypeError as exc:
                parser.error(f"argument {option_string or self.dest}: {exc}")
            for number in expanded:
                if number not in seen:
                    seen.add(number)
                    ports.append(number)
        setattr(namespace, self.dest, ports)


def positive_int(value: Any):
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError(f"{value} must be >= 1")
    return n


_DESCRIPTION = """\
Brute-force camera credentials, run known exploits, ask ONVIF devices for
their stream URL, and build a screenshot gallery. Options are grouped below;
every option states its own default."""

_EPILOG = """\
examples:
  # scan a /24 on the usual camera ports
  CamReaper -t 192.168.1.0/24 -p 554 8554 8000

  # exploit-first, then fall back to brute-force for whatever is left
  CamReaper -t targets.txt --mode combined

  # brute mode, but ask each host for its stream URL over ONVIF
  CamReaper -t targets.txt --onvif

  # slow and gentle, to stay under a camera's failed-login lockout
  CamReaper -t targets.txt --attempts-per-sec 5 --max-attempts 10

  # build a gallery from a previous run's result.txt, no scanning
  CamReaper --capture reports/latest/result.txt

  # resume an interrupted scan
  CamReaper -t targets.txt --resume
"""


parser = HelpParser(
    prog="CamReaper",
    description=_DESCRIPTION,
    epilog=_EPILOG,
    formatter_class=CustomHelpFormatter,
)

# -- targets and wordlists ----------------------------------------------------
target_group = parser.add_argument_group("targets and wordlists")
target_group.add_argument(
    "-t",
    "--targets",
    type=target_arg,
    metavar="SPEC",
    help=(
        "targets file (one IP, CIDR or range per line) or an inline spec: "
        "'192.168.1.0/24', '10.0.0.1-10.0.0.9', '1.1.1.1,8.8.8.8'"
    ),
)
target_group.add_argument(
    "-p",
    "--ports",
    nargs="+",
    default=[554],
    action=PortList,
    metavar="PORTS",
    help=(
        "RTSP ports, ranges allowed ('554 8554' or '8000-8008'). Cameras and "
        "DVRs commonly listen on 554 plus 8554/5554/10554/8000/6800"
    ),
)
target_group.add_argument(
    "-r",
    "--routes",
    type=file_path,
    default=DEFAULT_ROUTES,
    metavar="FILE",
    help="route list to probe (one path per line)",
)
target_group.add_argument(
    "-c",
    "--credentials",
    type=file_path,
    default=DEFAULT_CREDENTIALS,
    metavar="FILE",
    help="credential list to try ('user:pass' per line)",
)

# -- exploits: CVE and ONVIF --------------------------------------------------
exploit_group = parser.add_argument_group("exploits: CVE and ONVIF")
exploit_group.add_argument(
    "--mode",
    choices=["brute", "cve", "combined"],
    default="brute",
    help=(
        "'brute' = credentials only, 'cve' = exploits only, 'combined' = "
        "exploits first, then brute-force for hosts still unfound"
    ),
)
exploit_group.add_argument(
    "--cve-db",
    type=file_path,
    default=None,
    metavar="FILE",
    help="custom CVE database (JSON); omit to use the built-in cve_db.json",
)
exploit_group.add_argument(
    "--http-ports",
    nargs="+",
    default=[80, 443, 8080],
    action=PortList,
    metavar="PORTS",
    help=(
        "web ports for CVE probes, ranges allowed. Only used in 'cve' or "
        "'combined' mode, and only for hosts whose RTSP ports are all closed"
    ),
)
exploit_group.add_argument(
    "--http-timeout",
    default=5.0,
    type=float,
    metavar="S",
    help="socket timeout for CVE HTTP probes; lower it for hosts that swallow packets",
)
exploit_group.add_argument(
    "--no-http",
    action="store_true",
    help="disable the HTTP CVE-probe fallback",
)
exploit_group.add_argument(
    "--onvif",
    action="store_true",
    help=(
        "ask each host for its stream URL over ONVIF (SOAP GetProfiles / "
        "GetStreamUri) instead of guessing RTSP routes. Implied by 'cve' and "
        "'combined'; use it to enable ONVIF in 'brute' mode"
    ),
)
exploit_group.add_argument(
    "--no-onvif",
    action="store_true",
    help="disable ONVIF discovery even in 'cve'/'combined' mode",
)
exploit_group.add_argument(
    "--onvif-ports",
    nargs="+",
    default=None,
    action=PortList,
    metavar="PORTS",
    help=(
        "web ports probed for the ONVIF device service, ranges allowed. "
        "ONVIF listens on vendor-specific ports far more often than the "
        "vulnerable web panel does; omit for the built-in list"
    ),
)
exploit_group.add_argument(
    "--onvif-timeout",
    default=5.0,
    type=float,
    metavar="S",
    help="socket timeout for ONVIF SOAP requests",
)
exploit_group.add_argument(
    "--onvif-profiles",
    default=4,
    type=int,
    metavar="N",
    help=(
        "ONVIF profiles per device to resolve into RTSP URLs. Each one costs a "
        "GetStreamUri call, and a 64-channel NVR answers with dozens of tokens"
    ),
)

# -- pacing and robustness ----------------------------------------------------
perf_group = parser.add_argument_group("pacing and robustness")
perf_group.add_argument(
    "-ct",
    "--check-concurrency",
    default=300,
    type=positive_int,
    metavar="N",
    help="max concurrent host pipelines (network connections)",
)
perf_group.add_argument(
    "-T",
    "--timeout",
    default=2.0,
    type=float,
    metavar="S",
    help="socket timeout per network operation",
)
perf_group.add_argument(
    "--route-parallel",
    default=8,
    type=int,
    metavar="N",
    help=(
        "routes probed in parallel per host when hunting an open route "
        "(0 = serial). No credentials are sent, so it cannot trip lockouts"
    ),
)
perf_group.add_argument(
    "--max-attempts",
    default=0,
    type=int,
    metavar="N",
    help=(
        "credential attempts per host before giving up (0 = unlimited). Use "
        "this to avoid triggering the camera's failed-login lockout"
    ),
)
perf_group.add_argument(
    "--max-transport-fails",
    default=2,
    type=positive_int,
    metavar="N",
    help=(
        "consecutive transport failures (timeouts, dropped sockets) before "
        "abandoning a host. Raise it for large credential lists, where cameras "
        "may temporarily refuse connections"
    ),
)
perf_group.add_argument(
    "--attempts-per-sec",
    default=0.0,
    type=float,
    metavar="N",
    help=(
        "cap credential attempts per host per second (0 = no limit). Slows "
        "brute-force against one host to dodge lockouts"
    ),
)
perf_group.add_argument(
    "--host-timeout",
    default=0.0,
    type=float,
    metavar="S",
    help=(
        "wall-clock budget for one host's whole pipeline (0 = unlimited). "
        "Stops flaky cameras from occupying a slot for minutes"
    ),
)
perf_group.add_argument(
    "--dedup",
    action="store_true",
    help=(
        "skip IPs already seen earlier in the scan (bounded LRU cache); "
        "overlapping CIDRs and ranges would otherwise be scanned twice"
    ),
)
perf_group.add_argument(
    "--dedup-size",
    default=1_000_000,
    type=positive_int,
    metavar="N",
    help="LRU cache size for --dedup",
)

# -- screenshots and gallery --------------------------------------------------
gallery_group = parser.add_argument_group("screenshots and gallery")
gallery_group.add_argument(
    "-st",
    "--screenshot-concurrency",
    default=20,
    type=positive_int,
    metavar="N",
    help="max concurrent screenshot workers (decoding subprocesses)",
)
gallery_group.add_argument(
    "--screenshot-timeout",
    default=10.0,
    type=float,
    metavar="S",
    help="seconds to wait for one screenshot frame",
)
gallery_group.add_argument(
    "--no-screenshots",
    action="store_true",
    help="skip screenshot capture (pure brute-force, fastest)",
)
gallery_group.add_argument(
    "--scan-channels",
    action="store_true",
    help=(
        "after the scan, re-capture every channel of every confirmed stream "
        "(Hikvision 101..1601, Dahua h264/chN.., ONVIF ?channel=&subtype=) "
        "into the gallery. Slower, but surfaces all camera channels"
    ),
)
gallery_group.add_argument(
    "--scan-routes",
    type=file_path,
    default=DEFAULT_ROUTES,
    metavar="FILE",
    help=(
        "route list used ONLY by --scan-channels to probe each confirmed camera "
        "for all of its open streams. Does not affect the main scan"
    ),
)
gallery_group.add_argument(
    "--gallery-html",
    type=file_path,
    metavar="FILE",
    help=(
        "build a gallery index.html (click-to-copy, double-click fullscreen) "
        "from a file of rtsp:// URLs, without scanning"
    ),
)
gallery_group.add_argument(
    "--capture",
    type=file_path,
    metavar="RESULTS.TXT",
    help=(
        "build a gallery from a previous run's result.txt WITHOUT scanning: one "
        "screenshot per link, writes images/ and index.html next to the file, "
        "with a progress bar"
    ),
)

# -- extra output files -------------------------------------------------------
output_group = parser.add_argument_group("extra output files")
output_group.add_argument(
    "--failed-file",
    nargs="?",
    type=str,
    const="__auto__",
    metavar="PATH",
    help=(
        "also write hosts whose port opened but whose RTSP could not be "
        "confirmed, one 'ip port' per line. PATH is optional: with no value the "
        "file lands in the report folder as failed.txt. Only "
        "reachable-but-unconfirmed hosts are logged, so it does not slow the scan"
    ),
)
output_group.add_argument(
    "--failed-with-error",
    action="store_true",
    help=(
        "with --failed-file, append a short error reason so lines read "
        "'ip port error'. The reason is already computed by the scan"
    ),
)
output_group.add_argument(
    "--no-auth-file",
    nargs="?",
    type=str,
    const="__auto__",
    metavar="PATH",
    help=(
        "also write reachable cameras that required a password but accepted no "
        "credential in the list, one 'ip port' per line. PATH is optional: with "
        "no value the file lands in the report folder as noauth.txt"
    ),
)

# -- checkpoint / resume ------------------------------------------------------
resume_group = parser.add_argument_group("checkpoint and resume")
resume_group.add_argument(
    "--checkpoint",
    nargs="?",
    type=str,
    const="__auto__",
    metavar="PATH",
    help=(
        "save scan progress for later resumption. With no value the file lands "
        "in the report folder as checkpoint.json (finished IPs are appended to "
        "PATH+'.ips')"
    ),
)
resume_group.add_argument(
    "--resume",
    nargs="?",
    type=str,
    const="__auto__",
    metavar="PATH",
    help=(
        "resume from a previous checkpoint, skipping already-checked IPs. PATH "
        "is optional: with no value the newest reports/*/checkpoint.json is used"
    ),
)

parser.add_argument(
    "-v", "--version", action="version", version=f"%(prog)s {__version__}"
)
