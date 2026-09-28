import asyncio
import json
import platform
import resource
import sys
import time
from pathlib import Path

from tqdm.auto import tqdm

from CamReaper import report, screenshot
from CamReaper.cli import parser
from CamReaper.gallery import build_from_urls, iter_url_list
from CamReaper.scanner import Settings, run
from CamReaper.targets import count_targets, describe as describe_targets, iter_targets, iter_unique


def _load_lines(path: Path):
    return path.read_text(encoding="utf-8").splitlines()


def _load_list(path: Path) -> list:
    """Load a wordlist (routes / credentials), dropping blanks and comments.

    A trailing empty line - the norm in every hand-edited list - used to become
    a route "" or, worse, a credential ""; the empty credential then reached
    the Digest/Basic auth code and could take down the whole scan.  Comments
    (``#``) are stripped too, so a list can be annotated.
    """
    out = []
    for raw in _load_lines(path):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def _c(text, code="36"):
    """ANSI-color ``text`` for the terminal (no color when not a TTY)."""
    if not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


# Companion file for a checkpoint: appends the IPs finished since the last flush
# (the JSON only ever stores stats, so it stays small and the run never
# re-serialises the whole history - resilient to very large scans).
IPS_SUFFIX = ".ips"
# Flush the checkpoint at least this often (per completed host pipeline).
CHECKPOINT_EVERY = 500


def _ips_path(checkpoint_file: Path) -> Path:
    return Path(str(checkpoint_file) + IPS_SUFFIX)


def _load_checkpoint(path: Path) -> "tuple[dict, set]":
    """Read a checkpoint JSON (stats) plus its companion .ips file (checked).

    Missing/partial files degrade gracefully: stats default to zero and any
    already-recorded IPs are still skipped on resume.
    """
    stats = {"checked": 0, "found": 0, "screenshots": 0}
    if path and path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
        stats.update(data.get("stats", {}))
    ips = set()
    ips_path = _ips_path(path)
    if ips_path.exists():
        try:
            ips.update(ips_path.read_text(encoding="utf-8").split())
        except OSError:
            pass
    return stats, ips


def _write_checkpoint(path: Path, checked_ips, stats) -> None:
    """Persist current stats + the IPs processed since the last flush.

    Stats go to the JSON (small rewrite); finished IPs are *appended* to the
    companion .ips file, so history is never re-written.  ``checked_ips`` is a
    list of IPs completed since the previous flush and is drained here.
    """
    if path is None:
        return
    try:
        path.write_text(json.dumps({"stats": stats}, indent=2), encoding="utf-8")
    except OSError:
        return
    if checked_ips:
        try:
            with _ips_path(path).open("a", encoding="utf-8") as f:
                f.write("\n".join(checked_ips) + "\n")
        except OSError:
            return
    checked_ips.clear()


async def _resumed_targets(source, checked: set):
    """Stream targets, skipping IPs already finished in a previous run."""
    async for ip in iter_targets(source):
        if ip not in checked:
            yield ip


def _raise_rlimit() -> int:
    """Best-effort raise of the open-file limit to support many sockets."""
    if platform.system() != "Linux":
        return 0
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard == resource.RLIM_INFINITY:
        new = 1_000_000
    else:
        new = hard
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (new, hard))
    except (ValueError, OSError):
        return soft
    return new


def _latest_checkpoint() -> "Path | None":
    """Most recently modified reports/*/checkpoint.json, or None."""
    root = Path.cwd() / "reports"
    if not root.exists():
        return None
    candidates = sorted(
        root.glob("*/checkpoint.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def _resolve_log_path(value, report_folder: Path, default_name: str) -> Path:
    """Resolve a --failed-file/--no-auth-file value to a concrete Path.

    ``value`` is either the ``__auto__`` marker (flag given without a value) or
    a user-supplied path string.  ``__auto__`` falls back to the report folder
    (next to result.txt); anything else is used verbatim.  Returns None if the
    flag was not given at all (callers only call this when the flag was set).
    """
    if value == "__auto__":
        return report_folder / default_name
    return Path(value)


def _capture_from_results(results_file: Path, args) -> None:
    """--capture: build a gallery site from a previous run's result.txt.

    Reads the rtsp:// links from ``results_file`` and takes exactly ONE
    screenshot per link (no channel expansion, no route probing), slowly, so as
    many streams as possible open.  Writes the pictures into
    ``<results_file.parent>/images/`` and an ``index.html`` gallery next to the
    results file itself.  A progress bar tracks every capture.
    """
    urls = list(iter_url_list(results_file))
    images_dir = results_file.parent / "images"
    images_dir.mkdir(parents=True, exist_ok=True)
    html_file = results_file.parent / "shots.html"

    report.HTML_FILE = html_file
    report.init_html(html_file)

    if not urls:
        print(_c(f"[warn] no rtsp:// URLs found in {results_file}", "33"))
        return

    # Leisurely capture: a low concurrency and a longer frame timeout push the
    # success rate up (cameras get time to answer instead of being swamped).
    concurrency = min(args.screenshot_concurrency, 8)
    timeout = max(args.screenshot_timeout, 15.0)

    print(
        _c(
            f"[info] capture: {len(urls)} link(s) -> images/ next to "
            f"{results_file.name}, concurrency={concurrency}, "
            f"timeout={timeout:.0f}s"
        )
    )

    tty = sys.stdout.isatty()

    async def _run():
        flush_task = report.start_flush_task()
        bar = tqdm(
            total=None,
            unit="shot",
            file=sys.stdout if tty else None,
            disable=not tty,
        )
        sem = asyncio.Semaphore(concurrency)
        pics: dict = {}
        done = 0

        async def _one(url: str):
            nonlocal done
            async with sem:
                pic = await screenshot.capture(url, images_dir, timeout)
            if pic:
                pics[url] = f"images/{Path(pic).name}"
            done += 1
            if bar.total is None:
                bar.total = len(urls)
                bar.refresh()
            bar.update(1)

        try:
            tasks = [asyncio.create_task(_one(u)) for u in urls]
            await asyncio.gather(*tasks, return_exceptions=True)
            await report.write_gallery_sections(list(pics.items()), report.HTML_FILE)
            return len(pics)
        finally:
            bar.close()
            flush_task.cancel()
            await asyncio.gather(flush_task, return_exceptions=True)
            await report.close_report_files()

    t0 = time.monotonic()
    shots = asyncio.run(_run())
    print(
        _c(
            f"[done] capture: {shots}/{len(urls)} screenshot(s) taken in "
            f"{time.monotonic() - t0:.1f}s",
            "32",
        )
    )
    print(_c(f"[done] gallery: {html_file}"))
    print(_c(f"[done] images: {images_dir}"))


def main():
    args = parser.parse_args()

    if args.targets is None and args.gallery_html is None and args.capture is None:
        parser.error("the following arguments are required: -t/--targets")

    # Screenshot-only mode: read every camera from a previous run's result.txt
    # and capture it slowly, without any brute force, to maximise how many
    # streams open.  Output lives next to the supplied file.
    if args.capture is not None:
        _capture_from_results(args.capture, args)
        return

    start = time.strftime("%Y.%m.%d-%H.%M.%S")
    report_folder = Path.cwd() / "reports" / start
    pics_dir = report_folder / "pics"
    pics_dir.mkdir(parents=True, exist_ok=True)

    report.RESULT_FILE = report_folder / "result.txt"
    report.HTML_FILE = report_folder / "index.html"
    report.RESULT_FILE.touch()
    report.init_html(report.HTML_FILE)

    # Channel-probing route list used by --scan-channels / --gallery-html to
    # discover every open stream of a confirmed camera (the channels the scan
    # stored only as a bare root "/").  Independent of the main scan's -r.
    # Loaded only when one of those modes is actually requested: a plain brute
    # scan never looks at it.
    scan_routes = _load_list(args.scan_routes) if (
        args.scan_channels or args.gallery_html is not None
    ) else []

    # Gallery-only mode: build the site from a supplied list of rtsp:// URLs,
    # no scanning at all.
    if args.gallery_html is not None:
        urls = list(iter_url_list(args.gallery_html))
        if not urls:
            print(_c(f"[warn] no rtsp:// URLs found in {args.gallery_html}", "33"))
            print(_c(f"[done] report: {report_folder}"))
            return
        print(
            _c(
                f"[info] gallery: {len(urls)} streams, "
                f"capturing all channels -> {report_folder}"
            )
        )

        tty = sys.stdout.isatty()

        async def _run_gallery():
            flush_task = report.start_flush_task()
            bar = tqdm(
                total=None,
                unit="shot",
                file=sys.stdout if tty else None,
                disable=not tty,
            )

            async def progress(done, total):
                if bar.total is None:
                    bar.total = total
                    bar.refresh()
                bar.update(1)

            try:
                shots = await build_from_urls(
                    urls,
                    pics_dir,
                    report.HTML_FILE,
                    timeout=args.screenshot_timeout,
                    concurrency=args.screenshot_concurrency,
                    routes=scan_routes,
                    route_parallel=args.route_parallel,
                    progress=progress,
                )
                # The gallery's input *is* its stream list: record it so
                # result.txt and streams.m3u carry the URLs instead of staying
                # empty (the mode reports found=len(urls), so the files must
                # match).  Written before the writers are closed below.
                for url in urls:
                    await report.record_url(url)
                bar.close()
                return shots
            except BaseException:
                bar.close()
                raise
            finally:
                flush_task.cancel()
                await asyncio.gather(flush_task, return_exceptions=True)
                await report.close_report_files()

        t0 = time.monotonic()
        shots = asyncio.run(_run_gallery())
        report.write_m3u(report.RESULT_FILE, report_folder / "streams.m3u")
        stats = {
            "checked": len(urls),
            "found": len(urls),
            "screenshots": shots,
            "found_no_frame": len(urls) - shots,
            "vendors": {},
            "ports": {},
            "errors": 0,
            "mode": "gallery",
        }
        report.write_summary(
            report_folder / "summary.json", stats, time.monotonic() - t0
        )
        print(
            _c(
                f"[done] gallery: {shots}/{len(urls)} channels captured in "
                f"{time.monotonic() - t0:.1f}s",
                "32",
            )
        )
        print(_c(f"[done] report: {report_folder}"))
        return

    # Optional failed-connection log.  Disabled by default so a plain run pays
    # nothing; only reachable-but-unconfirmed hosts are logged (never the
    # millions of closed TCP ports), so it never slows the scan.  With no value
    # the file lands in the report folder next to result.txt.
    # (report.FAILED_FILE / NO_AUTH_FILE are what the scanner's report layer
    # reads - they are wired here, not passed through Settings.)
    if args.failed_file is not None:
        report.FAILED_FILE = _resolve_log_path(
            args.failed_file, report_folder, "failed.txt"
        )
        report.FAILED_FILE.touch()

    # Optional "no credential worked" log for confirmed live RTSP hosts.
    if args.no_auth_file is not None:
        report.NO_AUTH_FILE = _resolve_log_path(
            args.no_auth_file, report_folder, "noauth.txt"
        )
        report.NO_AUTH_FILE.touch()

    # Optional CVE exploit log.
    if args.mode in ("cve", "combined"):
        report.CVE_LOG_FILE = report_folder / "cve_log.txt"
        report.CVE_LOG_FILE.touch()

    # Optional HTTP CVE-probe log (hosts with a vulnerable web panel but no
    # live RTSP port).
    if (
        not args.no_http
        and args.mode in ("cve", "combined")
        and args.http_ports
    ):
        report.HTTP_CVE_FILE = report_folder / "http_cve.txt"
        report.HTTP_CVE_FILE.touch()

    # Optional checkpoint/resume support.  On a fresh checkpoint run every
    # CHECKPOINT_EVERY completed hosts (and at the end / on Ctrl+C) the current
    # stats are written to the JSON and the finished IPs appended to the
    # companion `*.ips` file.  Resuming skips everything already recorded.
    checkpoint_file = None
    checked: set = None
    pending_ips: list = []
    resumed_stats = None
    if args.resume is not None:
        if args.resume == "__auto__":
            checkpoint_file = _latest_checkpoint()
        else:
            checkpoint_file = Path(args.resume)
        if checkpoint_file is None:
            print(_c("[warn] no checkpoint found under reports/, starting fresh", "33"))
            checkpoint_file = None
        else:
            resumed_stats, checked = _load_checkpoint(checkpoint_file)
            if resumed_stats["checked"] or checked:
                print(
                    _c(
                        f"[info] resumed from {checkpoint_file}, "
                        f"already checked {len(checked)} hosts "
                        f"(found {resumed_stats['found']})"
                    )
                )
            else:
                print(
                    _c(
                        f"[warn] no checkpoint data in {checkpoint_file}, starting fresh",
                        "33",
                    )
                )
                resumed_stats = None
    elif args.checkpoint is not None:
        if args.checkpoint == "__auto__":
            checkpoint_file = report_folder / "checkpoint.json"
        else:
            checkpoint_file = Path(args.checkpoint)
        checked = set()

    fd_limit = _raise_rlimit()
    print(_c(f"[info] report folder: {report_folder}"))
    if fd_limit:
        print(_c(f"[info] open-file limit: {fd_limit}"))

    ports = args.ports
    routes = _load_list(args.routes)
    credentials = _load_list(args.credentials)

    # Load CVE database if scan mode requires it.
    cve_db = None
    if args.mode in ("cve", "combined"):
        from CamReaper.cve import CVEDatabase

        db_path = Path(args.cve_db) if args.cve_db else (
            Path(__file__).parent / "cve_db.json"
        )
        if db_path.exists():
            cve_db = CVEDatabase(db_path)
            print(
                _c(
                    f"[info] CVE database: {db_path.name} "
                    f"({len(cve_db.entries)} exploits, "
                    f"{sum(len(e.credentials) for e in cve_db.entries if e.type == 'backdoor_creds')} backdoor creds)"
                )
            )
        else:
            if args.mode == "cve":
                parser.error(f"CVE mode requires a valid database: {db_path}")
            else:
                print(_c(f"[warn] CVE database not found: {db_path}, skipping CVE stage", "33"))

    n_targets = count_targets(args.targets)
    if checked:
        total = max(n_targets - len(checked), 0)
    else:
        total = n_targets
    print(
        _c(
            f"[info] mode={args.mode} targets={describe_targets(args.targets)} ips={total}/{n_targets} ports={ports} "
            f"routes={len(routes)} creds={len(credentials)}"
        )
    )

    # Long credential lists stall the tail: a slow-but-alive camera burns ~one
    # socket timeout per credential.  Cap each host with a wall-clock budget so
    # the run finishes promptly; an explicit --host-timeout overrides this.
    if args.host_timeout == 0 and len(credentials) >= 100:
        args.host_timeout = 30.0
        print(_c("[info] auto host budget: 30s (override with --host-timeout)", "33"))

    # ONVIF discovery is implied by the exploit-oriented modes (its whole point
    # is to replace RTSP route guessing with the device's own answer) and can be
    # enabled explicitly in 'brute' mode with --onvif, or turned off again with
    # --no-onvif.
    onvif_enabled = (
        (args.onvif or args.mode in ("cve", "combined")) and not args.no_onvif
    )

    settings = Settings(
        ports=ports,
        routes=routes,
        credentials=credentials,
        timeout=args.timeout,
        host_concurrency=args.check_concurrency,
        screenshot_concurrency=args.screenshot_concurrency,
        pics_dir=pics_dir,
        enable_screenshots=not args.no_screenshots,
        screenshot_timeout=args.screenshot_timeout,
        max_attempts=args.max_attempts,
        max_transport_fails=args.max_transport_fails,
        attempts_per_sec=args.attempts_per_sec,
        host_timeout=args.host_timeout,
        failed_with_error=args.failed_with_error,
        route_parallel=args.route_parallel,
        mode=args.mode,
        cve_db=cve_db,
        http_ports=args.http_ports,
        http_timeout=args.http_timeout,
        no_http=args.no_http,
        onvif=onvif_enabled,
        onvif_ports=list(args.onvif_ports) if args.onvif_ports else [],
        onvif_timeout=args.onvif_timeout,
        onvif_profiles=max(1, args.onvif_profiles),
        # The ONVIF module's own short default list is used unless the caller
        # supplied credentials: the scanner's full wordlist is sized for RTSP
        # bruting, and replaying thousands of it over SOAP would be pointless.
        onvif_creds=list(credentials) if (credentials and args.onvif) else [],
    )

    # Local mirror of the live stats; ``show`` copies the scanner's own dict here
    # so interrupt/shutdown reporting never loses progress even if run() is cut.
    stats = {
        "checked": 0,
        "found": 0,
        "screenshots": 0,
        "found_no_frame": 0,
        "vendors": {},
        "ports": {},
        "cve_found": 0,
        "cve_tested": 0,
        "http_checked": 0,
        "http_found": 0,
        "errors": 0,
        "error_samples": [],
        "mode": args.mode,
    }
    base = resumed_stats or {
        "checked": 0,
        "found": 0,
        "screenshots": 0,
        "found_no_frame": 0,
    }

    def merged() -> dict:
        return {
            "checked": stats["checked"] + base["checked"],
            "found": stats["found"] + base["found"],
            "screenshots": stats["screenshots"] + base["screenshots"],
            "found_no_frame": stats["found_no_frame"] + base["found_no_frame"],
            "cve_found": stats["cve_found"],
            "cve_tested": stats["cve_tested"],
            "http_checked": stats["http_checked"],
            "http_found": stats["http_found"],
            "errors": stats["errors"],
            "error_samples": list(stats.get("error_samples", ())),
        }

    # Compose the (possibly deduped) scan iterator.  The original targets Path is
    # kept for counting - never swapped out.
    if checked:
        scan_iter = _resumed_targets(args.targets, checked)
    else:
        scan_iter = iter_targets(args.targets)
    if args.dedup:
        scan_iter = iter_unique(scan_iter, args.dedup_size)

    tty = sys.stdout.isatty()
    t0 = time.monotonic()

    pbar = tqdm(
        total=total,
        unit="host",
        file=sys.stdout if tty else None,
        disable=not tty,
    )

    def show(current, ip):
        # Runs on the event loop for every completed host pipeline.
        if checked is not None:
            checked.add(ip)
            pending_ips.append(ip)
        for k in ("checked", "found", "screenshots", "found_no_frame",
                  "cve_found", "cve_tested", "http_checked", "http_found",
                  "errors"):
            stats[k] = current[k]
        stats["error_samples"] = list(current.get("error_samples", ()))
        stats["vendors"] = current["vendors"]
        stats["ports"] = current["ports"]
        pbar.update(1)
        if checkpoint_file is not None and len(pending_ips) >= CHECKPOINT_EVERY:
            _write_checkpoint(checkpoint_file, pending_ips, merged())

    def on_status(info):
        # Live status goes on the progress bar (TTY).  In pipe mode tqdm is
        # disabled and the watchdog falls back to plain lines by itself.
        # Numbers are highlighted so the counts read easily against the bar.
        def hi(v):
            return f"\033[32m{v}\033[0m" if tty else str(v)

        pbar.set_postfix_str(
            f"found={hi(info['found'])} "
            f"shots={hi(info['screenshots'])} in-flight={hi(info['inflight'])}",
            refresh=False,
        )

    def finish():
        if checkpoint_file is not None and pending_ips:
            _write_checkpoint(checkpoint_file, pending_ips, merged())

    def emit_reports():
        report.write_m3u(report.RESULT_FILE, report_folder / "streams.m3u")
        report.write_summary(
            report_folder / "summary.json", stats, time.monotonic() - t0
        )

    async def _run_scan():
        # Flush report writers periodically so files stay fresh mid-scan; on
        # exit (normal or raised) close them so nothing is left unflushed.
        flush_task = report.start_flush_task()
        try:
            await run(scan_iter, settings, on_counter=show, on_status=on_status)
        finally:
            flush_task.cancel()
            await asyncio.gather(flush_task, return_exceptions=True)
            await report.close_report_files()

    try:
        asyncio.run(_run_scan())
    except KeyboardInterrupt:
        finish()
        emit_reports()
        pbar.close()
        dt = time.monotonic() - t0
        print()
        print(
            _c(
                f"[interrupt] stopped by user after {dt:.1f}s: "
                f"checked={merged()['checked']} found={merged()['found']} "
                f"screenshots={merged()['screenshots']}",
                "33",
            )
        )
        if checkpoint_file is not None:
            print(_c(f"[info] checkpoint saved: {checkpoint_file}"))
        print(_c(f"[info] report: {report_folder}"))
        return

    finish()
    emit_reports()
    pbar.close()

    # Post-scan channel expansion: re-capture every channel of every confirmed
    # stream (Hikvision 101..1601, others as-is) into the gallery.
    if args.scan_channels:
        try:
            urls = report.RESULT_FILE.read_text(encoding="utf-8").splitlines()
        except OSError:
            urls = []
        urls = [u for u in urls if u]
        if not urls:
            print(
                _c("[warn] --scan-channels: no confirmed streams to re-capture", "33")
            )
        else:
            print(
                _c(
                    f"[info] --scan-channels: capturing all channels of "
                    f"{len(urls)} confirmed stream(s) -> {report_folder}",
                    "33",
                )
            )

            async def _run_channels():
                flush_task = report.start_flush_task()
                bar = tqdm(
                    total=None,
                    unit="shot",
                    file=sys.stdout if tty else None,
                    disable=not tty,
                )

                async def progress(done, total):
                    if bar.total is None:
                        bar.total = total
                        bar.refresh()
                    bar.update(1)

                try:
                    return await build_from_urls(
                        urls,
                        pics_dir,
                        report.HTML_FILE,
                        timeout=args.screenshot_timeout,
                        concurrency=args.screenshot_concurrency,
                        routes=scan_routes,
                        route_parallel=args.route_parallel,
                        progress=progress,
                    )
                finally:
                    bar.close()
                    flush_task.cancel()
                    await asyncio.gather(flush_task, return_exceptions=True)
                    await report.close_report_files()

            shots = asyncio.run(_run_channels())
            stats["screenshots"] += shots
            report.write_summary(
                report_folder / "summary.json", stats, time.monotonic() - t0
            )
            print(
                _c(
                    f"[done] channels captured: {shots} new screenshot(s) in "
                    f"{time.monotonic() - t0:.1f}s",
                    "32",
                )
            )

    dt = time.monotonic() - t0
    final = merged()
    print()
    print(
        _c(
            f"[done] checked={final['checked']} found={final['found']} "
            f"screenshots={final['screenshots']} in {dt:.1f}s",
            "32",
        )
    )
    no_frame = final.get("found_no_frame", 0)
    if no_frame:
        # found > screenshots is not a bug to hide: every one of these is a
        # camera whose RTSP stream opened fine but produced no decodable frame
        # (unusual codec, or it needed longer than --screenshot-timeout).  The
        # URLs are all in result.txt, so the number alone is enough to act on.
        print(
            _c(
                f"[warn] {no_frame} found camera(s) gave no frame "
                f"(try a larger --screenshot-timeout; URLs are in result.txt)",
                "33",
            )
        )
    if final["errors"]:
        # Host pipelines that raised are counted, not fatal: surface the number
        # instead of pretending the run was clean - every one of them is a host
        # that produced no findings.
        print(_c(f"[warn] {final['errors']} host(s) errored during the scan", "33"))
        for sample in final.get("error_samples", [])[:5]:
            print(_c(f"[warn]   {sample}", "33"))
    print(_c(f"[done] report: {report_folder}"))


if __name__ == "__main__":
    main()
