"""Report output: result.txt (plain URLs), index.html gallery, summary.json
and streams.m3u (ready-to-play playlist).

Every output is written through a small buffered, lock-guarded writer so a
large scan does not pay an open()/write()/close() syscall per URL.  Buffers are
flushed as they fill up (and on shutdown via ``close_report_files``); a stray
crash loses at most a few thousand lines.
"""

import asyncio
import json
import re
import shutil
from pathlib import Path
from typing import Dict, Optional

RESULT_FILE: Optional[Path] = None
HTML_FILE: Optional[Path] = None
FAILED_FILE: Optional[Path] = (
    None  # set by __main__ to enable failed-connection logging
)
NO_AUTH_FILE: Optional[Path] = (
    None  # set by __main__ to enable no-matching-credential logging
)
_lock = asyncio.Lock()
# path -> handle of the currently open file, kept across writes.
_handles: Dict[Path, object] = {}
# path -> list of pending strings not yet flushed to disk.
_buffers: Dict[Path, list] = {}
# flush a path's buffer to disk once it holds at least this many lines.
_FLUSH_LINES = 1000

_HTML_HEADER = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CamReaper report</title>
<style>
 html{background-color:#141414}
 p{text-align:center;color:#fff;font-family:monospace}
 img{cursor:pointer;border:2px solid #707070;border-radius:4px}
 div.gallery img{width:100%;height:auto}
 *{box-sizing:border-box}
 .responsive{padding:6px;float:left;width:25%}
 @media only screen and (max-width:700px){.responsive{width:50%}}
 @media only screen and (max-width:500px){.responsive{width:100%}}
 #viewer{position:fixed;inset:0;background:rgba(0,0,0,.92);
   display:none;align-items:center;justify-content:center;z-index:99;cursor:zoom-out}
 #viewer img{max-width:96vw;max-height:96vh;border:none;border-radius:2px}
 #toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%);
   background:#222;border:1px solid #555;color:#7CFC00;
   padding:8px 16px;border-radius:4px;font-family:monospace;font-size:13px;
   display:none;z-index:100}
 .controls{text-align:center;color:#fff;font-family:monospace;
   padding:10px 0 4px 0}
 .controls select{background:#222;color:#fff;border:1px solid #555;
   font-family:monospace;padding:3px 6px;border-radius:4px}
 .camgroup::after{content:"";display:block;clear:both}
 .cam-head{color:#7CFC00;font-family:monospace;font-size:14px;
   background:#1e1e1e;border:1px solid #3a3a3a;border-left:4px solid #7CFC00;
   margin:22px 0 6px 0;padding:7px 12px;border-radius:3px}
 .cam-head small{color:#999;font-weight:normal}
</style>
</head>
<body>
<script>
var copyMode="url";
var CM_KEY="CamReaperCopyMode";
window.onload=function(){var n=document.querySelectorAll("div.responsive").length;
 document.getElementById("total").innerHTML=":: Total images: "+n+" ::";
 try{var s=localStorage.getItem(CM_KEY);if(s)setCopyMode(s,false);}catch(e){}}
function setCopyMode(m,persist){
 if(arguments.length===0){m=document.getElementById("copyMode").value;}
 copyMode=m;
 if(persist!==false){try{localStorage.setItem(CM_KEY,copyMode);}catch(e){}}
}
function copyText(img){
 // what gets copied is chosen by the "Copy on click" dropdown:
 //  * plain address (rtsp://...)  ->  copyMode="url"
 //  * ffplay <address>            ->  copyMode="ffplay"
 var t=(copyMode==="ffplay")?("ffplay -rtsp_transport tcp "+img.alt):img.alt;
 navigator.clipboard.writeText(t);
 var el=document.getElementById("toast");
 el.style.display="block"; el.textContent="Copied: "+t;
 setTimeout(function(){el.style.display="none";},1500);
}
var clickTimer=null;
function clickOrDouble(img,ev){
 if(ev.detail===2){
  // second click of a double click - cancel pending copy, toggle fullscreen
  if(clickTimer){clearTimeout(clickTimer);clickTimer=null;}
  toggleFull(img);
  return;
 }
 // single (first) click - wait briefly; if no second click follows, copy
 if(clickTimer){clearTimeout(clickTimer);}
 clickTimer=setTimeout(function(){
  clickTimer=null;
  copyText(img);
 },250);
}
function toggleFull(img){
 var v=document.getElementById("viewer");
 if(v.style.display==="flex"){v.style.display="none";return;}
 var big=v.querySelector("img");
 big.src=img.src; big.alt=img.alt;
 v.style.display="flex";
}
function closeFull(){
 var v=document.getElementById("viewer");
 if(v.style.display==="flex"){v.style.display="none";}
}
function viewerClick(ev){
 // click outside the enlarged image closes the fullscreen view
 if(ev.target===document.getElementById("viewer")){closeFull();}
}
</script>
<div class="controls">
 <label for="copyMode">Copy on click:</label>
 <select id="copyMode" onchange="setCopyMode()">
  <option value="url">address (rtsp://...)</option>
  <option value="ffplay">ffplay + address</option>
 </select>
</div>
<p id="total"></p>
<p>:: single click: copy (see dropdown) &middot; double click: fullscreen &middot; close: double click or click outside image ::</p>
<div id="viewer" onclick="viewerClick(event)"><img src="" alt="" ondblclick="closeFull()"></div>
<div id="toast"></div>
"""


def init_html(path: Path) -> None:
    path.write_text(_HTML_HEADER)


async def _append(path: Optional[Path], text: str) -> None:
    """Buffer ``text`` for ``path``; flush to disk under lock.

    Strings accumulate in memory and are written to the file in one atomic
    ``write()`` under the lock, so concurrent appends can never interleave or
    corrupt a line (a shared TextIO buffer can).  The file is only touched on
    flush - when the buffer exceeds a threshold or at shutdown.
    """
    if path is None:
        return
    buf = _buffers.setdefault(path, [])
    async with _lock:
        buf.append(text)
        if len(buf) >= _FLUSH_LINES:
            _flush_buffers([path])


def _flush_buffers(paths) -> None:
    """Flush the given paths' buffers to disk (caller must hold ``_lock``)."""
    for p in paths:
        buf = _buffers.get(p)
        if not buf:
            continue
        handle = _handles.get(p)
        if handle is None:
            handle = p.open("a", encoding="utf-8")
            _handles[p] = handle
        handle.write("".join(buf))
        buf.clear()
        handle.flush()


async def record_url(url: str) -> None:
    """Write one found stream URL to result.txt (always, screenshot or not)."""
    await _append(RESULT_FILE, f"{url}\n")


async def record_failed(ip: str, port: int, error: str = "") -> None:
    """Append one 'ip port [error]' line to the failed-connections file.

    No-op unless ``FAILED_FILE`` is configured (i.e. the user passed
    ``--failed-file``), so the default run pays nothing for this feature.  The
    write is buffered and only logs reachable-but-unconfirmed hosts ("port
    open, but no RTSP confirmed"), which are rare - it never logs the millions
    of closed/unreachable TCP ports, so it cannot slow the scan.
    """
    if FAILED_FILE is None:
        return
    line = f"{ip} {port}"
    if error:
        line += f" {error}"
    await _append(FAILED_FILE, line + "\n")


async def record_no_auth(ip: str, port: int) -> None:
    """Append one 'ip port' line for a camera whose RTSP port was live but no
    credential in the list opened it.

    No-op unless ``NO_AUTH_FILE`` is configured (``--no-auth-file``), so the
    default run pays nothing.  Only reaches hosts that actually answered
    401/403, which are confirmed-but-unopened cameras - not the millions of
    closed TCP ports - so it cannot slow the scan.
    """
    if NO_AUTH_FILE is None:
        return
    await _append(NO_AUTH_FILE, f"{ip} {port}\n")


async def record_gallery(url: str, pic_rel: str) -> None:
    """Append a gallery entry to index.html for a successful screenshot."""
    if HTML_FILE is None:
        return
    await _append(
        HTML_FILE,
        '<div class="responsive"><div class="gallery">\n'
        f'<img src="{pic_rel}" alt="{url}" width="600" height="400" '
        'loading="lazy" onclick="clickOrDouble(this,event)">'
        '<p style="font-size:11px;margin:2px">click: copy &middot; '
        "double click: fullscreen</p></div></div>\n\n",
    )


def _gallery_entry(url: str, pic_rel: str) -> str:
    return (
        '<div class="responsive"><div class="gallery">\n'
        f'<img src="{pic_rel}" alt="{url}" width="600" height="400" '
        'loading="lazy" onclick="clickOrDouble(this,event)">'
        '<p style="font-size:11px;margin:2px">click: copy &middot; '
        "double click: fullscreen</p></div></div>\n"
    )


def _gallery_label(url: str) -> str:
    """Short human-readable camera label from an RTSP URL (no credentials)."""
    s = url.replace("rtsp://", "", 1)
    at = s.find("@")
    if at != -1:  # admin:pass@host -> keep host:port/path only
        s = s[at + 1 :]
    path = s.find("/")
    hostport = s if path == -1 else s[:path]
    rest = s[path:] if path != -1 else ""
    for pat, tag in (
        (r"/Streaming/Channels/\d+", "Hikvision"),
        (r"/h264/ch\d+", "Dahua h264"),
        (r"channel=\d+", "ONVIF"),
    ):
        if re.search(pat, rest):
            return f"{hostport} [{tag}]"
    return hostport


def _camera_base(url: str) -> str:
    """Reduce a stream URL to its camera identity.

    Drops credentials and the channel number / sub-type so that the main & sub
    streams and ch1..ch8 of one device all map to the same group.
    """
    s = re.sub(r"rtsp://[^@]*@", "rtsp://", url)
    s = re.sub(r"/Streaming/Channels/\d+", "/Streaming/Channels/N", s)
    s = re.sub(r"/h264/ch\d+", "/h264/chN", s)
    s = re.sub(r"channel=\d+", "channel=N", s)
    s = re.sub(r"subtype=\d+", "subtype=S", s)
    return s


async def write_gallery_sections(entries, path: Optional[Path] = None) -> None:
    """Write all gallery entries grouped by base-stream, one section per camera.

    ``entries`` is an iterable of ``(url, pic_rel)`` tuples.  Entries sharing
    the same ``_camera_base`` are placed under one header so it is obvious which
    screenshots belong to the same camera.  Writes to ``path`` (defaults to the
    module-level ``HTML_FILE``).  Buffered like every other writer.
    """
    target = path if path is not None else HTML_FILE
    if target is None:
        return
    ordered = list(entries)
    ordered.sort(key=lambda e: _camera_base(e[0]))
    buf = []
    prev = None
    open_group = False
    for url, pic in ordered:
        base = _camera_base(url)
        if base != prev:
            if open_group:
                buf.append("</div><!-- /camgroup -->\n")
            buf.append(
                f'<div class="camgroup">\n<div class="cam-head">'
                f"{_gallery_label(url)}</div>\n"
            )
            prev = base
            open_group = True
        buf.append(_gallery_entry(url, pic))
    if open_group:
        buf.append("</div><!-- /camgroup -->\n")
    await _append(target, "".join(buf))


async def close_report_files() -> None:
    """Flush and close every open output writer (call once at shutdown)."""
    async with _lock:
        # Ensure every configured output file exists even if nothing was
        # buffered for it yet (buffering defers file creation to first flush).
        for path in (RESULT_FILE, HTML_FILE, FAILED_FILE, NO_AUTH_FILE):
            if path is not None:
                try:
                    path.touch()
                except OSError:
                    pass
        _flush_buffers(list(_buffers.keys()))
        for handle in _handles.values():
            try:
                handle.close()
            except Exception:
                pass
        _handles.clear()
        _buffers.clear()


def start_flush_task(interval: float = 10.0):
    """Return a background task that flushes writers every ``interval`` seconds.

    Buffered writers would otherwise only hit the disk once they fill; a
    long-lived scan should still leave searchable, up-to-date files.  Cancel
    the returned task after the scan (or rely on ``close_report_files``).
    """

    async def _tick():
        try:
            while True:
                await asyncio.sleep(interval)
                async with _lock:
                    _flush_buffers(list(_buffers.keys()))
        except asyncio.CancelledError:
            pass

    return asyncio.ensure_future(_tick())


def escape_chars(s: str) -> str:
    return re.sub(r"[^\w\-_. ]", "_", s)


def write_m3u(result_file: Path, m3u_file: Path) -> None:
    """Copy result.txt to a ready-to-play M3U playlist (one URL per line)."""
    try:
        shutil.copy(result_file, m3u_file)
    except OSError:
        pass


def write_summary(path: Path, stats: dict, elapsed: float = 0.0) -> None:
    """Write summary.json: counters plus found-stream vendor/port breakdown."""
    data = {
        "elapsed": round(elapsed, 1),
        "statistics": {
            k: stats.get(k, 0)
            for k in ("checked", "found", "screenshots", "found_no_frame")
        },
        "vendors": stats.get("vendors", {}),
        "ports": stats.get("ports", {}),
    }
    try:
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    except OSError:
        pass
