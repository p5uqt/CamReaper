# CamReaper

Asynchronous RTSP stream scanner with screenshots and gallery generation.

Scans networks for RTSP camera streams, brute-forces routes and credentials, captures screenshots, and builds an HTML gallery.

---

## Features

- **Async architecture** - asyncio event loop with bounded concurrency, no blocking threads. See the Russian documentation [README.ru.md](README.ru.md) for the localized version.
- **Route discovery** - parallel route probing across 810+ vendor paths (ONVIF, Dahua, Hikvision, Uniview, Axis, Samsung, Panasonic, Tapo, etc.)
- **Credential brute-force** - Basic and Digest (two-step) authentication
- **Screenshots** - FFmpeg-based capture with hard timeout (subprocess isolation)
- **HTML gallery** - click to copy RTSP URL, double-click for fullscreen
- **Multi-channel expansion** - Hikvision 101-1601, Dahua ch1-8, ONVIF channel/subtype
- **Resumable scans** - checkpoint/save state, resume interrupted runs
- **CVE exploits** - vendor-aware scans (`brute` / `cve` / `combined`) using backdoor credentials and HTTP probes against 26+ documented CVEs (Hikvision, Dahua, Zosi, Xiongmai, PTZOptics, Sony, V380, AVTECH, ...)
- **HTTP fallback probing** - hosts with no live RTSP port are probed on their web panel (80/443/8080) for CVE vulnerabilities
- **Deduplication** - LRU-based IP dedup for overlapping CIDRs/ranges
- **Report output** - result.txt, streams.m3u, summary.json, failed.txt, noauth.txt, cve_log.txt, http_cve.txt

---

## Installation

```bash
pip install -e .
```

Requires Python >= 3.8. For screenshots, `av` and `Pillow` must be installed. Without them, use `--no-screenshots` for pure brute-force mode.

---

## Quick Start

```bash
# Basic scan with multiple ports
CamReaper -t targets.txt -p 554 8554 5554

# Custom routes and credentials
CamReaper -t ips.txt -r routes.txt -c combos.txt -ct 500 -T 1

# Fast scan without screenshots
CamReaper -t broad_cidr.txt --no-screenshots -p 554
```

---

## Usage

```
CamReaper [OPTIONS]
```

### Required

| Flag | Description |
|------|-------------|
| `-t, --targets FILE` | Targets file - IPs, CIDRs, or IP ranges (one per line) |

### Scan Options

| Flag | Default | Description |
|------|---------|-------------|
| `-p, --ports PORTS` | `554` | RTSP ports to scan |
| `-r, --routes FILE` | built-in | Custom route list |
| `-c, --credentials FILE` | built-in | Credential list (`user:pass` per line) |
| `-ct, --check-concurrency N` | `300` | Max concurrent host pipelines |
| `-T, --timeout S` | `2.0` | Socket timeout in seconds |
| `--max-attempts N` | `0` (unlimited) | Cap credential attempts per host |
| `--attempts-per-sec N` | `0` (none) | Rate limit per host |
| `--host-timeout S` | `0` (unlimited) | Wall-clock budget per host |
| `--route-parallel N` | `8` | Routes probed in parallel (0 = serial) |
| `--dedup` | off | Skip duplicate IPs from overlapping ranges |
| `--dedup-size N` | `1000000` | LRU cache size for dedup |
| `--mode MODE` | `brute` | Scan strategy: `brute` (default), `cve` (CVE only), `combined` (CVE first, then brute) |
| `--cve-db PATH` | built-in | Path to a custom CVE database JSON file |
| `--http-ports PORTS` | `80 443 8080` | HTTP/HTTPS ports probed for CVEs on hosts with no live RTSP port |
| `--no-http` | off | Disable the HTTP CVE-probe fallback |

### Screenshot Options

| Flag | Default | Description |
|------|---------|-------------|
| `-st, --screenshot-concurrency N` | `20` | Max concurrent screenshot workers |
| `--screenshot-timeout S` | `10.0` | Timeout per screenshot frame |
| `--no-screenshots` | off | Skip screenshots entirely |
| `--scan-channels` | off | Re-capture all channels post-scan |
| `--scan-routes FILE` | same as `-r` | Route list for channel probing |

### Output Options

| Flag | Default | Description |
|------|---------|-------------|
| `--gallery-html FILE` | - | Build gallery from URL list (no scan) |
| `--capture FILE` | - | Screenshot-only mode from result.txt |
| `--failed-file [PATH]` | off | Log reachable-but-unconfirmed hosts |
| `--failed-with-error` | off | Append error reason to failed lines |
| `--no-auth-file [PATH]` | off | Log hosts where no credential worked |
| `--checkpoint [PATH]` | auto | Save progress for resumption |
| `--resume [PATH]` | auto | Resume from checkpoint |

---

## Examples

### Scan a network range

```bash
CamReaper -t 192.168.1.0/24 -p 554 8554
```

### Scan with custom wordlists

```bash
CamReaper -t targets.txt -r custom_routes.txt -c custom_creds.txt
```

### Fast discovery without screenshots

```bash
CamReaper -t large_network.txt --no-screenshots -p 554 --dedup
```

### Resumable long scan

```bash
CamReaper -t huge_list.txt --checkpoint --resume
```

### Build gallery from previous results

```bash
CamReaper --gallery-html urls.txt
CamReaper --capture reports/2026.09.01-12.00.00/result.txt
```

### Scan with rate limiting

```bash
CamReaper -t targets.txt --attempts-per-sec 5 --max-attempts 10 --host-timeout 30
```

### Scan with CVE exploits

```bash
# CVE-only: backdoor credentials + HTTP probes, no brute-force
CamReaper -t targets.txt --mode cve

# Combined: CVE exploits first, then brute-force for what remains
CamReaper -t targets.txt --mode combined

# Skip the HTTP web-panel fallback
CamReaper -t targets.txt --mode combined --no-http
```

---

## CVE Scanning

When `--mode` is `cve` or `combined`, CamReaper switches on known exploits for
the camera vendor detected from the RTSP `Server` header (and, for HTTP, from
the web panel's `Server` header / page body):

1. **Backdoor credentials** (`backdoor_creds`) - tries vendor-documented default
   or hardcoded credentials (e.g. Hikvision `admin:Hik@2014`) that were never
   changed by the operator. A successful login yields a playable RTSP URL,
   which is written to `result.txt`.
2. **HTTP probes** (`http_probe`) - issues a crafted HTTP request and matches
   the response against the CVE's success pattern to confirm the vulnerability
   is present (config disclosure, RCE endpoints, etc.).

For hosts whose RTSP ports are **all closed**, CamReaper falls back to probing
the configured `--http-ports` (default `80 443 8080`) on the remote web panel.
These HTTP-only hits confirm a vulnerable panel but do **not** produce a
playable RTSP stream, so they are recorded to `http_cve.txt` instead of
`result.txt`.

Modes:

| Mode | Behaviour |
|------|-----------|
| `brute` (default) | Credential/route brute-force only, CVE stage skipped |
| `cve` | CVE exploits only, brute-force skipped |
| `combined` | CVE exploits first, then brute-force for hosts still unfound |

The built-in CVE database (`CamReaper/cve_db.json`) ships with 26 entries for
Hikvision, Dahua, Zosi, Xiongmai, PTZOptics, Sony, V380, AVTECH and others,
kept current through 2024-2026 disclosures. Supply your own via `--cve-db PATH`.

---

## Input Formats

### Targets file

One entry per line. Supported formats:

```
192.168.1.100
192.168.1.0/24
10.0.0.1 - 10.0.0.254
```

### Routes file

Each route starts with `/`:

```
/
/stream1
/cam/realmonitor?channel=1&subtype=0
/Streaming/Channels/101/
/h264/ch1/main/av_stream
```

### Credentials file

`user:pass` per line:

```
admin:admin
root:root
admin:12345
```

---

## Output

Each run creates a timestamped folder under `reports/<timestamp>/`:

| File | Description |
|------|-------------|
| `result.txt` | Confirmed stream URLs (one per line) |
| `streams.m3u` | Same URLs as M3U playlist (open in VLC) |
| `summary.json` | Statistics: checked, found, screenshots, vendor/port breakdown |
| `pics/` | Captured screenshots |
| `index.html` | Interactive gallery with click-to-copy and fullscreen |
| `checkpoint.json` | Resume state (if `--checkpoint` was used) |
| `failed.txt` | Reachable-but-unconfirmed hosts (if `--failed-file` was used) |
| `noauth.txt` | Confirmed cameras with no matching credential (if `--no-auth-file` was used) |
| `cve_log.txt` | CVE exploit attempts, one per line: `ip port CVE-ID SUCCESS\|FAIL` (in `cve`/`combined` mode) |
| `http_cve.txt` | Hosts with a vulnerable web panel but no live RTSP port: `ip port CVE-ID` (if HTTP probing enabled) |

---

## Gallery Features

The HTML gallery (`index.html`) provides:

- **Click to copy** - copies the RTSP URL to clipboard
- **Double-click fullscreen** - opens the screenshot in a lightbox
- **Copy mode dropdown** - switch between plain URL and `ffplay` command
- **Camera grouping** - screenshots from the same camera are grouped under a header
- **Vendor detection** - headers show detected vendor (Hikvision, Dahua, ONVIF, etc.)

---

## Development

### Run tests

```bash
pip install pytest pytest-asyncio
python -m pytest -q
```

### Run with coverage

```bash
pytest --cov=CamReaper
```

### Lint

```bash
black CamReaper/ tests/
isort --profile black CamReaper/ tests/
```

---

## License

GPL-3.0 - see [LICENSE](LICENSE) for details.
