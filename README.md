# CamReaper

Asynchronous RTSP stream scanner with screenshots and gallery generation.

Scans networks for RTSP camera streams, brute-forces routes and credentials, captures screenshots, and builds an HTML gallery.

---

## Features

- **Async architecture** - asyncio event loop with bounded concurrency, no blocking threads
- **Route discovery** - parallel route probing across 810+ vendor paths (ONVIF, Dahua, Hikvision, Uniview, Axis, Samsung, Panasonic, Tapo, etc.)
- **Credential brute-force** - Basic and Digest (two-step) authentication
- **Screenshots** - FFmpeg-based capture with hard timeout (subprocess isolation)
- **HTML gallery** - click to copy RTSP URL, double-click for fullscreen
- **Multi-channel expansion** - Hikvision 101-1601, Dahua ch1-8, ONVIF channel/subtype
- **Resumable scans** - checkpoint/save state, resume interrupted runs
- **Deduplication** - LRU-based IP dedup for overlapping CIDRs/ranges
- **Report output** - result.txt, streams.m3u, summary.json, failed.txt, noauth.txt

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
