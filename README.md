# CamReaper

Asynchronous RTSP stream scanner with screenshots and gallery generation.

Scans networks for RTSP camera streams, brute-forces routes and credentials, captures screenshots, and builds an HTML gallery.

---

## Features

- **Async architecture** - asyncio event loop with bounded concurrency, no blocking threads. See the Russian documentation [README.ru.md](README.ru.md) for the localized version.
- **Route discovery** - parallel route probing across the built-in list of common vendor paths (ONVIF, Dahua, Hikvision, Uniview, Axis, Samsung, Panasonic, Tapo, etc.). Larger community lists are shipped in `routecreds/` (e.g. `routecreds/routes.txt`, 810+ paths) and can be passed with `-r`
- **Parallel port probing** - the `-p` ports of a host are probed concurrently (4 at a time), so a multi-port scan is no longer serial. The port of record is still the first responsive port in the order you gave
- **Lazily expanded targets** - IPs, CIDRs and ranges are generated on the fly, so `-t 10.0.0.0/8` costs no memory; a host-prefixed CIDR such as `192.168.1.5/24` is accepted and resolved to the containing network
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

# Port ranges
CamReaper -t targets.txt -p 8000-8008
CamReaper -t targets.txt -p 554 8000-8008 8554

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
| `-t, --targets SPEC` | Targets: a file with one entry per line, or an inline spec (CIDR, range, or comma/space separated IPs) |

### Scan Options

| Flag | Default | Description |
|------|---------|-------------|
| `-p, --ports PORTS` | `554` | RTSP ports to scan; ranges allowed (`8000-8008`); probed 4 at a time per host, first responsive port wins |
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
| `--http-ports PORTS` | `80 443 8080` | HTTP/HTTPS ports probed for CVEs on hosts with no live RTSP port; ranges allowed (`8000-8008`) |
| `--no-http` | off | Disable the HTTP CVE-probe fallback |
| `--http-timeout S` | `5.0` | Socket timeout in seconds for CVE HTTP probes |

### Screenshot Options

| Flag | Default | Description |
|------|---------|-------------|
| `-st, --screenshot-concurrency N` | `20` | Max concurrent screenshot workers |
| `--screenshot-timeout S` | `10.0` | Timeout per screenshot frame |
| `--no-screenshots` | off | Skip screenshots entirely |
| `--scan-channels` | off | Re-capture all channels post-scan |
| `--scan-routes FILE` | same as `-r` | Route list for channel probes |

`found` and `screenshots` are counted separately on purpose: `found` is every
stream whose RTSP authentication succeeded, while `screenshots` is only the ones
that actually produced a decodable frame. When a camera opens but yields no
frame the run ends with a warning and a count, and its URL is still in
`result.txt`. Raise `--screenshot-timeout` if that number is not zero.


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

### Several targets without a file

```bash
CamReaper -t 192.168.1.0/24,10.0.0.0/24 --no-screenshots
CamReaper -t 10.0.0.1,10.0.0.2,10.0.0.3 -p 554 8554
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

### Targets

`-t` takes either a file with one entry per line or the targets straight on the command
line. Both accept IPs, CIDRs and IP ranges:

```bash
CamReaper -t 192.168.1.0/24 -p 554 8554          # inline CIDR
CamReaper -t 10.0.0.1-10.0.0.50                   # inline range
CamReaper -t 1.1.1.1,8.8.8.8                      # several addresses
CamReaper -t "1.1.1.1 10.0.0.1 - 10.0.0.9"       # quote the whole list if it has spaces
CamReaper -t targets.txt                          # from a file
```

Supported entry formats (in a file line, or as an inline token):

```
192.168.1.100
192.168.1.0/24
192.168.1.5/24          # host-prefixed CIDR, resolved to 192.168.1.0/24
10.0.0.1 - 10.0.0.254
```

Blank lines and lines starting with `#` are ignored in every input file. If the value
is neither an existing file nor a valid target spec, the run stops with an error instead
of silently scanning nothing.

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

The password may be empty (`admin:`) and may contain non-ASCII characters. A line without
a `:` is treated as a login with an empty password instead of aborting the run.

---

## Output

Each run creates a timestamped folder under `reports/<timestamp>/`:

| File | Description |
|------|-------------|
| `result.txt` | Confirmed stream URLs (one per line) |
| `streams.m3u` | Same URLs as M3U playlist (open in VLC) |
| `summary.json` | Statistics: checked, found, screenshots, cve/http counters, host errors, vendor/port breakdown |
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

- **Click to copy** - copies to clipboard, in one of three modes chosen from the dropdown: bare `host:port`, the `ffplay` command over TCP, or the full `rtsp://` link
- **Double-click fullscreen** - opens the screenshot in a lightbox
- **Address under each screenshot** - address, port and login with password
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
