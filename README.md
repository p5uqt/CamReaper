# CamReaper

Asynchronous RTSP stream scanner with screenshots and gallery generation.

Scans networks for RTSP camera streams, brute-forces routes and credentials, captures screenshots, and builds an HTML gallery.

---

## Features

- **Async architecture** - asyncio event loop with bounded concurrency, no blocking threads. See the Russian documentation [README.ru.md](README.ru.md) for the localized version.
- **Route discovery** - parallel route probing across the built-in list of common vendor paths (ONVIF, Dahua, Hikvision, Uniview, Axis, Samsung, Panasonic, Tapo, etc.). Larger community lists are shipped in `routecreds/` (e.g. `routecreds/routes.txt`, 810+ paths) and can be passed with `-r`
- **Scan profiles** - `fast` is the default and restores the pre-profile speed (small wordlists, no ONVIF/deep-auth, first port only); `--profile balanced` and `--profile max` spend more time to find more devices
- **Parallel port probing** - the `-p` ports of a host are probed concurrently, so a multi-port scan is no longer serial. In `balanced`/`max` **every** responsive port is processed, so a test server or NVR that exposes many cameras on one IP yields all of them, not just the first
- **Lazily expanded targets** - IPs, CIDRs and ranges are generated on the fly, so `-t 10.0.0.0/8` costs no memory; a host-prefixed CIDR such as `192.168.1.5/24` is accepted and resolved to the containing network
- **Credential brute-force** - Basic and Digest authentication, including RFC 2617 `qop=auth`, `opaque` and SHA-256 algorithms; a second pass tries the password on real stream routes when `/` keeps returning 401
- **Any RTSP answer counts** - a camera that replies `404`/`400` to an unknown path is treated as live and swept, not discarded as "unconfirmed"
- **Screenshots** - FFmpeg-based capture with hard timeout (subprocess isolation)
- **HTML gallery** - click to copy RTSP URL, double-click for fullscreen
- **Multi-channel expansion** - Hikvision 101-1601, Dahua ch1-8, ONVIF channel/subtype
- **Resumable scans** - checkpoint/save state, resume interrupted runs
- **CVE exploits** - vendor-aware scans (`brute` / `cve` / `combined`) using backdoor credentials and HTTP probes against 26+ documented CVEs (Hikvision, Dahua, Zosi, Xiongmai, PTZOptics, Sony, V380, AVTECH, ...)
- **HTTP fallback probing** - hosts with no live RTSP port are probed on their web panel (80/443/8080) for CVE vulnerabilities
- **Deduplication** - LRU-based IP dedup for overlapping CIDRs/ranges
- **Large-scan controls** - deterministic target sharding across machines (`--shard 2/4`), chunked runs (`--skip`/`--limit`), network exclusions (`--exclude`), a global new-connection rate limit (`--rate-limit`), and instant dry-run counting (`--count-only`)
- **Structured findings** - `findings.jsonl` records every confirmed stream with vendor/port/route/CVE metadata for downstream processing
- **Report output** - result.txt, streams.m3u, summary.json, findings.jsonl, failed.txt, noauth.txt, cve_log.txt, http_cve.txt

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
CamReaper -t broad_cidr.txt --no-screenshots -p 554 --profile fast

# Pre-profile speed: small wordlists, no ONVIF, no deep-auth, first port only
CamReaper -t targets.txt --profile fast

# More coverage: ONVIF + deep-auth + every responsive port
CamReaper -t targets.txt --profile balanced

# Maximum findings: community wordlists, common ports, CVE mode
CamReaper -t targets.txt --profile max

# All ports, but no expensive ONVIF/deep-auth stages
CamReaper -t test-server -p 5000-5100 --profile balanced --no-onvif --no-deep-auth
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

### Scan profile

| Profile | What it changes |
|---------|-----------------|
| `fast` (default) | Pre-profile behaviour: the original 11 routes / 11 credentials, **no ONVIF**, **no deep-auth**, only the first responsive port, old `404` rules, no per-host budget. This is what runs when `--profile` is omitted. |
| `balanced` | ONVIF + deep-auth + every responsive port + the expanded built-in wordlists (36 routes / 52 credentials) + a 60s host budget. |
| `max` | Balanced plus the community lists from `routecreds/` (830+ routes, 200+ credentials), common camera ports when `-p` is not given, `--mode combined`, 16 port probes/pipelines at once and a 300s host budget. Slowest, but finds the most. |

Explicit flags still override the profile where it makes sense (`-p`, `-r`,
`-c`, `--mode`, `--onvif`/`--no-onvif`, `--deep-auth`/`--no-deep-auth`,
`--host-timeout`, concurrency and route counts).

### Scan Options

| Flag | Default | Description |
|------|---------|-------------|
| `--profile NAME` | `fast` | `fast`, `balanced` or `max`; see the table above |
| `-p, --ports PORTS` | `554` | RTSP ports to scan; ranges allowed (`8000-8008`); probed in parallel per host, every responsive port is processed (`fast` keeps only the first). `max` adds common camera ports when `-p` is omitted |
| `-r, --routes FILE` | profile | Custom route list; `fast` uses 11 paths, `balanced` 36, `max` the community list |
| `-c, --credentials FILE` | profile | Credential list (`user:pass` per line); `fast` uses 11, `balanced` 52, `max` the community list |
| `-ct, --check-concurrency N` | `300` | Max concurrent host pipelines |
| `-T, --timeout S` | `2.0` | Socket timeout in seconds |
| `--max-attempts N` | `0` (unlimited) | Cap credential attempts per RTSP port/camera (also disables the deep pass) |
| `--deep-auth` | profile | After the normal `/` pass fails, try the credentials against real stream routes. On in `balanced`/`max`, off in `fast` |
| `--no-deep-auth` | - | Disable the second credential pass |
| `--deep-auth-routes N` | profile | How many stream routes the second pass may try per camera (`balanced` 40, `max` 64) |
| `--attempts-per-sec N` | `0` (none) | Rate limit per RTSP port/camera |
| `--host-timeout S` | profile | Wall-clock budget per host (`fast` 0/unlimited, `balanced` 60, `max` 300) |
| `--route-parallel N` | `8` | Routes probed in parallel (0 = serial) |
| `--port-parallel N` | profile | Ports of one IP probed at once (`fast` 4, `balanced` 8, `max` 16) |
| `--port-pipeline-parallel N` | profile | Responsive ports of the same IP run through the route/credential pipeline at once (`fast` 1, `balanced` 8, `max` 16) |
| `--dedup` | off | Skip duplicate IPs from overlapping ranges |
| `--dedup-size N` | `1000000` | LRU cache size for dedup |
| `--exclude SPEC` | - | Skip a file/CIDR/range/IP; repeatable. Applied after `--dedup` |
| `--shard INDEX/TOTAL` | - | Scan one deterministic disjoint slice, e.g. `2/4` for distributed scans |
| `--skip N` | `0` | Skip the first N targets of this run (after `--shard`) |
| `--limit N` | `0` (all) | Stop after N targets of this run |
| `--count-only` | off | Print how many targets would be scanned and exit (no network) |
| `--rate-limit N` | `0` (none) | Global cap on new connections per second across all hosts |
| `--mode MODE` | `brute` | Scan strategy: `brute` (default), `cve` (CVE only), `combined` (CVE first, then brute). `max` uses `combined` when `--mode` is omitted |
| `--cve-db PATH` | built-in | Path to a custom CVE database JSON file |
| `--http-ports PORTS` | `80 443 8080` | HTTP/HTTPS ports probed for CVEs on hosts with no live RTSP port; ranges allowed (`8000-8008`) |
| `--https-ports PORTS` | `443 8443` | Subset of `--http-ports` probed over TLS |
| `--no-http` | off | Disable the HTTP CVE-probe fallback |
| `--http-timeout S` | `5.0` | Socket timeout in seconds for CVE HTTP probes |
| `--onvif` | profile | Ask each host for its stream URL over ONVIF (SOAP `GetProfiles`/`GetStreamUri`). On in `balanced`/`max`, off in `fast` |
| `--no-onvif` | - | Disable ONVIF discovery |
| `--onvif-ports PORTS` | `80 81 8000 8001 8080 8081 8082 8083 8088 8899 8888 2020 34567 5000 9000` | Web ports probed for the ONVIF device service; ranges allowed |
| `--onvif-timeout S` | `5.0` | Socket timeout in seconds for ONVIF SOAP requests |
| `--onvif-profiles N` | profile | How many ONVIF profiles per device to resolve into RTSP URLs (`max` 8) |

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

### Split a huge range across machines

Each shard scans a deterministic, disjoint subset of the same input, so four
hosts can work on a `/16` without coordination:

```bash
CamReaper -t 10.0.0.0/16 --shard 1/4 --rate-limit 500
CamReaper -t 10.0.0.0/16 --shard 2/4 --rate-limit 500
CamReaper -t 10.0.0.0/16 --shard 3/4 --rate-limit 500
CamReaper -t 10.0.0.0/16 --shard 4/4 --rate-limit 500
```

### Scan a big list in chunks, excluding noisy ranges

```bash
CamReaper -t huge_list.txt --exclude 10.0.10.0/24 --exclude excludes.txt
CamReaper -t huge_list.txt --skip 1000000 --limit 1000000
CamReaper -t 10.0.0.0/8 --count-only     # instant: no address is expanded
```

### Build gallery from previous results

```bash
CamReaper --gallery-html urls.txt
CamReaper --capture reports/2026.09.01-12.00.00/result.txt
```

### Scan with rate limiting

```bash
CamReaper -t targets.txt --attempts-per-sec 5 --max-attempts 10 --host-timeout 30
CamReaper -t 10.0.0.0/8 --rate-limit 500 --no-screenshots
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

### Scan with ONVIF discovery

```bash
# ONVIF is on by default in balanced/max
CamReaper -t targets.txt --profile balanced

# Only the vendor ports that actually serve ONVIF
CamReaper -t targets.txt --onvif-ports 8000 8080 34567

# Resolve more channels per device, and turn it off again
CamReaper -t targets.txt --onvif-profiles 8
CamReaper -t targets.txt --mode combined --no-onvif
```

### Maximum-findings command

```bash
# ONVIF on, CVE backdoors + web probes, expanded routes/credentials, deep
# credential pass, and every common camera port.
CamReaper -t targets.txt \
  -p 554 8554 5554 10554 8000 8080 \
  -r routecreds/routes.txt \
  -c routecreds/credentials.txt \
  --mode combined --check-concurrency 500 --deep-auth \
  --port-parallel 32 --port-pipeline-parallel 16 --host-timeout 600

# The same idea, without spelling all of it out:
CamReaper -t targets.txt --profile max
```

For one test server that exposes cameras on a port range, scan the range
directly - every responsive port is now processed:

```bash
CamReaper -t 10.0.0.5 -p 5000-5100 --port-parallel 64 \
  --port-pipeline-parallel 16 --host-timeout 600 --deep-auth
```

---

## Large-Scale Scanning

A scan of millions of addresses needs more than a high concurrency number. The
following controls are designed to be combined:

1. **Watch the cost first** - `--count-only` prints the exact number of targets
   this invocation would scan without expanding a single address.
2. **Pick a slice** - `--shard I/N` gives this process every N-th target
   starting at I (1-based). Shards are disjoint and deterministic, so N
   machines can share one input file and each writes its own
   `reports/<timestamp>-shardIofN/` folder.
3. **Pace the whole process** - `--rate-limit N` bounds *new connections per
   second across every host*, while `--attempts-per-sec` still bounds the
   credential attempts against one camera (lockout protection). Route sweeps,
   ONVIF probes and CVE HTTP probes all draw from the same bucket.
4. **Filter noise** - `--exclude` removes CIDRs, ranges, single IPs or a file
   of them after dedup; `--skip`/`--limit` carve out one chunk of a list.
5. **Keep it resumable** - `--checkpoint` appends finished IPs to a companion
   `.ips` file, so even a SIGTERM saves progress. `--resume` skips them.
6. **Process the results** - `findings.jsonl` is JSON Lines: one object per
   confirmed stream, including vendor and CVE metadata, ready for
   `jq`/pandas/whatever without re-parsing RTSP URLs.
7. **Budget ONVIF on very wide ranges** - ONVIF is on in `balanced`/`max` and
   probes the HTTP ports of every host. It is gated and cheap, but for a
   multi-million-IP sweep use `--no-onvif`, `--profile fast` or narrow
   `--onvif-ports`.

Progress output also reports the current hosts/second and an ETA derived from
`--count-only`-style arithmetic (no target list is materialised).

---

## CVE Scanning

When `--mode` is `cve` or `combined`, CamReaper switches on known exploits for
the camera vendor detected from the RTSP `Server` header, the
`WWW-Authenticate` realm, or (for HTTP) the web panel's `Server` header / page
body:

1. **Backdoor credentials** (`backdoor_creds`) - tries vendor-documented default
   or hardcoded credentials (e.g. Hikvision `admin:Hik@2014`) that were never
   changed by the operator. A successful login yields a playable RTSP URL,
   which is written to `result.txt`.
2. **HTTP probes** (`http_probe`) - issues a crafted HTTP request and matches
   the response against the CVE's success pattern to confirm the vulnerability
   is present (config disclosure, RCE endpoints, etc.).

Credentials are de-duplicated across all entries: the same default password is
listed by many CVEs, and a credential that failed once against a host fails
every time, so it is never re-sent.

A vendor with no backdoor entry of its own - including an unrecognised
`Generic` device - additionally gets the shared factory-default list shipped as
`GEN-CAM-DEFAULTS`, so an unidentified camera is still checked against the
passwords these devices ship with instead of being skipped.

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

## ONVIF Discovery

Route guessing only reaches the vendors whose paths are well known. Most modern
cameras speak ONVIF and will hand out their **exact** stream URL - correct
channel, correct sub-stream - if you just ask. CamReaper does that over the
device service's HTTP port (which is usually *not* the RTSP port):

1. `POST` a SOAP `GetProfiles` request to the device/media service endpoint;
2. collect every profile token (one per channel, main and sub-stream);
3. `POST` `GetStreamUri` per token, which returns the device's own `rtsp://` URL;
4. confirm that URL over RTSP before reporting it.

ONVIF is off in the default `fast` profile and on in `balanced`/`max`. Disable
it with `--no-onvif` for very large or latency-sensitive scans.

It also runs when **no RTSP port answered at all**: ONVIF lives on an HTTP port,
so a camera whose RTSP port is not in `-p` (or is closed) still hands out a
playable `rtsp://` URL. A short TCP gate over the ONVIF ports keeps dead hosts
cheap; only a port that accepts a connection gets the full SOAP flow.

Authentication is attempted in order, each step cheap and many devices accepting
more than one: no credentials at all, WS-Security `UsernameToken` with
`PasswordDigest`, WS-Security `PasswordText`, HTTP Basic, then HTTP Digest.

Cost is kept bounded in three ways: a port that is not serving ONVIF is
rejected after a single anonymous request; the credential list is de-duplicated
and capped; and at most `--onvif-profiles` tokens are resolved per device.
Every verified profile is reported (main and sub-stream), and every responding
ONVIF port is probed - not just the first - so a test server with several
independent camera services on one address yields all of them.
ONVIF is attempted only after the cheap RTSP route sweep on each live port, so
a camera that answers `/` straight away pays only a short TCP gate; use
`--no-onvif` to remove even that cost.

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
| `findings.jsonl` | One JSON object per confirmed stream (`ip`, `port`, `route`, `credentials`, `vendor`, `url`, `cve_id`, `ts`) |
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
