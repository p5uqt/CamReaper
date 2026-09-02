# CamReaper

Асинхронный сканер RTSP-потоков с капчей скриншотов и генерацией HTML-галереи.

Сканирует сети на наличие RTSP-стримов камер, подбирает маршруты и учетные данные, делает скриншоты и собирает HTML-галлерию.

---

## Фичи

- **Async architecture** - асинхронный цикл событий asyncio с ограниченной concurrency, без блокирующих потоков
- **Route discovery** - parallel route probing across 810+ vendor paths (ONVIF, Dahua, Hikvision, Uniview, Axis, Samsung, Panasonic, Tapo, etc.)
- **Credential brute-force** - Basic и Digest (двухшаговый) аутентификация
- **Screenshots** - FFmpeg-based capture с жестким таймаутом (изоляция subprocess)
- **HTML gallery** - клик для копирования RTSP URL, двойной клик для полноэкранного просмотра
- **Multi-channel expansion** - Hikvision 101-1601, Dahua ch1-8, ONVIF channel/subtype
- **CVE exploits** - vendor-aware scans (`brute` / `cve` / `combined`) используя backdoor credentials и HTTP probes against 26+ documented CVEs (Hikvision, Dahua, Zosi, Xiongmai, PTZOptics, Sony, V380, AVTECH, ...)
- **HTTP fallback probing** - хосты без live RTSP порта пронумерованы на их веб-панели (80/443/8080) для уязвимостей CVE
- **Deduplication** - LRU-based IP dedup для overlapping CIDRs/ranges
- **Report output** - result.txt, streams.m3u, summary.json, failed.txt, noauth.txt, cve_log.txt, http_cve.txt

---

## Установка

```bash
pip install -e .
```

Требуется Python >= 3.8. Для скриншотов `av` и `Pillow` должны быть установлены. Без них используйте `--no-screenshots` для纯 brute-force режима.

---

## Быстрый старт

```bash
# Basic scan with multiple ports
CamReaper -t targets.txt -p 554 8554 5554

# Custom routes and credentials
CamReaper -t ips.txt -r routes.txt -c combos.txt -ct 500 -T 1

# Fast scan without screenshots
CamReaper -t broad_cidr.txt --no-screenshots -p 554
```

---

## Использование

```
CamReaper [OPTIONS]
```

### Required

| Флаг | Описание |
|------|-------------|
| `-t, --targets FILE` | Файл с целевыми IP, CIDR или IP диапазонами (по одному на строку) |

### Scan Options

| Флаг | По умолчанию | Описание |
|------|-------------|-------------|
| `-p, --ports PORTS` | `554` | RTSP порты для сканирования |
| `-r, --routes FILE` | встроенный | Пользовательский список маршрутов |
| `-c, --credentials FILE` | встроенный | Список учетных данных (`user:pass` на строку) |
| `-ct, --check-concurrency N` | `300` | Максимум параллельных задач на хост |
| `-T, --timeout S` | `2.0` | Таймаут сокета в секундах |
| `--max-attempts N` | `0` (бесконечно) | Ограничить количество попыток creds на хост |
| `--attempts-per-sec N` | `0` (нет) | Rate limit на хост |
| `--host-timeout S` | `0` (бесконечно) | Wall-clock budget на хост |
| `--route-parallel N` | `8` | Количество маршрутов, проверяемых параллельно (0 = serial) |
| `--dedup` | off | Пропустить duplicate IPs из overlapping ranges |
| `--dedup-size N` | `1000000` | LRU cache size для dedup |
| `--mode MODE` | `brute` | Стратегия сканирования: `brute` (по умолчанию), `cve` (только CVE), `combined` (CVE сначала, потом brute) |
| `--cve-db PATH` | встроенный | Путь к кастомному JSON файлу с CVE базами данных |
| `--http-ports PORTS` | `80 443 8080` | HTTP/HTTPS порты для CVE-probe на хостах без live RTSP порта |
| `--no-http` | off | Отключить HTTP CVE-probe fallback для хостов без live RTSP порта |

### Screenshot Options

| Флаг | По умолчанию | Описание |
|------|-------------|-------------|
| `-st, --screenshot-concurrency N` | `20` | Максимум параллельных работников скриншотов |
| `--screenshot-timeout S` | `10.0` | Таймаут на одноCapture-frame |
| `--no-screenshots` | off | Пропустить скриншоты полностью |
| `--scan-channels` | off | Перекапчуры все channels после сканирования |
| `--scan-routes FILE` | такое же, как `-r` | Список маршрутов для channel probing |

### Output Options

| Флаг | По умолчанию | Описание |
|------|-------------|-------------|
| `--gallery-html FILE` | - | Построить галерею из списка URL (без сканирования) |
| `--capture FILE` | - | Режим только скриншотов из result.txt |
| `--failed-file [PATH]` | off | Записать reachable-but-unconfirmed hosts |
| `--failed-with-error` | off | Добавить причину ошибки в линии failed |
| `--no-auth-file [PATH]` | off | Записать хосты, где не сработала никакая учетная запись |
| `--checkpoint [PATH]` | auto | Сохранить прогресс для resumed сканирования |
| `--resume [PATH]` | auto | Восстановить сканирование из checkpoint |

---

## Примеры

### Сканирование сети

```bash
CamReaper -t 192.168.1.0/24 -p 554 8554
```

### С кастомными wordlists

```bash
CamReaper -t targets.txt -r custom_routes.txt -c custom_creds.txt
```

### Быстрое сканирование без скриншотов

```bash
CamReaper -t large_network.txt --no-screenshots -p 554 --dedup
```

### Восстанавливаемое сканирование

```bash
CamReaper -t huge_list.txt --checkpoint --resume
```

### Построение галереи из предыдущих результатов

```bash
CamReaper --gallery-html urls.txt
CamReaper --capture reports/2026.09.01-12.00.00/result.txt
```

### С ограничением скорости

```bash
CamReaper -t targets.txt --attempts-per-sec 5 --max-attempts 10 --host-timeout 30
```

### С CVE эксплойтами

```bash
# CVE-only: backdoor credentials + HTTP probes, no brute-force
CamReaper -t targets.txt --mode cve

# Combined: CVE exploits first, then brute-force for what remains
CamReaper -t targets.txt --mode combined

# Skip the HTTP web-panel fallback
CamReaper -t targets.txt --mode combined --no-http
```

---

## Скану CVE

Когда `--mode` установлен в `cve` или `combined`, CamReaper включаетKnown exploits для камеры, вендер определен из RTSP `Server` header (и для HTTP — из веб-панели `Server` header / body):

1. **Backdoor credentials** (`backdoor_creds`) - tries vendor-documented default или hardcoded credentials (например, Hikvision `admin:Hik@2014`), которые оператор никогда не менял. Удачный login дает playable RTSP URL, записываемый в `result.txt`.
2. **HTTP probes** (`http_probe`) - issues a crafted HTTP request и matching the response against the CVE's success pattern to confirm the vulnerability is present (config disclosure, RCE endpoints и т.д.).

Для хостов, чьи RTSP порты **все закрыты**, CamReaper падает back to probing the configured `--http-ports` (default `80 443 8080`) на удаленном веб-панели. Эти HTTP-only hits confirm a vulnerable panel but do **not** produce a playable RTSP stream, поэтому они записываются в `http_cve.txt` вместо `result.txt`.

Режимы:

| Режим | Поведение |
|-------|-----------|
| `brute` (default) | Только credential/route brute-force, CVE стадия пропущена |
| `cve` | Только CVE exploits, brute-force пропущен |
| `combined` | CVE exploits сначала, потом brute-force для хостов, которые не найдены |

Встроенная CVE база данных (`CamReaper/cve_db.json`) поставляется с 26 entry'ами для Hikvision, Dahua, Zosi, Xiongmai, PTZOptics, Sony, V380, AVTECH и других, поддержка актуальна через 2024-2026 disclosure. Свои можно передать через `--cve-db PATH`.

---

## Форматы входных данных

### Файл с целевыми хостами

Одна запись на строку. Поддерживаемые форматы:

```
192.168.1.100
192.168.1.0/24
10.0.0.1 - 10.0.0.254
```

### Файл с маршрутами

Каждый маршрут начинается с `/`:

```
/
/stream1
/cam/realmonitor?channel=1&subtype=0
/Streaming/Channels/101/
/h264/ch1/main/av_stream
`

### Файл с учетными данными

`user:pass` на строку:

```
admin:admin
root:root
admin:12345
```

---

## Вывод

Каждый запуск создает папку с временной меткой под `reports/<timestamp>/`:

| Файл | Описание |
|------|-------------|
| `result.txt` | Подтвержденные URL потоков (по одному на строку) |
| `streams.m3u` | То же, что и result.txt, но в формате M3U (открывается в VLC) |
| `summary.json` | Статистика: checked, found, screenshots, breakdown по vendor/port |
| `pics/` | Сaptured screenshots |
| `index.html` | Интерактивная галерея с кликом для копирования и полноэкранным просмотром |
| `checkpoint.json` | Состояние для resumed (если `--checkpoint` использовался) |
| `failed.txt` | Reachable-but-unconfirmed hosts (если `--failed-file` использовался) |
| `noauth.txt` | Подтвержденные камеры с нет matching credential (если `--no-auth-file` использовался) |
| `cve_log.txt` | Попыток CVE, одна на строку: `ip port CVE-ID SUCCESS\|FAIL` (в режиме `cve`/`combined`) |
| `http_cve.txt` | Хосты с уязвимой веб-панелью но без live RTSP порта: `ip port CVE-ID` (если HTTP probing включен) |

---

## Возможности галереи

HTML галерея (`index.html`) предоставляет:

- **Клик для копирования** - копирует RTSP URL в буфер обмена
- **Двойной клик полноэкранный** - открывает скриншот в lightbox
- **Выпадающий список режимов копирования** - переключает между plain URL и командой `ffplay`
- **Группировка камер** - скриншоты от одной камеры группируются под заголовком
- **Детекция вендора** - заголовки показывают детектированный вендор (Hikvision, Dahua, ONVIF и т.д.)

---

## Разработка

### Запуск тестов

```bash
pip install pytest pytest-asyncio
python -m pytest -q
```

### Запуск с покрытием

```bash
pytest --cov=CamReaper
```

### Lint

```bash
black CamReaper/ tests/
isort --profile black CamReaper/ tests/
```

---

## Лицензия

GPL-3.0 - см. [LICENSE](LICENSE) для подробностей.