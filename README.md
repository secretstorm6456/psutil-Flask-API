# psutil Flask API

A local REST API that exposes every [psutil](https://psutil.readthedocs.io/stable/) system metric over HTTP. Useful for monitoring rigs, dashboards, or any remote script that needs system stats without SSH.

---

## Requirements

```bash
pip install flask psutil flask_cors
```

---

## Starting the server

```bash
# Default — localhost only, port 5500, auth required
python3 app.py

# Custom host/port
python3 app.py --host 0.0.0.0 --port 8080

# Flask debug mode
python3 app.py --debug

# No authentication (trusted network / local use only)
python3 app.py --no-auth
```

> **Warning:** `--no-auth` disables all key checks. Only use it on a trusted LAN or loopback. Never expose it to the internet.

---

## API key management

Keys are stored hashed (SHA-256 + random salt) in `api_keys.json`. The plaintext key is shown once at creation and never stored.

```bash
# Create a new key
python3 app.py --create-key myrig
# [created] name=myrig
#           key=sys_api_z2eHS1tOPcSn9k38JREl

# List all key names
python3 app.py --list-keys

# Rename a key (does not change the key value)
python3 app.py --rename-key myrig prodrig

# Rotate a key (generates a new value, old one stops working)
python3 app.py --rotate-key prodrig

# Delete a key
python3 app.py --delete-key prodrig

# Check if a plaintext key is valid
python3 app.py --verify-key sys_api_z2eHS1tOPcSn9k38JREl
```

---

## Client usage

### Authentication

Pass your key in the `X-API-KEY` header on every request (not needed with `--no-auth`).

### Python (requests)

```python
import requests

BASE = "http://localhost:5500"
HEADERS = {"X-API-KEY": "sys_api_z2eHS1tOPcSn9k38JREl"}

# Simple GET
r = requests.get(f"{BASE}/system/overview", headers=HEADERS)
print(r.json())

# With query params
r = requests.get(f"{BASE}/cpu/percent", headers=HEADERS, params={"interval": 0.5, "percpu": "true"})
print(r.json())
```

### curl

```bash
# With auth
curl -H "X-API-KEY: sys_api_z2eHS1tOPcSn9k38JREl" http://localhost:5500/system/overview

# No-auth mode
curl http://localhost:5500/system/overview

# With query params
curl -H "X-API-KEY: ..." "http://localhost:5500/cpu/percent?interval=0.5&percpu=true"
```

### JavaScript (fetch)

```js
const BASE = "http://localhost:5500";
const HEADERS = { "X-API-KEY": "sys_api_z2eHS1tOPcSn9k38JREl" };

const res = await fetch(`${BASE}/system/overview`, { headers: HEADERS });
const data = await res.json();
console.log(data);
```

### Error responses

| Status | Meaning |
|--------|---------|
| `401` | No `X-API-KEY` header provided |
| `403` | Key provided but invalid |
| `404` | PID not found |
| `400` | Bad parameter (e.g. invalid path for disk usage) |
| `501` | Endpoint not available on this platform (e.g. sensors on macOS) |

---

## Endpoints

All endpoints accept `GET` requests. Query parameters are optional unless noted.

### System

| Endpoint | Params | Description |
|----------|--------|-------------|
| `GET /system/overview` | — | Full snapshot: CPU, memory, disk, network, uptime |
| `GET /system/boot_time` | — | Boot timestamp + ISO string |
| `GET /system/users` | — | Logged-in users |

### CPU

| Endpoint | Params | Description |
|----------|--------|-------------|
| `GET /cpu/count` | `logical=true` | Logical or physical core count |
| `GET /cpu/percent` | `interval=0.1`, `percpu=false` | CPU utilisation % |
| `GET /cpu/times` | `percpu=false` | Time spent in user/system/idle/etc |
| `GET /cpu/times_percent` | `interval=0.1`, `percpu=false` | Same but as percentages |
| `GET /cpu/stats` | — | Context switches, interrupts, syscalls |
| `GET /cpu/freq` | `percpu=false` | Current/min/max frequency in MHz |
| `GET /cpu/load_avg` | — | 1/5/15-min load average + % relative to core count |

### Memory

| Endpoint | Params | Description |
|----------|--------|-------------|
| `GET /memory/virtual` | — | RAM — total, available, used, free, percent |
| `GET /memory/swap` | — | Swap — total, used, free, percent, sin, sout |

### Disk

| Endpoint | Params | Description |
|----------|--------|-------------|
| `GET /disk/partitions` | `all=false` | Mounted partitions |
| `GET /disk/usage` | `path=/` | Usage for a given path |
| `GET /disk/io_counters` | `perdisk=false`, `nowrap=true` | Read/write bytes and counts |

### Network

| Endpoint | Params | Description |
|----------|--------|-------------|
| `GET /net/io_counters` | `pernic=false`, `nowrap=true` | Bytes/packets sent and received |
| `GET /net/connections` | `kind=inet` | Active connections (`inet`, `tcp`, `udp`, `unix`, `all`, etc.) |
| `GET /net/if_addrs` | — | IP/MAC addresses per interface |
| `GET /net/if_stats` | — | Speed, duplex, MTU, up/down per interface |

### Sensors *(Linux / limited macOS)*

| Endpoint | Params | Description |
|----------|--------|-------------|
| `GET /sensors/temperatures` | `fahrenheit=false` | Hardware temperatures by sensor |
| `GET /sensors/fans` | — | Fan RPM readings |
| `GET /sensors/battery` | — | Battery percent, time left, plugged in |

### Processes

| Endpoint | Params | Description |
|----------|--------|-------------|
| `GET /processes/pids` | — | List of all PIDs |
| `GET /processes/list` | `attrs=pid,name,status,cpu_percent,memory_percent,username` | Lightweight summary of all processes |
| `GET /processes/<pid>` | — | Full detail for one PID |
| `GET /processes/<pid>/threads` | — | Thread list for a PID |
| `GET /processes/<pid>/connections` | `kind=inet` | Network connections for a PID |
| `GET /processes/<pid>/children` | `recursive=false` | Child processes |
| `GET /processes/<pid>/memory_maps` | `grouped=true` | Memory map for a PID |
| `GET /processes/pid_exists/<pid>` | — | Check if a PID is alive |

---

## Example responses

**`GET /system/overview`**
```json
{
  "cpu": {
    "count_logical": 8,
    "count_physical": 4,
    "percent": 12.3,
    "freq": {"current": 2400.0, "min": 800.0, "max": 3500.0},
    "load_avg": {"1min": 1.2, "5min": 0.9, "15min": 0.7},
    "load_avg_percent": {"1min": 15.0, "5min": 11.25, "15min": 8.75}
  },
  "memory": {
    "virtual": {"total": 17179869184, "available": 8589934592, "percent": 50.0, ...},
    "swap": {"total": 2147483648, "used": 0, "percent": 0.0, ...}
  },
  ...
}
```

**`GET /processes/list?attrs=pid,name,cpu_percent`**
```json
{
  "count": 312,
  "processes": [
    {"pid": 1, "name": "launchd", "cpu_percent": 0.0},
    {"pid": 423, "name": "python3", "cpu_percent": 2.1},
    ...
  ]
}
```
