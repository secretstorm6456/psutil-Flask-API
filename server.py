from flask import Flask, jsonify, request
import os, psutil, hmac, hashlib, secrets, json, datetime, argparse, sys
from pathlib import Path
from functools import wraps

app = Flask(__name__)
app.config["NO_AUTH"] = False

KEYS_FILE = Path("api_keys.json")

# ─── Key Management ───────────────────────────────────────────────────────────

def load_keys() -> dict:
    if not KEYS_FILE.exists():
        return {}
    with open(KEYS_FILE, "r") as f:
        return json.load(f)

def save_keys(keys: dict) -> None:
    KEYS_FILE.touch(mode=0o600, exist_ok=True)
    with open(KEYS_FILE, "w") as f:
        json.dump(keys, f, indent=2)
    os.chmod(KEYS_FILE, 0o600)

def generate_api_key(prefix="sys_api_", length=20):
    return prefix + secrets.token_urlsafe(length)[:length]

def create_salt() -> bytes:
    return os.urandom(16)

def hash_api_key(api_key: str, salt: bytes) -> str:
    return hashlib.sha256(salt + api_key.encode("utf-8")).hexdigest()

def store_api_key(name: str, api_key: str) -> None:
    keys = load_keys()
    salt = create_salt()
    keys[name] = {
        "salt": salt.hex(),
        "hash": hash_api_key(api_key, salt),
    }
    save_keys(keys)

def verify_api_key(provided_key: str) -> bool:
    for record in load_keys().values():
        salt = bytes.fromhex(record["salt"])
        stored_hash = record["hash"]
        provided_hash = hashlib.sha256(salt + provided_key.encode("utf-8")).hexdigest()
        if hmac.compare_digest(provided_hash, stored_hash):
            return True
    return False

def require_api_key(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if app.config["NO_AUTH"]:
            return func(*args, **kwargs)
        api_key = request.headers.get("X-API-KEY")
        if not api_key:
            return jsonify({"error": "API key is missing"}), 401
        if not verify_api_key(api_key):
            return jsonify({"error": "Invalid API key"}), 403
        return func(*args, **kwargs)
    return wrapper

# ─── CLI Key Management Commands ──────────────────────────────────────────────

def cmd_create_key(name: str) -> None:
    keys = load_keys()
    if name in keys:
        print(f"[error] A key named '{name}' already exists. Delete it first or use a different name.")
        sys.exit(1)
    key = generate_api_key()
    store_api_key(name, key)
    print(f"[created] name={name}")
    print(f"          key={key}")
    print("Store this key somewhere safe — it cannot be recovered later.")

def cmd_delete_key(name: str) -> None:
    keys = load_keys()
    if name not in keys:
        print(f"[error] No key named '{name}' found.")
        sys.exit(1)
    del keys[name]
    save_keys(keys)
    print(f"[deleted] '{name}' removed.")

def cmd_list_keys() -> None:
    keys = load_keys()
    if not keys:
        print("[empty] No API keys stored.")
        return
    print(f"{'NAME':<30}  HASH (first 16 chars)")
    print("-" * 55)
    for name, record in keys.items():
        short_hash = record["hash"][:16] + "..."
        print(f"{name:<30}  {short_hash}")

def cmd_rename_key(old_name: str, new_name: str) -> None:
    keys = load_keys()
    if old_name not in keys:
        print(f"[error] No key named '{old_name}' found.")
        sys.exit(1)
    if new_name in keys:
        print(f"[error] A key named '{new_name}' already exists.")
        sys.exit(1)
    keys[new_name] = keys.pop(old_name)
    save_keys(keys)
    print(f"[renamed] '{old_name}' → '{new_name}'")

def cmd_rotate_key(name: str) -> None:
    """Generate a fresh key value for an existing name."""
    keys = load_keys()
    if name not in keys:
        print(f"[error] No key named '{name}' found.")
        sys.exit(1)
    new_key = generate_api_key()
    salt = create_salt()
    keys[name] = {
        "salt": salt.hex(),
        "hash": hash_api_key(new_key, salt),
    }
    save_keys(keys)
    print(f"[rotated] name={name}")
    print(f"          new key={new_key}")
    print("Store this key somewhere safe — it cannot be recovered later.")

def cmd_verify_key(key: str) -> None:
    if verify_api_key(key):
        print("[valid] The provided key is valid.")
    else:
        print("[invalid] The provided key does not match any stored key.")

# ─── CLI Entry Point ──────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        prog="app.py",
        description="psutil Flask API — manage keys or start the server",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    group = parser.add_mutually_exclusive_group()

    group.add_argument(
        "--create-key",
        metavar="NAME",
        help="Create a new API key with the given name and print it.",
    )
    group.add_argument(
        "--delete-key",
        metavar="NAME",
        help="Delete the API key with the given name.",
    )
    group.add_argument(
        "--list-keys",
        action="store_true",
        help="List all stored API key names (hashes shown, plaintext never stored).",
    )
    group.add_argument(
        "--rename-key",
        nargs=2,
        metavar=("OLD_NAME", "NEW_NAME"),
        help="Rename an existing key.",
    )
    group.add_argument(
        "--rotate-key",
        metavar="NAME",
        help="Generate a new key value for an existing name (invalidates the old one).",
    )
    group.add_argument(
        "--verify-key",
        metavar="KEY",
        help="Check whether a plaintext key is valid.",
    )

    parser.add_argument("--port", type=int, default=5500, help="Port to run the server on (default: 5500)")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to (default: 127.0.0.1)")
    parser.add_argument("--debug", action="store_true", help="Run Flask in debug mode")
    parser.add_argument(
        "--no-auth",
        action="store_true",
        help="Disable API key authentication (all endpoints open). Use only on trusted networks.",
    )

    return parser.parse_args()

# ─── Helper ───────────────────────────────────────────────────────────────────

def _nt(obj):
    """Recursively convert named tuples / lists of named tuples to dicts."""
    if hasattr(obj, "_asdict"):
        return {k: _nt(v) for k, v in obj._asdict().items()}
    if isinstance(obj, list):
        return [_nt(i) for i in obj]
    return obj

def _safe(method):
    try:
        return method()
    except (psutil.AccessDenied, psutil.ZombieProcess, NotImplementedError):
        return None

def _safe_nt(method):
    try:
        return _nt(method())
    except (psutil.AccessDenied, psutil.ZombieProcess, NotImplementedError):
        return None

def _safe_list(method):
    try:
        return [_nt(i) for i in method()]
    except (psutil.AccessDenied, psutil.ZombieProcess, NotImplementedError):
        return None

# ─── CPU ──────────────────────────────────────────────────────────────────────

@app.route("/cpu/count")
@require_api_key
def cpu_count():
    logical = request.args.get("logical", "true").lower() == "true"
    return jsonify({"cpu_count": psutil.cpu_count(logical=logical)})


@app.route("/cpu/percent")
@require_api_key
def cpu_percent():
    interval = request.args.get("interval", None)
    if interval is not None:
        interval = float(interval)
    percpu = request.args.get("percpu", "false").lower() == "true"
    return jsonify({"cpu_percent": psutil.cpu_percent(interval=interval, percpu=percpu)})


@app.route("/cpu/times")
@require_api_key
def cpu_times():
    percpu = request.args.get("percpu", "false").lower() == "true"
    return jsonify({"cpu_times": _nt(psutil.cpu_times(percpu=percpu))})


@app.route("/cpu/times_percent")
@require_api_key
def cpu_times_percent():
    interval = request.args.get("interval", None)
    if interval is not None:
        interval = float(interval)
    percpu = request.args.get("percpu", "false").lower() == "true"
    return jsonify({"cpu_times_percent": _nt(psutil.cpu_times_percent(interval=interval, percpu=percpu))})


@app.route("/cpu/stats")
@require_api_key
def cpu_stats():
    return jsonify({"cpu_stats": _nt(psutil.cpu_stats())})


@app.route("/cpu/freq")
@require_api_key
def cpu_freq():
    percpu = request.args.get("percpu", "false").lower() == "true"
    return jsonify({"cpu_freq": _nt(psutil.cpu_freq(percpu=percpu))})


@app.route("/cpu/load_avg")
@require_api_key
def load_avg():
    avg = psutil.getloadavg()
    cpu_c = psutil.cpu_count()
    return jsonify({
        "load_avg": {"1min": avg[0], "5min": avg[1], "15min": avg[2]},
        "cpu_count": cpu_c,
        "load_avg_percent": {
            "1min": round(avg[0] / cpu_c * 100, 2) if cpu_c else None,
            "5min": round(avg[1] / cpu_c * 100, 2) if cpu_c else None,
            "15min": round(avg[2] / cpu_c * 100, 2) if cpu_c else None,
        }
    })

# ─── Memory ───────────────────────────────────────────────────────────────────

@app.route("/memory/virtual")
@require_api_key
def virtual_memory():
    return jsonify({"virtual_memory": _nt(psutil.virtual_memory())})


@app.route("/memory/swap")
@require_api_key
def swap_memory():
    return jsonify({"swap_memory": _nt(psutil.swap_memory())})

# ─── Disks ────────────────────────────────────────────────────────────────────

@app.route("/disk/partitions")
@require_api_key
def disk_partitions():
    all_partitions = request.args.get("all", "false").lower() == "true"
    return jsonify({"disk_partitions": _nt(psutil.disk_partitions(all=all_partitions))})


@app.route("/disk/usage")
@require_api_key
def disk_usage():
    path = request.args.get("path", "/")
    try:
        return jsonify({"disk_usage": _nt(psutil.disk_usage(path)), "path": path})
    except (PermissionError, FileNotFoundError) as e:
        return jsonify({"error": str(e)}), 400


@app.route("/disk/io_counters")
@require_api_key
def disk_io_counters():
    perdisk = request.args.get("perdisk", "false").lower() == "true"
    nowrap = request.args.get("nowrap", "true").lower() == "true"
    result = psutil.disk_io_counters(perdisk=perdisk, nowrap=nowrap)
    if result is None:
        return jsonify({"disk_io_counters": None})
    if perdisk:
        return jsonify({"disk_io_counters": {k: _nt(v) for k, v in result.items()}})
    return jsonify({"disk_io_counters": _nt(result)})

# ─── Network ──────────────────────────────────────────────────────────────────

@app.route("/net/io_counters")
@require_api_key
def net_io_counters():
    pernic = request.args.get("pernic", "false").lower() == "true"
    nowrap = request.args.get("nowrap", "true").lower() == "true"
    result = psutil.net_io_counters(pernic=pernic, nowrap=nowrap)
    if result is None:
        return jsonify({"net_io_counters": None})
    if pernic:
        return jsonify({"net_io_counters": {k: _nt(v) for k, v in result.items()}})
    return jsonify({"net_io_counters": _nt(result)})


@app.route("/net/connections")
@require_api_key
def net_connections():
    kind = request.args.get("kind", "inet")
    try:
        conns = psutil.net_connections(kind=kind)
    except psutil.AccessDenied as e:
        return jsonify({"error": str(e)}), 403
    result = [{
        "fd": c.fd,
        "family": str(c.family),
        "type": str(c.type),
        "laddr": c.laddr._asdict() if c.laddr else None,
        "raddr": c.raddr._asdict() if c.raddr else None,
        "status": c.status,
        "pid": c.pid,
    } for c in conns]
    return jsonify({"net_connections": result})


@app.route("/net/if_addrs")
@require_api_key
def net_if_addrs():
    raw = psutil.net_if_addrs()
    return jsonify({"net_if_addrs": {iface: [_nt(a) for a in addrs] for iface, addrs in raw.items()}})


@app.route("/net/if_stats")
@require_api_key
def net_if_stats():
    return jsonify({"net_if_stats": {k: _nt(v) for k, v in psutil.net_if_stats().items()}})

# ─── Sensors ──────────────────────────────────────────────────────────────────

@app.route("/sensors/temperatures")
@require_api_key
def sensors_temperatures():
    if not hasattr(psutil, "sensors_temperatures"):
        return jsonify({"error": "Not available on this platform"}), 501
    fahrenheit = request.args.get("fahrenheit", "false").lower() == "true"
    raw = psutil.sensors_temperatures(fahrenheit=fahrenheit)
    return jsonify({"sensors_temperatures": {k: [_nt(e) for e in v] for k, v in raw.items()}, "fahrenheit": fahrenheit})


@app.route("/sensors/fans")
@require_api_key
def sensors_fans():
    if not hasattr(psutil, "sensors_fans"):
        return jsonify({"error": "Not available on this platform"}), 501
    raw = psutil.sensors_fans()
    return jsonify({"sensors_fans": {k: [_nt(e) for e in v] for k, v in raw.items()}})


@app.route("/sensors/battery")
@require_api_key
def sensors_battery():
    if not hasattr(psutil, "sensors_battery"):
        return jsonify({"error": "Not available on this platform"}), 501
    battery = psutil.sensors_battery()
    return jsonify({"sensors_battery": _nt(battery) if battery else None})

# ─── System Info ──────────────────────────────────────────────────────────────

@app.route("/system/boot_time")
@require_api_key
def boot_time():
    ts = psutil.boot_time()
    return jsonify({"boot_time": ts, "boot_time_iso": datetime.datetime.fromtimestamp(ts).isoformat()})


@app.route("/system/users")
@require_api_key
def users():
    result = [{
        "name": u.name,
        "terminal": u.terminal,
        "host": u.host,
        "started": u.started,
        "started_iso": datetime.datetime.fromtimestamp(u.started).isoformat(),
        "pid": u.pid,
    } for u in psutil.users()]
    return jsonify({"users": result})


@app.route("/system/overview")
@require_api_key
def system_overview():
    boot_ts = psutil.boot_time()
    avg = psutil.getloadavg()
    cpu_c = psutil.cpu_count()
    return jsonify({
        "cpu": {
            "count_logical": psutil.cpu_count(logical=True),
            "count_physical": psutil.cpu_count(logical=False),
            "percent": psutil.cpu_percent(interval=0.1),
            "freq": _nt(psutil.cpu_freq()),
            "load_avg": {"1min": avg[0], "5min": avg[1], "15min": avg[2]},
            "load_avg_percent": {
                "1min": round(avg[0] / cpu_c * 100, 2) if cpu_c else None,
                "5min": round(avg[1] / cpu_c * 100, 2) if cpu_c else None,
                "15min": round(avg[2] / cpu_c * 100, 2) if cpu_c else None,
            },
        },
        "memory": {
            "virtual": _nt(psutil.virtual_memory()),
            "swap": _nt(psutil.swap_memory()),
        },
        "disk": {
            "partitions": _nt(psutil.disk_partitions()),
            "root_usage": _nt(psutil.disk_usage("/")),
        },
        "network": {
            "io_counters": _nt(psutil.net_io_counters()),
            "if_stats": {k: _nt(v) for k, v in psutil.net_if_stats().items()},
        },
        "system": {
            "boot_time": boot_ts,
            "boot_time_iso": datetime.datetime.fromtimestamp(boot_ts).isoformat(),
            "process_count": len(psutil.pids()),
            "users": [u.name for u in psutil.users()],
        },
    })

# ─── Processes ────────────────────────────────────────────────────────────────

@app.route("/processes/pids")
@require_api_key
def pids():
    return jsonify({"pids": psutil.pids()})


@app.route("/processes/list")
@require_api_key
def process_list():
    attrs_param = request.args.get("attrs", "pid,name,status,cpu_percent,memory_percent,username")
    attrs = [a.strip() for a in attrs_param.split(",") if a.strip()]
    result = []
    for proc in psutil.process_iter(attrs):
        try:
            result.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return jsonify({"processes": result, "count": len(result)})


@app.route("/processes/<int:pid>")
@require_api_key
def process_detail(pid: int):
    try:
        p = psutil.Process(pid)
        with p.oneshot():
            info = {
                "pid": p.pid,
                "ppid": p.ppid(),
                "name": p.name(),
                "exe": _safe(p.exe),
                "cmdline": _safe(p.cmdline),
                "status": p.status(),
                "create_time": p.create_time(),
                "create_time_iso": datetime.datetime.fromtimestamp(p.create_time()).isoformat(),
                "username": _safe(p.username),
                "cwd": _safe(p.cwd),
                "cpu_percent": p.cpu_percent(interval=None),
                "cpu_times": _nt(p.cpu_times()),
                "cpu_num": _safe(p.cpu_num),
                "memory_info": _nt(p.memory_info()),
                "memory_percent": p.memory_percent(),
                "num_threads": p.num_threads(),
                "num_ctx_switches": _nt(p.num_ctx_switches()),
                "num_fds": _safe(p.num_fds),
                "io_counters": _safe_nt(p.io_counters),
                "open_files": _safe_list(p.open_files),
                "is_running": p.is_running(),
            }
        return jsonify({"process": info})
    except psutil.NoSuchProcess:
        return jsonify({"error": f"No process with PID {pid}"}), 404
    except psutil.AccessDenied as e:
        return jsonify({"error": str(e)}), 403


@app.route("/processes/<int:pid>/threads")
@require_api_key
def process_threads(pid: int):
    try:
        return jsonify({"pid": pid, "threads": [_nt(t) for t in psutil.Process(pid).threads()]})
    except psutil.NoSuchProcess:
        return jsonify({"error": f"No process with PID {pid}"}), 404
    except psutil.AccessDenied as e:
        return jsonify({"error": str(e)}), 403


@app.route("/processes/<int:pid>/connections")
@require_api_key
def process_connections(pid: int):
    kind = request.args.get("kind", "inet")
    try:
        conns = psutil.Process(pid).net_connections(kind=kind)
        result = [{
            "fd": c.fd,
            "family": str(c.family),
            "type": str(c.type),
            "laddr": c.laddr._asdict() if c.laddr else None,
            "raddr": c.raddr._asdict() if c.raddr else None,
            "status": c.status,
        } for c in conns]
        return jsonify({"pid": pid, "connections": result})
    except psutil.NoSuchProcess:
        return jsonify({"error": f"No process with PID {pid}"}), 404
    except psutil.AccessDenied as e:
        return jsonify({"error": str(e)}), 403


@app.route("/processes/<int:pid>/children")
@require_api_key
def process_children(pid: int):
    recursive = request.args.get("recursive", "false").lower() == "true"
    try:
        children = psutil.Process(pid).children(recursive=recursive)
        result = []
        for c in children:
            try:
                result.append({"pid": c.pid, "name": c.name(), "status": c.status()})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return jsonify({"pid": pid, "children": result})
    except psutil.NoSuchProcess:
        return jsonify({"error": f"No process with PID {pid}"}), 404


@app.route("/processes/<int:pid>/memory_maps")
@require_api_key
def process_memory_maps(pid: int):
    grouped = request.args.get("grouped", "true").lower() == "true"
    try:
        maps = psutil.Process(pid).memory_maps(grouped=grouped)
        return jsonify({"pid": pid, "memory_maps": [_nt(m) for m in maps]})
    except psutil.NoSuchProcess:
        return jsonify({"error": f"No process with PID {pid}"}), 404
    except psutil.AccessDenied as e:
        return jsonify({"error": str(e)}), 403


@app.route("/processes/pid_exists/<int:pid>")
@require_api_key
def pid_exists(pid: int):
    return jsonify({"pid": pid, "exists": psutil.pid_exists(pid)})


# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    args = parse_args()

    if args.create_key:
        cmd_create_key(args.create_key)
    elif args.delete_key:
        cmd_delete_key(args.delete_key)
    elif args.list_keys:
        cmd_list_keys()
    elif args.rename_key:
        cmd_rename_key(args.rename_key[0], args.rename_key[1])
    elif args.rotate_key:
        cmd_rotate_key(args.rotate_key)
    elif args.verify_key:
        cmd_verify_key(args.verify_key)
    else:
        if args.no_auth:
            app.config["NO_AUTH"] = True
            print("[warning] Authentication is DISABLED — all endpoints are open. Do not expose this to untrusted networks.")
        app.run(debug=args.debug, port=args.port, host=args.host)