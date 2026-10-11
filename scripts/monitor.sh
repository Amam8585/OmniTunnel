#!/usr/bin/env bash
# Safe per-instance ICMP metrics. Reads snapshots: never touches network state.
set -euo pipefail
mode="${1:-stats}"; inst="${2:-}"; format="${3:-}"
[[ "$mode" == stats || "$mode" == monitor ]] || { echo "usage: monitor.sh stats|monitor <instance> [--json]" >&2; exit 2; }
[[ "$inst" =~ ^[a-zA-Z0-9_-]+(\.service)?$ ]] || { echo "invalid instance name" >&2; exit 2; }
[[ "$format" == "" || "$format" == --json ]] || { echo "use --json" >&2; exit 2; }
conf="/etc/omnitunnel/inst/$inst/instance.conf"
if [[ ! -r "$conf" ]]; then
    if [[ "$inst" == *.service ]]; then
        exec python3 "$(dirname "${BASH_SOURCE[0]}")/monitor_legacy.py" "$mode" "$inst" "$format"
    fi
    echo "instance config missing: $conf; provide legacy unit name with .service" >&2
    exit 1
fi
type="$(sed -n 's/^TYPE=//p' "$conf" | head -1)"
[[ "$type" == icmp ]] || { echo "per-process metrics currently supported for Direct ICMP only (found $type)" >&2; exit 1; }
dev="$(sed -n 's/^DEV=//p' "$conf" | head -1)"
[[ "$dev" =~ ^[a-zA-Z0-9_-]{1,15}$ ]] || { echo "bad DEV in config" >&2; exit 1; }
path="/run/omnitunnel/icmp-$dev.json"
if [[ ! -r "$path" ]]; then
    echo "Internal ICMP counters unavailable at $path; falling back to kernel/systemd only" >&2
    exec python3 "$(dirname "${BASH_SOURCE[0]}")/monitor_legacy.py" "$mode" "omnitun-$inst.service" "$format"
fi
exec python3 - "$path" "$mode" "$format" "$inst" <<'PY'
import json, os, sys, time
path, mode, fmt, inst = sys.argv[1:]
last_kernel = None

def resource_snapshot():
    """Read-only process RSS and CPU from /proc, resolved through the owned unit."""
    global last_proc
    try:
        import subprocess
        run = subprocess.run(["systemctl", "show", "-P", "MainPID", "omnitun-" + inst + ".service"],
                             capture_output=True, text=True, timeout=1.0)
        pid = int(run.stdout.strip())
        if pid < 1:
            return {}
        with open("/proc/" + str(pid) + "/stat", encoding="utf-8") as handle:
            tail = handle.read().rsplit(") ", 1)[1].split()
        ticks = int(tail[11]) + int(tail[12])
        start_ticks = int(tail[19])
        with open("/proc/" + str(pid) + "/status", encoding="utf-8") as handle:
            rss = next((int(line.split()[1]) * 1024 for line in handle if line.startswith("VmRSS:")), 0)
        now = time.monotonic()
        res = {"pid":pid, "rss_bytes":rss}
        if last_proc and last_proc[0] == pid and last_proc[3] == start_ticks:
            elapsed = max(0.001, now - last_proc[2])
            res["cpu_percent_one_core"] = round(100 * max(0, ticks - last_proc[1]) /
                                                os.sysconf("SC_CLK_TCK") / elapsed, 1)
        last_proc = (pid, ticks, now, start_ticks)
        return res
    except (OSError, ValueError, IndexError, StopIteration):
        return {}
last_proc = None

def sample():
    with open(path, encoding="utf-8") as handle:
        obj = json.load(handle)
    if not isinstance(obj, dict):
        raise ValueError("bad counters")
    return obj
def kernel_snapshot():
    dev = os.path.basename(path).removeprefix("icmp-").removesuffix(".json")
    base = "/sys/class/net/" + dev + "/statistics/"
    counters = {}
    for key in ("rx_packets","tx_packets","rx_dropped","tx_dropped","rx_bytes","tx_bytes"):
        try:
            with open(base + key, encoding="ascii") as stream:
                counters[key] = int(stream.read())
        except (OSError,ValueError):
            counters[key] = None
    return counters

def fmt_rate(n, duration):
    return f"{max(0.,n/duration):,.1f}"
def show(cur, last=None, interval=1.0):
    global last_kernel
    kernel = kernel_snapshot()
    resources = resource_snapshot()
    age_sec = max(0.,time.monotonic() - float(cur.get("timestamp_ms",0))/1000.)
    stale = age_sec > 5
    reset = last is not None and any(
        isinstance(cur.get(k), (int,float)) and isinstance(last.get(k), (int,float))
        and cur[k] < last[k]
        for k in ("rx_bytes","tx_bytes","queue_drops","icmp_rx_packets","icmp_tx_packets")
    )
    if fmt == "--json":
        obj = dict(cur)
        obj["resources"] = resources
        obj["instance"] = inst
        obj["kernel_interface_counters"] = kernel
        obj["application_goodput_mbps"] = None
        obj["process_sample_stale"] = stale
        obj["sample_age_seconds"] = round(age_sec,2)
        obj["counter_reset_detected"] = bool(reset)
        obj["tunnel_reachable"] = None
        obj["latency_p95_ms"] = None
        obj["latency_p99_ms"] = None
        if last is not None:
            tracked = ("tun_rx_packets","tun_tx_packets","icmp_rx_packets","icmp_tx_packets",
                       "queue_drops","tun_queue_drops","tun_oversized","queue_pauses",
                       "flow_evictions","send_errors","recv_errors","rx_bytes","tx_bytes")
            obj["rates"] = {k + "_per_second":
                ((cur[k]-last[k])/interval if k in cur and k in last and
                 cur[k]>=last[k] and not stale and not reset else None)
                for k in tracked}
        if last_kernel is not None:
            obj["kernel_rates_per_second"]={
                key:((current-last_kernel[key])/max(interval,0.001) if current>=last_kernel[key] and not stale else None)
                for key,current in kernel.items()
                if current is not None and last_kernel.get(key) is not None}
        last_kernel = kernel
        print(json.dumps(obj, separators=(",",":")), flush=True)
        return
    print("  Kernel TUN counters:",kernel, flush=True)
    if stale: print("  WARNING: stale user-space snapshot: process could be stopped or stuck",flush=True)
    if reset: print("  WARNING: counters reset or process restarted; rate delta invalid",flush=True)
    print("  Application goodput, P95/P99 latency: NOT MEASURED", flush=True)
    if resources:
        print(f"  PID={resources.get('pid')} RSS={resources.get('rss_bytes', 0)/1048576:.1f} MiB "
              f"CPU={resources.get('cpu_percent_one_core', 'n/a')}% one core", flush=True)
    print(f"Direct ICMP {inst} | flow {cur.get('active_flows',0):,}/{cur.get('flow_capacity',0):,}"
          f" | send queue {cur.get('queue_length',0):,} (peak {cur.get('queue_peak',0):,})"
          f" | internal queue drops {cur.get('queue_drops',0):,}", flush=True)
    print(f"  TUN RX/TX {cur.get('tun_rx_packets',0):,}/{cur.get('tun_tx_packets',0):,}"
          f" | ICMP RX/TX {cur.get('icmp_rx_packets',0):,}/{cur.get('icmp_tx_packets',0):,}"
          f" | flow evictions {cur.get('flow_evictions',0):,}"
          f" | collisions {cur.get('flow_collisions',0):,}", flush=True)
    print(f"  errors: send={cur.get('send_errors',0):,} receive={cur.get('recv_errors',0):,}"
          f" tun={cur.get('tun_errors',0):,} invalid={cur.get('invalid_packets',0):,}"
          f" | reordered={cur.get('reorder_events',0):,}"
          f" timeouts={cur.get('reorder_timeouts',0):,}", flush=True)
    if last:
        print(f"  rate: rx {fmt_rate(cur.get('tun_rx_packets',0)-last.get('tun_rx_packets',0),interval)} pps"
              f" | tx {fmt_rate(cur.get('icmp_tx_packets',0)-last.get('icmp_tx_packets',0),interval)} pps"
              f" | decap inner bitrate (NOT app goodput): {(cur.get('rx_bytes',0)-last.get('rx_bytes',0))*8/interval/1e6:.2f} Mbps" if not reset else
              " | counters reset: bitrate unavailable",
              flush=True)
try:
    prev = sample()
    if mode == "stats":
        show(prev)
    else:
        while True:
            time.sleep(1)
            next_sample = sample()
            dt = max(0.001,(next_sample.get("timestamp_ms",0)-prev.get("timestamp_ms",0))/1000.)
            show(next_sample, prev, dt)
            prev = next_sample
except (OSError, json.JSONDecodeError, ValueError) as e:
    print(f"monitor failed: {e}", file=sys.stderr)
    sys.exit(1)
except KeyboardInterrupt:
    pass
PY