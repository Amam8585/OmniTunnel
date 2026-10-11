#!/usr/bin/env bash
# Safe per-instance ICMP metrics. Reads snapshots: never touches network state.
set -euo pipefail
mode="${1:-stats}"; inst="${2:-}"; format="${3:-}"
[[ "$mode" == stats || "$mode" == monitor ]] || { echo "usage: monitor.sh stats|monitor <instance> [--json]" >&2; exit 2; }
[[ "$inst" =~ ^[a-zA-Z0-9_-]+$ ]] || { echo "invalid instance name" >&2; exit 2; }
[[ "$format" == "" || "$format" == --json ]] || { echo "use --json" >&2; exit 2; }
conf="/etc/omnitunnel/inst/$inst/instance.conf"
[[ -r "$conf" ]] || { echo "instance config missing: $conf" >&2; exit 1; }
type="$(sed -n 's/^TYPE=//p' "$conf" | head -1)"
[[ "$type" == icmp ]] || { echo "per-process metrics currently supported for Direct ICMP only (found $type)" >&2; exit 1; }
dev="$(sed -n 's/^DEV=//p' "$conf" | head -1)"
[[ "$dev" =~ ^[a-zA-Z0-9_-]{1,15}$ ]] || { echo "bad DEV in config" >&2; exit 1; }
path="/run/omnitunnel/icmp-$dev.json"
[[ -r "$path" ]] || { echo "no metrics yet: $path (check service status and logs)" >&2; exit 1; }
exec python3 - "$path" "$mode" "$format" "$inst" <<'PY'
import json, os, sys, time
path, mode, fmt, inst = sys.argv[1:]
def sample():
    with open(path, encoding="utf-8") as handle:
        obj = json.load(handle)
    if not isinstance(obj, dict):
        raise ValueError("bad counters")
    return obj
def fmt_rate(n, duration):
    return f"{max(0.,n/duration):,.1f}"
def show(cur, last=None, interval=1.0):
    if fmt == "--json":
        obj = dict(cur)
        obj["instance"] = inst
        if last is not None:
            obj["rates"] = {k + "_per_second": max(0.,(cur.get(k,0)-last.get(k,0))/interval)
                            for k in ("tun_rx_packets","tun_tx_packets","icmp_rx_packets",
                                      "icmp_tx_packets","queue_drops","send_errors","recv_errors","rx_bytes","tx_bytes")}
        print(json.dumps(obj, separators=(",",":")), flush=True)
        return
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
              f" | goodput proxy {(cur.get('rx_bytes',0)-last.get('rx_bytes',0))*8/interval/1e6:.2f} Mbps",
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