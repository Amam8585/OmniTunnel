#!/usr/bin/env bash
# Read-only Direct ICMP diagnostics; no packet capture, no secrets, no live tuning.
set -euo pipefail
inst="${1:-}"
[[ "$inst" =~ ^[A-Za-z0-9_-]+$ ]] || { echo "usage: diagnostics.sh <instance>" >&2; exit 2; }
conf="/etc/omnitunnel/inst/$inst/instance.conf"
[[ -r "$conf" ]] || { echo "unknown instance" >&2; exit 1; }
dev="$(sed -n 's/^DEV=//p' "$conf" | head -1)"
type="$(sed -n 's/^TYPE=//p' "$conf" | head -1)"
[[ "$dev" =~ ^[A-Za-z0-9_-]{1,15}$ ]] || exit 2
echo "=== OmniTunnel $inst ($type on $dev) ==="
echo "Kernel: $(uname -r) | uptime: $(uptime -p 2>/dev/null || true)"
echo "-- Tunnel interface and counters"
ip -s link show dev "$dev" || true
echo "-- Queueing discipline"
tc -s qdisc show dev "$dev" 2>/dev/null || true
echo "-- Systemd service"
systemctl show "omnitun-$inst.service" -p MainPID -p ActiveState -p SubState -p NRestarts --no-pager 2>/dev/null || true
echo "-- Kernel ICMP counters"
awk '/^Icmp:/{print; getline; print; exit}' /proc/net/snmp || true
echo "-- Softnet processing"
cat /proc/net/softnet_stat 2>/dev/null || true
echo "-- TCP aggregate (whole-server, NOT active tunnel flow count)"
ss -s 2>/dev/null || true
echo "-- Conntrack"
if [[ -r /proc/sys/net/netfilter/nf_conntrack_count ]]; then
    printf 'count/max: %s/%s\n' "$(cat /proc/sys/net/netfilter/nf_conntrack_count)" \
        "$(cat /proc/sys/net/netfilter/nf_conntrack_max)"
else
    echo "not exposed by kernel"
fi
echo "-- ICMP userspace metrics (private counters, no payloads)"
cat "/run/omnitunnel/icmp-$dev.json" 2>/dev/null || echo "not available; version may be old or service inactive"
echo
echo "No settings were changed. A 10-second drop ratio alone cannot identify the bottleneck."
