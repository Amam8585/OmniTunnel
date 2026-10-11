#!/usr/bin/env bash
# OmniTunnel read-only host diagnostics. No network changes, no traffic generation.
set -u
export LC_ALL=C
OUT="${1:-/tmp/omnitunnel-diag-$(hostname -s)-$(date +%Y%m%d-%H%M%S).txt}"
umask 077
[[ "$OUT" == *.txt ]] || { echo "Output must end in .txt" >&2; exit 2; }
section() { printf '\n===== %s =====\n' "$1"; }
run() { printf '\n$ %s\n' "$*"; timeout 12 "$@" 2>&1 || true; }
{
section "Host / timestamp"
date -Is
uname -a
cat /etc/os-release 2>/dev/null | grep -E '^(NAME|VERSION_ID)=' || true
run uptime
run nproc
run free -h
section "Processes (filtered; no command arguments)"
ps -eo pid,comm,%cpu,%mem,rss --sort=-%cpu | head -n 30
section "TCP connection counts"
if command -v ss >/dev/null; then
 ss -Htan state established 2>/dev/null | wc -l
 ss -s 2>/dev/null
fi
section "Network interfaces and counters"
run ip -s link
run ip -br addr
section "Routes (destination prefixes only; may contain private IPs)"
run ip route show
section "TUN and tunnel interfaces"
for d in /sys/class/net/*; do
 n="${d##*/}"
 case "$n" in ic*|tun*|gre*|fou*|vxlan*|omni*|ot*) 
  printf '\ninterface=%s mtu=%s txqueuelen=%s\n' "$n" "$(cat "$d/mtu" 2>/dev/null)" "$(cat "$d/tx_queue_len" 2>/dev/null)"
  for c in rx_packets tx_packets rx_dropped tx_dropped rx_errors tx_errors; do
   printf '%s=%s ' "$c" "$(cat "$d/statistics/$c" 2>/dev/null)"
  done
  printf '\n'
 ;; esac
done
section "ICMP and UDP kernel counters"
run sh -c 'grep -E "^(Icmp|IcmpMsg|Udp|UdpLite):" /proc/net/snmp'
section "Kernel softnet"
run sh -c 'head -n 16 /proc/net/softnet_stat'
section "Conntrack occupancy"
for f in /proc/sys/net/netfilter/nf_conntrack_count /proc/sys/net/netfilter/nf_conntrack_max; do
 [[ -r "$f" ]] && printf '%s=%s\n' "$f" "$(cat "$f")"
done
section "Relevant sysctls (read only)"
for k in net.core.rmem_max net.core.wmem_max net.core.netdev_max_backlog net.ipv4.ip_forward net.ipv4.icmp_ratelimit; do
 sysctl "$k" 2>/dev/null || true
done
section "OmniTunnel services (names only)"
systemctl list-units --all --type=service --no-legend --no-pager 2>/dev/null | awk 'tolower($1) ~ /(omni|icmp|stripe|ackless|hysteria)/ {print $1,$3,$4}' || true
section "OmniTunnel processes (executable names only)"
ps -eo pid,comm,%cpu,%mem,rss --no-headers | awk 'tolower($2) ~ /(omni|icmp|stripe|ackless|hysteria)/ {print}' || true
section "Installed versions (if available)"
for b in /opt/omnitunnel/omnitun /usr/local/bin/omnitun; do
 [[ -x "$b" ]] && sha256sum "$b" 2>/dev/null || true
done
section "Completed (snapshot only; no active packet-loss or RTT measurement)"
} > "$OUT" 2>&1
chmod 600 "$OUT"
printf 'Saved: %s\nReview the file for hostnames, IP addresses and other sensitive details before sharing.\n' "$OUT"
