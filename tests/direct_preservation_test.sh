#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
fail() { echo "FAIL: $*" >&2; exit 1; }
bash -n install.sh omnitunnel.sh icmptun-ctl.sh
for p in scripts/monitor.sh scripts/diagnostics.sh scripts/optimizer.sh; do
    [[ -s "$p" ]] || fail "$p missing"
    bash -n "$p" || fail "$p malformed"
done
all=$(grep '^ALL_TYPES=' omnitunnel.sh | head -1)
[[ "$all" == 'ALL_TYPES="gre icmp udp hysteria tcp fou"' ]] ||
    fail "Direct protocol list altered: $all"
for t in gre icmp udp hysteria tcp fou; do
    grep -qE "^[[:space:]]*$t\\)" omnitunnel.sh || fail "Direct type handler missing: $t"
done
# Retired transports must not be selectable for new instances.
# Retired carriers must remain unavailable in the new-tunnel selection.
for retired in mux ws stripe vxlan ackless; do
    if grep '^ALL_TYPES=' omnitunnel.sh | grep -qw "$retired"; then
        fail "retired transport is selectable: $retired"
    fi
done
# Hybrid IG must not be selectable until a tested implementation exists.
if grep '^ALL_TYPES=' omnitunnel.sh | grep -qw hybrid; then
    fail "Hybrid IG advertised before implementation"
fi
for t in udp tcp icmp; do
    grep -q "tun_main_$t" src/main.c || fail "C Direct core dispatcher missing: $t"
done
if grep -qE 'reverse-mux|CHISEL_BIN|cmd_mux_(add|del|token)|--reverse' omnitunnel.sh; then
    fail "dedicated reverse implementation remains in management script"
fi
grep -q 'Restart=on-failure' omnitunnel.sh || fail "systemd restart policy missing"
grep -q -- '-F' src/icmptun.c || fail "ICMP flow configuration missing"
grep -q 'EPOLLOUT' src/icmptun.c || fail "backpressure interest not present"
grep -q 'metrics.queue_full' src/icmptun.c || fail "internal drop metric missing"
if grep -q 'systemctl restart' install.sh; then
    fail "installer must never blindly restart live services"
fi
echo "PASS: six active Direct transports registered; legacy preserved; safe installer and Bash syntax"
