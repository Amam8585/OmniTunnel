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
grep -Fq 'APADANA_LINK="$BIN_DIR/apadana"' install.sh || fail "APADANA executable alias missing"
grep -Fq 'ln -sfn "$PREFIX/omnitunnel.sh" "$APADANA_LINK"' install.sh || fail "APADANA alias not installed"
grep -Fq 'nitem 5 "Update APADANA"' omnitunnel.sh || fail "old update menu label"
grep -Fq 'nitem 6 "Completely Uninstall APADANA"' omnitunnel.sh || fail "old uninstall menu label"
# Uninstall must reject an unsafe purge before it takes a snapshot or removes files.
python3 - <<'PY'
from pathlib import Path
s = Path("install.sh").read_text()
start = s.index('    uninstall)\n', s.index('case "$ACTION" in'))
end = s.index('    prepare)\n', start)
block = s[start:end]
assert block.index("if ((PURGE)) && compgen") < block.index("snapshot"), "purge preflight must precede snapshot"
assert block.index("if ((PURGE)) && compgen") < block.index("((DRY))"), "dry-run must validate purge preflight"
PY
# A 100k-packet egress queue causes severe bufferbloat under congestion.
# Validate both userspace C dataplanes retain a bounded initial queue.
for core in src/obsctcp.c src/obsctun.c; do
    grep -q 'q.ifr_qlen = 1000;' "$core" || fail "$core must bound initial TUN queue"
    if grep -q 'q.ifr_qlen = 100000;' "$core"; then
        fail "$core contains legacy oversized TUN queue"
    fi
done
echo "PASS: six active Direct transports registered; legacy preserved; safe installer and Bash syntax"
