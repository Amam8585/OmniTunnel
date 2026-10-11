#!/usr/bin/env bash
# Mocked netfilter integration: no host rules/links/sysctls are ever changed.
set -euo pipefail
SCRIPT="$(cd "$(dirname "$0")/.." && pwd)/omnitunnel.sh"
extract() {
    awk -v names="$1" '
      BEGIN {n=split(names,a," ");for(i=1;i<=n;i++) want[a[i]]=1}
      block {print;if($0~/^}/)block=0;next}
      {if (match($0,/^[A-Za-z0-9_]+\(\)[ \t]*\{/)) {
         name=$0;sub(/\(\).*/,"",name)
         if(name in want){print;if($0 !~/}/)block=1}
      }}' "$SCRIPT"
}
eval "$(extract 'norm_port inst_path inst_pf list_instances dnat_chain pf_map_file pf_snat_chain pf_filter_chain pf_ipv4 pf_owned_chain pf_state_file pf_new_chain pf_detach_owned_chain pf_check_chain_collisions pf_apply_all pf_mapping_conflict pf_map_add pf_map_del pf_flush_chain')"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin" "$WORK/inst/a" "$WORK/inst/b"
INST_DIR="$WORK/inst"
: > "$INST_DIR/a/pf.conf"
: > "$INST_DIR/b/pf.conf"
export LOG="$WORK/firewall.log"
: > "$LOG"
cat > "$WORK/bin/iptables" <<'SH'
#!/usr/bin/env bash
echo "$*" >> "$LOG"
case "$*" in *" -C "*|*" -S "*) exit 1;; esac
exit 0
SH
cat > "$WORK/bin/ip" <<'SH'
#!/usr/bin/env bash
if [[ "$*" == *" addr show dev "* ]]; then
    printf '2: eth0 inet 192.0.2.10/24\n2: eth0 inet 192.0.2.11/24\n'
elif [[ "$*" == *"route get 10.1.1.2"* ]]; then
    echo '10.1.1.2 dev ts-a src 10.1.1.1'
elif [[ "$*" == *"route get 10.1.2.2"* ]]; then
    echo '10.1.2.2 dev ts-b src 10.1.2.1'
else exit 1; fi
SH
chmod +x "$WORK/bin/iptables" "$WORK/bin/ip"
PATH="$WORK/bin:$PATH"
die() { echo "ERROR: $*" >&2; exit 1; }
ok() { :; }
need_root() { :; }
type_is_hysteria() { return 1; }
load_inst() {
    TYPE=icmp
    DEV="ts-$1"
    TUN_ADDR="10.1.$([[ "$1" == a ]] && echo 1 || echo 2).1"
    PEER_ADDR="10.1.$([[ "$1" == a ]] && echo 1 || echo 2).2"
}
fail() { echo "FAIL: $*" >&2; exit 1; }
pf_map_add a tcp 192.0.2.10 443 10.1.1.2 8443 eth0
pf_map_add b tcp 192.0.2.11 443 10.1.2.2 8443 eth0
grep -qF 'tcp|192.0.2.10|443|10.1.1.2|8443|eth0' "$INST_DIR/a/map.conf" || fail "map a missing"
grep -qF 'tcp|192.0.2.11|443|10.1.2.2|8443|eth0' "$INST_DIR/b/map.conf" || fail "map b missing"
grep -qF -- '--to-destination 10.1.1.2:8443' "$LOG" || fail "DNAT destination port omitted"
grep -qF -- '-d 192.0.2.11' "$LOG" || fail "public IP match omitted"
grep -qF -- '--to-source 10.1.1.1' "$LOG" || fail "SNAT not interface-specific"
grep -qF -- '-t filter -A' "$LOG" || fail "filter FORWARD ACL missing"
grep -qF -- '--ctorigdst 192.0.2.10 --ctorigdstport 443' "$LOG" ||
    fail "SNAT is not restricted to the original forwarded public tuple"
grep -qF -- '-t nat -I PREROUTING 1 -j OTD_' "$LOG" ||
    fail "new DNAT chain not hooked after staging"
if (pf_map_add b tcp 192.0.2.10 443 10.1.2.2 8443 eth0); then
    fail "same ingress/public IP port collision accepted"
fi
pf_map_del a tcp 192.0.2.10 443 eth0
[[ ! -s "$INST_DIR/a/map.conf" ]] || fail "map a deletion failed"
[[ -s "$INST_DIR/b/map.conf" ]] || fail "deleting a accidentally removed b"
if grep -qE -- ' -F (FORWARD|PREROUTING|POSTROUTING|INPUT)( |$)' "$LOG"; then
    fail "global firewall flush attempted"
fi
# Two administrators race for the same UDP public tuple. Exactly one may win.
(pf_map_add a udp 192.0.2.10 5353 10.1.1.2 5353 eth0) > "$WORK/race-a" 2>&1 &
pid_a=$!
(pf_map_add b udp 192.0.2.10 5353 10.1.2.2 5353 eth0) > "$WORK/race-b" 2>&1 &
pid_b=$!
rc_a=0; rc_b=0
wait "$pid_a" || rc_a=$?
wait "$pid_b" || rc_b=$?
if [[ "$rc_a" -eq 0 && "$rc_b" -eq 0 ]] ||
   [[ "$rc_a" -ne 0 && "$rc_b" -ne 0 ]]; then
    fail "concurrent collision not serialized (rc_a=$rc_a rc_b=$rc_b)"
fi
count="$(grep -hEc '^udp\|192\.0\.2\.10\|5353\|' "$INST_DIR/a/map.conf" "$INST_DIR/b/map.conf" |
    awk '{s+=$1} END {print s+0}')"
[[ "$count" -eq 1 ]] || fail "concurrent mapping race created $count copies"
echo "PASS: two IPs on port443, DNAT/SNAT/FORWARD, deletion and concurrent duplicate protection"
