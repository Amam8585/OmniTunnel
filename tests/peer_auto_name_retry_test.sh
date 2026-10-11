#!/usr/bin/env bash
set -u

SCRIPT="${1:-$(dirname "$0")/../omnitunnel.sh}"

extract() {
    awk -v names="$1" '
    BEGIN { n=split(names, a, " "); for (i=1;i<=n;i++) want[a[i]]=1 }
    inblock { print; if ($0 ~ /^}/) inblock=0; next }
    {
        if (match($0, /^[A-Za-z0-9_]+\(\)[ \t]*\{/)) {
            nm=$0; sub(/\(\).*/, "", nm)
            if (nm in want) { print; if ($0 !~ /\}/) inblock=1 }
        }
    }' "$SCRIPT"
}

eval "$(extract "peer_reserve_auto_name peer_remote_state auto_name inst_exists inst_conf")"

fail() { echo "FAIL: $1" >&2; exit 1; }

D="$(mktemp -d)"
trap 'rm -rf "$D"' EXIT
INST_DIR="$D/local"; mkdir -p "$INST_DIR"
FAKE_ROOT="$D/foreign"; mkdir -p "$FAKE_ROOT/inst"

peer_ssh() { shift; local cmd="$*"; cmd="${cmd//\/etc\/omnitunnel/$FAKE_ROOT}"; eval "$cmd"; }
die() { echo "DIE: $*" >&2; exit 9; }

N=6
RES="$D/res"; : > "$RES"
for i in $(seq 1 "$N"); do ( peer_reserve_auto_name ackless 203.0.113.9 "" && echo "$PEER_AUTO_NAME" >> "$RES" ) & done
wait
got=$(grep -c . "$RES"); [[ "$got" -eq "$N" ]] || fail "(a) atomic reservation: expected $N successful reservations, got $got"
distinct=$(sort -u "$RES" | grep -c .); [[ "$distinct" -eq "$N" ]] || fail "(a) atomic reservation: names not distinct ($distinct unique of $N) - a name was double-provisioned"
fcount=$(ls -1 "$FAKE_ROOT/inst" | grep -c '^ackless'); [[ "$fcount" -eq "$N" ]] || fail "(a) foreign holds $fcount ackless* reservations, expected $N"

rc=0
( peer_ssh() { return 255; }; peer_reserve_auto_name ackless 203.0.113.9 "" ) >/dev/null 2>&1 || rc=$?
[[ "$rc" -ne 0 ]] || fail "(b) an SSH/transport error (exit 255) must fail closed (die), never provision on an unverified name (rc=$rc)"

rc=0
( peer_ssh() { printf ''; }; peer_reserve_auto_name ackless 203.0.113.9 "" ) >/dev/null 2>&1 || rc=$?
[[ "$rc" -ne 0 ]] || fail "(b) an inconclusive remote check (empty output) must fail closed, never treat the name as free (rc=$rc)"

echo "PASSED - $N concurrent reservers take $N DISTINCT names via the atomic foreign mkdir (no name double-provisioned); an SSH error or inconclusive remote check fails closed instead of provisioning on an unverified name"
