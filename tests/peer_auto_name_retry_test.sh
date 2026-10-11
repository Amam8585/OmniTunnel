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

eval "$(extract "peer_free_auto_name auto_name inst_exists inst_conf")"

fail() { echo "FAIL: $1" >&2; exit 1; }

INST_DIR="$(mktemp -d)"
trap 'rm -rf "$INST_DIR"' EXIT

FGN=" ackless2 "
peer_ssh() { printf '%s\n' $FGN; }
peer_has_inst() { case " $FGN " in *" $2 "*) return 0;; *) return 1;; esac; }
die() { echo "DIE: $*" >&2; exit 9; }

mkdir -p "$INST_DIR/ackless" "$INST_DIR/ackless1"
: > "$INST_DIR/ackless/instance.conf"
: > "$INST_DIR/ackless1/instance.conf"

PEER_AUTO_NAME=""
peer_free_auto_name ackless 203.0.113.9 ""
[[ "$PEER_AUTO_NAME" == "ackless3" ]] || fail "cross-host auto-name: with local {ackless,ackless1} and the foreign holding {ackless2}, a stale empty snapshot must refresh the foreign listing and retry to ackless3; got '$PEER_AUTO_NAME'"

rc=0
( peer_has_inst() { return 0; }; peer_ssh() { printf ''; }; peer_free_auto_name ackless 203.0.113.9 "" ) >/dev/null 2>&1 || rc=$?
[[ "$rc" -ne 0 ]] || fail "bounded retry: a foreign that keeps colliding must fail loudly after the retry bound, not loop forever (rc=$rc)"

echo "PASSED - cross-host auto-name refreshes the foreign listing and retries past local {ackless,ackless1} + foreign {ackless2} to ackless3, and fails loudly after a bounded number of retries"
