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

eval "$(extract "peer_require_absent peer_name_absent")"

fail() { echo "FAIL: $1" >&2; exit 1; }

D="$(mktemp -d)"
trap 'rm -rf "$D"' EXIT
FAKE_ROOT="$D/foreign"; mkdir -p "$FAKE_ROOT/inst"

peer_ssh() { shift; local cmd="$*"; cmd="${cmd//\/etc\/omnitunnel/$FAKE_ROOT}"; eval "$cmd"; }
die() { echo "DIE: $*" >&2; exit 9; }

rc=0
( peer_require_absent 203.0.113.9 ackless ) >/dev/null 2>&1 || rc=$?
[[ "$rc" -eq 0 ]] || fail "absent: a name confirmed ABSENT on the foreign must proceed (rc=$rc)"

mkdir -p "$FAKE_ROOT/inst/ackless"; : > "$FAKE_ROOT/inst/ackless/instance.conf"
before="$(ls -1 "$FAKE_ROOT/inst" | sort | tr '\n' ' ')"
out="$( ( peer_require_absent 203.0.113.9 ackless ) 2>&1 )"; rc=$?
[[ "$rc" -ne 0 ]] || fail "collision: a name that already exists on the foreign must die loudly (rc=$rc)"
echo "$out" | grep -q "already exists" || fail "collision: must fail loudly with an 'already exists' message, got: $out"
after="$(ls -1 "$FAKE_ROOT/inst" | sort | tr '\n' ' ')"
[[ "$before" == "$after" ]] || fail "collision: the read-only check must not create or remove remote state (before=[$before] after=[$after])"

rc=0
( peer_ssh() { return 255; }; peer_require_absent 203.0.113.9 ackless ) >/dev/null 2>&1 || rc=$?
[[ "$rc" -ne 0 ]] || fail "ssh-error: an SSH/transport error (exit 255) must fail closed (die), never provision on an unverified name (rc=$rc)"

rc=0
( peer_ssh() { printf 'garbage-no-sentinel\n'; }; peer_require_absent 203.0.113.9 ackless ) >/dev/null 2>&1 || rc=$?
[[ "$rc" -ne 0 ]] || fail "inconclusive: an inconclusive remote check must fail closed, never treat the name as free (rc=$rc)"

rc=0
( peer_ssh() { printf 'ERROR OMNIABSENT\n'; }; peer_require_absent 203.0.113.9 ackless ) >/dev/null 2>&1 || rc=$?
[[ "$rc" -ne 0 ]] || fail "non-exact: output that merely CONTAINS a sentinel (ERROR OMNIABSENT) must be inconclusive and die closed, never proceed (rc=$rc)"

echo "PASSED - read-only foreign existence check: ABSENT proceeds; an existing name fails loudly with no remote state created/removed; SSH error / inconclusive output fails closed (never provisions on an unverified name)"
