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

eval "$(extract "add_parse")"

fail() { echo "FAIL: $1" >&2; exit 1; }

check() {
    local desc="$1" wantrc="$2" wantauto="$3" wantkn="$4" wantfhost="$5" wantrest="$6"; shift 6
    local rc=0
    add_parse "$@" || rc=$?
    [[ "$rc" -eq "$wantrc" ]] || fail "$desc: rc=$rc want $wantrc"
    [[ "$rc" -ne 0 ]] && return 0
    [[ "$ADD_AUTO" == "$wantauto" ]] || fail "$desc: AUTO='$ADD_AUTO' want '$wantauto'"
    [[ "$ADD_KN" == "$wantkn" ]] || fail "$desc: KN='$ADD_KN' want '$wantkn'"
    [[ "$ADD_FHOST" == "$wantfhost" ]] || fail "$desc: FHOST='$ADD_FHOST' want '$wantfhost'"
    [[ "${ADD_REST[*]-}" == "$wantrest" ]] || fail "$desc: REST='${ADD_REST[*]-}' want '$wantrest'"
}

check "1-arg form auto-derives the name"        0 auto ackless 203.0.113.9 ""                   ackless 203.0.113.9
check "explicit name + foreign"                 0 ""   myname  203.0.113.9 ""                   ackless myname 203.0.113.9
check "dotted name + dotless foreign"           0 ""   my.name host1   ""                   ackless my.name host1
check "name that itself looks like an ip"       0 ""   1.2     203.0.113.9 ""                   ackless 1.2 203.0.113.9
check "explicit name + foreign + nconn/shape/ip" 0 ""  myname  203.0.113.9 "32 90mbit 9.9.9.9"  ackless myname 203.0.113.9 32 90mbit 9.9.9.9
check "two positional are name,foreign (no auto)" 0 "" 203.0.113.9 32      ""                   ackless 203.0.113.9 32
check "too few args fails"                      1 ""   ""      ""      ""                   ackless

echo "PASSED - add_parse: 1 positional arg auto-derives the name; 2+ positional args are always (name, foreign), so a dotted name with a dotless foreign still parses correctly"
