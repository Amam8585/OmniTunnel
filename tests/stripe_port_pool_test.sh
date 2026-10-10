#!/usr/bin/env bash
set -u

SCRIPT="${1:-$(dirname "$0")/../omnitunnel.sh}"

extract() {
    awk -v names="$1" '
    BEGIN { n=split(names, a, " "); for (i=1;i<=n;i++) want[a[i]]=1 }
    inblock { print; if ($0 ~ /^}/) inblock=0; next }
    {
        if (match($0, /^[A-Za-z0-9_]+\(\) \{/)) {
            nm=$0; sub(/\(\).*/, "", nm)
            if (nm in want) {
                print
                if ($0 !~ /\}/) inblock=1
            }
        }
    }' "$SCRIPT"
}

eval "$(extract "list_instances inst_conf inst_exists type_port_span occupied_port_ranges remote_port_ranges alloc_port_span alloc_port next_port")"

fail() { echo "FAIL: $1" >&2; exit 1; }

INST_DIR="$(mktemp -d)"
trap 'rm -rf "$INST_DIR"' EXIT
mkdir -p "$INST_DIR/strA"
printf 'TYPE=stripe\nPORT=40000\nPCOUNT=400\n' > "$INST_DIR/strA/instance.conf"

got=$(alloc_port 40001 "" stripe)
(( got >= 40400 )) || fail "a second stripe port landed inside instance 1's pool [40000,40399]: got $got (want >=40400)"

got2=$(alloc_port 40200 "" stripe)
(( got2 >= 40400 )) || fail "stripe candidate inside the pool was not stepped past it: got $got2"

got3=$(alloc_port 40000 "" stripe)
(( got3 >= 40400 )) || fail "stripe starting at the pool base was not stepped past the whole span: got $got3"

mkdir -p "$INST_DIR/plain"
printf 'TYPE=tcp\nPORT=51820\n' > "$INST_DIR/plain/instance.conf"
got4=$(alloc_port 40100 "" stripe)
(( got4 >= 40400 )) || fail "stripe pool collision not detected alongside a plain instance: got $got4"

mkdir -p "$INST_DIR/ackA"
printf 'TYPE=ackless\nPORT=49000\n' > "$INST_DIR/ackA/instance.conf"
got5=$(alloc_port 49001 "" ackless)
(( got5 >= 49100 )) || fail "a second ackless port landed inside instance 1's span [49000,49099]: got $got5 (want >=49100)"
got6=$(alloc_port 49050 "" ackless)
(( got6 >= 49100 )) || fail "ackless candidate inside the span was not stepped past it: got $got6"

REMOTE_DIR="$(mktemp -d)"
INST_DIR="$REMOTE_DIR"
rrng=$(printf 'stripe 41000 400\nackless 42000 100\n' | remote_port_ranges)
gotR=$(alloc_port 41001 "$rrng" stripe)
(( gotR >= 41400 )) || fail "a candidate inside a REMOTE stripe span [41000,41399] was accepted: got $gotR (want >=41400)"
gotR2=$(alloc_port 42050 "$rrng" ackless)
(( gotR2 >= 42100 )) || fail "a candidate inside a REMOTE ackless span [42000,42099] was accepted: got $gotR2 (want >=42100)"
rm -rf "$REMOTE_DIR"

echo "PASSED - allocator reserves and steps past local AND remote stripe/ackless port spans"
