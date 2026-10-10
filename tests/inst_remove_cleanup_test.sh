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

eval "$(extract "inst_cleanup_residue")"

fail() { echo "FAIL: $1" >&2; exit 1; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
BIN="$WORK/bin"; mkdir -p "$BIN"
VARLIB_DIR="$WORK/varlib"; mkdir -p "$VARLIB_DIR"
export IPT_DB="$WORK/ipt.db"; : > "$IPT_DB"

cat > "$BIN/iptables" <<'FAKE'
#!/usr/bin/env bash
set -u
db="${IPT_DB:?}"
action=""; rest=()
i=1
args=("$@")
while [ $i -le ${#args[@]} ]; do
    a="${args[$((i-1))]}"
    case "$a" in
        -t) i=$((i+1));;
        -A|-D|-C) action="$a";;
        *) rest+=("$a");;
    esac
    i=$((i+1))
done
key="${rest[*]}"
case "$action" in
    -A) echo "$key" >> "$db"; exit 0;;
    -C) grep -qxF "$key" "$db" 2>/dev/null && exit 0 || exit 1;;
    -D) if grep -qxF "$key" "$db" 2>/dev/null; then
            awk -v k="$key" 'BEGIN{d=0}{ if(!d && $0==k){d=1; next} print }' "$db" > "$db.t" && mv "$db.t" "$db"
            exit 0
        fi
        exit 1;;
esac
exit 0
FAKE
chmod +x "$BIN/iptables"
PATH="$BIN:$PATH"

DEV=ts-rmv; SDEV=ts_rmv
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -o "$DEV" -j TCPMSS --clamp-mss-to-pmtu
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -i "$DEV" -j TCPMSS --clamp-mss-to-pmtu
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -o ts-other -j TCPMSS --clamp-mss-to-pmtu

: > "$VARLIB_DIR/stripe-$SDEV.floor"
: > "$VARLIB_DIR/ackless_$SDEV.floor"
: > "$VARLIB_DIR/ackless_$SDEV.sendbase.0"
: > "$VARLIB_DIR/ackless_$SDEV.sendbase.1"
: > "$VARLIB_DIR/ackless_ts_other.floor"

inst_cleanup_residue "$DEV"

grep -q "$DEV" "$IPT_DB" && fail "mangle FORWARD rules for $DEV were left behind: $(grep "$DEV" "$IPT_DB")"
grep -q "ts-other" "$IPT_DB" || fail "cleanup wrongly removed an unrelated device's clamp rule"
[[ ! -e "$VARLIB_DIR/stripe-$SDEV.floor" ]] || fail "stripe floor left behind"
[[ ! -e "$VARLIB_DIR/ackless_$SDEV.floor" ]] || fail "ackless floor left behind"
[[ -z "$(ls "$VARLIB_DIR"/ackless_$SDEV.sendbase.* 2>/dev/null)" ]] || fail "ackless sendbase files left behind"
[[ -e "$VARLIB_DIR/ackless_ts_other.floor" ]] || fail "cleanup wrongly removed an unrelated device's floor file"

echo "PASSED - inst_remove cleanup drops both clamp rules + stripe/ackless floor + ackless sendbase for the device, and leaves unrelated devices intact"
