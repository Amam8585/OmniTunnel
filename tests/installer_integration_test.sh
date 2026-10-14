#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin" "$WORK/state" "$WORK/prefix" "$WORK/stubs"
cat > "$WORK/stubs/systemctl" <<'EOS'
#!/usr/bin/env bash
if [[ "$1" == list-units ]]; then cat "$FIXTURE"; exit 0; fi
if [[ "$1" == show && "$*" == *wrapper.service* ]]; then
    echo "ExecStart=/path/to/omnitun icmp"
fi
EOS
chmod +x "$WORK/stubs/systemctl"
export FIXTURE="$WORK/units"
: > "$FIXTURE"
fail() { echo "FAIL: $*" >&2; exit 1; }
run() {
    local cmd=(env "PATH=$WORK/stubs:$PATH" "OMNITUN_SOURCE_DIR=$ROOT"
        "OMNITUN_PREFIX=$WORK/prefix" "OMNITUN_STATE_DIR=$WORK/state"
        "OMNITUN_BIN_DIR=$WORK/bin" "FIXTURE=$FIXTURE" \
        "OMNITUN_TEST_FAIL_AFTER=${OMNITUN_TEST_FAIL_AFTER:-}" bash "$ROOT/install.sh")
    if (( EUID != 0 )); then sudo "${cmd[@]}" "$@"; else "${cmd[@]}" "$@"; fi
}
# A pre-existing shared executable must never become uninstall-owned.
printf '#!/bin/sh\nexit 0\n' > "$WORK/bin/hysteria"
chmod +x "$WORK/bin/hysteria"
run --prepare
[[ -e "$WORK/state/staged/current" ]] || fail "prepare pointer missing"
stage="$(cat "$WORK/state/staged/current")"
[[ -x "$stage/bin/omnitun-amd64" || -x "$stage/bin/omnitun-arm64" ]] || fail "real C build failed"
[[ ! -e "$WORK/bin/omnitun" ]] || fail "prepare activated without consent"
cp "$stage/omnitunnel.sh" "$WORK/orig"
echo '# deliberately corrupted' >> "$stage/omnitunnel.sh"
if run --apply; then fail "corrupt stage accepted"; fi
[[ ! -e "$WORK/bin/omnitun" ]] || fail "bad stage modified installed binary"
cp "$WORK/orig" "$stage/omnitunnel.sh"
cp "$stage/build-info.json" "$WORK/manifest"
python3 - "$stage/build-info.json" <<'PY_BAD'
import json,sys
p=sys.argv[1];v=json.load(open(p));del v['artifacts']['omnitunnel.sh']
with open(p,'w') as f: json.dump(v,f)
PY_BAD
if run --apply; then fail "incomplete artifact inventory accepted"; fi
cp "$WORK/manifest" "$stage/build-info.json"
ln -s /some/other/application "$WORK/bin/apadana"
if run --apply; then fail "foreign command symlink overwritten"; fi
rm "$WORK/bin/apadana"
printf 'omni-icmp79.service loaded active running legacy\nic79-direct.service loaded active running legacy\nwrapper.service loaded active running custom\n' > "$FIXTURE"
if run --apply; then fail "active legacy and custom service not detected"; fi
: > "$FIXTURE"
run --apply
"$WORK/bin/omnitun" version | grep -q '^omnitun ' || fail "wrong binary"
[[ -L "$WORK/bin/omnitunnel" ]] || fail "manager symlink absent"
cmp "$stage/omnitunnel.sh" "$WORK/prefix/omnitunnel.sh" || fail "manager mismatch"
python3 - "$WORK/prefix/build-info.json" <<'PY'
import json,sys
with open(sys.argv[1]) as stream: manifest=json.load(stream)
for key in ("binary_sha256","source_sha256","compiler","build_flags","version","artifacts"):
    assert manifest.get(key), key
PY
h="$(sha256sum "$WORK/bin/omnitun" | cut -d' ' -f1)"
run --prepare
for fault in after-binary after-manager partial-write after-copy; do
    if OMNITUN_TEST_FAIL_AFTER="$fault" run --apply; then
        fail "apply fault injection '$fault' ignored"
    fi
    [[ "$(sha256sum "$WORK/bin/omnitun" | cut -d' ' -f1)" == "$h" ]] ||
        fail "binary rollback failed after $fault"
    cmp -s "$stage/omnitunnel.sh" "$WORK/prefix/omnitunnel.sh" ||
        fail "manager rollback failed after $fault"
done
# A second successful apply must keep verified content and avoid unexplained downgrade.
run --apply
[[ "$(sha256sum "$WORK/bin/omnitun" | cut -d' ' -f1)" == "$h" ]] ||
    fail "repeated installation changed core binary"
run --backup
echo break > "$WORK/bin/omnitun"
run --rollback
[[ "$(sha256sum "$WORK/bin/omnitun" | cut -d' ' -f1)" == "$h" ]] ||
    fail "explicit rollback failed"
printf 'ic80-direct.service loaded active running legacy\n' > "$FIXTURE"
if run --uninstall; then fail "uninstall touched active Direct instance"; fi
: > "$FIXTURE"
echo 'user notes' > "$WORK/prefix/docs/custom.txt"
run --uninstall
# The installer explicitly preserves binaries in the shared BIN_DIR because it
# cannot prove ownership. Removing them would break unrelated applications.
[[ -e "$WORK/bin/omnitun" ]] || fail "uninstall incorrectly removed shared binary"
[[ ! -e "$WORK/bin/omnitunnel" ]] || fail "uninstall left manager symlink"
[[ ! -e "$WORK/prefix/omnitunnel.sh" ]] || fail "uninstall left managed program"
[[ ! -e "$WORK/prefix/build-info.json" ]] || fail "uninstall left build manifest"
echo "PASS: real C prepare/apply/verify, tamper + 4 fault injections, legacy multi-unit guard, repeated apply, auto/manual rollback, safe uninstall"
