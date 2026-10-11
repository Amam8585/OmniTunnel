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
        "OMNITUN_BIN_DIR=$WORK/bin" bash "$ROOT/install.sh")
    if (( EUID != 0 )); then sudo "${cmd[@]}" "$@"; else "${cmd[@]}" "$@"; fi
}
run --prepare
[[ -e "$WORK/state/staged/current" ]] || fail "prepare pointer missing"
stage="$(cat "$WORK/state/staged/current")"
[[ -x "$stage/bin/omnitun-amd64" || -x "$stage/bin/omnitun-arm64" ]] || fail "real C build failed"
[[ ! -e "$WORK/bin/omnitun" ]] || fail "prepare activated without consent"
