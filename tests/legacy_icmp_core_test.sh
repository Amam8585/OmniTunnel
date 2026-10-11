#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ctl="$root/icmptun-ctl.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
# Extract the actual function from the checked-out manager; no copied shim.
awk '/^cmd_build\(\) \{/ {copy=1} copy {print} copy && /^\}$/ {exit}' "$ctl" > "$work/build-function.sh"
grep -q '^cmd_build() {' "$work/build-function.sh"
# shellcheck disable=SC1090
source "$work/build-function.sh"
need_root() { :; }
cat > "$work/omnitun" <<'CORE'
#!/usr/bin/env bash
if [[ "${1:-}" == version ]]; then echo 'omnitun test'; exit 0; fi
printf '%s\n' "$@" > "$CAPTURE"
CORE
chmod +x "$work/omnitun"
cat > "$work/systemctl" <<'SYSTEMCTL'
#!/usr/bin/env bash
[[ "${ACTIVE:-0}" == 1 ]]
SYSTEMCTL
chmod +x "$work/systemctl"
export PATH="$work:$PATH" CAPTURE="$work/args" OMNITUN_MAINTAINED_BIN="$work/omnitun"
BIN="$work/legacy"; SERVICE_NAME='icmptun-legacy.service'
cmd_build
"$BIN" -L 10.0.0.1 -R 10.0.0.2 -M 1320
printf '%s\n' icmp -L 10.0.0.1 -R 10.0.0.2 -M 1320 > "$work/expected"
cmp "$work/expected" "$CAPTURE"
printf 'old-version\n' > "$BIN"
export ACTIVE=1
if cmd_build; then echo 'FAIL: active service was overwritten' >&2; exit 1; fi
grep -qx 'old-version' "$BIN"
export ACTIVE=0
cmd_build
grep -qx 'old-version' "${BIN}.previous"
cp -p "${BIN}.previous" "$BIN"
grep -qx 'old-version' "$BIN"
sha256sum -c "${BIN}.core.sha256" >/dev/null
echo 'PASS: actual legacy cmd_build dispatch, arguments, active guard, backup, rollback and checksum'
