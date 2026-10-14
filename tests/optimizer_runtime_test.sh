#!/usr/bin/env bash
# Executes status, analyze, recommendation and reversible queue changes with mock ip.
# Neither host routes nor host sysctls are modified.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$(mktemp -d)"
trap 'rm -rf "$DIR"' EXIT
mkdir -p "$DIR/config/inst/lab" "$DIR/stubs" "$DIR/state"
printf 'TYPE=icmp\nDEV=ts-lab\n' > "$DIR/config/inst/lab/instance.conf"
echo 1024 > "$DIR/current_qlen"
cat > "$DIR/stubs/ip" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == link && "$2" == set ]]; then
    echo "$6" > "$TEST_QLEN"
    echo "mutation" >> "$TEST_WRITES"
elif [[ "$1" == -o && "$2" == link ]]; then
    echo "2: ts-lab: <UP> mtu 1400 qdisc fq_codel state UP mode DEFAULT qlen $(cat "$TEST_QLEN")"
elif [[ "$1" == link && "$2" == show ]]; then
    echo "2: ts-lab: <UP> mtu 1400 qlen $(cat "$TEST_QLEN")"
elif [[ "$1" == -s || "$1" == -d ]]; then
    echo "2: ts-lab: <UP> mtu 1400 qlen $(cat "$TEST_QLEN")"
else
    echo "unexpected ip args: $*" >&2; exit 1
fi
SH
chmod +x "$DIR/stubs/ip"
# The integration must not query the runner's real network interface via tc.
cat > "$DIR/stubs/tc" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == 'qdisc show dev ts-lab' ]] || { echo "unexpected tc args: $*" >&2; exit 1; }
if [[ "${TEST_TC_FAIL:-0}" == 1 ]]; then exit 2; fi
printf 'qdisc fq_codel 0: dev ts-lab root\n'
SH
chmod +x "$DIR/stubs/tc"
export TEST_QLEN="$DIR/current_qlen" TEST_WRITES="$DIR/writes"
export OMNITUN_CONFIG_ROOT="$DIR/config" OMNITUN_OPTIMIZER_STATE_DIR="$DIR/state"
export PATH="$DIR/stubs:$PATH"
run() { bash "$ROOT/scripts/optimizer.sh" "$@"; }
die() { echo "FAIL optimizer runtime: $*" >&2; exit 1; }
run status lab > "$DIR/status"
grep -qF 'Interface details and MTU:' "$DIR/status" || die "broken literal newline in status"
run analyze lab > "$DIR/analyze"
run recommend lab low-latency > "$DIR/recommend"
grep -q 'P95/P99' "$DIR/recommend" || die "no validation/latency caution"
if grep -qF 'Auto-adaptive is observation-only' "$DIR/recommend"; then
    die "auto-adaptive warning printed for low-latency profile"
fi
run recommend lab auto-adaptive > "$DIR/auto"
grep -qF 'Auto-adaptive is observation-only' "$DIR/auto" ||
    die "missing auto-adaptive warning"
TEST_TC_FAIL=1 run status lab > "$DIR/failed-tc"
grep -qF 'qdisc details unavailable' "$DIR/failed-tc" ||
    die "optional tc failure incorrectly kills diagnostics"
run dry-run lab high-throughput > "$DIR/dry"
run compare lab > "$DIR/compare"
[[ "$(cat "$TEST_QLEN")" == 1024 ]] || die "read actions mutated queue"
[[ ! -e "$TEST_WRITES" ]] || die "read actions wrote ip state"
if ((EUID == 0)); then
    run apply lab balanced --acknowledge > "$DIR/noop"
    [[ ! -f "$DIR/state/lab.last" ]] || die "no-op profile created a snapshot"
    run apply lab low-latency --acknowledge > "$DIR/apply"
    [[ "$(cat "$TEST_QLEN")" == 512 ]] || die "owned qlen apply failed"
    run rollback lab > "$DIR/rollback"
    [[ "$(cat "$TEST_QLEN")" == 1024 ]] || die "rollback failed"
fi
echo "PASS: optimizer status/analyze/recommend/dry-run/compare and guarded apply/rollback"
