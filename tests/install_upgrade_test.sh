#!/usr/bin/env bash
set -u

SCRIPT="${1:-$(dirname "$0")/../install.sh}"

eval "$(grep -E '^bin_changed\(\) \{' "$SCRIPT")"

fail() { echo "FAIL: $1" >&2; exit 1; }

type bin_changed >/dev/null 2>&1 || fail "bin_changed guard missing: first upgrade would needlessly restart production tunnels"

bin_changed "" "newsum" && fail "an absent old engine (empty checksum) must NOT count as a change"
bin_changed "same" "same" && fail "an unchanged binary must NOT count as a change"
bin_changed "old" "new" || fail "a genuinely upgraded binary MUST count as a change"

echo "PASSED - install.sh treats an absent old engine as no-change (no first-upgrade bounce)"
