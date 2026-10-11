#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ctl="$root/icmptun-ctl.sh"
# This regression runs without root, systemd or any network changes.
if grep -q 'EOF_ICMPTUN_C' "$ctl"; then
    echo "FAIL: embedded legacy ICMP C dataplane still present" >&2; exit 1
fi
if grep -Eq 'gcc .*\\$SRC_FILE|write_source[[:space:]]*$' "$ctl"; then
    echo "FAIL: legacy source compilation still reachable" >&2; exit 1
fi
grep -Fq 'exec "$maintained" icmp "\$@"' "$ctl" || {
    echo "FAIL: legacy argument forwarding missing" >&2; exit 1;
}
grep -Fq 'systemctl is-active --quiet "$SERVICE_NAME"' "$ctl" || {
    echo "FAIL: active service guard missing" >&2; exit 1;
}
grep -Fq 'sha256sum "$maintained"' "$ctl" || {
    echo "FAIL: maintained core checksum missing" >&2; exit 1;
}
bash -n "$ctl"
echo "PASS: legacy embedded engine removed; dispatcher and service guard present"
