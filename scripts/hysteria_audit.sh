#!/usr/bin/env bash
# Read-only Hysteria audit: never downloads, changes config or touches services.
set -euo pipefail
arch="$(uname -m)"
case "$arch" in x86_64) arch=amd64;; aarch64) arch=arm64;; *) echo "unsupported arch" >&2; exit 2;; esac
bin="${OMNITUN_HYSTERIA_BIN:-/usr/local/bin/hysteria}"
manifest="${OMNITUN_MANIFEST:-/opt/omnitunnel/build-info.json}"
[[ -x "$bin" ]] || { echo "Hysteria binary unavailable: $bin" >&2; exit 1; }
echo "Direct Hysteria executable: $bin"
sha="$(sha256sum "$bin" | awk '{print $1}')"
echo "SHA256: $sha"
echo "Executable-reported version:"
timeout 8 "$bin" version 2>&1 || echo "version probe failed"
if [[ -r "$manifest" ]]; then
    python3 - "$manifest" "$sha" "$arch" <<'PY'
import json,sys
with open(sys.argv[1],encoding="utf-8") as stream:
    data=json.load(stream)
expected=data.get("artifacts",{}).get("bin/hysteria-"+sys.argv[3])
print("Build commit:",data.get("commit") or "UNKNOWN")
if not expected:
    print("Manifest Hysteria SHA256: UNKNOWN")
    sys.exit(2)
print("Staged checksum:",expected)
if expected!=sys.argv[2]:
    print("WARNING: installed Hysteria differs from manifest")
    sys.exit(3)
print("PASS: local build-artifact integrity (NOT official upstream signature)")
PY
else
    echo "No local manifest: Hysteria version and provenance remain UNVERIFIED"
fi
echo "Official release provenance requires independent verification."
