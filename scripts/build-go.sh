#!/usr/bin/env bash
# One release recipe shared by developers and CI. No host-specific Go settings.
set -euo pipefail
cd "$(dirname "$0")/.."
mode="${1:---check}"
[[ "$mode" == --check || "$mode" == --write ]] || { echo 'use --check or --write' >&2; exit 2; }
export GOENV=off GOTOOLCHAIN=local GOFLAGS= GOEXPERIMENT= GOWORK=off
export CGO_ENABLED=0 GOOS=linux GOAMD64=v1 GOARM64=v8.0
[[ "$(go env GOVERSION)" == go1.26.3 ]] || { echo 'release builds require Go 1.26.3' >&2; exit 1; }
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
modules=(omniackless omnistripe)
if [[ -n "${2:-}" ]]; then
    [[ "$2" == omniackless || "$2" == omnistripe ]] || exit 2
    modules=("$2")
fi
for module in "${modules[@]}"; do
    for arch in amd64 arm64; do
        output="$work/$module-$arch"
        (cd "src/$module"; GOARCH="$arch" go build -trimpath -buildvcs=false -o "$output" .)
        if [[ "$mode" == --write ]]; then
            install -m 0755 "$output" "bin/$module-$arch"
        else
            cmp "$output" "bin/$module-$arch"
        fi
        if [[ "$module" == omniackless ]]; then
            grep -aqF '.sendbase.' "bin/$module-$arch"
            grep -aqF 'refusing to start to avoid sequence reuse' "bin/$module-$arch"
        else
            marker="$(sed -nE 's/.*(omnistripe [0-9]+\.[0-9]+\.[0-9]+).*/\1/p' src/omnistripe/main.go)"
            [[ -n "$marker" ]] && grep -aqF "$marker" "bin/$module-$arch"
        fi
        echo "Verified $module-$arch (Go 1.26.3)"
    done
done
