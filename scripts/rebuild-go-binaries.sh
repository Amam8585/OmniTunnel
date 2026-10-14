#!/usr/bin/env bash
# Rebuild reviewed Go transport artifacts exactly as verified by CI.
# Run from any working directory; does not touch active services.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
[[ "$(go version)" == "go version go1.26.3 "* ]] || {
    echo "Required toolchain: go1.26.3 (got: $(go version))" >&2
    exit 1
}
for tool in readelf grep install mktemp; do command -v "$tool" >/dev/null || {
    echo "Required tool missing: $tool" >&2; exit 1
}; done
temp="$(mktemp -d)"
trap 'rm -rf "$temp"' EXIT
for module in omniackless omnistripe; do
    for arch in amd64 arm64; do
        output="$temp/$module-$arch"
        (
            cd "src/$module"
            CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -buildvcs=false -o "$output" .
        )
        [[ -s "$output" ]] || { echo "Empty Go build: $module-$arch" >&2; exit 1; }
        machine="$(readelf -h "$output" | sed -n 's/^[[:space:]]*Machine:[[:space:]]*//p')"
        case "$arch:$machine" in
            amd64:*X86-64*|arm64:*AArch64*) ;;
            *) echo "ELF architecture mismatch for $module-$arch: $machine" >&2; exit 1;;
        esac
        install -m 0755 "$output" "bin/$module-$arch"
        sha256sum "bin/$module-$arch"
    done
done
echo "Rebuilt the 4 Go artifacts with the pinned CI flags and verified ELF architectures."
