#!/usr/bin/env bash
# OmniTunnel Direct safe installer: stage -> validate -> apply (no service restarts).
set -Eeuo pipefail
umask 022
REPO="${OMNITUN_REPOSITORY:-Amam8585/OmniTunnel}"
REF="${OMNITUN_REF:-main}"
EXPECTED_ARCHIVE_SHA="${OMNITUN_ARCHIVE_SHA256:-}"
SOURCE="${OMNITUN_SOURCE_DIR:-}"
PREFIX="${OMNITUN_PREFIX:-/opt/omnitunnel}"
STATE="${OMNITUN_STATE_DIR:-/var/lib/omnitunnel}"
BIN_DIR="${OMNITUN_BIN_DIR:-/usr/local/bin}"
LINK="$BIN_DIR/omnitunnel"
APADANA_LINK="$BIN_DIR/apadana"
STAGES=$STATE/staged
BACKUPS=$STATE/backups
ACTION=install; YES=0; ACTIVE_OK=0; DRY=0; PURGE=0; DOWNGRADE_OK=0
log() { printf '[apadana] %s\n' "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }
usage() { cat <<'EOF'
Usage: sudo bash install.sh [--prepare|--apply|--update|--check|--backup|--rollback|--uninstall]
       [--allow-active] [--dry-run] [--yes] [--purge-config]
--update/--prepare: compile and stage only. --apply: activate, never restart services.
--allow-active: explicitly allow replacing on-disk binaries while tunnels run.
--allow-downgrade: explicitly permit older/unrelated Git commit lineage
Env: OMNITUN_REF, OMNITUN_REPOSITORY, OMNITUN_SOURCE_DIR
Default remote source: main, resolved to an immutable commit at prepare time.
EOF
}
while (($#)); do
    case "$1" in
        --prepare|--update) ACTION=prepare;;
        --apply) ACTION=apply;;
        --check) ACTION=check;;
        --backup) ACTION=backup;;
        --rollback) ACTION=rollback;;
        --uninstall) ACTION=uninstall;;
        --dry-run) DRY=1;;
        --allow-active) ACTIVE_OK=1;;
        --allow-downgrade) DOWNGRADE_OK=1;;
        --purge-config) PURGE=1;;
        -y|--yes) YES=1;;
        -h|--help) usage; exit 0;;
        *) die "unknown flag $1";;
    esac
    shift
done
[[ "$REPO" =~ ^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$ ]] || die "bad repo"
[[ "$REF" =~ ^[a-zA-Z0-9_./-]+$ ]] || die "bad ref"
case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;;
    *) die "unsupported CPU";;
esac
[[ -f /etc/os-release ]] || die "missing os-release"
. /etc/os-release
case "$ID:$VERSION_ID" in
    ubuntu:22.04|ubuntu:24.04|debian:12|debian:13) ;;
    *) die "unsupported OS $ID $VERSION_ID";;
esac
log "System: $ID $VERSION_ID $ARCH"
active_units() {
    local unit exec_line
    if command -v systemctl >/dev/null 2>&1; then
        while IFS= read -r unit; do
            [[ -n "$unit" ]] || continue
            exec_line="$(systemctl show --property=ExecStart --value "$unit" 2>/dev/null || true)"
            # Detect names AND binaries: legacy omni-icmp79/ic79-direct, custom
            # systemd names with ExecStart omnitun or icmptun, and shared installs.
            if [[ "$unit" =~ ^(omnitun-|icmptun|omni-icmp|ic[0-9]+-direct) ]] ||
               [[ "$exec_line" =~ (omnitun|icmptun|/opt/omnitunnel/|/usr/local/bin/omni) ]]; then
                printf '%s\n' "$unit"
            fi
        done < <(systemctl list-units --all --type=service --state=active --no-legend --no-pager 2>/dev/null | awk '$1 ~ /\.service$/ {print $1}')
    fi
    # Units may use a custom name or the process can be launched outside systemd.
    # Inspect actual executable paths, not shell process arguments.
    local proc exe
    for proc in /proc/[0-9]*/exe; do
        [[ -L "$proc" ]] || continue
        exe="$(readlink "$proc" 2>/dev/null || true)"
        case "$exe" in
            "$BIN_DIR/omnitun"|"$BIN_DIR/icmptun"|"$PREFIX/"*|/usr/local/bin/omnitun|/usr/local/bin/icmptun)
                local pid="${proc#/proc/}"
                printf 'PID:%s [%s]\n' "${pid%/exe}" "$exe";;
        esac
    done
}
bin_changed() { [[ -n "$1" && "$1" != "$2" ]]; }
root() { [[ $EUID -eq 0 ]] || die "run as root"; }
deps() {
    local missing=0 c
    for c in gcc curl tar gzip ip iptables python3 ssh sshpass openssl nc sha256sum; do
        command -v "$c" >/dev/null 2>&1 || missing=1
    done
    printf '#include <stdio.h>\nint main(void){return 0;}\n' |
        gcc -x c -fsyntax-only - >/dev/null 2>&1 || missing=1
    ((missing==0)) && return 0
    log "Installing missing build/network prerequisites"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update || die "apt update failed"
    apt-get install -y --no-install-recommends build-essential libc6-dev linux-libc-dev \
        ca-certificates curl tar gzip iproute2 iptables python3 openssh-client sshpass openssl netcat-openbsd ||
        die "dependency installation failed"
    printf '#include <stdio.h>\nint main(void){return 0;}\n' |
        gcc -x c -fsyntax-only - >/dev/null || die "stdio.h headers unavailable after installation"
}
check_tun() {
    [[ -c /dev/net/tun ]] && return
    command -v modprobe >/dev/null && modprobe tun 2>/dev/null || true
    [[ -c /dev/net/tun ]] || die "TUN unavailable: enable /dev/net/tun in host/kernel"
}
# Snapshots record absence as well as presence, including new installs.
snapshot() {
    mkdir -p "$BACKUPS" "$PREFIX"
    local dir="$BACKUPS/$(date -u +%Y%m%dT%H%M%SZ)-${BASHPID}" n src
    mkdir -p "$dir"
    : > "$dir/.inventory"
    for n in omnitunnel.sh omnitun hysteria omnistripe omniackless; do
        src="$BIN_DIR/$n"
        [[ "$n" == omnitunnel.sh ]] && src="$PREFIX/omnitunnel.sh"
        if [[ -f "$src" ]]; then cp -a "$src" "$dir/$n"
        else printf 'ABSENT:%s\n' "$n" >> "$dir/.inventory"; fi
    done
    for n in scripts docs bin; do
        if [[ -d "$PREFIX/$n" ]]; then cp -a "$PREFIX/$n" "$dir/$n"
        else printf 'ABSENT:%s\n' "$n" >> "$dir/.inventory"; fi
    done
    for n in README.md LICENSE CHANGELOG.md build-info.json; do
        if [[ -f "$PREFIX/$n" ]]; then cp -a "$PREFIX/$n" "$dir/$n"
        else printf 'ABSENT:%s\n' "$n" >> "$dir/.inventory"; fi
    done
    if [[ -L "$APADANA_LINK" ]]; then cp -a --no-dereference "$APADANA_LINK" "$dir/apadana-link"
    else printf 'ABSENT:apadana-link\n' >> "$dir/.inventory"; fi
    if [[ -L "$LINK" ]]; then cp -a --no-dereference "$LINK" "$dir/link"
    else printf 'ABSENT:link\n' >> "$dir/.inventory"; fi
    printf '%s\n' "$dir" > "$BACKUPS/.latest.new"
    mv -f "$BACKUPS/.latest.new" "$BACKUPS/.latest"
    log "Snapshot: $dir"
}
rollback_snapshot() {
    local dir="$1" n dest
    [[ "$dir" == "$BACKUPS/"* && -d "$dir" && -f "$dir/.inventory" ]] ||
        die "invalid snapshot/inventory"
    mkdir -p "$BIN_DIR" "$PREFIX"
    for n in omnitunnel.sh omnitun hysteria omnistripe omniackless; do
        dest="$BIN_DIR/$n"
        [[ "$n" == omnitunnel.sh ]] && dest="$PREFIX/omnitunnel.sh"
        if [[ -f "$dir/$n" ]]; then
            install -m 0755 "$dir/$n" "$dest.revert.${BASHPID}"
            mv -f "$dest.revert.${BASHPID}" "$dest"
        elif grep -qx "ABSENT:$n" "$dir/.inventory"; then rm -f "$dest"; fi
    done
    for n in scripts docs bin; do
        if [[ -d "$dir/$n" ]]; then
            rm -rf "$PREFIX/$n"; cp -a "$dir/$n" "$PREFIX/$n"
        elif grep -qx "ABSENT:$n" "$dir/.inventory"; then rm -rf "$PREFIX/$n"; fi
    done
    for n in README.md LICENSE CHANGELOG.md build-info.json; do
        if [[ -f "$dir/$n" ]]; then cp -a "$dir/$n" "$PREFIX/$n"
        elif grep -qx "ABSENT:$n" "$dir/.inventory"; then rm -f "$PREFIX/$n"; fi
    done
    if [[ -L "$dir/apadana-link" ]]; then ln -sfn "$(readlink "$dir/apadana-link")" "$APADANA_LINK"
    elif grep -qx 'ABSENT:apadana-link' "$dir/.inventory"; then rm -f "$APADANA_LINK"; fi
    if [[ -L "$dir/link" ]]; then ln -sfn "$(readlink "$dir/link")" "$LINK"
    elif grep -qx 'ABSENT:link' "$dir/.inventory"; then rm -f "$LINK"; fi
    log "Snapshot restored: $dir; no running services restarted."
}
rollback() {
    [[ -f "$BACKUPS/.latest" ]] || die "no snapshot"
    rollback_snapshot "$(cat "$BACKUPS/.latest")"
}
prepare() {
    mkdir -p "$STAGES"
    local work stage archive n commit="" archive_sha=""
    work="$(mktemp -d "$STAGES/.build.XXXXXX")"
    mkdir -p "$work/source" "$work/release/bin"
    if [[ -z "$SOURCE" && -f "$(dirname "${BASH_SOURCE[0]}")/src/main.c" ]]; then
        SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    fi
    if [[ -n "$SOURCE" ]]; then
        [[ -f "$SOURCE/src/main.c" ]] || die "invalid source dir $SOURCE"
        cp -a "$SOURCE/." "$work/source/"
        if [[ -n "${OMNITUN_SOURCE_COMMIT:-}" ]]; then
            commit="$OMNITUN_SOURCE_COMMIT"
        elif command -v git >/dev/null && [[ -d "$SOURCE/.git" ]]; then
            commit="$(git -C "$SOURCE" rev-parse HEAD 2>/dev/null || true)"
        fi
    else
        archive="$work/repo.tar.gz"
        # Resolve mutable branch/tag to one immutable commit BEFORE downloading.
        # If GitHub cannot verify the commit, fail closed rather than mixing versions.
        commit="$(curl -fsSL --retry 2 "https://api.github.com/repos/$REPO/commits/$REF" |
                  python3 -c 'import json,sys; print(json.load(sys.stdin)["sha"])')" ||
            die "unable to resolve source revision"
        [[ "$commit" =~ ^[a-fA-F0-9]{40}$ ]] || die "GitHub returned invalid revision"
        curl -fSL --retry 3 --connect-timeout 15 \
            "https://codeload.github.com/$REPO/tar.gz/$commit" -o "$archive" ||
            die "source download failed"
        archive_sha="$(sha256sum "$archive" | awk '{print $1}')"
        if [[ -n "$EXPECTED_ARCHIVE_SHA" && "$archive_sha" != "$EXPECTED_ARCHIVE_SHA" ]]; then
            die "archive SHA256 mismatch"
        fi
        tar -xzf "$archive" -C "$work/source" --strip-components=1 ||
            die "archive extraction failed"
    fi
    [[ -z "$commit" || "$commit" =~ ^[a-fA-F0-9]{40}$ ]] || die "invalid commit"
    [[ -z "$EXPECTED_ARCHIVE_SHA" || -n "$archive_sha" ]] ||
        die "archive SHA validation requires remote archive source"
    local src="$work/source" out="$work/release"
    bash -n "$src/omnitunnel.sh" || die "invalid manager script"
    local files=(main.c obsctun.c obsctcp.c obscmux.c obscws.c icmptun.c monocypher.c) args=()
    for n in "${files[@]}"; do
        [[ -f "$src/src/$n" ]] || die "missing src/$n"
        args+=("$src/src/$n")
    done
    log "Compiling all C Direct transports"
    gcc -O2 -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
        -o "$out/bin/omnitun-$ARCH" "${args[@]}" -pthread ||
        die "core compilation failed; installed version unchanged"
    "$out/bin/omnitun-$ARCH" version | grep -q '^omnitun ' ||
        die "compiled core validation failed"
    install -m 0755 "$src/omnitunnel.sh" "$out/omnitunnel.sh"
    mkdir -p "$out/scripts" "$out/docs"
    for n in monitor.sh optimizer.sh diagnostics.sh hysteria_audit.sh; do
        [[ -r "$src/scripts/$n" ]] || die "required Direct management script missing: scripts/$n"
        bash -n "$src/scripts/$n" || die "script syntax failed: $n"
        install -m 0755 "$src/scripts/$n" "$out/scripts/$n"
    done
    [[ -f "$src/scripts/monitor_legacy.py" ]] || die "missing legacy metrics helper"
    python3 - "$src/scripts/monitor_legacy.py" <<'PY' || die "legacy monitor has Python syntax errors"
import ast,sys
ast.parse(open(sys.argv[1], encoding="utf-8").read())
PY
    install -m 0644 "$src/scripts/monitor_legacy.py" "$out/scripts/monitor_legacy.py"
    if [[ -d "$src/docs" ]]; then cp -a "$src/docs/." "$out/docs/"; fi
    [[ ! -f "$src/README.md" ]] || cp -a "$src/README.md" "$out/README.md"
    [[ ! -f "$src/LICENSE" ]] || cp -a "$src/LICENSE" "$out/LICENSE"
    [[ ! -f "$src/CHANGELOG.md" ]] || cp -a "$src/CHANGELOG.md" "$out/CHANGELOG.md"
    # Retain Go Direct transports and Hysteria; no Chisel reverse engine.
    for n in hysteria omnistripe omniackless; do
        [[ -s "$src/bin/$n-$ARCH" ]] || die "missing Direct binary $n-$ARCH"
        install -m 0755 "$src/bin/$n-$ARCH" "$out/bin/$n-$ARCH"
    done
    local source_sha binary_sha options compiler
    source_sha="$(cd "$src" && find src -type f -print0 | LC_ALL=C sort -z |
                xargs -0 sha256sum | sha256sum | awk '{print $1}')"
    binary_sha="$(sha256sum "$out/bin/omnitun-$ARCH" | awk '{print $1}')"
    compiler="$(gcc --version | head -1)"
    options="-O2 -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2 -pthread"
    OMNI_COMMIT="$commit" OMNI_ARCHIVE_SHA="$archive_sha" OMNI_SOURCE_SHA="$source_sha" \
    OMNI_BINARY_SHA="$binary_sha" OMNI_COMPILER="$compiler" OMNI_OPTIONS="$options" \
    OMNI_VERSION="$("$out/bin/omnitun-$ARCH" version)" python3 - "$out/build-info.json" <<'PY'
import json, os, sys
keys = {"commit":"OMNI_COMMIT","archive_sha256":"OMNI_ARCHIVE_SHA",
        "source_sha256":"OMNI_SOURCE_SHA", "binary_sha256":"OMNI_BINARY_SHA",
        "compiler":"OMNI_COMPILER","build_flags":"OMNI_OPTIONS","version":"OMNI_VERSION"}
with open(sys.argv[1], "w", encoding="utf-8") as stream:
    json.dump({k:os.environ[e] for k,e in keys.items()}, stream, sort_keys=True, indent=2)
PY
    # Include a deterministic per-artifact inventory (SHA256 is corruption
    # detection; pin the reviewed commit / verify provenance separately).
    python3 - "$out" <<'PY'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
manifest = root/"build-info.json"
metadata = json.loads(manifest.read_text())
metadata["artifacts"] = {str(f.relative_to(root)): hashlib.sha256(f.read_bytes()).hexdigest()
                        for f in sorted(root.rglob("*")) if f.is_file() and f != manifest}
manifest.write_text(json.dumps(metadata,sort_keys=True,indent=2))
PY
    stage="$STAGES/release-$(date -u +%Y%m%dT%H%M%SZ)-${BASHPID}"
    mv "$out" "$stage"; rm -rf "$work"
    printf '%s\n' "$stage" > "$STAGES/current.new"
    mv -f "$STAGES/current.new" "$STAGES/current"
    log "Validated, staged: $stage"
}
validate_stage() {
    local stage="$1" n
    [[ "$stage" == "$STAGES/release-"* && -d "$stage" && ! -L "$stage" ]] || die "invalid stage"
    [[ -r "$stage/build-info.json" ]] || die "missing build metadata"
    for n in omnitun hysteria omnistripe omniackless; do
        [[ -x "$stage/bin/$n-$ARCH" ]] || die "missing staged engine $n"
    done
    bash -n "$stage/omnitunnel.sh" || die "invalid staged manager"
    for n in monitor.sh optimizer.sh diagnostics.sh hysteria_audit.sh; do
        [[ -r "$stage/scripts/$n" ]] && bash -n "$stage/scripts/$n" ||
            die "invalid staged tool $n"
    done
    python3 - "$stage" <<'PY' || die "staged SHA256 verification failed"
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1])
meta=json.loads((root/"build-info.json").read_text())
assert isinstance(meta.get("artifacts"),dict) and len(meta["artifacts"])>=7
for key, expected in meta["artifacts"].items():
    f=root/key
    assert f.is_file() and not f.is_symlink(),key
    assert f.resolve().is_relative_to(root.resolve()),key
    assert hashlib.sha256(f.read_bytes()).hexdigest()==expected,key
print("Stage artifact SHA256 checks passed:",len(meta["artifacts"]))
PY
    "$stage/bin/omnitun-$ARCH" version | grep -q '^omnitun ' ||
        die "staged engine version failed"
}
prevent_downgrade() {
    ((DOWNGRADE_OK)) && return 0
    [[ -r "$PREFIX/build-info.json" ]] || return 0
    local old new status
    old="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("commit",""))' "$PREFIX/build-info.json")"
    new="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("commit",""))' "$1/build-info.json")"
    if [[ "$old" == "$new" && -n "$old" ]]; then return 0; fi
    # A local source dir may lack .git metadata: never silently replace a
    # DIFFERENT binary when neither side has a traceable Git commit.
    if [[ -z "$old" && -z "$new" ]]; then
        # No Git metadata: only allow strict byte-identical repeated installs.
        # A changed manager, Go engine or helper is also a potential downgrade.
        if python3 - "$PREFIX/build-info.json" "$1/build-info.json" <<'PY'
import json, sys
with open(sys.argv[1],encoding="utf-8") as f:
    previous=json.load(f)
with open(sys.argv[2],encoding="utf-8") as f:
    staged=json.load(f)
keys=("source_sha256","binary_sha256","artifacts")
if any(not previous.get(key) or previous.get(key)!=staged.get(key) for key in keys):
    sys.exit(1)
PY
        then return 0; fi
        die "unknown Git revision and changed artifact: pin an immutable commit or explicitly approve --allow-downgrade"
    fi
    [[ "$old" =~ ^[a-fA-F0-9]{40}$ && "$new" =~ ^[a-fA-F0-9]{40}$ ]] ||
        die "unknown update lineage; --allow-downgrade requires manual verification"
    status="$(curl -fsSL "https://api.github.com/repos/$REPO/compare/$old...$new" |
        python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])')" ||
        die "cannot confirm commit ancestry"
    [[ "$status" == ahead || "$status" == identical ]] ||
        die "older/unrelated commit candidate ($status) refused"
}
apply() {
    [[ -f "$STAGES/current" ]] || die "run --prepare first"
    local stage active n prev
    stage="$(cat "$STAGES/current")"
    validate_stage "$stage"
    prevent_downgrade "$stage"
    active="$(active_units)"
    [[ -z "$active" || $ACTIVE_OK -eq 1 ]] ||
        die "active tunnels detected: $active. --allow-active required; NO restarts performed"
    [[ ! -e "$LINK" || -L "$LINK" ]] || die "refusing to overwrite unowned $LINK"
    [[ ! -e "$APADANA_LINK" || -L "$APADANA_LINK" ]] || die "refusing to overwrite unowned $APADANA_LINK"
    ((DRY==0)) || { log "dry-run: stage checks passed; no writes"; return 0; }
    mkdir -p "$PREFIX" "$BIN_DIR"
    snapshot
    prev="$(cat "$BACKUPS/.latest")"
    # Checked actions; each rename is atomic within one filesystem.
    # Multi-file replacement cannot be globally atomic; rollback on failure.
    if (
        for n in omnitun hysteria omnistripe omniackless; do
            install -m 0755 "$stage/bin/$n-$ARCH" "$BIN_DIR/$n.new.${BASHPID}" || exit 1
            mv -f "$BIN_DIR/$n.new.${BASHPID}" "$BIN_DIR/$n" || exit 1
            [[ "$PREFIX" == /opt/omnitunnel || "${OMNITUN_TEST_FAIL_AFTER:-}" != after-binary ]] || exit 79
        done
        mkdir -p "$PREFIX/scripts" "$PREFIX/docs" "$PREFIX/bin" || exit 1
        for n in monitor.sh optimizer.sh diagnostics.sh hysteria_audit.sh; do
            install -m 0755 "$stage/scripts/$n" "$PREFIX/scripts/$n.new.${BASHPID}" || exit 1
            mv -f "$PREFIX/scripts/$n.new.${BASHPID}" "$PREFIX/scripts/$n" || exit 1
        done
        cp -a "$stage/scripts/monitor_legacy.py" "$PREFIX/scripts/monitor_legacy.py" || exit 1
        cp -a "$stage/docs/." "$PREFIX/docs/" || exit 1
        cp -a "$stage/bin/." "$PREFIX/bin/" || exit 1
        for n in README.md LICENSE CHANGELOG.md; do
            [[ ! -f "$stage/$n" ]] || cp -a "$stage/$n" "$PREFIX/$n" || exit 1
        done
        install -m 0755 "$stage/omnitunnel.sh" "$PREFIX/omnitunnel.sh.new.${BASHPID}" || exit 1
        mv -f "$PREFIX/omnitunnel.sh.new.${BASHPID}" "$PREFIX/omnitunnel.sh" || exit 1
        [[ "$PREFIX" == /opt/omnitunnel || "${OMNITUN_TEST_FAIL_AFTER:-}" != after-manager ]] || exit 79
        cp -a "$stage/build-info.json" "$PREFIX/build-info.json.new.${BASHPID}" || exit 1
        mv -f "$PREFIX/build-info.json.new.${BASHPID}" "$PREFIX/build-info.json" || exit 1
        ln -sfn "$PREFIX/omnitunnel.sh" "$LINK" || exit 1
        ln -sfn "$PREFIX/omnitunnel.sh" "$APADANA_LINK" || exit 1
        if [[ "$PREFIX" != /opt/omnitunnel && "${OMNITUN_TEST_FAIL_AFTER:-}" == partial-write ]]; then
            printf 'partial simulated FS write\n' >> "$PREFIX/omnitunnel.sh"
            exit 79
        fi
        [[ "$PREFIX" == /opt/omnitunnel || "${OMNITUN_TEST_FAIL_AFTER:-}" != after-copy ]] || exit 79
        "$BIN_DIR/omnitun" version | grep -q '^omnitun ' || exit 1
        bash -n "$PREFIX/omnitunnel.sh" || exit 1
        cmp -s "$PREFIX/omnitunnel.sh" "$stage/omnitunnel.sh" || exit 1
        cmp -s "$PREFIX/build-info.json" "$stage/build-info.json" || exit 1
        python3 - "$PREFIX/build-info.json" "$BIN_DIR" "$ARCH" <<'PY' || exit 1
import hashlib,json,pathlib,sys
with open(sys.argv[1],encoding="utf-8") as stream:
    meta=json.load(stream)
root=pathlib.Path(sys.argv[2])
arch=sys.argv[3]
for engine in ("omnitun","hysteria","omnistripe","omniackless"):
    want=meta["artifacts"].get("bin/"+engine+"-"+arch)
    f=root/engine
    assert want and f.is_file()
    assert hashlib.sha256(f.read_bytes()).hexdigest()==want,(engine,"installed digest differs")
print("All installed Direct executable SHA256 values matched their stage")
PY

    ); then
        log "Build installed and verified; running services NOT restarted"
    else
        log "Apply error. Restoring exact previous program inventory"
        rollback_snapshot "$prev" || die "CRITICAL rollback failed: $prev"
        die "Apply failed; snapshot restored"
    fi
    log "Build metadata: $(cat "$PREFIX/build-info.json")"
    log "Active units after applying:"; active_units
}
if [[ "$ACTION" == check ]]; then
    log "Core: $("$BIN_DIR/omnitun" version 2>/dev/null || echo not-installed)"
    if [[ -r "$PREFIX/build-info.json" ]]; then
        log "Installed immutable build manifest:"
        cat "$PREFIX/build-info.json"
    else
        log "No installed build manifest (legacy/unmanaged installation)"
    fi
    log "Active units:"; active_units
    [[ -c /dev/net/tun ]] && log "TUN present" || log "TUN missing"
    exit 0
fi
root
# A single lock covers staging pointer, snapshots, apply, rollback and removal.
# Prevent overlapping installers from racing to replace the same paths.
mkdir -p "$STATE"
command -v flock >/dev/null 2>&1 || die "flock required for safe multi-instance upgrades"
exec {installer_lock}>"$STATE/.installer.lock"
flock -w 60 "$installer_lock" || die "installer busy: another operation holds $STATE/.installer.lock"
case "$ACTION" in
    backup) ((DRY)) && exit 0; snapshot;;
    rollback)
        [[ -z "$(active_units)" || $ACTIVE_OK -eq 1 ]] ||
            die "active instances: rollback needs --allow-active (no restart)"
        ((DRY)) && exit 0; rollback;;
    uninstall)
        [[ -z "$(active_units)" ]] || die "stop all OmniTunnel services explicitly first"
        [[ $PURGE -eq 0 || $YES -eq 1 ]] || die "--purge-config requires --yes"
        ((DRY)) && exit 0
        snapshot
        [[ -L "$LINK" && "$(readlink "$LINK")" == "$PREFIX/omnitunnel.sh" ]] &&
            rm -f "$LINK"
        [[ -L "$APADANA_LINK" && "$(readlink "$APADANA_LINK")" == "$PREFIX/omnitunnel.sh" ]] &&
            rm -f "$APADANA_LINK"
        rm -rf "$PREFIX/scripts" "$PREFIX/docs" "$PREFIX/bin"
        rm -f "$PREFIX/build-info.json" "$PREFIX/README.md" "$PREFIX/CHANGELOG.md" "$PREFIX/LICENSE"
        rm -f "$PREFIX/omnitunnel.sh" "$BIN_DIR/omnitun" \
            "$BIN_DIR/hysteria" "$BIN_DIR/omnistripe" "$BIN_DIR/omniackless"
        ((PURGE==0)) || rm -rf /etc/omnitunnel
        log "APADANA program files removed; instance configs and services preserved unless explicitly purged";;
    prepare)
        ((DRY)) && { log "dry run: would fetch/build/stage"; exit 0; }
        deps; prepare;;
    apply) apply;;
    install)
        if [[ $YES -eq 0 && -t 0 ]]; then
            read -r -p "Compile and install OmniTunnel? [Y/n] " ans
            [[ "${ans:-Y}" != n && "${ans:-Y}" != N ]] || exit 0
        fi
        ((DRY)) && { log "dry run: would compile then safely activate"; exit 0; }
        deps; check_tun; prepare
        if [[ -n "$(active_units)" ]]; then
            log "Active services detected: staged only, no restarts. Apply separately."
        else
            apply
        fi;;
esac
