#!/usr/bin/env bash
# OmniTunnel Direct safe installer: stage -> validate -> apply (no service restarts).
set -Eeuo pipefail
umask 022
REPO="${OMNITUN_REPOSITORY:-Amam8585/OmniTunnel}"
REF="${OMNITUN_REF:-main}"
SOURCE="${OMNITUN_SOURCE_DIR:-}"
PREFIX=/opt/omnitunnel
STATE=/var/lib/omnitunnel
STAGES=$STATE/staged
BACKUPS=$STATE/backups
ACTION=install; YES=0; ACTIVE_OK=0; DRY=0; PURGE=0
log() { printf '[omnitunnel] %s\n' "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }
usage() { cat <<'EOF'
Usage: sudo bash install.sh [--prepare|--apply|--update|--check|--backup|--rollback|--uninstall]
       [--allow-active] [--dry-run] [--yes] [--purge-config]
--update/--prepare: compile and stage only. --apply: activate, never restart services.
--allow-active: explicitly allow replacing on-disk binaries while tunnels run.
Env: OMNITUN_REF, OMNITUN_REPOSITORY, OMNITUN_SOURCE_DIR
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
    command -v systemctl >/dev/null || return 0
    systemctl list-units --type=service --state=active --no-legend --no-pager 2>/dev/null |
        awk '$1 ~ /^(omnitun-|icmptun)[^ ]*\.service$/ {print $1}' || true
}
bin_changed() { [[ -n "$1" && "$1" != "$2" ]]; }
root() { [[ $EUID -eq 0 ]] || die "run as root"; }
deps() {
    local missing=0 c
    for c in gcc curl tar gzip ip iptables python3; do
        command -v "$c" >/dev/null 2>&1 || missing=1
    done
    printf '#include <stdio.h>\nint main(void){return 0;}\n' |
        gcc -x c -fsyntax-only - >/dev/null 2>&1 || missing=1
    ((missing==0)) && return 0
    log "Installing missing build/network prerequisites"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update || die "apt update failed"
    apt-get install -y --no-install-recommends build-essential libc6-dev linux-libc-dev \
        ca-certificates curl tar gzip iproute2 iptables python3 openssh-client ||
        die "dependency installation failed"
    printf '#include <stdio.h>\nint main(void){return 0;}\n' |
        gcc -x c -fsyntax-only - >/dev/null || die "stdio.h headers unavailable after installation"
}
check_tun() {
    [[ -c /dev/net/tun ]] && return
    command -v modprobe >/dev/null && modprobe tun 2>/dev/null || true
    [[ -c /dev/net/tun ]] || die "TUN unavailable: enable /dev/net/tun in host/kernel"
}
snapshot() {
    mkdir -p "$BACKUPS"
    local dir="$BACKUPS/$(date -u +%Y%m%dT%H%M%SZ)-$$" n src
    mkdir -p "$dir"
    for n in omnitunnel.sh omnitun hysteria omnistripe omniackless; do
        src="/usr/local/bin/$n"
        [[ "$n" == omnitunnel.sh ]] && src="$PREFIX/omnitunnel.sh"
        [[ ! -f "$src" ]] || cp -a "$src" "$dir/$n"
    done
    printf '%s\n' "$dir" > "$BACKUPS/.latest.new"
    mv -f "$BACKUPS/.latest.new" "$BACKUPS/.latest"
    log "Backup saved: $dir"
}
rollback() {
    [[ -f "$BACKUPS/.latest" ]] || die "no snapshot"
    local dir n dst
    dir="$(cat "$BACKUPS/.latest")"
    [[ "$dir" == "$BACKUPS/"* && -d "$dir" ]] || die "invalid snapshot path"
    for n in omnitunnel.sh omnitun hysteria omnistripe omniackless; do
        [[ "$n" == omnitunnel.sh ]] && dst="$PREFIX/omnitunnel.sh" || dst="/usr/local/bin/$n"
        if [[ -f "$dir/$n" ]]; then
            install -m 0755 "$dir/$n" "$dst.new.$$"
            mv -f "$dst.new.$$" "$dst"
        fi
    done
    log "Restored saved files; NO service restart was performed"
}
prepare() {
    mkdir -p "$STAGES"
    local work stage archive n
    work="$(mktemp -d "$STAGES/.build.XXXXXX")"
    mkdir -p "$work/source" "$work/release/bin"
    if [[ -z "$SOURCE" && -f "$(dirname "${BASH_SOURCE[0]}")/src/main.c" ]]; then
        SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    fi
    if [[ -n "$SOURCE" ]]; then
        [[ -f "$SOURCE/src/main.c" ]] || die "invalid source dir $SOURCE"
        cp -a "$SOURCE/." "$work/source/"
    else
        archive="$work/repo.tar.gz"
        curl -fSL --retry 3 --connect-timeout 15 \
            "https://codeload.github.com/$REPO/tar.gz/$REF" -o "$archive" ||
            die "source download failed"
        tar -xzf "$archive" -C "$work/source" --strip-components=1 ||
            die "archive extraction failed"
    fi
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
    # Retain Go Direct transports and Hysteria; no Chisel reverse engine.
    for n in hysteria omnistripe omniackless; do
        [[ -s "$src/bin/$n-$ARCH" ]] || die "missing Direct binary $n-$ARCH"
        install -m 0755 "$src/bin/$n-$ARCH" "$out/bin/$n-$ARCH"
    done
    stage="$STAGES/release-$(date -u +%Y%m%dT%H%M%SZ)-$$"
    mv "$out" "$stage"; rm -rf "$work"
    printf '%s\n' "$stage" > "$STAGES/current.new"
    mv -f "$STAGES/current.new" "$STAGES/current"
    log "Validated, staged: $stage"
}
apply() {
    [[ -f "$STAGES/current" ]] || die "run --prepare first"
    local stage active n
    stage="$(cat "$STAGES/current")"
    [[ "$stage" == "$STAGES/release-"* && -d "$stage" ]] || die "invalid release pointer"
    [[ -x "$stage/bin/omnitun-$ARCH" ]] || die "compiled core missing"
    active="$(active_units)"
    [[ -z "$active" || $ACTIVE_OK -eq 1 ]] ||
        die "active tunnels: $active. Stage left untouched; use --apply --allow-active for a planned activation"
    [[ ! -e /usr/local/bin/omnitunnel || -L /usr/local/bin/omnitunnel ]] ||
        die "omnitunnel command is not a symlink; refusing overwrite"
    ((DRY==0)) || { log "dry run: would activate $stage without restarts"; return; }
    snapshot
    mkdir -p "$PREFIX/bin"
    for n in omnitun hysteria omnistripe omniackless; do
        install -m 0755 "$stage/bin/$n-$ARCH" "/usr/local/bin/$n.new.$$"
        mv -f "/usr/local/bin/$n.new.$$" "/usr/local/bin/$n"
        install -m 0755 "$stage/bin/$n-$ARCH" "$PREFIX/bin/$n-$ARCH"
    done
    install -m 0755 "$stage/omnitunnel.sh" "$PREFIX/omnitunnel.sh.new.$$"
    mv -f "$PREFIX/omnitunnel.sh.new.$$" "$PREFIX/omnitunnel.sh"
    ln -sfn "$PREFIX/omnitunnel.sh" /usr/local/bin/omnitunnel
    /usr/local/bin/omnitun version || die "installed core check failed; use --rollback"
    bash -n "$PREFIX/omnitunnel.sh" || die "installed manager syntax invalid; use --rollback"
    log "Activated programs. Existing tunnels, units, routes, firewall were NOT touched or restarted."
    log "Create a tunnel with: sudo omnitunnel"
}
if [[ "$ACTION" == check ]]; then
    log "Core: $(/usr/local/bin/omnitun version 2>/dev/null || echo not-installed)"
    log "Active units:"; active_units
    [[ -c /dev/net/tun ]] && log "TUN present" || log "TUN missing"
    exit 0
fi
root
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
        [[ -L /usr/local/bin/omnitunnel && "$(readlink /usr/local/bin/omnitunnel)" == "$PREFIX/omnitunnel.sh" ]] &&
            rm -f /usr/local/bin/omnitunnel
        rm -f "$PREFIX/omnitunnel.sh" /usr/local/bin/omnitun \
            /usr/local/bin/hysteria /usr/local/bin/omnistripe /usr/local/bin/omniackless
        ((PURGE==0)) || rm -rf /etc/omnitunnel
        log "Program files removed; unrelated network rules/services untouched";;
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
