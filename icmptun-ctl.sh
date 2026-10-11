#!/bin/bash
# icmptun-ctl.sh - install/manage the ICMPTUN core + TCP/UDP port-forwarding.
#
# Runs the SAME on both tunnel endpoints; role (client/server) and the two
# real IPs are set once via `init`. Deploy this one file to each box, run
# `init` + `start` on each, then use `pf add/del/list` on whichever side
# should expose a public port.
set -euo pipefail

VERSION="1.0.0"
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"

# A box can run more than one independent tunnel at once (e.g. two Iran
# servers both tunneling to the same foreign box, or one Iran server
# tunneling to several foreign boxes) - each such tunnel is an "instance"
# with its own config dir, binary, systemd unit, and iptables chains, so
# they can never step on each other. Select which instance a given
# invocation manages with ICMPTUN_INSTANCE=<name>; unset/empty means the
# original single-tunnel layout (fully backward compatible - an existing
# install never has to move or rename anything to keep working).
INSTANCE="${ICMPTUN_INSTANCE:-}"
SUFFIX=""
CHAIN_SUFFIX=""
if [[ -n "$INSTANCE" ]]; then
    if ! [[ "$INSTANCE" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        echo "instance name may only contain letters/digits/hyphen/underscore: $INSTANCE"
        exit 1
    fi
    SUFFIX="-$INSTANCE"
    CHAIN_SUFFIX="_$(echo "$INSTANCE" | tr '[:lower:]-' '[:upper:]_')"
fi

CONF_DIR="/etc/icmptun${SUFFIX}"
CONF_FILE="$CONF_DIR/icmptun.conf"
PF_FILE="$CONF_DIR/portforwards.conf"
PEER_CONF_FILE="$CONF_DIR/peer_ssh.conf"
SRC_FILE="$CONF_DIR/icmptun.c"
BIN="/usr/local/bin/icmptun${SUFFIX}"
LOG_FILE="/var/log/icmptun${SUFFIX}.log"
SERVICE_FILE="/etc/systemd/system/icmptun${SUFFIX}.service"
SERVICE_NAME="icmptun${SUFFIX}.service"
DNAT_CHAIN="ICMPTUN_DNAT${CHAIN_SUFFIX}"
FWD_CHAIN="ICMPTUN_FWD${CHAIN_SUFFIX}"

# ---------------------------------------------------------------- helpers --

need_root() {
    [[ $EUID -eq 0 ]] || { echo "must be run as root"; exit 1; }
}

load_conf() {
    [[ -f "$CONF_FILE" ]] || { echo "not configured yet."; exit 1; }
    # shellcheck disable=SC1090
    source "$CONF_FILE"
}

# ------------------------------------------------------------- C source ----

# Maintained Direct ICMP engine lives in src/icmptun.c.
# Never regenerate or compile the historical embedded dataplane.
write_source() {
    echo "Legacy embedded ICMP source is retired; use the maintained omnitun core." >&2
    return 1
}


# ------------------------------------------------------------------ init ---

cmd_init() {
    need_root
    # Each instance needs its OWN tun device - two tunnels both on "tun0"
    # would collide. Default the interface name to the instance name when
    # one is set, so a caller that omits -T still gets a unique device.
    local default_tun="tun0"
    [[ -n "$INSTANCE" ]] && default_tun="tun-${INSTANCE}"
    local role="" local_ip="" peer_ip="" ident="4d54" mtu="1400" tun="$default_tun"
    local tun_local="" tun_peer=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --role) role="$2"; shift 2 ;;
            -L) local_ip="$2"; shift 2 ;;
            -R) peer_ip="$2"; shift 2 ;;
            -I) ident="$2"; shift 2 ;;
            -M) mtu="$2"; shift 2 ;;
            -T) tun="$2"; shift 2 ;;
            -A) tun_local="$2"; shift 2 ;;
            -P) tun_peer="$2"; shift 2 ;;
            *) echo "invalid option: $1"; exit 1 ;;
        esac
    done
    [[ "$role" == "client" || "$role" == "server" ]] || { echo "--role must be client or server"; exit 1; }
    [[ -n "$local_ip" && -n "$peer_ip" ]] || { echo "both -L and -R are required"; exit 1; }

    # -A/-P let you pick the tunnel's own point-to-point IPs explicitly -
    # required once more than one tunnel exists on the same box (e.g. one
    # Iran server tunneling to several foreign boxes, or several Iran
    # servers into one foreign box - see ICMPTUN_INSTANCE): each needs
    # its own non-overlapping range. Falls back to the original fixed
    # convention (client=.1, server=.2 on 10.99.0.0/30) when not given,
    # for backward compatibility with a single-tunnel setup.
    if [[ -z "$tun_local" || -z "$tun_peer" ]]; then
        if [[ "$role" == "server" ]]; then tun_local="10.99.0.2"; tun_peer="10.99.0.1"
        else                               tun_local="10.99.0.1"; tun_peer="10.99.0.2"; fi
    fi

    mkdir -p "$CONF_DIR"
    cat > "$CONF_FILE" <<EOF
ROLE=$role
LOCAL_IP=$local_ip
PEER_IP=$peer_ip
IDENT=$ident
MTU=$mtu
TUN_NAME=$tun
TUN_LOCAL=$tun_local
TUN_PEER=$tun_peer
EOF
    touch "$PF_FILE"
    write_source
    echo "config written: $CONF_FILE"
    echo "role=$role local=$local_ip peer=$peer_ip tun=$tun_local<->$tun_peer"
    echo "next: pick 'Enable auto-start' from the menu"
}

# ----------------------------------------------------------------- build ---

cmd_build() {
    need_root
    local maintained="${OMNITUN_MAINTAINED_BIN:-/usr/local/bin/omnitun}"
    [[ -x "$maintained" ]] || { echo "Maintained OmniTunnel core unavailable: $maintained" >&2; return 1; }
    "$maintained" version >/dev/null || { echo "Maintained core version check failed" >&2; return 1; }
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        echo "Refusing to replace active legacy service binary: $SERVICE_NAME" >&2
        return 1
    fi
    local staged
    staged="$(mktemp "${BIN}.new.XXXXXXXX")" || return 1
    if ! install -m 0755 "$maintained" "$staged"; then rm -f "$staged"; return 1; fi
    local previous="${BIN}.previous"
    if [[ -e "$BIN" ]]; then
        cp -p "$BIN" "$previous" || { rm -f "$staged"; return 1; }
    fi
    mv -f "$staged" "$BIN" || { rm -f "$staged"; return 1; }
    sha256sum "$BIN" > "${BIN}.sha256"
    printf 'core=%s\n' "$maintained" > "${BIN}.provenance"
    echo "Installed maintained core at $BIN; existing service configuration was not changed."
}


# ------------------------------------------------------------ nat scaffold -

_ident_hex_upper() {
    # normalizes IDENT to 4 uppercase hex digits, e.g. 4d54 -> 4D54
    printf '%04X' "0x$1"
}

setup_nat_scaffolding() {
    load_conf
    sysctl -w net.ipv4.ip_forward=1 >/dev/null

    iptables -t nat -N "$DNAT_CHAIN" 2>/dev/null || true
    iptables -t nat -C PREROUTING -j "$DNAT_CHAIN" 2>/dev/null || \
        iptables -t nat -A PREROUTING -j "$DNAT_CHAIN"
    iptables -t nat -C POSTROUTING -o "$TUN_NAME" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -o "$TUN_NAME" -j MASQUERADE

    iptables -N "$FWD_CHAIN" 2>/dev/null || true
    iptables -C FORWARD -j "$FWD_CHAIN" 2>/dev/null || \
        iptables -A FORWARD -j "$FWD_CHAIN"
    iptables -C "$FWD_CHAIN" -i "$TUN_NAME" -j ACCEPT 2>/dev/null || \
        iptables -A "$FWD_CHAIN" -i "$TUN_NAME" -j ACCEPT
    iptables -C "$FWD_CHAIN" -o "$TUN_NAME" -j ACCEPT 2>/dev/null || \
        iptables -A "$FWD_CHAIN" -o "$TUN_NAME" -j ACCEPT

    # Suppress the local kernel's own auto-reply to an inbound client
    # envelope (icmp_echo_ignore_all=0 is required for real inner-tunnel
    # pings, but that means the kernel also answers our own outer client
    # packets with a spurious Echo Reply carrying the CLIENT's id - see
    # icmptun.c's decapsulate() comment for why this matters). Harmless to
    # install on both ends: the client never emits an outbound echo-reply
    # with this id in the first place.
    local hex; hex=$(_ident_hex_upper "$IDENT")
    iptables -t raw -C OUTPUT -p icmp --icmp-type echo-reply \
        -m u32 --u32 "24&0xFFFF0000=0x${hex}0000" -j DROP 2>/dev/null || \
        iptables -t raw -A OUTPUT -p icmp --icmp-type echo-reply \
            -m u32 --u32 "24&0xFFFF0000=0x${hex}0000" -j DROP
}

# ----------------------------------------------------------------- start ---

_pgrep_pattern() { echo "$BIN -L $LOCAL_IP -R $PEER_IP"; }

# Tracks the running process by matching its actual command line (pgrep)
# rather than a PID file. A PID file needs external bookkeeping to stay
# correct; a stale one caused a real bug here once already (systemd's
# Type=forking + PIDFile path normalization desynced from this script's
# own view of "is it running", leading to a second instance deleting the
# first one's still-live interface). pgrep has no state to go stale.
_is_running() { pgrep -f "$(_pgrep_pattern)" >/dev/null 2>&1; }

# True once `enable` has installed the unit: from then on, systemd owns
# starting/stopping the actual process (it runs the binary directly, no
# wrapper), and this script's start/stop just delegate to systemctl. This
# is what prevents a manual start/stop from ever running a second,
# independent instance alongside the systemd-managed one - the exact
# collision that once caused a live instance's tun0 to get deleted out
# from under it.
_systemd_owns_it() { systemctl is-enabled "$SERVICE_NAME" >/dev/null 2>&1; }

cmd_start() {
    need_root
    load_conf
    [[ -x "$BIN" ]] || cmd_build

    if _is_running; then
        echo "already running"
        return 0
    fi

    if _systemd_owns_it; then
        systemctl start "$SERVICE_NAME"
        echo "tunnel started (via systemd). role=$ROLE tun=$TUN_LOCAL<->$TUN_PEER"
        return 0
    fi

    ip link del "$TUN_NAME" 2>/dev/null || true

    local sflag=""
    [[ "$ROLE" == "server" ]] && sflag="-s"
    # shellcheck disable=SC2086
    setsid "$BIN" -L "$LOCAL_IP" -R "$PEER_IP" -A "$TUN_LOCAL" -P "$TUN_PEER" \
        -M "$MTU" -I "$IDENT" -T "$TUN_NAME" $sflag \
        >> "$LOG_FILE" 2>&1 < /dev/null &
    disown
    sleep 1

    cmd_postup
    echo "tunnel started. role=$ROLE tun=$TUN_LOCAL<->$TUN_PEER"
}

cmd_stop() {
    need_root
    load_conf 2>/dev/null || true
    if _systemd_owns_it; then
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    fi
    pkill -f "$(_pgrep_pattern)" 2>/dev/null || true
    sleep 0.3
    [[ -n "${TUN_NAME:-}" ]] && ip link del "$TUN_NAME" 2>/dev/null || true
    echo "tunnel stopped"
}

cmd_restart() { cmd_stop; sleep 1; cmd_start; }

# ---------------------------------------------------------------- status ---

_row() { printf "  %-16s %s\n" "$1" "$2"; }

cmd_status() {
    load_conf
    echo "┌─ tunnel ──────────────────────────────────────────────────"
    _row "role"     "$ROLE$([ -n "$INSTANCE" ] && echo "  (instance: $INSTANCE)")"
    _row "local"     "$LOCAL_IP"
    _row "peer"      "$PEER_IP"
    _row "interface" "$TUN_NAME  ($TUN_LOCAL <-> $TUN_PEER)"
    _row "ident/mtu" "0x$IDENT / $MTU"

    local pid
    pid=$(pgrep -f "$(_pgrep_pattern)" | head -1)
    if [[ -n "$pid" ]]; then
        _row "process" "${C_GREEN}running${C_RESET} (pid $pid)"
    else
        _row "process" "${C_RED}stopped${C_RESET}"
    fi
    if systemctl is-enabled "$SERVICE_NAME" >/dev/null 2>&1; then
        _row "systemd" "enabled ($(systemctl is-active "$SERVICE_NAME" 2>/dev/null))"
    fi

    if ip link show "$TUN_NAME" >/dev/null 2>&1; then
        _row "$TUN_NAME" "${C_GREEN}up${C_RESET}"
        if ping -c 3 -W 2 -i 0.3 "$TUN_PEER" >/tmp/.icmptun_ping.$$ 2>&1; then
            loss=$(grep -oP '\d+(?=% packet loss)' /tmp/.icmptun_ping.$$ || true)
            rtt=$(grep -oP 'rtt.*= \K[0-9.]+(?=/)' /tmp/.icmptun_ping.$$ || true)
            local loss_c="$C_GREEN"; [[ "${loss:-100}" != "0" ]] && loss_c="$C_YELLOW"
            _row "ping to peer" "${loss_c}loss=${loss}%${C_RESET}  rtt=${rtt}ms"
        else
            _row "ping to peer" "${C_RED}failed${C_RESET}"
        fi
        rm -f /tmp/.icmptun_ping.$$
    else
        _row "$TUN_NAME" "${C_RED}down${C_RESET}"
    fi
    echo "└───────────────────────────────────────────────────────────"
    echo
    echo "  port forwards:"
    pf_list | sed 's/^/  /'
}

# Applied after the binary is confirmed up (tcp_reordering + NAT/port-
# forward rules) - shared by both the manual start path and systemd's
# ExecStartPost. Safe to run even if tun0 hasn't finished appearing yet:
# iptables accepts rules naming an interface by string before it exists,
# they simply take effect the moment it does.
cmd_postup() {
    load_conf
    # The in-tunnel reorder buffer's window was shortened (see
    # REORDER_TIMEOUT_MS in icmptun.c) to bound head-of-line-blocking
    # latency under real multi-connection load, which means more
    # residual reordering now reaches TCP directly - bumped a bit from
    # the previous value to compensate so genuine reordering still
    # doesn't trigger spurious fast-retransmits.
    sysctl -w net.ipv4.tcp_reordering=16 >/dev/null
    setup_nat_scaffolding
    pf_apply_all
}

cmd_enable() {
    need_root
    load_conf
    [[ -x "$BIN" ]] || cmd_build
    # Avoid a manually-started instance sticking around once systemd also
    # starts owning this service - see _systemd_owns_it.
    cmd_stop 2>/dev/null || true

    local sflag=""
    [[ "$ROLE" == "server" ]] && sflag="-s"
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=ICMPTUN tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=-/sbin/ip link del $TUN_NAME
ExecStart=$BIN -L $LOCAL_IP -R $PEER_IP -A $TUN_LOCAL -P $TUN_PEER -M $MTU -I $IDENT -T $TUN_NAME $sflag
ExecStartPost=$SCRIPT_PATH postup
ExecStopPost=-/sbin/ip link del $TUN_NAME
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now "$SERVICE_NAME"
    echo "systemd service enabled: $SERVICE_NAME"
}

cmd_logs() {
    if [[ "${1:-}" == "-f" ]]; then
        tail -f "$LOG_FILE"
    else
        tail -100 "$LOG_FILE"
    fi
}

# ------------------------------------------------------- port forwarding ---

_pf_validate_proto() {
    case "$1" in
        tcp|udp) echo "$1" ;;
        both) echo "tcp udp" ;;
        *) echo "invalid protocol: $1 (must be tcp/udp/both)" >&2; exit 1 ;;
    esac
}

_pf_dnat_rule() {
    local action="$1" proto="$2" port="$3" tip="$4" tport="$5"
    iptables -t nat "$action" "$DNAT_CHAIN" -p "$proto" --dport "$port" \
        -j DNAT --to-destination "$tip:$tport"
}

# Surfaces exactly the class of bug that once silently broke a port
# forward here: a pre-existing DNAT rule elsewhere in the nat table (from
# an older/unrelated setup) sitting BEFORE our chain and matching the
# same port, or a local process already bound to it. Neither is fatal by
# itself, but both mean this forward may never actually reach the
# tunnel - warn loudly so it's a deliberate call, not a silent failure
# discovered hours later.
_pf_check_conflicts() {
    local port="$1" proto="$2"
    local hits
    hits=$(iptables-save -t nat 2>/dev/null | \
        grep -E "^-A (PREROUTING|OUTPUT) .*-p ${proto} .*--dport ${port}( |$)" || true)
    if [[ -n "$hits" ]]; then
        echo "${C_YELLOW}warning: another DNAT rule already claims port $port/$proto (outside our chain) - it may catch traffic before it ever reaches the tunnel:${C_RESET}"
        echo "$hits" | sed 's/^/    /'
    fi
    if ss -H -"${proto:0:1}"ln 2>/dev/null | awk '{print $4}' | grep -qE ":${port}\$"; then
        echo "${C_YELLOW}warning: a local process is already listening on port $port ($proto) on this box${C_RESET}"
    fi
}

cmd_pf_add() {
    need_root
    load_conf
    local port="${1:?port required}" proto="${2:?tcp/udp/both required}"
    local tip="${3:-$TUN_PEER}" tport="${4:-$port}"
    local plist; plist=$(_pf_validate_proto "$proto")

    for p in $plist; do
        if grep -qE "^${port} ${p} " "$PF_FILE" 2>/dev/null; then
            echo "already exists: $port/$p - skipped"
            continue
        fi
        _pf_check_conflicts "$port" "$p"
        echo "$port $p $tip $tport" >> "$PF_FILE"
        _pf_dnat_rule -A "$p" "$port" "$tip" "$tport"
        echo "added: $port/$p -> $tip:$tport"
    done
}

cmd_pf_del() {
    need_root
    load_conf
    local port="${1:?port required}" proto="${2:?tcp/udp/both required}"
    local plist; plist=$(_pf_validate_proto "$proto")

    for p in $plist; do
        local line; line=$(grep -E "^${port} ${p} " "$PF_FILE" 2>/dev/null || true)
        if [[ -z "$line" ]]; then
            echo "not found: $port/$p"
            continue
        fi
        local tip tport
        tip=$(awk '{print $3}' <<<"$line")
        tport=$(awk '{print $4}' <<<"$line")
        _pf_dnat_rule -D "$p" "$port" "$tip" "$tport" 2>/dev/null || true
        # grep -v legitimately exits 1 when it filters out the file's only
        # remaining line (zero output = "no lines selected") - under set -e
        # that must NOT skip the mv, or the "deleted" entry silently stays
        # in the file while this function still reports success.
        grep -vE "^${port} ${p} " "$PF_FILE" > "$PF_FILE.tmp" || true
        mv "$PF_FILE.tmp" "$PF_FILE"
        echo "removed: $port/$p"
    done
}

cmd_pf_list() { pf_list; }

pf_list() {
    load_conf 2>/dev/null || return 0
    [[ -s "$PF_FILE" ]] || { echo "(no port forwards defined)"; return 0; }
    printf "%-8s %-6s %-20s %-8s\n" "PORT" "PROTO" "TARGET" "TPORT"
    while read -r port proto tip tport; do
        [[ -z "$port" ]] && continue
        printf "%-8s %-6s %-20s %-8s\n" "$port" "$proto" "$tip" "$tport"
    done < "$PF_FILE"
}

pf_apply_all() {
    load_conf
    iptables -t nat -F "$DNAT_CHAIN" 2>/dev/null || true
    [[ -s "$PF_FILE" ]] || return 0
    while read -r port proto tip tport; do
        [[ -z "$port" ]] && continue
        _pf_dnat_rule -A "$proto" "$port" "$tip" "$tport"
    done < "$PF_FILE"
}

cmd_pf_flush() {
    need_root
    load_conf
    iptables -t nat -F "$DNAT_CHAIN" 2>/dev/null || true
    : > "$PF_FILE"
    echo "all port forwards cleared"
}

# ------------------------------------------------------------------ test ---

cmd_test() {
    load_conf
    echo "--- ping ---"
    ping -c 8 -i 0.3 -W 3 "$TUN_PEER" || true

    echo
    echo "--- speed test ---"
    if ! command -v iperf3 >/dev/null 2>&1; then
        echo "iperf3 is not installed on this box - speed test skipped."
        echo "install it with: apt-get install -y iperf3"
        return 0
    fi

    # Try to bring the peer's iperf3 server up ourselves rather than
    # failing with a raw socket error the user then has to decode. Only
    # possible when peer SSH details were saved (menu option 9).
    if load_peer_conf 2>/dev/null; then
        echo "starting iperf3 on the peer over SSH..."
        _peer_ssh "command -v iperf3 >/dev/null 2>&1 || (DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iperf3 >/dev/null 2>&1); pkill -x iperf3 2>/dev/null; setsid nohup iperf3 -s -1 -B $TUN_PEER >/dev/null 2>&1 < /dev/null & echo PEER_IPERF_UP" >/dev/null 2>&1 && sleep 2
    fi

    local out
    out=$(timeout 15 iperf3 -c "$TUN_PEER" -t 5 -B "$TUN_LOCAL" 2>&1) || true
    if echo "$out" | grep -q "sender"; then
        echo "$out" | grep -E "sender|receiver"
    else
        echo "could not run a speed test against the peer."
        if load_peer_conf 2>/dev/null; then
            echo "the peer was reachable over SSH but iperf3 did not accept the connection."
            echo "check that the tunnel itself is up on both ends (menu option 1)."
        else
            echo "no peer SSH details saved, so the peer's iperf3 server could not be started"
            echo "automatically. Either set them up (menu option 9), or run this on the peer:"
            echo "    iperf3 -s -D -B $TUN_PEER"
        fi
    fi
}

# ------------------------------------------------------------------- BBR ---
#
# System-wide TCP congestion control, independent of the tunnel itself -
# applies to any TCP this box originates or forwards. Worth offering on
# both ends: BBR tends to hold throughput better than the default cubic
# on paths with occasional loss/reordering, which is exactly this path's
# profile even with the reorder buffer catching most of it.

cmd_bbr_status() {
    local cur avail qdisc
    cur=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "?")
    avail=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "?")
    qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "?")
    echo "current algorithm: $cur   qdisc: $qdisc"
    echo "kernel-available algorithms: $avail"
    if [[ "$cur" == "bbr" ]]; then
        echo "status: ${C_GREEN}enabled${C_RESET}"
    else
        echo "status: ${C_RED}disabled${C_RESET}"
    fi
}

cmd_bbr_enable() {
    need_root
    modprobe tcp_bbr 2>/dev/null || true
    local avail; avail=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null)
    if [[ "$avail" != *bbr* ]]; then
        echo "this kernel doesn't support BBR (available: $avail)"
        return 1
    fi
    sysctl -w net.core.default_qdisc=fq >/dev/null
    sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null
    mkdir -p /etc/sysctl.d
    cat > /etc/sysctl.d/99-icmptun-bbr.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
    echo "BBR enabled and made persistent (survives reboot too)."
}

cmd_bbr_disable() {
    need_root
    sysctl -w net.ipv4.tcp_congestion_control=cubic >/dev/null
    rm -f /etc/sysctl.d/99-icmptun-bbr.conf
    echo "BBR disabled, back to cubic."
}

# ------------------------------------------------- peer SSH (remote mgmt) --
#
# Used only by "remove tunnel from both servers". Entered once, saved to a
# root-only file, never required again. Purely a management convenience -
# the tunnel core (icmptun itself) has zero SSH dependency, and a failed
# or unreachable peer connection here must never touch local tunnel state.

load_peer_conf() {
    [[ -f "$PEER_CONF_FILE" ]] || return 1
    # shellcheck disable=SC1090
    source "$PEER_CONF_FILE"
    [[ -n "${PEER_SSH_HOST:-}" ]]
}

wizard_peer_conf() {
    load_conf
    header
    echo "--- SSH connection details for the peer server ---"
    echo "Saved once (file $PEER_CONF_FILE, root-readable only) - you won't need to enter it again."
    echo
    read -rp "Peer IP/host [default: $PEER_IP]: " h; h="${h:-$PEER_IP}"
    read -rp "SSH port [22]: " prt; prt="${prt:-22}"
    read -rp "User [root]: " usr; usr="${usr:-root}"
    read -rsp "Password: " pass; echo
    read -rp "SOCKS5 proxy to reach that server (optional, host:port format - Enter to skip): " proxy
    mkdir -p "$CONF_DIR"
    cat > "$PEER_CONF_FILE" <<EOF
PEER_SSH_HOST=$h
PEER_SSH_PORT=$prt
PEER_SSH_USER=$usr
PEER_SSH_PASS=$pass
PEER_SSH_PROXY=$proxy
EOF
    chmod 600 "$PEER_CONF_FILE"
    echo "saved."
}

# Runs one command on the peer over SSH (password auth via a throwaway
# SSH_ASKPASS helper, optionally through a SOCKS5 proxy). Never touches
# local state; callers must treat a non-zero return as "remote step
# skipped", not as a reason to unwind anything already done locally.
_peer_ssh() {
    local remote_cmd="$1"
    load_peer_conf || return 1
    local ap; ap=$(mktemp)
    cat > "$ap" <<'EOF'
#!/bin/sh
printf '%s\n' "$ICMPTUN_PEER_PASS"
EOF
    chmod 700 "$ap"
    local proxy_opts=()
    if [[ -n "${PEER_SSH_PROXY:-}" ]]; then
        proxy_opts=(-o "ProxyCommand=nc -X 5 -x $PEER_SSH_PROXY %h %p")
    fi
    ICMPTUN_PEER_PASS="$PEER_SSH_PASS" SSH_ASKPASS="$ap" SSH_ASKPASS_REQUIRE=force DISPLAY=:0 \
        ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 \
            -o LogLevel=ERROR -o PreferredAuthentications=password -o PubkeyAuthentication=no \
            -o NumberOfPasswordPrompts=1 "${proxy_opts[@]}" \
            -p "${PEER_SSH_PORT:-22}" "${PEER_SSH_USER:-root}@${PEER_SSH_HOST}" "$remote_cmd"
    local rc=$?
    rm -f "$ap"
    return $rc
}

# --------------------------------------------------------------- remove ---

# Full local teardown: stop process, disable/remove the systemd unit,
# remove our iptables rules (targeted removal, never a blanket flush of
# chains we don't own), drop tun0. Config files are kept so the tunnel
# can be brought back with just "start" later. Always completes fully
# regardless of any later remote step's outcome.
cmd_remove_local() {
    need_root
    load_conf 2>/dev/null || { echo "nothing to remove (not configured)"; return 0; }

    systemctl disable --now "$SERVICE_NAME" 2>/dev/null || true
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload 2>/dev/null || true
    systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true

    cmd_stop 2>/dev/null || true
    pkill -f "$BIN -L" 2>/dev/null || true
    ip link del "$TUN_NAME" 2>/dev/null || true

    # Every rule this tool can create, removed in dependency order. The
    # jump rules must go before the chains they point at can be deleted.
    iptables -t nat -D PREROUTING -j "$DNAT_CHAIN" 2>/dev/null || true
    iptables -t nat -D POSTROUTING -o "$TUN_NAME" -j MASQUERADE 2>/dev/null || true
    iptables -t nat -F "$DNAT_CHAIN" 2>/dev/null || true
    iptables -t nat -X "$DNAT_CHAIN" 2>/dev/null || true
    iptables -D FORWARD -j "$FWD_CHAIN" 2>/dev/null || true
    iptables -F "$FWD_CHAIN" 2>/dev/null || true
    iptables -X "$FWD_CHAIN" 2>/dev/null || true
    local hex; hex=$(_ident_hex_upper "$IDENT")
    iptables -t raw -D OUTPUT -p icmp --icmp-type echo-reply \
        -m u32 --u32 "24&0xFFFF0000=0x${hex}0000" -j DROP 2>/dev/null || true

    # Port-forward bookkeeping goes too - otherwise a later start would
    # silently re-create forwards the user believes they just deleted.
    rm -f "$PF_FILE"

    if [[ "${1:-}" == "--purge" ]]; then
        rm -rf "$CONF_DIR"
        rm -f "$BIN" "$LOG_FILE"
        echo "tunnel and ALL its config/binaries purged from this box."
    else
        echo "tunnel removed from this box (config kept, 'start' brings it back)."
    fi
}

# Local removal always runs first and unconditionally; the remote attempt
# is strictly best-effort afterward and never allowed to affect the
# already-completed local result.
cmd_remove_both() {
    need_root
    local purge="${1:-}"
    local ident_hex tun_name
    ident_hex=$(_ident_hex_upper "${IDENT:-4d54}" 2>/dev/null || echo 4D54)
    tun_name="${TUN_NAME:-tun0}"

    cmd_remove_local "$purge"

    echo
    echo "attempting to remove the tunnel from the peer server too..."
    if ! load_peer_conf; then
        echo "no saved connection details for the peer server."
        read -rp "enter them now? (Y/n): " yn
        if [[ "${yn:-Y}" == "n" || "${yn:-Y}" == "N" ]]; then
            echo "skipped - the peer will need manual removal."
            return 0
        fi
        wizard_peer_conf
    fi

    # Mirror of cmd_remove_local, run on the peer. Kept in sync with it
    # deliberately: an asymmetric teardown is what leaves a peer half-
    # removed (service gone but chains/forwards still catching traffic).
    local remote_cmd="
systemctl disable --now icmptun.service 2>/dev/null
rm -f /etc/systemd/system/icmptun.service
systemctl daemon-reload 2>/dev/null
systemctl reset-failed icmptun.service 2>/dev/null
pkill -f 'icmptun -L' 2>/dev/null
ip link del ${tun_name} 2>/dev/null
iptables -t nat -D PREROUTING -j ICMPTUN_DNAT 2>/dev/null
iptables -t nat -D POSTROUTING -o ${tun_name} -j MASQUERADE 2>/dev/null
iptables -t nat -F ICMPTUN_DNAT 2>/dev/null
iptables -t nat -X ICMPTUN_DNAT 2>/dev/null
iptables -D FORWARD -j ICMPTUN_FWD 2>/dev/null
iptables -F ICMPTUN_FWD 2>/dev/null
iptables -X ICMPTUN_FWD 2>/dev/null
iptables -t raw -D OUTPUT -p icmp --icmp-type echo-reply -m u32 --u32 '24&0xFFFF0000=0x${ident_hex}0000' -j DROP 2>/dev/null
rm -f /etc/icmptun/portforwards
"
    if [[ "$purge" == "--purge" ]]; then
        remote_cmd="$remote_cmd
rm -rf /etc/icmptun
rm -f /usr/local/bin/icmptun /usr/local/bin/icmptun-ctl.sh /var/log/icmptun.log
"
    fi
    remote_cmd="$remote_cmd
echo REMOTE_REMOVE_OK"

    if _peer_ssh "$remote_cmd"; then
        echo "removal from the peer server succeeded too."
    else
        echo "SSH to the peer server failed - this box is fully removed and healthy, but the peer needs manual removal."
    fi
}

# ---------------------------------------------------------------- UI/menu --

C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
C_GREEN=$'\033[32m'; C_RED=$'\033[31m'; C_YELLOW=$'\033[33m'; C_CYAN=$'\033[36m'

pause() { echo; read -rp "Press Enter to continue..." _ || true; }

# Shown once at startup, not on every menu redraw - a big banner on every
# screen is a lot of scroll for something you glance at dozens of times a
# session. header() below (the compact bordered panel) carries the status
# summary on every subsequent screen instead.
print_banner() {
    clear
    echo -e "${C_CYAN}${C_BOLD}"
    cat <<'BANNER'
 ___    ____   __  __   ____   _____   _   _   _   _
|_ _|  / ___| |  \/  | |  _ \ |_   _| | | | | | \ | |
 | |  | |    | |\/| | | |_) |   | |   | | | | |  \| |
 | |  | |___ | |  | | |  __/    | |   | |_| | | |\  |
|___|  \____| |_|  |_| |_|      |_|    \___/  |_| \_|
BANNER
    echo -e "${C_RESET}"
    echo "  ICMP-Disguised IP Tunnel  -  by Free-Guy-IR  -  v${VERSION}"
    echo
}

header() {
    clear
    local title="ICMPTUN"
    [[ -n "$INSTANCE" ]] && title="ICMPTUN [$INSTANCE]"
    # Note: lines below deliberately don't close the box with a right-hand
    # border - printf's field-width padding counts ANSI color bytes as
    # visible characters, so a colored value inside a fixed-width field
    # throws off the padding and misaligns a right border. Left-aligned,
    # no right border, is the option that can't silently drift.
    echo -e "${C_CYAN}${C_BOLD}╔══════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_CYAN}${C_BOLD}║${C_RESET}  $title"
    echo -e "${C_CYAN}${C_BOLD}╠══════════════════════════════════════════════════════════${C_RESET}"
    if [[ -f "$CONF_FILE" ]]; then
        # shellcheck disable=SC1090
        source "$CONF_FILE"
        local proc_state tun_state
        if _is_running; then
            proc_state="${C_GREEN}●${C_RESET} running"
        else
            proc_state="${C_RED}●${C_RESET} stopped"
        fi
        if ip link show "$TUN_NAME" >/dev/null 2>&1; then
            tun_state="${C_GREEN}up${C_RESET}"
        else
            tun_state="${C_RED}down${C_RESET}"
        fi
        echo -e "${C_CYAN}${C_BOLD}║${C_RESET}  role: ${C_YELLOW}$ROLE${C_RESET}   local: $LOCAL_IP   peer: $PEER_IP"
        echo -e "${C_CYAN}${C_BOLD}║${C_RESET}  process: $proc_state   $TUN_NAME: $tun_state"
    else
        echo -e "${C_CYAN}${C_BOLD}║${C_RESET}  ${C_RED}not configured yet${C_RESET}"
    fi
    echo -e "${C_CYAN}${C_BOLD}╚══════════════════════════════════════════════════════════${C_RESET}"
    echo
}

# A wrong LOCAL_IP (e.g. pasting the *peer's* IP here) makes the binary
# die at bind() with "Cannot assign requested address" and systemd then
# restarts it forever, so the real mistake never surfaces to the user.
# Catch it at config time, where it can still be explained.
_ip_is_local() {
    ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -qx "$1"
}

# Full clean reinstall driven entirely from this box: wipes both ends,
# reconfigures this end, then pushes the matching config to the peer over
# SSH so the two halves can't drift apart. Run this on the client (Iran)
# side - it derives and applies the server side itself.
cmd_reinstall_both() {
    need_root
    header
    echo "--- Full reinstall (this box + peer) ---"
    echo
    echo "This wipes the existing tunnel from BOTH servers, then sets both up again"
    echo "from scratch. Run it from the client (Iran) side."
    echo
    read -rp "Continue? (y/N): " c
    [[ "$c" != "y" && "$c" != "Y" ]] && { echo "cancelled"; pause; return 0; }

    if ! load_peer_conf 2>/dev/null; then
        echo
        echo "Peer SSH details are required so the peer can be reinstalled automatically."
        wizard_peer_conf
        load_peer_conf 2>/dev/null || { echo "no peer details - aborting."; pause; return 1; }
    fi

    echo
    echo "checking SSH access to the peer first..."
    if ! _peer_ssh "echo PEER_SSH_OK" 2>/dev/null | grep -q PEER_SSH_OK; then
        echo "cannot reach the peer over SSH - fix that first (menu option 9)."
        echo "nothing has been changed."
        pause; return 1
    fi
    echo "peer SSH works."

    echo
    echo "[1/4] wiping the old tunnel from both boxes..."
    cmd_remove_both --purge || true

    echo
    echo "[2/4] configuring this box..."
    wizard_init_core || { echo "setup cancelled"; pause; return 1; }

    echo
    echo "[3/4] installing and configuring the peer..."
    load_conf
    _setup_remote_peer "$INSTANCE" "$PEER_IP" "$LOCAL_IP" "$IDENT" "$MTU" "$TUN_PEER" "$TUN_LOCAL" || true

    echo
    echo "[4/4] starting this box and verifying..."
    cmd_enable
    sleep 3
    echo
    if ping -c 4 -W 2 "$TUN_PEER" >/dev/null 2>&1; then
        echo "${C_GREEN}tunnel is up on both ends.${C_RESET}"
        ping -c 4 -W 2 "$TUN_PEER" | tail -2
    else
        echo "${C_YELLOW}tunnel is configured but not passing traffic yet - check status (option 1).${C_RESET}"
    fi
    pause
}

# ------------------------------------------------- multi-tunnel instances ---
#
# One box can hold any number of independent tunnels, each to a different
# peer. They are kept apart by instance name, which drives a separate
# config dir, binary, systemd unit, TUN device, ICMP identifier and
# iptables chains - see the INSTANCE block at the top of this file.

list_instances() {
    local d found=0
    for d in /etc/icmptun /etc/icmptun-*; do
        [[ -f "$d/icmptun.conf" ]] || continue
        found=1
        local nm="(default)"
        [[ "$d" != "/etc/icmptun" ]] && nm="${d#/etc/icmptun-}"
        local sfx=""; [[ "$nm" != "(default)" ]] && sfx="-$nm"
        local peer role state
        peer=$(grep -E '^PEER_IP=' "$d/icmptun.conf" 2>/dev/null | cut -d= -f2)
        role=$(grep -E '^ROLE=' "$d/icmptun.conf" 2>/dev/null | cut -d= -f2)
        state="stopped"
        pgrep -f "/usr/local/bin/icmptun${sfx} -L" >/dev/null 2>&1 && state="running"
        printf "  %-14s peer=%-16s role=%-7s %s\n" "$nm" "$peer" "$role" "$state"
    done
    [[ $found -eq 0 ]] && echo "  (no tunnels configured on this box)"
    return 0
}

# Pick an instance name, ICMP ident and tunnel subnet that don't collide
# with anything already on THIS box.
_next_free_instance() {
    local n=2
    while [[ -f "/etc/icmptun-t${n}/icmptun.conf" ]]; do n=$((n+1)); done
    printf 't%s' "$n"
}
_next_free_ident() {
    local base=$((0x4d54)) i=0 cand
    while [[ $i -lt 200 ]]; do
        cand=$(printf '%04x' $((base + i*2)))
        if ! grep -rqs "^IDENT=$cand$" /etc/icmptun/icmptun.conf /etc/icmptun-*/icmptun.conf 2>/dev/null; then
            printf '%s' "$cand"; return 0
        fi
        i=$((i+1))
    done
    printf '%s' "$(printf '%04x' $((RANDOM % 65535)))"
}
_next_free_subnet() {
    local n=99
    while grep -rqs "^TUN_LOCAL=10\.${n}\." /etc/icmptun/icmptun.conf /etc/icmptun-*/icmptun.conf 2>/dev/null; do
        n=$((n+1)); [[ $n -gt 250 ]] && break
    done
    printf '10.%s.0' "$n"
}

# Add another tunnel from this box to a DIFFERENT peer, leaving every
# existing tunnel (here and on the peer) untouched.
wizard_add_tunnel() {
    need_root
    header
    echo "--- Add another tunnel (to a different peer) ---"
    echo
    echo "Tunnels already on this box:"
    list_instances
    echo

    local inst def_inst
    def_inst=$(_next_free_instance)
    read -rp "Name for the new tunnel [default $def_inst]: " inst
    inst="${inst:-$def_inst}"
    if ! [[ "$inst" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        echo "name may only contain letters/digits/hyphen/underscore"; pause; return 1
    fi
    if [[ -f "/etc/icmptun-${inst}/icmptun.conf" ]]; then
        echo "a tunnel named '$inst' already exists on this box"; pause; return 1
    fi

    local detected_ip local_ip peer_ip
    detected_ip=$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || true)
    read -rp "This server's real IP [detected: ${detected_ip:-none}]: " local_ip
    local_ip="${local_ip:-$detected_ip}"
    read -rp "New peer server's real IP: " peer_ip
    [[ -z "$local_ip" || -z "$peer_ip" ]] && { echo "both IPs are required"; pause; return 1; }
    if ! _ip_is_local "$local_ip"; then
        echo "${C_RED}error: $local_ip is not an address on this machine.${C_RESET}"
        ip -4 -o addr show 2>/dev/null | awk '{print "    " $2 "  " $4}' | grep -v ' lo '
        pause; return 1
    fi

    local ident subnet mtu
    ident=$(_next_free_ident)
    subnet=$(_next_free_subnet)
    mtu=1400
    echo
    echo "auto-picked non-conflicting settings for this box:"
    echo "  instance : $inst"
    echo "  ICMP id  : $ident"
    echo "  tunnel   : ${subnet}.1 <-> ${subnet}.2"
    echo

    read -rp "Also install/configure the new peer automatically over SSH? (Y/n): " doremote
    local want_remote=1
    [[ "${doremote:-Y}" == "n" || "${doremote:-Y}" == "N" ]] && want_remote=0

    # local half
    ICMPTUN_INSTANCE="$inst" "$SCRIPT_PATH" init --role client \
        -L "$local_ip" -R "$peer_ip" -I "$ident" -M "$mtu" \
        -A "${subnet}.1" -P "${subnet}.2" || { echo "init failed"; pause; return 1; }
    ICMPTUN_INSTANCE="$inst" "$SCRIPT_PATH" build || { echo "build failed"; pause; return 1; }

    if [[ $want_remote -eq 1 ]]; then
        echo
        echo "--- new peer's SSH details ---"
        local h prt usr pass proxy
        read -rp "Peer SSH host [$peer_ip]: " h; h="${h:-$peer_ip}"
        read -rp "Peer SSH port [22]: " prt; prt="${prt:-22}"
        read -rp "Peer SSH user [root]: " usr; usr="${usr:-root}"
        read -rsp "Peer SSH password: " pass; echo
        read -rp "SOCKS5 proxy for SSH (host:port, blank for none): " proxy
        mkdir -p "/etc/icmptun-${inst}"
        cat > "/etc/icmptun-${inst}/peer_ssh.conf" <<EOF
PEER_SSH_HOST=$h
PEER_SSH_PORT=$prt
PEER_SSH_USER=$usr
PEER_SSH_PASS=$pass
PEER_SSH_PROXY=$proxy
EOF
        chmod 600 "/etc/icmptun-${inst}/peer_ssh.conf"

        PEER_SSH_HOST="$h" PEER_SSH_PORT="$prt" PEER_SSH_USER="$usr" \
        PEER_SSH_PASS="$pass" PEER_SSH_PROXY="$proxy" \
            _setup_remote_peer "$inst" "$peer_ip" "$local_ip" "$ident" "$mtu" "${subnet}.2" "${subnet}.1"
    fi

    ICMPTUN_INSTANCE="$inst" "$SCRIPT_PATH" enable || true
    sleep 2
    echo
    if ping -c 4 -W 2 "${subnet}.2" >/dev/null 2>&1; then
        echo "${C_GREEN}new tunnel '$inst' is up.${C_RESET}"
    else
        echo "${C_YELLOW}tunnel '$inst' configured but not passing traffic yet.${C_RESET}"
    fi
    echo
    echo "manage it with:  ICMPTUN_INSTANCE=$inst $SCRIPT_PATH"
    pause
}

# Install/configure the far end for a given instance. Critically: if that
# box ALREADY runs a tunnel (very likely - a foreign box is often shared
# by several Iran boxes), this never touches it. It picks a free instance
# slot on the peer instead, so the existing tunnel and its port forwards
# keep running untouched.
_setup_remote_peer() {
    local inst="$1" peer_ip="$2" our_ip="$3" ident="$4" mtu="$5" ptun_local="$6" ptun_peer="$7"

    echo "checking what is already installed on the peer..."
    local existing
    existing=$(_peer_ssh 'ls -d /etc/icmptun /etc/icmptun-* 2>/dev/null | while read d; do [ -f "$d/icmptun.conf" ] && echo "$d"; done' 2>/dev/null | tr -d '\r')

    local remote_inst=""
    if [[ -n "$existing" ]]; then
        echo "peer already has these tunnels - they will be left running:"
        echo "$existing" | sed 's/^/    /'
        # never reuse a slot that exists there
        if echo "$existing" | grep -qx "/etc/icmptun"; then
            local n=2
            while echo "$existing" | grep -qx "/etc/icmptun-t${n}"; do n=$((n+1)); done
            remote_inst="t${n}"
        fi
    fi
    local remote_sfx="" remote_env=""
    if [[ -n "$remote_inst" ]]; then
        remote_sfx="-$remote_inst"
        remote_env="ICMPTUN_INSTANCE=$remote_inst"
        echo "using instance '$remote_inst' on the peer so nothing existing is disturbed."
    else
        echo "peer has no existing tunnel - using its default instance."
    fi

    local remote_setup="
set -e
command -v gcc >/dev/null 2>&1 || (DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq gcc iptables >/dev/null 2>&1)
mkdir -p /usr/local/bin
cat > /usr/local/bin/icmptun-ctl.sh <<'ICMPTUN_CTL_EOF'
$(cat "$SCRIPT_PATH")
ICMPTUN_CTL_EOF
chmod +x /usr/local/bin/icmptun-ctl.sh
$remote_env /usr/local/bin/icmptun-ctl.sh init --role server -L $peer_ip -R $our_ip -I $ident -M $mtu -A $ptun_local -P $ptun_peer
$remote_env /usr/local/bin/icmptun-ctl.sh build
$remote_env /usr/local/bin/icmptun-ctl.sh enable
echo PEER_SETUP_OK
"
    if _peer_ssh "$remote_setup" 2>&1 | tail -25 | grep -q PEER_SETUP_OK; then
        echo "peer configured and started."
        return 0
    fi
    echo "peer setup did not report success - check it manually."
    return 1
}

menu_instances() {
    while true; do
        header
        echo "--- Tunnels on this box ---"
        echo
        list_instances
        echo
        echo "  ${C_BOLD}1)${C_RESET} Add another tunnel (to a different peer)"
        echo "  ${C_BOLD}2)${C_RESET} Manage a different tunnel (switch instance)"
        echo "  ${C_BOLD}0)${C_RESET} Back"
        read -rp "Choice: " c
        case "$c" in
            1) wizard_add_tunnel ;;
            2) read -rp "Instance name ((default) for the original): " nm
               if [[ "$nm" == "(default)" || -z "$nm" ]]; then
                   exec "$SCRIPT_PATH"
               else
                   exec env ICMPTUN_INSTANCE="$nm" "$SCRIPT_PATH"
               fi ;;
            0) return 0 ;;
            *) echo "invalid choice"; sleep 1 ;;
        esac
    done
}

wizard_init() {
    wizard_init_core && pause
}

wizard_init_core() {
    header
    echo "--- Initial setup ---"
    echo "What is this server's role?"
    echo "  1) client  (initiates the connection)"
    echo "  2) server  (answers - typically the box with the reachable public IP)"
    read -rp "Choice: " rchoice
    local role=""
    case "$rchoice" in
        1) role=client ;;
        2) role=server ;;
        *) echo "invalid choice"; pause; return 1 ;;
    esac
    local detected_ip
    detected_ip=$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || true)
    if [[ -n "$detected_ip" ]]; then
        read -rp "This server's real IP [detected: $detected_ip]: " local_ip
        local_ip="${local_ip:-$detected_ip}"
    else
        read -rp "This server's real IP: " local_ip
    fi
    read -rp "Peer server's real IP: " peer_ip
    if [[ -z "$local_ip" || -z "$peer_ip" ]]; then
        echo "both IPs are required"; pause; return 1
    fi
    read -rp "ICMP identifier, hex [default 4d54]: " ident; ident="${ident:-4d54}"
    read -rp "MTU [default 1400]: " mtu; mtu="${mtu:-1400}"

    local def_local def_peer
    if [[ "$role" == "server" ]]; then def_local="10.99.0.2"; def_peer="10.99.0.1"
    else                               def_local="10.99.0.1"; def_peer="10.99.0.2"; fi
    echo
    echo "Tunnel's internal IP (used only between the two tunnel ends, not a real IP)."
    echo "If this is the only tunnel running on this box, the default is fine."
    echo "If you're running several tunnels on this box at once (e.g. several Iran servers into one foreign box), each needs its own separate range."
    read -rp "This end's tunnel IP [default $def_local]: " tun_local; tun_local="${tun_local:-$def_local}"
    read -rp "Peer's tunnel IP [default $def_peer]: " tun_peer; tun_peer="${tun_peer:-$def_peer}"

    if ! _ip_is_local "$local_ip"; then
        echo
        echo "${C_RED}error: $local_ip is not an address on this machine.${C_RESET}"
        echo "'This server's real IP' must be THIS box's own IP, not the peer's."
        echo "addresses found on this box:"
        ip -4 -o addr show 2>/dev/null | awk '{print "    " $2 "  " $4}' | grep -v ' lo '
        echo
        echo "nothing was changed."
        return 1
    fi

    cmd_init --role "$role" -L "$local_ip" -R "$peer_ip" -I "$ident" -M "$mtu" -A "$tun_local" -P "$tun_peer"
    cmd_build

    read -rp "Start and enable the systemd service (auto-start) now too? (Y/n): " yn
    if [[ "${yn:-Y}" != "n" && "${yn:-Y}" != "N" ]]; then
        cmd_enable
    fi
    return 0
}

declare -a PF_IDX_PORT PF_IDX_PROTO

pf_list_numbered() {
    load_conf 2>/dev/null || { echo "(not configured)"; return 0; }
    PF_IDX_PORT=(); PF_IDX_PROTO=()
    if [[ ! -s "$PF_FILE" ]]; then
        echo "(no port forwards defined)"
        return 0
    fi
    printf "%-4s %-8s %-6s %-20s %-8s\n" "#" "PORT" "PROTO" "TARGET" "TPORT"
    local i=1
    while read -r port proto tip tport; do
        [[ -z "$port" ]] && continue
        printf "%-4s %-8s %-6s %-20s %-8s\n" "$i" "$port" "$proto" "$tip" "$tport"
        PF_IDX_PORT+=("$port"); PF_IDX_PROTO+=("$proto")
        i=$((i + 1))
    done < "$PF_FILE"
}

wizard_pf_add() {
    load_conf
    read -rp "Public port: " port
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then echo "invalid port"; return 1; fi
    echo "Protocol?  1) tcp   2) udp   3) both together (tcp+udp)"
    read -rp "Choice [3]: " pchoice
    local proto
    case "${pchoice:-3}" in
        1) proto=tcp ;;
        2) proto=udp ;;
        *) proto=both ;;
    esac
    read -rp "Target IP [default: tunnel peer - $TUN_PEER]: " tip; tip="${tip:-$TUN_PEER}"
    read -rp "Target port [default: same as $port]: " tport; tport="${tport:-$port}"
    cmd_pf_add "$port" "$proto" "$tip" "$tport"
}

wizard_pf_del() {
    pf_list_numbered
    [[ ${#PF_IDX_PORT[@]} -eq 0 ]] && return 0
    read -rp "Row number to remove (0 = cancel): " idx
    [[ -z "$idx" || "$idx" == "0" ]] && return 0
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || (( idx < 1 || idx > ${#PF_IDX_PORT[@]} )); then
        echo "invalid number"; return 1
    fi
    cmd_pf_del "${PF_IDX_PORT[$((idx - 1))]}" "${PF_IDX_PROTO[$((idx - 1))]}"
}

menu_portforward() {
    while true; do
        header
        echo -e "${C_DIM}── port forwarding (tcp/udp) ─────────────────────────────${C_RESET}"
        echo
        pf_list_numbered
        echo
        cat <<MENU
  ${C_BOLD}1)${C_RESET} Add a port forward
  ${C_BOLD}2)${C_RESET} Remove a port forward
  ${C_BOLD}3)${C_RESET} Clear all
  ${C_BOLD}0)${C_RESET} Back to main menu
MENU
        read -rp "Choice: " choice
        case "$choice" in
            1) wizard_pf_add; pause ;;
            2) wizard_pf_del; pause ;;
            3) read -rp "Sure? This clears every port forward (y/N): " c
               [[ "$c" == "y" || "$c" == "Y" ]] && cmd_pf_flush
               pause ;;
            0) return 0 ;;
            *) echo "invalid choice"; sleep 1 ;;
        esac
    done
}

menu_main() {
    while true; do
        header
        cat <<MENU
  ${C_DIM}tunnel${C_RESET}
   ${C_BOLD}1)${C_RESET} Status
   ${C_BOLD}2)${C_RESET} Start
   ${C_BOLD}3)${C_RESET} Stop
   ${C_BOLD}4)${C_RESET} Restart
   ${C_BOLD}5)${C_RESET} Port forwarding (add/remove/list)
   ${C_BOLD}6)${C_RESET} Ping + speed test

  ${C_DIM}system${C_RESET}
   ${C_BOLD}7)${C_RESET} Enable auto-start (systemd)
   ${C_BOLD}8)${C_RESET} Remove tunnel (this box + peer)
   ${C_BOLD}9)${C_RESET} Set peer SSH connection details
  ${C_BOLD}10)${C_RESET} Reconfigure this tunnel (re-init)
  ${C_BOLD}11)${C_RESET} Full reinstall - wipe & set up BOTH boxes
  ${C_BOLD}12)${C_RESET} Multiple tunnels (add / switch)
  ${C_BOLD}13)${C_RESET} Enable/disable BBR (this box)

   ${C_BOLD}0)${C_RESET} Exit
MENU
        read -rp "Choice: " choice
        case "$choice" in
            1) header; cmd_status; pause ;;
            2) header; cmd_start; pause ;;
            3) header; cmd_stop; pause ;;
            4) header; cmd_restart; pause ;;
            5) menu_portforward ;;
            6) header; cmd_test; pause ;;
            7) header; cmd_enable; pause ;;
            8) header
               echo "Remove the tunnel from this box AND the peer."
               echo
               echo "  1) Remove tunnel + all its rules/forwards (keep config, can 'start' again)"
               echo "  2) PURGE - also delete config, binaries and saved settings"
               echo "  0) Cancel"
               read -rp "Choice: " rc
               case "$rc" in
                   1) read -rp "Sure? (y/N): " c
                      [[ "$c" == "y" || "$c" == "Y" ]] && cmd_remove_both ;;
                   2) read -rp "Sure? This deletes EVERYTHING on both boxes (y/N): " c
                      [[ "$c" == "y" || "$c" == "Y" ]] && cmd_remove_both --purge ;;
               esac
               pause ;;
            9) wizard_peer_conf; pause ;;
            10) wizard_init ;;
            11) cmd_reinstall_both ;;
            12) menu_instances ;;
            13) menu_bbr ;;
            0) echo "goodbye"; exit 0 ;;
            *) echo "invalid choice"; sleep 1 ;;
        esac
    done
}

menu_bbr() {
    header
    echo "--- BBR (TCP congestion control) ---"
    echo
    cmd_bbr_status
    echo
    echo "  1) Enable BBR"
    echo "  2) Disable BBR (back to cubic)"
    echo "  0) Back"
    read -rp "Choice: " c
    case "$c" in
        1) cmd_bbr_enable ;;
        2) cmd_bbr_disable ;;
    esac
    pause
}

# ------------------------------------------------------------------- CLI ---
#
# Running with no arguments opens the interactive menu - the normal way to
# use this script day to day. Direct subcommands still work too, for quick
# one-off calls and scripting (e.g. `./icmptun-ctl.sh pf add 400 both`).

main() {
    need_root
    if [[ $# -gt 0 ]]; then
        case "$1" in
            init)     shift; cmd_init "$@"; exit 0 ;;
            start)    cmd_start; exit 0 ;;
            stop)     cmd_stop; exit 0 ;;
            restart)  cmd_restart; exit 0 ;;
            postup)   cmd_postup; exit 0 ;;
            status)   cmd_status; exit 0 ;;
            enable)   cmd_enable; exit 0 ;;
            build)    cmd_build; exit 0 ;;
            test)     cmd_test; exit 0 ;;
            logs)     shift; cmd_logs "$@"; exit 0 ;;
            bbr)
                case "${2:-status}" in
                    on|enable)   cmd_bbr_enable ;;
                    off|disable) cmd_bbr_disable ;;
                    *)           cmd_bbr_status ;;
                esac
                exit 0 ;;
            pf)
                shift
                case "${1:-}" in
                    add)   shift; cmd_pf_add "$@"; exit 0 ;;
                    del)   shift; cmd_pf_del "$@"; exit 0 ;;
                    list)  cmd_pf_list; exit 0 ;;
                    flush) cmd_pf_flush; exit 0 ;;
                    *) echo "usage: $SCRIPT_PATH pf add|del|list|flush ..."; exit 1 ;;
                esac
                ;;
            remove)
                case "${2:-}" in
                    both)  cmd_remove_both "${3:-}"; exit 0 ;;
                    purge) cmd_remove_local --purge; exit 0 ;;
                    *)     cmd_remove_local; exit 0 ;;
                esac
                ;;
            instances) list_instances; exit 0 ;;
        esac
    fi
    print_banner
    if [[ ! -f "$CONF_FILE" ]]; then
        echo "Welcome to the ICMPTUN management panel."
        echo "Not configured yet - let's set it up first."
        pause
        wizard_init
    fi
    menu_main
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
