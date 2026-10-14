#!/usr/bin/env bash
# Direct optimizer. Read-only diagnostics support six active carriers and existing legacy instances.
# Only owned L3 instance queue lengths are explicitly adjustable.
set -euo pipefail
ACTION="${1:-status}"; INSTANCE="${2:-}"; PROFILE="${3:-balanced}"; ACK="${4:-}"
[[ "$ACTION" == status || "$ACTION" == analyze || "$ACTION" == recommend || "$ACTION" == dry-run || "$ACTION" == apply || "$ACTION" == rollback || "$ACTION" == compare ]] ||
    { echo "usage: optimizer.sh status|analyze|recommend|dry-run|apply|rollback|compare <instance> [balanced|low-latency|high-throughput|extreme-connections|high-pps|auto-adaptive] [--acknowledge]" >&2; exit 2; }
[[ "$INSTANCE" =~ ^[a-zA-Z0-9_-]+$ ]] || { echo "invalid instance" >&2; exit 2; }
CONFIG_ROOT="${OMNITUN_CONFIG_ROOT:-/etc/omnitunnel}"
STATE_ROOT="${OMNITUN_OPTIMIZER_STATE_DIR:-/var/lib/omnitunnel/optimizer}"
[[ "$CONFIG_ROOT" = /* && "$STATE_ROOT" = /* ]] || { echo "config/state must be absolute paths" >&2; exit 2; }
conf="$CONFIG_ROOT/inst/$INSTANCE/instance.conf"
[[ -r "$conf" ]] || { echo "missing instance: $INSTANCE" >&2; exit 1; }
type="$(sed -n 's/^TYPE=//p' "$conf" | head -1)"
dev="$(sed -n 's/^DEV=//p' "$conf" | head -1)"
case "$type" in
    icmp|udp|tcp|mux|ws|gre|fou|vxlan|stripe|ackless|hysteria) ;;
    *) echo "unsupported Direct transport $type" >&2; exit 1;;
esac
if [[ "$type" == hysteria ]]; then
    case "$ACTION" in
        status|analyze|recommend|dry-run|compare)
            echo "Hysteria: QUIC/SOCKS engine, no dedicated kernel TUN device."
            echo "Engine: $(/usr/local/bin/hysteria version 2>&1 | head -1 || echo not-installed)"
            echo "Only native engine/relay diagnostics possible; no interface modified.";;
        *) echo "No per-instance L3 interface; refusing Hysteria queue mutation" >&2; exit 1;;
    esac
    exit 0
fi
[[ "$dev" =~ ^[A-Za-z0-9_-]{1,15}$ ]] || { echo "invalid TUN device" >&2; exit 1; }
command -v ip >/dev/null || { echo "iproute2 missing" >&2; exit 1; }
ip link show dev "$dev" >/dev/null || { echo "interface $dev is not up; changes refused" >&2; exit 1; }
get_qlen() { ip -o link show dev "$dev" | grep -oE 'qlen [0-9]+' | awk '{print $2}' | head -1; }
cur="$(get_qlen)"
[[ "$cur" =~ ^[0-9]+$ ]] || { echo "unknown queue size for $dev" >&2; exit 1; }
case "$PROFILE" in
    balanced) proposed="$cur";;
    low-latency) proposed="$((cur > 512 ? 512 : cur))";;
    high-throughput) proposed="$((cur < 2048 ? 2048 : cur))";;
    extreme-connections|high-pps|auto-adaptive) proposed="$cur";;
    *) echo "unknown profile $PROFILE" >&2; exit 2;;
esac
backup_dir="$STATE_ROOT"
snap="$backup_dir/$INSTANCE.last"
stats="/run/omnitunnel/icmp-$dev.json"
status() {
    echo "Device: $dev | Direct protocol: $type | current TUN txqueuelen: $cur"
    echo "Kernel: $(uname -r); CPU cores: $(nproc); RAM: $(awk '/MemTotal:/{printf "%.0f MiB",$2/1024}' /proc/meminfo)"
    echo "CPU topology: sockets=$(lscpu -p=socket 2>/dev/null | grep -cv '^#' || echo unavailable); logical=$(nproc)"
    echo "Available RAM: $(awk '/MemAvailable:/{printf "%.0f MiB",$2/1024}' /proc/meminfo)"
    echo "Transport-specific guidance: $type"
    case "$type" in
      gre|fou) echo "Kernel carrier: compare path MTU, fragmentation, softirq and interface drops; avoid global qdisc changes.";;
      icmp) echo "ICMP userspace: inspect per-core flow/queue counters before changing flow slots; changes require planned restart.";;
      udp) echo "UDP userspace: inspect socket receive errors and encryption CPU; do not blindly increase socket buffers.";;
      tcp) echo "TCP userspace: inspect retransmits, HOL blocking and reconnects; kernel autotuning unchanged.";;
      *) echo "Legacy carrier: read-only compatibility reporting.";;
    esac
    echo "Whole-host UDP/TCP counters (not tunnel-specific):"
    awk '/^(Udp|Tcp):/{print}' /proc/net/snmp 2>/dev/null || true
    echo "NIC queues (interface-specific):"
    if [[ -d "/sys/class/net/$dev/queues" ]]; then find "/sys/class/net/$dev/queues" -mindepth 1 -maxdepth 1 -printf '%f ' 2>/dev/null; echo; fi
    ip -s link show dev "$dev"
    echo "Interface details and MTU:"
    ip -d link show dev "$dev" || true
    # tc is diagnostic only; an absent/disappearing qdisc must not abort status.
    if command -v tc >/dev/null; then
        tc qdisc show dev "$dev" || echo "qdisc details unavailable (no changes made)"
    fi
    if [[ -r /proc/sys/net/netfilter/nf_conntrack_max ]]; then
        echo "Conntrack: $(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo n/a)/$(cat /proc/sys/net/netfilter/nf_conntrack_max)"
    else
        echo "Conntrack: module unavailable (no attempt to write nf_conntrack_max)"
    fi
    for setting in /proc/sys/net/core/rmem_max /proc/sys/net/core/wmem_max /proc/sys/net/core/netdev_max_backlog /proc/sys/net/ipv4/ip_forward; do
        [[ ! -r "$setting" ]] || echo "$setting=$(cat "$setting") (read-only report)"
    done
    [[ ! -r "$stats" ]] || { echo "ICMP core counters:"; cat "$stats"; echo; }
}
case "$ACTION" in
    status|analyze) status;;
    recommend|dry-run)
        status
        echo "Direct $type profile $PROFILE: original qlen=$cur; proposed qlen=$proposed"
        echo "Trade-off: a smaller queue may lower latency but increase drops; a larger one may buffer bursts but worsen tail latency."
        echo "Restart required: no. Rollback: optimizer.sh rollback $INSTANCE. Verify: matched-load RTT P95/P99, goodput, TUN tx_dropped."
        echo "Candidate command (NOT executed): ip link set dev $dev txqueuelen $proposed"
        echo "Experimental only. Lower kernel drop counts can mean longer queues and worse RTT."
        echo "Hypothetical, NOT certified: compare matched-load goodput, P95/P99, and drops."
        echo "GRE/FOU use kernel transport; no fake userspace transport is created."
        echo "No global sysctl, rp_filter, default route, firewall, qdisc, or other tunnel changed."
        if [[ "$PROFILE" == auto-adaptive ]]; then
            echo "Auto-adaptive is observation-only; no background controller is enabled."
        fi;;
    compare)
        status
        if [[ -r "$snap" ]]; then
            echo "Previous backup: $(cat "$snap")"
        else
            echo "No prior measurement/backup exists."
        fi
        echo "Compare RTT P95/P99, actual throughput and drops at matched load: this tool does not claim a speedup.";;
    apply)
        [[ $EUID -eq 0 ]] || { echo "root required for apply" >&2; exit 1; }
        [[ "$ACK" == --acknowledge ]] ||
            { echo "Explicit opt-in required: optimizer.sh apply $INSTANCE $PROFILE --acknowledge" >&2; exit 2; }
        [[ "$dev" == ts-* || "$dev" =~ ^ts[0-9]{4,}$ ]] ||
            { echo "non-owned-looking interface, refusing change: $dev" >&2; exit 1; }
        [[ "$proposed" != "$cur" ]] ||
            { echo "Balanced/no-op: queue unchanged; no snapshot created"; exit 0; }
        mkdir -p "$backup_dir"
        if [[ ! -f "$snap" ]]; then
            printf '%s %s %s %s\n' "$dev" "$cur" "$PROFILE" "$(date -u +%FT%TZ)" > "$snap.tmp"
            mv -f "$snap.tmp" "$snap"
        fi
        ip link set dev "$dev" txqueuelen "$proposed"
        updated="$(get_qlen)"
        [[ "$updated" == "$proposed" ]] ||
            { ip link set dev "$dev" txqueuelen "$cur" || true; echo "update validation failed" >&2; exit 1; }
        echo "$PROFILE applied to $dev: qlen $cur -> $updated; snapshot: $snap"
        echo "No claim of improvement: compare with equivalent traffic and tail-latency samples.";;
    rollback)
        [[ $EUID -eq 0 ]] || { echo "root required for rollback" >&2; exit 1; }
        [[ -r "$snap" ]] || { echo "no backup for $INSTANCE" >&2; exit 1; }
        read -r olddev before _ < "$snap"
        [[ "$olddev" == "$dev" && "$before" =~ ^[0-9]+$ ]] ||
            { echo "backup does not match this interface" >&2; exit 1; }
        [[ "$dev" == ts-* || "$dev" =~ ^ts[0-9]{4,}$ ]] ||
            { echo "non-owned interface: rollback refused" >&2; exit 1; }
        ip link set dev "$dev" txqueuelen "$before"
        [[ "$(get_qlen)" == "$before" ]] || { echo "rollback validation failed" >&2; exit 1; }
        rm -f "$snap"
        echo "Rolled back $dev TUN queue length to $before";;
esac