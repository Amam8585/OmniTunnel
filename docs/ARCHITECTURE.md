# OmniTunnel Direct: baseline architecture and dependency map

Baseline reviewed: `main` tree `0588e3b86c25cd647f3f1055739c5a4626ec3ba8`. Changes isolated to `refactor/direct-only-icmp-performance`; the original deployed binary and network were **not inspected or modified**.

## Architecture / ownership

| Component | Responsibility | Dependencies |
| --- | --- | --- |
| `install.sh` | Ubuntu/Debian prerequisite checks, compile, stage, explicit activation, local program backups/rollback | GCC, libc headers, iproute2, Bash, curl |
| `omnitunnel.sh` | Direct tunnel instance creation, per-instance config under `/etc/omnitunnel/inst`, systemd units, SSH provision, individual forwarding | omnitun C, Go engines, iproute2, systemd, iptables |
| `src/main.c` | Dispatch five C Direct transports without network logic | `obsctun.c, obsctcp.c, obscmux.c, obscws.c, icmptun.c` |
| `src/obsctun.c` | Direct UDP carrier; authenticated encryption | monocypher and `tcrypto.h` |
| `src/obsctcp.c` | Direct TCP carrier; authenticated encryption | shared crypto/TUN facilities |
| `src/obscmux.c` | **Direct** multi-connection TCP carrier (not Chisel Reverse); MUST retain | C crypto, socket/TUN |
| `src/obscws.c` | **Direct** WebSocket carrier; MUST retain | C crypto, sockets |
| `src/icmptun.c` | **Direct** ICMP echo encapsulation, TUN ioctl creation, raw socket, epoll, flow hash/reorder, bounded queues | Linux ICMP and TUN kernel interfaces |
| `src/monocypher.{c,h}`, `src/tcrypto.h` | Shared cryptography for keyed C Direct transports | C code above |
| `src/omnistripe/` and `src/omniackless/` | Go Direct carriers | Go toolchain for rebuild |
| `bin/hysteria-{amd64,arm64}` | Hysteria Direct QUIC engine; package binary retained | vendor Go binary; version pin/integrity should be independently audited |
| `bin/omnitun-*` | Historical compiled C artifacts; new installer builds from reviewed sources rather than using historical C binaries | not canonical build inputs |
| `bin/chisel-*` | Former Reverse-MUX only, no Direct dependent; obsolete in Direct-only branch | not installed by Direct installer |
| `icmptun-ctl.sh` | **Separate legacy ICMP Direct manager** containing an embedded C implementation in its `write_source()`. Kept to preserve backwards compatibility; not switched to new `src/icmptun.c` | GCC, iptables, systemd |
| `scripts/{monitor,optimizer,diagnostics}.sh` | ICMP introspection and constrained optional TUN setting changes | procfs, Python 3, iproute2 |
| `tests/` | Shell regression, C sanitizer regression, Go upstream tests | Bash, GCC, Go |
| `.github/workflows/ci.yml` | PR CI definition; not proof of successful execution until Actions checks complete | GitHub Actions |

## Kernel and packet path

Outgoing **Direct ICMP**:
`host route/TCP/UDP -> Linux TUN (IFF_TUN|IFF_NO_PI via /dev/net/tun and TUNSETIFF) -> non-blocking read -> five-tuple flow lookup -> per-flow sequence -> ICMP Echo Request/Reply encapsulation -> bounded TX ring -> sendto(SOCK_RAW, IPPROTO_ICMP) -> kernel/IP/network`.

Incoming:
`raw ICMP socket -> non-blocking recvfrom -> source IP and ICMP id/type checks -> inner IPv4 length -> per-flow sequence/reordering -> bounded TUN write queue -> Linux TUN -> kernel routes, TCP/UDP sockets`.

The C code uses `epoll_wait` for fair readiness-driven bounded batches and EPOLLOUT only when send/TUN buffers signal backpressure. `flow_table` and `timer_heap` have dynamic memory capacity but no new protocol bytes. The inner payload and sequence field retain their original format.

All other **Direct** transports are selected by `ALL_TYPES`: `gre icmp udp mux ws hysteria tcp fou vxlan stripe ackless`. Kernel native GRE/FOU/VXLAN use `ip link` and kernel tunnel encapsulation. Go stripe/ackless and Hysteria use their own executables. Direct forwarding maps packet flows with per-instance iptables chains in the manager; no global `iptables -F` was introduced by this branch.

## Dedicated Reverse removed

`reverse-mux` was specifically built from a forced-Reply ICMP carrier + **Chisel `server --reverse` and Chisel client**. Its dedicated service creation, token/mux-forward management, menu, type registration and benchmark path were removed. Direct `mux` and ordinary ICMP `-r reply|request` were **not removed**. The C Direct engines had no distinct Reverse implementation to delete.

Older live Chisel systemd instances are **not automatically stopped** by installing this branch. The manager only removes an old reverse service when an administrator explicitly deletes its corresponding instance. Any migrated instance having `TYPE=reverse-mux` cannot be newly recreated on this branch and requires an explicit migration plan.

## Observed and unproven bottlenecks

The earlier `read(TUN)` and `recvfrom(ICMP)` loops drained to EAGAIN, potentially starving outbound queue flushing. The ring queue logged each individual overflow (expensive log storms), ignored TUN short/EAGAIN writes, and returned from sendto EAGAIN without registering EPOLLOUT. These are **code-verified failure modes** addressed in the development branch. They are not proof the production network dropped packets for those reasons.

The original fork's ICMP flow table was 256 buckets x 4 = 1024 entries, *not* the 16,384 entries reportedly installed on production hosts. The extra capacity can be selected via `-F` but is not asserted to improve throughput. Flow eviction and out-of-window sequence resynchronization may still have nontrivial retransmission effects. Congestion at datacenter routers, kernel qdisc/softirq and network ICMP policing cannot be assessed by reading repository code.

## Compatibility and risks

No ICMP wire format change was intentional. New `-F` is local-only. Base ICMP identifier, per-flow sequence logic, role and reply override semantics remain.

Unlike keyed UDP/TCP transports, **Direct ICMP does not authenticate or encrypt inner packets**. Source IP and ICMP identifier checks are not cryptographic authentication. An opt-in negotiated secure mode remains future work.

TUN write buffering and scheduler fairness are nontrivial protocol-path changes; lab two-peer interoperability, error-injection and load benchmarking are still required before considering production rollout.
