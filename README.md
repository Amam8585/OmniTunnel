# APADANA — Direct Tunnel Manager

> **Development build.** APADANA is the new project-facing name. The repository URL and internal `omnitunnel` / `omnitun` paths remain unchanged in this migration to avoid disrupting existing installations. A complete on-disk rename has **not** been performed.

APADANA manages direct point-to-point tunnels between Linux servers. The Bash manager creates per-instance configurations, systemd units and forwarding rules. The C core handles selected userspace transports. Kernel transports use Linux networking facilities.

## Install from the current repository

Review the installer before running it as root. On supported Ubuntu/Debian hosts:

```bash
curl -fsSLo /tmp/apadana-install.sh https://raw.githubusercontent.com/Amam8585/OmniTunnel/main/install.sh
sudo bash /tmp/apadana-install.sh --prepare
sudo bash /tmp/apadana-install.sh --check
sudo bash /tmp/apadana-install.sh --apply
sudo omnitunnel
```

**Important:** the commands above install the **released main branch**, not this unmerged rebranding PR. The installer stages and validates before applying, and does not automatically restart running tunnel services. Existing on-disk command name is `omnitunnel`.

## Currently supported NEW tunnel transports

| Choice | Dataplane | Requirement |
| --- | --- | --- |
| GRE | Linux kernel GRE | GRE/IP protocol 47 permitted between peers |
| ICMP | C userspace ICMP over TUN | Bidirectional ICMP path and raw-socket privileges |
| UDP | C userspace authenticated encrypted UDP/TUN | UDP path and shared key |
| Hysteria2 | External Hysteria2 QUIC engine | Compatible engine and UDP path |
| TCP | C userspace authenticated encrypted TCP/TUN | TCP path and shared key |
| FOU | Linux kernel GRE encapsulated over UDP | UDP path, kernel FOU support |

**Hybrid IG (GRE primary + ICMP fallback) is not implemented.** There is no tested automatic failover, shared-interface handoff or connection-continuity guarantee. It is not offered as a working transport.

Legacy MUX, WebSocket, Stripe, VXLAN and ACKLess may remain in the source and on existing hosts for compatibility; they are **not** choices for new tunnel creation. Dedicated Reverse is not supported.

## Interactive manager

```text
1) Install / Create Tunnel
2) Manage Tunnels
3) Port Forwarding
4) Network Optimization
5) Update OmniTunnel
6) Completely Uninstall OmniTunnel
7) Exit
```

The menu retains historical wording for actions that operate on the existing installer and service namespace. An operator creates a tunnel on one host and pairs the other host with the generated token. The manager uses systemd to supervise the services and iptables-based forwarding for applicable L3 transports. Hysteria2 uses a separate engine and forwarding model.

## Optimizer

```bash
sudo bash scripts/optimizer.sh status INSTANCE
sudo bash scripts/optimizer.sh recommend INSTANCE low-latency
sudo bash scripts/optimizer.sh dry-run INSTANCE high-throughput
sudo bash scripts/optimizer.sh apply INSTANCE low-latency --acknowledge
sudo bash scripts/optimizer.sh rollback INSTANCE
```

Available profiles: `balanced`, `low-latency`, `high-throughput`, `extreme-connections`, `high-pps`, `auto-adaptive`. The last three are currently **observation-only**, not a working adaptive controller. Apply changes only with explicit approval and after comparing measured latency, drops and throughput under equivalent load. No performance uplift has been verified.

## Source layout

- `omnitunnel.sh`: manager, pairing, services, forwarding and UI.
- `install.sh`: staged installer and rollback tooling.
- `src/icmptun.c`: ICMP userspace dataplane.
- `src/obsctun.c`: authenticated UDP dataplane.
- `src/obsctcp.c`: authenticated TCP dataplane.
- `scripts/optimizer.sh`: read-only recommendations and opt-in interface queue adjustment.
- `scripts/monitor.sh`, `scripts/diagnostics.sh`: runtime diagnostics.
- `tests/`: source and integration test scripts.

## Compatibility and migration policy

The rebrand intentionally preserves existing `/etc/omnitunnel`, `/var/lib/omnitunnel`, `/usr/local/bin/omnitun`, systemd `omnitun-*.service`, and the `omnitunnel` command. Blindly renaming these would break live instances, backups and upgrades. A future full namespace migration requires an explicit compatibility strategy, reversible installer, and tests against existing deployments.

## Verification

This README describes implemented behavior, **not benchmark results**. A two-host lab, supported-kernel coverage, GCC/Clang/sanitizer builds, installer tests, forwarding tests and reconnection tests are required before calling the rebrand or Hybrid IG production-ready. No throughput, PPS, concurrency or failover claims are made.

Repository: https://github.com/Amam8585/OmniTunnel
