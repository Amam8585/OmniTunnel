# OmniTunnel

**Linux tunnel manager — development release**

OmniTunnel manages point-to-point tunnels between two Linux servers, with instance management, systemd services, and port forwarding. This README describes the **current development branch**, not a completed Hybrid IG release.

> **Release status:** UI and new-tunnel transport selection have been updated. **Hybrid IG (GRE primary + ICMP fallback) is planned but NOT implemented.** Do not assume automatic failover works. Production deployment and cross-server interoperability testing have not been completed for this branch.

## Supported choices for NEW tunnels

| Transport | Type | Notes |
| --- | --- | --- |
| GRE | Kernel GRE (IP protocol 47) | Requires bidirectional GRE reachability |
| ICMP | Userspace ICMP/TUN | Requires permitted ICMP traffic |
| UDP | Encrypted UDP/TUN | Requires bidirectional UDP reachability |
| Hysteria2 | QUIC-based transport | UDP-based; implementation has distinct forwarding behavior |
| TCP | Encrypted TCP/TUN | TCP carrier |
| FOU | GRE encapsulated in UDP (kernel) | Requires bidirectional UDP on selected port |

**Planned menu order:** GRE, ICMP, Hybrid IG, UDP, Hysteria2, TCP, FOU. The actual development branch currently lists **six** options, because Hybrid IG does not have a working engine yet.

**Removed from new-tunnel selection:** TCP MUX, WebSocket, TCP Stripe, VXLAN, ACKLess. Existing instances of retired transports are **not** automatically removed or migrated. Some legacy code and assets remain for compatibility; removal from the menu does not mean all related source files have been deleted.

## Main menu

```text
1) Install / Create Tunnel
2) Manage Tunnels
3) Port Forwarding
4) Network Optimization
5) Update OmniTunnel
6) Uninstall OmniTunnel
7) Exit
```

The former main-menu entries **Status & Monitoring** and **Diagnostics & Benchmark** were removed. Status information remains visible in the dashboard and tunnel management. Some CLI diagnostics and benchmark functions may still exist internally.

## Dashboard

The dashboard reports live values detected on the local machine, for example:

```text
OMNITUNNEL
Server:       <public-ip> · amd64
Tunnels:      1 online · 0 offline
Forwards:     0
Core:         Ready
Forwarding:   Boot override detected (/etc/sysctl.d/...)
```

The forwarding warning is intentional: another sysctl configuration may override forwarding settings at boot. **Do not ignore it** when forwarding stops working after a reboot. Use `omnitunnel fix-forwarding` only after reviewing conflicting system-wide sysctl configuration.

## Requirements

- Linux: Ubuntu 22.04 / 24.04 or Debian 12 / 13 (as accepted by `install.sh`)
- Root privileges
- amd64 or arm64
- Two servers with routable addresses and an allowed carrier protocol
- `curl`, systemd, and other installer-managed dependencies

## Installation — staged and cautious

The installer supports **prepare → check → apply**. `--prepare` stages and validates files; it **does not activate** the staged build. `--apply` activates the prepared build and is designed not to restart existing tunnel services automatically.

**Development branch:**

```bash
export OMNITUN_REF=release/ui-forwarding-hardening-20261012
curl -fsSLo /tmp/omnitunnel-install.sh "https://raw.githubusercontent.com/Amam8585/OmniTunnel/$OMNITUN_REF/install.sh"
sudo -E bash /tmp/omnitunnel-install.sh --prepare
sudo -E bash /tmp/omnitunnel-install.sh --check
sudo -E bash /tmp/omnitunnel-install.sh --apply
```

Review the installer and its output before applying it. On active servers, installation may require explicit `--allow-active`; see `--help` and make a backup first. **The development branch has not been production-validated.**

## Create a tunnel (manual token pairing)

1. Install the **same revision** on both servers.
2. On the first server, run `sudo omnitunnel`, choose **Install / Create Tunnel**, then select a supported transport.
3. Enter the local public IP, foreign public IP, and instance name. The manager prints a pairing token.
4. On the foreign server, run:

```bash
sudo omnitunnel server-token '<TOKEN_FROM_FIRST_SERVER>'
```

5. Check status and test the tunnel IPs in both directions before adding forwarding rules.

Manual token pairing does **not** require SSH credentials for the foreign host. Never paste a real pairing token into a public issue or chat.

## Manage instances and forwarding

```bash
sudo omnitunnel
sudo omnitunnel list
sudo omnitunnel status <instance>
sudo omnitunnel pf-add <instance> <tcp|udp|both> <port>
sudo omnitunnel pf-del <instance> <port>
sudo omnitunnel fix-forwarding
```

Forwarding requires a healthy tunnel, correct routes, permitted firewall traffic, and IPv4 forwarding. Adding rules does not increase the bandwidth available from the underlying network.

## Hybrid IG — planned, not available

The intended design is **GRE as the primary path** and **ICMP only as fallback** when GRE is down or degraded. A production implementation still requires:

- A real shared logical interface and a separately implemented failover controller/engine.
- Bidirectional health checks, hysteresis, safe switchover and return to GRE.
- Packet ordering and connection continuity validation across both carriers.
- Installation and service lifecycle integration, token pairing and removal support.
- Two-host failover, reboot, routing and load tests.

**There is currently no Hybrid IG binary or verified working Hybrid IG transport in this branch.** No zero-downtime failover, guaranteed TCP session preservation, or speed increase is claimed.

## Safety and compatibility

- Do not overwrite or delete existing tunnel configurations just to change transport menus.
- Review `/etc/omnitunnel/inst/` and back up state before upgrades.
- Keep an out-of-band SSH/console path when changing network routes.
- Test GRE, ICMP, UDP and other carriers on your own path; ISP filtering differs.
- This branch has not been merged into `main` as a finalized release.

## Source

Repository: https://github.com/Amam8585/OmniTunnel

Development branch: `release/ui-forwarding-hardening-20261012`

License and third-party notices: consult repository source and bundled components.
