# OmniTunnel Direct — experimental development branch

> **Do not deploy to a production Xray tunnel yet.** This branch changes the ICMP packet-processing loop and needs a successful build, lab two-peer interoperability test, safe restart testing and repeatable A/B load benchmarks. No improvement in Mbps, latency or packet drops is claimed.

OmniTunnel is a Linux multi-carrier **Direct** tunnel manager. It preserves all eleven existing Direct transports:

| Direct transport | Implementation | Status |
| --- | --- | --- |
| ICMP | `src/icmptun.c`: C raw ICMP + Linux TUN | Preserved; experimental scheduler and monitoring changes |
| UDP | `src/obsctun.c`: C encrypted UDP | Preserved |
| TCP | `src/obsctcp.c`: C encrypted TCP | Preserved |
| MUX | `src/obscmux.c`: C parallel **Direct TCP** | Preserved, **not** Reverse |
| WS | `src/obscws.c`: Direct WebSocket | Preserved |
| GRE | Linux kernel | Preserved |
| FOU | Linux GRE-over-UDP | Preserved |
| VXLAN | Linux kernel | Preserved |
| Hysteria | Standalone Hysteria QUIC engine | Preserved |
| Stripe | `src/omnistripe` Go engine | Preserved |
| ACKLess | `src/omniackless` Go engine | Preserved |

The former **Reverse-MUX/Chisel** mechanism, its manager commands and service creation have been removed from this branch. Existing reverse units are NOT terminated by installing it. No Direct type was converted to Reverse.

## Safe source-build staging

Run on a disposable VM, not the production pair:

```bash
OMNITUN_REF=refactor/direct-only-icmp-performance bash <(curl -fsSL https://raw.githubusercontent.com/Amam8585/OmniTunnel/refactor/direct-only-icmp-performance/install.sh) --prepare
```

The installer detects Ubuntu 22.04/24.04 or Debian 12/13 and CPU architecture, installs missing build packages, builds C from source, validates it and stages it. **It does not restart or replace running services.** Only after verifying the build and scheduling maintenance should you use `sudo bash install.sh --apply` from a local checkout. Applying while active instances are detected requires an additional explicit `--allow-active`, but even then there is **no automatic restart**.

For regular production users, remain on the working version until all tests pass. Do not apply an experimental build on both sides simultaneously.

## After lab installation

```bash
sudo omnitunnel                      # Direct tunnel manager
sudo omnitunnel list
sudo omnitunnel status INSTANCE
sudo omnitunnel stats INSTANCE       # ICMP counters, if instance TYPE=icmp
sudo omnitunnel stats INSTANCE --json
sudo omnitunnel monitor INSTANCE     # per-second deltas
sudo omnitunnel monitor INSTANCE --json
sudo omnitunnel diagnostics INSTANCE # read-only
sudo omnitunnel optimizer recommend INSTANCE balanced
sudo omnitunnel optimizer dry-run INSTANCE low-latency
```

Optional per-interface-only experimental queue tuning is explicit and reversible:

```bash
sudo omnitunnel optimizer apply INSTANCE balanced --acknowledge
sudo omnitunnel optimizer rollback INSTANCE
```

The optimizer's limited profiles change only that instance's **TUN txqueuelen** and deliberately do not write global network sysctls, change default routes, flush firewall rules or touch GRE, FOU and WireGuard devices. The values are hypotheses, not benchmark-certified. More aggressive multi-threading, kernel tuning and `recvmmsg/sendmmsg` require additional profiling.

For a **new** Direct ICMP instance only, `OMNITUN_ICMP_FLOW_SLOTS=16384` sets the per-process `-F` capacity at creation. Accepted powers of two range from 1024 to 65536. The original fork's actual default is **1024** (256 buckets × 4 ways); a reported larger flow table on a live host is a local fork/build difference and is not assumed here.

**Security notice:** Direct ICMP is plaintext and has no cryptographic peer authentication. An ICMP echo identifier and source-IP check are not sufficient authentication.

## Documentation

- [Architecture and ownership](docs/ARCHITECTURE.md)
- [Safe installer, updating and rollback](docs/INSTALL.md)
- [Benchmark methodology — no results claimed](benchmarks/README.md)
- [Direct security boundaries](docs/SECURITY.md)
- [Change log](CHANGELOG.md)

## Build and verification

```bash
gcc -O2 -Wall -Wextra -o /tmp/omnitun \
    src/main.c src/obsctun.c src/obsctcp.c src/obscmux.c src/obscws.c \
    src/icmptun.c src/monocypher.c -pthread

/tmp/omnitun version
for t in tests/*.sh; do bash "$t"; done
gcc -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
    -o /tmp/icmptun-core-test tests/icmptun_core_test.c
/tmp/icmptun-core-test
```

Building and passing offline unit tests is necessary but **not** a claim of two-host connectivity or a throughput improvement. Never run the old builtin multi-protocol benchmark on a live server without explicit capacity permission; it creates temporary units and traffic.

Legacy `icmptun-ctl.sh` is a separate manager with its own embedded C; this branch does not silently replace the legacy core.
