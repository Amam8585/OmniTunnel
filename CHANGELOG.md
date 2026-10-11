# Changelog

## Phase 3 — experimental (2026-10-12; NOT PRODUCTION READY)

- Corrected optimizer literal newline and added mock-ip runtime tests.
- Installer: exclusive state lock, unknown-commit downgrade guard, multi-point
  fault injection and tests for automatic/manual rollback.
- ICMP: detect oversized/GSO frames with 64KiB TUN reads, bound epoll TUN
  intake during ICMP backpressure, count queue pauses and lookup probes.
- WebSocket: validate Sec-WebSocket-Accept, RFC masks/lengths/FIN, serialized
  Pong, opt-in legacy server compatibility. Fragmentation unsupported.
- Forwarding: pre-build private DNAT/SNAT/FORWARD generations; attach new
  chains before retiring old, with SNAT scoped by conntrack original tuple.
  Not an atomic cross-table nftables transaction, NOT live-tested.
- Monitoring: expose stale snapshots, counter resets and unknown goodput.
- New offline C/Go microbenchmark and Python CI jobs; performance NOT measured.
- No production servers, routes or active tunnel processes touched.

**Blockers:** GitHub Actions runs total=0, no validated C/Go builds, installer
integration, netfilter namespace test, two-peer compatibility or high-load A/B
benchmark. Pull Request remains draft; no production-ready claim.

## Unreleased — experimental Direct-only branch (2026-10-11)

- Documented baseline main commit and Direct/Reverse dependency map.
- Preserved all eleven Direct choices: GRE, ICMP, UDP, TCP, MUX, WS, Hysteria, FOU, VXLAN, Stripe and ACKLess.
- Removed creation and menu/CLI hooks for Reverse-MUX and Chisel reverse forwarding; legacy stopped/active reverse instances are **not** removed by updating.
- Staged source-build installer with Ubuntu 22.04/24.04 and Debian 12/13 validation, prerequisite checks, snapshots, rollback and explicit no-restart apply.
- Direct ICMP: bounded epoll RX batches, paced TX flushing, readiness-based nonblocking send and TUN delivery under EAGAIN, bounded queues and counters; optional per-instance `-F` flow-table capacity 1024–65536. **No wire-format changes intended.**
- Readable/JSON ICMP metrics, read-only diagnostics, and conservative ICMP-only queue-length optimizer with dry-run/backup/rollback.
- New C offline sanitizer test, Direct transport regression test and Ubuntu CI job.
- Benchmark/testing instructions; no production tests or performance improvement claims.

### Known limitations

- Lab build/CI outcome and multi-server interoperability need to be confirmed.
- No actual benchmark before/after has been measured; performance tuning effectiveness is unproven.
- The separate legacy `icmptun-ctl.sh` embeds older C; new C changes affect only the OmniTunnel C dispatch path.
- Legacy kernel/sysctl/iptables code paths in `omnitunnel.sh` need further per-instance ownership/rollback auditing.
- ICMP remains unauthenticated and unencrypted. A secure version is future work.
- No multithreading, recvmmsg/sendmmsg or automatic adaptive AQM implemented; these require profiling evidence and safe protocol ordering tests.
