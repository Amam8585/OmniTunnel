# Changelog

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
