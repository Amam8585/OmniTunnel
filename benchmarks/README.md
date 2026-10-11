# Direct ICMP fair-load benchmark protocol

**Status: protocol defined, test results NOT available.** No stress testing was run against the operating Iran/foreign servers or their users.

## Test environment

Use **two isolated, authorized machines** (or namespaces/VMs with CAP_NET_RAW and TUN); record CPU topology, kernel, NIC, physical link quality, TUN MTU, TCP MSS, qdisc, CPU affinity, host and tunnel routing and conntrack. Verify both peers, one on baseline commit `0588e3b8`, both on candidate commit, and mixed-version interoperability. Do not generate traffic on user-facing production addresses.

Record three independent runs for each configuration, randomize test order if possible, keep offered load and paths identical. Use `iperf3` to measure TCP goodput with 100, 1,000 and optionally 5,000+ legal independent connections, bounded by sender CPU, file descriptors, and the test network; do **not** assume 30k stable sessions. Use configured rate/parallel streams for approximate 50/100/200/300/400 Mbps steps. The offered load is distinct from achieved throughput. Change only ONE parameter per A/B comparison.

## Record for each run

- Sender offered PPS, TUN `ip -s link` RX/TX/drop counters, raw socket ICMP errors, `/proc/net/softnet_stat`, `tc -s qdisc`, NIC queue counters.
- Application goodput; total bytes and matched wall time.
- ICMP internal JSON metric snapshots every second: receive/send rates, queue depth/high water, queue drop, flow active/collision/eviction, reordered packets, receive/send/write errors, memory allocation failures.
- TCP `ss -s`, retransmits via `nstat -az`/Linux TCP `/proc/net/netstat`, conntrack utilization.
- CPU `pidstat -u -r -p <pid> 1` or `perf stat -p <pid>` (with privilege); process RSS, major/minor faults.
- Unloaded RTT baseline and concurrent latency samples (at least hundreds of ICMP pings or an application-level timed request stream); compute P50/P95/P99 and packet-loss confidence intervals, not a single 10-packet run.

## Procedure and pass/fail

1. Confirm baseline and candidate have exactly the same peer IP, MTU 1320, TCP MSS 1280 and direct ICMP mode/ID (or document differences).
2. Record idle RTT for >=60s and samples under steady matched load.
3. Capture baseline 3x; then candidate 3x; reboot only in the disposable lab for service persistence testing.
4. Repeat with ICMP flow table capacities 1024 (baseline fork), 16384, 32768 and 65536 **one at a time**. Capture RSS; avoid OOM because 65k flows x 256 reorder slots is substantial memory.
5. Test hard packet bursts, reordering and capacity pressure under strict traffic limits; log queue saturation and scheduler fairness.
6. Introduce a controlled temporary peer outage in the lab; verify recovery, no stale flows, and no unsafe service restart loops.
7. Record mean ± spread, throughput/goodput, TX drop %, RTT P95/P99, losses, CPU%, RSS, and regressions for both ends. For each profile, reject a purported throughput gain if meaningful tail latency or loss worsens.

## Useful local commands (lab only)

```bash
ip -s link show ic79
tc -s qdisc show dev ic79
ss -s
nstat -az
sudo omnitunnel stats INSTANCE --json
sudo omnitunnel monitor INSTANCE --json
sudo omnitunnel diagnostics INSTANCE
```

Total TCP connections on the whole host are **not** equal to active ICMP flow keys or active users. The user's 10-second TX drop rates and 10-sample RTT measurements are insufficient to prove cause or improvement. No benchmark figures are fabricated in this project.
