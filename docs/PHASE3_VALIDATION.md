# OmniTunnel Direct — Phase 3 verification ledger

Baseline: main commit 6dc2800afe2c2887a08c5c935a93c39087396649.
Branch: phase3/direct-reliability-validation. Status: **EXPERIMENTAL / NOT PRODUCTION READY**.
Production Iran/foreign hosts were NOT contacted and NO live stress tests were run.

## Code changes committed

- Fixed literal newline escape in the optimizer status command; added runnable mock-ip
  status/analyze/recommend/dry-run/compare/apply/rollback regression.
- Staging installer retains source commit, build manifest and SHA256 checks. Added an
  exclusive staging/activation lock and fail-closed checks when local-build SHA lineage
  is unavailable. Test-only failure checkpoints simulate binary overwrite,
  manager overwrite, partial manager write and post-copy failure.
- ICMP uses a full 65536-byte TUN read scratch buffer and explicitly counts oversized
  or GSO frames (rather than silently truncating with a 1500-byte buffer). Under raw
  socket backpressure, new TUN reads are paused in epoll at a bounded high watermark
  and resumed at half that watermark. Memory remains bounded. No wire-format change.
- ICMP cumulative counters cover oversized TUN frames, ring pressure, TUN pauses,
  flow lookup probes and flow table byte footprint. Wrapped sequence/reorder and
  timer exhaustion have offline regression test cases.
- Crypto entropy: replacing the deterministic emergency nonce fallback in tcrypto.h with fail-closed kernel CSPRNG, with a mock failure test (unexecuted); WebSocket now batches cryptographic masking keys.\n- WebSocket validates Sec-WebSocket-Accept, 64-bit lengths, RSV/FIN, client masks,
  and serialized Ping/Pong. A previous non-RFC server sent a hardcoded Accept value:
  connecting a Phase 3 client to such an old server requires an explicit
  OMNITUN_WS_ALLOW_LEGACY_ACCEPT=1 compatibility exception after review.
  This legacy bypass relaxes only HTTP Upgrade validation; it does not bypass
  inner AEAD authentication. It must NOT be enabled broadly or permanently.
  Full RFC6455 fragmentation remains unsupported, so this is NOT a general
  purpose browser-facing RFC6455 server.
- Forwarding now pre-builds private DNAT, SNAT and FILTER chains while old hooks
  continue serving traffic, then adds new hooks and retires old owned hooks. SNAT
  additionally matches conntrack original public-IP/public-port. The transition
  across three netfilter hooks is NOT a single atomic nftables transaction and
  has NOT been verified against live policy/firewall variants. Post-crash
  reconciliation and an atomic nftables backend remain future acceptance gates.
- Monitoring marks stale/unknown metrics and process restarts; kernel interface
  drops, internal drops, measured application goodput and RTT are separate fields.
- Go synthetic microbenchmarks and offline C flow-table capacity/memory study were
  added to CI. They are NOT packet forwarding load tests.

## Verification status

| Verification | Status | Evidence / blocker |
| --- | --- | --- |
| Source reviewed from baseline | PASS | GitHub baseline and branch diff inspected |
| Actual GitHub commits in separate branch | PASS | GitHub commit history |
| Optimizer Bash correction | PASS (source inspection) | Escaped literal replaced by physical newline |
| Bash runtime + installer transactional tests | NOT TESTED | CI defined; no executable CI run available |
| C GCC and Clang builds | NOT TESTED | Workflow configured; no successful run |
| ASan/UBSan and WS interoperability regression | NOT TESTED | Workflow/test source present; not executed |
| Go test, race, vet, CPU/heap profiles | NOT TESTED | Workflow configured; no successful run |
| GitHub Actions jobs | BLOCKED | GET actions/runs returned total_count=0 even after PR; no dispatch/configuration write action exposed by connected GitHub interface |
| Two-peer new/new old/new compatibility | NOT TESTED | No isolated pair authorized/available |
| Mixed version WS compatibility | NOT TESTED | Old fixed Accept now requires explicit opt-in |
| Port forwarding on real nft/iptables kernels | NOT TESTED | Mock test exists, but no privileged network namespaces used |
| High-load 100–30,000 connection benchmark | NOT TESTED | No lab hardware/test results |
| Production-ready classification | FAIL | Acceptance gate not met |

No throughput, packet-loss, jitter, or tail-latency percentage is asserted.

## Offline validation commands for authorized lab

Run from the checked-out Phase 3 branch on a disposable Ubuntu/Debian VM:

    bash -n install.sh omnitunnel.sh scripts/*.sh
    python3 tests/shell_escape_regression.py
    python3 -m unittest discover -s benchmarks -p 'test_*.py' -v
    bash tests/pf_mapping_test.sh
    sudo bash tests/optimizer_runtime_test.sh
    sudo bash tests/installer_integration_test.sh
    gcc -O1 -g -Wall -Wextra -fsanitize=address,undefined -fno-omit-frame-pointer -o /tmp/icmp-offline tests/icmptun_core_test.c
    ASAN_OPTIONS=detect_leaks=1 /tmp/icmp-offline
    gcc -O1 -g -Wall -Wextra -fsanitize=address,undefined -fno-omit-frame-pointer -o /tmp/ws-offline tests/ws_handshake_test.c src/monocypher.c -pthread
    ASAN_OPTIONS=detect_leaks=1 /tmp/ws-offline
    gcc -O2 -o /tmp/icmp-micro tests/icmptun_microbench.c && /tmp/icmp-micro
    ( cd src/omnistripe && go test -race ./... && go vet ./... )
    ( cd src/omniackless && go test -race ./... && go vet ./... )

To stage the exact candidate, inspect its Git commit SHA in the GitHub PR first:

    curl -fsSL https://raw.githubusercontent.com/Amam8585/OmniTunnel/phase3/direct-reliability-validation/install.sh -o /tmp/omni-phase3-installer.sh
    sudo env OMNITUN_REF=<REVIEWED_40_CHARACTER_COMMIT_SHA> bash /tmp/omni-phase3-installer.sh --prepare

The command does not apply programs, restart services or touch live routes. Examine
the resulting release manifest and SHA256 hashes; then use the SAME reviewed
installer with --apply **only** on a disposable lab VM after all offline tests pass.

Rollback procedure on lab VM:

    sudo bash /tmp/omni-phase3-installer.sh --check
    sudo bash /tmp/omni-phase3-installer.sh --backup
    sudo bash /tmp/omni-phase3-installer.sh --rollback

Rollback restores local installed files; running processes are not restarted.
For live network rollback, do not assume binaries alone undo kernel routing,
active tunnel interfaces, iptables state or application protocol changes. Verify
pair connectivity and return paths separately.

## Required next acceptance work

1. Enable GitHub Actions in repository settings, run all workflow jobs and capture
   full logs. A workflow YAML file with zero runs is not CI evidence.
2. Correct any CI failures, especially C/Go sanitizer, shell, compiler or test
   fixture failures; repeat until every required job is green.
3. Add stateful Linux network namespace netfilter tests (including rollback after
   injected multi-hook failure), systemd old-unit tests and crash recovery tests.
4. Profile per-stage ICMP processing cost with perf/pidstat and measured queue
   residence time in an isolated two-peer network.
5. Run new/new and old/new interoperability, with explicit WS legacy-switch cases.
6. Only then conduct three or more controlled A/B tests at equal offered
   TCP/UDP load, reporting application goodput, RTT P95/P99, RSS and drops.
7. Verify reversible installation and nftables/firewall ownership after reboot.
