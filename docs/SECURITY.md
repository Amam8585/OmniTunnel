# Direct carrier security model

The Direct transports are not all equivalent security protocols.

**Direct ICMP is NOT authenticated or encrypted.** The code checks IPv4 source address, a 16-bit ICMP identifier, echo request/reply and packet lengths, but an active attacker able to spoof relevant packets or observe the path may inject or inspect traffic. Per-flow sequence numbers are not a replay-protection cryptographic nonce. Treat this as a network transport, not an end-to-end secure VPN. Encrypt sensitive traffic end-to-end (for example Xray TLS or a suitably configured secure VPN).

The C UDP/TCP/mux/WS keyed paths use Monocypher and must be audited separately. Legacy binaries and source code are not automatically attested; do not assume that a prebuilt executable matches its source unless proven. Client/server mode and key distribution must not be printed in verbose logs.

No new wire encryption handshake, peer authentication or mandatory framing was introduced by this PR. A future secure ICMP version needs an explicitly versioned opt-in handshake, authenticated replay window, key rotation and compatibility testing.

Counter snapshots never include packet contents; they are stored under `/run/omnitunnel/icmp-<dev>.json` (in a private runtime directory) and rotate once per second. `-v` still writes debug metadata and should be disabled in production. Runtime metrics are diagnostic estimates and not suitable as a security audit log.

Do not run privileged remote installers without reviewing and pinning their commit. No code here changes sshd configuration, the default route or flushes an unrelated host's firewall as part of routine installation.

Reverse removal does not automatically kill old Chisel units. Audit existing `omnitun-*-mux.service` on a controlled maintenance window; cleanup an explicitly retired instance only after verifying ownership and user impact.

The legacy ICMP manager `icmptun-ctl.sh` retains independent embedded code and older behavior; this PR did not rewrite it to share the new implementation. Do not mix its units and the new manager under the same interface name.
