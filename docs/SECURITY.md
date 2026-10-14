# Direct carrier security model

The Direct transports are not all equivalent security protocols.

**Direct ICMP is NOT authenticated or encrypted.** The code checks IPv4 source address, a 16-bit ICMP identifier, echo request/reply and packet lengths, but an active attacker able to spoof relevant packets or observe the path may inject or inspect traffic. Per-flow sequence numbers are not a replay-protection cryptographic nonce. Treat this as a network transport, not an end-to-end secure VPN. Encrypt sensitive traffic end-to-end (for example Xray TLS or a suitably configured secure VPN).

The C UDP/TCP/mux/WS keyed paths use Monocypher and must be audited separately. Legacy binaries and source code are not automatically attested; do not assume that a prebuilt executable matches its source unless proven. Client/server mode and key distribution must not be printed in verbose logs.

No new wire encryption handshake, peer authentication or mandatory framing was introduced by this PR. A future secure ICMP version needs an explicitly versioned opt-in handshake, authenticated replay window, key rotation and compatibility testing.

Counter snapshots never include packet contents; they are stored under `/run/omnitunnel/icmp-<dev>.json` (in a private runtime directory) and rotate once per second. `-v` still writes debug metadata and should be disabled in production. Runtime metrics are diagnostic estimates and not suitable as a security audit log.

Do not run privileged remote installers without reviewing and pinning their commit. No code here changes sshd configuration, the default route or flushes an unrelated host's firewall as part of routine installation.

Reverse removal does not automatically kill old Chisel units. Audit existing `omnitun-*-mux.service` on a controlled maintenance window; cleanup an explicitly retired instance only after verifying ownership and user impact.

The legacy ICMP manager `icmptun-ctl.sh` uses the maintained core; its historical embedded source is retired. Its configuration and service lifecycle remain separate. Do not mix its units and the new manager under the same interface name.

## Phase 3 — WebSocket compatibility and firewall caveats

New Direct WebSocket clients verify the actual RFC 6455
Sec-WebSocket-Accept derived from the random request key. Earlier releases
used one hardcoded digest. The explicit, narrow
OMNITUN_WS_ALLOW_LEGACY_ACCEPT=1 environment variable accepts only that
known digest, and is not recommended for a public-facing listener. It does
not disable the inner transport's AEAD checks, but it weakens HTTP Upgrade
validation. Binary fragmented messages are assembled up to MAX_FRAME bytes; unexpected
continuations, nested messages and oversized assemblies are rejected. Text messages
are not tunnel packets and remain unsupported. This is not a general-purpose WebSocket endpoint.

Forwarding uses staged private iptables chains; a successful staged
prepare protects the old generation from an in-place chain flush. The
multi-hook switch across NAT and FILTER is not a single nftables atomic
transaction and is not yet proven correct under external firewall managers,
hard system crashes or high concurrency. Inspect chain ownership before
deleting anything; never globally flush iptables/nftables.

No Phase 3 C or Go sanitizer result, network security penetration result,
or two-peer encrypted compatibility validation has been confirmed.

## Fail-closed cryptographic entropy (Phase 3)

The old `src/tcrypto.h` generated predictable nonce bytes if `/dev/urandom` could not be read. Phase 3 uses kernel `getrandom()` with kernel `/dev/urandom` fallback, and terminates rather than using deterministic values if neither CSPRNG is available. This protects the existing XChaCha20-Poly1305 nonce generation path without changing packet wire bytes. A mock failure-injection regression was committed but has **NOT yet passed CI**.

The WebSocket mask generator now preloads 4,096 bytes of kernel CSPRNG material rather than advancing a reversible xorshift state. Failure to obtain entropy is fatal. No security guarantee is claimed until tests and cryptographic review pass.
