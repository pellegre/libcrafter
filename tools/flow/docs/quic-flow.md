# QUIC Flows

`crafter-flow` has two deliberately different QUIC surfaces: packet-oriented
Initial-only flows and optional authenticated endpoint flows. The first surface
is useful for inspecting QUIC Initial behavior without claiming a connection;
the second delegates a bounded connection to a private protocol provider.

## Initial-only flows

`crafter-flow` provides two explicitly named bounded entrypoints:
`quic_initial_client_flow(QuicInitialClientConfig)` and
`quic_initial_server_flow(QuicInitialServerConfig)`. They construct typed
`Ipv4 / Udp / Quic` packet stacks, protect QUIC version 1 Initial packets, and
inspect protected Initial responses. **CRYPTO frame bytes are opaque test data,
and a successful Initial-only run does not establish a TLS session or a QUIC
endpoint.** In particular, `InitialObserved` is not `Established`.

These flows are for packet-level inspection. Full authenticated endpoint
behavior remains behind the separate private endpoint-driver boundary described
in [the flow scope](quic-flow-scope.md).

## State graphs

The client sends a protected Initial immediately. A matching protected server
Initial can complete the inspection; Version Negotiation or one valid Retry can
cause a newly protected Initial to be emitted; and bounded failures finish with
an inspectable outcome.

```text
                         supported v1 selected
                    +-------------------------------+
                    |                               |
                    v                               |
  start ------> InitialSent ---- Version Negotiation+
                    |  |          rejected/unsupported --> Closed (error)
                    |  |
                    |  +---- valid Retry --> RetryReceived
                    |                         | new Initial, fresh packet number
                    |                         +--------------------> InitialSent
                    |---- invalid Retry / malformed / bad ACK ----> Closed (error)
                    |---- CONNECTION_CLOSE -----------------------> Closed
                    |---- protected ACK + CRYPTO -----------------> InitialObserved
                    +---- protocol wakeup ------------------------> Timeout
```

The passive server validates the configured documentation-space tuple before
acting. It either inspects a supported Initial and emits a protected response,
or emits one bounded negotiation/Retry response according to policy.

```text
  start ------> InitialListening
                    |---- unsupported version --> VersionNegotiationSent
                    |---- Retry required -------> RetrySent
                    |---- protected Initial ----> InitialObserved
                    |                              (protected ACK + CRYPTO response)
                    |---- malformed / bad ACK / amplification bound --> Closed (error)
                    |---- CONNECTION_CLOSE ----------------------------> Closed
                    +---- protocol wakeup -----------------------------> Timeout
```

`VersionNegotiationSent` and `RetrySent` are bounded server outcomes. A client
that accepts either response emits a fresh Initial, but a new server flow is
needed to inspect that continuation. No Initial-only terminal state claims an
authenticated connection.

## Inputs and packet construction

`QuicInitialClientConfig` and `QuicInitialServerConfig` contain the local and
peer IPv4/UDP tuples, QUIC version policy, deterministic connection identifiers,
packet-number seed and encoded width, bounded opaque CRYPTO bytes, Retry policy,
and datagram/CRYPTO/Retry limits. Their defaults use documentation address
space and deterministic fixtures.

The original destination connection identifier (ODCID) is the destination ID
from the first client Initial. It is retained for Initial secret derivation and
Retry integrity verification. The current destination connection identifier is
the ID placed in the next outgoing Initial. A valid Retry replaces only the
current destination ID, attaches the Retry token, and preserves the ODCID. The
token is private flow state: reports indicate its presence but never render its
bytes.

Initial protection keys are directional. The client protects with client keys
and inspects server packets with server keys; the server does the reverse. Both
directions derive their Initial secrets from the retained ODCID. Every client
Initial UDP datagram is padded to at least 1200 bytes before protection, as
required for a client Initial. Server output remains subject to the
anti-amplification bound.

## Inspection and outcomes

Accepted Initial packets expose bounded, non-secret observations through
`PacketContext` and `FlowReport`: lifecycle and outcome labels, connection-ID
summaries, reconstructed packet numbers, compact inclusive ACK ranges, CRYPTO
byte counts/content in non-rendered context, close metadata, and tuple facts.
The packet itself remains a typed stack usable by compilation, mutation,
summaries, and dry-run planning.

ACK ranges are validated in the Initial packet-number space. A peer may only
acknowledge packet numbers this flow recorded as sent; malformed ranges,
acknowledgements of unsent numbers, excessive range counts, unexpected frame
types, protection failures, wrong tuples, and configured size-limit violations
become bounded error outcomes. Peer and local Initial `CONNECTION_CLOSE` frames
also finish with inspectable close category, code, and a bounded reason.

Version Negotiation is accepted only before authenticated server traffic, with
matching connection identifiers and an offered version allowed by policy. A
Retry must match the tuple, version, and connection identifiers; have a
nonempty token; pass integrity verification against the ODCID; and stay within
the one-Retry bound. Rejected Version Negotiation or Retry packets emit no
follow-up Initial.

## Safe offline use

The tracked examples use deterministic peer fixtures and `MemoryCaptureSource`;
they open no sender, require no credentials, and touch no real interface:

```sh
cargo run -p crafter-flow --example quic_initial_client_flow
cargo run -p crafter-flow --example quic_initial_server_flow
```

Keep ordinary experimentation on this offline path. Live traffic requires
explicit authorization, a dry-run first, and a disposable provider-backed
endpoint or lab with scoped targets and teardown; it must not originate from an
elevated developer host.

## Limits and source policy

Initial-only flows deliberately do not perform a TLS 1.3 handshake, authenticate
a peer, create streams, recover application data, or implement congestion
control. Generic packet decoding also cannot interpret protected short headers
without endpoint context. Use the packet primitives for explicit wire work and
the later full-flow driver for an authenticated bounded conversation.

Wire and safety decisions are governed by the
[QUIC source manifest](../../../.agents/docs/quic-manifest.md), the
[packet-protection scope](../../../.agents/docs/quic-packet-protection-scope.md),
and the [provider-backed live safety policy](quic-flow-scope.md#offline-and-live-boundary).
The public packet-primitive surface remains documented in
[`docs/guide/quic.md`](../../../docs/guide/quic.md).

## Authenticated client and server flows

Enable the optional endpoint adapter with the `quic-endpoint` feature. Its
entrypoints have collision-free names:

- `quic_client_flow(QuicClientFlowConfig)` initiates one authenticated request.
- `quic_server_flow(QuicServerFlowConfig)` accepts one request and returns one
  configured response.

Both flows are socket-free. They consume and emit UDP datagrams through the
ordinary flow engine, so the in-memory duplex harness can complete the whole
conversation without credentials, privileges, or live network access.

### State graphs

The endpoint provider may process Retry while the client is handshaking. Retry
does not add a public flow state: it replaces the provider's destination
connection identifier and causes a fresh protected Initial. Authentication and
transport-parameter validation must finish before application bytes are sent.

```text
client
  InitialSent --> Handshaking -- authenticated --> Established
                      |   ^                            |
                      |   +-- Retry / fresh Initial --+
                      |                                | response complete
                      |                                v
                      +-- idle timeout / TLS / transport error --> Closed (error)
                                                       |
                                                       v
                    Closed <-- Draining <-- Closing <--+
                                  |           |
                                  +-- idle timeout / peer close / error --> Closed
```

The passive server starts in `Listen`; receipt of a matching Initial enters
the same provider-owned handshake and bounded close sequence. A provider may
emit Retry while remaining on that handshake path.

```text
server
  Listen -- Initial --> Handshaking -- authenticated --> Established
    |                       |   ^                            |
    |                       +---+ Retry                     | response complete
    |                                                        v
    +-- malformed / idle timeout / configuration error --> Closed (error)
                                                             |
                                                             v
                      Closed <-- Draining <-- Closing <-------+
                                    |           |
                                    +-- idle timeout / peer close / error --> Closed
```

`Closing` sends or receives the graceful close; `Draining` suppresses new
application work while the peer's close can settle. Every state is bounded by
provider wakeups, the flow step timeout, and the overall run deadline. Peer
close, local close, idle timeout, TLS authentication failure, invalid transport
parameters, malformed input, and provider errors terminate with an inspectable
outcome rather than an unbounded wait.

### Configuration and bounds

`QuicClientFlowConfig` contains local/peer `QuicEndpointAddresses`, a
`QuicPeerConfig` peer name and ordered ALPN policy, caller-supplied trust roots
in `QuicSyntheticIdentity`, one opaque request, and `QuicTransportLimits`.
`QuicServerFlowConfig` contains the reversed address tuple, a certificate and
private key in `QuicSyntheticIdentity`, one opaque response, and the same
limits. The examples use `quic.example`, the `crafter-flow` ALPN, documentation
IPv4 addresses, and a conspicuously synthetic certificate fixture.

The limits bound UDP payload size, stream bytes, flow control, idle time, and
the single bidirectional application-stream policy. Oversized requests or
responses, missing trust, a peer-name mismatch, an ALPN mismatch, malformed
identity bytes, and unsupported stream behavior are configuration or protocol
outcomes. Synthetic fixtures are test material only: they are not production
credentials, do not establish a public trust chain, and must never be reused
for a live service.

### Packet and provider boundary

The private provider owns TLS 1.3 transcripts and authentication, connection
state, packet-number spaces, ACK generation, PTO and loss recovery, congestion
behavior, and stream state. None of those become endpoint APIs in `crafter`.
Every provider transmit is instead wrapped back into the existing typed
`Ipv4 / Udp / Quic::raw` packet stack before mutation, compilation, dry-run
planning, batching, summaries, or reports.

Generic ingress deliberately preserves protected short-header payloads as
`Raw`: their connection-ID length, keys, and full packet number require the
private endpoint context. A tuple-checked flow adapter passes those raw UDP
bytes to the provider. Recovery outputs are regeneration-only. The runner never
exactly replays a protected datagram, and the provider assigns fresh packet
numbers separately in Initial, Handshake, and Application spaces.

Reports expose only non-secret facts: lifecycle and close categories,
application completion, request/response byte counts, timeout events, PTO
firings, declared losses, regenerated transmits, and per-space packet counts.
They do not expose traffic secrets, private keys, tickets, tokens, or protected
payload plaintext. When troubleshooting, inspect the outcome category together
with the state trace, tuple, ALPN and peer-name policy, configured bounds,
payload counts, and recovery counters.

### Offline examples and non-goals

```sh
cargo run -p crafter-flow --features quic-endpoint --example quic_client_flow
cargo run -p crafter-flow --features quic-endpoint --example quic_server_flow
```

These commands use the deterministic in-memory harness and print dry-run send
plans. HTTP/3, QPACK, 0-RTT, resumption, arbitrary stream concurrency,
server-initiated application streams, DATAGRAM applications, migration,
multipath, IPv6 endpoint flows, and a general-purpose QUIC stack remain
non-goals.

Keep full-flow work offline by default. Any authorized interoperability run
must start with a dry-run plan, use disposable provider-backed endpoints or a
lab instead of the developer host, scope its targets, keep sensitive captures
untracked, collect only approved artifacts, and tear the environment down.
