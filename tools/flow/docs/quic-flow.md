# QUIC Initial-Only Flows

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
