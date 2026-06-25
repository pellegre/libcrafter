# QUIC Scope

This file defines the `crafter` QUIC boundary for the
`quic-protocol-bootstrap` plan. It is scoped by `AGENTS.md` and the refreshed
source evidence in `.agents/docs/quic-manifest.md`; later codepoint and grammar
notes may narrow individual parser rules, but they must not turn QUIC support
into a parallel endpoint stack.

`crafter` will expose QUIC as a packet-level primitive: generated tools should
be able to construct, decode, inspect, persist, and validate QUIC UDP datagrams
through the existing `Packet` abstraction, `compile()`, decode entrypoints,
`summary()`, `show()`, pcap fixtures, and oracle/probe workflows.

## Classification

| Area | Scope | Evidence boundary |
| --- | --- | --- |
| Core QUIC transport | In-scope | RFC 8999 and RFC 9000 evidence selected in `quic-manifest.md`: version-independent packet recognition, QUIC v1 headers, version negotiation, retry, packet numbers, connection IDs, frame sequences, transport parameters, and unknown preservation. |
| QUIC-TLS packet protection helpers | Deferred | RFC 9001 supports explicit helpers for fixed Initial secrets, header protection, packet-protection vectors, and Retry integrity. This does not include a TLS transcript engine or arbitrary session decryption. |
| QUIC v2 | In-scope | RFC 9369 is selected for packet-layer v2 shapes, labels, and test vectors. Endpoint policy remains out of scope. |
| Compatible version negotiation | In-scope | RFC 9368 is selected for packet and transport-parameter helpers after source-backed codepoint notes identify the exact fields. |
| DATAGRAM extension | In-scope | RFC 9221 is selected for DATAGRAM frame and transport-parameter parse/serialize behavior only. Application datagram semantics are out of scope. |
| QUIC bit greasing | In-scope | RFC 9287 is selected for inspectable header behavior and source-backed greasing helpers. |
| DoQ | Documentation-only | RFC 9250 may supply DNS-over-QUIC error-code notes. DNS-over-QUIC client/server behavior is not a crate primitive. |
| HTTP/3 | Non-goal | RFC 9114 maps HTTP semantics over QUIC and belongs outside `crafter`; packet fixtures may carry opaque bytes, but no HTTP client/server is implemented. |
| QPACK | Non-goal | RFC 9204 is HTTP/3 header compression, not QUIC packet grammar. |
| MASQUE and HTTP proxy documents | Non-goal | RFC 9297, RFC 9298, RFC 9484, and related HTTP proxy workflows are generated-tool or application behavior, not packet primitives. |
| Operational guidance | Documentation-only | RFC 9308 and RFC 9312 can inform explanatory docs and validation boundaries, but they do not authorize parser constants. |
| Draft, provisional, and experiment registry rows | Deferred | IANA provisional, draft, Google experiment, BDP token, SCONE, ACK_FREQUENCY, and multipath rows remain raw or provisional until later source-backed notes classify them. |
| Ambiguous discovered documents | Documentation-only or non-goal | Token-overlap documents rejected in `quic-manifest.md` stay outside implementation unless a later source-backed step explicitly selects them. |

## Crate Boundary

No full QUIC endpoint belongs in the `crafter` crate. In particular, no endpoint
state machine, congestion controller, loss recovery engine, stream reassembler,
TLS transcript engine, HTTP client/server, scanner, or fuzzer is part of this
implementation.

The crate may expose typed packet/header/frame/transport-parameter structures,
byte-preserving unknown variants, explicit raw protected payloads, and narrowly
scoped packet-protection helpers. Anything that combines those primitives into a
workflow belongs in examples, docs, skills, oracle/probe tooling, or generated
tools, not in `crafter` itself.

## Construction And Decode Rules

- Builders must preserve explicit user overrides, including malformed QUIC
  fields, and auto-fill dependent fields only when unset.
- Decoders must preserve encrypted, unknown, or unsupported content as raw bytes
  whenever the enclosing QUIC structure is valid.
- Malformed QUIC buffers must return structured `CrafterError` values with
  stable context, required length, and available length where applicable.
- UDP recognition must remain conservative so QUIC support does not corrupt
  neighboring UDP protocols or custom registry behavior.
- Packet examples and generated defaults must use documentation address space,
  such as `192.0.2.0/24`, `198.51.100.0/24`, and `2001:db8::/32`.

## Validation Boundary

This scope step performs no live traffic. QUIC validation starts offline with
golden bytes, malformed decode cases, pcap fixtures, and oracle/probe dry-runs.
Any later live validation must use explicit provider-backed plans, protected
confirmation, collected artifacts, and teardown or structured skip records.
