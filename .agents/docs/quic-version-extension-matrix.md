# QUIC Version And Extension Matrix

This matrix orders QUIC version, extension, and adjacent-document work for the
`quic-protocol-bootstrap` plan. It is source-backed by
`.agents/docs/quic-manifest.md`, `.agents/docs/quic-codepoints.md`, and the
refreshed protocol manifest from 2026-06-25. Later implementation steps must
cite those notes or a narrower source note before adding constants, parser
rules, fixtures, oracle rows, or probe behavior.

This file does not authorize live traffic. Packet examples and generated
defaults must use documentation address space such as `192.0.2.0/24`,
`198.51.100.0/24`, and `2001:db8::/32`. Builders must preserve explicit user
overrides, including malformed values; decoders must preserve encrypted or
unsupported content as raw bytes and return structured `CrafterError` values
for malformed buffers.

## Matrix

| Row | Source status | Packet bytes | Public API | Oracle coverage | Probe coverage | Docs only | Non-goal |
| --- | --- | --- | --- | --- | --- | --- | --- |
| QUIC v1 core transport | Selected: RFC 8999, RFC 9000, IANA QUIC version `0x00000001` and default-eligible v1 registries. | Yes: version-independent headers, v1 long and short headers, Version Negotiation, Retry, varints, packet numbers, connection IDs, frames, and transport parameters. | Yes: typed packet/header/frame/transport-parameter primitives behind the existing `Packet` abstraction. | Yes: golden bytes, malformed decode cases, pcap fixtures, and offline reference comparisons. | Yes, but only through dry-run or protected provider workflows in later steps. | No. | No endpoint state machine, loss recovery, congestion control, TLS transcript engine, scanner, or fuzzer. |
| QUIC v2 | Selected: RFC 9369, IANA QUIC version `0x6b3343cf`; draft codepoint `0x709a50c4` remains non-default. | Yes: v2 packet shape differences, labels, retry integrity context, and fixed vectors where later steps cite exact sections. | Yes: version constants, labels, classifiers, and packet builders/parsers after source-backed implementation steps. | Yes: v2 header and protection vectors in focused offline suites. | Yes for dry-run/live planning after offline coverage exists. | No. | No endpoint policy or version preference negotiation policy. |
| Version Negotiation packet (`0x00000000`) | Selected: RFC 8999, RFC 9000, IANA reserved version `0x00000000`. | Yes: long-header Version Negotiation packet structure and byte-preserving supported-version list. | Yes: builders and decoders that preserve caller-supplied versions, including reserved or grease values. | Yes: golden and malformed packet fixtures. | No live behavior in this step; later probe coverage can plan controlled negotiation stimuli. | No. | No automatic endpoint version selection. |
| compatible version negotiation | Selected: RFC 9368; IANA transport parameter `version_information` (`0x11`) and error `VERSION_NEGOTIATION_ERROR` (`0x11`) are default-eligible; draft parameter `0xff73db` remains non-default. | Yes: transport-parameter bytes and connection-close error code bytes. | Yes: packet-layer helpers and typed transport-parameter support after parameter parsing exists. | Yes: offline parameter and close-frame cases. | Planned only after core packet and transport-parameter support. | No. | No endpoint negotiation policy or retry logic. |
| DATAGRAM | Selected: RFC 9221; IANA frame types `0x30-0x31` and transport parameter `max_datagram_frame_size` (`0x20`) are default-eligible. | Yes: DATAGRAM and DATAGRAM_LEN frame payload bytes plus the transport-parameter tuple. | Yes: frame enum variants and builders/parsers after the frame scaffold lands. | Yes: frame sequence, fixture, and malformed coverage. | Yes for controlled generated stimuli after offline frame support. | No. | No application datagram protocol semantics. |
| Greasing the QUIC bit | Selected: RFC 9287; IANA transport parameter `grease_quic_bit` (`0x2ab2`) is default-eligible. | Yes: inspectable header-bit behavior and transport-parameter bytes. | Yes: explicit helpers only; user-pinned malformed header bits remain preserved. | Yes: header and transport-parameter fixtures. | Optional dry-run coverage for generated stimulus plans. | No. | No policy that forces peers to grease or validates peer behavior as an endpoint. |
| Reserved QUIC version grease values | Selected: IANA QUIC Versions registry and RFC 9000 registry policy. | Yes: recognize values matching `(value & 0x0f0f0f0f) == 0x0a0a0a0a`; never guess a version-specific grammar from them. | Yes: classification helpers; no defaults that emit them unless the caller asks. | Yes: classifier and preservation cases. | No required live coverage. | No. | No endpoint negotiation behavior. |
| Multiplexing updates | Selected: RFC 9443 updates the QUIC multiplexing scheme context. | Yes, but only as UDP payload recognition policy: avoid corrupting DTLS, STUN, RTP/RTCP, ZRTP, TURN ChannelData, ESP/IKE, DNS, DHCP, RIP, or custom UDP bindings. | Limited: conservative classifier/registry behavior, not a new application API. | Yes: classifier fixtures and oracle cases proving non-QUIC UDP payloads remain raw or dispatch to existing protocols. | Yes for dry-run plans only after offline classifier coverage. | No. | No broad UDP demultiplexer rewrite. |
| Packet protection utilities | Selected boundary: RFC 9001. | Yes only for explicit caller-supplied inputs, Initial secret derivation, header-protection masks, fixed vectors, and Retry integrity helpers. | Deferred: narrow utility APIs only after dependency review. | Yes: fixed v1/v2 vector checks after review. | No arbitrary live decryption coverage. | No. | No TLS stack, key schedule ownership, arbitrary session decryption, or endpoint transcript handling. |
| DoQ error codes | Selected for notes: RFC 9250 and the DNS-over-QUIC Error Codes registry discovered in the refreshed manifest. | No QUIC transport packet grammar effect; error-code numbers may be recorded for documentation or generated-tool use. | No `crafter` DoQ endpoint API. | No core QUIC oracle requirement unless a later docs/spec step records codepoint fixtures. | No. | Yes. | DNS-over-QUIC client/server behavior is out of scope. |
| HTTP/3 boundary | Rejected for crate primitive: RFC 9114. | No: HTTP semantics can appear only as opaque stream bytes. | No. | No HTTP/3 oracle layer in this plan. | No. | Yes. | HTTP client/server behavior is out of scope. |
| QPACK boundary | Rejected for crate primitive: RFC 9204. | No: QPACK is HTTP/3 header compression, not QUIC packet grammar. | No. | No. | No. | Yes. | QPACK encoder/decoder behavior is out of scope. |
| MASQUE-adjacent documents | Rejected for crate primitive: RFC 9297, RFC 9298, RFC 9484, and RFC 9931. | No: these are HTTP datagram/proxy workflows, not QUIC frame grammar; use RFC 9221 for QUIC DATAGRAM bytes. | No. | No MASQUE oracle coverage in this plan. | No. | Yes. | MASQUE, proxying UDP/IP in HTTP, and application proxy behavior are out of scope. |
| Operational and manageability guidance | Documentation boundary: RFC 9308 and RFC 9312. | No parser constants. | No. | No, except validation docs may reference operational limits. | No. | Yes. | Operational endpoint management is out of scope. |
| Active drafts, provisional rows, and experiments | Non-default in `quic-codepoints.md`: SCONE versions and parameter, ACK_FREQUENCY `min_ack_delay`, `IMMEDIATE_ACK`, and `ACK_FREQUENCY`, Google experiment rows, BDP token rows, `discard`, and unresolved multipath rows. | Preserve numeric values and raw bytes when an enclosing source-backed parser can determine extent; do not emit by default. | No stable convenience constants until a later source-backed step selects them. | Preservation or unsupported-case coverage only. | No live coverage unless a later step explicitly selects and gates it. | No. | No draft behavior is implemented as stable API in this bootstrap pass. |
| Rejected and ambiguous candidates | Rejected or ambiguous in `quic-manifest.md` and the refreshed protocol manifest: RFC 9463, RFC 9464, RFC 9539, RFC 4014, RFC 9445, and broad token-overlap documents. | No. | No. | No. | No. | Yes, as exclusion evidence. | These documents must not drive QUIC parser constants or packet behavior without a later source-backed selection step. |

## Ordering Rules

- Implement default-eligible RFC 8999/RFC 9000 QUIC v1 structure before
  extension-specific packet behavior.
- Add QUIC v2 only from RFC 9369 evidence and keep draft v2 codepoints
  non-default.
- Add compatible version negotiation, DATAGRAM, QUIC-bit grease, multiplexing,
  and DoQ notes only at the plan steps that name those documents.
- Keep active drafts, provisional registry rows, experiments, and unresolved
  multipath rows byte-preserving and non-default until a later source-backed
  step changes their status.
- Keep HTTP/3, QPACK, MASQUE, DNS-over-QUIC endpoint behavior, and operational
  endpoint guidance outside the `crafter` packet primitive.
