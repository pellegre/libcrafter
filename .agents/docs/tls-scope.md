# TLS Scope

This file defines the `crafter` TLS boundary for the
`tls-protocol-bootstrap` plan. It is agent-facing implementation guidance,
derived from `AGENTS.md`, `.agents/docs/tls-manifest.md`, and
`.agents/docs/tls-codepoints.md`. User-facing TLS documentation belongs under
`docs/`; generated-tool operating guidance belongs under `.agents/docs/`.

`crafter` will expose TLS as a packet primitive. Generated tools should be able
to construct, compile, decode, inspect, persist, and validate TLS records and
selected handshake structures through the existing `Packet` abstraction,
`Layer` implementations, `/` composition, `compile()`, decode entrypoints,
`summary()`, `show()`, fixtures, and offline oracle/probe workflows.

## Supported Packet-Layer Surface

| Area | Scope | Boundary |
| --- | --- | --- |
| TLS-over-TCP records | In scope | TLS records carried as TCP application payloads, including complete records, multiple records in one payload, and a complete-record sequence followed by a partial tail. |
| TLS 1.2 | In scope | Record framing, alerts, change-cipher-spec, application-data framing, handshake framing, hello messages, selected extensions, certificates as wire structures, and source-backed codepoint labels. |
| TLS 1.3 | In scope | Legacy record-version handling, supported_versions-driven negotiated version values, handshake messages selected by later steps, selected extensions, and opaque protected records. |
| Unknown codepoints | In scope | Unknown valid content types, handshake types, extensions, cipher suites, groups, signature schemes, certificate-compression algorithms, private-use values, and GREASE-shaped values remain numeric and byte-preserved. |
| Malformed construction | In scope | Builders and `compile()` may fill unset lengths, but explicit caller overrides survive, including intentionally malformed record, handshake, vector, and extension lengths. |
| Structured decode errors | In scope | Truncation and malformed buffers return structured `CrafterError` values with context, required byte count, and available byte count when the failure is a short buffer. |
| Registry dispatch | In scope | Common TLS TCP ports may decode only behind a conservative TLS-looking shape gate; non-TLS payloads remain `Raw`. |
| Fixtures and validation | In scope | Golden bytes, malformed cases, pcap fixtures, oracle specs, probe dry-runs, and lab dry-runs are offline defaults. |

The Rust implementation must follow existing protocol patterns from modules
such as MQTT, QUIC, BGP, and the TCP registry path. TLS should not create a
parallel API for raw bytes plus instructions; supported data remains typed
packet-layer state or explicitly preserved raw data inside the packet model.

## Explicit Non-Goals

TLS support in `crafter` is not a TLS client and is not a TLS server. The crate
does not perform endpoint negotiation, drive handshake state, retry records,
open sockets as a TLS endpoint, or schedule connection attempts.

The crate does not perform certificate validation, PKI trust decisions, trust
store lookup, certificate-chain path building, hostname verification,
revocation checking, policy enforcement, scanner behavior, fuzzer behavior, or
service fingerprinting. Certificate and certificate-related handshake messages
are packet-layer byte structures only.

The crate does not add a TCP stream reassembler, full TCP/IP stack, session
cache, key schedule, transcript engine, traffic-secret derivation, or general
record decryption path. A generated tool may combine `crafter` primitives with
other libraries for those workflows, but that logic does not belong in the
crate primitive.

The crate does not decode HTTP, MQTT, DNS-over-TLS, or other application
protocols carried inside TLS application data. Once bytes are encrypted or
application-specific, `crafter` keeps them opaque unless a later source-backed
packet-layer plan explicitly adds a narrower primitive.

DTLS, QUIC TLS transcript internals, Encrypted ClientHello, and other
TLS-adjacent transports or extensions remain deferred unless a separate
source-backed plan scopes them.

## Version Boundary

TLS 1.2 and TLS 1.3 are the selected bootstrap targets. TLS 1.2 record and
handshake grammar comes from the TLS 1.2 source set, with known updates and
errata accounted for by `.agents/docs/tls-manifest.md`. TLS 1.3 behavior comes
from the TLS 1.3 source set and current IANA TLS registries.

TLS 1.3 legacy record-version fields are not the negotiated protocol version.
Implementation and docs must keep record legacy versions and negotiated
supported_versions values inspectable as separate fields. Older, obsolete,
private, reserved, draft-backed, or GREASE-shaped version values are preserved
when seen or explicitly built, but they are not default negotiation policy.

## TCP Segmentation Limits

TLS decode works on the TCP payload bytes available to the packet decoder. A
single TCP payload may contain one complete TLS record, multiple complete
records, a complete sequence followed by a partial record tail, or only a
partial record. Complete records may decode into typed TLS structures. Partial
tails must be preserved as `Raw` or reported through structured errors according
to the local decode path; they must never be silently dropped or used to imply a
TCP stream state machine.

`crafter` does not reassemble TLS records across TCP segments. Any workflow that
needs ordered stream reconstruction, retransmission handling, duplicate segment
suppression, or flow state belongs in a generated tool or future explicit TCP
stream feature, not in TLS packet-layer support.

## Encrypted And Opaque Payloads

Encrypted handshake records, TLS 1.3 protected content, application data,
unknown handshake bodies, unknown extension bodies, and unsupported typed bodies
remain opaque and byte-preserved. Decode should expose enough structure to
inspect the enclosing record or message and then preserve the remaining bytes as
opaque data or `Raw`.

`summary()` and `show()` may label encrypted, opaque, or unknown regions, but
they must not claim decrypted semantics or infer application protocols from
ciphertext.

## Live-Validation Safety

This scope step adds no live traffic behavior. TLS examples, fixtures, oracle
profiles, probe plans, and lab plans must default to documentation address
space, checked-in bytes, pcap fixtures, or dry-run output.

Later live validation, if any, must be provider-backed, explicitly confirmed,
artifact-preserving, and safe to skip when provider credentials, disposable
endpoints, controlled TLS peers, or confirmation flags are absent. Live work
must not add credentials, public endpoint data, sensitive captures, host-specific
paths, or live traffic defaults to tracked files.

