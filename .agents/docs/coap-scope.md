# CoAP Packet-Layer Scope

CoAP support in `crafter` is a packet primitive. It exists so generated tools
can build, compile, decode, inspect, persist, and validate CoAP wire messages
through the existing `Packet` abstraction. It does not turn the crate into a
CoAP endpoint, service, or discovery product.

This note freezes the implementation boundary before wire behavior is added.
It is not authority for field layouts, numeric assignments, defaults, or
validity rules. Those facts must come from the planned CoAP source manifest,
current IANA registry snapshot, Datatracker relationships, RFC text, and
applicable errata before they are used by code, fixtures, or validation.

## Protocol family and public shape

CoAP is unversioned at the module and type-family level. Public APIs use a
`coap` module and explicit transport-oriented types such as `Coap` and
`CoapReliable`; they do not introduce `CoAPv1`, `CoapV1`, or similar aliases.
The RFC 7252 version value remains an inspectable datagram header field, and an
explicit caller value must remain visible even when it is non-default or
intentionally malformed.

Both datagram and reliable messages remain ordinary typed layers. They compose
with `/`, compile as part of a `Packet`, decode through explicit and registry
entrypoints, and participate in `summary()` and `show()`. Helpers and security
operations return typed layers, typed packet submodels, or `Packet` values;
they do not create a second raw-bytes-plus-instructions API.

## In-scope packet capabilities

| Area | Packet-layer scope |
| --- | --- |
| Core datagrams | Build, compile, and decode one RFC 7252 message as a typed application layer over UDP. Preserve the fixed header, token, ordered options, payload-marker state, and binary payload. Unset dependent values may receive protocol-correct defaults; explicit values must survive unchanged. |
| Codepoints and options | Expose current source-backed IANA assignments as inspectable metadata and typed helpers. Structurally valid unknown codes, option numbers, content formats, signaling values, repeated options, ordering, and opaque option bodies remain lossless rather than being rejected because the local registry does not name them. |
| Registry decode | Offer explicit strict decode and conservative built-in application dispatch. A service port alone is not enough to claim CoAP: unrelated data, malformed candidates, and secure ciphertext remain `Raw` when the cleartext shape gate cannot establish a complete supported message. |
| Resource discovery | Model CoRE resource-discovery requests, responses, link-format values, and extension attributes as packet data. Parsing and serialization may expose typed structure while preserving source-backed extension and raw forms. |
| Observe | Model the Observe option and stateless serial-order comparisons. Subscription ownership, notification scheduling, cancellation workflows, and persistent observation state stay outside the crate. |
| Blockwise and Q-Block | Model Block1, Block2, BERT, Q-Block1, and Q-Block2 option fields and stateless transfer metadata. The crate may build, decode, validate, and inspect individual messages, but it does not assemble transfers or schedule bursts. |
| Modern extensions | Add source-backed packet helpers for No-Response, PATCH and iPATCH, Hop-Limit, Echo, Request-Tag, URI, conditional, representation, location, size, and proxy options. Helpers do not implement the operational services suggested by those options. |
| Extended tokens | Preserve and encode source-backed extended token lengths without hiding base token semantics or repairing explicit token-length mismatches during compilation. Reserved or impossible encodings fail through structured decode errors where the selected grammar requires that result. |
| Reliable framing | Model one complete source-backed reliable-transport frame as `CoapReliable`, including its length/token-length encoding, code, token, options, payload state, and signaling messages. Compilation and direct decode operate on a complete frame supplied by the caller and report the consumed boundary; they do not create TCP stream state. |
| OSCORE | Provide explicit, stateless transforms between typed cleartext and OSCORE-protected `Coap` messages using immutable caller-supplied context inputs and source-backed algorithms. Packet fields, identifiers, option metadata, ciphertext, and authentication failures remain inspectable without leaking secrets. |
| Group wire metadata | Model source-backed CoAP group request/response metadata and admitted Group OSCORE wire fields. Unsupported signature or algorithm material remains explicit and opaque instead of implying group membership or key-management support. |
| Persistence and validation | Exercise CoAP through deterministic bytes, malformed corpora, round trips, classic pcap records, summaries, oracle comparisons, probe plans, and dry-run provider artifacts. These surfaces validate packet behavior; they are not runtime CoAP products. |

## Packet invariants

The CoAP family follows the same rules as every other `crafter` layer:

- `Packet` remains the owner of the typed layer stack and the common compile,
  decode, summary, show, and typed-access surface.
- Compilation fills only unset values. It does not normalize or overwrite
  explicit versions, types, token lengths, codes, message IDs, option
  encodings, payload markers, reliable lengths, or security fields.
- Unknown but structurally valid values remain numeric or opaque and
  round-trip byte-for-byte.
- Malformed or truncated explicit decode returns structured errors with stable
  context and required/available size data. It must not panic, overread, or
  silently reinterpret the bytes as a different valid message.
- Registry auto-dispatch is more conservative than explicit decode and keeps
  non-candidates as `Raw`.
- Reliable parsing consumes one complete caller-provided frame only. The
  repository explicitly does not provide TCP stream reassembly.

## Operational non-goals

CoAP support must not add:

- a client or server engine, resource store, daemon, or application framework;
- confirmable-message retransmission, congestion control, transaction
  scheduling, request/response correlation state, or duplicate suppression;
- an Observe subscription manager, blockwise/Q-Block reassembly engine, cache,
  proxy service, or discovery scanner;
- TCP stream reassembly, WebSocket framing, or connection/session management;
- DTLS or TLS handshakes, certificate management, or secure-session setup;
- ACE or EDHOC enrollment, context provisioning, replay databases, group
  membership, group key distribution, or unsupported cryptographic algorithms;
- target selection, multicast membership policy, route management, or a live
  traffic default; or
- credentials, public provider addresses, live host identifiers, sensitive
  captures, or transient lab state in tracked files.

Generated tools may assemble operational workflows from these primitives, but
those workflows remain outside the public `crafter` protocol API.

## Validation and live boundary

Offline construction, decode, fixture, pcap, oracle, probe, and dry-run paths
are the default. Tracked examples and artifacts use documentation address space
and synthetic non-sensitive data.

No CoAP acceptance command sends live traffic from the developer machine.
Optional live behavior requires an explicitly authorized, disposable
provider-backed endpoint or lab, bounded packet and time limits, a separate
CoAP-specific confirmation gate, deterministic artifact collection, and
teardown. If those prerequisites are absent, validation records a stable skip
reason and still produces the available dry-run artifacts.
