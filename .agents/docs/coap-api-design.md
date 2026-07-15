# CoAP public API design

This note freezes the planned public CoAP API before Rust implementation and
exports land. It is a design handoff, not an implementation. Wire facts remain
gated by `.agents/docs/coap-rfc-manifest.md`,
`.agents/docs/coap-codepoints.md`, `.agents/docs/coap-wire-grammar.md`, and
`.agents/docs/coap-extensions.md`.

The design follows the existing application-layer conventions in `Ntp`,
`Ssdp`, `Mqtt`, and `Quic`: a concrete `Layer` owns its bytes and typed state,
implements slash composition, compiles through `Packet`, supports typed packet
access, and supplies stable `summary()` and `show()` fields. Explicit parsing
is strict; built-in registry dispatch first applies a conservative shape gate
and preserves non-candidates as `Raw`.

CoAP support is a packet primitive. It does not add a client or server engine,
transaction state, retransmission, discovery scans, Observe subscriptions,
block transfer assembly, TCP stream reassembly, context provisioning, replay
databases, group membership, or live-send workflow.

## Naming and module boundary

The public family name is unversioned:

- `crafter::protocols::coap::Coap` is one RFC 7252 datagram message.
- `crafter::protocols::coap::CoapReliable` is one complete RFC 8323 reliable
  frame supplied by the caller.
- The two-bit RFC 7252 version remains a `CoapVersion` field on `Coap`; it does
  not appear in a public type or module name.
- No `CoAP`, `CoapV1`, `CoapUdp`, `CoapTcp`, `CoapMessage`, or other
  compatibility aliases are introduced.

The implementation lives under `crafter/src/protocols/coap/`. Internal files
may be split by constants, registry metadata, options, message layers,
reliable framing, link format, block metadata, OSCORE, group metadata, decode,
and validation. File layout is not public API; the canonical module path for
all exported symbols is `crafter::protocols::coap`.

## Common ownership and field rules

All public message and submodel types own their data. Token, option, payload,
link-format, identifier, ciphertext, and opaque extension bytes use owned
`Vec<u8>` or owned strings internally. Borrowing accessors return slices or
references tied to `&self`; they never return a reference to a temporary and
never panic on unknown, absent, non-UTF-8, or malformed semantic content.

Header or framing values that may be filled during compilation are private
`Field<T>` members. Their public setters call `Field::set_user`; decoding also
records the received representation as explicit data. Compilation derives a
default only when the corresponding field is `Unset`. It never replaces a
`Defaulted` or `User` value.

The following states remain independent so deliberately inconsistent packets
can be built:

- token bytes and the TKL discriminator, extension bytes, and declared length;
- typed option number/value data and an explicit raw option header encoding;
- payload bytes and the explicit present/absent payload-marker choice;
- reliable-frame body bytes and its Len discriminator, extension bytes, and
  declared length; and
- OSCORE option fields, outer options, ciphertext, and caller-supplied context
  inputs.

`Field<T>` itself remains the generic state primitive. CoAP accessors expose a
`FieldState` plus a non-panicking effective or borrowed value instead of
exposing mutable references to the layer's private `Field<T>` members.

Every builder and transform defined here returns `Coap`, `CoapReliable`, a
typed submodel, `Packet`, or a `Result` containing one of those types. No public
workflow returns raw bytes together with procedural assembly instructions.
Byte accessors exist only for inspection and lossless typed submodels.

## Datagram layer

The datagram layer has this private logical shape:

```rust
pub struct Coap {
    version: Field<CoapVersion>,
    message_type: Field<CoapMessageType>,
    token_length: Field<CoapTokenLength>,
    code: Field<CoapCode>,
    message_id: Field<u16>,
    token: Field<CoapToken>,
    options: Vec<CoapOption>,
    payload_marker: Field<CoapPayloadMarker>,
    payload: Vec<u8>,
}
```

`Coap` implements `Default`, `Layer`, `IntoPacket`, and the existing layer
division/object helpers used by neighboring protocols. It composes directly:

```rust
use crafter::prelude::*;

let packet: Packet = Ipv4::new()
    / Udp::new().destination_port(COAP_PORT)
    / Coap::get().message_id(0x1234).uri_path("status");
```

`Coap::new()` leaves dependent fields unset. Its effective compile defaults
are Version 1, Confirmable, Empty code, message ID zero, empty token, canonical
TKL zero, no options, absent marker, and empty payload. Named request and
response constructors only set the code and any constructor-specific message
type.

The frozen datagram constructors and setters are:

```rust
impl Coap {
    pub fn new() -> Self;
    pub fn empty() -> Self;
    pub fn request(code: CoapCode) -> Self;
    pub fn response(code: CoapCode) -> Self;
    pub fn get() -> Self;
    pub fn post() -> Self;
    pub fn put() -> Self;
    pub fn delete() -> Self;
    pub fn fetch() -> Self;
    pub fn patch() -> Self;
    pub fn ipatch() -> Self;

    pub fn version(self, value: impl Into<CoapVersion>) -> Self;
    pub fn message_type(self, value: CoapMessageType) -> Self;
    pub fn token_length(self, value: CoapTokenLength) -> Self;
    pub fn code(self, value: impl Into<CoapCode>) -> Self;
    pub fn message_id(self, value: u16) -> Self;
    pub fn token(self, value: impl Into<CoapToken>) -> Self;
    pub fn option(self, value: impl Into<CoapOption>) -> Self;
    pub fn options(self, values: impl IntoIterator<Item = CoapOption>) -> Self;
    pub fn payload_marker(self, value: CoapPayloadMarker) -> Self;
    pub fn payload(self, value: impl Into<Vec<u8>>) -> Self;

    pub fn confirmable(self) -> Self;
    pub fn non_confirmable(self) -> Self;
    pub fn acknowledgement(self) -> Self;
    pub fn reset(self) -> Self;
}
```

Convenience option setters append one ordered `CoapOption`; they never sort or
replace an existing occurrence:

```rust
impl Coap {
    pub fn uri_host(self, value: impl Into<CoapUriHost>) -> Self;
    pub fn uri_port(self, value: impl Into<CoapUriPort>) -> Self;
    pub fn uri_path(self, value: impl Into<CoapUriPath>) -> Self;
    pub fn uri_query(self, value: impl Into<CoapUriQuery>) -> Self;
    pub fn content_format(self, value: impl Into<CoapContentFormat>) -> Self;
    pub fn accept(self, value: impl Into<CoapAccept>) -> Self;
    pub fn observe(self, value: impl Into<CoapObserve>) -> Self;
    pub fn block(self, kind: CoapBlockKind, value: CoapBlock) -> Self;
    pub fn oscore_option(self, value: OscoreOption) -> Self;
}
```

The non-panicking datagram accessors are:

```rust
impl Coap {
    pub fn version_state(&self) -> FieldState;
    pub fn version_value(&self) -> CoapVersion;
    pub fn message_type_state(&self) -> FieldState;
    pub fn message_type_value(&self) -> CoapMessageType;
    pub fn token_length_state(&self) -> FieldState;
    pub fn token_length_value(&self) -> Result<CoapTokenLength>;
    pub fn code_state(&self) -> FieldState;
    pub fn code_value(&self) -> CoapCode;
    pub fn message_id_state(&self) -> FieldState;
    pub fn message_id_value(&self) -> u16;
    pub fn token_state(&self) -> FieldState;
    pub fn token_value(&self) -> &CoapToken;
    pub fn options_value(&self) -> &[CoapOption];
    pub fn payload_marker_state(&self) -> FieldState;
    pub fn payload_marker_value(&self) -> CoapPayloadMarker;
    pub fn payload_value(&self) -> &[u8];
}
```

`token_length_value()` is fallible because an unset TKL derived from an owned
token larger than the source-backed maximum cannot be represented. Accessors
for effective scalar defaults do not panic or return `Option`; collection and
byte accessors return empty slices when empty.

## Header, code, token, and marker types

```rust
pub struct CoapVersion(u8);

pub enum CoapMessageType {
    Confirmable,
    NonConfirmable,
    Acknowledgement,
    Reset,
}

pub struct CoapCode(u8);
pub struct CoapToken(Vec<u8>);

pub struct CoapTokenLength {
    // Exact discriminator, extension bytes, and logical declared length.
}

pub enum CoapPayloadMarker {
    Absent,
    Present,
}
```

`CoapVersion` exposes `from_wire(u8)`, `value()`, `wire_value()`, `label()`,
and `is_current()`. `CoapMessageType` exposes `from_wire(u8)`, `wire_value()`,
and `label()`. `CoapCode` exposes `from_wire(u8)`, `from_parts(u8, u8)`,
`wire_value()`, `class()`, `detail()`, `label()`, `registry_meta()`,
`is_empty()`, `is_request()`, `is_response()`, and `is_signaling()`.

`CoapCode` also has named associated constructors `empty`, `get`, `post`,
`put`, `delete`, `fetch`, `patch`, `ipatch`, `created`, `deleted`, `valid`,
`changed`, `content`, `continue_`, `bad_request`, `unauthorized`, `bad_option`,
`forbidden`, `not_found`, `method_not_allowed`, `not_acceptable`,
`request_entity_incomplete`, `conflict`, `precondition_failed`,
`request_entity_too_large`, `unsupported_content_format`,
`unprocessable_entity`, `too_many_requests`, `internal_server_error`,
`not_implemented`, `bad_gateway`, `service_unavailable`, `gateway_timeout`,
`proxying_not_supported`, `hop_limit_reached`, `csm`, `ping`, `pong`,
`release`, and `abort`. Unknown wire bytes use `from_wire` and remain typed.

`CoapToken` exposes `new`, `from_bytes`, `as_bytes`, `into_bytes`, `len`, and
`is_empty`. `CoapTokenLength` exposes `canonical_for_len`, `explicit`,
`nibble`, `extension_bytes`, and `declared_len`; `explicit` does not require
the three values to agree. `CoapPayloadMarker` exposes `is_present`.

## Ordered options and typed wrappers

`CoapOption` is the single ordered option envelope used by datagrams,
reliable ordinary messages, signaling messages, OSCORE Inner/Outer sequences,
and advanced extensions. No extension defines a parallel TLV collection.

```rust
pub struct CoapOptionNumber(u16);

pub struct CoapOption {
    number: CoapOptionNumber,
    value: Vec<u8>,
    encoding: Field<CoapOptionEncoding>,
}

pub struct CoapOptionEncoding {
    // Exact header, delta-extension, and length-extension bytes.
}

pub enum CoapOptionFormat {
    Empty,
    Opaque,
    Uint,
    String,
    Unknown,
}
```

`CoapOptionNumber` exposes `from_wire`, `value`, `registry_meta`, `is_critical`,
`is_unsafe`, `is_safe_to_forward`, and `is_no_cache_key`. Those properties are
derived from the numeric bits for every known or unknown option.

`CoapOption` exposes `new(number, bytes)`, `with_encoding`, `number`, `value`,
`into_value`, `encoding_state`, `encoding`, `registry_meta`, `format`,
`as_uint`, and `as_str`. `as_uint` and `as_str` return typed `Result` values;
they never panic, silently normalize a noncanonical representation, or reject
the underlying option from the message. Canonical compilation uses the
caller's order. An explicit `CoapOptionEncoding` wins byte-for-byte.

The following wrappers are owned, implement `From<Wrapper> for CoapOption`,
and implement `TryFrom<&CoapOption>` without discarding the original opaque
bytes on failure:

- URI and proxy: `CoapUriHost`, `CoapUriPort`, `CoapUriPath`, `CoapUriQuery`,
  `CoapProxyUri`, and `CoapProxyScheme`.
- Conditional: `CoapIfMatch`, `CoapIfNoneMatch`, and `CoapEtag`.
- Representation and location: `CoapContentFormat`, `CoapAccept`, `CoapMaxAge`,
  `CoapLocationPath`, `CoapLocationQuery`, `CoapSize1`, and `CoapSize2`.
- Stateful-semantics-free extensions: `CoapObserve`, `CoapNoResponse`,
  `CoapHopLimit`, `CoapEcho`, and `CoapRequestTag`.
- Protection metadata: `OscoreOption`.

String wrappers retain owned wire bytes and provide `as_bytes()` plus a
fallible `as_str()`. Opaque wrappers provide `as_bytes()` and `into_bytes()`.
Unsigned wrappers provide both the decoded integer and the original encoded
bytes so decoded noncanonical integers can round trip unchanged. Presence of
an empty value remains distinct from absence of an option.

`CoapObserve` exposes the raw value and a stateless `is_newer_than` comparison
that returns `CoapObserveOrdering`; it stores no timer or subscription state.
`CoapNoResponse` exposes response-class mask predicates. `CoapHopLimit` exposes
`decrement() -> Result<CoapHopLimit, CoapHopLimitExhausted>` without forwarding
a packet. Unknown bits and malformed raw encodings remain in `CoapOption` even
when a typed conversion reports an error.

## Block, Q-Block, and BERT metadata

```rust
pub enum CoapBlockKind {
    Block1,
    Block2,
    QBlock1,
    QBlock2,
}

pub struct CoapBlock {
    // Raw uint bytes plus decoded NUM, M, and SZX metadata.
}

pub struct CoapBlockValidation {
    // Stateless semantic findings for one option/message context.
}
```

`CoapBlock` exposes `from_raw_bytes`, `new(number, more, szx)`, `raw_bytes`,
`number`, `more`, `szx`, `block_size`, `offset`, `is_bert`, and
`validate(kind, transport, payload_len)`. `CoapBlockTransport` is exactly
`Datagram` or `Reliable`. BERT and Q-Block helpers return `CoapBlock`,
`CoapOption`, or `CoapBlockValidation`; they do not assemble bodies, schedule
bursts, retransmit, or retain transfer state.

## CoRE Link Format

```rust
pub struct CoapLinkFormat {
    links: Vec<CoapLink>,
    raw: Field<Vec<u8>>,
}

pub struct CoapLink {
    target: Vec<u8>,
    attributes: Vec<CoapLinkAttribute>,
}

pub struct CoapLinkAttribute {
    name: Vec<u8>,
    value: CoapLinkAttributeValue,
}

pub enum CoapLinkAttributeValue {
    Absent,
    Token(Vec<u8>),
    Quoted(Vec<u8>),
    Extended(Vec<u8>),
}
```

`CoapLinkFormat` exposes `new`, `parse`, `link`, `links`, `raw_state`,
`raw_bytes`, `to_bytes`, and `into_payload`. `CoapLink` exposes `new`,
`target`, `attribute`, and `attributes`. `CoapLinkAttribute` exposes `new`,
`name`, `value`, and source-backed constructors for `rel`, `anchor`, `rev`,
`hreflang`, `media`, `title`, `title_star`, `content_type`, `resource_type`,
`interface_description`, and `size`.

Parsing preserves ordered links, ordered and unknown attributes, and raw token
or quoted forms. Canonical serialization is available when `raw` is unset;
explicit raw bytes win when present. Discovery helpers return `Coap` or
`CoapLinkFormat`, never perform a scan or retain a resource directory.

## Reliable layer and signaling

`CoapReliable` models one caller-provided complete frame, not a TCP stream:

```rust
pub struct CoapReliable {
    length: Field<CoapReliableLength>,
    token_length: Field<CoapTokenLength>,
    code: Field<CoapCode>,
    token: Field<CoapToken>,
    options: Vec<CoapOption>,
    payload_marker: Field<CoapPayloadMarker>,
    payload: Vec<u8>,
}

pub struct CoapReliableLength {
    // Exact Len discriminator, extension bytes, and declared body length.
}
```

`CoapReliable` implements `Default` and `Layer`, composes as `Tcp /
CoapReliable`, and exposes `new(code)`, `request(code)`, `response(code)`,
`csm`, `ping`, `pong`, `release`, `abort`, `length`, `token_length`, `code`,
`token`, `option`, `options`, `payload_marker`, and `payload` builders.
Equivalent `_state` and `_value` accessors use the datagram naming above;
there are no Version, Type, or Message ID methods.

`CoapReliableLength` exposes `canonical_for_body_len`, `explicit`, `nibble`,
`extension_bytes`, and `declared_body_len`. The explicit representation is
preserved even when inconsistent with owned body bytes.

Reliable signaling options remain ordinary `CoapOption` envelopes, but their
metadata lookup is contextual: `coap_signaling_option_meta(code, number)`.
`CoapSignalingOption` is a typed view containing the signaling code, option,
and contextual metadata; it does not substitute datagram option labels.

## OSCORE and group metadata

OSCORE is an explicit typed `Coap -> Coap` transform. It does not introduce an
encrypted packet layer or provision contexts.

```rust
pub struct OscoreContext {
    // Immutable master secret/salt, sender/recipient IDs, ID Context,
    // algorithm identifiers, and derived material.
}

pub struct OscoreRequestBinding {
    // Request KID and Partial IV needed by a response transform.
}

pub struct OscoreProtectParams {
    // Partial IV, optional KID Context, and optional request binding.
}

pub struct OscoreUnprotectParams {
    // Expected identifiers and optional request binding.
}

pub enum OscoreAeadAlgorithm {
    AesCcm16_64_128,
    Unknown(i32),
}

pub enum OscoreKdfAlgorithm {
    HkdfSha256,
    Unknown(i32),
}

pub enum OscoreError {
    // Structured unsupported, malformed, authentication, and context errors.
}
```

`OscoreContext::new` validates immutable inputs and returns a typed result.
`OscoreContext::protect(&self, message: &Coap, params:
OscoreProtectParams) -> Result<Coap, OscoreError>` and
`OscoreContext::unprotect(&self, message: &Coap, params:
OscoreUnprotectParams) -> Result<Coap, OscoreError>` are the only high-level
security workflows. Free functions `protect_oscore` and `unprotect_oscore`
have the same typed inputs and outputs for generated-tool ergonomics.

`Debug`, `summary`, `Display`, and errors redact master secret, master salt,
derived keys, authentication keys, and recovered plaintext. `OscoreOption`
preserves its complete raw bytes plus parsed base fields. Unsupported or
provisional flag material remains inspectable and returns `OscoreError`
instead of selecting guessed behavior.

Stable group request/response packet facts use `CoapGroupMetadata` and
`CoapGroupMatch`. They inspect multicast destination, Non-confirmable type,
token-only response matching, and endpoint metadata without joining groups or
retaining response state. `GroupOscoreMetadata` is opaque and provisional; it
preserves group flag, identifiers, ciphertext, authentication, and signature
material but exposes no stable Group OSCORE serializer or protection method
until a final numbered RFC is reviewed.

## Semantic validation

Structural decode and compilation do not reject unknown assignments or repair
explicit malformed values. Opt-in validation is separate:

```rust
pub struct CoapValidation {
    issues: Vec<CoapValidationIssue>,
}

pub struct CoapValidationIssue {
    // Stable field/context, severity, and source-backed reason.
}

pub enum CoapValidationSeverity {
    Warning,
    Error,
}
```

`Coap::validate()` and `CoapReliable::validate()` return `CoapValidation`.
Validation reports role-inappropriate codes, version/type/code combinations,
TKL/token mismatches, option order and format issues, marker/payload mismatch,
Empty-message violations, option interactions, reliable framing mismatch, and
unsupported security metadata. It never mutates or normalizes the message.

## Direct decode entrypoints

Explicit decode treats the bytes as CoAP and returns structured `CrafterError`
values with the stable contexts defined by the grammar and later error-policy
note:

```rust
pub fn decode_coap(data: &[u8]) -> Result<Coap>;
pub fn decode_coap_reliable(data: &[u8]) -> Result<(CoapReliable, usize)>;

impl Coap {
    pub fn decode(data: &[u8]) -> Result<Self>;
}

impl CoapReliable {
    pub fn decode(data: &[u8]) -> Result<(Self, usize)>;
}
```

`decode_coap` consumes one complete datagram slice. `decode_coap_reliable`
consumes one complete frame and reports its boundary; following bytes remain
the caller's responsibility. Neither function silently returns `Raw`.

The built-in `ProtocolRegistry` uses internal
`looks_like_coap_datagram_payload` and `looks_like_coap_reliable_frame`
predicates. Cleartext service ports are hints only. Malformed candidates,
reserved-version datagrams, incomplete reliable frames, UDP/5684 ciphertext,
and TCP/5684 protected traffic remain `Raw`. Registry decode does not add TCP
stream reassembly.

## Stable inspection contract

`Layer::name()` returns `"Coap"` and `"CoapReliable"` respectively.

`Coap::summary()` has this stable field order:

```text
Coap(version=<n>, type=<label>, code=<C.DD(label)>, mid=0xNNNN, token_len=<n>, options=<n>, marker=<absent|present>, payload=<n> bytes)
```

`CoapReliable::summary()` has this stable field order:

```text
CoapReliable(length=<n>, code=<C.DD(label)>, token_len=<n>, options=<n>, marker=<absent|present>, payload=<n> bytes)
```

`show()` uses the existing `Layer::inspection_fields()` path. `Coap` fields
are exactly `version`, `type`, `token_length`, `code`, `message_id`, `token`,
`options`, `payload_marker`, and `payload_length`. `CoapReliable` fields are
exactly `length`, `token_length`, `code`, `token`, `options`,
`payload_marker`, and `payload_length`. Token and option bytes use bounded
hexadecimal inspection; OSCORE secrets and cleartext are never included.
Unknown values use the stable fallback labels from the codepoint snapshot.

## Packet helpers

Helpers assemble ordinary typed packet stacks and never send:

```rust
pub fn coap_request_udp() -> Udp;
pub fn coap_response_udp() -> Udp;
pub fn coap_ipv4_request(src: Ipv4Addr, dst: Ipv4Addr, message: Coap) -> Packet;
pub fn coap_ipv4_response(src: Ipv4Addr, dst: Ipv4Addr, message: Coap) -> Packet;
pub fn coap_ipv6_request(src: Ipv6Addr, dst: Ipv6Addr, message: Coap) -> Packet;
pub fn coap_ipv6_response(src: Ipv6Addr, dst: Ipv6Addr, message: Coap) -> Packet;
pub fn coap_discovery_request() -> Coap;
pub fn coap_discovery_response(links: CoapLinkFormat) -> Coap;
```

Request UDP defaults set destination port `COAP_PORT`; response defaults set
source port `COAP_PORT`. Callers may override either port. Tracked examples use
documentation addresses and compile, decode, pcap, or dry-run paths only.

## Registry metadata

Registry lookup is inspectable metadata, never a parse gate:

```rust
pub enum CoapRegistryStatus {
    Assigned,
    Temporary,
    Unassigned,
    Reserved,
    Documentation,
    Experimental,
    DraftBacked,
    Unknown,
}

pub struct CoapRegistryMeta {
    pub value: u64,
    pub label: String,
    pub status: CoapRegistryStatus,
    pub reference: Option<&'static str>,
}

pub enum CoapTransport {
    Udp,
    Tcp,
}
```

The exported lookup functions are `coap_code_meta`, `coap_option_meta`,
`coap_content_format_meta`, `coap_signaling_code_meta`,
`coap_signaling_option_meta`, `coap_oscore_flag_meta`, and
`coap_service_meta`. Each accepts the corresponding typed value or raw numeric
key and returns `CoapRegistryMeta` with the frozen fallback labels. No lookup
rejects an unknown value.

## Constants

The root/core/prelude constants introduced by this work are exactly:

- Base layout and bit fields: `COAP_HEADER_LEN`, `COAP_VERSION_1`,
  `COAP_VERSION_MASK`, `COAP_VERSION_SHIFT`, `COAP_TYPE_MASK`,
  `COAP_TYPE_SHIFT`, `COAP_TKL_MASK`, `COAP_CODE_CLASS_MASK`,
  `COAP_CODE_CLASS_SHIFT`, `COAP_CODE_DETAIL_MASK`, `COAP_PAYLOAD_MARKER`, and
  `COAP_MAX_TOKEN_LEN`.
- Service ports: `COAP_PORT` and `COAPS_PORT`.
- Option numbers: `COAP_OPTION_IF_MATCH`, `COAP_OPTION_URI_HOST`,
  `COAP_OPTION_ETAG`, `COAP_OPTION_IF_NONE_MATCH`, `COAP_OPTION_OBSERVE`,
  `COAP_OPTION_URI_PORT`, `COAP_OPTION_LOCATION_PATH`, `COAP_OPTION_OSCORE`,
  `COAP_OPTION_URI_PATH`, `COAP_OPTION_CONTENT_FORMAT`, `COAP_OPTION_MAX_AGE`,
  `COAP_OPTION_URI_QUERY`, `COAP_OPTION_HOP_LIMIT`, `COAP_OPTION_ACCEPT`,
  `COAP_OPTION_Q_BLOCK1`, `COAP_OPTION_LOCATION_QUERY`, `COAP_OPTION_BLOCK2`,
  `COAP_OPTION_BLOCK1`, `COAP_OPTION_SIZE2`, `COAP_OPTION_Q_BLOCK2`,
  `COAP_OPTION_PROXY_URI`, `COAP_OPTION_PROXY_SCHEME`, `COAP_OPTION_SIZE1`,
  `COAP_OPTION_ECHO`, `COAP_OPTION_NO_RESPONSE`, and
  `COAP_OPTION_REQUEST_TAG`.
- Content formats needed by typed helpers: `COAP_CONTENT_FORMAT_LINK_FORMAT`,
  `COAP_CONTENT_FORMAT_MISSING_BLOCKS_CBOR_SEQ`, and
  `COAP_CONTENT_FORMAT_OSCORE`.

Assigned codes and signaling values are expressed through the named
`CoapCode` constructors rather than a duplicate root-level constant for every
wire byte. Contextual signaling option numbers are expressed through typed
constructors on `CoapSignalingOption`, avoiding ambiguous root constants such
as an unqualified option number 2.

## Exact curated exports

`crafter::protocols::coap` exports the full module surface described above.
The crate's curated `protocols::exports` module promotes exactly the following
CoAP symbols to all three aggregate paths: `crafter::<name>`,
`crafter::core::<name>`, and `crafter::prelude::<name>`.

Types:

```text
Coap, CoapVersion, CoapMessageType, CoapCode, CoapToken, CoapTokenLength,
CoapPayloadMarker, CoapOptionNumber, CoapOption, CoapOptionEncoding,
CoapOptionFormat, CoapUriHost, CoapUriPort, CoapUriPath, CoapUriQuery,
CoapProxyUri, CoapProxyScheme, CoapIfMatch, CoapIfNoneMatch, CoapEtag,
CoapContentFormat, CoapAccept, CoapMaxAge, CoapLocationPath,
CoapLocationQuery, CoapSize1, CoapSize2, CoapObserve, CoapObserveOrdering,
CoapNoResponse, CoapHopLimit, CoapHopLimitExhausted, CoapEcho,
CoapRequestTag, CoapBlockKind, CoapBlock, CoapBlockTransport,
CoapBlockValidation, CoapLinkFormat, CoapLink, CoapLinkAttribute,
CoapLinkAttributeValue, CoapReliable, CoapReliableLength,
CoapSignalingOption, OscoreOption, OscoreContext, OscoreRequestBinding,
OscoreProtectParams, OscoreUnprotectParams, OscoreAeadAlgorithm,
OscoreKdfAlgorithm, OscoreError, CoapGroupMetadata, CoapGroupMatch,
GroupOscoreMetadata, CoapValidation, CoapValidationIssue,
CoapValidationSeverity, CoapRegistryStatus, CoapRegistryMeta, CoapTransport
```

Functions:

```text
decode_coap, decode_coap_reliable, protect_oscore, unprotect_oscore,
coap_request_udp, coap_response_udp, coap_ipv4_request, coap_ipv4_response,
coap_ipv6_request, coap_ipv6_response, coap_discovery_request,
coap_discovery_response, coap_code_meta, coap_option_meta,
coap_content_format_meta, coap_signaling_code_meta,
coap_signaling_option_meta, coap_oscore_flag_meta, coap_service_meta
```

The constants are exactly the names in the preceding Constants section.
`crafter::core` already re-exports `protocols::exports`, and `prelude` already
re-exports `core`, so implementation adds the CoAP list once to
`crafter/src/protocols/mod.rs`; it must not maintain three divergent lists.

No compatibility aliases, deprecated spellings, glob-only shadow surface, or
second packet API are added for names introduced by this work. Adding or
renaming a curated CoAP symbol requires an explicit revision of this design
before the implementation export step.
