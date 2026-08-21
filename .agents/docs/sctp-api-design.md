# SCTP public API design

This note sketches the planned public API for SCTP before any Rust surface is
exported. It is a design handoff, not an implementation. Wire facts remain
gated by `.agents/docs/sctp-rfc-manifest.md`,
`.agents/docs/sctp-codepoints.md`, `.agents/docs/sctp-wire-grammar.md`,
and `.agents/docs/sctp-scope.md`.

SCTP support in `crafter` is a packet primitive. The API must compose through
the existing typed `Packet` abstraction, decode through native IPv4/IPv6
protocol dispatch and guarded RFC 6951 UDP encapsulation, and expose
inspection through `summary()` and `show()`. It must not grow an SCTP
association stack, retransmission service, congestion controller, socket API,
endpoint daemon, scanner, fuzzer, analyzer, or live sender.

## Design constraints

- `Sctp` is the transport layer type for one SCTP packet.
- Builders may fill only fields the caller left unset. Explicit caller values,
  including malformed values used for tests, must survive compile and
  serialization.
- `compile()` fills unset dependent fields such as SCTP chunk lengths,
  parameter lengths, cause lengths, alignment padding, CRC32c checksum, IPv4
  protocol, and IPv6 next-header values.
- Unknown but structurally valid chunks, parameters, causes, flags, PPIDs, HMAC
  identifiers, adaptation code points, and error-detection method identifiers
  are preserved as inspectable packet data.
- Native SCTP decode is selected from IP protocol / IPv6 next-header value
  `132`. UDP-encapsulated SCTP decode is admitted only behind a conservative
  RFC 6951 shape gate for UDP port `9899`; unrelated UDP payloads remain
  `Raw`.
- Direct SCTP parsing returns structured `CrafterError` values for malformed
  common headers, chunk lengths, parameter lengths, cause lengths, and
  truncation. It must not panic, silently truncate, or normalize packet bytes
  away.
- All helpers return typed SCTP values or `Packet` values. They must not return
  raw bytes plus instructions for the caller to assemble later.
- Names introduced by this work do not get backward-compatible aliases.

## Layer and common-header types

The initial module should live under `crafter/src/protocols/transport/sctp/`
and expose a small stable surface after parser, serializer, checksum, registry
dispatch, and tests land.

```rust
pub struct Sctp {
    // Common header fields plus chunk storage and decoded checksum status.
}

pub enum SctpChecksumStatus {
    NotChecked,
    Valid,
    Invalid,
    ZeroChecksum,
}
```

`Sctp` is the layer generated tools compose as `Ip / Sctp`. It should implement
the same layer, compile, decode, summary, and show traits used by neighboring
transport protocols. Header fields are the RFC 9260 common-header fields:
source port, destination port, verification tag, and CRC32c checksum. Port `0`,
invalid verification-tag combinations, and invalid checksums remain
constructible when explicitly supplied.

`SctpChecksumStatus` is decode-time inspection metadata. A valid CRC32c is
reported as valid; a mismatch is reported as invalid while the packet remains
inspectable. `ZeroChecksum` records an observed zero checksum so RFC 9653
handling can remain explicit instead of being silently treated as ordinary
valid traffic.

## Chunk model

Chunks are stored in wire order and expose both typed variants and raw
preserving wrappers.

```rust
pub enum SctpChunk {
    Data(SctpDataChunk),
    Init(SctpInitChunk),
    InitAck(SctpInitAckChunk),
    Sack(SctpSackChunk),
    Heartbeat(SctpHeartbeatChunk),
    HeartbeatAck(SctpHeartbeatAckChunk),
    Abort(SctpAbortChunk),
    Shutdown(SctpShutdownChunk),
    ShutdownAck(SctpShutdownAckChunk),
    Error(SctpErrorChunk),
    CookieEcho(SctpCookieEchoChunk),
    CookieAck(SctpCookieAckChunk),
    Ecne(SctpEcneChunk),
    Cwr(SctpCwrChunk),
    ShutdownComplete(SctpShutdownCompleteChunk),
    Auth(SctpAuthChunk),
    IData(SctpIDataChunk),
    AsconfAck(SctpAsconfAckChunk),
    ReConfig(SctpReConfigChunk),
    Pad(SctpPadChunk),
    ForwardTsn(SctpForwardTsnChunk),
    Asconf(SctpAsconfChunk),
    IForwardTsn(SctpIForwardTsnChunk),
    Unknown(SctpUnknownChunk),
}

pub struct SctpChunkType(u8);

pub struct SctpUnknownChunk {
    pub chunk_type: SctpChunkType,
    pub flags: u8,
    pub value: Vec<u8>,
    pub padding: Vec<u8>,
}
```

The type list mirrors `.agents/docs/sctp-codepoints.md`. Later implementation
steps should add typed fields only for chunk families admitted by those steps.
Until then, assigned extension chunks can be label-aware but raw-preserving.
The `Unknown` variant is for unassigned, reserved, temporary, private, obsolete,
or future chunk types whose envelope is structurally valid.

Every chunk type must preserve flags as the exact 8-bit wire value. Helpers may
label DATA and I-DATA E/B/U/I bits and ABORT or SHUTDOWN COMPLETE T bits, but
they must not clear unassigned flag bits supplied by the caller or observed on
decode.

## Parameter and cause model

Parameters and error causes use parameter-shaped TLV envelopes but separate
registries. They should therefore have separate public models while sharing
internal parsing helpers where that keeps the implementation simple.

```rust
pub enum SctpParameter {
    HeartbeatInfo(SctpHeartbeatInfoParameter),
    Ipv4Address(SctpIpv4AddressParameter),
    Ipv6Address(SctpIpv6AddressParameter),
    StateCookie(SctpStateCookieParameter),
    UnrecognizedParameter(SctpUnrecognizedParameter),
    CookiePreservative(SctpCookiePreservativeParameter),
    HostNameAddress(SctpHostNameAddressParameter),
    SupportedAddressTypes(SctpSupportedAddressTypesParameter),
    ZeroChecksumAcceptable(SctpZeroChecksumAcceptableParameter),
    Auth(SctpAuthParameter),
    Padding(SctpPaddingParameter),
    SupportedExtensions(SctpSupportedExtensionsParameter),
    ForwardTsnSupported(SctpForwardTsnSupportedParameter),
    AddIpAddress(SctpAddIpAddressParameter),
    DeleteIpAddress(SctpDeleteIpAddressParameter),
    ErrorCauseIndication(SctpErrorCauseIndicationParameter),
    SetPrimaryAddress(SctpSetPrimaryAddressParameter),
    SuccessIndication(SctpSuccessIndicationParameter),
    AdaptationLayerIndication(SctpAdaptationLayerIndicationParameter),
    Unknown(SctpUnknownParameter),
}

pub enum SctpErrorCause {
    InvalidStreamIdentifier(SctpInvalidStreamIdentifierCause),
    MissingMandatoryParameter(SctpMissingMandatoryParameterCause),
    StaleCookie(SctpStaleCookieCause),
    OutOfResource(SctpOutOfResourceCause),
    UnresolvableAddress(SctpUnresolvableAddressCause),
    UnrecognizedChunkType(SctpUnrecognizedChunkTypeCause),
    InvalidMandatoryParameter(SctpInvalidMandatoryParameterCause),
    UnrecognizedParameters(SctpUnrecognizedParametersCause),
    NoUserData(SctpNoUserDataCause),
    CookieReceivedWhileShuttingDown(SctpCookieReceivedWhileShuttingDownCause),
    RestartWithNewAddresses(SctpRestartWithNewAddressesCause),
    UserInitiatedAbort(SctpUserInitiatedAbortCause),
    ProtocolViolation(SctpProtocolViolationCause),
    Unknown(SctpUnknownErrorCause),
}

pub struct SctpParameterType(u16);
pub struct SctpErrorCauseCode(u16);
pub struct SctpPayloadProtocolIdentifier(u32);
```

Typed variants expose source-backed fields only after their implementation
steps land. Unknown parameter and cause wrappers preserve numeric codepoints,
declared value bytes, and padding bytes. The two highest bits of unknown
parameter types and chunk types may be exposed through helper methods for
summary and validation, but those bits remain part of the original numeric
value.

PPID labels are metadata for DATA and I-DATA summaries. The SCTP layer must not
dispatch application decoders solely from PPID values unless a later
source-backed application protocol step admits that behavior.

## Constants and labels

Public constants should use the current transport-module naming style and cite
the evidence notes when implemented.

```rust
pub const SCTP_COMMON_HEADER_LEN: usize = 12;
pub const SCTP_CHUNK_HEADER_LEN: usize = 4;
pub const SCTP_PARAMETER_HEADER_LEN: usize = 4;
pub const SCTP_ERROR_CAUSE_HEADER_LEN: usize = 4;
pub const SCTP_UDP_ENCAP_PORT: u16 = 9899;
pub const SCTP_IP_PROTOCOL: u8 = 132;
```

Chunk type, parameter type, cause code, PPID, HMAC ID, adaptation code point,
and error-detection method constants should follow the IANA names recorded in
`.agents/docs/sctp-codepoints.md`. Classification helpers should preserve
numeric values:

```rust
pub fn sctp_chunk_type_name(value: u8) -> Option<&'static str>;
pub fn sctp_parameter_type_name(value: u16) -> Option<&'static str>;
pub fn sctp_error_cause_name(value: u16) -> Option<&'static str>;
pub fn sctp_ppid_name(value: u32) -> Option<&'static str>;
```

These helpers are labels for inspection and summaries. They are not validators
that reject unknown codepoints.

## Builder helpers

`Sctp` should expose packet-layer constructors and override-friendly setters:

```rust
impl Sctp {
    pub fn new() -> Self;

    pub fn source_port(self, value: u16) -> Self;
    pub fn sport(self, value: u16) -> Self;
    pub fn destination_port(self, value: u16) -> Self;
    pub fn dport(self, value: u16) -> Self;
    pub fn verification_tag(self, value: u32) -> Self;
    pub fn vtag(self, value: u32) -> Self;
    pub fn checksum(self, value: u32) -> Self;
    pub fn chksum(self, value: u32) -> Self;

    pub fn chunk(self, value: impl Into<SctpChunk>) -> Self;
    pub fn chunks(self, values: impl IntoIterator<Item = SctpChunk>) -> Self;
    pub fn clear_chunks(self) -> Self;
}
```

`Sctp::new()` may compile as a header-only layer for deterministic packet
tests and inspection. Chunk-bearing constructors should build at least one
chunk. A caller-supplied checksum, chunk length, parameter length, cause
length, flags value, verification tag, padding byte sequence, or raw payload
must survive unchanged, even when it is reserved, invalid, unknown, nonzero
padding, or deliberately malformed.

Chunk constructors should live on `SctpChunk` and typed chunk structs rather
than becoming workflow actions:

```rust
impl SctpChunk {
    pub fn data(tsn: u32, stream_id: u16, stream_sequence: u16, ppid: u32, user_data: Vec<u8>) -> Self;
    pub fn init(initiate_tag: u32, a_rwnd: u32, outbound_streams: u16, inbound_streams: u16, initial_tsn: u32) -> Self;
    pub fn unknown(chunk_type: u8, flags: u8, value: Vec<u8>) -> Self;
}
```

Typed chunk, parameter, and cause builders may provide source-backed defaults
for their own fields, but they must keep explicit override methods for declared
lengths, flags, padding, and raw value bytes needed by malformed-input tests.

## Decode helpers

The module should separate explicit parsing from registry-driven transport and
UDP-encapsulation decode:

```rust
pub fn decode_sctp(bytes: &[u8]) -> Result<Sctp>;
pub fn looks_like_sctp_payload(bytes: &[u8]) -> bool;
pub fn looks_like_udp_encapsulated_sctp_payload(src_port: u16, dst_port: u16, bytes: &[u8]) -> bool;
```

`decode_sctp` treats the input as an SCTP candidate and returns structured
errors for short common headers, short chunk headers, under-length chunks,
overrun chunks, short parameter or cause headers, under-length parameter or
cause fields, and overrun parameter or cause fields. A decoded packet exposes
the common header, chunk list, byte-preserved unknown values, padding, and
checksum status.

`looks_like_sctp_payload` is for conservative dispatch from native IP protocol
`132` and direct decode tests. `looks_like_udp_encapsulated_sctp_payload` is
stricter: UDP port `9899` is only a registry hint, and the function must reject
unrelated UDP payloads that cannot be structurally decoded as SCTP.

Registry append functions, such as an internal `append_sctp_packet_with_registry`,
should remain crate-private. Public generated-tool entrypoints should be
`Packet::decode_from_l3`, `Packet::decode_from_link`, direct `decode_sctp`, and
typed layer access from `Packet`.

## Packet helper shapes

Packet helpers should assemble documentation-safe packet stacks while returning
typed `Packet` values:

```rust
pub fn sctp_ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, sctp: Sctp) -> Packet;
pub fn sctp_ipv6_packet(src: Ipv6Addr, dst: Ipv6Addr, sctp: Sctp) -> Packet;
pub fn sctp_udp_encapsulated_ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, sctp: Sctp) -> Packet;
pub fn sctp_udp_encapsulated_ipv6_packet(src: Ipv6Addr, dst: Ipv6Addr, sctp: Sctp) -> Packet;
```

These helpers set IP protocol / next-header value `132` or UDP port `9899`
only where appropriate and only for fields the caller has not already set.
They do not send traffic, select interfaces, choose peers, retry exchanges,
join associations, or collect responses. Examples that use them must stay
offline or dry-run by default and use documentation address space.

## Export path

After implementation and tests stabilize, the curated public surface should be
exported through `crafter/src/protocols/transport/mod.rs`,
`crafter/src/protocols/mod.rs`, the crate root/core exports, and
`crafter::prelude::*`. Generated tools should be able to use:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let packet: Packet = Ipv4::new()
    .src(Ipv4Addr::new(192, 0, 2, 10))
    .dst(Ipv4Addr::new(198, 51, 100, 20))
    / Sctp::new()
        .sport(5000)
        .dport(5001)
        .verification_tag(0)
        .chunk(SctpChunk::unknown(63, 0, Vec::new()));

let bytes = packet.compile()?;
let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;
let sctp = decoded.layer::<Sctp>().expect("sctp layer");
```

The prelude export must include `Sctp`, `SctpChecksumStatus`, `SctpChunk`,
`SctpChunkType`, typed chunk structs that have landed, `SctpParameter`,
`SctpParameterType`, typed parameter structs that have landed,
`SctpErrorCause`, `SctpErrorCauseCode`, typed cause structs that have landed,
`SctpPayloadProtocolIdentifier`, public SCTP constants, classification helpers,
direct decode helpers, and packet helper functions.

Do not export crate-private registry append functions, internal TLV cursor
types, checksum scratch buffers, parser state machines, or temporary adapter
types. Do not add compatibility aliases for the new SCTP names.
