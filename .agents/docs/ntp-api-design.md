# NTP public API design

This note sketches the planned public API for NTP before any Rust surface is
exported. It is a design handoff, not an implementation. Wire facts remain
gated by `.agents/docs/ntp-rfc-manifest.md`,
`.agents/docs/ntp-wire-grammar.md`, and
`.agents/docs/ntp-codepoints.md`.

NTP support in `crafter` is a packet primitive. The API must compose through
the existing typed `Packet` abstraction, decode through the UDP application
path, and expose inspection through `summary()` and `show()`. It must not add a
clock daemon, synchronization loop, pool client, NTS-KE workflow, Autokey
verifier, scanner, or live sender.

## Design constraints

- `Ntp` is the UDP application layer type for one NTP packet carried in one UDP
  payload.
- Builder defaults may fill only fields the caller left unset. Explicit caller
  values, including malformed values used for tests, must survive compile and
  serialization.
- Unknown but structurally valid versions, modes, strata, reference IDs,
  extension field types, NTS bodies, MAC bytes, and packet tails are preserved.
- Registry-driven UDP decode must first pass the conservative NTP shape gate.
  UDP/123 payloads that do not pass the gate remain `Raw`.
- Direct NTP parsing returns structured errors for malformed candidates rather
  than panicking, truncating silently, or normalizing data away.
- All helpers return typed layers or `Packet` values. They must not return raw
  bytes plus instructions for the caller to assemble later.
- Names introduced by this work do not get backward-compatible aliases.

## Layer and field types

The initial module should live under `crafter/src/protocols/ntp/` and expose a
small stable surface after parser, serializer, and tests land.

```rust
pub struct Ntp {
    // Fixed-header fields plus raw-preserving extension fields and MAC tail.
}

pub enum NtpLeapIndicator {
    NoWarning,
    LastMinute61Seconds,
    LastMinute59Seconds,
    AlarmUnsynchronized,
}

pub struct NtpMode(u8);
pub struct NtpStratum(u8);
pub struct NtpTimestamp(u64);
pub struct NtpShortFormat(u32);
pub struct NtpReferenceId([u8; 4]);
```

`Ntp` is the layer generated tools compose as `Ip / Udp / Ntp`. It should
implement the same layer, compile, decode, summary, and show traits used by
neighboring application protocols. Field wrappers expose source-backed labels
where known while preserving the exact wire value for round-trip compilation.

## Tail and extension types

Extension fields and MAC data are packet data, not cryptographic workflows.

```rust
pub struct NtpExtensionField {
    pub field_type: NtpExtensionFieldType,
    pub body: Vec<u8>,
    pub padding: Vec<u8>,
}

pub struct NtpExtensionFieldType(u16);
pub struct NtpMac(Vec<u8>);

pub struct NtpNtsAuthenticator {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub padding: Vec<u8>,
}
```

`NtpExtensionField` preserves unknown field types and byte-exact extension
contents when the RFC 7822 envelope is structurally valid. NTS helpers may label
known packet extension bodies, including the authenticator field, but they must
not perform NTS-KE, AEAD encryption or decryption, cookie construction,
authentication decisions, or replay-cache behavior. `NtpMac` preserves legacy
MAC tail bytes without computing or verifying them.

## Constants

The public UDP service constant planned for generated tools is:

```rust
pub const NTP_PORT: u16 = 123;
```

`NTP_PORT` is a packet-construction default and decode binding for UDP/123. It
does not authorize live traffic. TCP/123 remains only a service-registry fact
unless a later source-backed packet primitive explicitly adds TCP behavior.

## Builder helpers

`Ntp` should expose constructors for packet-layer messages, not workflow
actions:

```rust
impl Ntp {
    pub fn new() -> Self;
    pub fn client() -> Self;
    pub fn server() -> Self;
    pub fn symmetric_active() -> Self;
    pub fn broadcast() -> Self;

    pub fn with_leap_indicator(self, value: NtpLeapIndicator) -> Self;
    pub fn with_version(self, value: u8) -> Self;
    pub fn with_mode(self, value: NtpMode) -> Self;
    pub fn with_stratum(self, value: NtpStratum) -> Self;
    pub fn with_poll(self, value: i8) -> Self;
    pub fn with_precision(self, value: i8) -> Self;
    pub fn with_root_delay(self, value: NtpShortFormat) -> Self;
    pub fn with_root_dispersion(self, value: NtpShortFormat) -> Self;
    pub fn with_reference_id(self, value: NtpReferenceId) -> Self;
    pub fn with_reference_timestamp(self, value: NtpTimestamp) -> Self;
    pub fn with_origin_timestamp(self, value: NtpTimestamp) -> Self;
    pub fn with_receive_timestamp(self, value: NtpTimestamp) -> Self;
    pub fn with_transmit_timestamp(self, value: NtpTimestamp) -> Self;
    pub fn with_extension_field(self, value: NtpExtensionField) -> Self;
    pub fn with_mac(self, value: NtpMac) -> Self;
}
```

Named constructors fill the source-backed defaults for the selected packet
shape, but callers must be able to replace LI, version, mode, stratum, poll,
precision, root fields, reference ID, timestamps, extension fields, and MAC
bytes for boundary and malformed-packet validation.

## Decode helpers

The module should separate explicit parsing from registry-driven application
decode:

```rust
impl Ntp {
    pub fn parse(data: &[u8]) -> Result<Self, NtpParseError>;
    pub fn is_shape_candidate(data: &[u8]) -> bool;
}
```

`parse` treats the payload as an NTP candidate and returns structured errors
for short buffers, malformed extension lengths, invalid alignment, impossible
tail partitions, and truncation. The registry path uses `is_shape_candidate`
before parsing so unrelated or malformed UDP/123 payloads stay `Raw`.

## Packet helper shapes

Packet helpers should assemble documentation-safe packet stacks while returning
typed `Packet` values:

```rust
pub fn ntp_ipv4_client_request(src: Ipv4Addr, dst: Ipv4Addr, ntp: Ntp) -> Packet;
pub fn ntp_ipv4_server_response(src: Ipv4Addr, dst: Ipv4Addr, ntp: Ntp) -> Packet;
pub fn ntp_ipv6_client_request(src: Ipv6Addr, dst: Ipv6Addr, ntp: Ntp) -> Packet;
pub fn ntp_ipv6_server_response(src: Ipv6Addr, dst: Ipv6Addr, ntp: Ntp) -> Packet;
```

These helpers set UDP source or destination ports to `NTP_PORT` where
appropriate and return composed `Packet` values. They do not send traffic,
select interfaces, choose real peers, retry requests, adjust clocks, or collect
responses. Examples that use them must stay offline or dry-run by default and
use documentation address space.

## Export path

After implementation and tests stabilize, the curated public surface should be
exported through `crafter/src/protocols/mod.rs`, the crate root/core exports,
and `crafter::prelude::*`. Generated tools should be able to use:

```rust
use crafter::prelude::*;

let packet: Packet = Ipv4::new() / Udp::new() / Ntp::client();
```

The prelude export must include `Ntp`, `NtpLeapIndicator`, `NtpMode`,
`NtpStratum`, `NtpTimestamp`, `NtpShortFormat`, `NtpReferenceId`,
`NtpExtensionField`, `NtpExtensionFieldType`, `NtpMac`,
`NtpNtsAuthenticator`, `NTP_PORT`, and the packet helper functions. No
backward-compatible aliases should be added for these new names.
