# SSDP public API design

This note sketches the provisional public API for SSDP before any Rust surface
is exported. It is a design handoff, not an implementation. Wire facts remain
gated by `.agents/docs/ssdp-source-manifest.md`,
`.agents/docs/ssdp-wire-grammar.md`, `.agents/docs/ssdp-codepoints.md`, and
the public UPnP, RFC, IANA, Datatracker, and errata sources cited there.

SSDP support in `crafter` is a packet primitive. The API must compose through
the existing typed `Packet` abstraction, decode through the existing UDP
application path, and expose inspection through `summary()` and `show()`. It
must not grow a scanner, discovery daemon, control point, retry scheduler,
service cache, HTTP client, or multicast membership manager.

## Design constraints

- `Ssdp` is the UDP application layer type. It stores one source-backed
  HTTP-like SSDP message carried in one UDP payload.
- Builder defaults may fill only fields the caller left unset. Explicit caller
  values, including malformed values used for tests, must survive compile and
  serialization.
- Unknown but structurally valid methods, status codes, reason phrases, header
  names, extension fields, duplicate headers, values, casing, ordering, and
  body bytes are preserved.
- Registry-driven UDP decode must first pass the conservative SSDP shape gate.
  UDP payloads on SSDP-related ports that do not pass the gate remain `Raw`.
- Explicit SSDP parsing returns structured errors for malformed candidates
  rather than panicking, truncating silently, or normalizing data away.
- Packet helper functions return typed `Packet` values, not raw bytes plus
  instructions.

## Layer and message types

The initial module should live under `crafter/src/protocols/ssdp/` and expose a
small stable surface after parser, serializer, and tests land.

```rust
pub struct Ssdp {
    message: SsdpMessage,
}

pub struct SsdpMessage {
    start_line: SsdpStartLine,
    headers: SsdpHeaders,
    body: Vec<u8>,
}

pub enum SsdpStartLine {
    Request(SsdpRequestLine),
    Response(SsdpStatusLine),
}
```

`Ssdp` is the layer a generated tool composes as `Ip / Udp / Ssdp`. It should
implement the same layer, compile, decode, summary, and show traits used by
neighboring application protocols. `SsdpMessage` owns the exact data needed to
round-trip the UDP payload: start line, ordered field lines, delimiter, and
opaque body bytes.

## Start-line wrappers

```rust
pub struct SsdpRequestLine {
    pub method: SsdpMethod,
    pub target: SsdpRequestTarget,
    pub version: SsdpVersion,
}

pub struct SsdpStatusLine {
    pub version: SsdpVersion,
    pub code: SsdpStatusCode,
    pub reason: SsdpReasonPhrase,
}

pub enum SsdpMethod {
    Notify,
    MSearch,
    Unknown(String),
}

pub struct SsdpRequestTarget(String);
pub struct SsdpVersion(String);
pub struct SsdpStatusCode(u16);
pub struct SsdpReasonPhrase(String);
```

Named constructors should cover the source-backed SSDP request and response
families from the codepoint table: `NOTIFY * HTTP/1.1`, `M-SEARCH * HTTP/1.1`,
and `HTTP/1.1 200 OK`. The wrappers must also retain unknown method tokens,
unknown request targets, non-default version tokens, unknown three-digit status
codes, and unusual reason phrases when the enclosing start line is structurally
valid.

## Headers and values

```rust
pub struct SsdpHeader {
    pub name: SsdpHeaderName,
    pub value: SsdpHeaderValue,
}

pub struct SsdpHeaders(Vec<SsdpHeader>);

pub enum SsdpHeaderName {
    Host,
    CacheControl,
    Location,
    Nt,
    Nts,
    Server,
    Usn,
    Man,
    Mx,
    St,
    Ext,
    BootId,
    ConfigId,
    SearchPort,
    NextBootId,
    SecureLocation,
    UserAgent,
    TcpPort,
    Cpfn,
    Cpuuid,
    Opt,
    NlsPrefixed(String),
    Unknown(String),
}

pub struct SsdpHeaderValue {
    raw: Vec<u8>,
}
```

Header lookup is case-insensitive, but serialization and inspection preserve
the original spelling, order, duplicates, empty values, and unknown extension
fields. `SsdpHeaders` should therefore provide both ordered iteration and
helper lookup:

- `iter()` returns every stored header in wire order.
- `get_first(name)` returns the first matching value without merging.
- `get_all(name)` returns all matching values in wire order.
- `push_raw(name, value)` appends a caller-supplied field without rewriting it.
- `set_source_default(name, value)` is available only to builders when a field
  is unset.

Typed value wrappers may be added for source-backed header families, but each
wrapper must retain the original raw value:

```rust
pub struct SsdpTarget(String);
pub struct SsdpLocation(String);
pub struct SsdpUsn(String);
pub struct SsdpCacheControl(String);
pub struct SsdpMaxAge(u32);
pub struct SsdpMx(u32);
pub struct SsdpServer(String);
pub struct SsdpBootId(u32);
pub struct SsdpConfigId(u32);
pub struct SsdpExtensionHeader {
    pub name: SsdpHeaderName,
    pub value: SsdpHeaderValue,
}
```

Value helpers may validate or parse only the portion authorized by the source
documents. They must never reject or discard an unknown value during generic
SSDP decoding.

## Constants

Constants should be exported only after the codepoint table and implementation
tests agree on names. The initial names may follow the existing protocol style:

```rust
pub const SSDP_SERVICE_NAME: &str = "ssdp";
pub const SSDP_UDP_PORT: u16 = 1900;
pub const SSDP_HTTP_VERSION: &str = "HTTP/1.1";
pub const SSDP_METHOD_NOTIFY: &str = "NOTIFY";
pub const SSDP_METHOD_M_SEARCH: &str = "M-SEARCH";
pub const SSDP_STATUS_OK: u16 = 200;
pub const SSDP_REASON_OK: &str = "OK";
pub const SSDP_IPV4_MULTICAST: &str = "239.255.255.250";
pub const SSDP_IPV6_LINK_LOCAL_MULTICAST: &str = "ff02::c";
pub const SSDP_IPV6_SITE_LOCAL_MULTICAST: &str = "ff05::c";
```

Named header constants should mirror `.agents/docs/ssdp-codepoints.md` and stay
limited to UPnP-backed discovery headers. `ssdp/tcp`, global-scope IPv6
multicast, eventing-only fields, generic HTTP methods, and draft-only values
must not become SSDP defaults.

## Builder helpers

`Ssdp` should expose constructors for packet-layer messages, not workflow
actions:

```rust
impl Ssdp {
    pub fn new(message: SsdpMessage) -> Self;
    pub fn m_search() -> Self;
    pub fn notify_alive() -> Self;
    pub fn notify_byebye() -> Self;
    pub fn notify_update() -> Self;
    pub fn response_ok() -> Self;
    pub fn with_header(self, name: impl Into<SsdpHeaderName>, value: impl Into<SsdpHeaderValue>) -> Self;
    pub fn with_body(self, body: impl Into<Vec<u8>>) -> Self;
}
```

Typed helper methods should cover common source-backed field values while
remaining override-friendly:

```rust
impl Ssdp {
    pub fn host(self, value: impl Into<SsdpHeaderValue>) -> Self;
    pub fn search_target(self, value: impl Into<SsdpTarget>) -> Self;
    pub fn notification_type(self, value: impl Into<SsdpTarget>) -> Self;
    pub fn notification_subtype(self, value: impl Into<SsdpHeaderValue>) -> Self;
    pub fn unique_service_name(self, value: impl Into<SsdpUsn>) -> Self;
    pub fn location(self, value: impl Into<SsdpLocation>) -> Self;
    pub fn cache_control(self, value: impl Into<SsdpCacheControl>) -> Self;
    pub fn max_age(self, seconds: u32) -> Self;
    pub fn man_discover(self) -> Self;
    pub fn mx(self, seconds: u32) -> Self;
    pub fn ext_empty(self) -> Self;
    pub fn server(self, value: impl Into<SsdpServer>) -> Self;
    pub fn boot_id(self, value: u32) -> Self;
    pub fn config_id(self, value: u32) -> Self;
}
```

Helpers fill missing fields for the selected message family, but they do not
lock the caller into valid SSDP. Callers must be able to replace method,
version, status, reason, target, headers, and body bytes for boundary and
malformed-packet validation.

## Decode helpers

The module should separate explicit parsing from registry-driven application
decode:

```rust
impl Ssdp {
    pub fn parse(data: &[u8]) -> Result<Self, SsdpParseError>;
    pub fn is_shape_candidate(data: &[u8]) -> bool;
}
```

`parse` treats the payload as an SSDP candidate and returns structured errors
for malformed start lines, headers, delimiters, and invalid tokens. The
registry path uses `is_shape_candidate` before parsing so unrelated UDP
payloads on port `1900` stay `Raw`. Decode helpers must preserve bodies as
opaque bytes after a valid header delimiter and must not consume UDP options or
surplus data from lower layers.

## Packet helper shapes

Packet helpers should assemble documentation-safe packet stacks while returning
typed `Packet` values:

```rust
pub fn ssdp_ipv4_m_search(src: Ipv4Addr, dst: Ipv4Addr, message: Ssdp) -> Packet;
pub fn ssdp_ipv4_notify(src: Ipv4Addr, dst: Ipv4Addr, message: Ssdp) -> Packet;
pub fn ssdp_ipv6_m_search(src: Ipv6Addr, dst: Ipv6Addr, message: Ssdp) -> Packet;
pub fn ssdp_ipv6_notify(src: Ipv6Addr, dst: Ipv6Addr, message: Ssdp) -> Packet;
```

Later multicast helpers may provide convenience constructors around the
source-backed IPv4 and IPv6 SSDP multicast constants, but they still return a
typed `Packet` and do not send traffic, join groups, choose interfaces, manage
hop limits, retry searches, or collect responses.

## Export path

After implementation and tests stabilize, the curated public surface should be
exported through `crafter/src/protocols/mod.rs` and `crafter::prelude::*`.
Generated tools should be able to use:

```rust
use crafter::prelude::*;

let packet: Packet = Ipv4::new() / Udp::new() / Ssdp::m_search();
```

Until that export step lands, this file is the intended API sketch only.
