# UDP Wire Coverage

This page describes the UDP packet-layer support in the `crafter` crate: what
the `Udp` layer builds and decodes, how the UDP length and checksum are filled
on `compile()`, how deliberate overrides are preserved, how the RFC 9868 UDP
surplus options are modeled, and what is intentionally out of scope.

`crafter` treats UDP as one packet layer, separate from TCP. It composes with
`/`, compiles into a single UDP datagram, decodes from the `decode_from_l3`
entrypoints, and stays inspectable through `summary()`, `show()`, and typed
getters. The `Udp` layer is a packet primitive: it exposes UDP options as typed
packet data, not as an application workflow, and it implements no UDP socket,
demultiplexer, or UDP fragmentation/reassembly engine. For the full API surface
see [the API reference](../reference/api.md).

All wire facts on this page trace to reviewed RFC text and IANA registries. The
RFCs and registries the UDP layer implements are listed in
[Standards and RFCs implemented](#standards-and-rfcs-implemented) at the end of
this guide.

## Coverage at a glance

| Area | State | Notes |
| --- | --- | --- |
| Base header (ports, length, checksum) | Supported | Builder setters; explicit values honored. |
| UDP Length | Auto-filled | Filled over the UDP header plus user data on `compile()`; explicit value preserved, even when intentionally malformed. |
| Checksum (IPv4 / IPv6 pseudo-header) | Auto-filled | Filled from network checksum context; explicit value preserved; IPv4 zero means "no checksum". |
| Checksum status (decode) | Supported | `UdpChecksumStatus`: `Valid`, `Invalid`, `Ipv4NoChecksum`, `Ipv6ZeroChecksum`, `NotChecked`. |
| Surplus options (RFC 9868) | Supported | Typed `UdpOptions` / `UdpOption` surplus layer placed after UDP user data. |
| Option Checksum (OCS) and APC | Auto-filled | OCS over the surplus area and the APC CRC32c over UDP user data filled on `compile()`; explicit values preserved. |
| Options (unknown / UNSAFE) | Supported (preserved) | Preserved with `UnknownSafe` / `UnknownUnsafe` / `UnsupportedFragmentation` status for inspection. |
| Decode (structured errors) | Supported | Malformed headers and options return typed errors with context; never a panic. |
| Inspection (`summary` / `show`) | Supported | One-line summary plus a full field tree. |
| UDP FRAG fragmentation / reassembly | Out of scope | FRAG option preserved and reported as unsupported; no fragment cache, timers, or reassembly. |

## UDP construction

The `Udp` layer is exported through `crafter::prelude::*`. Build it with
`Udp::new()`, set fields with chained setters, and compose it onto an IP layer
with `/`:

```rust
use crafter::prelude::*;

let packet = Ipv4::new()
    .src("192.0.2.10")?
    .dst("198.51.100.20")?
    / Udp::new().sport(40000).dport(53)
    / Raw::from("query");

let bytes = packet.compile()?;
println!("{}", packet.summary());
```

`compile()` fills the UDP Length over the UDP header plus user data and fills the
checksum from the enclosing IPv4 or IPv6 pseudo-header. It honors the crate-wide
rule: anything the builder set survives untouched, including a deliberately wrong
UDP length or checksum so a generated tool can exercise a remote stack with
malformed datagrams.

For IPv4 a transmitted checksum field of zero means the sender generated no UDP
checksum (RFC 768); for IPv6 the checksum is mandatory by default (RFC 8200).
On decode `Udp::checksum_status()` reports validation:

- `Valid` / `Invalid` — a nonzero checksum that does or does not validate; an
  invalid checksum stays inspectable rather than being silently dropped.
- `Ipv4NoChecksum` — an IPv4 zero checksum (no checksum transmitted).
- `Ipv6ZeroChecksum` — an IPv6 zero checksum, which is not accepted as ordinary
  IPv6 UDP. Call `requires_ipv6_zero_checksum_exception()` when a tool explicitly
  supports the RFC 6935 / RFC 6936 tunnel exception model.
- `NotChecked` — no network checksum context was available.

## UDP surplus options (RFC 9868)

UDP options live in the surplus area after the UDP user data and before the end
of the IP transport payload (RFC 9868). They are modeled as a typed `UdpOptions`
surplus layer placed after the UDP payload in the stack:

```rust
use crafter::prelude::*;

let options = UdpOptions::new()
    .udp_option(UdpOption::maximum_datagram_size(1200))?
    .udp_option(UdpOption::echo_request(0x0102_0304))?
    .additional_payload_checksum();

let packet = Ipv4::new()
    .src("192.0.2.10")?
    .dst("198.51.100.20")?
    / Udp::new().sport(53000).dport(33434)
    / Raw::from("probe")
    / options;

let bytes = packet.compile()?;
let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;
let udp = decoded.layer::<Udp>().ok_or("missing UDP")?;
let udp_options = decoded.layer::<UdpOptions>().ok_or("missing UDP options")?;

assert_eq!(udp.checksum_status(), UdpChecksumStatus::Valid);
assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
```

`compile()` fills the normal UDP length and checksum over the UDP user payload,
then materializes the surplus area after that length, filling the UDP Option
Checksum (OCS) over the surplus area and any auto `additional_payload_checksum()`
APC CRC32c over UDP user data. Explicit UDP length, checksum, OCS, and APC values
are preserved, including intentionally wrong values.

Typed options cover EOL, NOP, APC, MDS, MRDS, REQ, RES, TIME, the SAFE and UNSAFE
experimental options, and generic known or unknown kinds. Unknown SAFE options
are preserved with `UdpOptionStatus::UnknownSafe`; unknown UNSAFE options are
preserved with `UdpOptionStatus::UnknownUnsafe` and should be treated as
unsupported behavior by higher-level tools. UDP FRAG is recognized and preserved
as raw option data and reported as `UdpOptionStatus::UnsupportedFragmentation`,
because full UDP fragmentation and reassembly are out of scope for the primitive.

See [the API reference](../reference/api.md) for the complete `UdpOptions`
constructor and accessor table.

## Standards and RFCs implemented

The UDP layer traces every wire fact to reviewed RFC text and IANA registries.
The library implements the following for UDP (out-of-scope items are marked):

- **RFC 768 — User Datagram Protocol** — the base 8-octet header, UDP Length, the
  checksum pseudo-header, the IPv4 zero-checksum "no checksum" convention, and
  protocol number 17.
- **RFC 1122 — Requirements for Internet Hosts** — host requirements for UDP
  checksum generation and validation, with checksum generation on by default.
- **RFC 8200 — IPv6** — the IPv6 pseudo-header checksum inputs; the UDP checksum
  is mandatory for IPv6 by default.
- **RFC 6935 / RFC 6936 — IPv6 UDP Zero Checksum** — the narrow IPv6 zero-checksum
  exception for explicitly enabled tunnel use, inspected distinctly from normal
  IPv4 zero-checksum UDP.
- **RFC 1071 — Computing the Internet Checksum** — the one's-complement checksum
  algorithm used for the UDP checksum and the OCS.
- **RFC 9868 — UDP Options** — the surplus option area after UDP user data, the
  OCS and APC option semantics, and the EOL / NOP / typed-option encoding.
  Updates RFC 768.
- **IANA UDP Option Kind Numbers** — authority for the current UDP Option Kind
  assignments classified by `crafter`.

Out of scope for the UDP layer: a UDP socket, demultiplexer, or application
workflow, and UDP FRAG fragmentation, reassembly, fragment caches, timers, or
delivery of FRAG-contained data as UDP user data.
