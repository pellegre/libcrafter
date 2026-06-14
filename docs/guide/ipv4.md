# IPv4 Wire Coverage

This page describes the IPv4 packet-layer support in the `crafter` crate: what
the `Ipv4` layer builds and decodes, how dependent header fields are filled on
`compile()`, how deliberate overrides are preserved, how options and fragment
metadata are exposed, and what is intentionally out of scope.

`crafter` treats IPv4 as one packet layer. It composes with `/`, compiles into a
single IPv4 datagram, decodes from the `decode_from_l3` entrypoints, and stays
inspectable through `summary()`, `show()`, and typed getters. The base `Ipv4`
layer is **not** an IP stack, router, path MTU engine, scanner, or fuzzer. IPv4
fragment generation and reassembly live in the packet-stream `IpFragment` and
`IpDefrag` transforms under `crafter::wire`. See
[Explicit exclusions](#explicit-exclusions).

All wire facts on this page trace to reviewed RFC text and IANA registries. The
authoritative source record is
[`docs/ipv4-rfc-manifest.md`](../internal/manifests/ipv4-rfc-manifest.md); this guide summarizes the
user-facing API built on top of that manifest.

## Coverage at a glance

| Area | State | Notes |
| --- | --- | --- |
| Base header | Supported | Version, IHL, DS field, Total Length, ID, flags, fragment offset, TTL, Protocol, checksum, source, destination. |
| Construction | Supported | `Ipv4::new()`, `with_addresses`, builder setters, `/` composition, and raw payloads. |
| Auto-filled fields | Supported | IHL, Total Length, Protocol for ICMP/TCP/UDP stacks, option padding, and header checksum. |
| Deliberate overrides | Supported | Explicit DS field, Total Length, ID, flags, fragment offset, TTL, Protocol, checksum, addresses, and options are preserved within the header validation model. |
| DSCP / ECN | Supported | `Dscp`, `Ecn`, `ds_field`, `dscp`, `ecn`, and decode-time getters. |
| Protocol numbers | Supported | `Ipv4Protocol` variants, `IPPROTO_*` constants, labels in summaries, and `Raw` fallback for unknown or unsupported payloads. |
| Checksum status | Supported | Header checksum auto-fill on compile; decode records `Ipv4ChecksumStatus`. Invalid checksums remain inspectable. |
| Options | Supported | Raw options, typed `Ipv4Option` helpers, `Ipv4OptionIter`, `parsed_options`, and option-kind metadata. |
| Fragment fields and transforms | Supported | ID, reserved/DF/MF flags, fragment offset, `Ipv4FragmentInfo`, receive-side `IpDefrag`, and transmit-side `IpFragment`. |
| Decode errors | Supported | Malformed IPv4 headers and options return structured `CrafterError` values. |
| Inspection | Supported | `summary()`, `show()`, `hexdump()`, and per-field getters. |
| Pcap / oracle coverage | Supported | Focused public API tests, malformed corpus entries, deterministic fixtures, pcap-mode validation, and the `ipv4-enrichment` oracle profile. |

## IPv4 construction

The `Ipv4` layer is exported through `crafter::prelude::*` and from the crate
root. Build it with `Ipv4::new()` or `Ipv4::with_addresses`, set fields with
builder methods, and compose it with the next layer using `/`:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let packet = Ipv4::new()
    .src(Ipv4Addr::new(192, 0, 2, 10))
    .dst(Ipv4Addr::new(198, 51, 100, 20))
    .ttl(64)
    / Udp::new().sport(53000).dport(53)
    / Raw::from("dns bytes");

let compiled = packet.compile()?;
println!("{}", packet.summary());
println!("{}", compiled.hexdump());
```

`Ipv4::new()` uses deterministic packet-builder defaults: version `4`, DS field
`0`, identification `1`, flags `0`, fragment offset `0`, TTL `64`, protocol
`0`, and loopback source/destination addresses. For user-facing examples and
tests, prefer explicit documentation addresses such as `192.0.2.0/24` and
`198.51.100.0/24`.

Setters cover the full header surface:

- `version`, `ihl`, `total_length` / `len`
- `tos` / `ds_field`, `dscp`, `ecn`
- `identification` / `id`
- `flags`, `reserved_flag`, `dont_fragment`, `more_fragments`
- `fragment_offset` / `frag`
- `ttl`
- `protocol` / `proto`
- `checksum` / `chksum`
- `src`, `src_str`, `dst`, `dst_str`
- `option`, `ipv4_option` / `ip_option`, `options`, `clear_options`

`compile()` fills fields that were left unset:

- IHL from the fixed 20-octet header plus option bytes and padding.
- Total Length from the IPv4 header plus payload.
- Protocol from the next layer when the stack contains ICMPv4, TCP, or UDP.
- Option padding to a 32-bit boundary.
- IPv4 header checksum over the IPv4 header only.

Explicit values are not rewritten just because they are unusual. For example,
an explicit `protocol(253)`, `checksum(0xbeef)`, `ttl(0)`, reserved flag bit, or
maximum fragment offset is emitted as requested when it fits the modeled wire
field. Structural constraints still apply: IHL must be 5..15 words, options must
fit in the 60-octet header limit, flags must fit in three bits, fragment offset
must fit in 13 bits, and Total Length must be at least the header length.

## DSCP and ECN

IPv4's historical TOS octet is exposed as the DS field: six DSCP bits followed
by two ECN bits. The raw compatibility methods remain available, but new code
should prefer DS field terminology.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let packet = Ipv4::with_addresses(
    Ipv4Addr::new(192, 0, 2, 10),
    Ipv4Addr::new(198, 51, 100, 20),
)
.dscp(Dscp::new(46)?) // EF codepoint value
.ecn(Ecn::Ect0)
    / Raw::from("marked payload");

let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, packet.compile()?.as_bytes())?;
let ipv4 = decoded.layer::<Ipv4>().expect("IPv4 layer");

assert_eq!(ipv4.dscp_value(), Dscp::new(46)?);
assert_eq!(ipv4.ecn_value(), Ecn::Ect0);
```

Useful DS field APIs:

- `Dscp::new(value)` accepts six-bit values `0..=63`.
- `Dscp::from_ds_field(byte)` extracts the six high bits.
- `Ecn::new(value)` accepts two-bit values `0..=3`.
- `Ecn::from_ds_field(byte)` extracts the two low bits.
- `Ipv4::ds_field(byte)` sets the full octet.
- `Ipv4::dscp(dscp)` preserves the current ECN bits.
- `Ipv4::ecn(ecn)` preserves the current DSCP bits.
- `ds_field_value`, `tos_value`, `dscp_value`, and `ecn_value` inspect the
  builder or decoded layer.

The ECN variants are `Ecn::NotEct`, `Ecn::Ect1`, `Ecn::Ect0`, and `Ecn::Ce`.
`summary()` prints nonzero DS field state as `ds=dscp=.../ecn=...`; `show()`
always includes `tos`, `dscp`, and `ecn`.

## Protocol numbers and Raw fallback

The IPv4 Protocol field can be set as a raw byte or through the common
`Ipv4Protocol` enum:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let tcp_probe = Ipv4::with_addresses(
    Ipv4Addr::new(192, 0, 2, 10),
    Ipv4Addr::new(198, 51, 100, 20),
)
.ipv4_protocol(Ipv4Protocol::Tcp)
    / Tcp::new().sport(41000).dport(443).syn();

let opaque = Ipv4::with_addresses(
    Ipv4Addr::new(192, 0, 2, 10),
    Ipv4Addr::new(198, 51, 100, 20),
)
.protocol(IPPROTO_EXPERIMENTAL_1)
    / Raw::from("opaque-ipv4");
```

Exported protocol constants include `IPPROTO_ICMP`, `IPPROTO_TCP`,
`IPPROTO_UDP`, `IPPROTO_IPV6`, `IPPROTO_GRE`, `IPPROTO_ESP`, `IPPROTO_AH`,
`IPPROTO_ICMPV6`, `IPPROTO_OSPF`, `IPPROTO_SCTP`,
`IPPROTO_EXPERIMENTAL_1`, and `IPPROTO_EXPERIMENTAL_2`. Matching
`Ipv4Protocol` variants exist for those common values.

`compile()` can infer `1`, `6`, or `17` from ICMPv4, TCP, or UDP when the
Protocol field was not set explicitly. It does not infer body encoders for every
IANA assignment. If the Protocol value is unknown, experimental, reserved, or
known but unsupported by the current registry, decode keeps the `Ipv4` layer
typed and preserves any payload as a trailing `Raw` layer. An unknown protocol
with an empty payload does not synthesize an empty `Raw`.

## Header checksum status

The IPv4 header checksum covers only the IPv4 header. `compile()` writes a
correct checksum when `checksum` / `chksum` was left unset. An explicit checksum
is emitted verbatim, including a deliberately invalid value.

Decode records checksum validation on the `Ipv4` layer:

```rust
use crafter::prelude::*;

let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes)?;
let ipv4 = decoded.layer::<Ipv4>().expect("IPv4 layer");

match ipv4.checksum_status() {
    Ipv4ChecksumStatus::Valid => {}
    Ipv4ChecksumStatus::Invalid => eprintln!("invalid IPv4 header checksum"),
    Ipv4ChecksumStatus::NotChecked => eprintln!("checksum was not checked"),
}
```

`checksum_value()` returns the explicit or decoded 16-bit field value.
`checksum_status()` returns `Ipv4ChecksumStatus::NotChecked`, `Valid`, or
`Invalid`. Invalid checksums do not cause decode to drop the datagram: the
packet remains inspectable and re-compiles with the same checksum value.
`summary()` includes `checksum_status=invalid` only for invalid checksums;
`show()` always includes the checksum field and status.

## Options

IPv4 options can be appended as raw bytes or as typed `Ipv4Option` values:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let ip = Ipv4::with_addresses(
    Ipv4Addr::new(192, 0, 2, 10),
    Ipv4Addr::new(198, 51, 100, 20),
)
.ipv4_option(Ipv4Option::router_alert(0))?;

let ip = ip.ipv4_option(Ipv4Option::timestamp(5, 0, vec![0x0102_0304]))?;

let packet = ip.protocol(IPPROTO_EXPERIMENTAL_1) / Raw::from("optioned");
let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, packet.compile()?.as_bytes())?;
let ipv4 = decoded.layer::<Ipv4>().expect("IPv4 layer");

for option in ipv4.option_iter() {
    println!("{:?}", option?);
}
```

Typed constructors include:

- `Ipv4Option::end_of_list()` and `Ipv4Option::no_operation()`
- `Ipv4Option::generic(kind, data)`
- `Ipv4Option::timestamp(pointer, overflow, timestamps)`
- `Ipv4Option::timestamp_with_addresses(pointer, overflow, entries)`
- `Ipv4Option::timestamp_prespecified(pointer, overflow, entries)`
- `Ipv4Option::router_alert(value)`
- `Ipv4Option::record_route(pointer, routes)`
- `Ipv4Option::loose_source_route(pointer, routes)`
- `Ipv4Option::strict_source_route(pointer, routes)`
- `Ipv4Option::traceroute(id_number, outbound_hop_count, return_hop_count, originator)`

Option inspection APIs:

- `option_bytes()` returns the raw option area, including decode-time padding
  bytes.
- `option_iter()` iterates over decoded `Ipv4Option` values.
- `parsed_options()` collects typed options into a `Vec<Ipv4Option>`.
- `Ipv4OptionKind::new(kind)` splits a kind byte into copied flag, class, and
  option number.
- `Ipv4OptionKind::is_experimental()` classifies the RFC 4727 experiment option
  values.

`compile()` pads the IPv4 header to a 32-bit boundary. Unknown options are
preserved as `Ipv4Option::Generic`. Malformed option envelopes return structured
errors such as `ipv4 option`, `ipv4.option.length`, `ipv4.option.pointer`, or
`ipv4.option.timestamp`; they do not panic or loop.

## Fragment Fields And Transforms

The `Ipv4` layer exposes IPv4's fragmentation-related header fields. The layer
itself only models one datagram header; it does not keep fragment queues or
split outbound streams. Use `IpDefrag` on receive-side `Sniffer` pipelines and
`IpFragment` on transmit-side `Transmitter` pipelines when a packet stream needs
those transforms.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let packet = Ipv4::with_addresses(
    Ipv4Addr::new(192, 0, 2, 10),
    Ipv4Addr::new(198, 51, 100, 20),
)
.identification(0x4242)
.more_fragments(true)
.fragment_offset(7)
.protocol(IPPROTO_EXPERIMENTAL_1)
    / Raw::from("fragment metadata example");

let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, packet.compile()?.as_bytes())?;
let ipv4 = decoded.layer::<Ipv4>().expect("IPv4 layer");
let fragment = ipv4.fragment_info();

assert_eq!(fragment.identification(), 0x4242);
assert!(fragment.has_more_fragments());
assert_eq!(fragment.fragment_offset(), 7);
```

Field helpers:

- `identification` / `id`, read with `identification_value()`
- `flags`, read with `flags_value()`
- `reserved_flag`, read with `is_reserved_flag_set()`
- `dont_fragment`, read with `is_dont_fragment()`
- `more_fragments`, read with `has_more_fragments()`
- `fragment_offset` / `frag`, read with `fragment_offset_value()`
- `fragment_info()` for an `Ipv4FragmentInfo` snapshot
- `is_fragmented()` to test `MF || fragment_offset != 0`

Decode policy is intentionally conservative. A non-initial fragment
(`fragment_offset != 0`) keeps the IPv4 header typed and preserves the payload as
`Raw`, because the transport header is not available without reassembly. An
offset-zero packet with `MF` set may decode a complete transport header when the
payload is self-consistent; otherwise the payload remains `Raw`. The decoder
does not maintain fragment caches by itself.

Receive-side reassembly belongs on a source or sniffer:

```rust
use crafter::prelude::*;

let first = PacketRecord::new(
    Ipv4::new().src("192.0.2.10")?.dst("198.51.100.20")?
        .protocol(IPPROTO_EXPERIMENTAL_1)
        .identification(0x2024)
        .more_fragments(true)
        .fragment_offset(0)
        / Raw::from_bytes(b"abcdefgh"),
);
let final_fragment = PacketRecord::new(
    Ipv4::new().src("192.0.2.10")?.dst("198.51.100.20")?
        .protocol(IPPROTO_EXPERIMENTAL_1)
        .identification(0x2024)
        .fragment_offset(1)
        / Raw::from_bytes(b"ijkl"),
);

let records = Sniffer::new(VecPacketSource::new([final_fragment, first]))
    .with(IpDefrag::new())
    .collect_records()?;

for metadata in records[0].metadata().ip_defrag_metadata() {
    println!("{:?}", metadata);
}
# Ok::<(), crafter::CrafterError>(())
```

`IpDefrag` groups IPv4 fragments by source, destination, protocol, and
identification. It accepts exact duplicate ranges, records overlaps in
`IpDefragMetadata`, and does not silently emit ambiguous bytes for conflicting
overlaps. State is bounded by configured datagram count, byte count, and age.

Transmit-side fragmentation belongs on a writer or transmitter. The default
IPv4 policy honors DF: if a DF-set packet is larger than the configured MTU,
`IpFragment` returns a structured error instead of fragmenting unless the caller
chooses an explicit override policy.

```rust
use crafter::prelude::*;

let writer = MemoryPacketWriter::dry_run();
let mut tx = Transmitter::new(writer).with(IpFragment::new(576));

let reports = tx.send(
    Ipv4::new().src("192.0.2.10")?.dst("198.51.100.20")?
        .identification(0x2025)
        / Udp::new().sport(40000).dport(40001)
        / Raw::from_bytes(&[0u8; 1200]),
)?;

assert!(reports.iter().all(|report| report.is_dry_run()));
# Ok::<(), crafter::CrafterError>(())
```

Examples use documentation address space and offline or dry-run writers. Do not
turn fragment examples into live traffic instructions; provider-backed lab
workflows are the explicit live path.

## Decode behavior

Use `Packet::decode_from_l3(NetworkLayer::Ipv4, bytes)` for raw IPv4 datagrams.
The same IPv4 decoder is reached through link-layer decoders such as Ethernet,
Linux cooked capture, null/loopback, and pcap readers when the link type says
the payload is IPv4.

Decode behavior:

- A valid IPv4 header becomes an `Ipv4` layer with all header fields populated.
- ICMPv4, TCP, and UDP payloads dispatch through the protocol registry when the
  payload is complete enough for the corresponding decoder.
- Unknown or unsupported Protocol values preserve the payload as `Raw`.
- Non-initial fragments preserve the payload as `Raw`.
- Bytes after the IPv4 Total Length boundary are outside the datagram and become
  a separate trailing `Raw` layer.
- A Total Length that is smaller than the header length is an invalid-field
  error.
- A Total Length that is larger than the available buffer is a buffer-too-short
  error.
- Version other than 4, IHL below 5, truncated fixed headers, truncated option
  areas, and malformed option lengths return structured `CrafterError` values.

This keeps malformed or unknown traffic inspectable without turning truncation
or unsupported protocol numbers into panics.

## Inspection

Every IPv4 packet remains inspectable:

- `Packet::summary()` joins each layer's one-line summary. The IPv4 line includes
  `src`, `dst`, `proto`, nonzero DS field state, nonzero flags, nonzero fragment
  offset, invalid checksum status, and option count.
- `Packet::show()` prints the full field tree. IPv4 fields include `version`,
  `ihl`, `tos`, `dscp`, `ecn`, `total_length`, `id`, `flags`,
  `fragment_offset`, `ttl`, `protocol`, `checksum`, `checksum_status`, `src`,
  `dst`, `option_count`, and raw `options`.
- `Packet::hexdump()` and `CompiledPacket::hexdump()` produce canonical byte
  dumps for compiled packets.

Example:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let packet = Ipv4::with_addresses(
    Ipv4Addr::new(192, 0, 2, 10),
    Ipv4Addr::new(198, 51, 100, 20),
)
.dscp(Dscp::new(46)?)
.ecn(Ecn::Ce)
.dont_fragment(true)
.protocol(IPPROTO_EXPERIMENTAL_1)
    / Raw::from("inspect");

println!("{}", packet.summary());
println!("{}", packet.show());
```

Per-field getters mirror the inspection output:

- `version_value`, `ihl_value`, `header_len`
- `tos_value`, `ds_field_value`, `dscp_value`, `ecn_value`
- `total_length_value`
- `identification_value`, `flags_value`, `fragment_offset_value`
- `ttl_value`, `protocol_value`
- `checksum_value`, `checksum_status`
- `source`, `destination`
- `option_bytes`, `option_iter`, `parsed_options`

## Validation coverage

IPv4 behavior is covered by focused offline tests and deterministic fixtures:

- `crafter/tests/ipv4_public_api.rs` pins construction, compile output, decode,
  DSCP/ECN helpers, checksum status, options, fragment fields, unknown-protocol
  `Raw` fallback, Total Length boundaries, `summary()`, and `show()`.
- `crafter/tests/fixtures/malformed/core-decode-corpus.hex` includes malformed
  IPv4 option cases for structured-error coverage.
- `tools/oracle/specs/profiles.yaml` defines the `ipv4-enrichment` profile for
  focused offline IPv4 header behavior.
- `tools/oracle/specs/features/ip-fragment-transforms.yaml` covers IPv4
  fragment transform contracts and runnable offline packet cases.
- `tools/oracle/specs/stacks.yaml` includes IPv4 payload stacks for boundary
  fields, unknown protocol `Raw`, MF+offset fragments, TTL 255, and option
  coverage.
- `tools/oracle/adapters/src/bin/vectors/cases.rs` contains deterministic IPv4
  vectors, including option and source-route/traceroute cases.
- Pcap-mode validation and fixture tests exercise IPv4 datagrams through classic
  pcap paths and link wrappers such as Ethernet, VLAN, Linux cooked capture, and
  null/loopback.

All documented examples use documentation address space and offline construction
or decode. Live raw traffic remains opt-in through the crate's live send,
capture, provider, and lab-session APIs.

## Explicit exclusions

`crafter` stays a packet primitive. The IPv4 layer does **not** implement:

- IPv4 routing, forwarding, TTL decrement, route selection, or ICMP generation
  caused by forwarding.
- Stack delivery of reassembled data, TCP stream reassembly, or application
  payload reconstruction after `IpDefrag`.
- Global IPv4 Identification allocation or uniqueness tracking.
- Path MTU Discovery, Packetization Layer PMTUD, MTU probing, or MTU caches.
- A full IP stack, scanner, fuzzer, analyzer workflow, or live traffic policy.

The fields needed to build or inspect those packets are present; the workflows
that decide when to send them belong outside the crate primitive.

## Evidence

Protocol facts above come from
[`docs/ipv4-rfc-manifest.md`](../internal/manifests/ipv4-rfc-manifest.md). The source set, in brief:

- **RFC 791** - IPv4 base header, options, checksum, and fragmentation model.
- **RFC 1122** - host requirements for IPv4 validation, TTL, options, and
  robustness.
- **RFC 2474** - DS field and DSCP layout.
- **RFC 3168** - ECN codepoints.
- **RFC 6864** - updated IPv4 Identification field semantics.
- **IANA Assigned Internet Protocol Numbers** - Protocol field assignments.
- **IANA IPv4 Parameters** - option numbers, Router Alert values, and default
  TTL guidance.
- **IANA DSCP/ECN registries** - DSCP and ECN registry authority.
- **RFC 2113**, **RFC 1393**, **RFC 4727**, and **RFC 7126** - option-specific
  support and operational guidance for Router Alert, Traceroute, experiment
  values, and IPv4 options.
