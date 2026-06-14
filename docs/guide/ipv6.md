# IPv6 Wire Coverage

This page describes the IPv6 packet-layer support in the `crafter` crate: what
the `Ipv6` layer and IPv6 extension layers build and decode today, which fields
`compile()` fills, which caller overrides are preserved, and which IPv6 stack
behaviors stay outside the crate.

`crafter` treats IPv6 as packet data. It builds, compiles, decodes, summarizes,
and shows IPv6 layers through the same `Packet` surface as every other protocol:
`/` composition, `compile()`, `decode_from_l3`, `summary()`, `show()`, and
`hexdump()`. It is not an IPv6 stack, router, PMTUD engine, fragment
reassembler, SRv6 endpoint, Mobile IPv6 node, scanner, or fuzzer. IPv6
Fragment Header reassembly and source-side fragmentation are packet-stream
transforms: use `IpDefrag` on `Sniffer` sources and `IpFragment` on
`Transmitter` writers.

Protocol facts here are source-backed. The source record is
[`docs/ipv6-rfc-manifest.md`](../internal/manifests/ipv6-rfc-manifest.md), and the implementation
map is [`docs/ipv6-implementation-inventory.md`](../internal/inventories/ipv6-implementation-inventory.md).
The current branch also has focused oracle specs for the enriched IPv6 surface
under `tools/oracle/specs/layers/ipv6.yaml` and
`tools/oracle/specs/features/ipv6-fragment-routing.yaml`.

## Coverage At A Glance

| Area | State | Notes |
| --- | --- | --- |
| Base IPv6 header | Supported | Version, Traffic Class, Flow Label, Payload Length, Next Header, Hop Limit, source, destination. |
| DSCP / ECN | Supported | Typed helpers over the Traffic Class byte; the raw byte remains inspectable. |
| Flow Label | Supported | 20-bit field with checked helper; no automatic flow-label generation policy. |
| Payload Length | Auto-filled | Filled from following layers when unset; explicit values are preserved. |
| Jumbo Payload option | Supported as option bytes | `Ipv6Option::jumbo_payload`; full jumbogram transport behavior is out of scope. |
| Next Header chaining | Supported | Base and extension headers infer the next typed layer unless explicitly set. |
| Unknown Next Header | Supported as `Raw` | Unknown or unsupported payload bytes are preserved when the enclosing header is valid. |
| Hop-by-Hop Options | Supported | Ordered `Ipv6Option` TLVs, explicit-only options, 8-octet header padding. |
| Destination Options | Supported | Ordered `Ipv6Option` TLVs, including Home Address as packet-layer data. |
| Routing headers | Supported | Generic Routing Header, Mobile Type 2, and Segment Routing Header (SRH). |
| Fragment Header | Supported | Field inspection, initial/atomic/non-initial classification, transform-scoped `IpDefrag`, and source-side `IpFragment`. |
| Malformed decode | Supported | Structured errors for truncation and invalid fields; no silent panic. |
| Live traffic | Opt-in only | Examples, fixtures, and oracle coverage are offline or dry-run by default. |

## Base Header

The public base layer is `Ipv6`, exported through `crafter::prelude::*`,
`crafter::Ipv6`, and `crafter::protocols::ipv6::Ipv6`.

Builders and accessors cover the 40-octet IPv6 base header:

- `version` for the fixed IPv6 version field. `compile()` rejects values other
  than 6.
- `traffic_class` / `tc` for the raw Traffic Class byte.
- `dscp(Dscp)` and `ecn(Ecn)` for the DSCP and ECN subfields.
- `flow_label` / `fl` and `try_flow_label` for the 20-bit Flow Label field.
- `payload_length` / `plen` for explicit Payload Length overrides.
- `next_header` / `nh` for explicit Next Header overrides.
- `hop_limit` / `hlim` for Hop Limit.
- `src`, `dst`, `src_str`, `dst_str`, and `with_addresses` for addresses.

Defaults are deterministic: version 6, Traffic Class 0, Flow Label 0, Hop Limit
64, and loopback source/destination unless set. Examples and fixtures should use
documentation address space such as `2001:db8::/32`.

```rust
use crafter::prelude::*;

let ipv6 = Ipv6::new()
    .src_str("2001:db8:10::1")?
    .dst_str("2001:db8:10::2")?
    .dscp(Dscp::ef())
    .ecn(Ecn::ce())
    .try_flow_label(0x12345)?
    .hlim(37);

let packet = ipv6
    / Udp::new().sport(54049).dport(1049)
    / Raw::from("base-v6!");

let compiled = packet.compile()?;
let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, compiled.as_bytes())?;
println!("{}", decoded.summary());
```

## DSCP And ECN

IPv6 carries DSCP and ECN inside the single Traffic Class octet. `crafter`
therefore keeps the raw `traffic_class_value()` authoritative and exposes
derived helpers:

- `dscp(Dscp)` sets the upper six bits and preserves the current ECN bits.
- `ecn(Ecn)` sets the lower two bits and preserves the current DSCP bits.
- `dscp_value()` and `ecn_value()` decode the current raw byte.
- `Dscp::new(0..=63)`, `Dscp::ef()`, `Dscp::cs0()` through `Dscp::cs7()`, and
  `Dscp::class_selector(...)` validate DSCP values.
- `Ecn::not_ect()`, `Ecn::ect0()` / `Ecn::capable_0()`, `Ecn::ect1()` /
  `Ecn::capable_1()`, and `Ecn::ce()` validate ECN values.

The helpers do not create policy. They only encode and decode the wire bits so a
tool can decide how to use them.

## Flow Label

The Flow Label field is a 20-bit wire field. `flow_label` / `fl` preserves the
caller-supplied value until compile validation, while `try_flow_label` rejects a
value above `0x000f_ffff` immediately.

`crafter` does not generate Flow Label values automatically. If a tool needs a
nonzero Flow Label, set it explicitly and keep any generation policy in the
tool, not in the crate primitive.

## Payload Length And Jumbo Payload

When `payload_length` is unset, `compile()` fills the 16-bit IPv6 Payload Length
from the encoded bytes after the base header. If the computed payload is larger
than 65,535 octets, compile returns a structured `ipv6.payload_length` error.

When `payload_length` / `plen` is set explicitly, the value is emitted unchanged,
including deliberately short or zero values. On decode, the declared Payload
Length bounds the IPv6 payload. Extra bytes after that declared length are
preserved as a trailing `Raw` layer rather than discarded.

`Ipv6Option::jumbo_payload(length)` encodes and decodes the RFC 2675 Jumbo
Payload option for Hop-by-Hop Options headers:

```rust
use crafter::prelude::*;

let packet = Ipv6::new()
    .src_str("2001:db8:20::1")?
    .dst_str("2001:db8:20::2")?
    .plen(0)
    / Ipv6HopByHopOptionsHeader::new()
        .nh(IPPROTO_IPV6_NO_NEXT)
        .option(Ipv6Option::jumbo_payload(65_536));

let compiled = packet.compile()?;
```

The jumbogram caveat is intentional: the option bytes and explicit Payload
Length zero are preserved, but `crafter` does not allocate huge payloads, infer
or enforce the full jumbogram invariant, alter transport checksums for
jumbograms, or generate live jumbogram traffic.

## Next Header Behavior

`compile()` infers Next Header values from the next typed layer when the field
is unset:

- `Ipv6HopByHopOptionsHeader` -> 0
- `Ipv6DestinationOptionsHeader` -> 60
- `Ipv6RoutingHeader`, `Ipv6MobileRoutingHeader`, `Ipv6SegmentRoutingHeader`
  -> 43
- `Ipv6FragmentHeader` -> 44
- `Tcp`, `Udp`, and `Icmpv6` -> 6, 17, and 58

Explicit `next_header` / `nh` values are preserved on both the base header and
extension headers. This includes values that disagree with the following typed
layer, because malformed packet generation is a supported packet-layer use case.

Named IPv6 Next Header constants include:

- `IPPROTO_IPV6_HOPOPTS`, `IPPROTO_IPV6_ROUTE`,
  `IPPROTO_IPV6_FRAGMENT`, `IPPROTO_IPV6_DSTOPTS`.
- `IPPROTO_IPV6_ESP`, `IPPROTO_IPV6_AH`,
  `IPPROTO_IPV6_MOBILITY`, `IPPROTO_IPV6_HIP`,
  `IPPROTO_IPV6_SHIM6`.
- `IPPROTO_IPV6_NO_NEXT`, `IPPROTO_IPV6_EXPERIMENTAL_1`,
  `IPPROTO_IPV6_EXPERIMENTAL_2`.

Decode traverses supported IPv6 extension headers, then dispatches TCP, UDP, and
ICMPv6 through the registry. Unknown, unsupported, or custom Next Header payloads
are preserved as `Raw` when non-empty. `No Next Header` with no payload produces
no child layer; non-empty bytes are treated like other unsupported payload bytes.

`crafter` does not silently reorder extension headers. If a packet needs the
RFC-recommended extension order, compose layers in that order.

## Options

Hop-by-Hop and Destination Options share the `Ipv6Option` model:

- `Ipv6Option::pad1()`
- `Ipv6Option::padn(total_len)` and `padn_data(data)`
- `Ipv6Option::router_alert(value)`
- `Ipv6Option::jumbo_payload(length)`
- `Ipv6Option::home_address(addr)` and `home_address_str(...)`
- `Ipv6Option::generic(option_type, data)` / `unknown(...)`

Every option exposes the full option type byte, action bits, change-en-route
bit, low five-bit option number, encoded length, and data bytes. Unknown options
preserve the full type and data. If a known option type has the wrong fixed
length but is structurally contained in the options area, it decodes as
`Generic` so the bytes remain inspectable.

`Ipv6HopByHopOptionsHeader` and `Ipv6DestinationOptionsHeader` both support:

- `next_header` / `nh`
- `header_ext_len` for explicit length overrides
- `options([...])`, `option(...)`, and `push_option(...)`
- `options_value()` / `options_list()` for decoded inspection

Unset extension-header length is derived from option bytes and rounded to an
8-octet boundary. Extra padding is emitted as zero bytes and decodes as Pad1.
If an explicit `header_ext_len` is too small for the options, compile returns a
structured error instead of dropping data.

Router Alert is explicit-only. The builder never inserts Router Alert on its
own, and the crate does not implement router-intercept behavior. Current IANA
state deprecates Router Alert for new protocols, so generated examples should
only emit it when a caller requested that exact wire shape.

Home Address is packet-layer data only. `crafter` does not implement Mobile IPv6
binding caches, return routability, home-agent behavior, or route optimization.

## Routing Headers

The generic Routing Header is `Ipv6RoutingHeader`. It preserves:

- `next_header`
- `header_ext_len`
- `routing_type`
- `segments_left`
- raw type-specific bytes through `type_data` / `append_type_data`

Routing type helpers classify known IANA values as assigned, deprecated,
experimental, reserved, or unknown. Type 0 / RH0 is deprecated by RFC 5095.
`crafter` can decode and preserve RH0 bytes for inspection, but generated
examples should set a specific routing type and should not use RH0 as a default
behavior.

`Ipv6MobileRoutingHeader` models Mobile IPv6 Routing Header Type 2 packet
fields: `segments_left`, `reserved`, and `home_address`. It does not implement
the Mobility Header protocol, binding state, or Mobile IPv6 control workflows.

## Segment Routing Header

`Ipv6SegmentRoutingHeader` models the RFC 8754 Segment Routing Header (SRH)
packet fields:

- `segments_left`
- `last_entry` (with `first_segment` compatibility alias)
- raw `flags`
- `tag`
- segment list addresses
- `raw_trailing_data` / `extra_data` after the Segment List

The builder requires at least one segment and validates that `segments_left` and
`last_entry` refer to an existing segment. Decoding preserves raw trailing data
after the Segment List and checks that it has valid TLV shape.

This is SRH packet-layer support only. `crafter` does not execute SIDs,
install SR policies, act as an SRv6 endpoint, interpret current SRH TLV
semantics beyond shape preservation, or verify HMAC data.

```rust
use crafter::prelude::*;

let srh = Ipv6SegmentRoutingHeader::new()
    .push_ipv6_segment("2001:db8:30::40")?
    .push_ipv6_segment("2001:db8:30::50")?
    .segleft(1)
    .tag(0x1001);

let packet = Ipv6::new()
    .src_str("2001:db8:30::10")?
    .dst_str("2001:db8:30::20")?
    / srh
    / Udp::new().sport(5555).dport(6666)
    / Raw::from("srh");

let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, packet.compile()?.as_bytes())?;
```

## Fragment Header

`Ipv6FragmentHeader` exposes the Fragment Header fields used by packet-layer
inspection and by the packet-stream fragment transforms:

- `next_header` / `nh`
- `reserved`
- `fragment_offset` / `offset` / `frag`, in 8-octet units
- `res`, the two reserved bits in the fragment field
- `more_fragments` / `mflag`
- `identification` / `id`

Inspection helpers expose byte offsets, reserved-field status, and
`Ipv6FragmentHeaderStatus`:

- `Atomic`: Fragment Offset is zero and M flag is clear.
- `Initial`: Fragment Offset is zero and M flag is set.
- `NonInitial`: Fragment Offset is nonzero.

Initial and atomic fragments continue normal upper-layer decode when the header
chain is present. Non-initial fragments stop upper-layer decode and preserve the
remaining bytes as `Raw` in the base decoder.

The packet-stream `IpDefrag` transform follows RFC 6946 for atomic fragments:
an IPv6 Fragment Header with Fragment Offset zero and M flag clear is processed
in isolation from queued fragments with the same source, destination, and
identification. The default `Ipv6AtomicFragmentPolicy::Normalize` removes the
Fragment Header for supported chains and emits a normal packet-shaped record
with `IpDefragMetadata` and an `atomic fragment normalized` transform trace.
Configured pass-through keeps the Fragment Header and records an
`atomic fragment pass-through` trace; configured drop emits no record.

```rust
use crafter::prelude::*;

let packet = Ipv6::new()
    .src_str("2001:db8:40::1")?
    .dst_str("2001:db8:40::2")?
    / Ipv6FragmentHeader::new()
        .identification(0x0102_0304)
        .more_fragments(true)
    / Udp::new().sport(5353).dport(5353)
    / Raw::from("fragment");

let bytes = packet.compile()?;
let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes())?;
let fragment = decoded.layer::<Ipv6FragmentHeader>().unwrap();
assert_eq!(fragment.fragment_status(), Ipv6FragmentHeaderStatus::Initial);
```

Use `IpDefrag` on receive-side packet sources when a stream contains related
fragments. Reassembly identity is the IPv6 source address, destination address,
and Fragment Identification only; the Fragment Header Next Header value is
preserved as context and metadata, not as key material.

```rust
use crafter::prelude::*;

let first = PacketRecord::new(
    Ipv6::new().src_str("2001:db8:40::1")?.dst_str("2001:db8:40::2")?
        / Ipv6FragmentHeader::new()
            .next_header(IPPROTO_IPV6_EXPERIMENTAL_1)
            .identification(0x0102_0304)
            .more_fragments(true)
        / Raw::from_bytes(b"abcdefgh"),
);
let final_fragment = PacketRecord::new(
    Ipv6::new().src_str("2001:db8:40::1")?.dst_str("2001:db8:40::2")?
        / Ipv6FragmentHeader::new()
            .next_header(IPPROTO_IPV6_EXPERIMENTAL_1)
            .identification(0x0102_0304)
            .fragment_offset(1)
        / Raw::from_bytes(b"ijkl"),
);

let records = Sniffer::new(VecPacketSource::new([final_fragment, first]))
    .with(IpDefrag::new())
    .collect_records()?;

println!("{:?}", records[0].metadata().ip_defrag_metadata());
# Ok::<(), crafter::CrafterError>(())
```

Use `IpFragment` on transmit-side packet writers. It inserts IPv6 Fragment
Headers for supported source-side header chains and emits packet-shaped records
with `IpFragmentMetadata`.

```rust
use crafter::prelude::*;

let writer = MemoryPacketWriter::dry_run();
let mut tx = Transmitter::new(writer).with(
    IpFragment::with_config(
        IpFragmentConfig::new(1280).ipv6_identification(0x0102_0304),
    ),
);

let reports = tx.send(
    Ipv6::new().src_str("2001:db8:50::1")?.dst_str("2001:db8:50::2")?
        / Udp::new().sport(40000).dport(40001)
        / Raw::from_bytes(&[0u8; 1600]),
)?;

assert!(reports.iter().all(|report| report.is_dry_run()));
# Ok::<(), crafter::CrafterError>(())
```

The examples use `2001:db8::/32` and dry-run memory output. They are intended
for offline examples, tests, and generated tooling, not live traffic.

## Fragment Header Extension Scope

The packet-stream `IpDefrag` and `IpFragment` transforms use a deliberately
narrow IPv6 extension scope for Fragment Header handling. Source authority is
RFC 8200 for the Fragment Header and extension-chain repair rules, RFC 6946 for
atomic fragments, RFC 7112 for first-fragment header-chain requirements, and
[`docs/protocols/ip-fragment-source-manifest.md`](../internal/source/ip-fragment-source-manifest.md)
for the transform-specific manifest.

Supported scope:

- Plain IPv6 with a Fragment Header directly after the fixed header.
- Hop-by-Hop Options, Destination Options, and Routing headers before the
  Fragment Header. These are preserved as the unfragmentable part so the
  Fragment Header can be removed and the previous Next Header byte can be
  repaired from the offset-zero fragment.

Unsupported extension scope:

- AH, ESP, Mobility Header, HIP, Shim6, experimental extension-header values,
  and other known extension-header values that the transform cannot safely
  repair around a Fragment Header.
- Unknown Next Header values are preserved as ordinary unsupported payloads
  unless a caller installs custom registry support.

Unsupported extension chains are not partially rewritten. The transforms pass
them through unchanged and attach a transform trace with the note
`unsupported IPv6 extension chain outside Fragment Header extension scope`.
Malformed supported chains still return structured errors with the usual
context, required, and available lengths.

## Malformed Decode Policy

Decode returns structured `CrafterError` values. It does not panic on malformed
wire input.

The current policy is:

- Base IPv6 decode rejects buffers shorter than 40 octets.
- Base IPv6 decode rejects version values other than 6.
- Declared Payload Length must fit inside the available bytes. Short buffers
  return `buffer_too_short` with context, required, and available lengths.
- Bytes after the declared Payload Length are preserved as trailing `Raw`.
- Extension headers must be at least 8 octets and must fit their declared
  `Hdr Ext Len`.
- Option TLVs must fit inside the option area. Truncated option headers or data
  return structured errors.
- Known options with nonstandard fixed lengths decode as `Generic` when the
  declared bytes are present.
- Fragment Header decode requires 8 octets.
- SRH decode rejects Segment Lists shorter than `Last Entry` requires and raw
  trailing data whose TLV shape is truncated.
- Unsupported AH, ESP, Mobility Header, HIP, Shim6, experimental, and unknown
  Next Header payloads are preserved as `Raw` unless a caller installs custom
  registry bindings.

This behavior is what lets generated tools inspect malformed packets without
losing bytes or guessing which layer failed.

## Fixtures

Committed fixtures are offline and use documentation address space. Current IPv6
fixture coverage includes:

- Base traffic fields: `ipv6-base-traffic-flow-udp-raw.hex` and
  `raw-ipv6-base-traffic-flow-udp-raw.pcap`.
- Hop-by-Hop and Destination Options:
  `ipv6-options-hop-destination-udp.hex` plus summary/show fixtures.
- Generic routing, Mobile Type 2, and SRH:
  `ipv6-routing-generic-unknown-raw.hex`,
  `ipv6-mobile-routing-raw.hex`, and `ipv6-segment-routing-raw.hex`.
- Fragment Header status:
  `ipv6-fragment-udp-raw.hex`,
  `ipv6-fragment-atomic-udp-raw.hex`, and
  `ipv6-fragment-non-initial-udp-raw.hex`.
- Transport over IPv6:
  `ipv6-udp-raw.hex`, `ipv6-tcp-raw.hex`,
  `ipv6-tcp-rich-options.hex`, `ipv6-icmp-echo-request.bin`, and
  `ipv6-icmpv6-time-exceeded.hex`.
- Malformed decode corpus entries in
  `crafter/tests/fixtures/malformed/core-decode-corpus.hex`.

Fixture ownership and promotion rules live in
`crafter/tests/fixtures/README.md`. Do not add live captures or host-specific
addresses to tracked fixtures.

## Oracle Profile

The focused offline oracle profile is `ipv6-enrichment`:

```sh
tools/oracle/run offline --profile ipv6-enrichment --seed 1 --count 20
```

It samples the IPv6 base field cases, unknown Next Header `Raw` preservation,
Hop-by-Hop Options, Destination Options, option metadata, Fragment Header,
generic routing, Mobile Type 2, Segment Routing, TCP and ICMPv6 extension
chains, and structured malformed extension coverage. Its profile weights keep
pcap and live traffic disabled; use provider-backed lab or wire workflows only
when a human explicitly authorizes live packet exchange.

## Out Of Scope

The following behavior is intentionally outside `crafter`'s IPv6 packet
primitive:

- TCP stream reassembly and application payload reconstruction after
  `IpDefrag` emits an IPv6 datagram.
- Full IPv6 stack delivery, PMTUD probing, or live Packet Too Big workflows.
- Automatic Flow Label generation policy.
- Automatic extension-header ordering or Router Alert insertion.
- Full jumbogram transport semantics, huge payload allocation, or live
  jumbogram traffic.
- AH/ESP cryptography, key management, authentication, encryption, or
  verification.
- Mobility Header protocol 135 parsing beyond raw preservation, and all Mobile
  IPv6 state machines.
- SRv6 endpoint behavior, SID execution, policy installation, HMAC
  verification, or live SR domain operation.
- Treating generated examples, fixtures, oracle, or probe defaults as live
  network actions.
