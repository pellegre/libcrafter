# Rust API Guide

This document summarizes the public Rust surface for generated packet tools.
Version 0.3.0 focuses on explicit builders, deterministic compile/decode
behavior, bounded pcap workflows, and packet-level wire workflows. The only
public crate is `crafter`.

Most examples should start with:

```rust
use crafter::prelude::*;
```

## One Public Crate

Install and depend on `crafter` only. The public Rust surface is organized as
modules inside the one crate:

| Module | Responsibility |
| --- | --- |
| `crafter::prelude` | Common imports for examples and agent-written tools. |
| `crafter::core` | Packet model, layer model, encode/decode, checksums, formatting, and protocol registry. |
| `crafter::wire` | Wire packet I/O through `PacketWire`, `PacketRecord`, packet sources, packet writers, sniffers, transmitters, and transform chains. |
| `crafter::net` | Interfaces, raw sockets, send, send-receive, routing helpers, and address helpers. |

## Packet Composition

Generated tools should prefer explicit builders:

```rust
let packet = Packet::new()
    .push(
        Ipv4::new()
            .src("192.0.2.10")?
            .dst("198.51.100.20")?
            .ipv4_protocol(Ipv4Protocol::Icmpv4),
    )
    .push(Icmpv4::echo_request().id(0x1234).seq(1))
    .push(Raw::from_bytes(b"HelloPing!\n"));

let bytes = packet.compile()?;
```

Concise examples may use `/` composition:

```rust
let packet =
    Ipv4::new().dst("198.51.100.20")?
        .ipv4_protocol(Ipv4Protocol::Icmpv4)
    / Icmpv4::echo_request().seq(1)
    / Raw::from_bytes(b"HelloPing!\n");
```

Use `Ipv4Protocol` for known IPv4 protocol-field values and
`Ipv4::protocol(u8)` only when a tool deliberately needs an arbitrary raw
protocol byte.

## Builder Conventions

| Pattern | Meaning |
| --- | --- |
| `Layer::new()` | Construct a layer with unset auto-fill fields. |
| `Layer::request()` / `Layer::reply()` | Protocol-specific semantic constructors when useful. |
| `.field(value)` | Set a field explicitly and preserve it during compile. |
| `.try_field(value)?` | Parse or validate a fallible field value. |
| `.option(...)` | Append protocol options while preserving order. |
| `.payload(...)` | Attach raw bytes when no higher layer is needed. |
| `.clear_field()` | Return a field to unset so auto-fill may apply. |

The model distinguishes unset, defaulted, and explicitly set fields. `compile`
may fill unset lengths, protocol numbers, header lengths, and checksums, but it
must not overwrite explicit user input.

## Compile And Decode

```rust
let bytes = packet.compile()?;

let decoded = Packet::decode_from_link(LinkType::Ethernet, &bytes)?;
let l3 = Packet::decode_from_l3(NetworkLayer::Ipv4, &bytes)?;
let ipv4 = Packet::decode_ipv4(&bytes)?;
```

Decode rules:

- Malformed enclosing headers return structured errors.
- Unsupported next protocols are preserved as `Raw`.
- Link-layer entry points accept explicit link types rather than guessing.
- Deterministic inputs compile to deterministic bytes.

## Typed Layer Access

```rust
let packet = Packet::decode_from_link(LinkType::Ethernet, frame)?;

let ip = packet.layer::<Ipv4>().ok_or("missing Ipv4")?;
let tcp = packet.layer::<Tcp>();

for layer in packet.iter() {
    println!("{}", layer.summary());
}
```

| Rust API | Purpose |
| --- | --- |
| `packet.layer::<T>() -> Option<&T>` | First layer of type `T`. |
| `packet.layer_mut::<T>() -> Option<&mut T>` | Mutable typed access before compile. |
| `packet.layers::<T>() -> impl Iterator<Item = &T>` | All layers of type `T`. |
| `packet.get(index) -> Option<&dyn Layer>` | Positional stack access. |
| `packet.iter()` | Ordered layer iteration. |

## Inspection Helpers

| Workflow | Rust API |
| --- | --- |
| Detailed tree | `packet.show()` |
| One-line packet description | `packet.summary()` |
| Hex output | `packet.hexdump()` and `hexdump(&bytes)` |
| Raw payload as text | `packet.raw_string_lossy()` |
| Reply matching filter | `packet.reply_filter()` |

`summary` should be compact and stable enough for snapshot tests. `show` can be
more verbose and field-oriented.

## Pcap Through Packet Wire

```rust
let source = PacketWire::pcap_file("input.pcap")
    .filter("tcp or udp")
    .open()?
    .source()?;

let records = Sniffer::new(source).collect_records()?;

for record in records {
    println!("{}", record.packet().summary());
    println!("{:?}", record.metadata());
}
```

Deterministic pcap output uses a recorder backend and `Transmitter`:

```rust
let writer = PacketWire::pcap_recorder("out.pcap", LinkType::Ethernet)
    .open()?
    .writer()?;

let mut tx = Transmitter::new(writer);
let reports = tx.send(packet)?;
```

Low-level pcap codec details are owned by the packet wire backend. User code
should enter through `PacketWire`, `Sniffer`, and `Transmitter` so reads yield
packet records with pcap metadata and writes consume packets or packet records.

## Wire Packet I/O

The crate-level packet I/O surface lives under `crafter::wire`. See
[docs/wire.md](wire.md) for the full guide to `PacketWire`, `PacketRecord`
metadata, `PacketTransform`, `Sniffer`, and `Transmitter`.
See [docs/wire-api-inventory.md](wire-api-inventory.md) for the inspectable
API inventory and backend responsibility map.

The public stream shape is:

| API | Role |
| --- | --- |
| `PacketWire` | Opens one packet-capable backend or interface and exposes explicit source or writer capabilities. |
| `PacketSource` | Synchronous packet-record input trait used by `Sniffer`. |
| `PacketWriter` | Packet-record output trait used by `Transmitter`. |
| `PacketRecord` | Stream item containing a `Packet` plus inspectable backend, link, pcap, transform, and medium metadata. |
| `PacketTransform` | Stateful zero/one/many stream transform contract for inbound or outbound packet records. |
| `Sniffer` | Owns one `PacketSource`, applies inbound transforms, and yields transformed `PacketRecord` values. |
| `Transmitter` | Owns one `PacketWriter`, applies outbound transforms, and returns ordered write reports. |

`PacketWire::source()`, `PacketWire::writer()`, and `PacketWire::split()`
consume the opened wire and return typed `WireError::UnsupportedCapability`
errors when the backend cannot satisfy the requested direction. The pcap codec
and libpcap integration live behind the wire backend boundary; `wire` is the
user-facing packet stream abstraction.

WPA decryption is available as the stateful `WpaDecrypt` inbound
`PacketTransform`. It observes beacons and EAPOL handshakes, keeps per-network
key state for configured SSID/passphrase or SSID/PMK entries, and emits
decrypted packet records without changing `Sniffer`. The implemented decrypt
path is passive WPA2-PSK CCMP-128; unsupported ciphers and missing key material
remain inspectable metadata on packet-shaped records.

Offline pcap input:

```rust
let source = PacketWire::pcap_file("input.pcap")
    .filter("icmp")
    .open()?
    .source()?;

let mut sniffer = Sniffer::new(source).count(10);

while let Some(record) = sniffer.next_record()? {
    println!("{}", record.packet().summary());
    println!("{:?}", record.metadata());
}
```

Live pcap capture is explicit and bounded:

```rust
let source = PacketWire::pcap_interface("eth0")
    .filter("tcp port 80")
    .timeout(Duration::from_secs(1))
    .open()?
    .source()?;

let records = Sniffer::new(source)
    .timeout(Duration::from_secs(3))
    .count(100)
    .collect_records()?;
```

Offline pcap output and raw socket dry-run writing use `Transmitter`:

```rust
let writer = PacketWire::pcap_recorder("out.pcap", LinkType::Ethernet)
    .open()?
    .writer()?;

let mut tx = Transmitter::new(writer);
let reports = tx.send(packet)?;
```

`PacketWire::raw_socket_interface("eth0")` defaults to dry-run planning and
requires `.live()` for real raw socket transmission. Live capture or transmit
belongs in authorized endpoint provider or lab workflows, not local static
tests.

## IP Fragment Transforms

`IpDefrag` and `IpFragment` are packet-stream transforms under
`crafter::wire`. They do not change the `Packet` builder surface: generated
tools still compose IPv4 and IPv6 packets normally, then place the transform on
the stream that needs it.

Use `IpDefrag` on receive-side sources and sniffers. It buffers IPv4 fragments
and supported IPv6 Fragment Header records until a datagram is complete, then
emits one packet-shaped `PacketRecord` with `IpDefragMetadata` and transform
trace entries. Non-fragmented records pass through by default.

```rust
let first = PacketRecord::new(
    Ipv4::new().src("192.0.2.10")?.dst("198.51.100.20")?
        .protocol(IPPROTO_EXPERIMENTAL_1)
        .identification(0x4444)
        .more_fragments(true)
        .fragment_offset(0)
        / Raw::from_bytes(b"abcdefgh"),
);
let final_fragment = PacketRecord::new(
    Ipv4::new().src("192.0.2.10")?.dst("198.51.100.20")?
        .protocol(IPPROTO_EXPERIMENTAL_1)
        .identification(0x4444)
        .fragment_offset(1)
        / Raw::from_bytes(b"ijkl"),
);

let source = VecPacketSource::new([final_fragment, first]);
let records = Sniffer::new(source)
    .with(IpDefrag::new())
    .collect_records()?;
```

Use `IpFragment` on transmit-side writers and transmitters. It has an explicit
MTU, emits one or more packet-shaped fragment records, and records
`IpFragmentMetadata` on each emitted record. Offline pcap recorders and
`MemoryPacketWriter::dry_run()` are the default examples; use documentation
addresses such as `192.0.2.0/24`, `198.51.100.0/24`, and `2001:db8::/32`.

```rust
let writer = MemoryPacketWriter::dry_run();
let mut tx = Transmitter::new(writer).with(IpFragment::new(1280));

let reports = tx.send(
    Ipv6::new().src_str("2001:db8:10::1")?.dst_str("2001:db8:10::2")?
        / Udp::new().sport(40000).dport(40001)
        / Raw::from_bytes(&[0u8; 1600]),
)?;

assert!(reports.iter().all(|report| report.is_dry_run()));
```

These transforms reconstruct IP datagrams only. TCP stream reassembly,
fragmented application payload reconstruction, HTTP/file recovery, and full
stack delivery are out of scope for the crate primitive.

## Send And Send-Receive

```rust
let report = packet.send_recv_report(
    SendRecv::new()
        .iface("eth0")
        .network_layer()
        .timeout(Duration::from_secs(1))
        .retries(3)
        .filter(packet.reply_filter()?),
)?;

if let Some(reply) = report.reply() {
    println!("{}", reply.summary());
}
```

Batch send-receive returns positional reports:

```rust
let report = send_recv_packets(
    &packets,
    BatchSendRecv::new()
        .iface("eth0")
        .network_layer()
        .timeout(Duration::from_millis(750))
        .retries(1),
)?;
```

Raw socket operations are exposed through typed wrappers rather than integer
file descriptors in normal examples.

## UDP Options

UDP options (RFC 9868) are modeled as a typed surplus layer. A packet stack
places `UdpOptions` after the UDP user payload:

```rust
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
then materializes the UDP surplus area after that length. It also fills the UDP
Option Checksum (OCS) and any auto `additional_payload_checksum()` APC option.
Explicit UDP length, UDP checksum, OCS, and APC values are preserved, including
intentionally wrong values.

| Rust API | Purpose |
| --- | --- |
| `UdpOptions::new()` | Start an empty surplus option layer. |
| `UdpOptions::from_options(...)` | Encode typed `UdpOption` values. |
| `UdpOptions::from_bytes(...)` | Preserve already encoded option bytes. |
| `UdpOptions::udp_option(...)` | Append one typed option. |
| `UdpOptions::additional_payload_checksum()` | Append an APC whose CRC32c is filled from UDP user data at compile time. |
| `UdpOptions::option_checksum(value)` | Set OCS explicitly for malformed or fixed-vector cases. |
| `UdpOptions::status()` | Return decoded or parsed `UdpOptionStatus`. |
| `UdpOptions::options()` | Borrow cached parsed `UdpOption` values. |
| `UdpOptions::option_iter()` | Iterate over the encoded option bytes. |

Typed options cover EOL, NOP, APC, MDS, MRDS, REQ, RES, TIME, SAFE/UNSAFE
experimental options, and generic known or unknown option kinds. Unknown SAFE
options are preserved with `UdpOptionStatus::UnknownSafe`; unknown UNSAFE
options are preserved with `UdpOptionStatus::UnknownUnsafe` and should be
treated as unsupported behavior by higher-level tools. UDP FRAG is preserved as
raw option data and reported as `UdpOptionStatus::UnsupportedFragmentation`
because full UDP fragmentation/reassembly is not in scope.

`Udp::checksum_status()` reports checksum validation on decoded packets:
`Valid`, `Invalid`, `Ipv4NoChecksum`, `Ipv6ZeroChecksum`, or `NotChecked`.
`UdpChecksumStatus::Ipv6ZeroChecksum` is not accepted as ordinary IPv6 UDP; call
`requires_ipv6_zero_checksum_exception()` when a tool explicitly supports the
RFC 6935/RFC 6936 tunnel exception model.

## DHCP Packets

`Dhcp` is the DHCPv4 layer. It is a packet primitive: it crafts and inspects
BOOTP/DHCP frames but is not a DHCP client, server, or lease engine. It composes
over UDP, compiles through `Packet::compile()` with protocol-correct defaults,
and decodes through the registry when carried on the DHCP ports.

Named constructors cover the registered message types:

```rust
let discover = Dhcp::discover(client_mac);
let request = Dhcp::request(client_mac, "192.0.2.50".parse()?, "192.0.2.1".parse()?);
let offer = Dhcp::offer(client_mac, "192.0.2.50".parse()?, "192.0.2.1".parse()?);
// Also: decline, ack, nak, release, inform, force_renew,
// lease_query_by_ip, lease_query_by_mac, lease_query_by_client_id.
```

### Option model

Options follow a code-plus-value model rather than one enum variant per code.
A `DhcpOption` exposes its registered code, a typed `DhcpOptionValue` for
formats the codec understands, and the raw payload bytes for everything else.
Unknown, private-use, removed, ambiguous, and vendor-specific option payloads
are preserved as raw bytes rather than dropped or guessed.

```rust
let dhcp = Dhcp::discover(client_mac)
    .option(DhcpOption::parameter_request_list([1, 3, 6, 15]))
    .host_name("workstation");
```

Use `Dhcp::concatenated_option(code)` to read a logical option that may be
split across repeated instances (RFC 3396 long options). Per-area raw segments
remain inspectable through the segment scanner.

### Option overload, long options, and areas

DHCP options may live in the normal options area or in the overloaded `file`
and `sname` BOOTP fields (option 52). Place options into those areas with
`file_options(...)` / `sname_options(...)`; `compile()` auto-inserts the
overload option (52) when an area is used, and `option_overload()` reports the
decoded selector. Long values are split into 255-byte segments on encode and
concatenated back into one logical value on decode (RFC 3396), while the raw
segments stay inspectable.

### Relay agent information (option 82)

Relay agent information (RFC 3046, option 82) is a typed container of
sub-options. Registered sub-options decode to typed values; unknown
sub-options are preserved with `DhcpRelaySuboption::other(code, data)`.

```rust
let relay = DhcpRelayAgentInfo::new(vec![
    DhcpRelaySuboption::circuit_id(b"eth0:vlan100".to_vec()),
    DhcpRelaySuboption::remote_id(b"relay-1".to_vec()),
]);
let dhcp = Dhcp::discover(client_mac).relay_agent_info(relay);
let recovered = dhcp.relay_agent_information();
```

### Client identifiers (option 61)

`DhcpClientIdentifier` covers the common Ethernet MAC form, the RFC 4361
node-specific (IAID + DUID) form, and a raw fallback:

```rust
let id = DhcpClientIdentifier::ethernet_mac(client_mac.octets());
let dhcp = Dhcp::discover(client_mac).client_id_value(id);
let recovered = dhcp.client_identifier_value();
```

### Authentication and leasequery packet fields

These are packet fields only; the crate does not derive, sign, or verify
authentication, and does not run a leasequery state machine. The authentication
option (RFC 3118, option 90) is exposed as `DhcpAuthentication`
(`authentication()`), and the leasequery family exposes typed status/state
values (`DhcpStatusCodeOption`, `DhcpState`, `DhcpDataSource`) read back through
`status_code()`, `dhcp_state()`, and `associated_ip()`.

### Raw and opaque cases

Some registered codepoints are intentionally kept raw (for example PCP server
158, DNR 162, 6RD 212, and ambiguous historical codes), and intentionally
malformed packets are built through the explicit `Dhcp::malformed()` surface
rather than by weakening the typed builders. In all cases the option code and
payload bytes are preserved so they remain inspectable and re-encodable.

## Address And Range Helpers

```rust
let targets = Ipv4Range::parse("192.0.2.1-20")?;
```

| Helper | Purpose |
| --- | --- |
| `find_interface(name)` | Load interface metadata. |
| `get_ip_strings(iface)` | Return local addresses as strings for generated CLIs. |
| `Ipv4Range::parse(...)` | Parse IPv4 CIDR/range/list expressions. |

## Protocol Names

| Protocol | Rust type |
| --- | --- |
| Raw bytes | `Raw` |
| Ethernet | `Ethernet` |
| ARP | `Arp` |
| IPv4 | `Ipv4` |
| IPv6 | `Ipv6` |
| TCP | `Tcp` |
| UDP | `Udp` |
| UDP surplus options | `UdpOptions`, `UdpOption` |
| ICMPv4 | `Icmpv4` |
| ICMPv6 | `Icmpv6`, `Icmpv6Body` |
| ICMPv6 Neighbor Discovery options | `NdpOptions`, `NdpOption` |
| DNS | `Dns` |
| DHCP | `Dhcp` |
| 802.1Q VLAN | `Vlan` |
| Null/loopback | `NullLoopback` |
| Linux cooked capture | `LinuxSll` |

IPv4-specific construction and decode behavior is covered in
[IPv4 wire coverage](ipv4.md). The `Ipv4` layer exposes DSCP/ECN helpers,
protocol-number labels and constants, decode-time checksum status, typed IPv4
options, fragment metadata fields, `IpDefrag` / `IpFragment` packet-stream
transforms, enriched `summary()` / `show()` output, and `Raw` fallback for
unknown or unsupported payloads.

IPv6 base-header and extension-header details live in
[IPv6 wire coverage](ipv6.md), including source manifests, fixture coverage,
and the offline `ipv6-enrichment` oracle profile. IPv6 examples should use
documentation address space (`2001:db8::/32`) and dry-run or offline flows
unless a provider-backed live workflow is explicitly selected.

## ICMPv4 Messages

`Icmpv4` is the fixed ICMPv4 header and the front of an ICMPv4 packet. Data that
follows the fixed header is composed as its own typed body or extension layer
with `/`, so the same `compile`, `decode_from_l3`, `summary`, and `show` surface
applies to ICMPv4 as to every other protocol.

`Icmp` is now a deprecated alias for `Icmpv4`; existing code that imports `Icmp`
keeps compiling within the 0.x line with a deprecation warning that points at
the v4-explicit name. The ICMPv4 body layers below renamed alongside it, each
with a deprecated alias under its old name: `IcmpQuotedIpv4` → `Icmpv4QuotedIp`,
`IcmpTimestamp` → `Icmpv4Timestamp`, `IcmpAddressMask` → `Icmpv4AddressMask`,
`IcmpRouterAdvertisementEntry` → `Icmpv4RouterAdvertisementEntry`. The
version-neutral types (`IcmpKind`, `IcmpLayer`, and the `IcmpExtension*` RFC 4884
family) keep the `Icmp` prefix because they are shared by both ICMP versions.

Typed constructors track the IANA ICMP Parameters registry:

| Message family | Constructors |
| --- | --- |
| Echo (RFC 792) | `Icmpv4::echo_request()`, `Icmpv4::echo_reply()` |
| Errors (RFC 792) | `Icmpv4::destination_unreachable()`, `Icmpv4::time_exceeded()`, plus `Icmpv4::new().type_(...)` for source quench, redirect, and parameter problem |
| Timestamp / information (RFC 792) | `Icmpv4::timestamp_request()`, `Icmpv4::timestamp_reply()`, `Icmpv4::information_request()`, `Icmpv4::information_reply()` |
| Address mask (RFC 950) | `Icmpv4::address_mask_request()`, `Icmpv4::address_mask_reply()` |
| Router discovery (RFC 1256) | `Icmpv4::router_advertisement()`, `Icmpv4::router_solicitation()` |
| Extended echo (RFC 8335) | `Icmpv4::extended_echo_request()`, `Icmpv4::extended_echo_reply()` |
| Deprecated / experimental | By-name constructors such as `Icmpv4::traceroute()`, `Icmpv4::photuris()`, `Icmpv4::experiment_1()` |

The bytes after the fixed header are typed body and extension layers:

| Layer | Carries |
| --- | --- |
| `Icmpv4QuotedIp` | The quoted original datagram in an ICMPv4 error message. |
| `Icmpv4Timestamp` | RFC 792 originate, receive, and transmit timestamps. |
| `Icmpv4AddressMask` | The RFC 950 address mask. |
| `Icmpv4RouterAdvertisementEntry` | One RFC 1256 advertised router address and preference. |
| `IcmpExtension` / `IcmpExtensionObject` | RFC 4884 multi-part framing and a generic extension object. |
| `IcmpExtensionMpls` | RFC 4950 MPLS label stack object body. |
| `IcmpExtensionInterfaceInfo` | RFC 5837 interface information object body. |
| `IcmpExtensionInterfaceId` | RFC 8335 interface identification object body. |

Build a port-unreachable error that quotes the offending datagram:

```rust
let offending =
    Ipv4::new().src("198.51.100.20")?.dst("192.0.2.10")?
    / Udp::new().sport(40000).dport(53)
    / Raw::from_bytes(b"query");

let packet =
    Ipv4::new().src("192.0.2.10")?.dst("198.51.100.20")?
    / Icmpv4::destination_unreachable().code(ICMP_CODE_DU_PORT_UNREACHABLE)
    / Icmpv4QuotedIp::new(offending);

let bytes = packet.compile()?;
```

`compile` fills the fields the caller left unset — the ICMP checksum, the
RFC 4884 length and zero padding, extension checksums, router advertisement
counts and entry size, and type-specific default codes. Any value set
explicitly survives untouched, including intentionally invalid ones. The raw
escape hatches keep malformed or not-yet-typed messages reachable:

```rust
let icmp = Icmpv4::new()
    .type_(8)               // raw ICMP type
    .code(0)                // raw code
    .checksum(0xdead)       // explicit (here deliberately wrong) checksum
    .rest_of_header([0x11, 0x22, 0x33, 0x44]); // raw rest-of-header bytes
```

`decode_from_l3` types the header and any body it can parse defensibly. Unknown
types, codes, object classes, and trailing bytes stay inspectable through raw
values and `Raw` payloads; genuine header truncation returns a structured buffer
error instead of panicking.

```rust
let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;
let icmp = decoded.layer::<Icmpv4>().ok_or("missing Icmpv4")?;
let quote = decoded.layer::<Icmpv4QuotedIp>();
```

`summary` names the known type and code while keeping the raw numbers visible,
for example `Icmp(type=destination-unreachable(3), code=port-unreachable(3),
id=-, seq=-)`. Unassigned types print numerically, such as `Icmp(type=200,
code=7, ...)`. `show` lists every typed field — checksum, rest-of-header,
identifier, sequence number, RFC 4884 length, router fields, and extended-echo
flags — for field-level inspection workflows.

## ICMPv6 Messages

`Icmpv6` is the fixed ICMPv6 header and the front of an ICMPv6 packet. It carries
the IANA `Type` codepoint space and uses the same shape as `Icmpv4`: the bytes
after the fixed header are typed body layers composed with `/`, the checksum is
auto-filled over the IPv6 pseudo-header at `compile()`, and `summary`, `show`,
and `decode_from_l3` apply uniformly.

Typed constructors track the
[ICMPv6 Parameters registry](https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml):

| Message family | Type(s) | Constructors |
| --- | --- | --- |
| Echo (RFC 4443) | 128/129 | `Icmpv6::echo_request()`, `Icmpv6::echo_reply()` |
| Errors (RFC 4443) | 1–4 | `Icmpv6::destination_unreachable()`, `Icmpv6::packet_too_big()`, `Icmpv6::time_exceeded()`, plus `Icmpv6::new().icmp_type(...)` for parameter problem |
| Multicast Listener Discovery v1 (RFC 2710) | 130–132 | `Icmpv6::mld_query()`, `Icmpv6::mld_general_query()`, `Icmpv6::mld_report()`, `Icmpv6::mld_done()` |
| Multicast Listener Discovery v2 (RFC 3810) | 130, 143 | `Icmpv6::mldv2_report()`, `Icmpv6::mldv2_query()`, `Icmpv6::mldv2_general_query()` |
| Neighbor Discovery (RFC 4861) | 133–137 | `Icmpv6::router_solicitation()`, `Icmpv6::router_advertisement()`, `Icmpv6::neighbor_solicitation()`, `Icmpv6::neighbor_advertisement()`, `Icmpv6::redirect()` |
| Node Information (RFC 4620, **experimental**) | 139/140 | `Icmpv6::node_information_query()`, `Icmpv6::node_information_response()` |
| Extended Echo (RFC 8335) | 160/161 | `Icmpv6::extended_echo_request()`, `Icmpv6::extended_echo_reply()` |

The Neighbor Discovery messages carry an ordered list of NDP options as a typed
TLV layer. Build options through `NdpOption` constructors and collect them in
`NdpOptions`; `compile()` auto-fills each option's length field (in 8-octet
units, with padding), and unknown option types round-trip byte-for-byte.

| NDP option | Type | Reference | Constructor |
| --- | --- | --- | --- |
| Source Link-Layer Address | 1 | RFC 4861 | `NdpOption::source_link_layer_address(...)` |
| Target Link-Layer Address | 2 | RFC 4861 | `NdpOption::target_link_layer_address(...)` |
| Prefix Information | 3 | RFC 4861 | `NdpOption::prefix_information(...)` |
| Redirected Header | 4 | RFC 4861 | `NdpOption::redirected_header(...)` |
| MTU | 5 | RFC 4861 | `NdpOption::mtu(...)` |
| Nonce | 14 | RFC 3971 | `NdpOption::nonce(...)` |
| Route Information | 24 | RFC 4191 | `NdpOption::route_information(...)` |
| RDNSS | 25 | RFC 8106 | `NdpOption::rdnss(...)` |
| RA Flags Extension | 26 | RFC 5175 | `NdpOption::ra_flags_extension(...)` |
| DNSSL | 31 | RFC 8106 | `NdpOption::dnssl(...)` |
| Captive Portal | 37 | RFC 8910 | `NdpOption::captive_portal(...)` |
| PREF64 | 38 | RFC 8781 | `NdpOption::pref64(...)` |

Router Advertisement also exposes the RFC 4191 Default Router Preference (`Prf`)
through `Icmpv6::router_advertisement_with_preference(...)`. `Icmpv6::body()`
returns an `Icmpv6Body` view that classifies the decoded message (echo, error,
the five NDP types, MLD, extended echo, node information) from the header `type`;
unknown types are preserved as `Icmpv6Body::Unknown` with a trailing `Raw` body.

The codepoint coverage, the experimental status of Node Information, and the
deferred families (Router Renumbering, Inverse Neighbor Discovery) are detailed
in [ICMPv6 message coverage](icmpv6-coverage.md).

## Example Map

| Example | API surface exercised |
| --- | --- |
| `hello_world` | IPv4, ICMP, Raw construction, compile, summary, and hexdump output. |
| `packet_building` | Builder-style packet composition, typed field setting, and deterministic compile output. |
| `packet_inspection` | Typed layer access, mutation before compile, packet summaries, and detailed inspection output. |
| `decode_bytes` | Decode from link, network, and IPv4 entry points while preserving raw payloads. |
| `custom_registry` | Protocol registry customization and default decode comparison. |
| `send_plan` | Network-layer send planning, compiled bytes, targets, and derived reply filters. |
| `send_packet` | Network-layer and link-layer send reports using dry-run options by default. |
| `send_recv_icmp` | ICMP send/receive configuration, retry timing, filters, and dry-run reports. |
| `network_ping` | Network-layer ICMP echo send/receive for disposable endpoint smoke tests. |
| `reply_matching` | Synthetic request/reply matching and generated reply filters. |
| `batch_send` | Positional batch send reports for multiple TCP packets. |
| `batch_send_recv` | Batch send/receive reports across IPv4 and IPv6 requests. |
| `interface_helpers` | Documentation-safe interface metadata and address helper output. |
| `ip_ranges` | IPv4 CIDR, range, and list parsing. |
| `pcap_write` | Generated Ethernet/IPv4/TCP packets written to a pcap file. |
| `pcap_read` | Pcap metadata inspection, packet collection, and bounded `PacketWire` source workflows. |
| `sniffer_offline` | Offline `PacketWire` pcap input, `PacketRecord` metadata, and bounded `Sniffer` iteration. |
| `capture_pcap` | Bounded `PacketWire` pcap interface capture and pcap writing after isolated-lab opt-in. |
| `arp_who_has` | Explicit Ethernet broadcast ARP who-has construction from known MAC and IPv4 values. |
| `dns_query` | DNS query construction, dry-run send/receive reporting, and synthetic response decoding. |
| `dhcp_discover` | DHCP discover construction with an explicit client MAC and link-layer send options. |
| `dhcp_option82` | Offline DHCP relay agent information (option 82), classless static routes, and option overload construction and decode. |
| `dhcp_leasequery` | Offline DHCP leasequery, typed client identifier, authentication, and status/state packet-field construction and decode. |
| `icmpv4_error` | ICMPv4 time-exceeded error with a quoted datagram and an RFC 4884/4950 MPLS extension object, compiled and decoded offline. |
| `icmpv6_echo` | IPv6 ICMPv6 echo construction and optional dry-run send/receive reporting. |
| `vlan` | 802.1Q VLAN frame construction, compile, and decode. |
| `linux_sll` | Linux cooked capture packet construction, compile, and decode. |
| `null_loopback` | BSD null/loopback link-layer packet construction, compile, and decode. |
| `ipv4_enrichment` | IPv4 DSCP/ECN helpers, typed options, checksum status, and fragment metadata inspection. |
| `ipv4_options` | IPv4 option builders with checksum and length auto-fill. |
| `tcp_options` | TCP option builders, option ordering, and header-length auto-fill. |
| `ipv6_extensions` | IPv6 routing, segment-routing, and fragment extension header decoding. |

The example set is limited to construction, decoding, pcap, and bounded
validation flows.

## Agent-Oriented Style

Agent-generated tools should prefer:

- `Packet::new().push(...).push(...)` over deeply nested expressions.
- Explicit `SendRecv` configuration over positional timeout/retry arguments.
- `?` propagation with concrete error types or `Box<dyn std::error::Error>`.
- `packet.summary()` for compact output and `packet.show()` for detailed output.
- Offline `compile`, decode, and pcap flows before live send flows.
- Named protocol constructors such as `Icmpv4::echo_request()` and
  `Dns::query_a(name)`.

Concise human examples may use `/`, but generated examples should keep the
builder form nearby in documentation.
