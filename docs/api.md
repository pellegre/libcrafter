# Rust API Guide

This document summarizes the public Rust surface for generated packet tools.
Version 2.0.0 focuses on explicit builders, deterministic compile/decode
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
| `crafter::pcap` | Pcap reader/writer helpers and libpcap-backed capture adapters. |
| `crafter::net` | Interfaces, raw sockets, send, send-receive, routing helpers, and address helpers. |

## Packet Composition

Generated tools should prefer explicit builders:

```rust
let packet = Packet::new()
    .push(Ipv4::new().src("192.0.2.10")?.dst("198.51.100.20")?)
    .push(Icmp::echo_request().id(0x1234).seq(1))
    .push(Raw::from_bytes(b"HelloPing!\n"));

let bytes = packet.compile()?;
```

Concise examples may use `/` composition:

```rust
let packet =
    Ipv4::new().dst("198.51.100.20")?
    / Icmp::echo_request().seq(1)
    / Raw::from_bytes(b"HelloPing!\n");
```

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

## Pcap Helpers

```rust
let packets = PcapReader::open("input.pcap")?.collect_packets()?;

PcapWriter::create("out.pcap", LinkType::Ethernet)?
    .write_packet(&packet)?
    .flush()?;
```

Lower-level streaming APIs:

```rust
let mut reader = PcapReader::open("input.pcap")?;
while let Some(record) = reader.next_record()? {
    let packet = Packet::decode_from_link(record.link_type(), record.data())?;
    println!("{}", packet.summary());
}
```

Pcap helpers are exposed under `crafter::pcap` and through the prelude where
appropriate.

## Sniff Helpers

Iterator form:

```rust
let mut sniffer = Sniffer::interface("eth0")
    .filter("icmp")
    .timeout(Duration::from_secs(3))
    .open()?;

for packet in sniffer.take(10) {
    println!("{}", packet?.summary());
}
```

Callback form:

```rust
Sniffer::interface("eth0")
    .filter("tcp port 80")
    .capture(100, |packet| {
        println!("{}", packet.summary());
        Ok(CaptureControl::Continue)
    })?;
```

Spawned capture:

```rust
let handle = Sniffer::interface("eth0").filter("arp").spawn(50)?;
let packets = handle.join()?;
```

Sniffing must use timeouts by default in examples and tests. Live sniffing
belongs in disposable wire endpoint workflows, not local static tests.

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
| ICMP | `Icmp` |
| ICMPv6 | `Icmpv6` |
| DNS | `Dns` |
| DHCP | `Dhcp` |
| 802.1Q VLAN | `Vlan` |
| Null/loopback | `NullLoopback` |
| Linux cooked capture | `LinuxSll` |

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
| `network_ping` | Network-layer ICMP echo send/receive for disposable wire endpoint smoke tests. |
| `reply_matching` | Synthetic request/reply matching and generated reply filters. |
| `batch_send` | Positional batch send reports for multiple TCP packets. |
| `batch_send_recv` | Batch send/receive reports across IPv4 and IPv6 requests. |
| `interface_helpers` | Documentation-safe interface metadata and address helper output. |
| `ip_ranges` | IPv4 CIDR, range, and list parsing. |
| `pcap_write` | Generated Ethernet/IPv4/TCP packets written to a pcap file. |
| `pcap_read` | Pcap metadata inspection, packet collection, and streaming `PcapReader` workflows. |
| `sniffer_offline` | Offline `Sniffer` filtering and bounded packet iteration. |
| `capture_pcap` | Bounded libpcap capture configuration and pcap writing after isolated-lab opt-in. |
| `arp_who_has` | Explicit Ethernet broadcast ARP who-has construction from known MAC and IPv4 values. |
| `dns_query` | DNS query construction, dry-run send/receive reporting, and synthetic response decoding. |
| `dhcp_discover` | DHCP discover construction with an explicit client MAC and link-layer send options. |
| `dhcp_option82` | Offline DHCP relay agent information (option 82), classless static routes, and option overload construction and decode. |
| `dhcp_leasequery` | Offline DHCP leasequery, typed client identifier, authentication, and status/state packet-field construction and decode. |
| `icmpv6_echo` | IPv6 ICMPv6 echo construction and optional dry-run send/receive reporting. |
| `vlan` | 802.1Q VLAN frame construction, compile, and decode. |
| `linux_sll` | Linux cooked capture packet construction, compile, and decode. |
| `null_loopback` | BSD null/loopback link-layer packet construction, compile, and decode. |
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
- Named protocol constructors such as `Icmp::echo_request()` and
  `Dns::query_a(name)`.

Concise human examples may use `/`, but generated examples should keep the
builder form nearby in documentation.
