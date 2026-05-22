# Rust API Map

This document maps the legacy libcrafter API and Scapy-inspired packet workflows
to the planned Rust public surface. It is a design target for the port, not a
claim that every symbol already exists.

The first milestone is a packet crafting library that agents can use by copying
small, explicit examples. The generated-code style is therefore primary:
predictable constructors, builder methods, typed errors, and named helpers. A
concise `/` composition style is still planned for interactive and example code.

Example parity should be checked against `LIBCRAFTER_EXAMPLES_DIR` when set, or
the conventional sibling checkout at `../libcrafter-examples`.

## Public Crates

| Crate | Responsibility |
| --- | --- |
| `crafter-core` | Packet model, layer model, encode/decode, checksums, formatting, fixture-friendly APIs. |
| `crafter-pcap` | Pcap reader/writer helpers and libpcap-backed capture adapters. |
| `crafter-net` | Interfaces, raw sockets, send, send-receive, routing helpers, address helpers. |
| `crafter-live` | Disposable live-lab helpers and integration-test support only. |
| `crafter` | Facade crate re-exporting the stable public API for examples and agent-written tools. |

Most examples should start with:

```rust
use crafter::prelude::*;
```

The prelude should expose the common packet, layer, pcap, sniffing, and send
helpers without hiding protocol-specific types.

## Packet Composition

Legacy libcrafter uses `Packet`, `Layer`, `PushLayer`, and `operator/`:

```cpp
Packet packet = IP() / ICMP() / RawLayer("hello");
packet.PushLayer(TCP());
```

The Rust port should expose the same workflow through `Packet::new`, `push`, and
`/` composition.

Generated-code style:

```rust
use crafter::prelude::*;

let packet = Packet::new()
    .push(Ipv4::new().src("192.0.2.10")?.dst("198.51.100.20")?)
    .push(Icmp::echo_request().identifier(0x1234).sequence(1))
    .push(Raw::from_bytes(b"HelloPing!\n"));

let bytes = packet.compile()?;
```

Concise composition style:

```rust
use crafter::prelude::*;

let packet =
    Ipv4::new().dst("198.51.100.20")?
    / Icmp::echo_request().sequence(1)
    / Raw::from_bytes(b"HelloPing!\n");

packet.show();
```

The builder style is the canonical surface for agents. The `/` style is a
convenience layer implemented with `std::ops::Div` for layer-to-layer,
layer-to-packet, and packet-to-layer composition.

## Layer Builders

Each protocol should use a concrete layer struct with predictable methods:

```rust
let tcp = Tcp::new()
    .sport(44444)
    .dport(80)
    .syn()
    .window(64240)
    .option(TcpOption::mss(1460))
    .option(TcpOption::sack_permitted());
```

Builder conventions:

| Pattern | Meaning |
| --- | --- |
| `Layer::new()` | Construct an empty layer with unset auto-fill fields. |
| `Layer::request()` / `Layer::reply()` | Protocol-specific semantic constructors when useful. |
| `.field(value)` | Set a field explicitly and preserve it during compile. |
| `.try_field(value)?` | Parse or validate a fallible field value. |
| `.option(...)` | Append protocol options while preserving order. |
| `.payload(...)` | Attach raw bytes when no higher layer is needed. |
| `.clear_field()` | Return a field to the unset state so auto-fill may apply. |

The core model must distinguish unset, defaulted, and explicitly set fields.
`compile` may fill unset lengths, protocol numbers, header lengths, and
checksums, but it must not overwrite explicit user input.

## Packet Compile and Decode

Legacy libcrafter operations:

| libcrafter | Rust equivalent |
| --- | --- |
| `Packet::GetRawPtr`, `GetData`, `PreCraft` | `packet.compile()?`, `packet.compile_into(&mut buf)?`, `packet.freeze()?` |
| `Packet(data, len, proto_id)` | `Packet::decode_from_link`, `Packet::decode_from_l3`, `Packet::decode_as` |
| `PacketFromEthernet`, `PacketFromIP`, `PacketFromIPv6` | `Packet::decode_ethernet`, `Packet::decode_ipv4`, `Packet::decode_ipv6` |
| `CraftLayer(layer)` | `layer.compile_with_context(ctx)?` internal API |

Planned API:

```rust
let bytes: Bytes = packet.compile()?;

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

Legacy libcrafter exposes `GetLayer<T>`, `GetIP`, `GetTCP`, `operator[]`, and
iterators. Rust should provide typed access without downcast ceremony:

```rust
let packet = Packet::decode_from_link(LinkType::Ethernet, frame)?;

let ip = packet.layer::<Ipv4>().ok_or(Error::missing_layer("Ipv4"))?;
let tcp = packet.layer::<Tcp>();
let all_options = packet.layers::<TcpOptionLayer>();

for layer in packet.iter() {
    println!("{}", layer.summary());
}
```

Planned accessors:

| Rust API | Purpose |
| --- | --- |
| `packet.layer::<T>() -> Option<&T>` | First layer of type `T`. |
| `packet.layer_mut::<T>() -> Option<&mut T>` | Mutable typed access before compile. |
| `packet.layers::<T>() -> impl Iterator<Item = &T>` | All layers of type `T`. |
| `packet.get(index) -> Option<&dyn Layer>` | Positional stack access. |
| `packet.subpacket(range) -> Packet` | Equivalent to libcrafter `SubPacket`. |
| `packet.iter()` | Ordered layer iteration. |

## Inspection Helpers

The Rust names should be lowercase and easy for generated tools to print:

| libcrafter / workflow | Rust equivalent |
| --- | --- |
| `Print()` | `packet.show()` and `format!("{}", packet.display_tree())` |
| packet one-line description | `packet.summary()` |
| `HexDump()` | `packet.hexdump()` and `hexdump(&bytes)` |
| `RawString()` | `packet.raw_string_lossy()` |
| filter emitted for reply matching | `packet.reply_filter()` |

Example:

```rust
println!("{}", packet.summary());
packet.show();
println!("{}", packet.hexdump()?);
```

`summary` should be compact and stable enough for snapshot tests. `show` can be
more verbose and field-oriented.

## Pcap Helpers

Legacy libcrafter pcap functions live in `PacketContainer.h`: `OpenOffPcap`,
`LoopPcap`, `OpenPcapDumper`, `DumperPcap`, and `ClosePcap`.

Planned Rust API:

```rust
use crafter::prelude::*;

let packets = PcapReader::open("input.pcap")?
    .filter("icmp")?
    .collect_packets()?;

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

Pcap helpers belong in `crafter-pcap`, re-exported by `crafter`.

## Sniff Helpers

Legacy libcrafter uses `Sniffer`, `SetFilter`, `Capture`, `Spawn`, `Join`, and
callback-style packet handlers. Rust should offer both iterator and callback
forms.

Iterator form:

```rust
let mut sniffer = Sniffer::new()
    .iface("eth0")
    .filter("icmp")
    .timeout(Duration::from_secs(3))
    .open()?;

for packet in sniffer.take(10) {
    println!("{}", packet?.summary());
}
```

Callback form:

```rust
Sniffer::new()
    .iface("eth0")
    .filter("tcp port 80")
    .capture(100, |packet| {
        println!("{}", packet.summary());
        Ok(ControlFlow::Continue)
    })?;
```

Spawned capture should be explicit:

```rust
let handle = Sniffer::new().iface("eth0").filter("arp").spawn(50)?;
let packets = handle.join()?;
```

Sniffing must use timeouts by default in examples and tests. Live sniffing
belongs in disposable lab workflows, not local static tests.

## Send and Send-Receive Helpers

Legacy libcrafter:

| libcrafter | Rust equivalent |
| --- | --- |
| `packet.Send(iface)` | `packet.send(&iface)?` |
| `packet.SendRecv(iface, timeout, retry, filter)` | `packet.send_recv(SendRecv::new().iface(iface).timeout(...).retry(...).filter(...))?` |
| `packet.SocketSend(sd)` | `socket.send(&packet)?` |
| `packet.SocketSendRecv(sd, ...)` | `socket.send_recv(&packet, SendRecv::new()...)` |
| `packet.GetFilter(out)` | `packet.reply_filter()?` |

The configuration object is named `SendRecv` so generated tools can assemble
send-receive behavior without remembering argument order:

```rust
let reply = packet.send_recv(
    SendRecv::new()
        .iface("eth0")
        .timeout(Duration::from_secs(1))
        .retries(3)
        .filter(packet.reply_filter()?),
)?;

if let Some(reply) = reply {
    println!("{}", reply.summary());
}
```

Batch send-receive should return positional results:

```rust
let replies = SendRecv::new()
    .iface("eth0")
    .timeout(Duration::from_millis(750))
    .retries(1)
    .send_all(packets)?;

for result in replies {
    println!("{:?}", result);
}
```

Raw socket operations should be exposed through typed socket wrappers rather
than integer file descriptors in normal examples.

## Batch Helpers

Legacy libcrafter has range-based `Send`, `SendMultiThread`, `PreCraft`, IP
range parsing, number parsing, and address helpers.

Planned Rust API:

```rust
let targets = Ipv4Targets::parse("192.0.2.1-20,198.51.100.10")?;
let ports = NumberSet::<u16>::parse("22,80,443,8000-8010")?;

let packets: Vec<Packet> = targets
    .iter()
    .map(|dst| Packet::new()
        .push(Ipv4::new().dst(dst))
        .push(Icmp::echo_request()))
    .collect();

PacketBatch::from(packets)
    .precompile()?
    .send(SendOptions::new().iface("eth0").concurrency(4))?;
```

Address helper map:

| libcrafter | Rust equivalent |
| --- | --- |
| `GetMyMAC(iface)` | `Interface::open(iface)?.mac()?` |
| `GetMyIP(iface)` | `Interface::open(iface)?.ipv4_addr()?` |
| `GetMyIPv6(iface, ll)` | `Interface::open(iface)?.ipv6_addr(AddressScope::LinkLocal)` |
| `GetMAC(ip, iface)` | `ArpResolver::new(iface).resolve(ip)?` |
| `GetIPs`, `GetNumbers` | `Ipv4Targets::parse`, `NumberSet::parse` |

## Protocol Naming

Use Rust idioms while keeping old example names recognizable:

| libcrafter | Rust |
| --- | --- |
| `RawLayer` | `Raw` |
| `Ethernet` | `Ethernet` |
| `ARP` | `Arp` |
| `IP` | `Ipv4` |
| `IPv6` | `Ipv6` |
| `TCP` | `Tcp` |
| `UDP` | `Udp` |
| `ICMP` | `Icmp` |
| `ICMPv6` | `Icmpv6` |
| `DNS` | `Dns` |
| `DHCP` | `Dhcp` |
| `VLAN` / 802.1Q | `Vlan` |
| `NULL` | `NullLoopback` |
| Linux cooked capture | `LinuxSll` |

## High-Priority Example Map

Each Rust port should live under `examples/` and preserve the intent and
arguments of the matching C++ example from `LIBCRAFTER_EXAMPLES_DIR` or
`../libcrafter-examples`.

| Legacy example | Planned Rust example | API surface exercised |
| --- | --- | --- |
| `HelloWorld` | `examples/hello_world.rs` | Layer construction, `show`, `summary`. |
| `PayloadHelloWorld` | `examples/payload_hello_world.rs` | `Raw`, `/` composition, `compile`. |
| `BasicSend` | `examples/basic_send.rs` | `Packet::new`, Ethernet/IPv4/ICMP, `send`. |
| `Ping` | `examples/ping.rs` | `Icmp::echo_request`, `SendRecv`, reply parsing. |
| `BasicPingPong` | `examples/basic_ping_pong.rs` | Request/reply matching and `reply_filter`. |
| `NetworkPing` | `examples/network_ping.rs` | `Ipv4Targets`, `PacketBatch`, concurrent `SendRecv`. |
| `ARPPing` | `examples/arp_ping.rs` | `Arp::who_has`, L2 send-receive, MAC resolution. |
| `DNSQuery` | `examples/dns_query.rs` | `Udp`, `Dns::query`, response decoding. |
| `TCPTraceroute` | `examples/tcp_traceroute.rs` | TTL loops, TCP SYN, ICMP time-exceeded handling. |
| `SimpleSniffer` | `examples/simple_sniffer.rs` | `Sniffer`, BPF filters, packet iteration. |
| `ReadPcap` | `examples/read_pcap.rs` | `PcapReader`, decode from link type. |
| `DumpPcap` | `examples/dump_pcap.rs` | `Sniffer` plus `PcapWriter`. |
| `TCPOptions` | `examples/tcp_options.rs` | TCP option builders and header-length auto-fill. |
| `IPOptions` | `examples/ip_options.rs` | IPv4 option builders and checksum/length auto-fill. |
| `DHCPRequest` | `examples/dhcp_request.rs` | `Dhcp::discover`, broadcast Ethernet/IPv4/UDP. |
| `Ping6` | `examples/ping6.rs` | IPv6 and ICMPv6 checksum pseudo-header. |
| `PingIPv4IPv6` | `examples/ping_ipv4_ipv6.rs` | Dual-stack example organization. |
| `CombineIPv4IPv6` | `examples/combine_ipv4_ipv6.rs` | Mixed packet collections and pcap output. |
| `IPv6RoutingHeader` | `examples/ipv6_routing_header.rs` | IPv6 extension header composition. |
| `NULLHeader` | `examples/null_header.rs` | Loopback/null link-layer decode. |
| `SACKOption` | `examples/sack_option.rs` | TCP SACK option encoding/decoding. |
| `ExtendedDataOffset` | `examples/extended_data_offset.rs` | TCP data-offset edge cases. |
| `UserSockets` | `examples/user_sockets.rs` | Explicit socket wrappers and send helpers. |

should be ported later behind live-lab-only labels and must not run by default.

## Agent-Oriented Style Guide

Agent-generated tools should prefer:

- `Packet::new().push(...).push(...)` over deeply nested expressions.
- Explicit `SendRecv` configuration over positional timeout/retry arguments.
- `?` propagation with `crafter::Result`.
- `packet.summary()` for compact output and `packet.show()` for detailed output.
- Offline `compile`, decode, and pcap flows before live send flows.
- Named protocol constructors such as `Icmp::echo_request()` and
  `Dns::query_a(name)`.

Concise human examples may use `/`, but generated examples should always have a
builder equivalent nearby in documentation.

