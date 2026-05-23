# Rust API Map

This document summarizes the public Rust surface for generated packet tools.
The first alpha focuses on explicit builders, deterministic compile/decode
behavior, bounded pcap workflows, and lab-only live traffic.

Most examples should start with:

```rust
use crafter::prelude::*;
```

## Public Crates

| Crate | Responsibility |
| --- | --- |
| `crafter` | Facade crate re-exporting the public API for examples and agent-written tools. |
| `crafter-core` | Packet model, layer model, encode/decode, checksums, formatting, and protocol registry. |
| `crafter-pcap` | Pcap reader/writer helpers and libpcap-backed capture adapters. |
| `crafter-net` | Interfaces, raw sockets, send, send-receive, routing helpers, and address helpers. |
| `crafter-live` | Disposable live-lab helpers and integration-test support only. |

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
let packets = read_pcap_filtered("input.pcap", "icmp")?;

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
belongs in disposable lab workflows, not local static tests.

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

## Address And Range Helpers

```rust
let targets = Ipv4Range::parse("192.0.2.1-20")?;
```

| Helper | Purpose |
| --- | --- |
| `find_interface(name)` | Load interface metadata. |
| `get_ip_strings(iface)` | Return local addresses as strings for generated CLIs. |
| `resolve_mac(ip, iface)` | Resolve MAC addresses through ARP in live-lab contexts. |
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
| `hello_world.rs` | Layer construction, `show`, `summary`. |
| `payload_hello_world.rs` | `Raw`, `/` composition, `compile`. |
| `basic_send.rs` | `Packet::new`, Ethernet/IPv4/TCP, send planning. |
| `ping.rs` | `Icmp::echo_request`, compile-only send plans. |
| `basic_ping_pong.rs` | Request/reply matching and `reply_filter`. |
| `network_ping.rs` | ICMP send/receive workflow. |
| `arp_ping.rs` | `Arp::who_has`, L2 send-receive, MAC resolution. |
| `dns_query.rs` | `Udp`, `Dns::query`, response decoding. |
| `tcp_traceroute.rs` | TTL loops, TCP SYN, ICMP time-exceeded handling. |
| `simple_sniffer.rs` | `Sniffer`, BPF filters, packet iteration. |
| `read_pcap.rs` | `PcapReader`, decode from link type. |
| `dump_pcap.rs` | `PcapWriter`. |
| `capture_pcap.rs` | Bounded libpcap capture into pcap files. |
| `tcp_options.rs` | TCP option builders and header-length auto-fill. |
| `ip_options.rs` | IPv4 option builders and checksum/length auto-fill. |
| `dhcp_request.rs` | DHCP over Ethernet/IPv4/UDP. |
| `ping6.rs` | IPv6 and ICMPv6 checksum pseudo-header. |
| `ping_ipv4_ipv6.rs` | Dual-stack example organization. |
| `combine_ipv4_ipv6.rs` | Mixed packet collections and pcap output. |
| `ipv6_routing_header.rs` | IPv6 extension header composition. |
| `null_header.rs` | Loopback/null link-layer decode. |
| `sack_option.rs` | TCP SACK option encoding/decoding. |
| `extended_data_offset.rs` | TCP data-offset edge cases. |
| `user_sockets.rs` | Explicit socket wrappers and send helpers. |

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
