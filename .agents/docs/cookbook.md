# Agent Cookbook

This cookbook is for generated packet tools. Prefer the public `crafter`
facade and `crafter::prelude::*`, keep local behavior offline or dry-run by
default, and require an explicit live-lab path before sending packets.

Generated tools should expose structured errors instead of panicking. For small
CLIs, returning `Result<(), Box<dyn std::error::Error>>` is enough. For services
or agent tools, match concrete errors such as `CrafterError::BufferTooShort` and
return fields like `context`, `required`, and `available` to the caller.

## Build A Packet

Use builder-style setters for generated code. The `/` composition operator is
stable and concise, but `Packet::new().push(...)` is also available when a tool
needs conditional layers.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Icmp::echo_request().id(0x4242).seq(1)
        / Raw::from("agent-ping");

    let bytes = packet.compile()?;
    println!("{}", packet.summary());
    println!("{}", bytes.hexdump());
    Ok(())
}
```

Use documentation addresses such as `192.0.2.0/24`, `198.51.100.0/24`, and
`2001:db8::/32` in examples and tests. Do not use real targets in generated
defaults.

## Build ARP

ARP is a link-layer (L2) protocol, so wrap the `Arp` layer in an `Ethernet`
frame with `ETHERTYPE_ARP`. The `who_has` / `is_at` helpers cover the common
Ethernet/IPv4 request and reply; `compile()` fills the protocol-correct HRD,
PRO, HLN, PLN, and operation defaults. Use RFC 7042 documentation MAC space
(`00:00:5e:00:53:00`–`ff`) and documentation IPv4 for generated defaults.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let me = MacAddr::from([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]);

let request = Ethernet::new()
    .src(me)
    .dst(MacAddr::BROADCAST)
    .ethertype(ETHERTYPE_ARP)
    / Arp::who_has(
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(192, 0, 2, 1),
        me,
    );

println!("{}", request.summary());
```

Named operation codepoints (`ArpOperation`) coexist with the raw `opcode(u16)`
escape hatch, and unknown numeric values round-trip byte-for-byte. ARP-family
opcodes (RARP/DRARP/InARP/ARP-NAK/MAPOS) are named codepoints only — there is no
extension-specific behavior, so do not build tools that assume one. For
nonstandard hardware/protocol families, use the generic raw setters
(`sender_hardware`/`target_hardware`/`sender_protocol`/`target_protocol`); the
matching length field auto-fills from the byte count unless set explicitly, and
a deliberate length mismatch is honored until it fails `compile()` with a
structured `BufferTooShort`.

```rust
use crafter::prelude::*;

let exotic = Arp::new()
    .hardware_type(ARP_HRD_INFINIBAND)
    .protocol_type(ETHERTYPE_IPV6)
    .opcode(1)
    .sender_hardware([0u8; 8])
    .target_protocol([0u8; 16]);

assert!(exotic.sender_mac().is_none());            // typed view declines
assert_eq!(exotic.sender_hardware_bytes_value().len(), 8); // raw view stays
```

ARP dry-run sends use the link-layer plan; never send raw ARP from the
developer host. Reserve the live path for a disposable lab (see Live-Lab
Sending below):

```rust
use crafter::prelude::*;

let plan = request.send_dry_run(
    SendOptions::new()
        .iface("dry-run0")
        .link_layer(),
)?;

println!("target={:?}", plan.target());
println!("filter={}", reply_filter(&request).unwrap_or_default());
println!("{}", plan.compiled_packet().hexdump());
```

`reply_filter` emits BPF host terms only for standard 4-byte IPv4 addresses and
degrades to a bare `arp` filter for variable-length or non-IPv4 forms, so
generated matchers stay correct on nonstandard ARP.

Live ARP validation is L2-only and must run through provider-backed QEMU or
VirtualBox lab sessions with `link_layer_send` + `link_layer_capture`
capability checks, protected confirmation, artifact collection, and teardown.
When authorization or VM prerequisites are absent, plan with `--dry-run` and
record a skip artifact rather than faking a live run. The user-facing coverage
boundary lives in [`docs/arp-rfc-coverage.md`](../../docs/arp-rfc-coverage.md).

## Decode Bytes

Pick the decode entrypoint from the context that produced the bytes. Link-layer
pcaps usually use `LinkType::Ethernet`; raw IP sockets usually use
`NetworkLayer::Ipv4` or `NetworkLayer::Ipv6`.

```rust
use crafter::prelude::*;

fn decode_ipv4(bytes: &[u8]) -> Result<(), CrafterError> {
    let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes)?;
    println!("{}", packet.show());

    if let Some(tcp) = packet.layer::<Tcp>() {
        println!(
            "tcp {} -> {}",
            tcp.source_port_value(),
            tcp.destination_port_value()
        );
    }

    Ok(())
}
```

Malformed input should be reported as data, not hidden. For example:

```rust
match Packet::decode_from_l3(NetworkLayer::Ipv4, bytes) {
    Ok(packet) => println!("{}", packet.summary()),
    Err(CrafterError::BufferTooShort { context, required, available }) => {
        eprintln!("decode_error context={context} required={required} available={available}");
    }
    Err(error) => eprintln!("decode_error {error}"),
}
```

## Read A pcap

Use `read_pcap` for full offline reads and `read_pcap_filtered` when a libpcap
BPF filter should be applied while reading.

```rust
use crafter::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let packets = read_pcap_filtered("capture.pcap", "tcp or udp")?;
    for captured in packets {
        println!(
            "ts={} summary={}",
            captured.timestamp().seconds(),
            captured.packet().summary()
        );
    }
    Ok(())
}
```

## Write A pcap

Use `dump_pcap` for deterministic fixtures. Use an explicit link type so the
file can be decoded later without guessing.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let packet = Ethernet::new()
        .src_str("02:00:5e:00:53:01")?
        .dst_str("02:00:5e:00:53:ff")?
        / Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Udp::new().sport(53000).dport(33434)
        / Raw::from("payload");

    dump_pcap("target/agent-fixture.pcap", [&packet], LinkType::Ethernet)?;
    Ok(())
}
```

## Sniff With A Filter

Prefer offline sniffing for generated code and tests. It exercises the same
packet decode paths without requiring root or interfaces.

```rust
use crafter::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let packets = Sniffer::offline("target/agent-fixture.pcap")
        .filter("udp")
        .count(10)
        .collect()?;

    for packet in packets {
        println!("{}", packet.packet().summary());
    }
    Ok(())
}
```

Live sniffing must be bounded and lab-only:

```rust
use crafter::prelude::*;
use std::time::Duration;

let packets = Sniffer::interface("eth0")
    .filter("icmp")
    .count(3)
    .timeout(Duration::from_secs(2))
    .collect()?;
```

Only run that form inside a disposable live lab.

## Dry-Run Sending

Dry-run is the default mode generated tools should choose. It compiles the
packet, derives the send target, and returns a plan without transmitting.

```rust
use crafter::prelude::*;

let plan = packet.send_dry_run(
    SendOptions::new()
        .iface("dry-run0")
        .network_layer(),
)?;

println!("target={:?}", plan.target());
println!("{}", plan.compiled_packet().hexdump());
```

Expose a `--live` flag only when the tool also checks for an isolated lab marker
or is run through `tools/live-lab/`.

## Live-Lab Sending

Live sending belongs in disposable infrastructure, not on the developer
machine. Run local checks first, then use the provider-agnostic lab command:

```sh
cargo test --workspace
tools/live-lab/libcrafter-live-lab doctor --provider local-dry-run
tools/live-lab/libcrafter-live-lab run --provider local-dry-run --suite all
```

When credentials are configured outside the repo, the same suite can run on a
disposable provider host:

```sh
tools/live-lab/libcrafter-live-lab doctor --provider hetzner --dry-run
tools/live-lab/libcrafter-live-lab run --provider hetzner --suite all
```

Inside that disposable host, live code can opt in explicitly:

```rust
let report = packet.send(
    SendOptions::new()
        .iface("eth0")
        .network_layer()
        .live(),
)?;
println!("bytes_sent={}", report.bytes_sent());
```

Always destroy provider resources after the run.

## Oracle Validation

Use the oracle runner when generated tools change packet behavior. The oracle is
the validation system. Backend-specific names and implementation details belong
inside `tools/oracle/`; agents should not add ad hoc reference-backend imports
to tests or scripts when an oracle mode covers the same behavior.

Offline validation compares generated raw packet vectors and normalized decode
models without root privileges:

```sh
tools/oracle/run offline --profile smoke --seed 1 --count 10
```

Pcap validation exercises pcap writer, reader, and roundtrip behavior:

```sh
tools/oracle/run pcap --profile smoke --seed 1 --count 10
```

Live validation routes through a provider. Use `local-dry-run` for agent and CI
planning, and reserve real providers for explicit live-lab workflows:

```sh
tools/oracle/run live --provider local-dry-run --profile smoke --seed 1 --count 10
tools/oracle/run live --provider hetzner --dry-run --profile smoke --seed 12345 --count 10
```

Artifacts default below `target/oracle/`, with mode-specific reports under
`target/oracle/offline`, `target/oracle/pcap`, and `target/oracle/live`. Every
failing oracle command should be rerunnable with the same `--profile`, `--seed`,
`--count`, and, when the report identifies one packet, `--index`.

Pull request CI runs deterministic oracle offline coverage and pcap smoke
coverage with the configured backend. Provider-backed live traffic must stay
behind explicit live-lab confirmation or dry-run workflows.

## send_recv Matching

Use `send_recv_report` when the tool needs the derived reply filter and timeout
state. In dry-run mode it builds the request and filter without sending.

```rust
use crafter::prelude::*;
use std::time::Duration;

let options = SendRecv::new()
    .iface("dry-run0")
    .network_layer()
    .dry_run()
    .timeout(Duration::from_secs(1))
    .retries(1)
    .filter("icmp");

let report = packet.send_recv_report(options)?;
println!("filter={}", report.effective_filter().unwrap_or(""));
println!("timed_out={}", report.timed_out());

if let Some(reply) = report.reply() {
    println!("reply={}", reply.summary());
}
```

For offline tests, build a synthetic reply and use `reply_matches(&request,
&reply)` to validate matching logic without live traffic.

## Batch Scans

Use `BatchSendRecv` for ping sweeps, traceroute probes, and ARP scans. Keep
timeouts short, cap the packet list, and return per-request reports to the
caller.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let src = Ipv4Addr::new(192, 0, 2, 10);
let dst = Ipv4Addr::new(198, 51, 100, 20);
let packets = (1..=4)
    .map(|ttl| {
        Ipv4::new().src(src).dst(dst).ttl(ttl)
            / Icmp::echo_request().id(0x4242).seq(ttl as u16)
    })
    .collect::<Vec<_>>();

let report = send_recv_packets(
    &packets,
    BatchSendRecv::new()
        .iface("dry-run0")
        .network_layer()
        .dry_run()
        .retries(1)
        .filter("icmp"),
)?;

for entry in report.entries() {
    println!(
        "request={} attempts={} matched={}",
        entry.request_index(),
        entry.attempts(),
        entry.reply().is_some()
    );
}
```

## Oracle Comparison

Use oracle offline artifacts to validate byte-level behavior for deterministic
packets. Offline generation does not require root.

```sh
tools/oracle/run offline --profile smoke --seed 1 --count 10
```

A generated Rust tool can write its compiled bytes to a target file and compare
against the raw vector artifacts under `target/oracle/offline/`. Prefer exact
byte comparison for stable headers and structured field comparison when
timestamps, random ids, route state, or OS-assigned values are expected to vary.
