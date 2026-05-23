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

## Reference Fixture Comparison

Use reference fixtures to validate byte-level behavior for deterministic packets.
Fixture generation is offline and does not require root.

```sh
tools/reference/generate-reference-fixtures --list
tools/reference/generate-reference-fixtures --only ipv4-icmp --out target/reference-fixtures
```

A generated Rust tool can write its compiled bytes to a target file and compare
against `target/reference-fixtures/ipv4-icmp.bin`. Prefer exact byte comparison
for stable headers and structured field comparison when timestamps, random ids,
route state, or OS-assigned values are expected to vary.
