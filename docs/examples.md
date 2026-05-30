# Examples

The Rust examples live under `crafter/examples/` and build against the
public `crafter` facade API. The suite covers packet construction, decode,
inspection, registry customization, pcap read/write, offline sniffing,
live-gated capture, send planning, send/receive reports, batch workflows,
interface helpers, IPv4 ranges, reply matching, and representative protocol
layers.

For the complete inventory, safety classification, and per-example command map,
see [`crafter/examples/README.md`](../crafter/examples/README.md).

## Representative Commands

Build every example:

```sh
cargo build -p crafter --examples
```

Run a compact local tour:

```sh
cargo run -p crafter --example hello_world
cargo run -p crafter --example packet_inspection
cargo run -p crafter --example pcap_write
cargo run -p crafter --example pcap_read
cargo run -p crafter --example sniffer_offline
cargo run -p crafter --example send_plan
cargo run -p crafter --example send_recv_icmp
cargo run -p crafter --example batch_send_recv
cargo run -p crafter --example dns_query -- --name example.com
```

## UDP Options Snippet

UDP options use the same packet composition surface as the rest of the crate.
Place the `UdpOptions` layer after the UDP user payload so `compile()` can keep
the UDP length/checksum boundary correct and materialize the RFC 9868 surplus
area.

```rust
use crafter::prelude::*;

fn main() -> crafter::Result<()> {
    let options = UdpOptions::new()
        .udp_option(UdpOption::maximum_datagram_size(1200))?
        .additional_payload_checksum();

    let packet = Ipv4::new()
        .src("192.0.2.10")?
        .dst("198.51.100.20")?
        / Udp::new().sport(53000).dport(33434)
        / Raw::from("udp-options")
        / options;

    let bytes = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;
    println!("{}", decoded.summary());
    Ok(())
}
```

Focused offline checks for UDP options:

```sh
cargo test -p crafter --test fixture_suite udp_options
tools/oracle/run offline --backend scapy --profile smoke --seed 9868 --count 20 --family udp --out target/oracle/udp-options-example-offline
```

Examples are safe by default. Live-capable examples require `--live` and
`--i-understand-isolated-lab` before opening live send or capture handles, and
should run only inside disposable wire endpoints.
