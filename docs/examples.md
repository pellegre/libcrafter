# Examples

The Rust examples live under `crates/crafter/examples/` and build against the
public `crafter` facade API. The suite covers packet construction, decode,
inspection, registry customization, pcap read/write, offline sniffing,
live-gated capture, send planning, send/receive reports, batch workflows,
interface helpers, IPv4 ranges, reply matching, and representative protocol
layers.

For the complete inventory, safety classification, and per-example command map,
see [`crates/crafter/examples/README.md`](../crates/crafter/examples/README.md).

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

Examples are safe by default. Live-capable examples require `--live`,
`--i-understand-isolated-lab`, and `LIBCRAFTER_LIVE_LAB=1` before opening live
send or capture handles.
