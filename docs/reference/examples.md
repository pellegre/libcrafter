# Examples

The Rust examples live under `crafter/examples/` and build against the
public `crafter` facade API. The suite covers packet construction, decode,
inspection, registry customization, pcap read/write, offline sniffing,
live-gated capture, send planning, send/receive reports, batch workflows,
interface helpers, IPv4 ranges, reply matching, and representative protocol
layers.

IPv6-specific examples, including DHCPv6, stay offline or dry-run by default
and use documentation address space. See [IPv6 wire coverage](../guide/ipv6.md)
and [DHCPv6 wire coverage](../guide/dhcpv6.md) for guides, fixtures, and
validation coverage.

For the complete inventory, safety classification, and per-example command map,
see [`crafter/examples/README.md`](../../crafter/examples/README.md).

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
cargo run -p crafter --example snmp_get
cargo run -p crafter --example snmp_trap
cargo run -p crafter --example snmpv3_message
cargo run -p crafter --example ipv4_enrichment
cargo run -p crafter --example tcp_options
cargo run -p crafter --example dhcpv6_solicit
cargo run -p crafter --example dhcpv6_relay
```

## mDNS Packet Snippet

mDNS currently appears as packet-level snippets and guide coverage rather than
a live example binary. Build DNS-SD browse, resolve, announce, known-answer,
probe, and goodbye shapes with the existing `Dns` layer and the `mdns` helper
module, then compile or decode them offline.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> crafter::Result<()> {
    let service = mdns::dns_sd_tcp_service_name("ipp", DNS_SD_DEFAULT_DOMAIN)?;
    let dns = mdns::query(DnsQuestion::new(service, DNS_TYPE_PTR).mdns_qu(true));
    let packet = mdns::mdns_ipv4_packet(Ipv4Addr::new(192, 0, 2, 10), dns);

    let bytes = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;
    println!("{}", decoded.summary());
    Ok(())
}
```

Use [mDNS and DNS-SD wire coverage](../guide/mdns.md) for the full helper
catalog. Live mDNS traffic is not part of default examples; use dry-run plans
or provider-backed lab/probe workflows when real multicast behavior is
authorized.

## DHCPv4 And DHCPv6 Examples

The DHCP examples are packet-primitive smoke tests. `dhcpv4_discover` defaults
to a dry-run link-layer send plan; `dhcpv4_option82` and `dhcpv4_leasequery`
compile and decode offline. `dhcpv6_solicit` and
`dhcpv6_information_request` use `SendRecv::new().dry_run()` for
network-layer send/receive planning; `dhcpv6_prefix_delegation` and
`dhcpv6_relay` compile and decode offline.

```sh
cargo run -p crafter --example dhcpv4_discover
cargo run -p crafter --example dhcpv4_option82
cargo run -p crafter --example dhcpv4_leasequery
cargo run -p crafter --example dhcpv6_solicit
cargo run -p crafter --example dhcpv6_information_request
cargo run -p crafter --example dhcpv6_prefix_delegation
cargo run -p crafter --example dhcpv6_relay
```

Both protocol families use the same packet stack surface: compose a typed
`Dhcpv4` or `Dhcpv6` layer under the right IP/UDP envelope, compile bytes,
decode fixtures, inspect `summary()`/`show()`, and keep live network I/O behind
explicit dry-run-to-live workflow gates. DHCPv6 live validation belongs in the
provider-backed lab, oracle, and probe workflows under `docs/operations/`,
where artifacts and teardown are part of the run.

## TCP Options Snippet

The `tcp_options` example builds IPv4 TCP segments carrying the common typed
options (MSS, Window Scale, SACK Permitted, Timestamps), SACK blocks, and
Fast Open, then decodes each one and prints `summary()`, `show()`, and
`hexdump()`. It stays offline: it ends with a `send_dry_run` plan over the
documentation interface `dry-run0` instead of opening a live socket.

```sh
cargo build -p crafter --example tcp_options
cargo run -p crafter --example tcp_options
```

```rust
use crafter::prelude::*;

fn main() -> crafter::Result<()> {
    let tcp = Tcp::new()
        .sport(41000)
        .dport(443)
        .seq(1)
        .flags(TCP_FLAG_SYN)
        .tcp_option(TcpOption::mss(1460))?
        .tcp_option(TcpOption::window_scale(7))?
        .tcp_option(TcpOption::sack_permitted())?
        .tcp_option(TcpOption::timestamp(0x1020_3040, 0))?;

    let packet = Ipv4::new().src("192.0.2.10")?.dst("198.51.100.20")? / tcp;

    let bytes = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;
    println!("{}", decoded.summary());
    println!("{}", decoded.show());
    Ok(())
}
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
tools/oracle/run offline --profile smoke --seed 9868 --count 20 --family udp --out target/oracle/udp-options-example-offline
```

Examples are safe by default. Live-capable examples require `--live` and
`--i-understand-isolated-lab` before opening live send or capture handles, and
should run only inside disposable wire endpoints.
