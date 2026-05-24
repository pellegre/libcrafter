# Crafter Examples

This directory is being curated into a teaching suite for the public `crafter`
crate. The final inventory is grouped by workflow below. Examples listed under
"Runnable now" already use their final names; entries listed as planned are not
documented as commands yet.

## Safety Modes

- Offline examples build, decode, inspect, read, or write generated data without
  opening live network handles.
- Dry-run examples create send plans and reports without transmitting packets by
  default.
- Live-gated examples will require `--live`, `--i-understand-isolated-lab`, and
  `LIBCRAFTER_LIVE_LAB=1` before opening live send or capture handles.

## Core Packet Model

| Example | Safety mode | Command |
| --- | --- | --- |
| `hello_world` | Offline | `cargo run -p crafter --example hello_world` |
| `packet_building` | Offline | `cargo run -p crafter --example packet_building` |
| `packet_inspection` | Offline | `cargo run -p crafter --example packet_inspection` |
| `decode_bytes` | Offline | `cargo run -p crafter --example decode_bytes` |
| `custom_registry` | Offline | `cargo run -p crafter --example custom_registry` |

## Net Workflows

| Example | Safety mode | Command |
| --- | --- | --- |
| `send_plan` | Dry-run | `cargo run -p crafter --example send_plan` |
| `send_packet` | Dry-run by default, live-gated with `--live` | `cargo run -p crafter --example send_packet` |
| `send_recv_icmp` | Dry-run | `cargo run -p crafter --example send_recv_icmp` |
| `reply_matching` | Offline | `cargo run -p crafter --example reply_matching` |
| `batch_send` | Dry-run | `cargo run -p crafter --example batch_send` |
| `batch_send_recv` | Dry-run | `cargo run -p crafter --example batch_send_recv` |
| `interface_helpers` | Offline | `cargo run -p crafter --example interface_helpers` |
| `ip_ranges` | Offline | `cargo run -p crafter --example ip_ranges` |

`send_packet --live` is available only after `--i-understand-isolated-lab` and
`LIBCRAFTER_LIVE_LAB=1` are supplied. The default command never transmits
traffic.

## Pcap And Sniffing

| Example | Safety mode | Command |
| --- | --- | --- |
| `pcap_write` | Offline | `cargo run -p crafter --example pcap_write -- --out target/examples/pcap-write.pcap --count 3` |
| `pcap_read` | Offline | `cargo run -p crafter --example pcap_read -- --in target/examples/pcap-write.pcap --filter tcp` |
| `sniffer_offline` | Offline | `cargo run -p crafter --example sniffer_offline -- --pcap target/examples/pcap-write.pcap --filter tcp --count 2` |
| `capture_pcap` | Live-gated; prints a plan by default | `cargo run -p crafter --example capture_pcap -- --iface dry-run0 --out target/examples/capture-plan.pcap --count 1` |

`capture_pcap.rs` opens a live capture handle only when `--live`,
`--i-understand-isolated-lab`, and `LIBCRAFTER_LIVE_LAB=1` are all supplied.
The documented command prints the planned interface, filter, count, timeout, and
output path without capturing traffic.

## Protocols

| Example | Safety mode | Command |
| --- | --- | --- |
| `arp_who_has` | Dry-run | `cargo run -p crafter --example arp_who_has` |
| `dns_query` | Dry-run send/receive plus offline decode | `cargo run -p crafter --example dns_query -- --name example.com` |
| `dhcp_discover` | Dry-run by default, live-gated with `--live` | `cargo run -p crafter --example dhcp_discover` |
| `icmpv6_echo` | Offline by default, dry-run send/receive with `--send-recv` | `cargo run -p crafter --example icmpv6_echo` |
| `vlan` | Offline | `cargo run -p crafter --example vlan` |
| `linux_sll` | Offline | `cargo run -p crafter --example linux_sll` |
| `null_loopback` | Offline | `cargo run -p crafter --example null_loopback` |
| `ipv4_options` | Offline | `cargo run -p crafter --example ipv4_options` |
| `tcp_options` | Offline | `cargo run -p crafter --example tcp_options` |
| `ipv6_extensions` | Offline | `cargo run -p crafter --example ipv6_extensions` |

`dhcp_discover --live` is available only after
`--i-understand-isolated-lab` and `LIBCRAFTER_LIVE_LAB=1` are supplied. The
documented command never transmits traffic. `arp_who_has` always shows a
link-layer dry-run plan and never attempts MAC discovery.
`icmpv6_echo --send-recv` uses a dry-run `SendRecv` report only; it does not
offer live mode.
