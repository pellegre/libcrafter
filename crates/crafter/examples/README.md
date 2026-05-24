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

Planned: `send_plan.rs`, `send_packet.rs`, `send_recv_icmp.rs`,
`reply_matching.rs`, `batch_send.rs`, `batch_send_recv.rs`,
`interface_helpers.rs`, and `ip_ranges.rs`.

The send and send/receive examples will default to dry-run mode on `dry-run0`.
Any live mode will be gated by the live-lab acknowledgement and environment
marker.

## Pcap And Sniffing

Planned: `pcap_write.rs`, `pcap_read.rs`, `sniffer_offline.rs`, and
`capture_pcap.rs`.

The pcap write/read and offline sniffer examples will use generated pcap files
under `target/`. The capture example will be live-gated before it is documented
as a runnable command in this suite.

## Protocols

Runnable now:

| Example | Safety mode | Command |
| --- | --- | --- |
| `dns_query` | Dry-run by default | `cargo run -p crafter --example dns_query` |
| `tcp_options` | Offline | `cargo run -p crafter --example tcp_options` |

Planned: `arp_who_has.rs`, `dhcp_discover.rs`, `icmpv6_echo.rs`, `vlan.rs`,
`linux_sll.rs`, `null_loopback.rs`, `ipv4_options.rs`, and
`ipv6_extensions.rs`.
