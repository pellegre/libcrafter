# Crafter Examples

This directory is the authoritative map of the user-facing `crafter` examples.
Every example uses only public APIs from the `crafter` crate, with
`crafter::prelude::*` used unless a narrower import keeps the example clearer.

## Safety Legend

- Offline: builds, decodes, inspects, reads, or writes generated data without
  opening live network handles.
- Dry-run: builds send or send/receive plans and reports without transmitting
  packets.
- Live-gated: defaults to a safe plan or dry-run and opens live send or capture
  handles only after the wire endpoint guard is satisfied.

| example | area | safety mode | what it demonstrates | command |
| --- | --- | --- | --- | --- |
| `hello_world` | Core packet model | Offline | IPv4, ICMP, Raw construction, compile, summary, and hexdump output. | `cargo run -p crafter --example hello_world` |
| `packet_building` | Core packet model | Offline | Builder-style packet composition, typed field setting, and deterministic compile output. | `cargo run -p crafter --example packet_building` |
| `packet_inspection` | Core packet model | Offline | Typed layer access, mutation before compile, packet summaries, and detailed inspection output. | `cargo run -p crafter --example packet_inspection` |
| `decode_bytes` | Core packet model | Offline | Decode from link, network, and IPv4 entry points while preserving raw payloads. | `cargo run -p crafter --example decode_bytes` |
| `custom_registry` | Core packet model | Offline | Protocol registry customization and default decode comparison. | `cargo run -p crafter --example custom_registry` |
| `send_plan` | Net workflows | Dry-run | Network-layer send planning, compiled bytes, targets, and derived reply filters. | `cargo run -p crafter --example send_plan` |
| `send_packet` | Net workflows | Dry-run by default; live-gated with `--live` | Network-layer and link-layer send reports using dry-run options by default. | `cargo run -p crafter --example send_packet` |
| `send_recv_icmp` | Net workflows | Dry-run | ICMP send/receive configuration, retry timing, filters, and dry-run reports. | `cargo run -p crafter --example send_recv_icmp` |
| `network_ping` | Net workflows | Dry-run by default; live-gated with `--live` | Network-layer ICMP echo send/receive for disposable wire endpoint smoke tests. | `cargo run -p crafter --example network_ping` |
| `reply_matching` | Net workflows | Offline | Synthetic request/reply matching and generated reply filters. | `cargo run -p crafter --example reply_matching` |
| `batch_send` | Net workflows | Dry-run | Positional batch send reports for multiple TCP packets. | `cargo run -p crafter --example batch_send` |
| `batch_send_recv` | Net workflows | Dry-run | Batch send/receive reports across IPv4 and IPv6 requests. | `cargo run -p crafter --example batch_send_recv` |
| `interface_helpers` | Net workflows | Offline | Documentation-safe interface metadata and address helper output. | `cargo run -p crafter --example interface_helpers` |
| `ip_ranges` | Net workflows | Offline | IPv4 CIDR, range, and list parsing. | `cargo run -p crafter --example ip_ranges` |
| `pcap_write` | Pcap and sniffing | Offline | Generated Ethernet/IPv4/TCP packets written to a pcap file. | `cargo run -p crafter --example pcap_write` |
| `pcap_read` | Pcap and sniffing | Offline | Pcap metadata inspection, packet collection, and streaming `PcapReader` workflows. | `cargo run -p crafter --example pcap_read` |
| `sniffer_offline` | Pcap and sniffing | Offline | Offline `Sniffer` filtering and bounded packet iteration. | `cargo run -p crafter --example sniffer_offline` |
| `capture_pcap` | Pcap and sniffing | Live-gated; plan by default | Bounded libpcap capture configuration and pcap writing on an isolated wire endpoint. | `cargo run -p crafter --example capture_pcap` |
| `arp_who_has` | Protocols | Dry-run | Explicit Ethernet broadcast ARP who-has construction from known MAC and IPv4 values. | `cargo run -p crafter --example arp_who_has` |
| `dns_query` | Protocols | Dry-run send/receive plus offline decode | DNS query construction, dry-run send/receive reporting, and synthetic response decoding. | `cargo run -p crafter --example dns_query -- --name example.com` |
| `dhcp_discover` | Protocols | Dry-run by default; live-gated with `--live` | DHCP discover construction with an explicit client MAC and link-layer send options. | `cargo run -p crafter --example dhcp_discover` |
| `dhcp_option82` | Protocols | Offline | DHCP relay agent information (option 82), classless static routes, and option overload construction and offline decode. | `cargo run -p crafter --example dhcp_option82` |
| `dhcp_leasequery` | Protocols | Offline | DHCP leasequery, typed client identifier, authentication, and status/state packet-field construction and offline decode. | `cargo run -p crafter --example dhcp_leasequery` |
| `icmpv6_echo` | Protocols | Offline by default; dry-run with `--send-recv` | IPv6 ICMPv6 echo construction and optional dry-run send/receive reporting. | `cargo run -p crafter --example icmpv6_echo` |
| `vlan` | Protocols | Offline | 802.1Q VLAN frame construction, compile, and decode. | `cargo run -p crafter --example vlan` |
| `linux_sll` | Protocols | Offline | Linux cooked capture packet construction, compile, and decode. | `cargo run -p crafter --example linux_sll` |
| `null_loopback` | Protocols | Offline | BSD null/loopback link-layer packet construction, compile, and decode. | `cargo run -p crafter --example null_loopback` |
| `ipv4_options` | Protocols | Offline | IPv4 option builders with checksum and length auto-fill. | `cargo run -p crafter --example ipv4_options` |
| `tcp_options` | Protocols | Offline | TCP option builders, option ordering, and header-length auto-fill. | `cargo run -p crafter --example tcp_options` |
| `ipv6_extensions` | Protocols | Offline | IPv6 routing, segment-routing, and fragment extension header decoding. | `cargo run -p crafter --example ipv6_extensions` |

Live-gated examples require all three opt-ins before opening live sockets or
capture handles: `--live`, `--i-understand-isolated-lab`, and
`LIBCRAFTER_WIRE_ENDPOINT=1`.
