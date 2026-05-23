# Changelog

## 0.1.0-alpha.1 - Rust Packet Crafting Alpha

This is the first public alpha of the Rust packet crafting workspace, centered
on the facade crate `crafter` and its supporting crates.

### Added

- Layer-based packet construction with `Packet::new().push(...)` and `/`
  composition.
- Auto-filled lengths, protocol numbers, header lengths, and checksums while
  preserving explicitly set field values.
- Decode entrypoints for Ethernet, Linux cooked capture, null/loopback, raw
  IPv4, and raw IPv6 inputs.
- Protocol coverage for Ethernet, VLAN, ARP, IPv4, IPv4 options, IPv6, selected
  IPv6 extension headers, TCP, TCP options, UDP, ICMP, ICMPv6, DNS, DHCP, and
  raw payloads.
- Protocol registry hooks for custom link, network, transport, and application
  decode bindings.
- Classic pcap read/write helpers, libpcap BPF filters, offline
  sniffer iteration, callbacks, and background capture handles.
- Raw send planning, live send backends, send/receive matching, batch
  workflows, interface helpers, address range helpers, and ARP resolution.
- Safe-by-default Rust examples for basic, intermediate, and gated advanced
  packet workflows.
- Provider-agnostic disposable live-lab tooling with local dry-run and Hetzner
  providers.
- Reference fixture harnesses, malformed decode corpus, property tests,
  and GitHub Actions workflows.

### Known Gaps

- The Rust API is alpha and may change before a stable release.
- The decoder is intentionally smaller than a full packet analyzer and focuses
  on the current example surface.
- TCP stream reassembly, packet fragmentation/reassembly, full pcapng support,
  full BPF parsing, and full TCP/IP stack behavior are not included.
- DNS encoding is deterministic and uncompressed; DNS decoding accepts
  compressed names.
- Live packet sends and captures require platform privileges and should run only
  inside disposable live labs.

### Safety

- Local tests and examples are dry-run or offline by default.
- Advanced examples require `--live`, `--i-understand-isolated-lab`, and
  `LIBCRAFTER_LIVE_LAB=1` before traffic-changing behavior.
- Provider credentials are read from environment variables or ignored local
  config files and must not be committed.
