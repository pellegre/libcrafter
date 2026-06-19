# Changelog

## 0.3.0 - Packet-Level Network Interaction

This is the first public release of the Rust packet-level network interaction
workspace, released as one public crate: `crafter`.

### Added

- Layer-based packet construction with `Packet::new().push(...)` and `/`
  composition.
- Auto-filled lengths, protocol numbers, header lengths, and checksums while
  preserving explicitly set field values.
- Decode entrypoints for Ethernet, Linux cooked capture, null/loopback, raw
  IPv4, and raw IPv6 inputs.
- Link-layer coverage for Ethernet, 802.1Q VLAN, Linux cooked capture,
  null/loopback, IEEE 802.11 (management, control, and data frames) with
  radiotap and LLC/SNAP, and EAPOL/RSN (802.11i) key-exchange fields.
- Network and control coverage for ARP, IPv4 (DSCP/ECN, typed options,
  checksum status, and fragment fields), IPv6 with hop-by-hop, destination,
  fragment, routing, mobile-routing, and segment-routing extension headers,
  ICMPv4 (with the `Icmp` deprecated alias), ICMP extensions (RFC 4884), and
  ICMPv6 including Neighbor Discovery (RFC 4861), Multicast Listener Discovery
  v1/v2, Extended Echo, and experimental Node Information.
- Transport coverage for TCP with options and UDP with options and checksum
  status.
- Application and payload coverage for DNS (EDNS(0), SVCB/HTTPS, and DNSSEC
  record types), DHCPv4 (option overload, RFC 3396 long options, relay agent
  option 82, client identifiers, authentication, and leasequery fields), BGP
  (OPEN, UPDATE, KEEPALIVE, NOTIFICATION, ROUTE-REFRESH, path attributes, and
  capabilities), and raw payloads.
- IPsec coverage for ESP, AH, and IKEv2 (IKE header and payload set) with
  security-association and transform primitives.
- Routing coverage for OSPFv2 (IP protocol 89) as a wire-level primitive: the
  five packet types (Hello, Database Description, Link State Request, Link State
  Update, Link State Acknowledgment) over one shared common header with
  auto-filled packet length and checksum; the link-state advertisement family
  (Router, Network, Summary, AS-External, NSSA, and Opaque types 9/10/11
  including TE and Router Information) with the auto-filled Fletcher LSA
  checksum; authentication (null, simple password, keyed-MD5, and HMAC-SHA
  cryptographic) with the matching checksum and digest-trailer semantics;
  structured-error decode that preserves unknown packet/LSA/opaque types as raw
  and surfaces truncated buffers as typed errors; and an OSPFv3 base layer (RFC
  5340 common header with Hello and request/update/ack framing). No OSPF state
  machine, SPF computation, or LSDB management is included. The work ships with
  oracle layer/feature/malformed specs, gated dry-run-default live and probe
  coverage, and the `docs/guide/ospf.md` guide.
- Protocol registry hooks for custom link, network, transport, and application
  decode bindings.
- Classic pcap read/write helpers, libpcap BPF filters, offline
  sniffer iteration, callbacks, and background capture handles.
- Raw send planning, live send backends, send/receive matching, batch
  workflows, interface helpers, address range helpers, and ARP resolution.
- Monitor-mode radiotap Wi-Fi injection: `Radiotap / Dot11` frames now
  transmit on a monitor-mode interface through the live send API, with the
  `Radiotap::monitor_tx` TX-header convenience, named `RadiotapTxFlags`
  constants (`NO_ACK`, `NO_SEQ`, `FIXED_RATE`, `ORDER`, `NO_REORDER`), and the
  `RadiotapChannel::channel_2ghz` channel-number helper. Putting the interface
  into monitor mode (channel and regulatory domain) stays an operator
  prerequisite, and live transmission keeps the existing `--live`,
  `--i-understand-isolated-lab`, and `LIBCRAFTER_ENDPOINT=1` gates.
- Transmit-side IP fragmentation (`IpFragment`) and receive-side IP reassembly
  (`IpDefrag`) as explicit `wire` transforms with configurable limits and
  statistics.
- Receive-side WPA2 CCMP decryption (`WpaDecrypt`) as an explicit `wire`
  transform driven by captured EAPOL key exchanges.
- Safe-by-default Rust examples for basic, intermediate, and gated advanced
  packet workflows.
- Provider-agnostic wire endpoint tooling with local dry-run and Hetzner
  providers for endpoint-backed packet workflows.
- Reference fixture harnesses, malformed decode corpus, property tests,
  and GitHub Actions workflows.

### Known Boundaries

- The 0.x Rust API may evolve as protocol and wire workflow coverage grows.
- The decoder is intentionally smaller than a full packet analyzer and focuses
  on the current example surface.
- TCP stream reassembly, full pcapng support, full BPF parsing, and full
  TCP/IP stack behavior are not included. IP fragmentation and reassembly are
  available as explicit `IpFragment`/`IpDefrag` wire transforms, not as
  automatic decode-time behavior.
- DNS encoding is deterministic and uncompressed; DNS decoding accepts
  compressed names.
- Live packet sends and captures require platform privileges and should run only
  in authorized wire environments.
- QEMU and VirtualBox wire providers are not included in 0.3.0.

### Safety

- Local tests and examples are dry-run or offline by default.
- Advanced examples require `--live`, `--i-understand-isolated-lab`, and
  `LIBCRAFTER_ENDPOINT=1` before traffic-changing behavior.
- Provider credentials are read from environment variables or ignored local
  config files and must not be committed.
