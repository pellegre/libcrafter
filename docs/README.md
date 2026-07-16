# Documentation

This directory contains user and contributor documentation for the Rust
`crafter` crate and its validation workflow. It is organized into role-based
areas:

- **[`guide/`](guide/)** — per-protocol wire coverage for everyday packet work,
  each with the explicit list of RFCs/standards the library implements.
- **[`reference/`](reference/)** — the API surface, the wire I/O layer, and how
  to run the bundled examples.
- **[`operations/`](operations/)** — live, provider-backed, and manual testing
  workflows (validation, probes, lab sessions, endpoints).

## Guides

Per-protocol wire coverage for building and decoding packets.

- [IPv4 wire coverage](guide/ipv4.md) — IPv4 construction, DSCP/ECN,
  protocol-number labels, checksum status, typed options, fragment fields
  without reassembly, decode policy, and validation coverage.
- [IGMP wire coverage](guide/igmp.md) — IPv4 packet-layer IGMP construction,
  decode, Router Alert envelope guidance, v1/v2/v3 membership packets, generic
  extensions, multicast router discovery packet shapes, and the dry-run/live
  boundary. IGMP is not a multicast router implementation or scanner.
- [IPv6 wire coverage](guide/ipv6.md) — IPv6 base and extension headers,
  source-backed manifests, offline fixtures, and oracle coverage.
- [TCP wire coverage](guide/tcp.md) — TCP segment construction, typed options,
  checksums, decode, inspection, and sizing helpers.
- [UDP wire coverage](guide/udp.md) — UDP datagram construction, length and
  checksum auto-fill, decode dispatch, and the implemented RFCs.
- [SCTP wire coverage](guide/sctp.md) — native IPv4/IPv6 SCTP, RFC 6951 UDP
  encapsulation, CRC32c status, chunk/parameter/cause preservation, pcap
  fixtures, and the dry-run/live boundary. SCTP support is not an association
  stack or socket API.
- [DHCPv4 wire coverage](guide/dhcpv4.md) — BOOTP/DHCPv4 packet construction,
  named message constructors, typed options, option overload, RFC 3396 long
  options, relay agent information (option 82), client identifiers,
  authentication, leasequery packet fields, decode, inspection, dry-run
  planning, and the provider-backed live boundary.
- [DHCPv6 wire coverage](guide/dhcpv6.md) — DHCPv6 client/server and relay
  packet construction, typed options, prefix delegation, decode, inspection,
  offline fixtures, dry-run send/receive planning, and the provider-backed live
  boundary.
- [ARP wire coverage](guide/arp.md) — ARP request/reply construction over
  Ethernet, IPv4 address resolution, decode, and the implemented RFCs.
- [ICMPv6 wire coverage](guide/icmpv6.md) — ICMPv6 error/informational messages,
  Neighbor Discovery, checksum handling, decode, and the implemented RFCs.
- [DNS wire coverage](guide/dns.md) — supported DNS wire-message primitives,
  planned typed records, and known deferrals.
- [BGP wire coverage](guide/bgp.md) — BGP message construction, UPDATE path
  attributes, MP-BGP, TCP/179 decode dispatch, and the offline/live surfaces.
- [MQTT wire coverage](guide/mqtt.md) — MQTT 3.1.1 and 5.0 control packet
  construction, properties, TCP/1883 decode dispatch, stacked payload decode,
  inspection, and the offline/live surfaces.
- [CoAP wire coverage](guide/coap.md) — CoAP datagrams and reliable frames,
  typed options and extensions, OSCORE transforms, conservative Raw fallback,
  pcap persistence, and the guarded provider-backed validation boundary.
- [SNMP wire coverage](guide/snmp.md) — SNMP BER values, VarBinds, v1/v2c
  PDUs, v3 wire framing, UDP/161 and UDP/162 decode dispatch, unknown
  preservation, pcap fixtures, and the dry-run/live-lab boundary. SNMP support
  is not a scanner, manager, agent daemon, MIB engine, credential store, or
  VACM evaluator.
- [NTP wire coverage](guide/ntp.md) — NTP fixed-header construction, UDP/123
  decode dispatch, extension fields, NTS packet extension wrappers, legacy MAC
  tails, Kiss-o'-Death labels, raw fallback, and the provider-backed live
  boundary.
- [RIP wire coverage](guide/rip.md) — RIPv1/RIPv2 and RIPng message
  construction, route entries, authentication, UDP/520 and UDP/521 decode
  dispatch, and the offline/live surfaces.
- [Dot11 wire coverage](guide/dot11.md) — bare IEEE 802.11, radiotap, LLC/SNAP,
  EAPOL, RSN foundations, pcap link types, and the dry-run/manual live boundary.
- [BLE advertising wire coverage](guide/ble.md) — BLE radio pseudo-header,
  advertising Link Layer PDUs, GAP Advertising Data structures, pcap link type,
  and the dry-run/live dongle boundary.
- [IPsec wire coverage](guide/ipsec.md) — AH/ESP construction, transforms, and
  the supported offline and live surfaces.

## Reference

The public API and wire I/O surface, plus example instructions.

- [API guide](reference/api.md) — the public crate, explicit IPv4/IPv6 packet
  APIs, packet composition style, packet I/O, and helper APIs.
- [Wire packet I/O](reference/wire.md) — `crafter::wire`, `PacketWire`,
  `PacketRecord` metadata, `Sniffer`, `Transmitter`, and transform chains.
- [Examples](reference/examples.md) — how to build and run the Rust examples.

## Operations

Live, provider-backed, and manual testing workflows.

- [Tools overview](operations/tools.md) — the endpoint/lab/oracle/probe stack,
  when to reach for each tool, and safe dry-run examples.
- [Appliance operations](operations/appliance.md) — the standard Docker
  appliance, profiles, modules, substrates, persistent assets, leases, checks,
  artifacts, dry-run defaults, and live gates.
- [Oracle validation](operations/validation.md) — corpus, offline, pcap, and
  provider-backed reference validation.
- [Probe validation](operations/probe.md) — kernel and service behavior probes.
- [Lab sessions](operations/lab.md) — provider-backed multi-endpoint sessions
  used by oracle and probe.
- [Endpoint provider guide](operations/endpoint.md) — shared disposable endpoint
  provider setup, credentials, artifacts, and cleanup for one endpoint.
- [NTP live validation](operations/ntp.md) — guarded dry-run, oracle, probe,
  endpoint, artifact, and teardown notes for NTP live validation.
- [Dot11 live manual](operations/dot11-live-manual.md) — manual procedure for
  the IEEE 802.11 live testing boundary.
- [BLE WHAD live manual](operations/ble-whad-live-manual.md) — manual procedure
  for the feature-gated WHAD dongle live testing boundary.

Agent operating guidance belongs under
[`.agents/docs/cookbook.md`](../.agents/docs/cookbook.md), not here.
