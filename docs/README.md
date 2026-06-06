# Documentation

This directory contains user and contributor documentation for the Rust
`crafter` crate and its validation workflow.

- [API guide](api.md) summarizes the public crate, explicit IPv4/IPv6 packet
  APIs, packet composition style, packet I/O, and helper APIs.
- [Wire packet I/O](wire.md) covers `crafter::wire`, `PacketWire`,
  `PacketRecord` metadata, `Sniffer`, `Transmitter`, and transform chains.
- [IPv4 wire coverage](ipv4.md) describes IPv4 construction, DSCP/ECN,
  protocol-number labels, checksum status, typed options, fragment fields
  without reassembly, decode policy, and validation coverage, and links the
  source-backed [IPv4 RFC manifest](ipv4-rfc-manifest.md).
- [DNS wire coverage](dns.md) describes the supported DNS wire-message
  primitives, planned typed records, and known deferrals.
- [TCP wire coverage](tcp.md) describes the supported TCP segment construction,
  typed options, checksums, decode, inspection, and sizing helpers, and links
  the source-backed [TCP RFC manifest](tcp-rfc-manifest.md).
- [IPv6 wire coverage](ipv6.md) describes the supported IPv6 base and extension
  headers, source-backed manifests, offline fixtures, and oracle coverage.
- [Dot11 wire coverage](dot11.md) describes bare IEEE 802.11, radiotap,
  LLC/SNAP, EAPOL, RSN foundations, pcap link types, and the current dry-run
  and manual live testing boundary.
- [ICMPv6 message coverage](icmpv6-coverage.md) lists the typed ICMPv6 message
  families and the deferred codepoints (Router Renumbering, Inverse Neighbor
  Discovery) preserved as unknown/`Raw`, with RFC references and reasons.
- [ICMPv6 / NDP validation report](validation/icmpv6-ndp-report.md) records the
  final validation run for the ICMPv6 / Neighbor Discovery effort: the gate,
  tests, oracle, interop, provider dry-run matrix, and the QEMU / VirtualBox
  live-run outcomes including the NDP hop-limit-255 defect found and fixed.
- [Examples](examples.md) explains how to build and run the Rust examples.
- [Oracle validation](validation.md) describes corpus, offline, pcap, and
  provider-backed reference validation.
- [Probe validation](probe.md) describes kernel and service behavior probes.
- [Lab sessions](lab.md) describes provider-backed multi-endpoint sessions used
  by oracle and probe.
- [Endpoint provider guide](endpoint.md) covers shared disposable endpoint
  provider setup, credentials, artifacts, and cleanup for one endpoint.
Agent operating guidance belongs under
[`.agents/docs/cookbook.md`](../.agents/docs/cookbook.md), not here.
