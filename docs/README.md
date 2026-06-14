# Documentation

This directory contains user and contributor documentation for the Rust
`crafter` crate and its validation workflow. It is organized into role-based
areas so end-user material stays separate from maintainer and agent artifacts:

- **[`guide/`](guide/)** — per-protocol wire coverage for everyday packet work.
- **[`reference/`](reference/)** — the API surface, the wire I/O layer, and how
  to run the bundled examples.
- **[`operations/`](operations/)** — live, provider-backed, and manual testing
  workflows (validation, probes, lab sessions, endpoints).
- **[`internal/`](internal/)** — maintainer/agent material: RFC manifests,
  implementation and API inventories, source manifests, and validation reports.

## Guides

Per-protocol wire coverage for building and decoding packets.

- [IPv4 wire coverage](guide/ipv4.md) — IPv4 construction, DSCP/ECN,
  protocol-number labels, checksum status, typed options, fragment fields
  without reassembly, decode policy, and validation coverage.
- [IPv6 wire coverage](guide/ipv6.md) — IPv6 base and extension headers,
  source-backed manifests, offline fixtures, and oracle coverage.
- [TCP wire coverage](guide/tcp.md) — TCP segment construction, typed options,
  checksums, decode, inspection, and sizing helpers.
- [DNS wire coverage](guide/dns.md) — supported DNS wire-message primitives,
  planned typed records, and known deferrals.
- [BGP wire coverage](guide/bgp.md) — BGP message construction, UPDATE path
  attributes, MP-BGP, TCP/179 decode dispatch, and the offline/live surfaces.
- [Dot11 wire coverage](guide/dot11.md) — bare IEEE 802.11, radiotap, LLC/SNAP,
  EAPOL, RSN foundations, pcap link types, and the dry-run/manual live boundary.
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

- [Oracle validation](operations/validation.md) — corpus, offline, pcap, and
  provider-backed reference validation.
- [Probe validation](operations/probe.md) — kernel and service behavior probes.
- [Lab sessions](operations/lab.md) — provider-backed multi-endpoint sessions
  used by oracle and probe.
- [Endpoint provider guide](operations/endpoint.md) — shared disposable endpoint
  provider setup, credentials, artifacts, and cleanup for one endpoint.
- [Dot11 live manual](operations/dot11-live-manual.md) — manual procedure for
  the IEEE 802.11 live testing boundary.

## Internal / maintainer

Maintainer and agent material. These documents back the guides above with
source evidence and validation history; they are not user-facing.

- [`internal/manifests/`](internal/manifests/) — source-backed RFC manifests and
  coverage checklists (IPv4, IPv6, TCP, UDP, IPsec, ARP, ICMPv6).
- [`internal/inventories/`](internal/inventories/) — implementation and API
  inventories (IPv4, IPv6, TCP, wire, Dot11).
- [`internal/source/`](internal/source/) — protocol source manifests (Dot11,
  IP fragment, WPA decryptor).
- [`internal/validation/`](internal/validation/) — validation reports, including
  the [ICMPv6 / NDP validation report](internal/validation/icmpv6-ndp-report.md).

Agent operating guidance belongs under
[`.agents/docs/cookbook.md`](../.agents/docs/cookbook.md), not here.
