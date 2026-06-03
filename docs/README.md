# Documentation

This directory contains user and contributor documentation for the Rust
`crafter` crate and its validation workflow.

- [API guide](api.md) summarizes the public crate, modules, packet composition
  style, and helper APIs.
- [DNS wire coverage](dns.md) describes the supported DNS wire-message
  primitives, planned typed records, and known deferrals.
- [TCP wire coverage](tcp.md) describes the supported TCP segment construction,
  typed options, checksums, decode, inspection, and sizing helpers, and links
  the source-backed [TCP RFC manifest](tcp-rfc-manifest.md).
- [ICMPv6 message coverage](icmpv6-coverage.md) lists the typed ICMPv6 message
  families and the deferred codepoints (Router Renumbering, Inverse Neighbor
  Discovery) preserved as unknown/`Raw`, with RFC references and reasons.
- [ICMPv6 / NDP validation report](validation/icmpv6-ndp-report.md) records the
  final validation run for the ICMPv6 / Neighbor Discovery effort: the gate,
  tests, oracle, interop, provider dry-run matrix, and the QEMU / VirtualBox
  live-run outcomes including the NDP hop-limit-255 defect found and fixed.
- [Examples](examples.md) explains how to build and run the Rust examples.
- [Oracle validation](validation.md) describes corpus, offline, pcap, and wire
  reference validation.
- [Probe validation](probe.md) describes kernel and service behavior probes.
- [Lab sessions](lab.md) describes provider-backed multi-endpoint sessions used
  by oracle and probe.
- [Wire endpoint provider guide](wire.md) covers shared disposable provider setup,
  credentials, artifacts, and cleanup for one endpoint.
Agent operating guidance belongs under
[`.agents/docs/cookbook.md`](../.agents/docs/cookbook.md), not here.
