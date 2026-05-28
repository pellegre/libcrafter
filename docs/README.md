# Documentation

This directory contains user and contributor documentation for the Rust
`crafter` crate and its validation workflow.

- [API guide](api.md) summarizes the public crate, modules, packet composition
  style, and helper APIs.
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
