# Supported Platforms And Known Gaps

This page describes the first Rust alpha support matrix. The only public crate
is `crafter`; APIs may change before a stable release.

## Supported Rust Toolchain

- Rust 1.78 or newer.
- Cargo workspace builds with edition 2021.
- Local static tests do not require root privileges.

## Local Offline Support

The following workflows are intended to work on common Linux and macOS
developer environments without live traffic:

- Packet construction and decode tests through `crafter::core`.
- Classic pcap read/write and libpcap-backed filtering through
  `crafter::pcap`.
- Example builds and dry-run example execution.
- Malformed input resilience and encode/decode roundtrip tests.

Windows is not a primary target for the alpha because raw socket and interface
behavior differs substantially. Pure encode/decode and pcap file code may work,
but it is not yet part of the acceptance matrix.

## Live Packet Support

Live send, capture, and send/receive workflows are developed for Linux
disposable wire endpoints. They require suitable privileges on the endpoint and
may depend on reference packet tooling and basic networking tools installed on
the wire endpoint.

Live raw-packet tests must not run on a developer workstation by default. Use:

```sh
tools/wire/run doctor --provider hetzner --exposure wan --dry-run
tools/oracle/run live --provider hetzner --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider hetzner --dry-run --profile smoke --seed 1 --count 10
```

For provider-backed runs, configure credentials outside the repository. The
Hetzner wire provider reads `HETZNER_API_TOKEN` or `HCLOUD_TOKEN` from the
process environment.

## Known Protocol Coverage Gaps

- The crate is not a general-purpose dissector catalogue.
- No interactive REPL, packet expression language, or dynamic Python-style field
  mutation model is included.
- DNS encoding does not emit compression, although decoding handles compressed
  names safely.
- pcapng, full libpcap BPF grammar support, TCP stream reassembly, IP
  fragmentation reassembly, and broad application protocol coverage are future
  work.
- The public API prefers explicit builders and typed errors so generated Rust
  tools can be compiled and audited.

## Release Boundaries

The alpha is suitable for:

- Generating small packet tools from documented examples.
- Building deterministic fixtures.
- Decoding and inspecting supported packet families.
- Offline pcap workflows.
- Disposable wire endpoint validation.

The alpha is not suitable for:

- Running unreviewed traffic-changing tools on shared networks.
- Replacing a full packet analyzer.
- Acting as a production TCP/IP stack.
- Publishing provider credentials or wire endpoint state.
