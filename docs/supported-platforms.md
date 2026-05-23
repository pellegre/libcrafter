# Supported Platforms And Known Gaps

This page describes the first Rust alpha. The legacy C++ library remains in the
repository and has its own build expectations.

## Supported Rust Toolchain

- Rust 1.78 or newer.
- Cargo workspace builds with edition 2021.
- Local static tests do not require root privileges.

## Local Offline Support

The following workflows are intended to work on common Linux and macOS
developer environments without live traffic:

- Packet construction and decode tests in `crafter-core`.
- Classic pcap read/write and deterministic offline filtering in
  `crafter-pcap`.
- Example builds and dry-run example execution.
- Malformed input resilience and encode/decode roundtrip tests.

Windows is not a primary target for the alpha because raw socket and interface
behavior differs substantially. Pure encode/decode and pcap file code may work,
but it is not yet part of the acceptance matrix.

## Live Packet Support

Live send, capture, ARP resolution, and send/receive workflows are developed for
Linux disposable labs. They require suitable privileges inside the lab and may
depend on `tcpdump`, Scapy, Docker, and basic networking tools installed by the
live-lab image.

Live raw-packet tests must not run on a developer workstation by default. Use:

```sh
tools/live-lab/libcrafter-live-lab doctor --provider local-dry-run
tools/live-lab/libcrafter-live-lab run --provider local-dry-run --suite all
```

For provider-backed runs, configure credentials outside the repository. The
Hetzner provider reads only the `HETZNER_API_TOKEN` variable or the ignored
local env file described in `docs/live-lab.md`.

## Known Gaps Versus Legacy Libcrafter

- The Rust API is not source-compatible with the C++ API.
- Threading is expressed through Rust handles and bounded capture helpers rather
  than the legacy callback classes.
  disposable lab templates; they do not mutate host firewall or forwarding
  state.
- Route discovery uses interface hints and address tables rather than a full
  platform route parser.
- Live L2 sending focuses on Ethernet frames. Linux cooked and null/loopback
  live sends are rejected explicitly.

## Known Gaps Versus Scapy

- The crate is not a general-purpose dissector catalogue.
- No interactive REPL, packet expression language, or dynamic Python-style field
  mutation model is included.
- DNS encoding does not emit compression, although decoding handles compressed
  names correctly.
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
- Disposable-lab live validation.

The alpha is not suitable for:

- Running unreviewed traffic-changing tools on shared networks.
- Replacing a full packet analyzer.
- Acting as a production TCP/IP stack.
- Publishing provider credentials or live-lab state.
