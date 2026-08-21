# QUIC Guide

`crafter` exposes QUIC as a packet primitive: build, compile, decode, inspect,
and preserve QUIC UDP datagrams, packets, headers, frames, transport
parameters, and protected payload bytes inside the existing `Packet`
abstraction.

It is not a QUIC endpoint stack. There is no connection state machine, loss
recovery, congestion controller, TLS transcript engine, stream reassembler, or
application protocol implementation in this crate.

The optional `quic-endpoint` feature belongs to the separate `crafter-flow`
tool, not to the public packet crate. Its bounded `quic_client_flow` and
`quic_server_flow` entrypoints delegate TLS, packet numbers, recovery,
congestion, and one opaque request/response stream to a private socket-free
provider. Provider transmits return through typed `Ipv4 / Udp / Quic::raw`
packets, while generic short-header ingress remains `Raw` until interpreted by
connection-aware provider state. See the
[crafter-flow QUIC guide](../../tools/flow/docs/quic-flow.md) for configuration,
state graphs, reports, non-goals, and its dry-run-first disposable-provider
safety contract.

## Packet Primitive Scope

Use QUIC support when a tool needs packet-layer bytes:

- Version-independent and v1/v2 long-header packet shapes.
- Version Negotiation, Retry, Initial, Handshake, 0-RTT, and short-header byte
  construction or inspection.
- QUIC frame parse/serialize helpers where frame boundaries are source-backed.
- Transport-parameter tuple helpers, including extension parameters selected by
  the source-backed plan.
- Raw preservation for encrypted payloads, unknown versions, unsupported
  frames, and caller-pinned malformed fields.

Normal packet composition stays the same:

```rust
use crafter::prelude::*;

let stream = QuicFrame::stream(QuicVarInt::from_u64_unchecked(0), b"opaque stream bytes")?;
let initial = QuicLongHeaderPacket::initial_builder()
    .packet_number(QuicPacketNumber::new(1))
    .frames([stream])
    .build()?;
let packet = Ipv4::new()
    / Udp::new().sport(49152).dport(4433)
    / Quic::new().packet(QuicPacket::from_long_header(initial));

let bytes = packet.compile()?;
println!("{}", bytes.hexdump());
# Ok::<(), crafter::CrafterError>(())
```

## HTTP/3 And QPACK Boundary

HTTP/3, QPACK, MASQUE, DNS-over-QUIC, and other application protocols are above
the QUIC packet primitive:

- RFC 9114 maps HTTP semantics onto QUIC streams; it is not QUIC packet
  construction or decode.
- RFC 9204 defines QPACK header compression for HTTP/3; it is not a packet or
  frame grammar used by QUIC itself.
- MASQUE and HTTP datagram documents define application proxy workflows; QUIC
  DATAGRAM frame bytes come from the QUIC DATAGRAM extension, not from MASQUE.
- DNS-over-QUIC error codes can be recorded as codepoints, but DoQ client or
  server behavior is not part of this crate.

When a generated tool experiments above QUIC, keep application bytes opaque.
Use `Raw` for uninterpreted payloads or QUIC STREAM/DATAGRAM frame data for
explicit packet fixtures. A generated HTTP/3 or QPACK parser should live in the
tool that needs it, with its own tests and source manifest.

## Validation

Use the tracked deterministic validation surfaces first:

```sh
tools/oracle/run offline --profile smoke --seed 1 --count 10
tools/oracle/run pcap --profile smoke --seed 1 --count 10
tools/probe/run --profile smoke --seed 1 --count 10 --out target/probe/plan
```

These commands do not select infrastructure or send packets. Any authorized use
of concrete interfaces, peers, radios, or targets is owned by external operator
tooling, which supplies runtime inputs and collects artifacts. libcrafter does
not provision machines, configure responders, manage credentials, or perform
remote cleanup.

The focused deterministic probe profile is `quic-smoke`.
