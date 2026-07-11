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

Keep QUIC validation offline by default:

- Golden byte fixtures for packet, frame, and transport-parameter round trips.
- Malformed decode fixtures that check structured `CrafterError` values.
- Pcap fixtures and oracle/probe dry-run plans before any provider-backed live
  work.

The focused probe profile is `quic-smoke`. It includes one live-capable case,
`quic-initial-udp-observation`, which builds an IPv4/UDP/QUIC datagram through
the Rust stimulus adapter and targets a controlled UDP echo service on port
4433. The Version Negotiation, Retry, stateless reset, and protected-flow cases
are planned-only; they record target requirements and packet bytes without
claiming state-machine behavior.

```sh
tools/probe/run --provider qemu --dry-run --profile quic-smoke --seed 1 --count 5 --out target/probe/quic-smoke-dry-run
tools/lab/run plan --provider qemu --dry-run --profile quic-smoke --seed 1 --role stimulus --role target --json
```

Live QUIC traffic is not a default guide path. Use provider-backed lab sessions
and explicit dry-run plans before any authorized live validation. A live run must
use `--confirm-live-run`, disposable endpoints, captured artifacts under
`target/`, and teardown.
