# QUIC Endpoint Provider Decision

This decision applies only to the private full-connection driver in
`crafter-flow`. It does not add an endpoint, TLS transcript, recovery engine,
stream implementation, or socket owner to the public `crafter` crate. Every
provider transmit remains an opaque UDP payload until the flow wraps it in the
typed `Ipv4 / Udp / Quic` packet stack.

Evidence was refreshed on 2026-07-10. Crate metadata came from the published
crate manifests and `cargo info`; API claims were checked against the published
0.11.14 and 0.22.0 sources and their versioned rustdoc. Maintained status means
that the upstream project is still publishing releases, not that every older
MSRV-compatible release receives indefinite support.

## Candidate comparison

| Gate | `quinn-proto` 0.11.14 | `quiche` 0.22.0 |
| --- | --- | --- |
| License | MIT OR Apache-2.0 | BSD-2-Clause |
| Maintained line | Quinn remains active; 0.11.14 is on the current 0.11 line. The newer 0.11.16 raises its MSRV to 1.85, so it is not eligible here. | quiche remains active, but the current 0.29.2 release requires Rust 1.88. The Rust-1.78-compatible 0.22.0 release is several minor lines behind current development. |
| Declared MSRV | Rust 1.74.1; verified below with Rust 1.78 | Rust 1.66; metadata-compatible with Rust 1.78 |
| Socket-free ingress | `Endpoint::handle(now, remote, local_ip, ecn, BytesMut, buf)` accepts a caller-owned UDP datagram. The crate describes itself as having no networking code. | `Connection::recv(buf, RecvInfo)` accepts a caller-owned UDP datagram and tuple metadata. |
| Transmit polling | `Connection::poll_transmit(now, max_datagrams, buf)` returns `Transmit`; endpoint-generated Version Negotiation, Retry, refusal, and reset responses also return `Transmit`. | `Connection::send(out)` / `send_on_path(out, from, to)` return `SendInfo`. |
| Explicit timers | `Connection::poll_timeout()` and `handle_timeout(now)` | `Connection::timeout_instant()` / `timeout()` and `on_timeout()` |
| TLS 1.3 authentication | `rustls` integration through `QuicClientConfig` and `QuicServerConfig`; custom roots, peer name, certificates, ALPN, and TLS-1.3-only conversion are exposed. | TLS is integrated through BoringSSL-compatible configuration, including peer verification, certificate/key loading, server name, and ALPN. |
| Retry and transport parameters | `Endpoint::retry`, `Incoming::may_retry`, retry token lifetime, `TransportConfig`, and peer parameter validation inside the state machine | Stateless `retry`/version-negotiation helpers, connection token handling, `Config` transport limits, and `peer_transport_params()` |
| Stream API | `streams().open/accept`, `send_stream(id).write/finish`, `recv_stream(id).read`, plus `Event::Stream` | `stream_send`, `stream_recv`, readable/writable iterators, finish flag, and stream shutdown |
| Deterministic tests | All protocol `Instant`s are supplied by the caller; endpoint RNG seeds, CID generation, server `TimeSource`, transport limits, and qlog start time are configurable. Cryptographic output is intentionally not asserted byte-for-byte. | Caller controls ingress ordering and timeout calls, but the selected release's BoringSSL build and lower-level server dispatch leave more harness policy in the adapter. |
| Fresh packet-number evidence | Optional `qlog` feature emits `PacketSent`, `PacketReceived`, and `PacketLost` events with packet numbers; a test-only in-memory writer can compare packet number/type events with captured transmit hashes. | Optional `qlog` and connection statistics can provide equivalent test evidence. |
| Platform/build profile | Pure Rust protocol state machine plus `ring` C/assembly build support; no Tokio, async runtime, UDP socket, OpenSSL installation, or platform trust store is required. | Default crypto vendors BoringSSL and has a materially larger C/C++/CMake build surface; alternate system OpenSSL setup adds platform coupling. |

Both candidates expose genuine protocol-only connection APIs and could be
adapted without giving them a UDP socket. `quinn-proto` wins because its public
`Endpoint` plus `Connection` split already matches the required driver
boundary, its current 0.11 line has an exact release that builds at the
repository MSRV, and its Rustls/ring setup avoids the older quiche release's
larger vendored BoringSSL build and maintenance gap.

## Selected provider

Select **`quinn-proto` exactly 0.11.14** with default features disabled and
features **`rustls-ring` and `qlog`** enabled:

```toml
quinn-proto = { version = "=0.11.14", default-features = false, features = ["rustls-ring", "qlog"] }
```

This dependency belongs only in `tools/flow/Cargo.toml` and must be activated
only by the flow crate's `quic-endpoint` feature. The exact pin prevents a
silent update to 0.11.16, whose declared Rust 1.85 baseline is incompatible
with this workspace's Rust 1.78 baseline. The `bloom`, `log`, platform verifier,
AWS-LC, FIPS, and post-quantum test features are not selected. Retry does not
depend on `bloom`; that feature controls reusable validation-token replay
tracking, which is outside the bounded no-resumption flow.

The selected feature set was compiled from the published crate and its locked
dependency graph with the installed Rust 1.78.0 toolchain:

```text
CARGO_TARGET_DIR=/tmp/libcrafter-quinn-proto-0.11.14-target \
  cargo +1.78.0 check --manifest-path <published-quinn-proto-0.11.14>/Cargo.toml \
  --locked --no-default-features --features rustls-ring,qlog

result: exit 0
```

This proves the selected provider feature set itself builds with Rust 1.78.
Step 03 must still resolve it in the workspace lockfile, and step 04 must prove
the exact adapter calls from `crafter-flow`; either step stops if the workspace
resolution changes this conclusion.

## Driver API map

The private flow-owned adapter should map provider calls as follows:

- Client creation: construct `EndpointConfig`, `TransportConfig`, and
  `ClientConfig`, then call `Endpoint::connect(now, config, remote, peer_name)`.
- Server ingress: call `Endpoint::handle`; accept
  `DatagramEvent::NewConnection` with `Endpoint::accept`, or exercise address
  validation with `Endpoint::retry`. Send `DatagramEvent::Response` directly as
  an ordered provider transmit.
- Existing-connection ingress: route the returned `ConnectionEvent` to
  `Connection::handle_event`. Drain `poll_endpoint_events()` back through
  `Endpoint::handle_event` until both sides are quiescent.
- Egress: repeatedly call `Connection::poll_transmit(now, 1, buf)`. A returned
  `Transmit` supplies destination, source-IP hint, ECN, size, and optional GSO
  segment size. The adapter uses `max_datagrams = 1` and disables segmentation
  offload so each ordered flow output is one unambiguous UDP datagram.
- Timers: schedule the absolute `Instant` from `poll_timeout()` and call
  `handle_timeout(now)` when due. Then drain transmits, endpoint events, and
  application events in the provider-documented order.
- Lifecycle and events: drain `Connection::poll()` for `HandshakeDataReady`,
  `Connected`, `Stream`, and `ConnectionLost`; use `is_handshaking`,
  `is_closed`, and `is_drained` only as supporting snapshots.
- Stream I/O: open or accept exactly one bidirectional stream through
  `streams().open(Dir::Bi)` / `streams().accept(Dir::Bi)`, write with
  `send_stream(id).write`, finish with `finish`, and consume ordered chunks from
  `recv_stream(id).read(true)`.
- Close: call `Connection::close(now, code, reason)` and continue the normal
  transmit/timer/event drain through closing and draining.

No provider object or secret enters `PacketContext`. The driver owns
`Endpoint`, `Connection`, their handles, TLS state, and buffers. It exports only
datagrams, deadlines, stable flow events, bounded stream bytes, counters, and a
non-secret lifecycle snapshot.

## TLS and crypto setup

`rustls-ring` selects Rustls 0.23 integration and ring. Build client trust from
caller-provided synthetic/test roots and construct a TLS-1.3 client config with
the ring `CryptoProvider`; set ALPN before converting it with
`QuicClientConfig::try_from`. Build the server config from the caller-provided
certificate chain and private key with `QuicServerConfig` (or
`ServerConfig::with_single_cert`) and the same bounded ALPN. The client always
passes the configured peer DNS name to `Endpoint::connect`, so certificate and
name validation remain enabled.

Use one explicit ring provider consistently. Prefer
`rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))`
and the corresponding server builder over relying on process-global provider
selection. Enable TLS 1.3 only, disable early data and resumption, and never use
a dangerous certificate verifier. The Initial-required
TLS13_AES_128_GCM_SHA256 suite is present in the ring provider.

Native builds require the normal Rust/C toolchain needed by ring. No OpenSSL,
BoringSSL, CMake, Tokio, async executor, system certificate store, or live UDP
socket is part of the selected configuration. WASM and FIPS targets are not in
scope for this milestone.

## License evidence

The selected crate is MIT OR Apache-2.0. A `cargo tree` plus Cargo metadata
inspection of the exact locked graph used for the Rust 1.78 check found only
permissive SPDX families: MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC,
Zlib, Unlicense, and Unicode-3.0. In particular, Rustls is
Apache-2.0 OR ISC OR MIT, ring is Apache-2.0 AND ISC, qlog is BSD-2-Clause, and
Rustls webpki is ISC. No GPL, LGPL, AGPL, MPL, or proprietary dependency was in
the selected normal/build graph.

Step 03 must preserve the exact feature set and record the workspace lockfile.
The repository release gate remains authoritative: if the workspace-resolved
graph introduces a non-permissive or unknown license, a dependency with an
MSRV above Rust 1.78, or an unsupported platform requirement, implementation
stops at that gate rather than changing the compiler baseline or moving
endpoint behavior into `crafter`.

## Packet-number freshness hook

`qlog` is enabled solely as an inspectable test hook. Tests attach a bounded
in-memory writer through `QlogConfig::writer`, set a deterministic qlog start
time, install the resulting stream with `TransportConfig::qlog_stream`, and
retain only packet type, packet number, loss, and recovery metadata. They also
hash each emitted protected UDP payload. After one induced loss, assertions
require a new `PacketSent` number in the correct packet-number space and a
different payload hash; they never log TLS keys, certificate private keys, or
application payload contents, and tracked fixtures contain no live captures.

## Sources

- [`quinn-proto` 0.11.14 published manifest](https://docs.rs/crate/quinn-proto/0.11.14/source/Cargo.toml)
- [`quinn-proto::Connection` 0.11.14](https://docs.rs/quinn-proto/0.11.14/quinn_proto/struct.Connection.html)
- [`quinn-proto::Endpoint` 0.11.14](https://docs.rs/quinn-proto/0.11.14/quinn_proto/struct.Endpoint.html)
- [`quinn-proto::TransportConfig` 0.11.14](https://docs.rs/quinn-proto/0.11.14/quinn_proto/struct.TransportConfig.html)
- [`quiche` 0.22.0 published manifest](https://docs.rs/crate/quiche/0.22.0/source/Cargo.toml)
- [`quiche::Connection` 0.22.0](https://docs.rs/quiche/0.22.0/quiche/struct.Connection.html)
