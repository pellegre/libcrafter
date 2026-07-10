# QUIC Flow Scope

This note defines the bounded QUIC conversations implemented by
`crafter-flow`. It extends the packet-primitive boundary in
`docs/guide/quic.md` and `.agents/docs/quic-scope.md`; it does not move an
endpoint stack into the public `crafter` crate.

## Source Boundary

Wire and endpoint decisions must be traceable to the evidence index in
`.agents/docs/quic-manifest.md`:

- `E-RFC-8999` supplies version-independent packet properties and Version
  Negotiation structure.
- `E-RFC-9000` supplies the QUIC version 1 transport, packet, frame, connection,
  stream, transport-parameter, Retry, and close rules.
- `E-RFC-9001` supplies the TLS 1.3 binding, Initial secrets, packet and header
  protection, and Retry integrity rules.
- `E-RFC-9002` supplies loss detection, PTO, and congestion-control behavior.
  These algorithms remain owned by the selected endpoint implementation rather
  than being reimplemented in `crafter`.
- `E-RFC-9369` supplies QUIC version 2 packet-layer differences and vectors. It
  bounds version handling and tests but does not expand the full-flow milestone
  beyond QUIC version 1.
- `E-QUIC-IANA` supplies current QUIC version, frame, transport-parameter, and
  transport-error registries. Draft, provisional, and experimental values are
  not promoted without a later source-backed decision.
- `E-ERRATA` records the reviewed RFC Editor errata state. Work touching RFC
  9000 must check verified errata 6811, 7861, 8240, and 7365 and held errata
  7578, 8875, 9003, and 7374; RFC 9001 erratum 7785 is rejected; and RFC 9002
  erratum 7539 is verified. The manifest records no matching RFC 8999 or RFC
  9369 errata. Affected behavior must follow the reviewed errata decision, not
  unqualified base-RFC text.

No QUIC wire fact may rely on model memory. Missing or ambiguous evidence stops
implementation until the manifest or a narrower source-backed note resolves
it.

## Full Flow Contract

The full client and server flows cover exactly one authenticated QUIC version 1
connection over IPv4 and UDP. TLS 1.3 authenticates the configured peer, and
the endpoint carries exactly one client-initiated bidirectional stream with one
bounded opaque request and one bounded opaque response. Application bytes have
no protocol interpretation.

The happy path includes Initial, Handshake, and one-round-trip packet
protection, in-order request and response delivery, bounded recovery, and a
graceful close through inspectable closing and draining outcomes. Recovery is
delegated behind a flow-owned endpoint driver and must generate newly protected
packets with fresh packet numbers; protected bytes are never replayed. All
timers, packet-number spaces, acknowledgements, TLS transcript state, stream
state, loss detection, and congestion behavior stay inside that driver.

The driver is protocol-only and socket-free. It accepts timestamped UDP
datagrams and tuple metadata, exposes ordered transmit datagrams and its next
wakeup, and reports non-secret lifecycle and application observations. The
flow engine wraps every transmit in the existing typed `Packet` stack so
mutation, compilation, summaries, dry-run planning, and reports remain
available. The driver dependency belongs only in `tools/flow`; `crafter`
remains a packet primitive.

Execution is bounded by configured stream, flow-control, idle, timeout, and run
limits. Malformed input, invalid transport parameters, authentication failure,
peer or local close, idle timeout, and recovery exhaustion produce inspectable
terminal outcomes rather than an unbounded endpoint loop.

## Initial-only Contract

The separate Initial-only client and server milestone exercises protected QUIC
Initial packets without implementing an authenticated endpoint. It builds
deterministic typed IPv4/UDP/QUIC datagrams, protects and inspects Initial
payloads, observes ACK and CRYPTO frames, handles Version Negotiation and
Retry, verifies Retry integrity, and reports Initial close or error outcomes.

Initial-only CRYPTO bytes are bounded opaque test material, not a TLS
transcript. Success means that protected Initial content was inspected and the
configured exchange reached an Initial-only terminal observation. An
Initial-only flow never reports `Established` and never claims that a QUIC
connection or TLS session was established.

## Non-goals

This milestone does not provide:

- 0-RTT, session resumption, or key updates;
- HTTP/3, QPACK, MASQUE, DNS over QUIC, or another application protocol;
- connection migration, connection-ID rotation policy, NAT rebinding, or
  multipath;
- arbitrary, concurrent, or server-initiated application streams;
- a general-purpose QUIC stack, a new congestion controller, or an independent
  RFC 9002 implementation;
- automatic protected-packet decryption in generic `Packet` decode paths; or
- a scanner, fuzzer, proxy, or production client/server embedded in `crafter`.

## Offline and Live Boundary

Defaults, examples, fixtures, and acceptance checks are offline,
deterministic, bounded, and use documentation address space such as
`192.0.2.0/24` and `198.51.100.0/24`. In-memory duplex tests and dry-run send,
probe, endpoint, and lab plans are the first validation path and require no
credentials or elevated privileges.

Live traffic requires explicit authorization and a dry-run first. It must run
on disposable provider-backed endpoint or lab infrastructure, with scoped
targets, non-sensitive artifact collection, and teardown. It must not originate
from an elevated developer host.
