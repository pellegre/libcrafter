# SCTP Packet-Layer Scope

SCTP support in `crafter` is a packet primitive. It exists so generated tools
can build, compile, decode, inspect, fixture, and validate SCTP bytes through
the existing `Packet` abstraction without adding an SCTP endpoint stack.

This scope is source-backed by [`sctp-rfc-manifest.md`](sctp-rfc-manifest.md),
[`sctp-codepoints.md`](sctp-codepoints.md), and
[`sctp-wire-grammar.md`](sctp-wire-grammar.md). RFC 9260, current IANA SCTP
registries, RFC 6951, RFC 9653, and selected extension RFCs define packet
fields, codepoints, padding, checksums, encapsulation shape, and preservation
rules. They do not authorize stateful association behavior in the crate.

## In Scope

- Native SCTP over IPv4 and IPv6 as a typed transport layer with IP protocol /
  next-header value `132` auto-filled only when the enclosing field is unset.
- Guarded RFC 6951 UDP encapsulation where SCTP is decoded from UDP payloads
  only after a conservative shape check; unrelated UDP/9899 payloads remain
  `Raw`.
- The 12-octet common header: source port, destination port, verification tag,
  and CRC32c checksum.
- Chunk, parameter, and error-cause envelopes, including declared lengths,
  four-octet padding boundaries, and byte-preserving padding round trips.
- Source-backed typed chunk, parameter, and cause variants admitted by later
  implementation steps.
- Unknown, reserved, temporary, private, obsolete, or future chunk types,
  parameter types, cause codes, flags, PPIDs, HMAC identifiers, adaptation code
  points, and error-detection method IDs as inspectable byte-preserving packet
  data when structurally valid.
- `compile()` defaults for unset dependent fields such as SCTP lengths, padding,
  IP protocol / next-header values, and CRC32c checksum.
- Explicit caller overrides, including malformed ports, verification tags,
  lengths, flags, codepoints, checksums, and payload bytes.
- Decode-time checksum status, summaries, `show()` output, deterministic byte
  fixtures, pcap fixtures, oracle specs, probe plans, and malformed-buffer
  tests.

All public helpers should return or expose `Packet` values or typed SCTP layer,
chunk, parameter, and cause values. SCTP work must compose through `/`,
`compile()`, decode entrypoints, `summary()`, and `show()` rather than creating
a parallel raw-byte workflow API.

## Not In Scope

The following SCTP behaviors are not in scope for `crafter`:

- association setup, teardown, restart, peer lifecycle, or verification-tag
  state tracking beyond packet-field construction and inspection;
- retransmission services, RTO calculation, timer management, partial
  reliability policy, or lost-data recovery;
- congestion control, congestion-window state, ECNE/CWR reaction policy, or
  path MTU discovery workflow;
- stream scheduling, ordered delivery, fragmented user-message reassembly, or
  application payload dispatch from PPID labels;
- dynamic address-management workflow, path failover, multihoming policy, or
  ASCONF state mutation;
- SCTP socket APIs, kernel-stack compatibility layers, userland daemons, or
  endpoint services;
- AUTH HMAC computation or verification, DTLS, key management, or a
  cryptographic association layer;
- scanners, fuzzers, analyzers, traffic generators, or long-running validation
  workflows inside the public crate.

Those behaviors can be generated as tools on top of `crafter` packet
primitives. The crate exposes the wire data and validation evidence those tools
need; it does not own SCTP runtime state.

## Construction And Decode Contract

- Builders fill protocol-correct defaults only when the caller leaves a field
  unset.
- Caller-supplied values survive unchanged, even when reserved, invalid,
  unknown, or intentionally malformed.
- Decoders preserve unknown but structurally valid SCTP data instead of
  discarding it or forcing it into a lossy enum.
- Malformed or truncated buffers return structured errors with context,
  required length, and available length where applicable.
- Padding bytes are transmitted bytes for checksum and round-trip purposes, but
  they are not semantic chunk, parameter, or cause value bytes.
- PPID, HMAC, adaptation, and error-detection labels are summary metadata only
  unless a later source-backed step explicitly admits deeper behavior.

## Validation Boundary

SCTP examples, tests, fixtures, oracle specs, probe plans, and generated-tool
defaults must stay offline or dry-run by default. Addresses in examples must
use documentation address space such as `192.0.2.0/24`, `198.51.100.0/24`, or
`2001:db8::/32`.

Any live SCTP validation must be explicitly gated, provider-backed through the
repository lab/session/endpoint workflow, preceded by a dry-run plan, and kept
out of tracked artifacts unless the artifact is sanitized and intentionally
documented.
