# IPv6 Implementation Inventory

This is the final handoff inventory for the IPv6 enrichment work on
`feature/enrich-ipv6-protocol`. It replaces the earlier gap inventory and
records the behavior that is now implemented, the source evidence used to back
it, the validation that passed, and the exclusions that remain intentional.

Date checked: 2026-06-05. This inventory is offline-only: no live packet
exchange, raw socket traffic, provider endpoint, or lab session was required.

## Implemented packet behavior

The enriched IPv6 implementation now fits the existing `Packet` abstraction:
typed layers compose with `/`, compile through `compile()`, decode through
`Packet::decode_from_l3(NetworkLayer::Ipv6, ...)`, and inspect through
`summary()`, `show()`, and typed getters. Protocol-correct defaults are filled
when fields are unset, and explicit caller overrides are preserved, including
malformed values intended for stack testing.

Implemented base-header behavior includes:

- The 40-octet IPv6 base header fields: version, Traffic Class, Flow Label,
  Payload Length, Next Header, Hop Limit, source address, and destination
  address.
- Auto-filled Payload Length and Next Header values when unset.
- Preserved explicit Payload Length and Next Header values when set by the
  caller.
- Structured decode errors for short IPv6 buffers, invalid version, declared
  payload overruns, and extension-header truncation.
- Preservation of extra bytes after the declared Payload Length as trailing
  `Raw` data.
- Traffic Class DSCP/ECN helpers through `Dscp` and `Ecn`, while preserving the
  raw Traffic Class byte as the authoritative wire value.
- Flow Label getters and checked helpers for the 20-bit field. Automatic Flow
  Label generation remains outside the crate.

Implemented Next Header behavior includes:

- Named constants and summary labels for Hop-by-Hop Options, Routing,
  Fragment, ESP, AH, No Next Header, Destination Options, Mobility Header, HIP,
  Shim6, and the two experimental values 253 and 254.
- Decode traversal for supported Hop-by-Hop Options, Destination Options,
  Routing, Fragment, Mobile Type 2 Routing, and Segment Routing Header layers.
- Registry dispatch after supported extension chains for TCP, UDP, and ICMPv6.
- `Raw` preservation for unknown or unsupported non-empty Next Header payloads.
- `IPPROTO_IPV6_NO_NEXT` support for explicit No Next Header values and labels;
  an empty payload decodes without a child layer, while non-empty bytes follow
  the raw-preservation policy.

Implemented Hop-by-Hop and Destination Options behavior includes:

- `Ipv6HopByHopOptionsHeader` and `Ipv6DestinationOptionsHeader` typed layers.
- Shared ordered `Ipv6Option` TLVs for Pad1, PadN, Router Alert, Jumbo Payload,
  Home Address, and generic or unknown options.
- Option metadata helpers for the full option type byte, action bits,
  change-en-route bit, low five-bit option number, encoded length, and option
  data bytes.
- Auto-filled option-header `Hdr Ext Len` with 8-octet padding when unset.
- Structured compile errors when an explicit option-header length is too short
  for caller-supplied options.
- Byte-preserving decode of unknown options and malformed known-option lengths
  as generic options when the declared bytes are contained.
- Explicit-only Router Alert handling. The crate builds the option bytes but
  never inserts Router Alert automatically or implements router-intercept
  behavior.
- Jumbo Payload option bytes through `Ipv6Option::jumbo_payload`. Full
  jumbogram transport behavior remains unsupported.
- Home Address Destination Option bytes through `Ipv6Option::home_address`.
  Mobile IPv6 control-plane and state-machine behavior remains unsupported.

Implemented routing behavior includes:

- Generic `Ipv6RoutingHeader` build/decode for Next Header, Hdr Ext Len,
  Routing Type, Segments Left, and raw type-specific data.
- Source-backed routing type constants and classification helpers for assigned,
  deprecated, experimental, reserved, and unknown routing types.
- Mobile IPv6 Routing Header Type 2 through `Ipv6MobileRoutingHeader`, including
  home address, reserved-field inspection, header-length status, segments-left
  status, and overall validity status.
- Segment Routing Header support through `Ipv6SegmentRoutingHeader`, including
  Routing Type 4, Segments Left, Last Entry, raw Flags, Tag, Segment List
  addresses, and raw trailing TLV/padding bytes.
- SRH fixed-field validation for segment-list size, Last Entry, Segments Left,
  and trailing TLV shape.
- Compatibility aliases for older SRH builder names where needed, without
  claiming SRv6 endpoint behavior.

Implemented Fragment Header behavior includes:

- `Ipv6FragmentHeader` build/decode for Next Header, reserved octet, Fragment
  Offset, reserved fragment bits, M flag, and Identification.
- `Ipv6FragmentHeaderStatus` classification as `Atomic`, `Initial`, or
  `NonInitial`.
- Upper-layer decode continuation for atomic and initial fragments when the
  complete header chain is present.
- `Raw` preservation for non-initial fragment payload bytes.
- Explicit inspection of reserved-field status and fragment offsets without
  adding any fragment cache or stateful processing.

## Source evidence

The source-backed behavior is anchored in
[`docs/ipv6-rfc-manifest.md`](ipv6-rfc-manifest.md). That manifest remains the
authority for future protocol changes and reconciles the implementation with
RFC 8200, RFC 2474, RFC 3168, RFC 2675, RFC 2711, RFC 5095, RFC 6275, RFC 6946,
RFC 7045, RFC 7112, RFC 8754, RFC 9673, RFC 9800 notes, and the relevant IANA
protocol-number and routing-type registries.

Current implementation evidence is in:

- `crafter/src/protocols/ipv6.rs` for the IPv6 base layer, extension layers,
  option TLVs, routing helpers, fragment classification, decode traversal,
  summary labels, and unit tests.
- `crafter/src/protocols/ip.rs` for shared IP constants plus `Dscp` and `Ecn`.
- `crafter/src/protocols/mod.rs` and `crafter/src/lib.rs` for public exports
  through root, `core`, `prelude`, and protocol module paths.
- `crafter/src/registry.rs` for IPv6 child dispatch and raw fallback after the
  extension-chain traversal.
- `docs/ipv6.md` for the new user-facing IPv6 wire coverage page.
- `docs/api.md`, `docs/README.md`, `README.md`, and
  `crafter/examples/README.md` for links into the IPv6 coverage.
- `crafter/examples/ipv6_extensions.rs` for offline examples covering Traffic
  Class helpers, Flow Label, Hop-by-Hop Options, Destination Options, generic
  routing, SRH, Fragment Header, No Next Header, and unknown raw fallback.

## Behavioral suite and command results

The final IPv6 validation results recorded for this branch were:

- `cargo test -p crafter --test ipv6_public_api` passed with 131 tests.
- `cargo test -p crafter --test fixture_suite ipv6` passed with 4 tests,
  including the IPv6 fixture and pcap roundtrip filters.
- `cargo test -p crafter --test resilience ipv6` passed with 8 tests.
- `tools/oracle/run offline --profile ipv6-enrichment --seed 1 --count 20 --root l3:ipv6`
  passed with 20/20 offline oracle comparisons.
- `cargo test --workspace` passed.
- `.agents/scripts/check-crafter-release --static` passed.

These commands validate offline behavior only. Live traffic remains opt-in
through explicit live flags, provider configuration, or lab/wire workflows.

## Tests

The focused test coverage now includes:

- `crafter/tests/ipv6_public_api.rs` for public exports, builder aliases,
  DSCP/ECN helpers, option TLVs, Hop-by-Hop and Destination Options headers,
  No Next Header constants/labels, routing classification, Fragment Header
  status, Mobile Type 2 status, SRH fields, and compile/decode round trips.
- IPv6 unit tests in `crafter/src/protocols/ipv6.rs` for base header
  compile/decode behavior, payload length handling, extension chaining,
  routing headers, Fragment Header behavior, option parsing, malformed option
  handling, and SRH validation.
- `crafter/tests/fixture_suite.rs` for committed byte, summary, show, and pcap
  fixtures that pin the public decode surface.
- `crafter/tests/resilience.rs` for malformed IPv6 base-header, option-header,
  routing-header, Fragment Header, Mobile Type 2, and SRH structured-error
  cases, plus unsupported Next Header raw preservation.
- ICMPv6/NDP and transport tests that exercise IPv6 as the enclosing network
  layer for checksum and child decode behavior, without broadening IPv6 into a
  host stack.

## Fixtures

Fixtures are committed offline artifacts under `crafter/tests/fixtures/` and
use documentation address space. Current IPv6 fixture coverage includes:

- Base traffic fields:
  `bytes/ipv6-base-traffic-flow-udp-raw.hex`.
- Hop-by-Hop and Destination Options:
  `bytes/ipv6-options-hop-destination-udp.hex`,
  `summaries/ipv6-options-hop-destination-udp.summary.txt`, and
  `summaries/ipv6-options-hop-destination-udp-show.summary.txt`.
- Generic routing, Mobile Type 2, and SRH:
  `bytes/ipv6-routing-generic-unknown-raw.hex`,
  `bytes/ipv6-mobile-routing-raw.hex`,
  `bytes/ipv6-segment-routing-raw.hex`, and their summary fixtures.
- Fragment Header status fixtures:
  `bytes/ipv6-fragment-udp-raw.hex`,
  `bytes/ipv6-fragment-atomic-udp-raw.hex`,
  `bytes/ipv6-fragment-non-initial-udp-raw.hex`, and their summaries.
- IPv6 transport fixtures:
  `bytes/ipv6-udp-raw.hex`,
  `bytes/ipv6-udp-options-unknown-unsafe.hex`,
  `bytes/ipv6-udp-options-frag.hex`,
  `bytes/ipv6-tcp-raw.hex`,
  `bytes/ipv6-tcp-rich-options.hex`,
  `bytes/ipv6-icmp-echo-request.bin`, and
  `bytes/ipv6-icmpv6-time-exceeded.hex`.
- Raw IPv6 classic-pcap fixtures:
  `pcaps/raw-ipv6-icmp-echo-request.pcap` and
  `pcaps/raw-ipv6-base-traffic-flow-udp-raw.pcap`.
- Malformed decode corpus entries in
  `malformed/core-decode-corpus.hex` for IPv6 base and extension truncation
  cases.

The pcap roundtrip path is pinned by `fixture_suite` and covers deterministic
RawIP IPv6 pcap read/write/decode behavior. Tracked fixtures must not contain
real credentials, provider account data, live host identifiers, public IPs, or
captures from sensitive networks.

## Oracle coverage

Oracle coverage for the IPv6 enrichment is now a focused offline path:

- `tools/oracle/specs/profiles.yaml` defines the `ipv6-enrichment` profile with
  offline sampling and `pcap: 0` / `live: 0` feature weights.
- `tools/oracle/specs/layers/ipv6.yaml` declares base IPv6 fields, DSCP/ECN,
  Hop-by-Hop Options, Destination Options, shared IPv6 option metadata,
  Fragment Header, generic routing, Mobile Type 2, SRH, unknown Next Header,
  and malformed extension coverage.
- `tools/oracle/specs/features/ipv6-fragment-routing.yaml` indexes the focused
  IPv6 extension-header cases.
- `tools/oracle/specs/stacks.yaml` includes rooted `l3:ipv6` stacks for base
  IPv6, Hop-by-Hop Options, Destination Options, Fragment Header, routing,
  TCP-chain, UDP-chain, and ICMPv6-chain cases.
- The oracle reference fixture set marks both reference-originated and
  libcrafter-originated IPv6 enrichment cases.
- The oracle reference backend packet materializer emits enriched reference
  packets, including Hop-by-Hop Options, Destination Options, Router Alert,
  Jumbo Payload, Home Address, Fragment Header, generic routing, and SRH.
- The oracle reference backend normalizer canonicalizes IPv6 extension chains
  and option bytes for comparison.
- `tools/oracle/adapters/src/bin/vectors/cases.rs` materializes the
  libcrafter-originated IPv6 vectors.

Malformed IPv6 extension chains are represented as structured-error coverage,
not strict-byte offline oracle comparisons. The oracle path remains offline by
default; provider-backed live validation is a separate, explicitly authorized
workflow.

## Docs and examples

User-facing IPv6 documentation now exists at [`docs/ipv6.md`](ipv6.md). It
documents base-header fields, DSCP/ECN helpers, Flow Label behavior, Payload
Length and Jumbo Payload caveats, Next Header constants, Hop-by-Hop and
Destination Options, routing headers, SRH, Fragment Header classification,
malformed decode policy, fixtures, the `ipv6-enrichment` oracle profile, and
explicit unsupported behavior.

The `ipv6_extensions` example is offline and demonstrates the enriched API
without raw sockets or live targets. Other docs point to `docs/ipv6.md` rather
than duplicating the packet-layer behavior map.

## Unsupported behavior that remains known

The following behaviors are deliberately unsupported by the current IPv6 packet
primitive:

- Automatic Flow Label generation policy.
- Automatic extension-header reordering.
- Automatic Router Alert insertion or router-intercept behavior.
- Full jumbogram transport semantics, huge payload allocation, automatic
  jumbogram invariant enforcement, or live jumbogram traffic.
- AH and ESP cryptography, key management, authentication, encryption, or
  verification.
- Mobility Header protocol 135 typed parsing and all Mobile IPv6 state
  machines, binding caches, return-routability behavior, home-agent behavior,
  and route-optimization workflows.
- HIP and Shim6 typed protocol parsers.
- SRv6 endpoint behavior, SID execution, policy installation, HMAC
  verification, or live SR domain operation.
- PMTUD probing or live Packet Too Big workflows.
- Treating fixtures, examples, oracle runs, or probe defaults as live network
  authorization.

Unsupported non-empty payloads are still preserved as `Raw` where the enclosing
IPv6 or extension header is valid. This is byte preservation, not support for
the unsupported protocol.

## Out of scope fragmentation and reassembly exclusions

IPv6 fragmentation generation and IPv6 reassembly remain explicitly out of
scope.

`crafter` can build and decode a single `Ipv6FragmentHeader` layer and can
classify the packet as atomic, initial, or non-initial. It does not split a
payload into multiple IPv6 fragments, choose fragment sizes, create fragment
series, repair or reorder fragments, or generate provider-backed fragmented live
traffic.

`crafter` also does not implement IPv6 reassembly, overlap handling, fragment
queues, fragment timers, fragment caches, endpoint state, or first-fragment
complete-header-chain enforcement. Initial and atomic fragments may continue
upper-layer decode when the complete header chain is present. Non-initial
fragments preserve remaining bytes as `Raw` because there is no reassembly
context.

These exclusions are intentional for the 2.x packet primitive. Future generated
tools may build workflows on top, but the crate remains a protocol-correct
packet construction and decode library rather than an IPv6 stack.
