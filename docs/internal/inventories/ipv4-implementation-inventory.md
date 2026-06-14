# IPv4 Implementation Inventory

This is the final handoff inventory for the IPv4 enrichment work. It maps the
implemented `crafter` IPv4 surface to the source-backed behavior recorded in
[`docs/internal/manifests/ipv4-rfc-manifest.md`](../manifests/ipv4-rfc-manifest.md), and points future
maintainers to the validation commands, fixtures, docs, examples, and known
exclusions.

Date checked: 2026-06-04, after the focused IPv4 suite, workspace tests, and
static release gate steps.

Primary implementation paths:

- `crafter/src/protocols/ip.rs` - IPv4 layer, DSCP/ECN helpers, checksum status,
  protocol labels, options, fragment metadata, encode/decode tests.
- `crafter/src/registry.rs` - IPv4 payload dispatch, unknown-protocol `Raw`
  fallback, fragment-aware dispatch.
- `crafter/src/protocols/mod.rs` and `crafter/src/lib.rs` - protocol, root,
  `core`, and `prelude` re-exports.
- `crafter/tests/ipv4_public_api.rs` - public API behavior through
  `crafter::prelude::*`.
- `crafter/tests/fixture_suite.rs` - byte, summary, and pcap fixture assertions.
- `crafter/tests/resilience.rs` - malformed corpus and random decode panic
  guards.
- `tools/oracle/specs/` - offline oracle data for the `ipv4-enrichment` profile.

## Implemented Features

The IPv4 layer remains a typed `Packet` layer. It composes with `/`, compiles
with `compile()`, decodes through `Packet::decode_from_l3`, and stays
inspectable through `summary()`, `show()`, `hexdump()`, and typed getters.

Implemented base-header coverage:

- Version, IHL, DS field/TOS byte, total length, identification, reserved/DF/MF
  flags, fragment offset, TTL, protocol, checksum, source, destination, and raw
  option bytes are exposed through builders and getters.
- `compile()` fills IHL, total length, ICMPv4/TCP/UDP protocol numbers, option
  padding, and IPv4 header checksum when those dependent fields are unset.
- Explicit field values are preserved within the modeled wire constraints,
  including intentionally unusual DS field values, protocol numbers, checksum
  words, TTL, flags, fragment offset, and total length values.
- Compatibility aliases remain available, including `tos`, `len`, `id`, `frag`,
  `proto`, `chksum`, and `ip_option`.

Implemented DSCP/ECN coverage:

- `Dscp` is a six-bit range-checked type and `Ecn` exposes the four RFC 3168
  ECN states.
- `Ipv4::ds_field`, `Ipv4::dscp`, and `Ipv4::ecn` compose over the historical
  TOS octet without changing the other subfield unexpectedly.
- `ds_field_value`, `tos_value`, `dscp_value`, and `ecn_value` work on built and
  decoded packets.

Implemented protocol-number behavior:

- IANA-backed common `IPPROTO_*` constants and `Ipv4Protocol` variants are
  exported for ICMP, TCP, UDP, IPv6 encapsulation, GRE, ESP, AH, ICMPv6, OSPF,
  SCTP, and experimental/testing values 253 and 254.
- Summaries and inspection output use richer protocol labels.
- Unknown, experimental, reserved, or unsupported IPv4 protocol payloads decode
  as typed `Ipv4` plus `Raw` payload rather than failing the enclosing IPv4
  datagram.

Implemented checksum behavior:

- Compile-time IPv4 header checksum fill is implemented.
- Explicit checksum overrides are preserved, including deliberately invalid
  checksums.
- Decode stores `Ipv4ChecksumStatus::{NotChecked, Valid, Invalid}` separately
  from the checksum word. Invalid checksums remain inspectable and round-trip
  with the decoded checksum value.
- `summary()` calls out invalid checksum status; `show()` includes checksum
  value and status.

Implemented decode boundaries and malformed handling:

- IPv4 decode returns structured `CrafterError` values for truncated fixed
  headers, invalid version, invalid IHL, header truncation, total length shorter
  than the header, total length beyond available bytes, and malformed option
  envelopes.
- Bytes after the IPv4 total length are preserved as a following `Raw` layer.
- Quoted IPv4 inside ICMPv4 errors remains inspectable through the lenient quote
  decoder.
- Random IPv4-like byte inputs and direct option decode inputs are covered by
  no-panic resilience tests.

Implemented option coverage:

- Raw options, `Ipv4OptionIter`, `parsed_options`, `Ipv4OptionKind`, copied
  flag/class/number metadata, and RFC 4727 experiment classification are
  available publicly.
- Typed options include End of List, No Operation, Generic, Record Route, Loose
  Source Route, Strict Source Route, RFC 1393 Traceroute, RFC 791 Timestamp
  modes, and RFC 2113 Router Alert.
- Unsupported Timestamp flag values preserve bytes as `Generic`.
- Compile pads options to a 32-bit header boundary, and decode preserves option
  bytes after End of List for round-trip.

Implemented fragmentation field support:

- Identification, reserved flag, DF, MF, raw flags, fragment offset, and
  `Ipv4FragmentInfo` are first-class public fields.
- `is_fragmented()` is true when MF is set or fragment offset is nonzero.
- Non-initial fragments (`fragment_offset != 0`) preserve payload as `Raw` and
  do not invoke transport decoders.
- Offset-zero MF fragments may type a complete registered transport header; if
  the registered decode fails, the payload is preserved as `Raw`.
- Fragmentation field support is implemented, but fragmentation generation and
  reassembly remain out of scope.

Implemented docs and examples:

- [`docs/guide/ipv4.md`](../../guide/ipv4.md) is the user-facing IPv4 guide.
- [`docs/operations/validation.md`](../../operations/validation.md) records the offline IPv4 behavioral
  suite.
- [`docs/README.md`](../../README.md), [`docs/reference/api.md`](../../reference/api.md), and the top-level
  [`README.md`](../../../README.md) link the IPv4 guide.
- `crafter/examples/ipv4_enrichment.rs` demonstrates DSCP/ECN helpers, typed
  Router Alert, checksum status, and fragment metadata inspection offline.
- `crafter/examples/ipv4_options.rs` remains the focused IPv4 option builder
  example.
- Agent operating guidance lives in `.agents/docs/cookbook.md`.

## Behavioral suite / validation commands

Focused IPv4 checks:

```sh
cargo test -p crafter --test ipv4_public_api
cargo test -p crafter --test fixture_suite ipv4
cargo test -p crafter --test resilience ipv4
cargo test -p crafter --test fixture_suite pcap_fixture_roundtrips
tools/oracle/run offline --profile ipv4-enrichment --seed 1 --count 12 --root l3:ipv4
```

Broad validation and release gate:

```sh
cargo test --workspace
.agents/scripts/check-crafter-release --static
```

Useful supporting checks used during the enrichment work:

```sh
cargo fmt --check
cargo test -p crafter --test fixture_suite
cargo test -p crafter --test resilience malformed_corpus_reports_structured_errors
```

## Fixtures, pcaps, and oracle profile

IPv4-specific byte fixtures:

- `crafter/tests/fixtures/bytes/ipv4-icmp-echo-request.bin`
- `crafter/tests/fixtures/bytes/ipv4-icmp-destination-unreachable.hex`
- `crafter/tests/fixtures/bytes/ipv4-udp-dscp-ecn-raw.hex`
- `crafter/tests/fixtures/bytes/ipv4-fragment-noninitial-raw.hex`
- `crafter/tests/fixtures/bytes/ipv4-options-traceroute-udp-raw.hex`

IPv4 carrier fixtures for adjacent protocols:

- `crafter/tests/fixtures/bytes/ipv4-tcp-syn-options.hex`
- `crafter/tests/fixtures/bytes/ipv4-tcp-syn-rich-options.hex`
- `crafter/tests/fixtures/bytes/ipv4-udp-dns-query-example-com.bin`
- `crafter/tests/fixtures/bytes/ipv4-udp-dns-response-example-com.hex`
- `crafter/tests/fixtures/bytes/ipv4-udp-dns-soa-srv-response.hex`
- `crafter/tests/fixtures/bytes/ipv4-udp-dns-dnssec-response.hex`
- `crafter/tests/fixtures/bytes/ipv4-udp-dns-svcb-https-response.hex`
- `crafter/tests/fixtures/bytes/ipv4-udp-dns-edns-opt-query.hex`
- `crafter/tests/fixtures/bytes/ipv4-udp-dns-raw-unknown-records-response.hex`
- `crafter/tests/fixtures/bytes/ipv4-udp-dns-section-placement-response.hex`
- `crafter/tests/fixtures/bytes/ipv4-udp-dhcp-discover.hex`
- `crafter/tests/fixtures/bytes/ipv4-udp-options-known.hex`
- `crafter/tests/fixtures/bytes/ipv4-udp-options-unknown-safe.hex`

Link wrapper fixtures with IPv4 payloads:

- `crafter/tests/fixtures/bytes/ethernet-vlan-ipv4-udp-raw.bin`
- `crafter/tests/fixtures/bytes/null-loopback-ipv4-udp-raw.hex`

Summary fixtures carrying IPv4 coverage:

- `crafter/tests/fixtures/summaries/ipv4-options-traceroute-udp-raw.summary.txt`
- `crafter/tests/fixtures/summaries/ipv4-tcp-syn-options.summary.txt`
- `crafter/tests/fixtures/summaries/ipv4-tcp-syn-rich-options.summary.txt`
- `crafter/tests/fixtures/summaries/ipv4-udp-dns-*.summary.txt`
- `crafter/tests/fixtures/summaries/ipv4-udp-dhcp-discover.summary.txt`
- `crafter/tests/fixtures/summaries/ipv4-udp-options-*.summary.txt`

Classic pcap fixtures with IPv4 coverage:

- `crafter/tests/fixtures/pcaps/raw-ipv4-icmp-echo-request.pcap`
- `crafter/tests/fixtures/pcaps/raw-ipv4-udp-dscp-ecn-raw.pcap`
- `crafter/tests/fixtures/pcaps/null-loopback-ipv4-udp-raw.pcap`

The RawIp DSCP/ECN pcap is covered by
`cargo test -p crafter --test fixture_suite pcap_fixture_roundtrips`. Pcap
records for IPv4 fragment fields, IPv4 options, Timestamp, and Router Alert are
not currently checked in; those behaviors are covered by byte fixtures, summary
fixtures, public API tests, and malformed corpus rows instead.

Malformed IPv4 corpus rows live in
`crafter/tests/fixtures/malformed/core-decode-corpus.hex` and cover:

- `short-ipv4-header`
- `bad-ipv4-version`
- `bad-ipv4-ihl`
- `ipv4-ihl-larger-than-available`
- `ipv4-total-length-shorter-than-header`
- `ipv4-total-length-larger-than-available`
- `ipv4-option-length-overrun`
- `ipv4-option-length-below-minimum`
- `ipv4-option-overrun-minimal`
- `ipv4-option-decoder-overrun`
- `ipv4-route-option-too-short`
- `ipv4-route-option-bad-pointer`
- `ipv4-timestamp-option-malformed-data`
- `ipv4-router-alert-bad-length`

Oracle coverage:

- `tools/oracle/specs/layers/ipv4.yaml` contains the enriched IPv4 layer fields
  and coverage cases.
- `tools/oracle/specs/stacks.yaml` contains the `ipv4_payload` stack used by
  focused IPv4 sampling.
- `tools/oracle/specs/profiles.yaml` contains the `ipv4-enrichment` profile.
- `tools/oracle/specs/README.md` documents the profile.
- The profile is offline-only and samples DS field, unknown protocol Raw
  fallback, MF/offset fragment metadata, TTL 255, and supported option cases
  under `--root l3:ipv4`.

## Out of scope

Fragmentation generation remains out of scope. `crafter` can construct or decode
IPv4 headers that already carry identification, flags, and fragment offset
metadata, but it does not split payloads into multiple IPv4 fragments.

Fragment reassembly remains out of scope. There is no fragment cache, timer,
overlap policy, stack delivery model, or API that combines fragments into a
transport payload.

Other explicit exclusions:

- No global IPv4 Identification allocator, per-tuple ID tracker, RFC 6864
  uniqueness/rate policy, or host-stack ID management.
- No router, forwarding path, TTL decrement behavior, PMTUD state machine,
  scanner, fuzzer, or full IP stack.
- No live IPv4 packet exchange in this enrichment suite. Validation is offline,
  fixture-based, pcap-file based, or oracle dry-run/offline.
- No automatic transport decode for non-initial fragments. They intentionally
  remain `Raw` above IPv4.
- No typed experiment-option payload semantics. RFC 4727 option values are
  exposed and classified, but experiment option bodies remain generic bytes.
