# Oracle Specs

The oracle runner uses specs as the source of truth for packet behavior. Backend
code, including Scapy support, should materialize and normalize packets from
these specs instead of carrying its own sampling rules.

## Runner Modes

`tools/oracle/run offline` validates raw vectors and normalized decode behavior.
`tools/oracle/run pcap` validates pcap writer, reader, and roundtrip behavior.
`tools/oracle/run live` validates provider-backed live exchange plans and
reports. All three modes accept `--backend scapy`, `--profile`, `--seed`,
`--count`, and targeted reproduction coordinates such as `--case`, `--feature`,
`--family`, and `--index`.

Artifacts default below `target/oracle/`. A failing case should be reproducible
with the same mode, backend, profile, seed, and packet index reported by the
oracle runner.

## Layer Specs

Layer specs live under `tools/oracle/specs/layers/`. A layer spec defines the
generic layer name, supported parents and children, allowed roots, field domains,
default values, generated boundary values, and backend support. Field names are
oracle-normalized names, not Scapy or libcrafter implementation names.

## Feature Specs

Feature specs live under `tools/oracle/specs/features/`. A feature describes a
behavior inside or near one or more layers, such as TCP options, checksum rules,
IPv6 extension headers, malformed cases, pcap link types, or live exchange
patterns. Feature specs declare the layers they depend on, directions they apply
to, whether malformed input is expected, and any backend limitations.

## Stack Grammar

`tools/oracle/specs/stacks.yaml` defines valid protocol stacks. It constrains
which layers can appear together and how parent/child relationships are sampled.
If a sampled stack violates the grammar or a selected feature's constraints, the
generator must reject it and resample instead of relying on backend exceptions.

## Fixture Case Specs

`tools/oracle/specs/fixtures/` contains backend-owned case matrices that seed
oracle generation and compatibility reports. The Scapy case matrix in
`fixtures/scapy-cases.json` documents historical packet behaviors that now run
through oracle modes and write artifacts below `target/oracle/`.

## Profiles

`tools/oracle/specs/profiles.yaml` defines sampling profiles. Profiles change
weights, counts, feature emphasis, and boundary-value frequency; they do not add
backend-specific generation logic. The expected profiles are:

- `smoke`: tiny stable subset for quick local checks.
- `ci`: deterministic pull request coverage.
- `wild`: common packet shapes and field values.
- `boundary`: edge values, lengths, checksums, options, and limits.
- `fuzz`: valid-weird and explicitly malformed behavior.
- `ipv4-enrichment`: focused offline IPv4 header enrichment coverage for
  supported DS field, raw fallback, fragment-field, TTL, and option cases.
- `tcp-header`: focused offline TCP header compile/decode coverage. It narrows
  stack/case/feature selection to the `tcp_header` feature (SYN, SYN-ACK,
  RST-ACK, payload ACK, IPv4/IPv6 checksum contexts, explicit checksum override,
  and raw payload preservation). The deliberately malformed invalid-data-offset
  case is declared coverage but carries `byte_policy: structured_error`, so it is
  excluded from the offline encode/decode pathway (a data offset past the
  available bytes is a structured decode error, not a comparable packet).
- `ipv6-enrichment`: focused offline IPv6 base and extension-header
  reproducibility coverage rooted at `l3:ipv6`. It samples strict-byte
  comparable base, unknown-next-header, Hop-by-Hop, Destination Options,
  fragment, routing, Segment Routing Header, TCP-chain, and ICMPv6-chain cases
  in both `reference_to_libcrafter` and `libcrafter_to_reference` directions.
  Its malformed IPv6 extension cases are declared as
  `byte_policy: structured_error` and are therefore excluded from offline byte
  comparison; the oracle reports structured decode-error coverage separately
  from packet equivalence. Store focused run artifacts below `target/oracle/`,
  such as `target/oracle/ipv6-enrichment-offline/` and
  `target/oracle/ipv6-enrichment-reference-to-libcrafter/`.
- `ip-fragment-offline`, `ip-fragment-pcap`, and
  `ip-fragment-lab-dry-run`: planned profiles declared by the
  `ip_fragment_transforms` feature contract. They cover Scapy-backed IPv4 and
  IPv6 fragment byte sequences, `IpDefrag` many-record-to-one behavior,
  `IpFragment` one-record-to-many behavior, duplicate and overlap policy,
  missing-fragment eviction, IPv4 DF handling, IPv6 atomic fragments, supported
  extension-header scope, pcap payload-hash comparison, and provider-backed
  constrained-MTU lab dry-runs. These profile names are contract metadata until
  the oracle transform-case schema can execute packet-stream transforms.

## Directions

Oracle reports use backend-neutral direction names:

- `reference_to_libcrafter`: reference backend emits bytes or pcaps that
  libcrafter decodes.
- `libcrafter_to_reference`: libcrafter emits bytes or pcaps that the reference
  backend decodes.
- `roundtrip`: one side decodes and re-encodes a packet for comparison.
- `live_exchange`: at least two endpoints exchange packets over a live network.

A feature that is supported in only one direction must say so in its spec.

## IP Fragment Transform Contract

`tools/oracle/specs/features/ip-fragment-transforms.yaml` defines the planned
oracle contract for IPv4 and IPv6 packet-stream transforms before the library
implementation exists. Scapy is the reference backend for byte-level fragment
behavior: Scapy-owned inputs feed `IpDefrag` in the
`reference_to_libcrafter` direction, and future `IpFragment` output is decoded
and normalized by Scapy in the `libcrafter_to_reference` direction. Roundtrip
cases feed `IpFragment` output back into `IpDefrag`, while the live profile is
reserved for provider-backed constrained-MTU lab sessions.

Those cases are marked `contract_only` because the current oracle schema can
compare single packet vectors but cannot yet model many input `PacketRecord`s,
many output `PacketRecord`s, or transform trace metadata. The minimal extension
is recorded in the feature spec: add transform-case input and output record
sequences, transform names, expected trace/error assertions, Scapy fragment
sequence materializers, libcrafter transform adapter JSON, pcap payload-hash
comparison, and provider-backed dry-run/live profiles.

`tools/oracle/run specs suite --family ip --json` therefore emits the planned
contract matrix without producing runnable offline commands yet. Once the schema
extension lands, the same case names should become executable without changing
the byte policies or directions recorded in the contract.

## Strict Byte Comparison

`strict_bytes` controls whether encoded bytes must match exactly. Strict
comparison is required for deterministic byte-level behavior such as raw vector
and pcap writer checks. Semantic comparison may be used only when the spec says
different encodings are equivalent and both sides normalize to the same model.

## Normalized Field Naming

Comparison happens through `DecodedModel`, not backend-native packet objects.
Specs must use stable oracle field names such as `checksum`, `header_length`, or
`vlan_id` rather than backend names like Scapy `chksum`, `dataofs`, or `Dot1Q`.
Backend-specific names may appear only in diagnostic metadata.
