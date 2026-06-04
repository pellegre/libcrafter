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

## Directions

Oracle reports use backend-neutral direction names:

- `reference_to_libcrafter`: reference backend emits bytes or pcaps that
  libcrafter decodes.
- `libcrafter_to_reference`: libcrafter emits bytes or pcaps that the reference
  backend decodes.
- `roundtrip`: one side decodes and re-encodes a packet for comparison.
- `live_exchange`: at least two endpoints exchange packets over a live network.

A feature that is supported in only one direction must say so in its spec.

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
