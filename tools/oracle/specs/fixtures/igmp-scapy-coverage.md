# IGMP Scapy Coverage Matrix

This matrix records the IGMP oracle cases that the Scapy backend materializes
as exact IPv4 protocol 2 bytes and normalizes from the IPv4 payload. It covers
IGMP over IPv4 only; IPv6 MLD stays in the ICMPv6 family and is not part of
these rows.

## How To Read This Matrix

- **Case ID** is the oracle coverage case name from the IGMP feature specs and
  `tools/oracle/specs/fixtures/scapy-cases.json`.
- **Directions** are the feature-spec directions:
  `reference_to_libcrafter` and `libcrafter_to_reference`.
- **Byte policy** is `strict_bytes` for comparable packet bytes. There are no
  normalized IGMP cases in this matrix yet.
- **Scapy path** is `raw` for all current executable rows. This avoids
  version-sensitive Scapy contrib IGMP classes while still preserving and
  comparing the exact IPv4 protocol 2 bytes.

All examples use documentation IPv4 unicast space and source-backed multicast
documentation or link-local control groups, including `224.0.0.1`,
`224.0.0.2`, `224.0.0.22`, `224.0.0.106`, and `233.252.0.0/24`.

## Strict-Byte Cases

| Area | Case ID | Directions | Byte policy | Scapy path |
| --- | --- | --- | --- | --- |
| Bootstrap | `igmp-membership-query` | both | strict_bytes | raw IPv4 protocol 2 bytes |
| V2 | `igmp-v2-membership-query` | both | strict_bytes | raw IPv4 protocol 2 bytes |
| Bootstrap | `igmp-v1-membership-report` | both | strict_bytes | raw IPv4 protocol 2 bytes |
| V2 | `igmp-v2-membership-report` | both | strict_bytes | raw IPv4 protocol 2 bytes |
| V2 | `igmp-v2-leave-group` | both | strict_bytes | raw IPv4 protocol 2 bytes |
| Override | `igmp-checksum-explicit-invalid` | both | strict_bytes | raw IPv4 protocol 2 bytes, checksum pinned |
| Unknown values | `igmp-unknown-type-raw` | both | strict_bytes | raw IPv4 protocol 2 payload |
| Unknown values | `igmp-unsupported-assigned-type-raw` | both | strict_bytes | raw IPv4 protocol 2 payload |
| V3 query | `igmp-v3-query-general` | both | strict_bytes | raw IPv4 protocol 2 bytes |
| V3 query | `igmp-v3-query-group-specific` | both | strict_bytes | raw IPv4 protocol 2 bytes |
| V3 query | `igmp-v3-query-group-and-source-specific` | both | strict_bytes | raw IPv4 protocol 2 bytes |
| V3 query override | `igmp-v3-query-source-count-override` | both | strict_bytes | raw IPv4 protocol 2 bytes |
| V3 query override | `igmp-v3-query-checksum-explicit-invalid` | both | strict_bytes | raw IPv4 protocol 2 bytes, checksum pinned |
| V3 query raw tail | `igmp-v3-query-ignored-extra-octets` | both | strict_bytes | raw IPv4 protocol 2 bytes |
| V3 report | `igmp-v3-report-empty` | both | strict_bytes | raw IPv4 protocol 2 bytes |
| V3 report | `igmp-v3-report-include-record` | both | strict_bytes | raw IPv4 protocol 2 bytes |
| V3 report | `igmp-v3-report-exclude-record` | both | strict_bytes | raw IPv4 protocol 2 bytes |
| V3 report | `igmp-v3-report-source-list-change-records` | both | strict_bytes | raw IPv4 protocol 2 bytes |
| V3 report aux | `igmp-v3-report-auxiliary-data-record` | both | strict_bytes | raw IPv4 protocol 2 bytes |
| V3 report unknown | `igmp-v3-report-unknown-record-type` | both | strict_bytes | raw IPv4 protocol 2 bytes |
| V3 report override | `igmp-v3-report-count-override` | both | strict_bytes | raw IPv4 protocol 2 bytes |
| V3 report override | `igmp-v3-report-checksum-explicit-invalid` | both | strict_bytes | raw IPv4 protocol 2 bytes, checksum pinned |
| RFC 9279 extension | `igmp-extension-query-noop` | both | strict_bytes | raw IPv4 protocol 2 bytes |
| RFC 9279 extension | `igmp-extension-report-noop-zero-length` | both | strict_bytes | raw IPv4 protocol 2 bytes |
| RFC 9279 extension | `igmp-extension-unassigned-type` | both | strict_bytes | raw extension TLV bytes |
| RFC 9279 extension | `igmp-extension-experimental-type` | both | strict_bytes | raw extension TLV bytes |
| RFC 9279 extension | `igmp-extension-ordered-tlvs` | both | strict_bytes | raw ordered TLV bytes |
| RFC 9279 extension | `igmp-extension-e-flag-clear-raw-tail` | both | strict_bytes | raw IPv4 protocol 2 bytes |
| MRD | `igmp-mrd-advertisement` | both | strict_bytes | raw IPv4 protocol 2 payload |
| MRD | `igmp-mrd-solicitation` | both | strict_bytes | raw IPv4 protocol 2 payload |
| MRD | `igmp-mrd-termination` | both | strict_bytes | raw IPv4 protocol 2 payload |
| MRD override | `igmp-mrd-explicit-checksum-invalid` | both | strict_bytes | raw IPv4 protocol 2 payload |
| MRD override | `igmp-mrd-reserved-override` | both | strict_bytes | raw IPv4 protocol 2 payload |

## Normalized Cases

None yet. IGMP comparable cases currently require strict byte preservation. If a
future Scapy or libcrafter path normalizes an otherwise valid wire shape, add a
case here and mark the feature `supported_cases` byte policy accordingly.

## Structured-Error Exclusions

These malformed cases are declared by the IGMP feature specs as
`byte_policy: structured_error`. They are intentionally excluded from
strict-byte Scapy fixture rows because there is no valid packet byte comparison
after decode rejects the malformed input.

| Area | Case ID | Expected structured-error scope |
| --- | --- | --- |
| Bootstrap | `malformed-igmp-truncated-header` | short IGMP fixed header |
| V2 | `malformed-igmp-v2-truncated-group-address` | short fixed-header group address |
| V3 query | `malformed-igmp-v3-query-truncated-body` | missing query body fields |
| V3 query | `malformed-igmp-v3-query-truncated-source-list` | declared source list exceeds available bytes |
| V3 report | `malformed-igmp-v3-report-truncated-body` | missing report count/body fields |
| V3 report | `malformed-igmp-v3-report-truncated-group-record` | declared record area shorter than one group record |
| V3 report | `malformed-igmp-v3-report-truncated-record-source-list` | declared record source list exceeds available bytes |
| V3 report | `malformed-igmp-v3-report-truncated-record-auxiliary-data` | declared auxiliary data exceeds available bytes |
| RFC 9279 extension | `malformed-igmp-extension-empty-area` | E flag set with no extension area |
| RFC 9279 extension | `malformed-igmp-extension-truncated-header` | extension area shorter than a TLV header |
| RFC 9279 extension | `malformed-igmp-extension-truncated-value` | TLV value shorter than declared length |
| RFC 9279 extension | `malformed-igmp-extension-length-overrun` | TLV length extends beyond remaining payload |
| MRD | `malformed-igmp-mrd-truncated-advertisement` | short MRD advertisement body |
| MRD | `malformed-igmp-mrd-truncated-solicitation` | short MRD solicitation body |
| MRD | `malformed-igmp-mrd-truncated-termination` | short MRD termination body |

## Backend Limitations

- Scapy native IGMP support is limited and version-sensitive. The executable
  backend therefore emits exact `Raw` bytes under IPv4 protocol number 2 for
  all IGMP cases.
- RFC 9279 generic extension TLVs have no Scapy high-level typed layer in this
  plan. The backend should materialize the TLV area from explicit raw bytes and
  compare those bytes strictly.
- RFC 4286 Multicast Router Discovery cases may need raw IPv4 protocol 2 bytes.
  The crate implements only packet construction, decode, and inspection; it
  does not implement router discovery behavior.
- Unknown IGMP Types, unsupported assigned Types, unknown group record Types,
  extension Types, invalid checksums, explicit count overrides, and reserved
  field overrides are byte-preservation cases. The backend must not normalize
  them away while building reference packets.
- Live multicast behavior is out of scope for this fixture matrix. Provider and
  live gates remain dry-run or protected by later lab/oracle/probe steps.
