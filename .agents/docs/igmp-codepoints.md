# IGMP Codepoint Handoff

Reviewed: 2026-06-20

This handoff records the source-backed IGMP codepoints that later implementation
steps should use when adding constants, builders, decode labels, oracle specs,
and reference-backend cases. It is derived from `docs/igmp-rfc-manifest.md`,
`.agents/docs/igmp-manifest.md`, the local protocol-facts manifest under
`target/rfc-protocol-spec/igmp/`, and the official RFC/IANA pages below.

## Official Sources

- RFC 9776, current IGMPv3 Internet Standard / STD 100:
  <https://www.rfc-editor.org/info/rfc9776>
- RFC 9778, current IANA considerations / BCP 57:
  <https://datatracker.ietf.org/doc/html/rfc9778>
- IANA Internet Group Management Protocol (IGMP) Type Numbers:
  <https://www.iana.org/assignments/igmp-type-numbers/igmp-type-numbers.xhtml>
- RFC 1112, IGMPv1 and IPv4 multicast host baseline:
  <https://www.rfc-editor.org/info/rfc1112>
- RFC 2236, IGMPv2 compatibility:
  <https://www.rfc-editor.org/info/rfc2236>
- RFC 9279, IGMPv3 and MLDv2 message extension:
  <https://www.rfc-editor.org/info/rfc9279>
- RFC 4286, multicast router discovery:
  <https://www.rfc-editor.org/info/rfc4286>

## Registry Policy

- The IANA IGMP Type Numbers registry was last reviewed here from the official
  page last updated `2025-03-28`.
- RFC 9778 says IGMP Type and Code fields are IANA-managed, Code values are
  scoped by a specific Type value, and the registration policy for the IGMP
  Type Numbers and Code Fields registries is Standards Action.
- RFC 9778 creates the IGMP/MLD Query Message Flags and Report Message Flags
  registries. New flag-bit assignments also require Standards Action.
- The local protocol-facts manifest did not contain selected IANA registry
  records or extracted wire facts, so this file is the reviewed codepoint
  bridge until the cache includes the official IANA registry data.
- A focused local protocol-facts manifest attempt for
  `IGMP MLD RFC 9279 extension` timed out without usable output. The RFC 9279
  extension rows and flag mappings below are sourced from the official RFC
  Editor text and the current IANA IGMP registry, not from generated artifact
  evidence.

## IGMP Type Numbers

| Value | Name | Current source |
| --- | --- | --- |
| `0x00` | Reserved | IANA |
| `0x01..=0x08` | Reserved (Obsolete) | RFC 988 |
| `0x09..=0x10` | Unassigned | IANA |
| `0x11` | IGMP Membership Query | RFC 1112, updated by RFC 9776 behavior |
| `0x12` | IGMPv1 Membership Report | RFC 1112 |
| `0x13` | DVMRP | `draft-ietf-idmr-dvmrp-v3-11` |
| `0x14` | PIM version 1 | `draft-ietf-idmr-pim-spec-02` |
| `0x15` | Cisco Trace Messages | IANA |
| `0x16` | IGMPv2 Membership Report | RFC 2236 |
| `0x17` | IGMPv2 Leave Group | RFC 2236 |
| `0x1e` | Multicast Traceroute Response | IANA contact reference |
| `0x1f` | Multicast Traceroute | IANA contact reference |
| `0x22` | IGMPv3 Membership Report | RFC 9776 |
| `0x30` | Multicast Router Advertisement | RFC 4286 |
| `0x31` | Multicast Router Solicitation | RFC 4286 |
| `0x32` | Multicast Router Termination | RFC 4286 |
| `0xf0..=0xff` | Reserved for experimentation | RFC 9778 |

Implementation guidance:

- Type `0x11`, `0x12`, `0x16`, `0x17`, `0x22`, and `0x30..=0x32` are the
  packet-layer targets already planned for typed support.
- DVMRP, PIMv1, Cisco Trace, and multicast traceroute are valid values in the
  IGMP Type space, but they are not initial typed bodies. Preserve them as
  inspectable unknown or raw payloads until a source-backed step promotes them.
- Treat unassigned, reserved, and experimental Type values as representable
  bytes. Do not reject them during construction when the caller set them
  explicitly.

## Code Fields

The IANA Code Fields registry is scoped by IGMP Type.

| Type | Code values | Name |
| --- | --- | --- |
| `0x11` | `0` | IGMP Version 1 |
| `0x11` | `1..=255` | IGMP Version 2 or above Max Response Time |
| `0x12` | none registered | IGMPv1 Membership Report |
| `0x13` | `1` | Probe |
| `0x13` | `2` | Route Report |
| `0x13` | `3` | Old Ask Neighbors |
| `0x13` | `4` | Old Neighbors Reply |
| `0x13` | `5` | Ask Neighbors |
| `0x13` | `6` | Neighbors Reply |
| `0x13` | `7` | Prune |
| `0x13` | `8` | Graft |
| `0x13` | `9` | Graft Ack |
| `0x14` | `0` | Query |
| `0x14` | `1` | Register |
| `0x14` | `2` | Register-Stop |
| `0x14` | `3` | Join/Prune |
| `0x14` | `4` | RP-Reachable |
| `0x14` | `5` | Assert |
| `0x14` | `6` | Graft |
| `0x14` | `7` | Graft Ack |
| `0x14` | `8` | Mode |
| `0x16` | none registered | IGMPv2 Membership Report |
| `0x17` | none registered | IGMPv2 Leave Group |
| `0x1e` | none registered | Multicast Traceroute Response |
| `0x1f` | none registered | Multicast Traceroute |
| `0x22` | none registered | IGMPv3 Membership Report |
| `0xf0..=0xff` | none registered | Reserved for experimentation |

Implementation guidance:

- Do not model the `0x11` Code field as a generic enum only. In IGMPv2 and
  later query packets it carries the Max Response Time/Code byte.
- For IGMPv2 Query packets, the Max Response Time byte is linear in tenths of
  a second. A zero value is still representable because RFC 2236 uses it for
  IGMPv1-query compatibility handling.
- For IGMPv3 report Type `0x22`, the byte after Type is reserved in the base
  report format. Code Fields has no registered values for that Type.
- For IGMPv2 Membership Report Type `0x16` and Leave Group Type `0x17`, RFC
  2236 sends this byte as zero and receivers ignore it; `crafter` should still
  preserve caller-supplied bytes for malformed or exploratory packets.
- Preserve explicitly supplied Code bytes even when the current registry has no
  registration for the enclosing Type.

## IGMPv2 Compatibility Scope

RFC 2236 is the source for IGMPv2 packet compatibility, while RFC 9776 remains
the current complete IGMP protocol authority. Implement IGMPv2 as compatibility
message construction, decode, summary, fixture, and validation behavior rather
than as a router or host state machine.

Shared fixed-header fields:

- Type selects Query (`0x11`), IGMPv1 Report (`0x12`), IGMPv2 Report (`0x16`),
  or Leave Group (`0x17`).
- Max Response Time/Code is interpreted as the IGMPv2 query response bound only
  for Type `0x11`; reports and leave messages should default to zero but must
  not reject explicit overrides.
- Checksum covers the whole IGMP message/IP payload, including any trailing
  bytes kept for forward compatibility.
- Group Address is zero for General Query, the target group for Group-Specific
  Query, and the affected group for report or leave messages.

Newly supported IGMPv2 Type values:

- `0x16`: Version 2 Membership Report.
- `0x17`: Leave Group.

Compatibility-only values and behavior:

- `0x12` remains the IGMPv1 Membership Report form from RFC 1112.
- Query Max Response Time `0` indicates IGMPv1-query compatibility in RFC 2236;
  expose it as a byte-level value and do not force the operational 10-second
  interpretation into packet construction.
- All-systems `224.0.0.1`, all-routers `224.0.0.2`, TTL 1, Router Alert,
  report suppression, leave transmission rules, querier election, timers, and
  RFC 9776 compatibility-mode translation are operational or IPv4 composition
  concerns outside the IGMP layer's codepoint surface.

## IGMPv3 Membership Report Wire Layout

RFC 9776 Sections 4.2 through 4.2.13 define the Type `0x22` Membership Report
and the Group Record wire shape:

| Field | Width | Implementation note |
| --- | --- | --- |
| Type | 8 bits | Fixed value `0x22` for IGMPv3 Membership Report |
| Reserved | 8 bits | Default zero on transmit; ignore but preserve on receive |
| Checksum | 16 bits | Covers the whole IGMP message / IPv4 payload |
| Flags | 16 bits | IANA-managed report flags; preserve unassigned bits |
| Number of Group Records (`M`) | 16 bits | Count of following Group Record blocks |
| Group Record `[i]` | variable | Repeated `M` times, then optional trailing report bytes |

Each Group Record has this common wire layout:

| Field | Width | Implementation note |
| --- | --- | --- |
| Record Type | 8 bits | Values `1..=6` below; preserve unknown values |
| Aux Data Len | 8 bits | Auxiliary data length in 32-bit words |
| Number of Sources (`N`) | 16 bits | Count of IPv4 source addresses in this record |
| Multicast Address | 32 bits | Multicast group address for this record |
| Source Address `[i]` | `N * 32` bits | IPv4 source-address vector |
| Auxiliary Data | `Aux Data Len * 32` bits | Untyped bytes; preserve exactly |

Implementation guidance:

- The base Group Record length is `8 + 4 * N + 4 * Aux Data Len` bytes. Treat a
  shorter buffer as a structured truncation error.
- RFC 9776 defines no IGMPv3 auxiliary data semantics and says IGMPv3
  implementations set Aux Data Len to zero when sending and ignore auxiliary
  data when receiving. `crafter` should default generated reports to no
  auxiliary data while preserving explicit caller-supplied and decoded
  auxiliary bytes.
- RFC 9776 says additional received report octets beyond the last Group Record
  are included in checksum verification and otherwise ignored. Keep those bytes
  inspectable and byte-preserving rather than silently dropping them.

## IGMPv3 Group Record Types

RFC 9776 Section 4.2.13 defines the IGMPv3 report Group Record Type values:

| Value | Name | Record class |
| --- | --- | --- |
| `1` | `MODE_IS_INCLUDE` | Current-State Record |
| `2` | `MODE_IS_EXCLUDE` | Current-State Record |
| `3` | `CHANGE_TO_INCLUDE_MODE` | Filter-Mode-Change Record |
| `4` | `CHANGE_TO_EXCLUDE_MODE` | Filter-Mode-Change Record |
| `5` | `ALLOW_NEW_SOURCES` | Source-List-Change Record |
| `6` | `BLOCK_OLD_SOURCES` | Source-List-Change Record |

Implementation guidance:

- Unknown Group Record Type values are valid to decode as byte-preserving
  unknown records. RFC 9776 requires IGMP implementations to ignore
  unrecognized record types, but `crafter` should still expose them for packet
  inspection.
- Auxiliary data is not defined by IGMPv3 itself. Keep it byte-preserving until
  an extension source review defines typed semantics.
- RFC 4604 SSM guidance is operational. It can inform optional diagnostics for
  EXCLUDE-mode records in SSM ranges, but it should not become a construction or
  decode-time rejection rule for otherwise well-formed bytes.

## IGMP/MLD Extension Types

RFC 9279 defines the shared IGMPv3/MLDv2 extension mechanism and the IANA
IGMP/MLD Extension Types registry.

| Value range | Registration procedure | Name |
| --- | --- | --- |
| `0..=65533` | IETF Review | Registry-managed extension range |
| `0` | IETF Review | No-op |
| `1..=65533` | IETF Review | Unassigned |
| `65534..=65535` | Experimental Use | Reserved for Experimental Use |

Implementation guidance:

- Only `0` currently has a named extension type in the official registry.
- Extension Type `0` is No-op. Its Extension Value is arbitrary bytes and is
  ignored by protocol implementations; do not assign semantic subtype behavior
  to it.
- The experimental extension range is separate from the IGMP Type
  experimentation range `0xf0..=0xff`.
- Preserve extension blocks generically as ordered TLVs until a dedicated
  source review for a specific assigned Extension Type justifies typed bodies.
- Do not implement MLD in the IGMP module just because the extension registry
  is shared by IGMP and MLD.

## RFC 9279 Extension TLV Layout

RFC 9279 extensions are carried in the Additional Data area of IGMPv3 Query and
IGMPv3 Membership Report messages when the E-bit is set. The generic TLV wire
format is:

| Field | Width | Implementation note |
| --- | --- | --- |
| Extension Type | 16 bits | IANA IGMP/MLD Extension Types value |
| Extension Length | 16 bits | Value length in octets; zero is valid |
| Extension Value | variable | Exactly Extension Length bytes |

Implementation guidance:

- TLVs are byte-contiguous. RFC 9279 does not require alignment or padding
  between TLVs.
- The extension area must contain at least one TLV when E is set.
- Validation walks TLVs until the IP-payload remainder is exhausted; any bytes
  left after the last complete TLV make the extension invalid.
- The total extension length must not exceed the remaining IP payload.
- Unsupported Extension Types are ignored by IGMP/MLD implementations, but
  `crafter` should preserve their type, declared length, and value bytes for
  inspection and round-trip work.
- Structured truncation and length-overrun handling belong in the later
  extension decode/encode steps. Until then, ambiguous extension behavior is
  unsupported rather than inferred from generic IGMPv3 trailing-byte rules.

## IGMP/MLD Query Message Flags

| Bit | Short name | Description | Reference |
| --- | --- | --- | --- |
| `0` | `E` | Extension | RFC 9279 |
| `1..=3` | unassigned | Reserved for future Standards Action | RFC 9778 |

Implementation guidance:

- RFC 9778 maps these bit numbers to the flag columns in the IGMPv3 Query
  packet format from RFC 9776.
- RFC 9279 uses E set to `1` when an extension is present and `0` otherwise.
- For the IGMPv3 Query wire layout, registry bit `0` is the top bit of the
  Flags/S/QRV octet. Do not map it to the least-significant bit of that octet.
- Preserve unassigned flag bits when callers set them explicitly.
- The S flag and QRV bits remain the existing IGMPv3 query fields; they are not
  entries in the IGMP/MLD Query Message Flags registry.

## IGMP/MLD Report Message Flags

| Bit | Short name | Description | Reference |
| --- | --- | --- | --- |
| `0` | `E` | Extension | RFC 9279 |
| `1..=15` | unassigned | Reserved for future Standards Action | RFC 9778 |

Implementation guidance:

- RFC 9778 maps these bit numbers to the flag columns in the IGMPv3 Report
  packet format from RFC 9776.
- RFC 9279 uses E set to `1` when an extension is present and `0` otherwise.
- For IGMPv3 Membership Report, the E-bit is registry bit `0` in the 16-bit
  report Flags field as mapped by RFC 9778 and IANA.
- Preserve unassigned flag bits when callers set them explicitly.
- Report flag bits `1..=15` have no assigned semantics today. Preserve them
  exactly; do not reject or reinterpret them during construction or decode.

## Minimal Generic Extension Surface

The extension implementation planned after this handoff should expose only the
source-backed generic surface:

- `Extension Type`, `Extension Length`, and raw `Extension Value` bytes for each
  TLV, preserving order.
- Generic metadata for No-op (`0`), unassigned (`1..=65533`), and experimental
  (`65534..=65535`) Extension Type ranges.
- E-bit helpers for IGMPv3 Query and IGMPv3 Membership Report only.
- Structured errors later for TLV header truncation, value truncation, leftover
  bytes after the final TLV, and declared total extension length beyond the IP
  payload remainder.

Unsupported without additional source evidence:

- Semantic subtypes for Extension Types other than No-op metadata.
- Query-only, report-only, ordering, dependency, or combination rules for
  future TLVs.
- Applying the extension mechanism to IGMPv1, IGMPv2, MRD, DVMRP, PIMv1,
  Cisco trace, multicast traceroute, or experimental IGMP Type messages.
- MLD packet construction or decode inside the IGMP module.
- Alignment or padding behavior not present in RFC 9279.

## RFC Reference Map

| Area | Current reference | Use in this plan |
| --- | --- | --- |
| IGMPv1 | RFC 1112 | Membership query/report compatibility and original IPv4 multicast host behavior |
| IGMPv2 | RFC 2236, updated by RFC 9776 | Membership report, leave group, and v2 compatibility behavior |
| IGMPv3 | RFC 9776 / STD 100 | Current query/report packet authority |
| IANA policy | RFC 9778 / BCP 57 | Type, Code, Query Flags, and Report Flags registry policy |
| Extensions | RFC 9279 | Extension flag and extension type registry |
| Multicast Router Discovery | RFC 4286 | IGMP types `0x30`, `0x31`, and `0x32` packet shapes only |
| Experimental Type values | RFC 9778 and IANA | IGMP Type range `0xf0..=0xff` |
| Experimental Extension values | RFC 9279 and IANA | Extension Type range `65534..=65535` |

## Non-Goals For Constants Steps

- Do not implement router, proxy, snooping, scanner, MIB, YANG, or multicast
  daemon behavior from these registries.
- Do not merge MLD with IGMP. The shared flag and extension registries are
  relevant evidence only; MLD remains ICMPv6-family behavior.
- Do not turn DVMRP, PIMv1, Cisco Trace, or multicast traceroute into typed
  message bodies unless a later step performs a dedicated source review.
