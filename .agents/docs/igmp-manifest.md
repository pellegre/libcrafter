# IGMP Source Handoff

Reviewed: 2026-06-19

This is the agent-facing source handoff for IGMP work in `crafter`. The full
review record is in `docs/igmp-rfc-manifest.md`.

## Retrieval Summary

- Protocol-facts command used:

  ```sh
  PYTHONPATH=$RFC_PROTOCOL_SPEC python3 -m proto manifest "IGMP" --json --brief --output-dir target/rfc-protocol-spec/igmp
  ```

- Generated artifacts:
  - `target/rfc-protocol-spec/igmp/protocol-manifest.json`
  - `target/rfc-protocol-spec/igmp/protocol-brief.md`
- Official live confirmations used for current authority:
  - RFC 9776: <https://www.rfc-editor.org/info/rfc9776/>
  - RFC 9778: <https://www.rfc-editor.org/info/rfc9778/>
  - IANA IGMP Type Numbers:
    <https://www.iana.org/assignments/igmp-type-numbers/>

The local protocol-facts run succeeded but only had cached RFC index metadata
and did not extract wire facts. Treat this handoff as a reviewed manifest, not
as a substitute for full RFC section review in each implementation step.

## Implementation Source Order

- Bootstrap IGMP fixed header and decode:
  - RFC 9776 for current IGMPv3 framing expectations.
  - IANA IGMP Type Numbers for current Type and Code assignments.
  - RFC 1112 for IGMPv1 compatibility.
- IGMPv2 compatibility:
  - RFC 2236 for v2 Membership Report and Leave Group packet behavior.
  - RFC 9776 where it updates RFC 2236 for current v3 interoperability.
- IGMPv3 query and report:
  - RFC 9776 as the current Internet Standard and RFC 3376 replacement.
- IANA and flags:
  - RFC 9778 and the live IANA IGMP registries.
- Generic extensions:
  - RFC 9279 and the IANA extension type and flag registries.
- Multicast Router Discovery:
  - RFC 4286 and IANA types `0x30`, `0x31`, and `0x32`.
- Router Alert composition:
  - RFC 2113 and RFC 6398, using existing IPv4 option helpers.

## Packet-Layer Boundaries

- Implement `crafter` packet primitives only: layers, builders, decode,
  summaries, fixtures, oracle cases, and live validation gates.
- Do not implement a multicast router, snooping switch, proxy, scanner, MIB,
  YANG model, or full IGMP state machine in the crate.
- Keep MLD in the ICMPv6 family. Shared IANA extension text does not make MLD
  part of the IGMP module.
- Preserve unknown but valid IGMP Type values as inspectable bytes until a
  source-backed typed body is explicitly added.

## Current Codepoint Handoff

Use the official IANA registry before coding constants. The reviewed snapshot
for planning is:

- `0x11`: IGMP Membership Query.
- `0x12`: IGMPv1 Membership Report.
- `0x16`: IGMPv2 Membership Report.
- `0x17`: IGMPv2 Leave Group.
- `0x22`: IGMPv3 Membership Report.
- `0x30..=0x32`: Multicast Router Discovery messages.
- `0xf0..=0xff`: reserved for experimentation.
- Query Code `0`: IGMPv1.
- Query Code `1..=255`: IGMPv2 or later Max Response Time.
- RFC 9279 extension type `0`: No-op.
- RFC 9279 extension types `65534..=65535`: experimental use.
- Query and report flag bit `0`: extension flag.

## Rejected Or Deferred Sources

- Reject as obsolete for packet authority: RFC 988, RFC 1054, RFC 3228,
  RFC 3376, RFC 2933, RFC 3019, RFC 3810, RFC 1885, and RFC 2463.
- Defer as operational or management guidance unless a later step narrows a
  wire-level fact: RFC 4541, RFC 4604, RFC 4605, RFC 5519, RFC 5790, RFC 6636,
  RFC 8114, RFC 8220, RFC 8652, RFC 9166, RFC 9251, and RFC 9398.
- Exclude from IGMP implementation: MLD-only sources RFC 2710, RFC 3810, and
  RFC 9777, except for shared IANA extension registry comparisons.

## Open Follow-Ups

- Refresh protocol-facts with full RFC documents and IANA registries if later
  steps need machine-extracted field evidence.
- Decide in the codepoint step whether non-core registered IGMP types such as
  DVMRP, PIMv1, Cisco trace, and multicast traceroute remain `Raw` or get typed
  minimal metadata.
- Validate provider multicast support before any live IGMP run; dry-run and
  protected gates remain mandatory.

