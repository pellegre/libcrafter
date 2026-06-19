# IGMP RFC Manifest

Reviewed: 2026-06-19

This manifest is the source handoff for implementing Internet Group Management
Protocol support in `crafter`. It records which protocol sources are suitable
for packet-layer work and which IGMP-related sources are obsolete, operational,
or out of scope for crate primitives.

## Retrieval

- Local protocol-facts checkout: `/home/e/practicas/rfc-protocol-spec`.
- Command run from the repository root:

  ```sh
  PYTHONPATH=/home/e/practicas/rfc-protocol-spec python3 -m proto manifest "IGMP" --json --brief --output-dir target/rfc-protocol-spec/igmp
  ```

- Generated artifacts:
  - `target/rfc-protocol-spec/igmp/protocol-manifest.json`
  - `target/rfc-protocol-spec/igmp/protocol-brief.md`
- Generation timestamp in the brief: `2026-06-19T23:18:00Z`.
- Protocol-facts source mode: cached RFC Editor index metadata from
  `/home/e/.cache/rfc-protocol-spec`; HTML fallback was not used.
- Official live checks, also performed on 2026-06-19:
  - RFC Editor: <https://www.rfc-editor.org/info/rfc9776/>
  - Datatracker/RFC text: <https://datatracker.ietf.org/doc/rfc9778/>
  - IANA IGMP registries:
    <https://www.iana.org/assignments/igmp-type-numbers/>

The generated manifest is useful for discovery, but it did not include full
cached RFC document text or selected IANA registry records. Use the official
links above, plus the RFC links below, as the source authority for packet facts
until the protocol-facts cache is refreshed with full documents and registries.

## Current Authoritative Sources

- RFC 1112, "Host Extensions for IP Multicasting":
  <https://www.rfc-editor.org/info/rfc1112/>
  - Role: IGMPv1 and IPv4 multicast host baseline.
  - Status from protocol-facts/RFC Editor index: Internet Standard.
  - Use for bootstrap compatibility with the original membership query and
    report forms.

- RFC 2236, "Internet Group Management Protocol, Version 2":
  <https://www.rfc-editor.org/info/rfc2236/>
  - Role: IGMPv2 membership report and leave-group compatibility.
  - Status from protocol-facts/RFC Editor index: Proposed Standard.
  - RFC 9776 updates RFC 2236. Keep RFC 2236 for v2 packet shape and
    compatibility review, but prefer RFC 9776 where it clarifies current IGMPv3
    interaction with v2 behavior.

- RFC 9776, "Internet Group Management Protocol, Version 3":
  <https://www.rfc-editor.org/info/rfc9776/>
  - Role: current IGMPv3 group membership protocol authority.
  - Official confirmation: RFC Editor lists it as STD 100 / Internet Standard,
    published March 2025, updating RFC 2236 and obsoleting RFC 3376.
  - Packet-layer facts to review before implementation: IPv4 protocol number 2,
    link-local forwarding expectations such as TTL 1 and Router Alert use,
    membership query format, version 3 membership report format, source-list
    behavior, and v1/v2 interoperability requirements.

- RFC 9778, "IANA Considerations for Internet Group Management Protocols":
  <https://www.rfc-editor.org/info/rfc9778/>
  - Role: current IANA policy authority for IGMP and MLD registries.
  - Official confirmation: Datatracker/RFC text lists it as BCP 57, March 2025,
    and obsoleting RFC 3228.
  - Packet-layer relevance: IGMP Type and Code fields are IANA-managed, Code
    values are scoped by Type, and the current registration procedure is
    Standards Action.

- IANA "Internet Group Management Protocol (IGMP) Type Numbers":
  <https://www.iana.org/assignments/igmp-type-numbers/>
  - Role: current codepoint registry.
  - Official confirmation: registry last updated 2025-03-28 and references
    RFC 9778.
  - Packet-layer codepoint snapshot for implementation planning:
    - `0x11`: IGMP Membership Query.
    - `0x12`: IGMPv1 Membership Report.
    - `0x16`: IGMPv2 Membership Report.
    - `0x17`: IGMPv2 Leave Group.
    - `0x22`: IGMPv3 Membership Report.
    - `0x30`, `0x31`, `0x32`: Multicast Router Discovery advertisement,
      solicitation, and termination.
    - `0xf0..=0xff`: reserved for experimentation.
    - Other registered types such as DVMRP, PIMv1, Cisco trace, and multicast
      traceroute are valid IGMP Type values but are not initial typed bodies.
  - Code-field snapshot:
    - Type `0x11` uses Code `0` for IGMPv1 and `1..=255` for IGMPv2 or later
      Max Response Time.
    - The listed report, leave, traceroute, and experiment ranges have no Code
      registrations at the time of review.

- RFC 9279, "IGMPv3 and MLDv2 Message Extension":
  <https://www.rfc-editor.org/info/rfc9279/>
  - Role: generic extension mechanism for later IGMPv3 extension work.
  - IANA snapshot: extension type `0` is No-op; `1..=65533` are unassigned;
    `65534..=65535` are reserved for experimental use. Query and report flag
    bit `0` is the extension flag; remaining bits are unassigned.
  - Implement extension bytes conservatively and byte-preservingly until the
    extension step performs a dedicated source review.

- RFC 4286, "Multicast Router Discovery":
  <https://www.rfc-editor.org/info/rfc4286/>
  - Role: packet shapes behind IANA IGMP types `0x30..=0x32`.
  - Use only for constructing and decoding MRD messages; do not implement
    multicast router state, discovery workflows, or daemons in `crafter`.

- RFC 2113, "IP Router Alert Option":
  <https://www.rfc-editor.org/info/rfc2113/>
  and RFC 6398, "IP Router Alert Considerations and Usage":
  <https://www.rfc-editor.org/info/rfc6398/>
  - Role: Router Alert option source for IPv4 composition guidance.
  - Use with the existing IPv4 option support. Do not make live Router Alert
    traffic the default path.

## Rejected Obsolete Sources

- RFC 988 and RFC 1054: older host extensions for IP multicasting, both
  obsoleted by RFC 1112.
- RFC 3228: old IGMP IANA considerations, obsoleted by RFC 9778.
- RFC 3376: old IGMPv3 specification, obsoleted by RFC 9776.
- RFC 2933 and RFC 3019: older management MIB documents, obsoleted by RFC 5519.
- RFC 3810: old MLDv2 source, obsoleted by RFC 9777 and not part of the IGMP
  crate surface.
- RFC 1885 and RFC 2463: obsolete ICMPv6 sources, outside IGMP.

## Ambiguous Or Out-Of-Scope Candidates

- RFC 9776 and RFC 9778 appeared in protocol-facts as ambiguous token matches
  because the local command relied on cached index metadata. They are promoted
  in this manifest only after official RFC Editor/Datatracker confirmation.
- RFC 9777, RFC 2710, and RFC 3810 are MLD/ICMPv6 sources. Keep them out of the
  IGMP module except when comparing shared IANA extension registries.
- RFC 4541, RFC 4605, RFC 6636, RFC 8652, RFC 9166, RFC 9251, and RFC 9398 are
  operational, proxy, snooping, tuning, YANG, or management documents. They can
  inform generated tools or docs, but they do not justify router, proxy,
  snooping, or management-plane code in `crafter`.
- RFC 4604 and RFC 5790 describe SSM or lightweight protocol behavior. Treat
  them as later review inputs, not bootstrap packet format authority.
- RFC 8114 and RFC 8220 are multicast service mapping or PIM-over-VPLS
  documents. They are not initial IGMP packet-layer sources.
- RFC 8507 is historic SIP material. It is not an IGMP source for this crate.
- RFC 5501 and RFC 7028 remained ambiguous in protocol-facts and are not packet
  authorities for this plan.

## Unresolved Questions

- The protocol-facts run reported missing full cached RFC documents for many
  selected RFCs, including RFC 1112, RFC 2236, RFC 4286, RFC 9279, RFC 9776,
  and RFC 9778. Later implementation steps must consult full official RFC text
  before encoding exact field layouts or validation rules.
- The generated manifest selected no IANA registries. Later codepoint steps
  should use the official IANA IGMP registry or a refreshed protocol-facts
  registry artifact before committing constants.
- DVMRP, PIMv1, Cisco trace, and multicast traceroute are registered in the
  IGMP Type space, but this plan has not yet decided whether they should be
  typed minimal messages, typed unknown metadata, or preserved `Raw` payloads.
- RFC 9279 extension handling needs a dedicated review before any typed TLV
  bodies beyond No-op and generic byte-preserving extension blocks are added.
- Provider-backed live IGMP validation may depend on multicast support,
  interface privileges, and lab topology. Live tests must remain dry-run or
  protected until those capabilities are explicit.

