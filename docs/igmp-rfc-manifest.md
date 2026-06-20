# IGMP RFC Manifest

Reviewed: 2026-06-20

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
  - Packet-layer facts reviewed from the full RFC text: IGMPv2 keeps the
    8-octet host/router fixed header with Type, Max Response Time, Checksum,
    and Group Address; adds Type `0x16` Version 2 Membership Report and Type
    `0x17` Leave Group; retains Type `0x11` Query and Type `0x12` Version 1
    Membership Report compatibility; treats Max Response Time as meaningful
    only for Query messages; and computes the checksum over the whole IGMP
    message/IP payload, including any bytes beyond the fixed header.

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

- RFC 3569, "An Overview of Source-Specific Multicast (SSM)":
  <https://www.rfc-editor.org/info/rfc3569/>
  and RFC 4604, "Using IGMPv3 and MLDv2 for Source-Specific Multicast":
  <https://www.rfc-editor.org/info/rfc4604/>
  - Role: Source-Specific Multicast context and IGMPv3/MLDv2 behavior
    guidance.
  - Packet-layer relevance: use as source-filtering and SSM-awareness
    guidance when interpreting IGMPv3 source lists and record types. Do not
    promote SSM routing policy, host API behavior, or router compatibility
    mode into `crafter` primitives.

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
- RFC 4604 describes SSM-aware IGMPv3/MLDv2 behavior and is retained here as
  source-filtering guidance, not bootstrap packet format authority. RFC 5790
  describes lightweight protocol behavior and remains a later review input.
- RFC 8114 and RFC 8220 are multicast service mapping or PIM-over-VPLS
  documents. They are not initial IGMP packet-layer sources.
- RFC 8507 is historic SIP material. It is not an IGMP source for this crate.
- RFC 5501 and RFC 7028 remained ambiguous in protocol-facts and are not packet
  authorities for this plan.

## IGMPv2 Compatibility Review

RFC 2236 updates the RFC 1112 IGMPv1 host model by reusing the fixed 8-octet
IGMP header and assigning the second octet as Max Response Time for membership
queries. RFC 9776 is the current complete IGMP protocol specification, so
`crafter` should treat RFC 2236 as compatibility packet-shape authority rather
than as the final protocol behavior model.

Fields shared with the base `Igmp` layer:

- Type: `0x11` Membership Query, `0x12` IGMPv1 Membership Report, `0x16`
  IGMPv2 Membership Report, and `0x17` Leave Group are all fixed-header message
  forms.
- Code/Max Response Time: for Type `0x11`, RFC 2236 uses this byte as a linear
  Max Response Time in tenths of a second; for reports and leave messages it is
  sent as zero and ignored by receivers. Preserve explicit caller values.
- Checksum: computed over the whole IGMP message/IP payload. This matches the
  existing crate rule that an IGMP layer owns following IGMP payload bytes for
  checksum purposes.
- Group Address: zero for a General Query, the queried group for a
  Group-Specific Query, and the reported or left multicast group for report and
  leave messages. Later validation should expose helpers but still preserve
  representable overrides.

Message types newly supported by the IGMPv2 phase are Type `0x16` Version 2
Membership Report and Type `0x17` Leave Group. Type `0x11` Query gains the
IGMPv2 Max Response Time interpretation, while Type `0x12` remains IGMPv1
compatibility behavior.

Operational behavior remains out of crate scope: querier election, host/router
state machines, timers, report suppression, leave retransmission, v1/v2/v3
compatibility-mode transitions, and the RFC 9776 translation of older reports
and leaves into internal IGMPv3 state are generated-tool or stack concerns, not
packet-layer primitives. IPv4 destination addresses such as all-systems
`224.0.0.1` and all-routers `224.0.0.2`, TTL 1, and Router Alert composition
belong in send-plan guidance, examples, and tests rather than implicit IGMP
layer mutation.

## IGMPv3 Packet-Shape Review

RFC 9776 is the current Internet Standard for IGMPv3 and the source authority
for the Version 3 packet shapes implemented by this plan. It obsoletes RFC
3376 and updates RFC 2236; therefore RFC 3376 is historical context only, while
RFC 2236 remains the compatibility source for Version 2 fixed-header messages
and legacy interoperation. RFC 9776 still requires IGMPv3 implementations to
support the legacy IGMPv1 Membership Report, IGMPv2 Membership Report, and
IGMPv2 Leave Group message types for interoperation, but `crafter` models those
as packet-layer compatibility formats rather than protocol state.

In-scope IGMPv3 wire structures:

- Membership Query, Type `0x11`, with the Version 3 query extension after the
  shared fixed header: Max Resp Code, Checksum, Group Address, Flags/S/QRV,
  QQIC, Number of Sources, and a vector of IPv4 unicast source addresses.
- Query variants as packet shapes: General Query has zero Group Address and
  zero sources; Group-Specific Query has a multicast Group Address and zero
  sources; Group-and-Source Specific Query has a multicast Group Address and
  one or more source addresses. IPv4 destination address selection is an IPv4
  composition concern, not hidden mutation inside the IGMP layer.
- IGMPv3 Membership Report, Type `0x22`, with Reserved, Checksum, Flags,
  Number of Group Records, and a sequence of Group Records.
- Group Records with Record Type, Aux Data Len, Number of Sources, Multicast
  Address, source-address vector, and optional auxiliary bytes. RFC 9776
  defines no auxiliary data semantics; preserve received bytes and expose
  lengths rather than inventing typed bodies.
- Source lists, Max Resp Code, QQIC, QRV, the S flag, and registry-managed
  query/report flags as wire fields. Encoding, decoding, display, and optional
  validation are in scope; timer scheduling and operational interpretation are
  not.

Compatibility and version distinctions:

- RFC 9776 distinguishes Query versions by packet shape: an 8-octet Query with
  Max Resp Code zero is IGMPv1-compatible, an 8-octet Query with nonzero Max
  Resp Code is IGMPv2-compatible, and a Query of at least 12 octets is IGMPv3.
- RFC 9776 says additional received Query or Report octets beyond the described
  fields are included in checksum verification and otherwise ignored by an
  implementation. For `crafter`, those bytes should remain inspectable and
  byte-preserving; generated stacks or probes can decide whether to treat them
  as operationally invalid.
- Unrecognized IGMP message types are ignored by IGMP implementations, but
  `crafter` should keep them representable and inspectable as typed metadata
  plus `Raw` payload where the fixed header can be parsed.

IGMPv3 Membership Report implementation handoff:

- RFC 9776 Sections 4.2 through 4.2.13 and Figures 4 and 5 are the packet
  authority for report decoding and construction. A report body is Type
  `0x22`, one reserved octet, 16-bit checksum, 16-bit report Flags, 16-bit
  Number of Group Records (`M`), followed by exactly `M` Group Record blocks.
- The report reserved octet defaults to zero on transmit and is ignored on
  receive. The checksum covers the whole IGMP message / IPv4 payload, including
  any preserved trailing report bytes.
- A Group Record is Record Type (`u8`), Aux Data Len (`u8`), Number of Sources
  (`u16`), Multicast Address (`Ipv4Addr`), `N` IPv4 Source Address entries,
  then `Aux Data Len * 4` auxiliary octets. Its minimum wire length is
  `8 + 4 * N + 4 * Aux Data Len` bytes.
- RFC 9776 defines these Group Record Type values: `1` `MODE_IS_INCLUDE`, `2`
  `MODE_IS_EXCLUDE`, `3` `CHANGE_TO_INCLUDE_MODE`, `4`
  `CHANGE_TO_EXCLUDE_MODE`, `5` `ALLOW_NEW_SOURCES`, and `6`
  `BLOCK_OLD_SOURCES`.
- RFC 9776 defines no auxiliary data semantics for IGMPv3. Normal transmit
  defaults should use Aux Data Len zero, but `crafter` must preserve decoded
  auxiliary bytes and explicit caller-supplied auxiliary bytes for malformed,
  extension, or exploratory packets.
- Unrecognized Group Record Type values are silently ignored by IGMP
  implementations. For `crafter`, they are not decode errors: parse the common
  Group Record shape, preserve the unknown type byte, sources, auxiliary bytes,
  and any report-level trailing data for inspection and round-trip work.

Source-Specific Multicast guidance:

- RFC 9776 adds source filtering through INCLUDE/EXCLUDE filter modes and
  source lists. RFC 3569 describes SSM as channel membership identified by a
  source and group, and RFC 4604 provides SSM-aware IGMPv3/MLDv2 behavior
  guidance.
- For packet primitives, SSM guidance affects diagnostics and optional
  validation helpers only. For example, RFC 9776 notes that SSM-aware hosts
  should not send EXCLUDE-mode records for SSM addresses because SSM-aware
  routers ignore them. The crate should preserve such packets when explicitly
  built or decoded, while later tools can flag them for probe expectations.
- RFC 4604 is operational SSM guidance for host/router behavior and configured
  SSM address ranges. Do not use it to reject otherwise well-formed report or
  Group Record bytes at construction or decode time unless a later validation
  step deliberately adds an opt-in diagnostic.

Out of crate scope:

- Socket state, interface state, router group/source state, querier election,
  response scheduling, report suppression, robustness-variable timers, and
  v1/v2/v3 compatibility-mode transitions are host/router stack behavior.
- Forwarding decisions, PIM/SSM routing policy, multicast router discovery
  workflows, and live interoperability checks belong in generated tools,
  oracle specs, probe specs, or provider-backed live validation. The crate
  should expose the bytes, metadata, builders, decode results, summaries, and
  optional validation helpers those tools need.

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
