# IPv6 RFC Manifest

This manifest records the authoritative sources to use before enriching IPv6
support in `crafter`. It is intentionally a source document, not an
implementation design. Future IPv6 code, fixtures, pcaps, oracle dry-run
profiles, examples, and user-facing docs should trace wire-level facts back to
one of the reviewed records below.

Date checked: 2026-06-04. Reviewed authorities: RFC Editor RFC text and errata,
IETF Datatracker status and relationship records, IANA IPv6 Parameters, IANA
Assigned Internet Protocol Numbers, and the repo-local `rfc-protocol-spec`
source-discovery workflow.

## Classification Vocabulary

- **core**: Defines the IPv6 packet format or behavior that `crafter` must model
  to construct, decode, summarize, or preserve packets.
- **extension**: Defines an IPv6 extension header, option, routing type, or
  adjunct protocol that may be modeled as typed packet data.
- **registry**: IANA is the current authority for codepoint names, assignment
  state, registration rules, and later assignments.
- **operational**: Defines processing, deployment, security, PMTUD, or
  middlebox guidance that informs examples, validation, and docs but should not
  become automatic live behavior.
- **obsolete**: Defines deprecated wire behavior or a deprecation rule. It may
  still need decode/preserve coverage, but it should not be a generated default.
- **historical**: Superseded material useful only to understand references from
  older RFCs.
- **ambiguous**: Candidate or relationship that needs more review before it can
  support behavior changes.

## Primary Source Records

| Classification | Source | Current Datatracker / registry status | Scope for `crafter` | Errata review |
| --- | --- | --- | --- | --- |
| core | RFC 8200, Internet Protocol, Version 6 (IPv6) Specification | Internet Standard, STD 86. Datatracker says it obsoletes RFC 2460 and is updated by RFC 9673. | Current base authority for the 40-octet IPv6 header, Traffic Class field, Flow Label field, Payload Length, Next Header, Hop Limit, source/destination addresses, extension header chain rules, Hop-by-Hop Options, Destination Options, Routing Header base format, Fragment Header field layout, No Next Header, upper-layer pseudo-header inputs, and malformed/truncated packet expectations. `crafter` should construct and decode these fields, preserve caller overrides, and keep unknown Next Header payloads inspectable as raw data. Fragment generation, reassembly, and PMTUD probing remain out of scope for this base IPv6 manifest; packet-stream `IpFragment` and `IpDefrag` behavior is governed by [`docs/protocols/ip-fragment-source-manifest.md`](protocols/ip-fragment-source-manifest.md). | Verified: 5945, 5256. Reported: 8698. Held for Document Update: 5933, 6248, 5259, 5506. Rejected: 5170, 5171, 5172, 5173, 6003. |
| registry | IANA Assigned Internet Protocol Numbers | Last updated 2026-03-09. Registration procedure: IESG Approval or Standards Action. | Authority for the IPv4 Protocol / IPv6 Next Header number space. Relevant current rows include 0 HOPOPT, 43 IPv6-Route, 44 IPv6-Frag, 50 ESP, 51 AH, 58 IPv6-ICMP, 59 IPv6-NoNxt, 60 IPv6-Opts, and 135 Mobility Header. The registry also marks which protocol numbers are IPv6 Extension Header types. | No RFC errata; registry must be rechecked when codepoint behavior changes. |
| registry | IANA Internet Protocol Version 6 (IPv6) Parameters | Last updated 2025-12-24. Includes Next Header Types, IPv6 Extension Header Types, Destination Options and Hop-by-Hop Options, Routing Types, RPL-option-TLV, TaggerId Types, Segment Routing Header Flags, and Segment Routing Header TLVs. | Authority for IPv6-specific extension header and option codepoints. The old Next Header Types registry is closed in favor of the IPv6 Extension Header Types registry. Relevant rows include extension header numbers 0, 43, 44, 50, 51, 60, 135, 139, 140, 253, and 254; option types Pad1 0x00, PadN 0x01, Jumbo Payload 0xC2, Router Alert 0x05, and Home Address 0xC9; routing types 0 through 6, 253, 254, and reserved 255. | No RFC errata; registry references may include RFC errata, including RFC 8754 erratum 7081 for SRH TLVs. |
| operational | RFC 8201, Path MTU Discovery for IP version 6 | Internet Standard, STD 87. Datatracker says it obsoletes RFC 1981. | Authority for IPv6 PMTUD behavior and minimum-MTU guidance. Use for docs, examples, dry-run oracle profiles, and sizing notes. Do not implement live PMTUD probing by default. | No current RFC Editor errata groups found. |
| extension | RFC 2675, IPv6 Jumbograms | Proposed Standard. Datatracker says it obsoletes RFC 2147. | Defines the Jumbo Payload Hop-by-Hop option and the payload-length-zero jumbogram condition for links with MTU greater than 65,575 octets. Scope is parse/build/inspect of the option and related length invariants; no attempt to allocate huge buffers or force live jumbogram traffic by default. | Held for Document Update: 2175. |
| extension | RFC 2711, IPv6 Router Alert Option | Proposed Standard. Datatracker says it is updated by RFC 6398 and RFC 9805. IANA currently labels Router Alert deprecated for new protocols. | Defines the Router Alert Hop-by-Hop option. Scope is parse/build/preserve and summary display, not automatic router-intercept behavior. New generated defaults should avoid Router Alert unless a caller explicitly requests it. | No current RFC Editor errata groups found. |
| obsolete | RFC 5095, Deprecation of Type 0 Routing Headers in IPv6 | Proposed Standard. Datatracker says it updates RFC 2460 and RFC 4294. | Deprecation authority for Routing Header Type 0. `crafter` may decode and preserve RH0 bytes for inspection and malformed-packet work, but should mark the type deprecated and avoid emitting it by default. IANA Routing Types lists value 0 as Source Route (DEPRECATED). | No current RFC Editor errata groups found. |
| operational | RFC 6946, Processing of IPv6 "Atomic" Fragments | Proposed Standard. Datatracker says it updates RFC 2460 and RFC 5722. | Authority for Fragment Header inspection when Fragment Offset is zero and M flag is zero. Scope is field parsing, summary, and validation notes. Reassembly and fragment queue behavior remain out of scope. | Rejected: 3988. |
| operational | RFC 7045, Transmission and Processing of IPv6 Extension Headers | Proposed Standard. Datatracker says it updates RFC 2460 and RFC 2780. | Source for extension-header transmission/processing guidance and the IANA registry split that distinguishes Assigned Internet Protocol Numbers from IPv6 Extension Header Types. Use it to avoid treating every Next Header value as a structured IPv6 extension header. | No current RFC Editor errata groups found. |
| operational | RFC 7112, Implications of Oversized IPv6 Header Chains | Proposed Standard. Datatracker says it updates RFC 2460. | Source for the requirement that the first fragment contain the entire IPv6 header chain. `crafter` should expose enough Fragment/Header Chain information for tests and dry-run validation, but should not perform fragmentation or reassembly. | No current RFC Editor errata groups found. |
| extension | RFC 6275, Mobility Support in IPv6 | Proposed Standard. Datatracker says it obsoletes RFC 3775. | Defines Mobile IPv6 wire artifacts relevant to this IPv6 enrichment: Mobility Header protocol number 135, Home Address Destination Option, and Type 2 Routing Header. Scope is packet-layer parse/build/inspect of those artifacts only. Mobile IPv6 state machines, binding caches, return routability, home-agent behavior, and route optimization workflows are out of scope. | Verified: 3235, 5083, 5695. Rejected: 5898. |
| extension | RFC 8754, IPv6 Segment Routing Header (SRH) | Proposed Standard. Datatracker says it is updated by RFC 9800. | Defines Routing Type 4, SRH fields, Segment List encoding, SRH TLVs, and IANA SRH Flags/TLV registries. Scope is parse/build/inspect of SRH packets, not SRv6 endpoint behavior, SID execution, HMAC verification, policy installation, or live SR domain operation. | Verified: 7081, 7102. |

## IANA Registry Highlights

| Registry | Current authority facts to carry forward |
| --- | --- |
| Assigned Internet Protocol Numbers | IPv6 uses the same 8-bit number space as IPv4 Protocol for the Next Header field. Values marked as IPv6 Extension Header are not the whole protocol-number space. TCP is 6, UDP is 17, IPv6-ICMP is 58, No Next Header is 59. Unknown assigned or unassigned values should preserve the remaining bytes as raw payload when the enclosing IPv6 header is otherwise valid. |
| IPv6 Extension Header Types | Current rows include Hop-by-Hop Options 0, Routing 43, Fragment 44, ESP 50, AH 51, Destination Options 60, Mobility Header 135, HIP 139, Shim6 140, and experimental/testing 253 and 254. AH/ESP crypto is out of scope; packet-layer decode should not imply cryptographic support. |
| Destination Options and Hop-by-Hop Options | Pad1 and PadN come from RFC 2460 references retained by IANA but are covered by current RFC 8200. Jumbo Payload is RFC 2675. Router Alert is RFC 2711 and is deprecated for new protocols by current IANA state. Home Address is RFC 6275. Option Type action/change bits are defined by RFC 8200 Section 4.2, but see unresolved ambiguity for RFC 9673. |
| Routing Types | Source Route type 0 (RH0) is deprecated by RFC 5095, and Nimrod type 1 is also deprecated in the current IANA registry. Type 2 is Mobile IPv6 from RFC 6275, type 3 is RPL source routing, type 4 is SRH from RFC 8754, and types 5/6 are CRH-16/CRH-32. Values 7-252 are unassigned, 253 and 254 are RFC 3692-style experiments, and 255 is reserved. `crafter` should classify these values for inspection, preserve unknown or deprecated Routing Header bytes, and must not implement RH0 forwarding behavior or reject RH0 solely because it is deprecated. |
| Segment Routing Header Flags and TLVs | IANA tracks SRH flags and TLVs separately from generic IPv6 options. The SRH TLV registry references RFC 8754 and RFC erratum 7081. Newer rows such as the O-flag and later TLV assignments need review before any semantics beyond preservation are added. |

## Datatracker Relationship Digest

Datatracker relationships reviewed through the API:

| Record | Relationships reviewed |
| --- | --- |
| RFC 8200 | Obsoletes RFC 2460; contained by STD 86; updated by RFC 9673. |
| RFC 8201 | Obsoletes RFC 1981; contained by STD 87. |
| RFC 2675 | Obsoletes RFC 2147. |
| RFC 2711 | Updated by RFC 6398 and RFC 9805. |
| RFC 5095 | Updates RFC 2460 and RFC 4294. |
| RFC 6946 | Updates RFC 2460 and RFC 5722. |
| RFC 7045 | Updates RFC 2460 and RFC 2780. |
| RFC 7112 | Updates RFC 2460. |
| RFC 6275 | Obsoletes RFC 3775. |
| RFC 8754 | Updated by RFC 9800. |

## Historical And Superseded Material

The following sources were encountered through relationships or registry
references but should not be treated as the current base authority:

| Classification | Source | Use |
| --- | --- | --- |
| historical | RFC 2460 | Obsoleted by RFC 8200. Use only when older RFCs or IANA rows still cite it; interpret base IPv6 behavior through RFC 8200. |
| historical | RFC 1981 | Obsoleted by RFC 8201. |
| historical | RFC 2147 | Obsoleted by RFC 2675. |
| historical | RFC 3775 | Obsoleted by RFC 6275. |
| historical | RFC 2780 | Updated by RFC 7045 for extension-header registry handling. |
| historical | RFC 5722 | Still relevant through RFC 6946 for overlapping-fragment context, but reassembly is out of this scope. |

## Explicit Ambiguity And Follow-Up

- The repo-local `rfc-protocol-spec` discovery for the broad query `IPv6`
  returned many weak token-only candidates, including unrelated DHCP, DNS, PPP,
  and historical RFCs. For this manifest, the exact RFC and IANA sources named
  in the internal workflow step were manually reviewed against official sources. Future
  protocol facts should use targeted RFC numbers or registry names, not a broad
  `IPv6` keyword result.
- RFC 8200 is updated by RFC 9673, which was not in the original candidate list.
  Before implementing detailed Hop-by-Hop or Destination Option action handling
  beyond RFC 8200-compatible parsing/preservation, review RFC 9673 and the
  current IANA option registry.
- RFC 2711 is updated by RFC 6398 and RFC 9805, and IANA currently marks Router
  Alert as deprecated for new protocols. Treat Router Alert as an explicit,
  inspectable option, not a default behavior.
- RFC 8754 is updated by RFC 9800, and IANA SRH registries have assignments
  after RFC 8754. Typed SRH field parsing is in scope; endpoint behavior,
  SID semantics, HMAC verification, and later SRH TLV semantics require
  separate source review.
- Traffic Class is a core RFC 8200 field, but DSCP and ECN semantics are in
  RFC 2474, RFC 3168, and the IANA DSCP registries. Those sources must be
  reviewed before adding DSCP/ECN-specific helpers beyond raw Traffic Class bit
  access and preservation.
- Flow Label is a core RFC 8200 field, but nontrivial flow-label generation and
  recommendations are in RFC 6437. Preserve explicit Flow Label values and
  default conservatively until that source is reviewed.
- AH and ESP are listed as IPv6 Extension Header Types by IANA, but
  authentication, encryption, key management, and crypto verification are out of
  scope. Packet-layer preservation must not imply AH/ESP implementation.
- RFC 8200 inherited changes from several RFC 2460 updates, including RFC 5095,
  RFC 6946, RFC 7045, and RFC 7112. When a later source appears to conflict
  with RFC 8200 text, prefer the current Datatracker relationship graph and
  current errata before changing behavior.

## Source Links

- RFC 8200: https://datatracker.ietf.org/doc/rfc8200/
- RFC 8201: https://datatracker.ietf.org/doc/rfc8201/
- RFC 2675: https://datatracker.ietf.org/doc/rfc2675/
- RFC 2711: https://datatracker.ietf.org/doc/rfc2711/
- RFC 5095: https://datatracker.ietf.org/doc/rfc5095/
- RFC 6946: https://datatracker.ietf.org/doc/rfc6946/
- RFC 7045: https://datatracker.ietf.org/doc/rfc7045/
- RFC 7112: https://datatracker.ietf.org/doc/rfc7112/
- RFC 6275: https://datatracker.ietf.org/doc/rfc6275/
- RFC 8754: https://datatracker.ietf.org/doc/rfc8754/
- IANA IPv6 Parameters: https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml
- IANA Assigned Internet Protocol Numbers: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
- RFC Editor errata search: https://errata.rfc-editor.org/search/
