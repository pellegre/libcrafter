# SSDP Source Manifest

This manifest is the evidence gate for SSDP packet support. Later SSDP
grammar, codepoint, constant, builder, fixture, oracle, probe, and guide work
must cite this document and then cite the specific source section used for each
wire fact. Do not rely on memory for SSDP methods, headers, status lines,
multicast destinations, service ports, URI forms, HTTP-like syntax, or malformed
input policy.

## Source Classes

- `core`: primary SSDP or UPnP authority for packet-level SSDP behavior.
- `base`: generic protocol authority needed to parse or serialize the
  surrounding syntax or transport.
- `extension`: optional behavior that is not part of the first core packet
  surface unless a later scope document admits it.
- `registry`: IANA or equivalent registry authority for assigned values.
- `mapping`: source that maps current behavior to older versions, lower layers,
  or scoped address forms.
- `operational`: source that informs safe validation or deployment behavior but
  is not itself a packet grammar.
- `obsolete`: source superseded by a newer authority.
- `historical`: source useful for context but not a direct implementation
  authority.
- `ambiguous`: source whose authority, applicability, or relationship must be
  resolved before downstream behavior can rely on it.

## Selected Sources

| Class | Source | Use in this project | Downstream gate |
| --- | --- | --- | --- |
| core | OCF / UPnP Forum, "UPnP Device Architecture 2.0", `https://openconnectivity.org/upnp-specs/UPnP-arch-DeviceArchitecture-v2.0-20200417.pdf` | Primary public UPnP discovery source for SSDP request, notify, response, and header behavior. | May define SSDP packet facts only after a later grammar or codepoint document cites exact discovery sections. |
| core | UPnP Forum, "UPnP Device Architecture 1.1", `https://upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1.pdf` | Compatibility authority for widely deployed UPnP 1.1 SSDP discovery traffic. | May be used when 2.0 differs or omits deployed 1.1 behavior; differences must be recorded before code depends on them. |
| mapping | UPnP Forum, "UPnP Device Architecture 1.1 Annex A - IPv6", `https://upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1-AnnexA.pdf` | Maps UPnP discovery behavior onto IPv6 multicast and link-local operation. | IPv6 constants and helpers must cite this plus the RFC/IANA IPv6 multicast sources below. |
| historical | UPnP Forum, "UPnP Device Architecture 1.0", `https://upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.0-20080424.pdf` | Context for legacy SSDP traffic and fixtures. | Do not prefer 1.0 over 1.1 or 2.0 unless the fixture is explicitly legacy. |
| historical, ambiguous | IETF Internet-Draft `draft-cai-ssdp-v1-03`, "Simple Service Discovery Protocol/1.0", `https://datatracker.ietf.org/doc/html/draft-cai-ssdp-v1-03` | Historical SSDP proposal and terminology source. | Expired draft material is not core authority. Any draft-only method, header, field, or behavior is blocked until a core UPnP source or an accepted extension admits it. |
| base | RFC 9110, "HTTP Semantics", `https://www.rfc-editor.org/rfc/rfc9110.html` | Current HTTP semantic baseline for method token, status code, field name, field value, and URI-reference concepts. | Use only for generic HTTP concepts that SSDP inherits; do not import client/server workflow, TCP behavior, caching, or negotiation into `crafter`. |
| base | RFC 9112, "HTTP/1.1", `https://www.rfc-editor.org/rfc/rfc9112.html` | Current HTTP/1.1 message syntax baseline for start lines, header section framing, and CRLF rules. | SSDP parsing must remain a conservative UDP payload shape gate, not a full HTTP stack. Differences from UPnP text must be resolved in the grammar document. |
| obsolete, mapping | RFC 2616, "Hypertext Transfer Protocol -- HTTP/1.1", `https://www.rfc-editor.org/rfc/rfc2616.html` | Historical HTTP reference used by older UPnP text. | Do not cite RFC 2616 for new behavior unless documenting what an older UPnP document referenced; map current syntax through RFC 9110/9112. |
| extension, historical | RFC 2774, "An HTTP Extension Framework", `https://www.rfc-editor.org/rfc/rfc2774.html` | Historical source for MAN and extension declaration syntax referenced by SSDP-era HTTP extension usage. | Generic HTTP extension behavior is blocked. Only UPnP-backed SSDP uses of MAN, EXT, and related headers may be implemented. |
| mapping | IETF status change, "Moving RFCs 2324, 2774, 5842 and 7168 to Historic", `https://datatracker.ietf.org/doc/status-change-http-experiments-to-historic/` | Datatracker evidence that RFC 2774 is historical context rather than current HTTP authority. | Later MAN/EXT helpers must cite UPnP discovery text, not RFC 2774 alone. |
| base | RFC 3986, "Uniform Resource Identifier (URI): Generic Syntax", `https://www.rfc-editor.org/rfc/rfc3986.html` | URI and URI-reference syntax for SSDP header values that carry URLs or URNs. | Header helpers may validate URI shape only where the UPnP source requires a URI class. Unknown or extension values must still be preserved. |
| base | RFC 2141, "URN Syntax", `https://www.rfc-editor.org/rfc/rfc2141.html` | Historical URN syntax for `urn:` values used in UPnP service and device identifiers. | Treat as mapping context unless a later codepoint document chooses a current URN authority for validation. |
| base | RFC 8141, "Uniform Resource Names (URNs)", `https://www.rfc-editor.org/rfc/rfc8141.html` | Current URN syntax authority. | Do not reject older UPnP examples solely because they predate RFC 8141; preserve unknown values. |
| base | RFC 768, "User Datagram Protocol", `https://www.rfc-editor.org/rfc/rfc768.html` | UDP transport authority. | SSDP is an application payload over UDP; UDP checksum, length, and ports stay in the existing UDP layer. |
| base | RFC 791, "Internet Protocol", `https://www.rfc-editor.org/rfc/rfc791.html` | IPv4 packet baseline when SSDP is composed over IPv4. | No SSDP-specific IPv4 behavior may be inferred beyond the UPnP, multicast, and registry sources. |
| base | RFC 8200, "Internet Protocol, Version 6 (IPv6) Specification", `https://www.rfc-editor.org/rfc/rfc8200.html` | IPv6 packet baseline when SSDP is composed over IPv6. | No SSDP-specific IPv6 behavior may be inferred beyond UPnP Annex A, multicast RFCs, and IANA assignments. |
| mapping | RFC 1112, "Host Extensions for IP Multicasting", `https://www.rfc-editor.org/rfc/rfc1112.html` | IPv4 multicast host behavior context. | Use with IANA and UPnP sources for IPv4 multicast destination constants only; do not implement membership management in the packet layer. |
| mapping | RFC 2365, "Administratively Scoped IP Multicast", `https://www.rfc-editor.org/rfc/rfc2365.html` | Context for administratively scoped IPv4 multicast ranges that include common SSDP addresses. | Packet helpers may expose constants but must not infer routing, TTL, or scope policy without exact UPnP evidence. |
| mapping | RFC 5771, "IANA Guidelines for IPv4 Multicast Address Assignments", `https://www.rfc-editor.org/rfc/rfc5771.html` | Current IPv4 multicast assignment and registry relationship. | Use as registry context only; exact SSDP address authority should come from IANA plus UPnP discovery text. |
| mapping | RFC 4291, "IPv6 Addressing Architecture", `https://www.rfc-editor.org/rfc/rfc4291.html` | IPv6 multicast address and scope syntax. | Use with IANA and UPnP Annex A for IPv6 multicast constants; do not guess scope behavior. |
| mapping | RFC 3306, "Unicast-Prefix-based IPv6 Multicast Addresses", `https://www.rfc-editor.org/rfc/rfc3306.html` | IPv6 multicast format context. | Not a source for SSDP group assignments unless later evidence requires it. |
| mapping | RFC 3307, "Allocation Guidelines for IPv6 Multicast Addresses", `https://www.rfc-editor.org/rfc/rfc3307.html` | IPv6 multicast assignment and registry context. | Exact SSDP group constants must come from IANA and UPnP Annex A. |
| registry | IANA Service Name and Transport Protocol Port Number Registry, `https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=ssdp` | Authority for registered SSDP service name and transport port assignments. | Port constants and default UDP decode bindings must cite this registry plus UPnP discovery text. |
| registry | IANA IPv4 Multicast Address Space Registry, `https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml` | Authority for assigned IPv4 multicast group records. | IPv4 SSDP multicast constants must cite the exact registry row and UPnP discovery text. |
| registry | IANA IPv6 Multicast Address Space Registry, `https://www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xhtml` | Authority for assigned IPv6 multicast group records. | IPv6 SSDP multicast constants must cite the exact registry row and UPnP Annex A. |
| registry | IANA HTTP Method Registry, `https://www.iana.org/assignments/http-methods/http-methods.xhtml` | Registry cross-check for method names. | Absence from the registry is not rejection authority for UPnP-defined SSDP methods. Unknown methods remain preservable values. |
| registry | IANA HTTP Field Name Registry, `https://www.iana.org/assignments/http-fields/http-fields.xhtml` | Registry cross-check for HTTP field names. | Absence from the registry is not rejection authority for UPnP-defined SSDP headers. Unknown headers remain preservable ordered fields. |
| datatracker | IETF Datatracker RFC metadata pages, e.g. `https://datatracker.ietf.org/doc/rfc9112/` and `https://datatracker.ietf.org/doc/rfc3986/` | Source for RFC status, updates, and obsoletes relationships. | Before freezing behavior from an RFC, check whether Datatracker marks the document obsolete, updated, or historical. |
| errata | RFC Editor errata search pages, e.g. `https://www.rfc-editor.org/errata_search.php?rfc=9112`, `https://www.rfc-editor.org/errata_search.php?rfc=9110`, `https://www.rfc-editor.org/errata_search.php?rfc=3986`, `https://www.rfc-editor.org/errata_search.php?rfc=768`, `https://www.rfc-editor.org/errata_search.php?rfc=1112`, `https://www.rfc-editor.org/errata_search.php?rfc=8200`, `https://www.rfc-editor.org/errata_search.php?rfc=4291`, and `https://www.rfc-editor.org/errata_search.php?rfc=3307` | Errata authority for source-backed corrections to base protocol text. | Any parser, serializer, constant, or fixture that depends on a subtle RFC rule must re-check accepted errata for the exact RFC section. |
| operational | UPnP Device Architecture discovery guidance in the core UPnP sources | Timing, advertisement, search, and response behavior that can inform probe and lab dry-runs. | Do not add daemon, scanner, retry, cache, or control-point behavior to the crate. Generated tools own workflows above the packet primitive. |

## Authority Order

1. For SSDP packet behavior, prefer current OCF / UPnP Device Architecture 2.0
   discovery text.
2. Use UPnP Device Architecture 1.1 when supporting deployed compatibility or
   when the 2.0 text delegates to earlier UPnP discovery behavior.
3. Use UPnP Annex A plus RFC/IANA multicast sources for IPv6 mapping.
4. Use RFC 9110/9112 only for generic HTTP-like syntax and semantics that UPnP
   explicitly reuses.
5. Use IANA registries for assigned service ports, multicast groups, HTTP
   method names, and HTTP field names; registry absence does not invalidate a
   UPnP-defined SSDP value.
6. Treat expired drafts, older UPnP versions, obsolete RFCs, and historical
   HTTP extension documents as context until a later step explicitly maps their
   behavior to a core source.

## Blocked Until Later Evidence

- Do not implement an SSDP method, status-code rule, header helper, multicast
  constant, service port binding, URI parser, or body rule until a later
  grammar or codepoint document cites a core/base/registry source above.
- Do not reject unknown but structurally valid SSDP methods, status codes,
  reason phrases, headers, extension values, or bodies solely because they are
  absent from an IANA registry.
- Do not decode every UDP payload on the SSDP service port as SSDP. A later
  grammar step must define the conservative shape gate; unrelated text or
  binary payloads must remain `Raw`.
- Do not implement search retry timing, advertisement lifetime management,
  service caches, control-point behavior, device daemons, or live discovery
  workflows in `crafter`.
- Do not implement TCP, HTTP over TCP, HTTP upgrade, generic HTTP extension
  processing, or UPnP eventing as part of the SSDP packet layer.
- Do not add IPv6 multicast scope defaults beyond exact UPnP Annex A and IANA
  evidence. Link-local and site-local behavior must not be guessed.

## Unresolved Questions

- unresolved: The initial crate target must choose how to reconcile UPnP Device
  Architecture 2.0 with widely deployed 1.1 traffic. Until step 03 classifies
  authority, builders should not assume version-specific required headers that
  are not common or explicitly mapped.
- unresolved: Older UPnP text references RFC 2616 while current HTTP syntax is
  split across RFC 9110 and RFC 9112. Step 04 must map the exact SSDP grammar
  to current HTTP syntax and record any intentional deviations.
- unresolved: SSDP uses MAN and EXT-style extension headers, while RFC 2774 is
  historical. Step 05 or step 50 must decide whether helpers cite only UPnP
  discovery text or also retain limited RFC 2774 mapping notes.
- unresolved: Draft-only SSDP material, including any pre-UPnP method names,
  header names, or search targets, remains blocked unless later source review
  finds a current UPnP or registry-backed reason to preserve it as a named
  helper. Generic preservation of unknown values is still required.
- unresolved: IPv6 SSDP multicast helpers need exact scope behavior from UPnP
  Annex A, IANA, and the IPv6 multicast RFCs before constants beyond the
  assigned group records can be exported.
- unresolved: Body handling must be source-checked. The packet layer must
  preserve bodies in structurally valid messages, but builders should not
  generate non-empty bodies until a core source justifies that behavior.
