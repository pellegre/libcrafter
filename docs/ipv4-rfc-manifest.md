# IPv4 RFC Manifest

This manifest records the IPv4 behavior that `crafter` will use for
source-backed compile, decode, display, fixture, and oracle work. It is
intentionally narrow: `crafter` remains a packet primitive. It builds and
decodes individual IPv4 datagrams, fills dependent header fields on
`compile()`, preserves deliberate overrides, and keeps unsupported or unknown
payloads inspectable. It does not implement an IP stack, routing, PMTUD state,
fragment generation, fragment reassembly, fragment caches, timers, overlap
handling, or stack delivery semantics.

Date checked: 2026-06-04 (RFC Editor, IANA Assigned Internet Protocol Numbers,
IANA IPv4 Parameters, and IANA DSCP/ECN registries reviewed on this date).

The local `rfc-protocol-spec` discovery and manifest workflow was run for the
broad query `IPv4`. As expected for such a broad term, the automated result
included many ambiguous and unrelated candidates. The curated source set below
is the authority for this IPv4 work; model memory and noisy discovery output are
not authority.

## Source Authority And How To Read This Manifest

Every new IPv4 wire behavior must trace to one of the entries below before
code, tests, fixtures, docs, or oracle specs rely on it. "Normative for wire
behavior" means the source defines bytes that `crafter` must construct, fill,
or decode correctly. "Registry authority" means IANA is the current source for
names, numeric assignments, or registry status. "Guidance only" informs
documentation, diagnostics, or exclusions but does not add a serialized field
by itself.

## Source Set

### Normative for wire behavior

- **RFC 791 - Internet Protocol** defines the IPv4 base header format, Version,
  IHL, Type of Service, Total Length, Identification, flags, Fragment Offset,
  TTL, Protocol, Header Checksum, source and destination addresses, option
  encoding, padding, fragmentation, and reassembly model. Source:
  https://www.rfc-editor.org/rfc/rfc791.html
- **RFC 1122 - Requirements for Internet Hosts - Communication Layers** records
  host requirements for IPv4, including version handling, checksum validation,
  TTL guidance, option handling, malformed option robustness, and
  fragmentation/reassembly requirements. Source:
  https://www.rfc-editor.org/rfc/rfc1122.html
- **RFC 2474 - Definition of the Differentiated Services Field (DS Field) in
  the IPv4 and IPv6 Headers** replaces the historical IPv4 TOS octet with the
  DS field and defines the six-bit DSCP layout. Source:
  https://www.rfc-editor.org/rfc/rfc2474.html
- **RFC 3168 - The Addition of Explicit Congestion Notification (ECN) to IP**
  defines the two low-order ECN bits in the IPv4 DS/TOS octet and the Not-ECT,
  ECT(1), ECT(0), and CE codepoints. Source:
  https://www.rfc-editor.org/rfc/rfc3168.html
- **RFC 6864 - Updated Specification of the IPv4 ID Field** updates the meaning
  of the IPv4 Identification field, especially the distinction between atomic
  and non-atomic datagrams and the requirement that ID values are used only for
  fragmentation and reassembly. Source:
  https://www.rfc-editor.org/rfc/rfc6864.html

### Registry authority

- **IANA Assigned Internet Protocol Numbers** is the authority for IPv4
  Protocol field numeric assignments, names, keywords, experimental values, and
  reserved/unassigned ranges. The registry was last updated 2026-03-09 when
  reviewed. Source:
  https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
- **IANA Internet Protocol Version 4 (IPv4) Parameters** is the authority for
  IPv4 option numbers, Router Alert option values, the current recommended
  default TTL, and the deprecated status of the old TOS registries. The
  registry was last updated 2018-05-03 when reviewed. Source:
  https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
- **IANA Differentiated Services Field Codepoints (DSCP)** is the authority for
  current DSCP codepoint names, DSCP pool status, and ECN field registrations.
  The registry was last updated 2026-05-13 when reviewed. Source:
  https://www.iana.org/assignments/dscp-registry/dscp-registry.xhtml

### Option-specific and guidance sources

- **RFC 2113 - IP Router Alert Option** defines the Router Alert option wire
  format and the value zero meaning "router shall examine packet". It is
  required before typed Router Alert construction or decode behavior is added.
  Source: https://www.rfc-editor.org/rfc/rfc2113.html
- **RFC 1393 - Traceroute Using an IP Option** defines the Traceroute option
  recorded in the IANA IPv4 Parameters registry. It is required before changing
  typed Traceroute option behavior. Source:
  https://www.rfc-editor.org/rfc/rfc1393.html
- **RFC 4727 - Experimental Values in IPv4, IPv6, ICMPv4, ICMPv6, UDP, and
  TCP Headers** defines RFC 3692-style IPv4 option experiment values listed by
  IANA. It is required before adding named helpers for IPv4 option experiment
  values. Source: https://www.rfc-editor.org/rfc/rfc4727.html
- **RFC 7126 - Recommendations on Filtering of IPv4 Packets Containing IPv4
  Options** is guidance for operational risk around IPv4 options. It does not
  define new `crafter` wire encodings, but it informs documentation and test
  scope for options. Source: https://www.rfc-editor.org/rfc/rfc7126.html

## IPv4 Core Header Evidence

| Area | Size | Source | Source-backed behavior for `crafter` |
| --- | ---: | --- | --- |
| Version | 4 bits | RFC 791 section 3.1; RFC 1122 section 3.2.1.1 | IPv4 datagrams carry version 4. Decode must reject non-4 enclosing headers with a structured error rather than panicking. |
| Internet Header Length (IHL) | 4 bits | RFC 791 section 3.1 | IHL is the header length in 32-bit words. The minimum valid IPv4 header is 5 words (20 octets); the maximum encodable header is 15 words (60 octets). Compile fills IHL from fixed header plus options plus padding unless explicitly set. |
| DS field / historical TOS octet | 8 bits | RFC 791 section 3.1; RFC 2474 section 3; RFC 3168 section 5; IANA DSCP registry | The old TOS octet is now interpreted as a six-bit DSCP plus two-bit ECN field. `.tos()` remains a compatibility alias for the full octet; new helpers should use DS field, DSCP, and ECN terminology. |
| Total Length | 16 bits | RFC 791 section 3.1 | Total Length is the length in octets of IPv4 header plus data. Compile fills it from header and payload length unless explicitly set. Decode must respect the total-length boundary and preserve bytes after that boundary as following `Raw` data. |
| Identification | 16 bits | RFC 791 sections 2.3 and 3.1; RFC 6864 sections 4.1-4.3 | ID distinguishes fragments of one non-atomic datagram from another. RFC 6864 says the field is meaningful for fragmentation/reassembly and may be arbitrary for atomic datagrams. Compile must preserve explicit IDs. |
| Flags | 3 bits | RFC 791 sections 2.3 and 3.1; RFC 6864 section 4.3 | The flags field contains the reserved bit, Don't Fragment (DF), and More Fragments (MF). DF=1 datagrams must not be fragmented. `crafter` may expose flags and preserve malformed/reserved-bit overrides; it does not fragment packets. |
| Fragment Offset | 13 bits | RFC 791 sections 2.3 and 3.1 | Fragment Offset gives the fragment position in 8-octet units. Decode may type the IPv4 layer for fragments, but non-initial fragments remain `Raw` above IPv4 because transport headers cannot be interpreted without reassembly. |
| Time to Live (TTL) | 8 bits | RFC 791 sections 2.4 and 3.1; RFC 1122 section 3.2.1.7; IANA IPv4 Parameters | TTL bounds datagram lifetime and is decremented by nodes that process/forward it. RFC 1122 says hosts must not send TTL zero. IANA records the current recommended default TTL as 64. |
| Protocol | 8 bits | RFC 791 section 3.1; IANA Assigned Internet Protocol Numbers | Protocol identifies the next-level protocol in the IPv4 payload. IANA is the current source for numeric labels and constants. Unknown values must keep the IPv4 layer typed and preserve the remaining payload as `Raw`. |
| Header Checksum | 16 bits | RFC 791 section 3.1; RFC 1122 section 3.2.1.2 | The checksum covers the IPv4 header only. It is recomputed when mutable header fields change. Compile fills it unless explicitly set; decode records valid vs invalid checksum status without making the packet uninspectable. |
| Source Address | 32 bits | RFC 791 sections 2.3 and 3.1; RFC 1122 section 3.2.1.3 | The source address is a four-octet IPv4 address. `crafter` validates wire length and preserves the address value; address assignment, routing, and host-interface ownership checks are outside the packet primitive. |
| Destination Address | 32 bits | RFC 791 sections 2.3 and 3.1; RFC 1122 section 3.2.1.3 | The destination address is a four-octet IPv4 address. Broadcast, multicast, loopback, and special-use routing policy are not implemented by `crafter`; packet bytes remain inspectable. |
| Options and Padding | Variable, up to IHL | RFC 791 sections 3.1 and 3.2; RFC 1122 section 3.2.1.8; IANA IPv4 Parameters | Options follow the fixed 20-octet header and are padded with zero octets to a 32-bit boundary. EOOL and NOP are one-octet options; other options carry type, length, and data. Decode must report malformed option envelopes with structured context. |

## DSCP And ECN Evidence

| Field | Bits in DS/TOS octet | Source | Behavior |
| --- | ---: | --- | --- |
| DSCP | 0-5 (six most significant bits) | RFC 2474 section 3; IANA DSCP registry | DSCP is a six-bit codepoint, so helper values must fit 0..63. IANA is authoritative for names such as CS0-CS7, AF classes, EF, VOICE-ADMIT, LE, and NQB. |
| ECN | 6-7 (two least significant bits) | RFC 3168 section 5; IANA DSCP/ECN registry | ECN values are `00` Not-ECT, `01` ECT(1), `10` ECT(0), and `11` CE. Helpers must compose with DSCP without changing the other six bits unless requested. |
| Historical TOS compatibility | Full octet | RFC 791 section 3.1; RFC 2474 section 3; IANA IPv4 Parameters | The old IP TOS and Type-of-Service Values registries are deprecated after RFC 2474. Existing `tos` APIs should remain aliases for the raw octet, while new docs and summaries prefer DS field terminology. |

## Protocol Number Evidence

| Protocol value or range | Source | Behavior |
| --- | --- | --- |
| 0-147 | IANA Assigned Internet Protocol Numbers | Assigned protocol numbers have IANA keywords and labels. Public constants and summaries should use IANA names when added. |
| 1 | IANA Assigned Internet Protocol Numbers; RFC 792 | ICMP for IPv4. Decode may dispatch when the transport/control header is complete and the fragment offset is zero. |
| 6 | IANA Assigned Internet Protocol Numbers; RFC 9293 | TCP. Decode may dispatch only when the fragment offset is zero and enough payload exists for a self-consistent TCP header. |
| 17 | IANA Assigned Internet Protocol Numbers; RFC 768 | UDP. Decode may dispatch only when the fragment offset is zero and enough payload exists for a self-consistent UDP header. |
| 148-252 | IANA Assigned Internet Protocol Numbers | Unassigned as of the reviewed registry. Decode preserves payload as `Raw` unless later registry updates and decoders are added. |
| 253-254 | IANA Assigned Internet Protocol Numbers; RFC 3692 | Reserved for experimentation and testing. Helpers must not treat experiment values as production defaults. |
| 255 | IANA Assigned Internet Protocol Numbers | Reserved. Decode preserves payload as `Raw`. |

## Option Evidence

| Option or option area | Source | Behavior |
| --- | --- | --- |
| Option type envelope | RFC 791 section 3.1; IANA IPv4 Parameters | The option type byte is split into copied flag, class, and option number. EOOL (0) and NOP (1) are one octet. All other options use type, one-octet length, then length-2 data bytes. |
| EOOL and NOP | RFC 791 section 3.1; IANA IPv4 Parameters | EOOL marks the end of options; NOP provides alignment. Compile pads the IPv4 header to a 32-bit boundary with zero octets when options do not naturally align. |
| Timestamp (TS) | RFC 791 section 3.1; IANA IPv4 Parameters | Timestamp is option value 68. Typed timestamp helpers require RFC 791 evidence for pointer, overflow, flags, and timestamp/address encodings before behavior changes. |
| Record Route (RR), Loose Source Route (LSR), Strict Source Route (SSR) | RFC 791 section 3.1; RFC 1122 section 3.2.1.8; IANA IPv4 Parameters | These route options have pointer-address list semantics. `crafter` may preserve and inspect raw or typed forms, but it does not route packets or act as an intermediate hop. |
| Traceroute (TR) | RFC 1393; IANA IPv4 Parameters | Existing or future Traceroute option behavior must cite RFC 1393 for the option data layout. |
| Router Alert (RTRALT) | RFC 2113; IANA IPv4 Parameters | Router Alert is option value 148. The Router Alert value registry is separate; value 0 means routers examine the packet. Typed support must cite RFC 2113 and IANA Router Alert values. |
| Experiment options | RFC 4727; IANA IPv4 Parameters | IPv4 option values 30, 94, 158, and 222 are RFC 3692-style experiment values. Helpers must not ship these as production defaults. |
| Unknown or unsupported options | RFC 1122 section 3.2.1.8; IANA IPv4 Parameters | Unknown options must be preserved enough for inspection. Malformed option lengths must return structured errors and must never panic or loop. |

## Fragmentation Evidence And Explicit Exclusion

| Area | Source | Behavior |
| --- | --- | --- |
| Fragment identity | RFC 791 section 2.3; RFC 6864 sections 4.1-4.3 | Reassembly identity uses source address, destination address, protocol, and Identification. This fact only informs decode and summaries; `crafter` does not implement reassembly. |
| Atomic datagrams | RFC 6864 sections 4.1-4.3 | For atomic datagrams, the IPv4 ID has no fragmentation/reassembly meaning and may be arbitrary. `crafter` must not invent uniqueness requirements for atomic packet construction. |
| Non-initial fragments | RFC 791 section 2.3 | A nonzero fragment offset means the payload begins in the middle of the original datagram. Decode should keep payload as `Raw` rather than dispatching to a transport decoder without reassembly context. |
| Fragment generation | RFC 791 section 2.3 | Fragmentation generation is explicitly out of scope. `crafter` can expose fields needed to build a datagram that already carries fragment metadata, but it must not split payloads into fragments in this work. |
| Reassembly | RFC 791 section 2.3; RFC 1122 sections 3.2.1.4 and 3.3.2 | Fragment reassembly, fragment caches, timers, overlap policy, and stack delivery of reassembled data are explicitly out of scope. |

## Decode And Compile Guardrails

- `compile()` fills unset IHL, total length, protocol number from the next
  layer, option padding, and header checksum according to the evidence above.
- Explicit values that fit their wire fields are preserved, including values
  that are deliberately wrong for malformed-packet tests.
- Unknown protocol numbers and unsupported protocol payloads remain inspectable
  as `Raw`.
- Decode errors for enclosing IPv4 header malformation must be structured:
  truncated fixed header, invalid version, invalid IHL, total length shorter
  than header length, or option length overrun must not panic.
- Bytes after the IPv4 Total Length boundary are outside the datagram and are
  preserved as a following `Raw` layer.
- Live packet transmission, captures, scanner behavior, router behavior,
  fragmentation generation, and reassembly remain outside this manifest's
  implementation scope.
