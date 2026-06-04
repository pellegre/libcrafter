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
  and non-atomic datagrams, the requirement that ID values are used only for
  fragmentation and reassembly, and the remaining uniqueness requirements for
  non-atomic datagram sources. Source:
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
| Identification | 16 bits | RFC 791 sections 2.3 and 3.1; RFC 6864 sections 4.1-4.3 | ID distinguishes fragments of one non-atomic datagram from another. RFC 6864 says the field is meaningful for fragmentation/reassembly and may be arbitrary for atomic datagrams. `crafter` uses a deterministic default ID for reproducible packet construction, preserves explicit IDs, and does not provide global ID generation or uniqueness tracking. |
| Flags | 3 bits | RFC 791 sections 2.3 and 3.1; RFC 6864 section 4.3 | The flags field contains the reserved bit, Don't Fragment (DF), and More Fragments (MF). DF=1 datagrams must not be fragmented. `crafter` may expose flags and preserve malformed/reserved-bit overrides; it does not fragment packets. |
| Fragment Offset | 13 bits | RFC 791 sections 2.3 and 3.1 | Fragment Offset gives the fragment position in 8-octet units. Decode may type the IPv4 layer for fragments, but non-initial fragments remain `Raw` above IPv4 because transport headers cannot be interpreted without reassembly. |
| Time to Live (TTL) | 8 bits | RFC 791 sections 2.4 and 3.1; RFC 1122 section 3.2.1.7; IANA IPv4 Parameters | TTL bounds datagram lifetime and is decremented by nodes that process/forward it. RFC 1122 says hosts must not send TTL zero. IANA records the current recommended default TTL as 64. |
| Protocol | 8 bits | RFC 791 section 3.1; IANA Assigned Internet Protocol Numbers | Protocol identifies the next-level protocol in the IPv4 payload. IANA is the current source for numeric labels and constants. Unknown values must keep the IPv4 layer typed and preserve the remaining payload as `Raw`. |
| Header Checksum | 16 bits | RFC 791 section 3.1; RFC 1122 section 3.2.1.2 | The checksum covers the IPv4 header only. It is recomputed when mutable header fields change. Compile fills it unless explicitly set; decode records valid vs invalid checksum status without making the packet uninspectable. |
| Source Address | 32 bits | RFC 791 sections 2.3 and 3.1; RFC 1122 section 3.2.1.3 | The source address is a four-octet IPv4 address. `crafter` validates wire length and preserves the address value; address assignment, routing, and host-interface ownership checks are outside the packet primitive. |
| Destination Address | 32 bits | RFC 791 sections 2.3 and 3.1; RFC 1122 section 3.2.1.3 | The destination address is a four-octet IPv4 address. Broadcast, multicast, loopback, and special-use routing policy are not implemented by `crafter`; packet bytes remain inspectable. |
| Options and Padding | Variable, up to IHL | RFC 791 sections 3.1 and 3.2; RFC 1122 section 3.2.1.8; IANA IPv4 Parameters | Options follow the fixed 20-octet header and are padded with zero octets to a 32-bit boundary. EOOL and NOP are one-octet options; other options carry type, length, and data. Decode must report malformed option envelopes with structured context. |

## TTL Defaults And Non-Goals

- **Source facts:** RFC 791 defines TTL as an 8-bit upper bound on IPv4
  datagram lifetime and describes decrement during internet header processing.
  RFC 1122 says hosts must not send TTL zero and must expose a way to set TTL.
  IANA IPv4 Parameters records the current recommended default TTL as 64.
- **`crafter` default behavior:** `Ipv4::new()` uses TTL 64, matching the IANA
  recommended default. `compile()` writes the configured or default TTL field
  value and preserves explicit caller-provided TTL values.
- **Explicit non-goals:** `crafter` does not implement routing or decrement TTL
  during compile or decode. Route selection, forwarding, gateway TTL
  expiration, ICMP Time Exceeded generation caused by forwarding, and hop-by-hop
  checksum recomputation after TTL decrement are not crate primitive
  responsibilities.

## IPv4 Identification And RFC 6864

- **Source facts:** RFC 6864 defines atomic datagrams as `DF=1`, `MF=0`, and
  fragment offset `0`; non-atomic datagrams either allow fragmentation
  (`DF=0`) or already carry fragment metadata (`MF=1` or nonzero fragment
  offset). RFC 6864 says the Identification field has no meaning for atomic
  datagrams, may be set to any value in those datagrams, and must be ignored by
  devices that examine atomic IPv4 headers. For non-atomic datagrams, RFC 6864
  retains the source requirement not to repeat IPv4 ID values within one MDL for
  a given source address, destination address, and protocol tuple.
- **`crafter` default behavior:** `Ipv4::new()` uses deterministic packet
  builder defaults: Identification `1`, flags `0`, and fragment offset `0`.
  That default is for reproducible offline construction and tests; it is not a
  per-source, per-destination, per-protocol ID allocator. `compile()` writes the
  configured or default Identification value and never attempts global
  uniqueness management.
- **Explicit override behavior:** `.identification(...)` and the compatibility
  `.id(...)` alias set the exact 16-bit field value to compile. Decode preserves
  the wire Identification value for inspection, summary, and re-encode.
- **Explicit non-goals:** `crafter` does not generate globally unique IPv4 IDs,
  maintain fragment caches, enforce RFC 6864 non-atomic source rate limits,
  perform fragmentation, perform reassembly, or assign reassembly semantics to
  the Identification field beyond exposing and preserving the header value.

## DSCP And ECN Evidence

| Field | Bits in DS/TOS octet | Source | Behavior |
| --- | ---: | --- | --- |
| DSCP | 0-5 (six most significant bits) | RFC 2474 section 3; IANA DSCP registry | DSCP is a six-bit codepoint, so helper values must fit 0..63. IANA is authoritative for names such as CS0-CS7, AF classes, EF, VOICE-ADMIT, LE, and NQB. |
| ECN | 6-7 (two least significant bits) | RFC 3168 section 5; IANA DSCP/ECN registry | ECN values are `00` Not-ECT, `01` ECT(1), `10` ECT(0), and `11` CE. Helpers must compose with DSCP without changing the other six bits unless requested. |
| Historical TOS compatibility | Full octet | RFC 791 section 3.1; RFC 2474 section 3; IANA IPv4 Parameters | The old IP TOS and Type-of-Service Values registries are deprecated after RFC 2474. Existing `tos` APIs should remain aliases for the raw octet, while new docs and summaries prefer DS field terminology. |

## Protocol Number Evidence

The IANA Assigned Internet Protocol Numbers registry is the current authority
for IPv4 Protocol field and IPv6 Next Header numeric assignments. The table
below records values that are currently exported by `crafter` and the planned
additions named for this enrichment. The IANA keyword and protocol-name columns
should drive future constants, labels, and summaries; protocol-specific RFCs
are still required before adding body encoders or decoders.

| Value | IANA keyword | IANA protocol name | IPv6 extension header | `crafter` coverage | Source-backed behavior |
| ---: | --- | --- | :---: | --- | --- |
| 0 | HOPOPT | IPv6 Hop-by-Hop Option | Y | Current `IpProtocol::HopByHop`; IPv6 module constant `IPPROTO_IPV6_HOPOPTS` | Assigned by IANA. In IPv4, no body decoder is implied by the enum value; unsupported payload remains `Raw`. |
| 1 | ICMP | Internet Control Message |  | Current `IPPROTO_ICMP` and `IpProtocol::Icmp` | ICMP for IPv4. Decode may dispatch when the control header is complete and fragment offset is zero. |
| 6 | TCP | Transmission Control |  | Current `IPPROTO_TCP` and `IpProtocol::Tcp` | TCP. Decode may dispatch only when fragment offset is zero and enough payload exists for a self-consistent TCP header. |
| 17 | UDP | User Datagram |  | Current `IPPROTO_UDP` and `IpProtocol::Udp` | UDP. Decode may dispatch only when fragment offset is zero and enough payload exists for a self-consistent UDP datagram. |
| 41 | IPv6 | IPv6 encapsulation |  | Current `IPPROTO_IPV6` and `IpProtocol::Ipv6` | Assigned IPv6-in-IPv4 encapsulation value. Until encapsulated IPv6 dispatch is explicitly implemented, preserve payload as `Raw`. |
| 47 | GRE | Generic Routing Encapsulation |  | Planned protocol constant and label | Assigned GRE value. Adding a constant or label is source-backed; GRE header encode/decode requires GRE-specific evidence. |
| 50 | ESP | Encap Security Payload | Y | Planned protocol constant and label | Assigned ESP value and also an IPv6 extension header type. Payload remains opaque unless ESP-specific support is added. |
| 51 | AH | Authentication Header | Y | Planned protocol constant and label | Assigned AH value and also an IPv6 extension header type. Payload remains opaque unless AH-specific support is added. |
| 58 | IPv6-ICMP | ICMP for IPv6 |  | Current `IPPROTO_ICMPV6` and `IpProtocol::Icmpv6` | Assigned ICMPv6 value. It can identify an IPv4 payload by number, but ICMPv6 body behavior follows ICMPv6 evidence and checksum rules. |
| 89 | OSPFIGP | OSPFIGP |  | Planned protocol constant and label | Assigned OSPF IGP value. Adding the number and label is source-backed; OSPF packet support requires OSPF-specific evidence. |
| 132 | SCTP | Stream Control Transmission Protocol |  | Planned protocol constant and label | Assigned SCTP value. Adding the number and label is source-backed; SCTP chunk encode/decode requires SCTP-specific evidence. |
| 148-252 | Unassigned | Unassigned |  | No constants planned | Unassigned as of the reviewed IANA registry. Decode must preserve payload as `Raw` unless a future registry update assigns a value. |
| 253 |  | Use for experimentation and testing | Y | Planned experiment/testing label only | RFC 3692-style experiment value. Helpers must not use it as a production default. |
| 254 |  | Use for experimentation and testing | Y | Planned experiment/testing label only | RFC 3692-style experiment value. Helpers must not use it as a production default. |
| 255 |  | Reserved |  | No constant planned | Reserved by IANA. Decode preserves payload as `Raw`. |

## Option Evidence

| Option or option area | Source | Behavior |
| --- | --- | --- |
| Option type envelope | RFC 791 section 3.1; IANA IPv4 Parameters | The option type byte is split into copied flag, class, and option number. EOOL (0) and NOP (1) are one octet. All other options use type, one-octet length, then length-2 data bytes. |
| EOOL and NOP | RFC 791 section 3.1; IANA IPv4 Parameters | EOOL marks the end of options; NOP provides alignment. Compile pads the IPv4 header to a 32-bit boundary with zero octets when options do not naturally align. |
| Timestamp (TS) | RFC 791 section 3.1; IANA IPv4 Parameters | Timestamp is option value 68. Typed timestamp helpers require RFC 791 evidence for pointer, overflow, flags, and timestamp/address encodings before behavior changes. |
| Record Route (RR), Loose Source Route (LSR), Strict Source Route (SSR) | RFC 791 section 3.1; RFC 1122 section 3.2.1.8; IANA IPv4 Parameters | These route options have pointer-address list semantics. `crafter` may preserve and inspect raw or typed forms, but it does not route packets or act as an intermediate hop. |
| Traceroute (TR) | RFC 1393; IANA IPv4 Parameters | Existing or future Traceroute option behavior must cite RFC 1393 for the option data layout. |
| Router Alert (RTRALT) | RFC 2113; IANA IPv4 Parameters | Router Alert is option value 148. The Router Alert value registry is separate; value 0 means routers examine the packet. Typed support must cite RFC 2113 and IANA Router Alert values. |
| Experiment options | RFC 4727; IANA IPv4 Parameters | IPv4 option values 30, 94, 158, and 222 are RFC 3692-style experiment values. `Ipv4OptionKind` classifies these values for inspection. Helpers must not ship these as production defaults. |
| Unknown or unsupported options | RFC 1122 section 3.2.1.8; IANA IPv4 Parameters | Unknown options must be preserved enough for inspection. Malformed option lengths must return structured errors and must never panic or loop. |

## Fragmentation Evidence And Explicit Exclusion

| Area | Source | Behavior |
| --- | --- | --- |
| Fragmentation fields | RFC 791 sections 2.3 and 3.1; RFC 6864 sections 4.1-4.3 | Identification, flags, and fragment offset are supported IPv4 header fields. Builders, decode, summaries, and re-encode preserve those field values, including explicit reserved, DF, MF, and offset values that fit the wire fields. |
| Fragment identity | RFC 791 section 2.3; RFC 6864 sections 4.1-4.3 | Reassembly identity uses source address, destination address, protocol, and Identification. This fact only informs decode and summaries; `crafter` does not implement reassembly. |
| Atomic datagrams | RFC 6864 sections 4.1-4.3 | For atomic datagrams, the IPv4 ID has no fragmentation/reassembly meaning and may be arbitrary. `crafter` must not invent uniqueness requirements for atomic packet construction. |
| Non-initial fragments | RFC 791 section 2.3 | A nonzero fragment offset means the payload begins in the middle of the original datagram. Decode keeps payload as `Raw` and does not dispatch to a transport decoder without reassembly context. |
| Offset-zero MF fragments | RFC 791 section 2.3 | A fragment offset of zero means the payload starts at the original datagram payload. If MF is set and transport decode succeeds, `crafter` may type the transport layer. If the payload is too short, internally inconsistent, unknown, or unsupported, the remaining payload is preserved as `Raw`. |
| Fragment generation | RFC 791 section 2.3 | IPv4 fragmentation generation is explicitly out of scope. `crafter` can expose fields needed to build a datagram that already carries fragment metadata, but it must not split payloads into fragments in this work. |
| Reassembly | RFC 791 section 2.3; RFC 1122 sections 3.2.1.4 and 3.3.2 | IPv4 fragment reassembly, fragment caches, timers, overlap policy, and stack delivery of reassembled data are explicitly out of scope. |

Focused tests pin this policy in
`crafter/tests/ipv4_public_api.rs::fragment_fields_roundtrip_supported_flags_and_offsets`,
`crafter/tests/ipv4_public_api.rs::fragment_fields_reject_invalid_offset`, and
the `crafter/src/protocols/ip.rs::ipv4_fragment_info` tests
`noninitial_fragment_udp_payload_decodes_as_raw_without_udp_layer`,
`noninitial_fragment_tcp_payload_decodes_as_raw_without_tcp_layer`,
`initial_fragment_decode_types_complete_udp_header`,
`initial_fragment_decode_preserves_truncated_udp_header_as_raw`, and
`initial_fragment_decode_preserves_unknown_protocol_payload_as_raw`.

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
  routing, TTL decrement, fragmentation generation, and reassembly remain
  outside this manifest's implementation scope.
