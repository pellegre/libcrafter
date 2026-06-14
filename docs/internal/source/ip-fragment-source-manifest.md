# IP Fragment Transform Source Manifest

This manifest records the authoritative source facts for the planned
`IpFragment` and `IpDefrag` packet-stream transforms. It is intentionally
narrow: it governs packet-shaped fragmentation and defragmentation transforms,
not a full IPv4 or IPv6 stack.

Date checked: 2026-06-07. Reviewed authorities: RFC Editor HTML for RFC 791,
RFC 792, RFC 1191, RFC 6864, RFC 6946, RFC 7112, RFC 8200, RFC 8201, and
RFC 4443. The repo-local `rfc-protocol-spec` broad discovery workflow was run
for IP fragmentation terms and produced many unrelated candidates, as expected
for broad IP searches. A targeted manifest helper run did not complete in this
environment, so this file is a hand-curated official-source manifest. Model
memory and implementation behavior in operating systems are not authority for
new wire behavior.

## Scope Decision

This manifest updates the earlier IPv4 and IPv6 manifests that kept fragment
generation and reassembly out of scope. Those exclusions remain true for the
base protocol-layer builder/decoder work they documented, but this plan adds
two explicit wire transforms:

- `IpFragment`: a transmit-side `PacketTransform` that emits packet-shaped
  IPv4 or IPv6 fragments for an explicit MTU.
- `IpDefrag`: a receive-side `PacketTransform` that consumes fragment
  `PacketRecord`s and emits a packet-shaped reassembled `PacketRecord` when
  source-backed conditions are satisfied.

The transforms do not implement routing, forwarding, ICMP error generation,
PMTUD caches, PLPMTUD probing, TCP stream reassembly, application object
reassembly, or live traffic from the developer machine. ICMP and ICMPv6 MTU
feedback is validation context only.

## Source Set

### Normative for transform wire behavior

- **RFC 791 - Internet Protocol** defines IPv4 fragmentation and reassembly
  fields, 8-octet fragment offsets, Don't Fragment and More Fragments behavior,
  source/destination/protocol/identification reassembly identity, affected
  header fields, total-length updates, and header checksum recomputation.
  Source: https://www.rfc-editor.org/rfc/rfc791.html
- **RFC 6864 - Updated Specification of the IPv4 ID Field** updates RFC 791
  and RFC 1122 by defining the IPv4 Identification field only for fragmentation
  and reassembly, distinguishing IPv4 atomic and non-atomic datagrams, and
  preserving non-atomic ID uniqueness requirements. Source:
  https://www.rfc-editor.org/rfc/rfc6864.html
- **RFC 8200 - Internet Protocol, Version 6 (IPv6) Specification** is the
  current IPv6 base authority for the Fragment Header, source-only IPv6
  fragmentation, per-fragment headers, fragmentable part, reassembly rules,
  duplicate and overlap behavior, and IPv6 packet size requirements. Source:
  https://www.rfc-editor.org/rfc/rfc8200.html
- **RFC 6946 - Processing of IPv6 "Atomic" Fragments** updates IPv6 atomic
  fragment handling: Fragment Header with offset zero and M flag zero is
  processed in isolation from other fragments with the same source,
  destination, and identification. Source:
  https://www.rfc-editor.org/rfc/rfc6946.html
- **RFC 7112 - Implications of Oversized IPv6 Header Chains** updates IPv6
  behavior around first fragments that do not include the complete header chain
  through the upper-layer header. Source:
  https://www.rfc-editor.org/rfc/rfc7112.html

### Validation and MTU-feedback context only

- **RFC 792 - Internet Control Message Protocol** defines ICMPv4 Destination
  Unreachable type 3 code 4 for "fragmentation needed and DF set" and Time
  Exceeded type 11 code 1 for fragment reassembly timeout. Source:
  https://www.rfc-editor.org/rfc/rfc792.html
- **RFC 1191 - Path MTU Discovery** updates the ICMPv4 type 3 code 4 message
  with a Next-Hop MTU field and defines the field as the largest IPv4 datagram
  size, including IP header and data, that could be forwarded without
  fragmentation at that router. Source:
  https://www.rfc-editor.org/rfc/rfc1191.html
- **RFC 4443 - ICMPv6 for IPv6** defines ICMPv6 Packet Too Big type 2 code 0,
  its MTU field, and ICMPv6 Time Exceeded code 1 for fragment reassembly
  timeout. Source: https://www.rfc-editor.org/rfc/rfc4443.html
- **RFC 8201 - Path MTU Discovery for IPv6** defines IPv6 PMTUD behavior,
  including reducing PMTU estimates from Packet Too Big messages and not
  reducing a PMTU estimate below the IPv6 minimum link MTU. Source:
  https://www.rfc-editor.org/rfc/rfc8201.html

## IPv4 Fragmentation Facts

| Area | Source-backed behavior for `IpFragment` and `IpDefrag` |
| --- | --- |
| Fragment detection | A whole IPv4 datagram has MF clear and fragment offset zero. A fragmented or fragmentable non-atomic datagram has DF clear, MF set, or a nonzero fragment offset. |
| Reassembly identity | Fragments are associated by source address, destination address, protocol, and Identification. IPv4 ID must not be used for unrelated duplicate-detection or tracing semantics. |
| IPv4 ID updates | For atomic datagrams, defined by RFC 6864 as `DF=1`, `MF=0`, and offset `0`, the ID may be arbitrary and receivers must ignore it. For non-atomic datagrams, sources must not repeat IDs within one MDL for a given source/destination/protocol tuple. |
| Offset and byte ranges | Fragment Offset is in 8-octet units. A fragment's payload byte range starts at `fragment_offset * 8` and has length `total_length - ihl_bytes`. Non-final fragments produced by `IpFragment` must carry payload lengths that are multiples of 8 octets. |
| Don't Fragment | If DF is set and a datagram is too large for the configured MTU, default `IpFragment` behavior must not emit fragments. It should return a structured error or explicit non-fragmenting trace result, according to the public transform options. |
| Header fields changed by fragmentation | RFC 791 names options, MF, Fragment Offset, IHL, Total Length, and Header Checksum as fields affected by fragmentation. `IpFragment` must recompute per-fragment total length and checksum through existing compile behavior unless an explicit caller override is intentionally preserved by the API contract. |
| IPv4 options | RFC 791 says some options are copied to all fragments and others remain in the first fragment only. Initial support must either implement the copied-bit option rule for the options it fragments or reject/pass through unsupported option-bearing packets with explicit trace metadata. It must not blindly copy all options while claiming source-backed correctness. |
| Reassembly completion | `IpDefrag` needs first-fragment header context, final total data length from the fragment with MF clear, and complete coverage of byte ranges from offset zero to the final length. The reassembled IPv4 packet must carry corrected Total Length and Header Checksum. |
| Duplicates and overlaps | Exact duplicate fragments may be accepted and recorded as duplicates. RFC 791's example procedure overwrites overlapping data with the most recently arrived bytes, but this transform must not silently emit ambiguous conflicting payload bytes; conflicting overlaps become structured ambiguity/error metadata and no reassembled payload is emitted for that datagram. |
| State bounds | RFC 791 describes timer-bounded reassembly resources. `IpDefrag` must additionally expose implementation bounds by age, datagram count, and byte count, and eviction must be inspectable through trace metadata. |

## IPv6 Fragment Header Facts

| Area | Source-backed behavior for `IpFragment` and `IpDefrag` |
| --- | --- |
| Fragment Header shape | RFC 8200 Section 4.5 defines an 8-octet Fragment Header with Next Header, an 8-bit reserved field, 13-bit Fragment Offset, 2 reserved bits, M flag, and 32-bit Identification. |
| Reserved fields | Reserved Fragment Header fields are initialized to zero on transmission and ignored on reception. Decode should preserve and report nonzero reserved bits rather than treating them as a hard parse failure. |
| Source-only fragmentation | IPv6 fragmentation is performed only by source nodes. `IpFragment` may emit source fragments for an explicit MTU; it must not model routers fragmenting IPv6 packets. |
| Fragmentation unit | The Fragmentable Part is divided into fragments sized to fit the path MTU. Every complete fragment except the last must be an integer multiple of 8 octets. `IpFragment` must not create overlapping fragments. |
| Per-fragment headers | Fragment packets carry the Per-Fragment headers from the original packet, change the last Per-Fragment Next Header to 44, and insert a Fragment Header whose Next Header identifies the first header after the Per-Fragment headers in the original packet. |
| First-fragment contents | Extension headers, if any, and the upper-layer header must be in the first fragment. If they cannot fit in the configured MTU, the transform must report unsupported/too-small MTU rather than emitting nonconformant fragments. |
| Reassembly identity | RFC 8200 reassembles only from packets with the same Source Address, Destination Address, and Fragment Identification. This is a source-backed correction to the plan text that mentioned final next-header in the IPv6 key. `IpDefrag` must not require a matching Fragment Header Next Header value to group fragments. |
| Reassembled chain repair | The Fragment Header is absent from the final reassembled packet. The last Per-Fragment Next Header is restored from the offset-zero fragment's Fragment Header Next Header, and Payload Length is recomputed from the first and last fragment lengths and offsets. |
| Varying fragment headers | RFC 8200 allows different pre-Fragment headers and different Fragment Header Next Header values across fragments of the same original packet. Only values from the offset-zero fragment are retained or used for reassembly; differences should be recorded in metadata when observed. |
| Atomic fragments | RFC 8200 and RFC 6946 define a Fragment Header with offset zero and M flag zero as a whole datagram. It is processed in isolation, has the Fragment Header removed, and must not be merged with or flush state for other fragments with the same source, destination, and identification. |
| Timeout | If enough fragments are not received within 60 seconds of the first-arriving fragment, reassembly is abandoned. `IpDefrag` may use a stricter configured age bound, but eviction must be explicit in trace metadata. |
| Invalid non-final length | A fragment whose fragmentable data length is not a multiple of 8 octets while M is set is invalid for reassembly. The transform should mark it invalid and not use it to complete a datagram. |
| Oversized reassembly | If a fragment's length and offset would make the reassembled IPv6 Payload Length exceed 65,535 octets, the datagram must not be emitted by the narrow transform. Jumbogram behavior is outside this plan. |
| Overlaps and duplicates | Overlap during IPv6 reassembly requires abandoning that packet. Exact duplicate fragments may be detected and dropped while keeping the remaining fragments for the packet. |
| Narrow extension-header scope | Initial IPv6 transform support should cover plain IPv6 plus extension-header chains already represented by the crate and needed for tests. Chains outside that supported subset must fail with structured errors or pass through with explicit trace metadata; they must not be partially rewritten silently. |

## MTU Feedback Context

The transforms consume explicit MTU configuration. They do not learn MTU from
ICMP, cache PMTU, retransmit, or notify upper layers.

- IPv4 validation may observe ICMP Destination Unreachable type 3 code 4.
  RFC 1191 adds the Next-Hop MTU field to that message. This informs oracle and
  lab checks but does not require `IpFragment` to implement PMTUD.
- IPv6 validation may observe ICMPv6 Packet Too Big type 2 code 0 with an MTU
  field. RFC 8201 says a node must not reduce a PMTU estimate below the IPv6
  minimum link MTU from a Packet Too Big message. This is PMTUD state-machine
  behavior and is out of scope for the transform.
- RFC 8200 requires every IPv6 Internet link to support an MTU of at least
  1280 octets. Offline tests may use smaller explicit MTUs to exercise planner
  errors and tight header calculations, but any live provider artifact using a
  sub-1280 IPv6 link MTU must document that it is a constrained lab condition,
  not normal IPv6 Internet behavior.

## Plan-Facing Corrections

- IPv6 `IpDefrag` grouping must use source address, destination address, and
  Fragment Identification only. The final/Fragment Header Next Header value is
  metadata and offset-zero repair input, not a key component.
- IPv6 reserved Fragment Header fields are ignored on reception by RFC 8200.
  They should be inspectable metadata, not automatic hard decode failures.
- IPv4 conflicting overlaps are not given a single modern deterministic merge
  rule by the reviewed source set. This plan will use the safer packet
  primitive rule already in the spec: do not silently emit ambiguous bytes.
- IPv4 option-bearing fragmentation requires copied-bit option handling or an
  explicit unsupported result. All-options-copy behavior is not source-backed.
