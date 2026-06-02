# TCP RFC Manifest

This manifest records the TCP behavior that `crafter` models for RFC-backed
compile, decode, display, fixture, and oracle work. It is intentionally narrow:
`crafter` stays a packet primitive. It builds and decodes individual TCP
segments, fills dependent header fields on `compile()`, preserves deliberate
overrides, and exposes TCP options as typed, inspectable packet data. It does
not implement a TCP/IP stack, connection state machine, retransmission engine,
congestion control, stream reassembly, IP fragmentation, or IP reassembly. The
fragmentation-adjacent facts recorded here (TCP MSS, payload sizing, option
budgeting, Don't Fragment guidance, IPv6 minimum MTU, PMTUD/PLPMTUD) are
modeled only to size and document correct TCP segments, never to fragment,
reassemble, or probe by default.

Date checked: 2026-06-02 (RFC Editor, IANA TCP Parameters, and Datatracker
status reviewed on this date).

## Source Authority And How To Read This Manifest

Every wire fact `crafter` relies on must trace to one of the entries below.
Model memory may suggest what to look up, but it is not the authority; the cited
RFC or IANA registry is. When the local RFC manifest automation (the
`rfc-protocol-spec` source tooling) is too noisy for broad TCP queries — which
the plan anticipates because the TCP registries and RFC set are large — this
manifest is maintained as a hand-curated official-source fallback: each row
names the specific RFC section or IANA registry that backs it, so the fact can
be re-verified directly against the official source rather than against a search
result. Any future addition must add or update a citation here before code
changes depend on it.

"Normative for wire behavior" means the source defines bytes on the wire that
`crafter` must construct, fill, or decode correctly. "Guidance only" means the
source informs documentation, defaults, or helper recommendations but does not
itself dictate a field encoding that `crafter` serializes.

## Source Set

### Normative for wire behavior

- **RFC 9293 — Transmission Control Protocol** is the current base TCP
  specification. It obsoletes RFC 793, RFC 879, RFC 2873, RFC 6093, RFC 6429,
  RFC 6528, and RFC 6691, and updates RFC 1011, RFC 1122, and RFC 5961. It
  defines the TCP header layout, the Data Offset field, the control bits, the
  16-bit checksum over the pseudo-header plus TCP header and data, the
  end-of-option-list (EOL, kind 0), no-operation (NOP, kind 1), and
  maximum-segment-size (MSS, kind 2) options, and the option encoding rule that
  multi-byte options carry a one-byte kind and a one-byte length covering kind,
  length, and value. Source: https://www.rfc-editor.org/rfc/rfc9293.html
- **IANA TCP Parameters registry** is the authority for current TCP Option Kind
  Numbers and the TCP Header Flags registry, including any assignments made
  after the existing `crafter` implementation. Source:
  https://www.iana.org/assignments/tcp-parameters
- **RFC 2018 — TCP Selective Acknowledgment Options** defines SACK-Permitted
  (kind 4, length 2) and SACK (kind 5, variable length) and the 32-bit
  left-edge / right-edge block encoding. Source:
  https://www.rfc-editor.org/rfc/rfc2018.html
- **RFC 2883 — An Extension to the SACK Option for Duplicate Packets (D-SACK)**
  reuses the SACK option (kind 5) to report duplicate (already-received)
  segments; the wire encoding is unchanged and the first block may report a
  duplicate range. `crafter` represents D-SACK at the SACK-block level rather
  than as a distinct option kind. Source:
  https://www.rfc-editor.org/rfc/rfc2883.html
- **RFC 3168 — The Addition of Explicit Congestion Notification (ECN) to IP**
  defines the classic ECN TCP control bits CWR and ECE in the TCP header.
  Source: https://www.rfc-editor.org/rfc/rfc3168.html
- **RFC 8311 — Relaxing Restrictions on Explicit Congestion Notification (ECN)
  Experimentation** deprecates the ECN-nonce (the experimental use of the bit
  historically exported as `NS`) and relaxes ECN experimentation rules,
  freeing that header bit for later assignment. Source:
  https://www.rfc-editor.org/rfc/rfc8311.html
- **RFC 7323 — TCP Extensions for High Performance** defines Window Scale
  (kind 3, length 3, one shift-count byte) and Timestamps (kind 8, length 10,
  32-bit TSval and 32-bit TSecr). It obsoletes RFC 1323. Source:
  https://www.rfc-editor.org/rfc/rfc7323.html
- **RFC 5482 — TCP User Timeout Option** defines the User Timeout option
  (kind 28, length 4): a 1-bit granularity flag plus a 15-bit timeout value.
  Source: https://www.rfc-editor.org/rfc/rfc5482.html
- **RFC 5925 — The TCP Authentication Option (TCP-AO)** defines TCP-AO (kind 29)
  with KeyID, RNextKeyID, and a Message Authentication Code field. `crafter`
  preserves TCP-AO bytes for inspection and round-trip; it does not compute or
  verify the MAC. Source: https://www.rfc-editor.org/rfc/rfc5925.html
- **RFC 5926 — Cryptographic Algorithms for the TCP Authentication Option
  (TCP-AO)** defines the MAC and KDF algorithms used by TCP-AO. It is normative
  for the algorithms but `crafter` only preserves the option bytes, so it acts
  here mainly as the algorithm reference. Source:
  https://www.rfc-editor.org/rfc/rfc5926.html
- **RFC 6994 — Shared Use of Experimental TCP Options** defines the
  experimental option format for kinds 253 and 254: a 16-bit Experiment
  Identifier (ExID) immediately after the kind/length header, distinguishing
  co-existing experiments that share the same option kind. Source:
  https://www.rfc-editor.org/rfc/rfc6994.html
- **RFC 7413 — TCP Fast Open** defines the Fast Open Cookie option (kind 34)
  carrying a server-issued cookie. Source:
  https://www.rfc-editor.org/rfc/rfc7413.html
- **RFC 8547 — TCP-ENO: Encryption Negotiation Option** defines TCP-ENO
  (kind 69) and its suboption byte structure. `crafter` preserves TCP-ENO bytes
  for inspection; it does not negotiate encryption. Source:
  https://www.rfc-editor.org/rfc/rfc8547.html
- **RFC 8548 — Cryptographic Protection of TCP Streams (tcpcrypt)** defines the
  tcpcrypt protocol that runs over TCP-ENO and its associated registries.
  `crafter` does not implement tcpcrypt: the tcpcrypt session protocol, key
  exchange, session caching, and any negotiated encryption are out of scope.
  The TCP-ENO option (kind 69) only preserves its raw suboption bytes for
  inspection and round-trip. Source:
  https://www.rfc-editor.org/rfc/rfc8548.html
- **RFC 8684 — TCP Extensions for Multipath Operation with Multiple Addresses
  (MPTCP v1)** defines the MPTCP option (kind 30) and the 4-bit subtype field
  that selects MP_CAPABLE, MP_JOIN, DSS, ADD_ADDR, REMOVE_ADDR, MP_PRIO,
  MP_FAIL, MP_FASTCLOSE, MP_TCPRST, and reserved subtypes. It obsoletes RFC 6824
  and defines the IANA MPTCP Option Subtypes and MP_TCPRST Reason Codes
  registries. Source: https://www.rfc-editor.org/rfc/rfc8684.html
- **RFC 9768 — More Accurate Explicit Congestion Notification (ECN) Feedback in
  TCP (AccECN)** defines the Accurate ECN TCP option kinds 172 (AccECN0) and
  174 (AccECN1) and uses the previously freed header bit as the AE (Accurate
  ECN) flag. This is the source-backed current name for the bit `crafter`
  historically exported as `NS`. Source:
  https://www.rfc-editor.org/rfc/rfc9768.html

### Guidance only (no `crafter`-serialized field)

- **RFC 1191 — Path MTU Discovery** defines classic IPv4 PMTUD and informs MSS
  and payload-sizing guidance. `crafter` does not implement PMTUD probing.
  Source: https://www.rfc-editor.org/rfc/rfc1191.html
- **RFC 8201 — Path MTU Discovery for IP version 6** defines IPv6 PMTUD and the
  IPv6 minimum MTU of 1280 octets used in sizing guidance. `crafter` does not
  implement PMTUD probing. Source:
  https://www.rfc-editor.org/rfc/rfc8201.html
- **RFC 8899 — Packetization Layer Path MTU Discovery (PLPMTUD)** defines
  datagram PLPMTUD and is referenced for sizing guidance only. Source:
  https://www.rfc-editor.org/rfc/rfc8899.html

## TCP Core Header

TCP is a minimum 20-octet transport header (RFC 9293 §3.1) followed by optional
options and then TCP user data:

| Field | Size | Source-backed behavior |
| --- | ---: | --- |
| Source Port | 16 bits | Sending process port. |
| Destination Port | 16 bits | Receiving process port. |
| Sequence Number | 32 bits | First data octet's sequence number; the SYN's sequence number when SYN is set. |
| Acknowledgment Number | 32 bits | Next expected sequence number; valid only when ACK is set. |
| Data Offset | 4 bits | TCP header length in 32-bit words. Minimum 5 (20 octets), maximum 15 (60 octets). |
| Reserved | 4 bits | Bits after Data Offset preceding the control bits. RFC 9293 reserves these and RFC 9768 assigns the high reserved bit as AE. |
| Control Bits (flags) | 8/9 bits | CWR, ECE, URG, ACK, PSH, RST, SYN, FIN, plus the AE/`NS`-position bit, per RFC 9293, RFC 3168, and RFC 9768. |
| Window | 16 bits | Receive window in octets. |
| Checksum | 16 bits | One's-complement checksum over the pseudo-header, TCP header, options, padding, and TCP data. |
| Urgent Pointer | 16 bits | Offset of urgent data; valid only when URG is set. |

`crafter` compile must fill Data Offset, header padding, and checksum when they
are unset, fill the IPv4 protocol number / IPv6 next-header (TCP is IP protocol
number 6, RFC 9293 §3.1) and enclosing lengths through the existing packet
composition behavior, and preserve explicit user-provided values — including
deliberately malformed values that fit the field, such as an intentionally
wrong checksum, a Data Offset below the 20-octet minimum, or reserved bits set
on purpose. Decode keeps malformed segments inspectable with structured status
rather than panicking.

## TCP Header Flags Registry

The IANA TCP Header Flags registry (under IANA TCP Parameters, reviewed
2026-06-02) tracks the control bits. `crafter` exports a flag constant per bit.

| Bit position (from MSB of the 9-bit control field) | Current IANA name | `crafter` constant | Source |
| --- | --- | --- | --- |
| `0x100` | AE (Accurate ECN) | `TCP_FLAG_NS` (compatibility alias); add `TCP_FLAG_AE` | RFC 9768; formerly ECN-nonce, deprecated by RFC 8311 |
| `0x080` | CWR | `TCP_FLAG_CWR` | RFC 3168 |
| `0x040` | ECE | `TCP_FLAG_ECE` | RFC 3168 |
| `0x020` | URG | `TCP_FLAG_URG` | RFC 9293 |
| `0x010` | ACK | `TCP_FLAG_ACK` | RFC 9293 |
| `0x008` | PSH | `TCP_FLAG_PSH` | RFC 9293 |
| `0x004` | RST | `TCP_FLAG_RST` | RFC 9293 |
| `0x002` | SYN | `TCP_FLAG_SYN` | RFC 9293 |
| `0x001` | FIN | `TCP_FLAG_FIN` | RFC 9293 |

The `0x100` bit was historically the ECN-nonce sum bit exported as `NS`. RFC
8311 deprecated the ECN nonce and RFC 9768 (Accurate ECN) names this bit AE.
`crafter` must keep `TCP_FLAG_NS` as a permanent compatibility alias for the
bit even though the current registry name is AE, and add a source-backed
current name such as `TCP_FLAG_AE`. Summaries may display the current AE name
while tests preserve the older `NS` constant. CWR and ECE remain the classic
ECN bits (RFC 3168). Together AE, CWR, and ECE provide the AccECN three-bit
feedback codepoint on the SYN exchange (RFC 9768).

## Checksum Scope

RFC 9293 §3.1 defines the TCP checksum as the 16-bit one's-complement of the
one's-complement sum of a pseudo-header, the TCP header, the options, any
header padding, and the TCP data, with a zero pad octet appended for an odd
data length. The pseudo-header supplies the source and destination addresses,
the protocol number, and the TCP segment length:

- For IPv4, the pseudo-header is the 32-bit source and destination addresses,
  a zero byte, the protocol number 6, and the 16-bit TCP length (RFC 9293
  §3.1, consistent with RFC 793's pseudo-header).
- For IPv6, the pseudo-header uses the 128-bit source and destination
  addresses, the 32-bit upper-layer packet length, and the next-header value 6
  (RFC 8200 §8.1, applied to TCP by RFC 9293). Unlike IPv4 UDP, TCP has no
  zero-checksum exemption; the TCP checksum is mandatory.

`crafter` compile fills the checksum from IPv4 or IPv6 pseudo-header context
when available and leaves the checksum zero only when there is no network
checksum context. An explicit user-set checksum is preserved, including a
deliberately invalid value. Offline decode represents an invalid checksum in
checksum status instead of silently dropping the decoded segment.

## Data Offset, Options Area, And Padding

Data Offset (4 bits) gives the TCP header length in 32-bit words. The minimum is
5 words (20 octets, no options) and the maximum is 15 words (60 octets), so the
options area is at most 40 octets (RFC 9293 §3.1). Options begin immediately
after the 20-octet fixed header and are followed by TCP user data:

```text
tcp_header_len = Data Offset * 4
tcp_options    = segment[20 .. tcp_header_len]
tcp_user_data  = segment[tcp_header_len ..]
```

`crafter` compile fills Data Offset from the padded option bytes when unset and
pads the option area to a 32-bit boundary with zero/EOL bytes. Application
decoders reached through TCP ports must receive only `tcp_user_data` — the bytes
after the validated TCP header — and never the options area.

Decode edge cases backed by RFC 9293 §3.1 option rules:

- Data Offset below 5 (header shorter than 20 octets) is a structured error.
- Data Offset that points past the available bytes is a structured
  buffer-too-short error.
- A user-set Data Offset that is intentionally malformed but accepted by the
  existing validation model must not be silently rewritten.
- EOL (kind 0) ends option processing before the Data Offset area; trailing
  bytes up to the Data Offset boundary are padding that must be preserved and
  inspectable.
- NOP (kind 1) is one-byte alignment padding decoded without losing the
  original option bytes.
- An option length below 2 (for non-EOL/NOP kinds), a fixed-length mismatch,
  or a length that overruns the options area is a structured error.

## IANA TCP Option Kind Numbers

This table follows the IANA TCP Option Kind Numbers registry (under IANA TCP
Parameters, reviewed 2026-06-02) together with the defining RFCs. EOL, NOP, and
MSS are RFC 9293 base options. `crafter` prioritizes the currently relevant
standardized and deployed options first; obsolete, reserved, and unassigned
kinds remain inspectable with source-backed classification rather than being
silently discarded.

| Kind | Length | Name | Source | Scope for `crafter` |
| ---: | --- | --- | --- | --- |
| 0 | 1 | End of Option List (EOL) | RFC 9293 | Parse and build; stop option processing; preserve trailing padding. |
| 1 | 1 | No-Operation (NOP) | RFC 9293 | Parse and build as alignment padding without losing bytes. |
| 2 | 4 | Maximum Segment Size (MSS) | RFC 9293 | Parse and build a 16-bit MSS. |
| 3 | 3 | Window Scale (WS) | RFC 7323 | Parse and build a one-byte shift count. |
| 4 | 2 | SACK Permitted | RFC 2018 | Parse and build; presence-only. |
| 5 | variable | SACK | RFC 2018, RFC 2883 | Parse and build 32-bit left/right edge blocks; D-SACK represented at block level. |
| 6 | 6 | Echo (obsolete) | RFC 1072, obsoleted by RFC 7323 | Preserve as classified obsolete option. |
| 7 | 6 | Echo Reply (obsolete) | RFC 1072, obsoleted by RFC 7323 | Preserve as classified obsolete option. |
| 8 | 10 | Timestamps (TSopt) | RFC 7323 | Parse and build 32-bit TSval and 32-bit TSecr. |
| 9 | 2 | Partial Order Connection Permitted (obsolete) | RFC 1693, RFC 6247 | Preserve as classified obsolete option. |
| 10 | 3 | Partial Order Service Profile (obsolete) | RFC 1693, RFC 6247 | Preserve as classified obsolete option. |
| 11-13 | variable | CC, CC.NEW, CC.ECHO (obsolete) | RFC 1644, RFC 6247 | Preserve as classified obsolete options. |
| 14 | 3 | TCP Alternate Checksum Request (obsolete) | RFC 1146, RFC 6247 | Preserve as classified obsolete option. |
| 15 | variable | TCP Alternate Checksum Data (obsolete) | RFC 1146, RFC 6247 | Preserve as classified obsolete option. |
| 18 | 3 | Trailer Checksum (historic) | (Stev Knowles) | Preserve as classified historic/unauthorized option. |
| 19 | 18 | MD5 Signature (obsolete) | RFC 2385, obsoleted by RFC 5925 | Preserve as classified obsolete option, superseded by TCP-AO. |
| 27 | 8 | Quick-Start Response | RFC 4782 (experimental) | Preserve as classified experimental option. |
| 28 | 4 | User Timeout (UTO) | RFC 5482 | Parse and build a 1-bit granularity flag plus 15-bit timeout. |
| 29 | variable | TCP Authentication Option (TCP-AO) | RFC 5925 | Preserve KeyID/RNextKeyID/MAC bytes; do not compute or verify the MAC. |
| 30 | variable | Multipath TCP (MPTCP) | RFC 8684 | Parse subtype nibble and preserve subtype-specific bytes. |
| 34 | variable | TCP Fast Open Cookie | RFC 7413 | Parse and build cookie bytes. |
| 69 | variable | Encryption Negotiation (TCP-ENO) | RFC 8547 | Preserve suboption bytes for inspection; no negotiation. |
| 172 | variable | Accurate ECN Order 0 (AccECN0) | RFC 9768 | Parse and classify distinctly from generic private data. |
| 174 | variable | Accurate ECN Order 1 (AccECN1) | RFC 9768 | Parse and classify distinctly from generic private data. |
| 253 | variable (min 4) | RFC 3692-style Experiment 1 | RFC 6994 | Parse a 16-bit ExID then experiment bytes; preserve. |
| 254 | variable (min 4) | RFC 3692-style Experiment 2 | RFC 6994 | Parse a 16-bit ExID then experiment bytes; preserve. |
| others | variable | Unassigned / reserved | IANA TCP Parameters | Preserve as generic or classified unknown option; round-trip bytes. |

Kinds 0 and 1 are single-byte options with no length field. Every other option
carries a one-byte kind, a one-byte length covering the kind, length, and value
octets, and the value (RFC 9293 §3.1). Kinds 253 and 254 additionally carry a
16-bit ExID immediately after the length byte (RFC 6994), which must not be
confused with generic experiment payload once typed ExID support exists.

## Legacy Security Options

The IANA TCP Option Kind Numbers registry still records obsolete security
options. The TCP MD5 Signature option (kind 19, the `Md5` option of RFC 2385) is
the notable legacy entry: it carried a per-segment MD5 digest of the segment,
pseudo-header, and a shared key, and was obsoleted by RFC 5925 (TCP-AO, kind
29). `crafter` treats these as legacy options that remain inspectable:

- The kind constant `TCP_OPTION_MD5_SIGNATURE = 19` is exported and the kind is
  classified as `Assigned` (it still holds a registry name), so a segment using
  it round-trips as a recognized legacy option rather than an unknown blob.
- The option bytes are preserved verbatim through the generic representation.
  `crafter` performs no MD5 signing, key management, or signature validation:
  operational security policy for this legacy option is out of scope for the
  primitive packet layer, exactly as for TCP-AO (kind 29).

This keeps obsolete security options buildable and inspectable for testing a
stack without turning `crafter` into a TCP security implementation.

## Accurate ECN And The AE Bit

RFC 9768 defines AccECN, which provides more granular ECN feedback than classic
RFC 3168 ECN. AccECN uses the AE header bit (the `0x100` position historically
exported as `NS`) together with CWR and ECE to carry a three-bit feedback
codepoint, and defines the AccECN option kinds 172 (AccECN0) and 174 (AccECN1)
to carry byte counters when the codepoint space is insufficient. `crafter` must:

- Keep `TCP_FLAG_NS` as a compatibility alias and add a current `TCP_FLAG_AE`
  name for the same bit.
- Recognize option kinds 172 and 174 as AccECN options classified distinctly
  from generic private data, so a packet that uses them round-trips as AccECN
  rather than as an unknown blob.

## Extended Data Offset (EDO) Status Reconciliation

`crafter` currently exports `TcpExtendedDataOffset` and the option kind constant
`TCP_OPTION_EDO = 237`, modeling the TCP Extended Data Offset draft
(draft-ietf-tcpm-tcp-edo). EDO is not an RFC-published assigned kind in the
current IANA TCP Option Kind Numbers registry; kind 237 is unassigned there as
of 2026-06-02. The plan treats EDO as source-status reconciliation: the existing
public API is preserved and its draft (not RFC-published) status is documented
here, and source-backed experimental ExID support (RFC 6994, kinds 253/254) is
added rather than silently removing or redefining the exported EDO names.

## Segment Sizing And Fragmentation-Adjacent Guidance (Documentation Only)

These facts size correct TCP segments and inform helper documentation. They do
not introduce a fragmenter, reassembler, fragment cache, or live probe.

- MSS (RFC 9293, option kind 2) advertises the largest segment the sender is
  willing to receive, excluding the TCP and IP headers. RFC 9293 §3.7.1 ties the
  effective send MSS to the path and to PMTUD.
- IPv4 PMTUD (RFC 1191) uses the Don't Fragment bit so a sender learns the path
  MTU instead of relying on fragmentation; this informs IPv4 DF guidance for
  sized segments.
- IPv6 has no in-path fragmentation; the minimum link MTU is 1280 octets
  (RFC 8201), which bounds the minimum payload sizing guidance for IPv6 TCP.
- PLPMTUD (RFC 8899) is a datagram-layer alternative to ICMP-based PMTUD and is
  referenced for guidance only.
- The TCP options area is at most 40 octets (Data Offset bound, RFC 9293 §3.1).
  Option-budget helpers document how MSS, Window Scale, SACK-Permitted,
  Timestamps, and other SYN options fit within that 40-octet budget. This is a
  sizing helper, not a state machine.

## IPv6 Fragment-Header Interaction

When TCP is carried over IPv6 with a Fragment header (RFC 8200 §4.5), only the
first fragment contains the TCP header. `crafter` must preserve non-initial
fragments as raw and must not attempt TCP decode without the initial TCP header.
This is consistent with the scope exclusion: `crafter` does not reassemble IPv6
fragments; it only avoids misparsing a fragment that has no TCP header.

Modeled behavior (decode rules):

- An IPv6 INITIAL fragment (fragment offset 0, more-fragments set) carries the
  start of the TCP header, so decode runs through the Fragment header, the Tcp
  layer is present, and the IPv6 pseudo-header still supplies TCP checksum
  context.
- A non-initial IPv6 fragment with TCP next-header is preserved as Raw; this is
  fragmentation-adjacent behavior, not reassembly support. The decoded stack
  ends in a `Raw` layer and no TCP decode is attempted, because a non-initial
  fragment does not begin with a TCP header.

These two rules are pinned by the `tcp_ipv6_fragment_adjacent_decode_rules`
unit test in `crafter/src/protocols/transport/tcp/tests.rs`. They document and
test the boundary only; `crafter` still performs no IPv6 reassembly.

## Explicit Exclusions

`crafter` does not implement, and this manifest does not authorize, a TCP
connection state machine, retransmission engine, congestion control, TCP stream
reassembly, IP fragmentation, IP reassembly, a fragment cache, a scanner, a
fuzzer, or a packet-analyzer workflow. TCP-AO and TCP-ENO bytes are preserved
for inspection and round-trip only; `crafter` does not compute MACs, derive
keys, or negotiate encryption. MPTCP subtype bytes are preserved and the subtype
is parsed, but `crafter` does not run multipath connection logic.

MPTCP behavior and policy are explicitly out of scope: `crafter` implements no
MPTCP connection recovery, subflow management, path management, or reaction to a
reset. For the `MP_TCPRST` subtype (RFC 8684 §3.6) `crafter` only exposes the
8-bit Reason code as inspectable data — the `MPTCP_TCPRST_REASON_*` constants and
the byte-preserving `TcpOption::mptcp_tcprst_reason` accessor name the wire value
without acting on it. Deciding whether to tear down a subflow, fall back to
regular TCP, or recover the connection in response to an `MP_TCPRST` reason is
the responsibility of a generated tool, not the crate.
