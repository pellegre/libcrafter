# SCTP RFC Manifest

Review date: 2026-07-03.

This manifest records the public source evidence for Stream Control
Transmission Protocol (SCTP) packet-layer work in `crafter`. Later SCTP code,
tests, fixtures, docs, oracle specs, probe expectations, summaries, and
examples must cite this manifest and the exact RFC section, IANA registry row,
Datatracker relationship, or RFC Editor erratum that supplies a wire fact.

SCTP remains a packet primitive in this repository. These sources define bytes,
fields, codepoints, padding, checksum behavior, encapsulation shapes, and
registry relationships. They do not authorize adding an SCTP association stack,
socket API, retransmission service, congestion controller, scanner, analyzer,
fuzzer, daemon, or live traffic default.

## Source Classes

- `core wire behavior`: current normative source for the SCTP packet header,
  chunk framing, TLV parameter framing, error-cause framing, checksum, or
  direct SCTP-over-IP decode shape.
- `registry authority`: official source for assigned SCTP protocol numbers,
  chunk types, chunk flags, parameter types, error causes, PPIDs, HMAC IDs,
  adaptation code points, error-detection methods, status, update,
  obsolescence, or errata records.
- `packet-data extension`: source for optional chunks, parameters, causes, or
  PPID labels that must remain byte-preserving when structurally valid.
- `encapsulation source`: source for an alternate packet envelope that may
  expose SCTP bytes after a conservative shape gate.
- `operational guidance`: source that informs safe examples, dry-run defaults,
  external qualification, or deployment risk, but is not by itself a packet grammar
  authority for this crate.
- `obsolete context`: source superseded by newer SCTP authority and usable only
  to understand older fixtures or lineage.
- `blocked`: behavior that must not be implemented in `crafter` unless a later
  source-backed scope step explicitly admits it.

## Selected Sources

| Class | Source | Use in this project | Downstream gate |
| --- | --- | --- | --- |
| core wire behavior | RFC 9260, "Stream Control Transmission Protocol", <https://www.rfc-editor.org/rfc/rfc9260.html> | Current base SCTP packet grammar: common header, chunk envelope, parameter TLV envelope, built-in chunk definitions, error-cause envelope, padding, bundling constraints, verification tag rules, CRC32c checksum, and IANA registration rules. | Packet structs, constants, decode/encode, `summary()`, `show()`, checksum status, malformed-length errors, and IP protocol inference must cite the exact section used and apply verified errata before freezing behavior. |
| registry authority | IETF Datatracker RFC 9260 page, <https://datatracker.ietf.org/doc/rfc9260/> | Official RFC status, stream, publication date, and obsolescence relationship. On review, Datatracker lists RFC 9260 as an IETF Proposed Standard from June 2022, obsoleting RFC 4960, RFC 4460, RFC 6096, RFC 7053, and RFC 8540. | Prefer RFC 9260 over obsolete SCTP core and errata RFCs for new behavior. Check Datatracker before relying on a relationship or status note. |
| registry authority | RFC Editor errata for RFC 9260, <https://www.rfc-editor.org/errata_search.php?rfc=9260&presentation=records> | Official errata authority. On review, verified errata include IDs 7148, 7387, 8402, 7147, and 7852; held-for-update errata include ID 8772. | Before implementing behavior from Sections 3.2, 3.3.3, 5.1.6, 5.2.4.1, or 8.5, apply verified errata. Held-for-update errata must be called out in tests or docs if the affected section is used. |
| registry authority | IANA "Stream Control Transmission Protocol (SCTP) Parameters", <https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml> | Current authority for chunk types, parameter types, per-chunk flag subregistries, error cause codes, SCTP Payload Protocol Identifiers, HMAC identifiers, adaptation code points, and error detection methods. The registry was last updated 2026-02-20 when reviewed. | Constants, labels, unknown-value policy, and extension codepoint tests must cite exact IANA rows. Unknown or future values remain preservable when structurally valid. Temporary draft-backed rows can be labeled from IANA but must not become stable typed behavior without later scope. |
| registry authority | IANA "Assigned Internet Protocol Numbers", <https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml> | Authority for IP protocol / IPv6 next-header number 132, labeled SCTP. | IPv4 protocol and IPv6 next-header auto-fill for an SCTP layer should use 132 only when the caller did not explicitly override the enclosing field. |
| encapsulation source | RFC 6951, "UDP Encapsulation of Stream Control Transmission Protocol (SCTP) Packets for End-Host to End-Host Communication", <https://www.rfc-editor.org/rfc/rfc6951.html> | SCTP-over-UDP packet shape, use of UDP port 9899 (`sctp-tunneling`), SCTP payload placement after the UDP header, and checksum guidance for encapsulated SCTP. | UDP/9899 payloads must decode as SCTP only through a conservative RFC 6951 shape gate; unrelated UDP/9899 bytes remain `Raw`. UDP encapsulation does not authorize a user-space SCTP stack. |
| packet-data extension | RFC 9653, "Zero Checksum for the Stream Control Transmission Protocol", <https://www.rfc-editor.org/rfc/rfc9653.html> | Defines the Zero Checksum Acceptable parameter, the SCTP Error Detection Methods registry, and the relationship between zero checksums and alternate error detection methods such as SCTP over DTLS. | `crafter` may expose checksum status and preserve or build the parameter, but must not silently accept a bad checksum as "valid" outside the explicit zero-checksum evidence and caller-visible status model. |
| packet-data extension | RFC 4895, "Authenticated Chunks for the Stream Control Transmission Protocol (SCTP)", <https://www.rfc-editor.org/rfc/rfc4895.html> | Source for AUTH chunk, HMAC parameter/codepoint registrations, and related error cause registration. | AUTH bytes and registry labels are packet data. Do not implement cryptographic authentication computation or verification unless a later source-backed step explicitly scopes it. |
| packet-data extension | RFC 3758, "Stream Control Transmission Protocol (SCTP) Partial Reliability Extension", <https://www.rfc-editor.org/rfc/rfc3758.html> | Source for FORWARD TSN support and related parameter/codepoint registrations. | Preserve and label PR-SCTP packet data; do not implement retransmission or partial-reliability policy. |
| packet-data extension | RFC 5061, "Stream Control Transmission Protocol (SCTP) Dynamic Address Reconfiguration", <https://www.rfc-editor.org/rfc/rfc5061.html> | Source for ASCONF/ASCONF-ACK chunks, supported extensions parameter, address parameters, ASCONF error causes, and adaptation codepoint context. | Preserve and label address-configuration packet data. Do not implement address-management state or path reconfiguration workflow in the crate. |
| packet-data extension | RFC 6525, "Stream Control Transmission Protocol (SCTP) Stream Reconfiguration", <https://www.rfc-editor.org/rfc/rfc6525.html> | Source for RE-CONFIG chunk and stream reset/reconfiguration parameters. | Preserve and label reconfiguration packet data. Do not implement stream-state mutation workflow. |
| packet-data extension | RFC 8260, "Stream Schedulers and User Message Interleaving for the Stream Control Transmission Protocol", <https://www.rfc-editor.org/rfc/rfc8260.html> | Source for I-DATA, I-FORWARD-TSN, and related flags/fields. | Preserve and label interleaving packet data. Do not implement scheduler, association, or user-message reassembly behavior. |
| packet-data extension | RFC 4820, "Padding Chunk and Parameter for the Stream Control Transmission Protocol", <https://www.rfc-editor.org/rfc/rfc4820.html> | Source for PAD chunk and Padding parameter registrations. | Padding bytes are packet data and should round-trip, but semantic values must exclude RFC padding bytes where RFC 9260 says padding is not part of the length. |

## Core Wire Facts

- RFC 9260 Section 3 defines an SCTP packet as a common header followed by one
  or more chunks. INIT, INIT ACK, and SHUTDOWN COMPLETE have bundling
  restrictions; all other chunks may be bundled when packet size permits.
- RFC 9260 Section 3.1 defines the 12-byte common header: 16-bit source port,
  16-bit destination port, 32-bit verification tag, and 32-bit checksum. SCTP
  port 0 is invalid on the wire, but `crafter` must still preserve explicit
  caller overrides when constructing intentionally malformed packets.
- RFC 9260 Section 3.1 defines verification tag exceptions: INIT packets use
  zero, SHUTDOWN COMPLETE with T bit copies the SHUTDOWN ACK packet tag, and
  ABORT can copy the packet that caused the ABORT. Decode should expose the
  tag value and checksum status; it must not try to maintain association state.
- RFC 9260 Section 3.2 defines each chunk as an 8-bit type, 8-bit flags,
  16-bit length, and chunk-specific value. The length includes the chunk
  header and value, but not chunk padding.
- RFC 9260 Section 3.2 defines unknown-chunk action bits in the two highest
  bits of the chunk type. For `crafter`, every well-formed unknown chunk must
  remain inspectable and byte-preserving; action bits can be exposed for
  summaries and later validation, but packet decode must not drop bytes.
- RFC 9260 Section 3.2 says unassigned chunk flags are normally sent as zero
  and ignored on receipt unless a chunk-specific source says otherwise. This
  means flag values must be preserved, not normalized away.
- RFC 9260 Section 3.2 requires chunks to be padded to a 4-octet boundary with
  at most three zero bytes, and receivers ignore padding bytes. Padding is not
  semantic chunk value data and must round-trip separately from the declared
  value.
- RFC 9260 Section 3.2.1 defines SCTP parameters as 16-bit type, 16-bit
  length, and variable value. Parameter length includes the parameter header and
  value, not parameter padding. Parameter type values are unique across chunks.
- RFC 9260 Section 3.2.1 defines unknown-parameter action bits in the two
  highest bits of the parameter type. Well-formed unknown parameters must
  remain byte-preserving and inspectable.
- RFC 9260 Section 3.3.10 defines ERROR chunk causes as variable-length
  parameter-shaped fields with a 16-bit cause code, 16-bit cause length, and
  cause-specific information. Cause length includes the cause header and value.
- RFC 9260 Section 6.8 defines CRC32c over the SCTP common header and chunks
  with the checksum field zeroed for calculation; the result is inserted into
  the common header. Compile should fill an unset checksum but must preserve an
  explicit checksum override, including zero or invalid values.
- RFC 9653 adds source-backed context for intentionally zero checksum handling.
  Because zero can also be a correct CRC32c result, decoded packets should
  expose status rather than collapsing zero into a single meaning.
- RFC 6951 places the complete SCTP packet as the UDP payload. For guarded
  UDP encapsulation, decode may remove the UDP header only after the packet
  shape is consistent with RFC 6951 and the SCTP payload is structurally
  decodable.

## IANA Registry Authority

IANA SCTP Parameters was last updated on 2026-02-20 when reviewed. Use IANA
rows for current labels and registration policy, while preserving unassigned,
temporary, private, obsolete, or future values when their enclosing packet data
is well formed.

| Registry | Downstream use |
| --- | --- |
| Chunk Types | 8-bit chunk type labels. RFC 9260 defines DATA through SHUTDOWN COMPLETE and reserves extension values. Current IANA rows also include AUTH, I-DATA, ASCONF-ACK, RE-CONFIG, PAD, FORWARD TSN, ASCONF, I-FORWARD-TSN, and temporary DTLS. |
| Chunk Parameter Types | 16-bit parameter labels. RFC 9260 defines heartbeat info, addresses, state cookie, unrecognized parameter, cookie preservative, host name address, supported address types, and ECN capable. Current IANA rows also include reconfiguration, zero checksum acceptable, AUTH, padding, supported extensions, PR-SCTP, and ASCONF parameters. |
| Chunk Flags | Per-chunk 8-bit flag labels. DATA and I-DATA define E, B, U, and I bits. ABORT and SHUTDOWN COMPLETE define the T bit. Most other current flag subregistries are unassigned. Unknown flag bits remain byte-preserving. |
| Error Cause Codes | 16-bit cause labels. RFC 9260 defines causes 1 through 13. RFC 5061 and RFC 4895 define current extension causes. Unknown well-formed causes remain byte-preserving. |
| SCTP Payload Protocol Identifiers | 32-bit PPID labels for DATA/I-DATA payload interpretation. PPID labels are summary metadata only; `crafter` should not decode application payloads solely from a PPID unless a later source-backed application protocol step scopes that behavior. |
| Hashed Message Authentication Code Identifiers | AUTH HMAC ID labels from RFC 4895, including SHA-1 and SHA-256 assignments. Labels do not imply MAC computation support. |
| Adaptation Code Points | 32-bit adaptation codepoint labels from RFC 5061 and related registrations. These are packet metadata for adaptation-indication parameters. |
| Error Detection Methods | 32-bit alternate error detection method IDs from RFC 9653. Current row 1 is SCTP over DTLS. Labels do not change default CRC32c handling. |

IANA Assigned Internet Protocol Numbers lists protocol number 132 as SCTP. Use
that registry value for IPv4 `protocol` and IPv6 `next_header` auto-fill when
the following layer is SCTP and the enclosing field is unset. Preserve explicit
IPv4/IPv6 protocol overrides even when the next typed layer is SCTP.

## Authority Order

1. Use RFC 9260, with verified RFC Editor errata applied, for the base SCTP
   packet grammar, common header, chunks, parameters, error causes, padding,
   verification tag model, CRC32c checksum, and IANA registration structure.
2. Use IANA SCTP Parameters for current assigned codepoint labels and registry
   policies. Prefer current IANA rows over stale RFC tables when naming assigned
   values, while retaining the RFC section as the wire-format source.
3. Use IANA Assigned Internet Protocol Numbers for IP protocol / IPv6
   next-header value 132.
4. Use RFC 6951 only for guarded UDP encapsulation shape and UDP port 9899
   context. Native SCTP-over-IP remains the base behavior.
5. Use RFC 9653 for zero-checksum extension facts and the Error Detection
   Methods registry, without changing default checksum correctness.
6. Use extension RFCs such as RFC 4895, RFC 3758, RFC 5061, RFC 6525, RFC 8260,
   and RFC 4820 only for packet-data extensions admitted by later steps.
7. Use Datatracker metadata and RFC Editor errata before freezing any RFC fact.
8. Use obsolete RFCs 2960, 4460, 4960, 6096, 7053, and 8540 only for lineage or
   legacy fixture explanation. Do not prefer them over RFC 9260.

## Errata Review

- RFC Editor errata search for RFC 9260 reported five verified errata at
  review time: 7148, 7387, 8402, 7147, and 7852.
- Verified Errata 7148 affects Section 3.3.3 INIT ACK handling when `a_rwnd`
  is smaller than 1500. This is association behavior, not a reason for packet
  decode to drop a syntactically valid INIT ACK.
- Verified Errata 7387 and 8402 affect timer names and examples in Sections
  5.2.4.1 and 5.1.6. These are operational state-machine facts and should not
  become crate runtime behavior without later scope.
- Verified Errata 7147 affects Section 3.2 wording around the error cause name
  in unknown-chunk action text. It does not change byte layout.
- Verified Errata 7852 affects Section 8.5 verification-tag ordering. Decode
  should expose tag values and checksum status, but association validation must
  remain outside the packet primitive unless a later step explicitly scopes it.
- Held-for-update Errata 8772 affects Section 3.3.4 SACK chunk length wording.
  Any SACK implementation should cite both RFC 9260 Section 3.3.4 and this
  held erratum when documenting the chosen length handling.

## Blocked Until Later Evidence

- Do not decode every UDP/9899 payload as SCTP. RFC 6951 support must use a
  conservative shape gate, and unrelated UDP payloads must remain `Raw`.
- Do not discard unknown but structurally valid chunk types, parameter types,
  cause codes, flags, PPIDs, HMAC IDs, adaptation codepoints, or error
  detection method IDs solely because they are absent from an enum.
- Do not expose chunk or parameter padding as semantic value bytes. Padding
  should be preserved for round-trip and display, and ignored for semantic
  typed values.
- Do not reject constructible packets at build time solely because a field
  value is protocol-invalid. Explicit caller values must survive so generated
  tools can craft malformed packets.
- Do not implement SCTP association state, retransmission, congestion control,
  fragmentation/reassembly service, stream scheduling, dynamic address
  reconfiguration workflow, socket APIs, AUTH cryptography, DTLS, or live
  sender behavior inside `crafter`.
- Do not add live SCTP validation from the developer machine. Any later live
  work must be externally executed, explicitly confirmed, and documented through
  the repository live-gate policy.
- Do not rely on packet captures, vendor behavior, Stack Overflow answers,
  expired drafts, implementation source, or public host observations as
  authority for wire facts unless a later source-backed step records them as
  non-normative fixture context.
