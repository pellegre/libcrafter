# SCTP Codepoint Authority Notes

Source-backed SCTP codepoint notes for the SCTP protocol bootstrap plan. This
file is the implementation source note for SCTP chunk types, parameter types,
chunk flags, error causes, Payload Protocol Identifiers, AUTH HMAC identifiers,
adaptation code points, error-detection methods, and the IP protocol number
until generated Rust constants and protocol docs replace the note.

User-facing SCTP documentation belongs under `docs/`. This file adds no live
traffic defaults, credentials, host identifiers, packet captures, external runner
account data, or public endpoint data.

## Provenance

- IANA Stream Control Transmission Protocol (SCTP) Parameters XML:
  <https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xml>
- IANA Stream Control Transmission Protocol (SCTP) Parameters HTML:
  <https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml>
- IANA Assigned Internet Protocol Numbers XML:
  <https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml>
- IANA Assigned Internet Protocol Numbers HTML:
  <https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml>
- Source manifest: `.agents/docs/sctp-rfc-manifest.md`
- Reviewed on 2026-07-03. IANA SCTP Parameters reported `updated`
  2026-02-20; IANA Protocol Numbers reported `updated` 2026-03-09.

The local protocol-manifest generator did not complete in a bounded time during
this step. These notes therefore use the step-01 source manifest plus fresh
IANA XML fetched from the public registry. RFC 9260 remains the base SCTP wire
authority; current IANA rows are authoritative for assigned labels and registry
state.

## Registry Policy

| Registry | Wire width | Source | Crate rule |
| --- | --- | --- | --- |
| IP protocol / IPv6 next-header | 8 bits | IANA Protocol Numbers | Auto-fill `132` for SCTP only when the enclosing IPv4 `protocol` or IPv6 `next_header` is unset. Preserve explicit overrides. |
| Chunk Types | 8 bits | IANA SCTP Parameters, RFC 9260 | Decode known rows when implemented. Preserve unknown or future well-formed chunks with their type, flags, declared value bytes, and padding. |
| Chunk Flags | 8 bits per chunk | IANA SCTP Parameters, RFC 9260 | Preserve every flag bit. Only label assigned bits; do not normalize unassigned bits to zero on decode or overwrite explicit builder values. |
| Parameter Types | 16 bits | IANA SCTP Parameters, RFC 9260 | Decode known rows when implemented. Preserve unknown or future well-formed parameters with type, declared value bytes, and padding. |
| Error Cause Codes | 16 bits | IANA SCTP Parameters, RFC 9260 | Treat causes as parameter-shaped fields. Preserve unknown well-formed causes and reject truncated or under-length causes structurally. |
| SCTP Payload Protocol Identifiers | 32 bits | IANA SCTP Parameters | Label DATA/I-DATA PPIDs only. Do not dispatch application decoders solely from PPID values in this SCTP bootstrap. |
| HMAC Identifiers | 16 bits | IANA SCTP Parameters, RFC 4895 | Label AUTH HMAC IDs. Labels do not imply MAC calculation or verification support. |
| Adaptation Code Points | 32 bits | IANA SCTP Parameters, RFC 5061 | Label adaptation-indication metadata. Do not add adaptation-layer workflow behavior. |
| Error Detection Methods | 32 bits | IANA SCTP Parameters, RFC 9653 | Label alternate error-detection methods. Do not change default CRC32c behavior without explicit zero-checksum handling. |

Temporary draft-backed IANA rows are label-eligible and byte-preserving but
non-default. Do not expose stable convenience builders for temporary DTLS rows
unless a later source-backed scope step admits that behavior.

## IP Protocol Number

| Value | Name | Reference | Crate disposition |
| --- | --- | --- | --- |
| `132` | SCTP, Stream Control Transmission Protocol | IANA Protocol Numbers | Default-eligible for IPv4 `protocol` and IPv6 `next_header` auto-fill when the next layer is SCTP and the field is unset. |

## Chunk Types

Source: IANA SCTP Parameters registry `Chunk Types`; base envelope and
unknown-chunk action bits are from RFC 9260 Sections 3.2 and 15.2.

| Value | Name | Reference | Crate disposition |
| --- | --- | --- | --- |
| `0` | Payload Data (DATA) | RFC 9260 | core typed chunk |
| `1` | Initiation (INIT) | RFC 9260 | core typed chunk |
| `2` | Initiation Acknowledgement (INIT ACK) | RFC 9260 | core typed chunk |
| `3` | Selective Acknowledgement (SACK) | RFC 9260 | core typed chunk |
| `4` | Heartbeat Request (HEARTBEAT) | RFC 9260 | core typed chunk |
| `5` | Heartbeat Acknowledgement (HEARTBEAT ACK) | RFC 9260 | core typed chunk |
| `6` | Abort (ABORT) | RFC 9260 | core typed chunk |
| `7` | Shutdown (SHUTDOWN) | RFC 9260 | core typed chunk |
| `8` | Shutdown Acknowledgement (SHUTDOWN ACK) | RFC 9260 | core typed chunk |
| `9` | Operation Error (ERROR) | RFC 9260 | core typed chunk |
| `10` | State Cookie (COOKIE ECHO) | RFC 9260 | core typed chunk |
| `11` | Cookie Acknowledgement (COOKIE ACK) | RFC 9260 | core typed chunk |
| `12` | Reserved for Explicit Congestion Notification Echo (ECNE) | RFC 9260 | preserve and label |
| `13` | Reserved for Congestion Window Reduced (CWR) | RFC 9260 | preserve and label |
| `14` | Shutdown Complete (SHUTDOWN COMPLETE) | RFC 9260 | core typed chunk |
| `15` | Authentication Chunk (AUTH) | RFC 4895 | preserve and label; no AUTH cryptography |
| `16-62` | Unassigned | IANA | preserve as unknown when structurally valid |
| `63` | Reserved for IETF-defined Chunk Extensions | RFC 9260 | preserve reserved value |
| `64` | Payload Data supporting Interleaving (I-DATA) | RFC 8260 | preserve and label until typed |
| `65` | DTLS (TEMPORARY - registered 2026-02-20, expires 2027-02-20) | draft-ietf-tsvwg-sctp-dtls-chunk-01 | temporary preserve-only |
| `66-126` | Unassigned | IANA | preserve as unknown when structurally valid |
| `127` | Reserved for IETF-defined Chunk Extensions | RFC 9260 | preserve reserved value |
| `128` | Address Configuration Acknowledgment (ASCONF-ACK) | RFC 5061 | preserve and label until typed |
| `129` | Unassigned | IANA | preserve as unknown when structurally valid |
| `130` | Re-configuration Chunk (RE-CONFIG) | RFC 6525 | preserve and label until typed |
| `131` | Unassigned | IANA | preserve as unknown when structurally valid |
| `132` | Padding Chunk (PAD) | RFC 4820 | preserve and label until typed |
| `133-190` | Unassigned | IANA | preserve as unknown when structurally valid |
| `191` | Reserved for IETF-defined Chunk Extensions | RFC 9260 | preserve reserved value |
| `192` | Forward TSN | RFC 3758 | preserve and label until typed |
| `193` | Address Configuration Change Chunk (ASCONF) | RFC 5061 | preserve and label until typed |
| `194` | I-FORWARD-TSN | RFC 8260 | preserve and label until typed |
| `195-254` | Unassigned | IANA | preserve as unknown when structurally valid |
| `255` | Reserved for IETF-defined Chunk Extensions | RFC 9260 | preserve reserved value |

## Parameter Types

Source: IANA SCTP Parameters registry `Chunk Parameter Types`; TLV envelope,
padding, and unknown-parameter action bits are from RFC 9260 Section 3.2.1.

| Value | Hex | Name | Reference | Crate disposition |
| --- | --- | --- | --- | --- |
| `1` | `0x0001` | Heartbeat Info | RFC 9260 | core typed parameter |
| `2-4` | `0x0002-0x0004` | Unassigned | IANA | preserve as unknown when structurally valid |
| `5` | `0x0005` | IPv4 Address | RFC 9260 | core typed parameter |
| `6` | `0x0006` | IPv6 Address | RFC 9260 | core typed parameter |
| `7` | `0x0007` | State Cookie | RFC 9260 | core typed parameter |
| `8` | `0x0008` | Unrecognized Parameter | RFC 9260 | core typed parameter |
| `9` | `0x0009` | Cookie Preservative | RFC 9260 | core typed parameter |
| `10` | `0x000a` | Unassigned | IANA | preserve as unknown when structurally valid |
| `11` | `0x000b` | Host Name Address | RFC 9260 | core typed parameter |
| `12` | `0x000c` | Supported Address Types | RFC 9260 | core typed parameter |
| `13` | `0x000d` | Outgoing SSN Reset Request Parameter | RFC 6525 | preserve and label until typed |
| `14` | `0x000e` | Incoming SSN Reset Request Parameter | RFC 6525 | preserve and label until typed |
| `15` | `0x000f` | SSN/TSN Reset Request Parameter | RFC 6525 | preserve and label until typed |
| `16` | `0x0010` | Re-configuration Response Parameter | RFC 6525 | preserve and label until typed |
| `17` | `0x0011` | Add Outgoing Streams Request Parameter | RFC 6525 | preserve and label until typed |
| `18` | `0x0012` | Add Incoming Streams Request Parameter | RFC 6525 | preserve and label until typed |
| `19-32767` | `0x0013-0x7fff` | Unassigned | IANA | preserve as unknown when structurally valid |
| `32768` | `0x8000` | Reserved for ECN Capable | RFC 9260 | preserve reserved value |
| `32769` | `0x8001` | Zero Checksum Acceptable | RFC 9653 | preserve and label until typed |
| `32770` | `0x8002` | Random | RFC 4895 | preserve and label; no AUTH cryptography |
| `32771` | `0x8003` | Chunk List | RFC 4895 | preserve and label; no AUTH cryptography |
| `32772` | `0x8004` | Requested HMAC Algorithm Parameter | RFC 4895 | preserve and label; no AUTH cryptography |
| `32773` | `0x8005` | Padding | IANA row; RFC 4820 in source manifest | preserve and label until typed |
| `32774` | `0x8006` | DTLS Key Management (TEMPORARY - registered 2026-02-20, expires 2027-02-20) | draft-ietf-tsvwg-sctp-dtls-chunk-01 | temporary preserve-only |
| `32775` | `0x8007` | Unassigned | IANA | preserve as unknown when structurally valid |
| `32776` | `0x8008` | Supported Extensions | RFC 5061 | preserve and label until typed |
| `32777-49151` | `0x8009-0xbfff` | Unassigned | IANA | preserve as unknown when structurally valid |
| `49152` | `0xc000` | Forward TSN supported | RFC 3758 | preserve and label until typed |
| `49153` | `0xc001` | Add IP Address | RFC 5061 | preserve and label until typed |
| `49154` | `0xc002` | Delete IP Address | RFC 5061 | preserve and label until typed |
| `49155` | `0xc003` | Error Cause Indication | RFC 5061 | preserve and label until typed |
| `49156` | `0xc004` | Set Primary Address | RFC 5061 | preserve and label until typed |
| `49157` | `0xc005` | Success Indication | RFC 5061 | preserve and label until typed |
| `49158` | `0xc006` | Adaptation Layer Indication | RFC 5061 | preserve and label until typed |
| `49159-65534` | `0xc007-0xfffe` | Unassigned | IANA | preserve as unknown when structurally valid |
| `65535` | `0xffff` | Reserved for IETF-defined Chunk Extensions | RFC 9260 | preserve reserved value |

## Chunk Flags

Source: IANA SCTP Parameters chunk-flag subregistries. RFC 9260 says unknown
or unassigned chunk flags are normally sent as zero and ignored by receivers
unless a chunk-specific source says otherwise. For `crafter`, decode preserves
all flag bits and builders preserve explicit flag overrides.

| Chunk | Assigned flags | Reference | Crate disposition |
| --- | --- | --- | --- |
| DATA | `0x01` E bit, `0x02` B bit, `0x04` U bit, `0x08` I bit | RFC 9260 | label assigned bits; preserve all others |
| I-DATA | `0x01` E bit, `0x02` B bit, `0x04` U bit, `0x08` I bit | RFC 8260 | label assigned bits; preserve all others |
| ABORT | `0x01` T bit | RFC 9260 | label assigned bit; preserve all others |
| SHUTDOWN COMPLETE | `0x01` T bit | RFC 9260 | label assigned bit; preserve all others |
| INIT, INIT ACK, SACK, HEARTBEAT, HEARTBEAT ACK, SHUTDOWN, SHUTDOWN ACK, ERROR, COOKIE ECHO, COOKIE ACK, ECNE, CWR, AUTH, ASCONF-ACK, RE-CONFIG, PAD, FORWARD TSN, ASCONF, I-FORWARD-TSN | none currently assigned | IANA | preserve all bits as numeric flags |

## Error Cause Codes

Source: IANA SCTP Parameters registry `Error Cause Codes`; RFC 9260 Section
3.3.10 defines the cause envelope.

| Value | Name | Reference | Crate disposition |
| --- | --- | --- | --- |
| `1` | Invalid Stream Identifier | RFC 9260 | core typed cause |
| `2` | Missing Mandatory Parameter | RFC 9260 | core typed cause |
| `3` | Stale Cookie | RFC 9260 | core typed cause |
| `4` | Out of Resource | RFC 9260 | core typed cause |
| `5` | Unresolvable Address | RFC 9260 | core typed cause |
| `6` | Unrecognized Chunk Type | RFC 9260 | core typed cause |
| `7` | Invalid Mandatory Parameter | RFC 9260 | core typed cause |
| `8` | Unrecognized Parameters | RFC 9260 | core typed cause |
| `9` | No User Data | RFC 9260 | core typed cause |
| `10` | Cookie Received While Shutting Down | RFC 9260 | core typed cause |
| `11` | Restart of an Association with New Addresses | RFC 9260 | core typed cause |
| `12` | User-Initiated Abort | RFC 9260 | core typed cause |
| `13` | Protocol Violation | RFC 9260 | core typed cause |
| `14-159` | Unassigned | IANA | preserve as unknown when structurally valid |
| `160` | Request to Delete Last Remaining IP Address | RFC 5061 | preserve and label until typed |
| `161` | Operation Refused Due to Resource Shortage | RFC 5061 | preserve and label until typed |
| `162` | Request to Delete Source IP Address | RFC 5061 | preserve and label until typed |
| `163` | Association Aborted due to illegal ASCONF-ACK | RFC 5061 | preserve and label until typed |
| `164` | Request refused - no authorization | RFC 5061 | preserve and label until typed |
| `165-260` | Unassigned | IANA | preserve as unknown when structurally valid |
| `261` | Unsupported HMAC Identifier | RFC 4895 | preserve and label until typed |
| `262-65535` | Unassigned | IANA | preserve as unknown when structurally valid |

## SCTP Payload Protocol Identifiers

Source: IANA SCTP Parameters registry `SCTP Payload Protocol Identifiers`.
PPIDs are DATA/I-DATA payload metadata, not application-decoder authority for
this SCTP bootstrap.

| Value | Name | Source class | Crate disposition |
| --- | --- | --- | --- |
| `0` | Reserved by SCTP | RFC 9260 | preserve reserved value |
| `1-6` | IUA, M2UA, M3UA, SUA, M2PA, V5UA | RFC-backed IANA rows | label only |
| `7-15` | H.248, BICC/Q.2150.3, TALI, DUA, ASAP, ENRP, H.323, Q.IPC/Q.2150.3, SIMCO | mixed RFC, ITU-T, draft, and IANA rows | label only |
| `16-17` | DDP Segment Chunk, DDP Stream Session Control | RFC 5043 | label only |
| `18-20` | S1AP, RUA, HNBAP | 3GPP rows | label only |
| `21-23` | ForCES-HP, ForCES-MP, ForCES-LP | RFC 5811 | label only |
| `24-25` | SBc-AP, NBAP | 3GPP rows | label only |
| `26` | Unassigned | IANA | preserve as numeric |
| `27-45` | X2AP through SSH over SCTP | mixed IANA rows | label only |
| `46-47` | Diameter in SCTP DATA and Diameter in DTLS/SCTP DATA | RFC 6733 | label only |
| `48-49` | R14P and Generic Data Transfer | IANA rows | label only |
| `50-54` | WebRTC DCEP, string, binary partial, binary, string partial | RFC 8831 and RFC 8832 | label only |
| `55` | 3GPP PUA | 3GPP row | label only |
| `56-57` | WebRTC string empty and binary empty | RFC 8831 | label only |
| `58-64` | XwAP, Xw-Control Plane, NGAP, XnAP, F1 AP, HTTP/SCTP, E1AP | mixed 3GPP and IANA rows | label only |
| `65-69` | ELE2 LI and 3GPP DTLS-over-SCTP PPIDs | mixed IANA and 3GPP rows | label only |
| `70-73` | E2-CP, O-RAN D2, E2-DU, W1AP | O-RAN and 3GPP rows | label only |
| `74-4241` | Unassigned | IANA | preserve as numeric |
| `4242` | DTLS Chunk Key-Management Messages | draft-westerlund-tsvwg-sctp-dtls-chunk-01 | draft-backed label only |
| `4243-4294967295` | Unassigned | IANA | preserve as numeric |

## HMAC Identifiers

Source: IANA SCTP Parameters registry `Hashed Message Authentication Code
(HMAC) Identifiers`; packet-data source is RFC 4895.

| Value | Name | Reference | Crate disposition |
| --- | --- | --- | --- |
| `0` | Reserved | RFC 4895 | preserve reserved value |
| `1` | SHA-1 | RFC 4895 | label only; no MAC computation |
| `2` | Reserved | RFC 4895 | preserve reserved value |
| `3` | SHA-256 | RFC 4895 | label only; no MAC computation |
| `4-65535` | Unassigned | IANA | preserve as numeric |

## Adaptation Code Points

Source: IANA SCTP Parameters registry `Adaptation Code Points`.

| Value | Name | Reference | Crate disposition |
| --- | --- | --- | --- |
| `0` | Unassigned | RFC 5061 | preserve as numeric |
| `0x00000001` | DDP | RFC 5043 | label only |
| `0x00000002-0xffffffff` | Unassigned | RFC 5061 | preserve as numeric |

## Error Detection Methods

Source: IANA SCTP Parameters registry `Error Detection Methods`; packet-data
source is RFC 9653.

| Value | Name | Reference | Crate disposition |
| --- | --- | --- | --- |
| `0` | Reserved | RFC 9653 | preserve reserved value |
| `1` | SCTP over DTLS | RFC 9653 | label only; does not change CRC32c default |
| `2-4294967295` | Unassigned | IANA | preserve as numeric |

## Implementation Rules

- Constants and display labels must cite this file or the exact IANA/RFC source
  row used here.
- `compile()` fills dependent fields only when unset; caller-supplied
  codepoints, flags, lengths, checksums, PPIDs, and raw values survive even
  when malformed or reserved.
- Decode preserves valid unknown chunks, parameters, causes, flags, PPIDs, HMAC
  IDs, adaptation code points, and error-detection methods as inspectable
  numeric values with byte-preserved payloads where the enclosing structure is
  well formed.
- Malformed fixed headers, chunk lengths, parameter lengths, and cause lengths
  must return structured errors with context, required byte count, and
  available byte count where applicable.
- Chunk and parameter padding is not semantic value data. It must round-trip
  separately from declared value bytes.
- Temporary or draft-backed rows must not become default builders, stable typed
  behavior, or application decoders without a later source-backed scope step.
