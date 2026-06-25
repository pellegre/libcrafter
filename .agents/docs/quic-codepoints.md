# QUIC Codepoint Authority Notes

Source-backed QUIC registry notes for the `quic-protocol-bootstrap` plan. This
file is the implementation source note for QUIC versions, transport parameters,
frame types, and transport error codes until a later generated manifest replaces
it. Parser constants, fixtures, oracle specs, and docs must cite this file or
`.agents/docs/quic-manifest.md`; do not use model memory as authority for QUIC
wire behavior.

## Provenance

- IANA QUIC XML: <https://www.iana.org/assignments/quic/quic.xml>
- IANA QUIC HTML: <https://www.iana.org/assignments/quic/quic.xhtml>
- Local refreshed cache: `/home/e/.cache/rfc-protocol-spec/sources/iana/quic.xml`
- Cache/live SHA-256 checked on 2026-06-25:
  `8867dffa0213139187ea9bb358ab907b746f47918a6ed713c38a322580232536`
- IANA registry created: 2021-02-11
- IANA registry last updated: 2026-05-04
- Reviewed source boundary: `.agents/docs/quic-manifest.md` and
  `/tmp/rfc-protocol-spec-handoff/protocol-manifest.json`

Rows marked `default-eligible` are permanent and backed by selected RFC
evidence in `quic-manifest.md`. Rows marked `non-default` must be preserved as
known numeric codepoints but must not be emitted by defaults or exported as
stable convenience constants until a later source-backed step selects them.
Multipath rows are permanent in IANA, but remain non-default here because the
current IANA xref is draft-like and `quic-manifest.md` records the final RFC
state as unresolved.

## Registry Policy

| Registry | Codepoint space | Permanent policy | Provisional policy | Reserved or grease rule |
| --- | --- | --- | --- | --- |
| QUIC Versions | 32-bit | Specification Required; first unassigned codepoint by Standards Action | Expert Review; Date field update by First Come First Served | Values matching `0x?a?a?a?a` are reserved. Recognize with `(value & 0x0f0f0f0f) == 0x0a0a0a0a`. `0x00000000` is reserved for Version Negotiation. |
| QUIC Transport Parameters | 62-bit QUIC varint | Standards Action or IESG Approval for `0x00-0x3f`; Specification Required above `0x3f`; first unassigned codepoint by Standards Action | Expert Review; Date field update by First Come First Served | Values `31 * N + 27`, for integer values of `N`, are reserved greasing values and must not be assigned by IANA. |
| QUIC Frame Types | 62-bit QUIC varint | Standards Action or IESG Approval for `0x00-0x3f`; Specification Required above `0x3f`; first unassigned codepoint by Standards Action | Expert Review; Date field update by First Come First Served | No frame-type grease formula is listed in the IANA QUIC registry or selected RFC 9000 sections. Unknown frame handling must be byte-preserving only where the parser has source-backed length rules. |
| QUIC Transport Error Codes | 62-bit QUIC varint | Standards Action or IESG Approval for `0x00-0x3f`; Specification Required above `0x3f`; first unassigned codepoint by Standards Action | Expert Review; Date field update by First Come First Served | `0x0100-0x01ff` is the permanent `CRYPTO_ERROR` TLS alert-code range. No registry-specific grease formula is listed. |

Unknown-codepoint policy for all four registries:

- Unknown versions remain typed numeric values. Version-independent header
  recognition may proceed, but version-specific packet grammar must not be
  guessed.
- Unknown transport parameters preserve the parameter identifier, encoded
  length, and raw value bytes. Truncated identifiers, lengths, or values must
  return structured `CrafterError` values.
- Unknown frame types preserve the frame type and raw bytes only when a
  source-backed parser can determine the frame extent. Otherwise decoding must
  fail with a structured `CrafterError` instead of guessing.
- Unknown transport error codes preserve the numeric value and any
  `CONNECTION_CLOSE` reason bytes.
- Builders preserve caller-supplied malformed or reserved values; `compile()`
  only fills dependent fields when unset.

## QUIC Versions

| Value | Name | Status | Reference | Date | Controller | Notes | Default |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 0x00000000 | 0x00000000 | permanent | RFC 9000 | 2021-02-11 | IETF | Reserved for Version Negotiation | default-eligible |
| 0x00000001 | 0x00000001 | permanent | RFC 9000 | 2021-02-11 | IETF | QUIC version 1 | default-eligible |
| 0x51303433 | 0x51303433 | provisional | none | 2021-10-15 | Google | Google QUIC Q043 | non-default: provisional experiment |
| 0x51303436 | 0x51303436 | provisional | none | 2021-10-15 | Google | Google QUIC Q046 | non-default: provisional experiment |
| 0x51303530 | 0x51303530 | provisional | none | 2021-10-15 | Google | Google QUIC Q050 | non-default: provisional experiment |
| 0x6b3343cf | 0x6b3343cf | permanent | RFC 9369 | 2022-12-16 | IETF | QUIC version 2 | default-eligible |
| 0x6f7dc0fd | 0x6f7dc0fd | provisional | draft-ietf-scone-protocol-04 | 2026-04-16 | IETF | SCONE Protocol - Even Signal Values | non-default: draft provisional |
| 0x709a50c4 | 0x709a50c4 | provisional | RFC 9369 | 2022-12-16 | IETF | QUIC v2 draft codepoint | non-default: provisional |
| 0xef7dc0fd | 0xef7dc0fd | provisional | draft-ietf-scone-protocol-04 | 2026-04-16 | IETF | SCONE Protocol - Odd Signal Values | non-default: draft provisional |

## QUIC Transport Parameters

| Value | Name | Status | Reference | Date | Controller | Notes | Default |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 0x00 | original_destination_connection_id | permanent | RFC 9000 Section 18.2 | 2021-02-11 | IETF | none | default-eligible |
| 0x01 | max_idle_timeout | permanent | RFC 9000 Section 18.2 | 2021-02-11 | IETF | none | default-eligible |
| 0x02 | stateless_reset_token | permanent | RFC 9000 Section 18.2 | 2021-02-11 | IETF | none | default-eligible |
| 0x03 | max_udp_payload_size | permanent | RFC 9000 Section 18.2 | 2021-02-11 | IETF | none | default-eligible |
| 0x04 | initial_max_data | permanent | RFC 9000 Section 18.2 | 2021-02-11 | IETF | none | default-eligible |
| 0x05 | initial_max_stream_data_bidi_local | permanent | RFC 9000 Section 18.2 | 2021-02-11 | IETF | none | default-eligible |
| 0x06 | initial_max_stream_data_bidi_remote | permanent | RFC 9000 Section 18.2 | 2021-02-11 | IETF | none | default-eligible |
| 0x07 | initial_max_stream_data_uni | permanent | RFC 9000 Section 18.2 | 2021-02-11 | IETF | none | default-eligible |
| 0x08 | initial_max_streams_bidi | permanent | RFC 9000 Section 18.2 | 2021-02-11 | IETF | none | default-eligible |
| 0x09 | initial_max_streams_uni | permanent | RFC 9000 Section 18.2 | 2021-02-11 | IETF | none | default-eligible |
| 0x0a | ack_delay_exponent | permanent | RFC 9000 Section 18.2 | 2021-02-11 | IETF | none | default-eligible |
| 0x0b | max_ack_delay | permanent | RFC 9000 Section 18.2 | 2021-02-11 | IETF | none | default-eligible |
| 0x0c | disable_active_migration | permanent | RFC 9000 Section 18.2 | 2021-02-11 | IETF | none | default-eligible |
| 0x0d | preferred_address | permanent | RFC 9000 Section 18.2 | 2021-02-11 | IETF | none | default-eligible |
| 0x0e | active_connection_id_limit | permanent | RFC 9000 Section 18.2 | 2021-02-11 | IETF | none | default-eligible |
| 0x0f | initial_source_connection_id | permanent | RFC 9000 Section 18.2 | 2021-02-11 | IETF | none | default-eligible |
| 0x10 | retry_source_connection_id | permanent | RFC 9000 Section 18.2 | 2021-02-11 | IETF | none | default-eligible |
| 0x11 | version_information | permanent | RFC 9368 | 2022-12-16 | IETF | none | default-eligible |
| 0x20 | max_datagram_frame_size | permanent | RFC 9221 | 2021-10-20 | IETF | none | default-eligible |
| 0x3e | initial_max_path_id | permanent | RFC-ietf-quic-multipath-21 | 2026-03-30 | IETF | multipath xref unresolved in manifest | non-default: draft/multipath |
| 0x173e | discard | provisional | QUIC WG Quantum Readiness test URI | 2022-06-02 | none | Receiver silently discards | non-default: provisional experiment |
| 0x219e | scone_supported | provisional | draft-ietf-scone-protocol-04 | 2026-04-16 | IETF | none | non-default: draft provisional |
| 0x26ab | google handshake message | provisional | none | 2022-11-01 | Google | Used to carry Google internal handshake message | non-default: provisional experiment |
| 0x2ab2 | grease_quic_bit | permanent | RFC 9287 | 2022-07-13 | IETF | QUIC bit grease signal | default-eligible |
| 0x3127 | initial_rtt | provisional | none | 2021-10-20 | Google | Initial RTT in microseconds | non-default: provisional experiment |
| 0x3128 | google_connection_options | provisional | none | 2021-10-20 | Google | Google connection options for experimentation | non-default: provisional experiment |
| 0x3129 | user_agent | provisional | none | 2021-10-20 | Google | User agent string (deprecated) | non-default: provisional experiment |
| 0x4752 | google_version | provisional | none | 2026-05-04 | Google | Deprecated; use version_information instead | non-default: provisional experiment |
| 0xff73db | version_information_draft | provisional | draft-ietf-quic-version-negotiation-13 | 2025-03-21 | IETF | Deprecated; use version_information instead | non-default: draft provisional |
| 0x219bbcd0 | google_debug_1 | provisional | none | 2025-09-23 | none | none | non-default: provisional |
| 0xff04de1b | min_ack_delay | provisional | draft-ietf-quic-ack-frequency-07 | 2023-10-27 | Mirja Kuehlewind | none | non-default: draft provisional |
| 0x4143414213370002 | bdp_frame | provisional | draft-misell-quic-bdp-token-02 | 2024-01-24 | Q Misell | none | non-default: draft provisional |

## QUIC Frame Types

| Value | Name | Status | Reference | Date | Controller | Notes | Default |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 0x00 | PADDING | permanent | RFC 9000 Section 19.1 | 2021-02-11 | IETF | none | default-eligible |
| 0x01 | PING | permanent | RFC 9000 Section 19.2 | 2021-02-11 | IETF | none | default-eligible |
| 0x02-0x03 | ACK | permanent | RFC 9000 Section 19.3 | 2021-02-11 | IETF | ACK and ACK_ECN encodings | default-eligible |
| 0x04 | RESET_STREAM | permanent | RFC 9000 Section 19.4 | 2021-02-11 | IETF | none | default-eligible |
| 0x05 | STOP_SENDING | permanent | RFC 9000 Section 19.5 | 2021-02-11 | IETF | none | default-eligible |
| 0x06 | CRYPTO | permanent | RFC 9000 Section 19.6 | 2021-02-11 | IETF | none | default-eligible |
| 0x07 | NEW_TOKEN | permanent | RFC 9000 Section 19.7 | 2021-02-11 | IETF | none | default-eligible |
| 0x08-0x0f | STREAM | permanent | RFC 9000 Section 19.8 | 2021-02-11 | IETF | OFF/LEN/FIN bit variants | default-eligible |
| 0x10 | MAX_DATA | permanent | RFC 9000 Section 19.9 | 2021-02-11 | IETF | none | default-eligible |
| 0x11 | MAX_STREAM_DATA | permanent | RFC 9000 Section 19.10 | 2021-02-11 | IETF | none | default-eligible |
| 0x12-0x13 | MAX_STREAMS | permanent | RFC 9000 Section 19.11 | 2021-02-11 | IETF | bidirectional and unidirectional variants | default-eligible |
| 0x14 | DATA_BLOCKED | permanent | RFC 9000 Section 19.12 | 2021-02-11 | IETF | none | default-eligible |
| 0x15 | STREAM_DATA_BLOCKED | permanent | RFC 9000 Section 19.13 | 2021-02-11 | IETF | none | default-eligible |
| 0x16-0x17 | STREAMS_BLOCKED | permanent | RFC 9000 Section 19.14 | 2021-02-11 | IETF | bidirectional and unidirectional variants | default-eligible |
| 0x18 | NEW_CONNECTION_ID | permanent | RFC 9000 Section 19.15 | 2021-02-11 | IETF | none | default-eligible |
| 0x19 | RETIRE_CONNECTION_ID | permanent | RFC 9000 Section 19.16 | 2021-02-11 | IETF | none | default-eligible |
| 0x1a | PATH_CHALLENGE | permanent | RFC 9000 Section 19.17 | 2021-02-11 | IETF | none | default-eligible |
| 0x1b | PATH_RESPONSE | permanent | RFC 9000 Section 19.18 | 2021-02-11 | IETF | none | default-eligible |
| 0x1c-0x1d | CONNECTION_CLOSE | permanent | RFC 9000 Section 19.19 | 2021-02-11 | IETF | transport and application close variants | default-eligible |
| 0x1e | HANDSHAKE_DONE | permanent | RFC 9000 Section 19.20 | 2021-02-11 | IETF | none | default-eligible |
| 0x1f | IMMEDIATE_ACK | provisional | draft-ietf-quic-ack-frequency-07 | 2023-10-27 | Mirja Kuehlewind | none | non-default: draft provisional |
| 0x30-0x31 | DATAGRAM | permanent | RFC 9221 | 2021-10-20 | IETF | DATAGRAM and DATAGRAM_LEN variants | default-eligible |
| 0x3e-0x3f | PATH_ACK | permanent | RFC-ietf-quic-multipath-21 | 2026-03-30 | IETF | multipath xref unresolved in manifest | non-default: draft/multipath |
| 0xaf | ACK_FREQUENCY | provisional | draft-ietf-quic-ack-frequency-07 | 2023-10-27 | Mirja Kuehlewind | none | non-default: draft provisional |
| 0x3e75 | PATH_ABANDON | permanent | RFC-ietf-quic-multipath-21 | 2026-03-30 | IETF | multipath xref unresolved in manifest | non-default: draft/multipath |
| 0x3e76 | PATH_STATUS_BACKUP | permanent | RFC-ietf-quic-multipath-21 | 2026-03-30 | IETF | multipath xref unresolved in manifest | non-default: draft/multipath |
| 0x3e77 | PATH_STATUS_AVAILABLE | permanent | RFC-ietf-quic-multipath-21 | 2026-03-30 | IETF | multipath xref unresolved in manifest | non-default: draft/multipath |
| 0x3e78 | PATH_NEW_CONNECTION_ID | permanent | RFC-ietf-quic-multipath-21 | 2026-03-30 | IETF | multipath xref unresolved in manifest | non-default: draft/multipath |
| 0x3e79 | PATH_RETIRE_CONNECTION_ID | permanent | RFC-ietf-quic-multipath-21 | 2026-03-30 | IETF | multipath xref unresolved in manifest | non-default: draft/multipath |
| 0x3e7a | MAX_PATH_ID | permanent | RFC-ietf-quic-multipath-21 | 2026-03-30 | IETF | multipath xref unresolved in manifest | non-default: draft/multipath |
| 0x3e7b | PATHS_BLOCKED | permanent | RFC-ietf-quic-multipath-21 | 2026-03-30 | IETF | multipath xref unresolved in manifest | non-default: draft/multipath |
| 0x3e7c | PATH_CIDS_BLOCKED | permanent | RFC-ietf-quic-multipath-21 | 2026-03-30 | IETF | multipath xref unresolved in manifest | non-default: draft/multipath |

## QUIC Transport Error Codes

| Value | Name | Status | Reference | Date | Controller | Description | Default |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 0x00 | NO_ERROR | permanent | RFC 9000 Section 20 | 2021-02-11 | IETF | No error | default-eligible |
| 0x01 | INTERNAL_ERROR | permanent | RFC 9000 Section 20 | 2021-02-11 | IETF | Implementation error | default-eligible |
| 0x02 | CONNECTION_REFUSED | permanent | RFC 9000 Section 20 | 2021-02-11 | IETF | Server refuses a connection | default-eligible |
| 0x03 | FLOW_CONTROL_ERROR | permanent | RFC 9000 Section 20 | 2021-02-11 | IETF | Flow control error | default-eligible |
| 0x04 | STREAM_LIMIT_ERROR | permanent | RFC 9000 Section 20 | 2021-02-11 | IETF | Too many streams opened | default-eligible |
| 0x05 | STREAM_STATE_ERROR | permanent | RFC 9000 Section 20 | 2021-02-11 | IETF | Frame received in invalid stream state | default-eligible |
| 0x06 | FINAL_SIZE_ERROR | permanent | RFC 9000 Section 20 | 2021-02-11 | IETF | Change to final size | default-eligible |
| 0x07 | FRAME_ENCODING_ERROR | permanent | RFC 9000 Section 20 | 2021-02-11 | IETF | Frame encoding error | default-eligible |
| 0x08 | TRANSPORT_PARAMETER_ERROR | permanent | RFC 9000 Section 20 | 2021-02-11 | IETF | Error in transport parameters | default-eligible |
| 0x09 | CONNECTION_ID_LIMIT_ERROR | permanent | RFC 9000 Section 20 | 2021-02-11 | IETF | Too many connection IDs received | default-eligible |
| 0x0a | PROTOCOL_VIOLATION | permanent | RFC 9000 Section 20 | 2021-02-11 | IETF | Generic protocol violation | default-eligible |
| 0x0b | INVALID_TOKEN | permanent | RFC 9000 Section 20 | 2021-02-11 | IETF | Invalid Token received | default-eligible |
| 0x0c | APPLICATION_ERROR | permanent | RFC 9000 Section 20 | 2021-02-11 | IETF | Application error | default-eligible |
| 0x0d | CRYPTO_BUFFER_EXCEEDED | permanent | RFC 9000 Section 20 | 2021-02-11 | IETF | CRYPTO data buffer overflowed | default-eligible |
| 0x0e | KEY_UPDATE_ERROR | permanent | RFC 9000 Section 20 | 2021-02-11 | IETF | Invalid packet protection update | default-eligible |
| 0x0f | AEAD_LIMIT_REACHED | permanent | RFC 9000 Section 20 | 2021-02-11 | IETF | Excessive use of packet protection keys | default-eligible |
| 0x10 | NO_VIABLE_PATH | permanent | RFC 9000 Section 20 | 2021-02-11 | IETF | No viable network path exists | default-eligible |
| 0x11 | VERSION_NEGOTIATION_ERROR | permanent | RFC 9368 | 2022-12-16 | IETF | Error negotiating version | default-eligible |
| 0x0100-0x01ff | CRYPTO_ERROR | permanent | RFC 9000 Section 20 | 2021-05-18 | IETF | TLS alert code | default-eligible |
| 0x3e | APPLICATION_ABANDON_PATH | permanent | RFC-ietf-quic-multipath-21 | 2026-03-30 | IETF | Path abandoned at the application's request | non-default: draft/multipath |
| 0x3e75 | PATH_RESOURCE_LIMIT_REACHED | permanent | RFC-ietf-quic-multipath-21 | 2026-03-30 | IETF | Path abandoned due to resource limitations in the transport | non-default: draft/multipath |
| 0x3e76 | PATH_UNSTABLE_OR_POOR | permanent | RFC-ietf-quic-multipath-21 | 2026-03-30 | IETF | Path abandoned due to unstable interfaces or poor performance | non-default: draft/multipath |
| 0x3e77 | NO_CID_AVAILABLE_FOR_PATH | permanent | RFC-ietf-quic-multipath-21 | 2026-03-30 | IETF | Path abandoned due to no available connection IDs for the path | non-default: draft/multipath |
| 0x4143414213370002 | BDP_TOKEN_ERROR | provisional | draft-misell-quic-bdp-token-02 | 2024-01-24 | Q Misell | The BDP token received from the client is invalid | non-default: draft provisional |

