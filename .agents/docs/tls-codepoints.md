# TLS Codepoint Authority Table

Source-backed TLS registry notes for the `tls-protocol-bootstrap` plan. This
file is the implementation source note for TLS versions, ContentType,
HandshakeType, Alert, CipherSuite, ExtensionType, Supported Groups,
SignatureScheme, PSK mode, and certificate-compression codepoints until a
later generated manifest replaces it. Rust constants, fixtures, oracle specs,
and docs must cite this file or `.agents/docs/tls-manifest.md`; do not use
model memory as authority for TLS wire behavior.

This is agent-facing implementation guidance. User-facing TLS documentation
belongs under `docs/`. This file adds no live traffic defaults, credentials,
public endpoint data, sensitive captures, or host-specific paths.

## Provenance

- IANA TLS Parameters XML: <https://www.iana.org/assignments/tls-parameters/tls-parameters.xml>
- IANA TLS Parameters HTML: <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml>
- IANA TLS Extensions XML: <https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xml>
- IANA TLS Extensions HTML: <https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml>
- RFC 5246, TLS 1.2: <https://www.rfc-editor.org/rfc/rfc5246.html>
- RFC 8446, TLS 1.3: <https://www.rfc-editor.org/rfc/rfc8446.html>
- RFC 8447 and RFC 9847: TLS/DTLS registry policy and Recommended-column
  handling.
- RFC 8701: GREASE reserved values for TLS extension points.
- RFC 8879: certificate-compression extension, handshake, and algorithm IDs.
- Reviewed on 2026-06-30. IANA TLS Parameters reported `updated` 2026-06-18;
  IANA TLS Extensions reported `updated` 2026-06-10.

IANA rows currently cite some active TLS drafts such as
`RFC-ietf-tls-rfc8446bis-13` and `RFC-ietf-tls-tls12-frozen-08`. For this
plan, IANA is authoritative for assignment state. Stable wire grammar still
comes from the selected RFCs in `.agents/docs/tls-manifest.md` until a later
step explicitly selects a draft-backed row.

## Registry Policy

| Registry | Wire width | Source | Status columns | Default rule | Preserve-only rule |
| --- | --- | --- | --- | --- | --- |
| ProtocolVersion | 16 bits | RFC 5246, RFC 8446, RFC 8701 | RFC-defined, GREASE | `0x0303` legacy fields and `0x0304` supported_versions are default-eligible where the grammar requires them. | Unknown versions, old versions, and GREASE values stay numeric. |
| ContentType | 8 bits | IANA TLS ContentType | DTLS where listed | `change_cipher_spec`, `alert`, `handshake`, and `application_data` are TLS-over-TCP bootstrap rows. | DTLS-only or deferred rows stay numeric/opaque. |
| AlertLevel and AlertDescription | 8 bits each | RFC 5246/RFC 8446, IANA TLS Alerts | DTLS where listed | Known alert names may be labeled. | Unknown alert descriptions stay numeric. |
| HandshakeType | 8 bits | IANA TLS HandshakeType plus RFC tables | DTLS where listed | TLS 1.2/1.3 handshake messages in scope may be typed by later steps. | DTLS-only, reserved, unassigned, and unknown types stay numeric with raw bodies. |
| CipherSuite | 16 bits | IANA TLS Cipher Suites plus RFC 8446 | DTLS and Recommended | Recommended RFC-backed rows may get labels. | Recommended `N`/`D`, draft-backed, GREASE, private, reserved, and unknown suites stay buildable and round-trippable by value. |
| ExtensionType | 16 bits | IANA TLS ExtensionType Values plus RFC 8446 | TLS 1.3 context, DTLS-only, Recommended | Selected RFC-backed extension rows may get typed bodies. | Unknown, duplicate, private, GREASE, DTLS-only, and out-of-scope extension bodies remain raw-preserved. |
| Supported Groups | 16 bits | IANA TLS Supported Groups plus RFC 8446/RFC 7919 | DTLS and Recommended | Selected RFC-backed groups may get labels. | Unknown, private-use, GREASE, draft-backed, and unassigned groups stay numeric. |
| SignatureScheme | 16 bits | IANA TLS SignatureScheme plus RFC 8446 | Recommended | Recommended RFC-backed schemes may get labels. | Unknown, private-use, GREASE, reserved, and legacy `N` schemes stay numeric. |
| PskKeyExchangeMode | 8 bits | IANA TLS PskKeyExchangeMode plus RFC 8446/RFC 8701 | Recommended | `psk_ke` and `psk_dhe_ke` may get labels. | Unknown, private-use, and GREASE modes stay numeric. |
| Certificate Compression Algorithm | 16 bits | IANA TLS Certificate Compression Algorithm IDs plus RFC 8879 | registry policy ranges | `zlib`, `brotli`, and `zstd` may get labels if certificate compression is selected. | Experimental and unknown algorithms stay numeric. |

Unknown-codepoint policy for all registries:

- Decode preserves the numeric value and the bytes controlled by that value.
- Builders must allow explicit caller-supplied numeric values, including
  malformed, unassigned, private-use, reserved, GREASE, or discouraged values.
- `compile()` may fill dependent lengths when unset, but must not replace a
  caller-specified codepoint with a safer default.
- Truncated buffers must return structured errors with context, required byte
  count, and available byte count.

## ProtocolVersion

TLS version values are not maintained in a standalone IANA TLS version
registry. Use RFC 5246 for TLS 1.2 syntax, RFC 8446 for TLS 1.3 legacy-version
and supported_versions behavior, and RFC 8701 for GREASE version values.

| Value | Name | Status | Source | Notes | Default |
| --- | --- | --- | --- | --- | --- |
| `0x0300` | SSL 3.0 historical value | obsolete / not TLS default | RFC 8446 sec. 5.1 notes the historical sequence | Preserve only if seen or explicitly built. | non-default |
| `0x0301` | TLS 1.0 | obsolete for modern negotiation | RFC 8446 sec. 5.1 compatibility note | Initial ClientHello record version compatibility value; not the negotiated TLS 1.3 version. | preserve/compat |
| `0x0302` | TLS 1.1 | obsolete | RFC 8446 Appendix D relationship to prior versions | Preserve only unless a later TLS 1.1 fixture needs it. | non-default |
| `0x0303` | TLS 1.2 / TLS 1.3 legacy record and hello fields | in scope | RFC 5246, RFC 8446 sec. 4.1.2 and sec. 5.1 | TLS 1.3 ClientHello and ServerHello legacy fields use `0x0303`; TLS 1.2 uses it as the protocol version. | default-eligible |
| `0x0304` | TLS 1.3 supported_versions value | in scope | RFC 8446 sec. 4.2.1 and sec. 5.1 | Real TLS 1.3 negotiation is carried in supported_versions, not the record legacy_version field. | default-eligible |
| `0x0A0A`, `0x1A1A`, ... `0xFAFA` | GREASE versions | reserved | RFC 8701 sec. 2 | Values matching bytes `?A ?A` from the RFC 8701 set must stay numeric and non-default. | preserve-only |

## ContentType

Source: IANA TLS Parameters registry `TLS ContentType`; record syntax in RFC
5246 sec. 6.2 and RFC 8446 sec. 5.1.

| Value | Hex | Name | Status | Source | Notes | Default |
| --- | --- | --- | --- | --- | --- | --- |
| `0-19` | `0x00-0x13` | Unassigned | requires coordination | IANA, RFC 5764, RFC 9443 | Preserve as unknown if explicitly built; do not default. | non-default |
| `20` | `0x14` | `change_cipher_spec` | assigned | IANA, RFC 8446bis draft row; RFC 8446 sec. 5 | TLS compatibility content type; later step may add typed one-byte body. | default-eligible |
| `21` | `0x15` | `alert` | assigned | IANA, RFC 8446bis draft row; RFC 8446 sec. 6 | Alert records carry `AlertLevel` and `AlertDescription`. | default-eligible |
| `22` | `0x16` | `handshake` | assigned | IANA, RFC 8446bis draft row; RFC 8446 sec. 4 | Handshake records may contain one or more handshake messages or fragments. | default-eligible |
| `23` | `0x17` | `application_data` | assigned | IANA, RFC 8446bis draft row; RFC 8446 sec. 5 | TLS 1.3 encrypted content remains opaque. | default-eligible |
| `24` | `0x18` | `heartbeat` | assigned | IANA, RFC 6520 | Candidate only; heartbeat step must resolve RFC 6520 errata and safety boundary. | deferred |
| `25` | `0x19` | `tls12_cid` | assigned | IANA, RFC 9146 | DTLS/TLS CID behavior is out of the TLS-over-TCP bootstrap. | preserve-only |
| `26` | `0x1A` | `ACK` | assigned | IANA, RFC 9147 | DTLS 1.3; not TLS-over-TCP. | preserve-only |
| `27` | `0x1B` | `return_routability_check` | assigned | IANA, RFC 9853 | DTLS path validation; not TLS-over-TCP. | preserve-only |
| `28-31` | `0x1C-0x1F` | Unassigned | unassigned | IANA | Preserve explicit values only. | non-default |
| `32-63` | `0x20-0x3F` | Reserved | reserved | IANA, RFC 9147 | Reserved for DTLS content types. | preserve-only |
| `64-255` | `0x40-0xFF` | Unassigned | requires coordination | IANA, RFC 5764, RFC 9443 | Preserve explicit values only. | non-default |

## Alert Codepoints

`AlertLevel` is from RFC 5246 and RFC 8446. TLS 1.3 treats most alerts as
fatal but the wire level remains a one-byte level followed by a one-byte
description.

| Value | Name | Source | Notes |
| --- | --- | --- | --- |
| `1` | `warning` | RFC 5246 / RFC 8446 | Preserve when seen; not all TLS 1.3 alerts use warning semantics. |
| `2` | `fatal` | RFC 5246 / RFC 8446 | Default alert level for explicit fatal alerts. |

Source for AlertDescription rows: IANA TLS Alerts.

| Value | Name | Status | Source | Notes |
| --- | --- | --- | --- | --- |
| `0` | `close_notify` | assigned | IANA, RFC 8446bis draft row | Closure alert. |
| `10` | `unexpected_message` | assigned | IANA, RFC 8446bis draft row | Generic unexpected record/message alert. |
| `20` | `bad_record_mac` | assigned | IANA, RFC 8446bis draft row | Includes protected-record integrity failures. |
| `21` | `decryption_failed_RESERVED` | reserved legacy | IANA, RFC 8446bis draft row | Used before TLS 1.3; preserve only. |
| `22` | `record_overflow` | assigned | IANA, RFC 8446bis draft row | Relevant to record length validation. |
| `30` | `decompression_failure_RESERVED` | reserved legacy | IANA, RFC 8446bis draft row | Preserve only. |
| `40` | `handshake_failure` | assigned | IANA, RFC 8446bis draft row | Generic handshake failure. |
| `41` | `no_certificate_RESERVED` | reserved SSLv3 | IANA, RFC 8446bis draft row | Not TLS; preserve only. |
| `42` | `bad_certificate` | assigned | IANA, RFC 8446bis draft row | Certificate alert label only; no certificate validation. |
| `43` | `unsupported_certificate` | assigned | IANA, RFC 8446bis draft row | Label only. |
| `44` | `certificate_revoked` | assigned | IANA, RFC 8446bis draft row | Label only. |
| `45` | `certificate_expired` | assigned | IANA, RFC 8446bis draft row | Label only. |
| `46` | `certificate_unknown` | assigned | IANA, RFC 8446bis draft row | Label only. |
| `47` | `illegal_parameter` | assigned | IANA, RFC 8446bis draft row | Useful for malformed-codepoint examples. |
| `48` | `unknown_ca` | assigned | IANA, RFC 8446bis draft row | Label only. |
| `49` | `access_denied` | assigned | IANA, RFC 8446bis draft row | Label only. |
| `50` | `decode_error` | assigned | IANA, RFC 8446bis draft row | Useful for malformed decode fixtures. |
| `51` | `decrypt_error` | assigned | IANA, RFC 8446bis draft row | Label only. |
| `52` | `too_many_cids_requested` | DTLS-oriented | IANA, RFC 9147 | Preserve-only for TLS-over-TCP. |
| `60` | `export_restriction_RESERVED` | reserved legacy | IANA, RFC 8446bis draft row | Preserve only. |
| `70` | `protocol_version` | assigned | IANA, RFC 8446bis draft row | Version negotiation failure label. |
| `71` | `insufficient_security` | assigned | IANA, RFC 8446bis draft row | Label only. |
| `80` | `internal_error` | assigned | IANA, RFC 8446bis draft row | Label only. |
| `86` | `inappropriate_fallback` | assigned | IANA, RFC 7507 | Related to `TLS_FALLBACK_SCSV`. |
| `90` | `user_canceled` | assigned | IANA, RFC 8446bis draft row | Label only. |
| `100` | `no_renegotiation_RESERVED` | reserved legacy | IANA, RFC 8446bis draft row | Used before TLS 1.3; preserve only. |
| `109` | `missing_extension` | assigned | IANA, RFC 8446bis draft row | Extension validation label. |
| `110` | `unsupported_extension` | assigned | IANA, RFC 8446bis draft row | Extension validation label. |
| `111` | `certificate_unobtainable_RESERVED` | reserved legacy | IANA, RFC 6066 / RFC 8446bis draft row | Preserve only. |
| `112` | `unrecognized_name` | assigned | IANA, RFC 6066 | SNI alert label. |
| `113` | `bad_certificate_status_response` | assigned | IANA, RFC 6066 | Status request alert label. |
| `114` | `bad_certificate_hash_value_RESERVED` | reserved legacy | IANA, RFC 6066 / RFC 8446bis draft row | Preserve only. |
| `115` | `unknown_psk_identity` | assigned | IANA, RFC 4279 | PSK alert label. |
| `116` | `certificate_required` | assigned | IANA, RFC 8446bis draft row | TLS 1.3 certificate-request alert label. |
| `117` | `general_error` | assigned | IANA, RFC 8446bis draft row | Label only. |
| `120` | `no_application_protocol` | assigned | IANA, RFC 7301 / RFC 8447 | ALPN alert label. |
| `121` | `ech_required` | assigned | IANA, RFC 9849 | ECH is out of first bootstrap scope; preserve label only. |
| other gaps | Unassigned | unassigned | IANA | Preserve explicit values only. |

## HandshakeType

Source: IANA TLS HandshakeType; RFC 5246 Appendix A.4.1 and RFC 8446 Appendix
B.3. RFC 8446 represents HelloRetryRequest as a `server_hello` form rather
than a distinct default handshake type.

| Value | Hex | Name | Status | Source | Notes | Default |
| --- | --- | --- | --- | --- | --- | --- |
| `0` | `0x00` | `hello_request_RESERVED` | reserved legacy | IANA, RFC 8446bis draft row | Used before TLS 1.3. | preserve-only |
| `1` | `0x01` | `client_hello` | assigned | IANA, RFC 8446bis draft row; RFC 5246/RFC 8446 tables | Core bootstrap handshake. | default-eligible |
| `2` | `0x02` | `server_hello` | assigned | IANA, RFC 8446bis draft row; RFC 5246/RFC 8446 tables | Also carries TLS 1.3 HelloRetryRequest form. | default-eligible |
| `3` | `0x03` | `hello_verify_request_RESERVED` | reserved / DTLS legacy | IANA, RFC 6347 / RFC 8446bis draft row | Not TLS-over-TCP. | preserve-only |
| `4` | `0x04` | `new_session_ticket` | assigned | IANA, RFC 4507 / RFC 8447 | TLS 1.2 and TLS 1.3 forms differ; later step must select grammar. | default-eligible |
| `5` | `0x05` | `end_of_early_data` | assigned | IANA, RFC 8446bis draft row | TLS 1.3 post-early-data message. | default-eligible |
| `6` | `0x06` | `hello_retry_request_RESERVED` | reserved draft legacy | IANA, RFC 8446bis draft row | Functionality moved to `server_hello`. | preserve-only |
| `7` | `0x07` | Unassigned | unassigned | IANA | Preserve explicit values only. | non-default |
| `8` | `0x08` | `encrypted_extensions` | assigned | IANA, RFC 8446bis draft row | TLS 1.3 encrypted extensions. | default-eligible |
| `9` | `0x09` | `request_connection_id` | DTLS-oriented | IANA, RFC 9147 | Not TLS-over-TCP. | preserve-only |
| `10` | `0x0A` | `new_connection_id` | DTLS-oriented | IANA, RFC 9147 | Not TLS-over-TCP. | preserve-only |
| `11` | `0x0B` | `certificate` | assigned | IANA, RFC 8446bis draft row; RFC 5246/RFC 8446 tables | TLS 1.2 and TLS 1.3 forms differ. | default-eligible |
| `12` | `0x0C` | `server_key_exchange_RESERVED` | reserved legacy | IANA, RFC 8446bis draft row | Used before TLS 1.3. | preserve-only |
| `13` | `0x0D` | `certificate_request` | assigned | IANA, RFC 8446bis draft row | TLS 1.2 and TLS 1.3 forms differ. | default-eligible |
| `14` | `0x0E` | `server_hello_done_RESERVED` | reserved legacy | IANA, RFC 8446bis draft row | Used before TLS 1.3. | preserve-only |
| `15` | `0x0F` | `certificate_verify` | assigned | IANA, RFC 8446bis draft row | Typed later. | default-eligible |
| `16` | `0x10` | `client_key_exchange_RESERVED` | reserved legacy | IANA, RFC 8446bis draft row | Used before TLS 1.3. | preserve-only |
| `17` | `0x11` | `client_certificate_request` | assigned legacy | IANA, RFC 9261 | RFC 9261 client-generated authenticator context; not first bootstrap typed. | preserve-only |
| `18-19` | `0x12-0x13` | Unassigned | unassigned | IANA | Preserve explicit values only. | non-default |
| `20` | `0x14` | `finished` | assigned | IANA, RFC 8446bis draft row | Finished message is opaque verify data until typed. | default-eligible |
| `21` | `0x15` | `certificate_url_RESERVED` | reserved legacy | IANA, RFC 8446bis draft row | Preserve only. | preserve-only |
| `22` | `0x16` | `certificate_status_RESERVED` | reserved legacy | IANA, RFC 8446bis draft row | Preserve only. | preserve-only |
| `23` | `0x17` | `supplemental_data_RESERVED` | reserved legacy | IANA, RFC 8446bis draft row | Preserve only. | preserve-only |
| `24` | `0x18` | `key_update` | assigned | IANA, RFC 8446bis draft row | TLS 1.3 key update. | default-eligible |
| `25` | `0x19` | `compressed_certificate` | assigned | IANA, RFC 8879 | Only typed if certificate compression is selected. | deferred |
| `26` | `0x1A` | `ekt_key` | DTLS-oriented | IANA, RFC 8870 | Not TLS-over-TCP bootstrap. | preserve-only |
| `27-253` | `0x1B-0xFD` | Unassigned | unassigned | IANA | Unknown handshake bodies remain raw. | non-default |
| `254` | `0xFE` | `message_hash` | assigned | IANA, RFC 8446bis draft row | Synthetic TLS 1.3 transcript message; preserve/label only. | preserve-only |
| `255` | `0xFF` | Unassigned | unassigned | IANA | Preserve explicit values only. | non-default |

## CipherSuite

Source: IANA TLS Cipher Suites. Values are encoded as two bytes on the wire and
may be represented as a big-endian `u16` in Rust labels. RFC 8446 sec. 9.1
requires TLS 1.3 implementations to support `TLS_AES_128_GCM_SHA256`; this
crate is a packet primitive and does not implement TLS policy.

| Wire bytes | U16 | Name | IANA Recommended | Source | Notes | Default |
| --- | --- | --- | --- | --- | --- | --- |
| `{0x13,0x01}` | `0x1301` | `TLS_AES_128_GCM_SHA256` | Y | IANA, RFC 8446 | TLS 1.3 AEAD suite. | default-eligible |
| `{0x13,0x02}` | `0x1302` | `TLS_AES_256_GCM_SHA384` | Y | IANA, RFC 8446 | TLS 1.3 AEAD suite. | default-eligible |
| `{0x13,0x03}` | `0x1303` | `TLS_CHACHA20_POLY1305_SHA256` | Y | IANA, RFC 8446 / RFC 8439 | TLS 1.3 AEAD suite. | default-eligible |
| `{0x13,0x04}` | `0x1304` | `TLS_AES_128_CCM_SHA256` | Y | IANA, RFC 8446 | TLS 1.3 AEAD suite. | default-eligible |
| `{0x13,0x05}` | `0x1305` | `TLS_AES_128_CCM_8_SHA256` | N | IANA, RFC 8446 | Assigned but not Recommended; preserve/build by value. | preserve-only |
| `{0xC0,0x2B}` | `0xC02B` | `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` | Y | IANA, RFC 5289 | TLS 1.2 commonly used AEAD suite. | label-eligible |
| `{0xC0,0x2C}` | `0xC02C` | `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` | Y | IANA, RFC 5289 | TLS 1.2 commonly used AEAD suite. | label-eligible |
| `{0xC0,0x2F}` | `0xC02F` | `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | Y | IANA, RFC 5289 | TLS 1.2 commonly used AEAD suite. | label-eligible |
| `{0xC0,0x30}` | `0xC030` | `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` | Y | IANA, RFC 5289 | TLS 1.2 commonly used AEAD suite. | label-eligible |
| `{0xCC,0xA8}` | `0xCCA8` | `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256` | Y | IANA, RFC 7905 | TLS 1.2 ChaCha20-Poly1305 suite. | label-eligible |
| `{0xCC,0xA9}` | `0xCCA9` | `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256` | Y | IANA, RFC 7905 | TLS 1.2 ChaCha20-Poly1305 suite. | label-eligible |
| `{0xCC,0xAC}` | `0xCCAC` | `TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256` | Y | IANA, RFC 7905 | TLS 1.2 PSK suite; label only unless PSK body selected. | label-eligible |
| `{0xD0,0x01}` | `0xD001` | `TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256` | Y | IANA, RFC 8442 | TLS 1.2 PSK suite; label only unless PSK body selected. | label-eligible |
| `{0xD0,0x02}` | `0xD002` | `TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384` | Y | IANA, RFC 8442 | TLS 1.2 PSK suite; label only unless PSK body selected. | label-eligible |
| `{0xD0,0x05}` | `0xD005` | `TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256` | Y | IANA, RFC 8442 | TLS 1.2 PSK suite; label only unless PSK body selected. | label-eligible |
| `{0x00,0xFF}` | `0x00FF` | `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` | N | IANA, RFC 5746 | Signaling cipher suite value, not a normal cipher. | preserve-only |
| `{0x56,0x00}` | `0x5600` | `TLS_FALLBACK_SCSV` | N | IANA, RFC 7507 | Signaling cipher suite value. | preserve-only |
| `{0x0A,0x0A}`, `{0x1A,0x1A}`, ... `{0xFA,0xFA}` | `0x0A0A` ... `0xFAFA` | GREASE | reserved | RFC 8701 | Reserved sparse values. | preserve-only |
| `{0xFF,0x00-0xFF}` | `0xFF00-0xFFFF` | Reserved for Private Use | private use | IANA | Buildable only by explicit value. | preserve-only |

Other assigned cipher suites in the IANA registry must not become convenience
constants until this table records their source, Recommended state, and
bootstrap disposition.

## ExtensionType

Source: IANA TLS ExtensionType Values. TLS 1.3 context abbreviations are `CH`
ClientHello, `SH` ServerHello, `EE` EncryptedExtensions, `CT` Certificate, `CR`
CertificateRequest, `NST` NewSessionTicket, and `HRR` HelloRetryRequest.

| Value | Hex | Name | TLS 1.3 contexts | IANA Recommended | Source | Notes | Default |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `0` | `0x0000` | `server_name` | CH, EE, CR | Y | IANA, RFC 6066, RFC 9261 | SNI. `CR` context is tied to RFC 9261 and must be selected explicitly. | default-eligible |
| `1` | `0x0001` | `max_fragment_length` | CH, EE | N | IANA, RFC 6066, RFC 8449 | Superseded by record_size_limit guidance. | preserve-only |
| `5` | `0x0005` | `status_request` | CH, CR, CT | Y | IANA, RFC 6066 | Certificate status request. | default-eligible |
| `10` | `0x000A` | `supported_groups` | CH, EE | Y | IANA, RFC 8422, RFC 7919 | Formerly `elliptic_curves`. | default-eligible |
| `11` | `0x000B` | `ec_point_formats` | - | Y | IANA, RFC 8422 | TLS 1.2 legacy EC extension. | label-eligible |
| `13` | `0x000D` | `signature_algorithms` | CH, CR | Y | IANA, RFC 8446 | Carries SignatureScheme list. | default-eligible |
| `15` | `0x000F` | `heartbeat` | CH, EE | Y | IANA, RFC 6520 | Candidate only; heartbeat safety step must select it. | deferred |
| `16` | `0x0010` | `application_layer_protocol_negotiation` | CH, EE | Y | IANA, RFC 7301 | ALPN vector grammar. | default-eligible |
| `21` | `0x0015` | `padding` | CH | Y | IANA, RFC 7685 | Padding extension. | default-eligible |
| `27` | `0x001B` | `compress_certificate` | CH, CR | Y | IANA, RFC 8879 | Certificate compression negotiation. | deferred |
| `28` | `0x001C` | `record_size_limit` | CH, EE | Y | IANA, RFC 8449 | Preferred record-size limit extension. | default-eligible |
| `40` | `0x0028` | Reserved | - | D | IANA, RFC 9847 | Reserved formerly used codepoint. | preserve-only |
| `41` | `0x0029` | `pre_shared_key` | CH, SH | Y | IANA, RFC 8446 | TLS 1.3 PSK extension; body is position-sensitive. | default-eligible |
| `42` | `0x002A` | `early_data` | CH, EE, NST | Y | IANA, RFC 8446 | TLS 1.3 early data. | default-eligible |
| `43` | `0x002B` | `supported_versions` | CH, SH, HRR | Y | IANA, RFC 8446 | Carries `0x0304` for TLS 1.3. | default-eligible |
| `44` | `0x002C` | `cookie` | CH, HRR | Y | IANA, RFC 8446 | TLS 1.3 cookie extension. | default-eligible |
| `45` | `0x002D` | `psk_key_exchange_modes` | CH | Y | IANA, RFC 8446 | Carries PskKeyExchangeMode list. | default-eligible |
| `46` | `0x002E` | Reserved | - | D | IANA, RFC 9847 | Reserved formerly used codepoint. | preserve-only |
| `47` | `0x002F` | `certificate_authorities` | CH, CR | Y | IANA, RFC 8446 | TLS 1.3 certificate-authorities extension. | default-eligible |
| `48` | `0x0030` | `oid_filters` | CR | Y | IANA, RFC 8446 | CertificateRequest extension. | default-eligible |
| `49` | `0x0031` | `post_handshake_auth` | CH | Y | IANA, RFC 8446 | TLS 1.3 post-handshake authentication signal. | default-eligible |
| `50` | `0x0032` | `signature_algorithms_cert` | CH, CR | Y | IANA, RFC 8446 | Certificate signature schemes. | default-eligible |
| `51` | `0x0033` | `key_share` | CH, SH, HRR | Y | IANA, RFC 8446 | TLS 1.3 key share. | default-eligible |
| `57` | `0x0039` | `quic_transport_parameters` | CH, EE | Y | IANA, RFC 9001 | QUIC binding; out of TLS-over-TCP packet scope. | preserve-only |
| `2570`, `6682`, ... `64250` | `0x0A0A` ... `0xFAFA` | GREASE reserved | CH, CR, NST | N | IANA, RFC 8701 | Reserved sparse extension values. | preserve-only |
| `64768` | `0xFD00` | `ech_outer_extensions` | CH | Y | IANA, RFC 9849 | ECH deferred by TLS manifest. | preserve-only |
| `65037` | `0xFE0D` | `encrypted_client_hello` | CH, HRR, EE | Y | IANA, RFC 9849 | ECH deferred by TLS manifest. | preserve-only |
| `65038-65279` | `0xFE0E-0xFEFF` | Unassigned | - | - | IANA | Preserve explicit values only. | non-default |
| `65280` | `0xFF00` | Reserved for Private Use | - | - | IANA | Buildable only by explicit value. | preserve-only |
| `65281` | `0xFF01` | `renegotiation_info` | - | Y | IANA, RFC 5746 | TLS 1.2 renegotiation; label only unless selected. | preserve-only |
| `65282-65535` | `0xFF02-0xFFFF` | Reserved for Private Use | - | - | IANA | Buildable only by explicit value. | preserve-only |

Other assigned ExtensionType rows remain unknown-preserved until a later step
adds a row here with source, contexts, and disposition.

## Supported Groups

Source: IANA TLS Supported Groups; RFC 8446 sec. 4.2.7 and RFC 7919 for FFDHE
groups. Values are 16-bit `NamedGroup` codepoints inside supported_groups and
key_share.

| Value | Hex | Name | IANA Recommended | Source | Notes | Default |
| --- | --- | --- | --- | --- | --- | --- |
| `0` | `0x0000` | Reserved | - | IANA, RFC 8447 | Reserved zero value. | preserve-only |
| `23` | `0x0017` | `secp256r1` | Y | IANA, RFC 8422 | RFC 8446 named group. | default-eligible |
| `24` | `0x0018` | `secp384r1` | Y | IANA, RFC 8422 | RFC 8446 named group. | default-eligible |
| `25` | `0x0019` | `secp521r1` | N | IANA, RFC 8422 | Assigned but no longer Recommended. | preserve-only |
| `29` | `0x001D` | `x25519` | Y | IANA, RFC 8446bis draft row / RFC 8422 | RFC 8446 named group. | default-eligible |
| `30` | `0x001E` | `x448` | Y | IANA, RFC 8446bis draft row / RFC 8422 | RFC 8446 named group. | default-eligible |
| `256` | `0x0100` | `ffdhe2048` | N | IANA, RFC 7919 | RFC 8446 lists FFDHE; IANA Recommended is N. | preserve-only |
| `257` | `0x0101` | `ffdhe3072` | N | IANA, RFC 7919 | Preserve/build by value unless selected. | preserve-only |
| `258` | `0x0102` | `ffdhe4096` | N | IANA, RFC 7919 | Preserve/build by value unless selected. | preserve-only |
| `259` | `0x0103` | `ffdhe6144` | N | IANA, RFC 7919 | Preserve/build by value unless selected. | preserve-only |
| `260` | `0x0104` | `ffdhe8192` | N | IANA, RFC 7919 | Preserve/build by value unless selected. | preserve-only |
| `4588` | `0x11EC` | `X25519MLKEM768` | Y | IANA, draft-ietf-tls-ecdhe-mlkem-05 | Draft-backed current row; do not default until selected. | preserve-only |
| `2570`, `6682`, ... `64250` | `0x0A0A` ... `0xFAFA` | GREASE reserved | N | IANA, RFC 8701 | Reserved sparse group values. | preserve-only |
| `65024-65279` | `0xFE00-0xFEFF` | Reserved for Private Use | - | IANA, RFC 8422 | Buildable only by explicit value. | preserve-only |
| `65281` | `0xFF01` | `arbitrary_explicit_prime_curves` | N | IANA, RFC 8422 | Legacy explicit-curve indicator. | preserve-only |
| `65282` | `0xFF02` | `arbitrary_explicit_char2_curves` | N | IANA, RFC 8422 | Legacy explicit-curve indicator. | preserve-only |

## SignatureScheme

Source: IANA TLS SignatureScheme; RFC 8446 sec. 4.2.3. SignatureScheme replaces
the older TLS 1.2 pair of hash and signature algorithms for TLS 1.3 extension
payloads.

| Value | Name | IANA Recommended | Source | Notes | Default |
| --- | --- | --- | --- | --- | --- |
| `0x0201` | `rsa_pkcs1_sha1` | N | IANA, RFC 8446bis draft row / RFC 9155 | Legacy; preserve label only. | preserve-only |
| `0x0203` | `ecdsa_sha1` | N | IANA, RFC 8446bis draft row / RFC 9155 | Legacy; preserve label only. | preserve-only |
| `0x0401` | `rsa_pkcs1_sha256` | Y | IANA, RFC 8446 | RFC 8446 signature scheme. | default-eligible |
| `0x0403` | `ecdsa_secp256r1_sha256` | Y | IANA, RFC 8446 | RFC 8446 signature scheme. | default-eligible |
| `0x0501` | `rsa_pkcs1_sha384` | Y | IANA, RFC 8446 | RFC 8446 signature scheme. | default-eligible |
| `0x0503` | `ecdsa_secp384r1_sha384` | Y | IANA, RFC 8446 | RFC 8446 signature scheme. | default-eligible |
| `0x0601` | `rsa_pkcs1_sha512` | Y | IANA, RFC 8446 | RFC 8446 signature scheme. | default-eligible |
| `0x0603` | `ecdsa_secp521r1_sha512` | Y | IANA, RFC 8446 | RFC 8446 signature scheme. | default-eligible |
| `0x0804` | `rsa_pss_rsae_sha256` | Y | IANA, RFC 8446 | RFC 8446 signature scheme. | default-eligible |
| `0x0805` | `rsa_pss_rsae_sha384` | Y | IANA, RFC 8446 | RFC 8446 signature scheme. | default-eligible |
| `0x0806` | `rsa_pss_rsae_sha512` | Y | IANA, RFC 8446 | RFC 8446 signature scheme. | default-eligible |
| `0x0807` | `ed25519` | Y | IANA, RFC 8446 | RFC 8446 signature scheme. | default-eligible |
| `0x0808` | `ed448` | Y | IANA, RFC 8446 | RFC 8446 signature scheme. | default-eligible |
| `0x0809` | `rsa_pss_pss_sha256` | Y | IANA, RFC 8446 | RFC 8446 signature scheme. | default-eligible |
| `0x080A` | `rsa_pss_pss_sha384` | Y | IANA, RFC 8446 | RFC 8446 signature scheme. | default-eligible |
| `0x080B` | `rsa_pss_pss_sha512` | Y | IANA, RFC 8446 | RFC 8446 signature scheme. | default-eligible |
| `0x0A0A`, `0x1A1A`, ... `0xFAFA` | GREASE reserved | N | IANA, RFC 8701 | Reserved sparse signature-scheme values. | preserve-only |
| `0xFE00-0xFFFF` | Reserved for Private Use | - | IANA, RFC 8446 | Buildable only by explicit value. | preserve-only |

IANA also reserves many ranges for backward compatibility; those ranges remain
numeric/preserve-only unless a later step records a narrower source-backed row.

## PskKeyExchangeMode

Source: IANA TLS PskKeyExchangeMode; RFC 8446 sec. 4.2.9.

| Value | Hex | Name | IANA Recommended | Source | Notes | Default |
| --- | --- | --- | --- | --- | --- | --- |
| `0` | `0x00` | `psk_ke` | Y | IANA, RFC 8446 | PSK-only key establishment mode. | default-eligible |
| `1` | `0x01` | `psk_dhe_ke` | Y | IANA, RFC 8446 | PSK plus DHE key establishment mode. | default-eligible |
| `2-253` | `0x02-0xFD` | Unassigned | - | IANA | Preserve explicit values only. | non-default |
| `254-255` | `0xFE-0xFF` | Reserved for Private Use | - | IANA, RFC 8446 | Buildable only by explicit value. | preserve-only |
| `0x0B`, `0x2A`, `0x49`, `0x68`, `0x87`, `0xA6`, `0xC5`, `0xE4` | listed | GREASE reserved | - | RFC 8701 | Sparse GREASE values for PSK mode lists. | preserve-only |

## Certificate Compression Algorithm IDs

Source: IANA TLS Certificate Compression Algorithm IDs; RFC 8879 sec. 7. The
certificate compression feature remains deferred until its dedicated plan
steps review RFC 8879 errata and select grammar.

| Value | Name | Status | Source | Notes | Default |
| --- | --- | --- | --- | --- | --- |
| `0` | Reserved | reserved | IANA, RFC 8879 | Must not be emitted by defaults. | preserve-only |
| `1` | `zlib` | assigned | IANA, RFC 8879 | Label eligible if certificate compression is selected. | deferred |
| `2` | `brotli` | assigned | IANA, RFC 8879 | Label eligible if certificate compression is selected. | deferred |
| `3` | `zstd` | assigned | IANA, RFC 8879 | Label eligible if certificate compression is selected. | deferred |
| `4-16383` | Unassigned | unassigned | IANA | Preserve explicit values only. | non-default |
| `16384-65535` | Reserved for Experimental Use | experimental | IANA, RFC 8879 | Buildable only by explicit value. | preserve-only |

## Implementation Notes

- Constants should use existing protocol-module patterns: a small constants or
  labels module, typed known/unknown wrappers, and raw-preserving unknown
  variants rather than a registry loader or a parallel API.
- Labels can cover source-backed rows from this file without requiring typed
  extension or handshake-body parsers at the same time.
- TCP dispatch must not infer TLS solely from port numbers. The later registry
  shape gate must check TLS-looking record headers before decoding; otherwise
  payloads remain `Raw`.
- DTLS rows in IANA are recorded only so unknown codepoints can be labeled or
  preserved. This TLS-over-TCP plan does not implement DTLS record formats.
- Draft-backed IANA rows are current registry facts but non-default in this
  bootstrap unless `.agents/docs/tls-manifest.md` or a later notes file selects
  that draft explicitly.
