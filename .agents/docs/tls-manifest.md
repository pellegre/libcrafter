# TLS Source Manifest

Source-backed evidence record for the planned `crafter` TLS packet primitive.
Later constants, record and handshake parsers, builders, fixtures, oracle specs,
probe plans, and documentation must cite this manifest or a narrower TLS notes
file produced from it. Model memory is not authority for TLS wire behavior.

Implementation must stop when a TLS wire fact, registry value, version rule,
extension format, errata interpretation, or Datatracker relationship is
unresolved. The next implementation step must resolve the conflict in a
source-backed note before code, fixtures, or docs use that fact.

## Provenance

Evidence was reviewed on 2026-06-30 using the repo-local
`rfc-protocol-bootstrap` workflow:

- Read the project skill wrapper and the canonical `rfc-protocol-bootstrap`
  skill before selecting sources.
- Ran the repo-local protocol evidence CLI for discovery and a brief manifest
  for the query `TLS`.
- Reviewed the generated handoff and rejected the broad token-match expansion
  that pulled in unrelated TLS-using applications, QUIC, DTLS, DNS, HTTP, EAP,
  SNMP, and mail profiles.
- Refreshed authoritative checks directly from RFC Editor, IANA, IETF
  Datatracker, and RFC Editor errata pages over HTTPS.

The generated evidence workflow is useful for discovery, but this file is the
reviewed source-selection boundary for libcrafter TLS-over-TCP packet-layer
work.

## Current Scope

In scope:

- TLS records carried as TCP application payloads and represented through the
  existing `Packet` and `Layer` abstraction.
- TLS 1.2 and TLS 1.3 record, alert, change-cipher-spec, application-data, and
  handshake framing.
- Compile-time filling of unset TLS record lengths, handshake lengths, and
  nested vector lengths while preserving explicit caller overrides.
- Decode of complete records, multiple records in one TCP payload, and
  complete-record sequences followed by a partial tail.
- Typed ClientHello, ServerHello, HelloRetryRequest-as-ServerHello,
  EncryptedExtensions, Certificate, CertificateRequest, CertificateVerify,
  Finished, NewSessionTicket, EndOfEarlyData, KeyUpdate, selected extensions,
  and opaque encrypted/application fragments when source-backed.
- Unknown content types, handshake types, extensions, cipher suites, supported
  groups, signature schemes, certificate compression algorithms, and private or
  draft-backed registry rows must remain inspectable and round-trippable.
- Conservative TCP dispatch on common TLS ports only when bytes match a
  TLS-looking record shape; non-TLS payloads remain `Raw`.

Out of scope: DTLS, QUIC TLS transcript internals, TLS Encrypted ClientHello, a
TLS client or server, certificate validation, trust stores, scanners, fuzzers,
retry schedulers, TCP stream reassembly, and decryption of protected traffic.
This step adds no live traffic defaults, credentials, public endpoints,
sensitive captures, or host-specific operational data.

## Evidence Index

| ID | Source | Retrieval and review status | Implementation use |
| --- | --- | --- | --- |
| E-IANA-TLS-PARAMS | IANA Transport Layer Security (TLS) Parameters, <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml> and <https://www.iana.org/assignments/tls-parameters/tls-parameters.xml> | HTTPS review on 2026-06-30. XML registry reports `updated` 2026-06-18. | Root authority for TLS ContentType, HandshakeType, Alerts, Cipher Suites, Supported Groups, SignatureScheme, PskKeyExchangeMode, heartbeat registries if selected, and registry policy notes. |
| E-IANA-TLS-EXT | IANA Transport Layer Security (TLS) Extensions, <https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml> and <https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xml> | HTTPS review on 2026-06-30. XML registry reports `updated` 2026-06-10. | Root authority for TLS ExtensionType values and TLS Certificate Compression Algorithm IDs. |
| E-RFC-5246 | RFC 5246, TLS 1.2, <https://www.rfc-editor.org/rfc/rfc5246.html>; Datatracker <https://datatracker.ietf.org/doc/rfc5246/> | RFC Editor and Datatracker reviewed on 2026-06-30. | TLS 1.2 record, handshake, alert, hello, certificate, and vector grammar. Use with relationship notes because RFC 8446 obsoletes it but TLS 1.2 remains explicitly in scope. |
| E-RFC-8446 | RFC 8446, TLS 1.3, <https://www.rfc-editor.org/rfc/rfc8446.html>; Datatracker <https://datatracker.ietf.org/doc/rfc8446/> | RFC Editor and Datatracker reviewed on 2026-06-30. | TLS 1.3 record behavior, legacy record version handling, handshake syntax, extensions, alerts, IANA rules, and TLS 1.2 update notes. |
| E-RFC-6066 | RFC 6066, TLS extension definitions, <https://www.rfc-editor.org/rfc/rfc6066.html>; Datatracker <https://datatracker.ietf.org/doc/rfc6066/> | Datatracker and errata reviewed on 2026-06-30. | Server Name Indication, max_fragment_length, status_request, and older extension grammar that later steps may select. |
| E-RFC-7301 | RFC 7301, ALPN, <https://www.rfc-editor.org/rfc/rfc7301.html>; Datatracker <https://datatracker.ietf.org/doc/rfc7301/> | Datatracker and errata reviewed on 2026-06-30. | Application-Layer Protocol Negotiation extension syntax and IANA registry update context. |
| E-RFC-8449 | RFC 8449, record_size_limit, <https://www.rfc-editor.org/rfc/rfc8449.html>; Datatracker <https://datatracker.ietf.org/doc/rfc8449/> | Datatracker and errata reviewed on 2026-06-30. | Record Size Limit extension and its relationship to RFC 6066 max_fragment_length. |
| E-RFC-8879 | RFC 8879, certificate compression, <https://www.rfc-editor.org/rfc/rfc8879.html>; Datatracker <https://datatracker.ietf.org/doc/rfc8879/> | Datatracker and errata reviewed on 2026-06-30. | compress_certificate extension, CompressedCertificate handshake message, and certificate compression algorithm IDs. |
| E-RFC-8447 | RFC 8447, IANA registry updates for TLS and DTLS, <https://www.rfc-editor.org/rfc/rfc8447.html>; Datatracker <https://datatracker.ietf.org/doc/rfc8447/> | Datatracker and errata reviewed on 2026-06-30. | Registry policy and Recommended-column interpretation for TLS codepoint extraction. |
| E-RFC-9847 | RFC 9847, IANA registry updates for TLS and DTLS, <https://www.rfc-editor.org/rfc/rfc9847.html>; Datatracker <https://datatracker.ietf.org/doc/rfc9847/> | Datatracker reviewed on 2026-06-30 because current IANA TLS registries cite it. | Current update to RFC 8447 registry policy. Downstream codepoint work must account for it before exporting registry-derived constants. |
| E-RFC-8701 | RFC 8701, GREASE, <https://www.rfc-editor.org/rfc/rfc8701.html>; Datatracker <https://datatracker.ietf.org/doc/rfc8701/> | Errata query reviewed on 2026-06-30; no errata buckets were returned. | Boundary evidence for reserved grease values and unknown-preserving codepoint behavior, not endpoint policy. |
| E-RFC-7685 | RFC 7685, ClientHello padding, <https://www.rfc-editor.org/rfc/rfc7685.html>; Datatracker <https://datatracker.ietf.org/doc/rfc7685/> | Errata query reviewed on 2026-06-30; no errata buckets were returned. | Candidate source for the padding extension selected in later extension work. |
| E-RFC-7919 | RFC 7919, FFDHE groups, <https://www.rfc-editor.org/rfc/rfc7919.html>; Datatracker <https://datatracker.ietf.org/doc/rfc7919/> | Errata query reviewed on 2026-06-30. | Candidate source for supported_groups rows beyond elliptic-curve groups. |
| E-RFC-6520 | RFC 6520, heartbeat, <https://www.rfc-editor.org/rfc/rfc6520.html>; Datatracker <https://datatracker.ietf.org/doc/rfc6520/> | Errata query reviewed on 2026-06-30. | Candidate source only if the later heartbeat primitive step selects safe packet-level heartbeat modeling. |
| E-ERRATA | RFC Editor errata search, for example <https://errata.rfc-editor.org/search/?rfc_number=8446&presentation=records> | Errata buckets reviewed on 2026-06-30 for selected baseline documents. | Required stop point before using affected sections in code or fixtures. |
| E-DATATRACKER | IETF Datatracker document pages under <https://datatracker.ietf.org/doc/> | Relationship pages reviewed on 2026-06-30 for selected baseline documents. | Updates, updated-by, obsoletes, and obsoleted-by relationships. |

## Verified Required Candidates

| Required area | Selected candidate sources | Candidate status |
| --- | --- | --- |
| TLS 1.2 | RFC 5246 plus RFC 8446 relationship review and RFC 8447/RFC 9847 registry policy | Verified candidate. Use RFC 5246 only with known updates and errata checked for affected sections. |
| TLS 1.3 | RFC 8446 plus IANA TLS registries | Verified candidate. TLS 1.3 is the core source for legacy record versions, supported_versions, TLS 1.3 handshakes, and extension contexts. |
| SNI | RFC 6066 sec. 3 plus IANA ExtensionType `server_name` | Verified candidate. IANA lists ExtensionType value 0 and TLS 1.3 contexts `CH, EE, CR`; the `CR` context is tied to RFC 9261 and must be selected explicitly if implemented. |
| ALPN | RFC 7301 plus IANA ExtensionType `application_layer_protocol_negotiation` | Verified candidate. IANA lists ExtensionType value 16 and TLS 1.3 contexts `CH, EE`. |
| Record size limit | RFC 8449 plus IANA ExtensionType `record_size_limit` | Verified candidate. IANA lists ExtensionType value 28 and TLS 1.3 contexts `CH, EE`; RFC 8449 updates RFC 6066. |
| Certificate compression | RFC 8879 plus IANA ExtensionType `compress_certificate` and TLS Certificate Compression Algorithm IDs | Verified candidate. IANA lists ExtensionType value 27 and TLS 1.3 contexts `CH, CR`; algorithm IDs include zlib, brotli, and zstd rows from RFC 8879. |
| Relevant IANA TLS registries | IANA TLS Parameters XML/XHTML and TLS Extensions XML/XHTML | Verified candidate. Downstream codepoint extraction must separate permanent RFC rows, private-use rows, draft-backed rows, discouraged rows, and recommended-state changes. |

## IANA Registry Review

IANA registry state reviewed on 2026-06-30:

| Registry source | Updated | Relevant registries for this plan |
| --- | --- | --- |
| E-IANA-TLS-PARAMS | 2026-06-18 | TLS ContentType, TLS Alerts, TLS HandshakeType, TLS Cipher Suites, TLS Supported Groups, TLS SignatureScheme, TLS PskKeyExchangeMode, heartbeat message types and modes if selected. |
| E-IANA-TLS-EXT | 2026-06-10 | TLS ExtensionType Values and TLS Certificate Compression Algorithm IDs. |

IANA TLS registries currently cite RFC 8447 and RFC 9847 for registration and
expert-review policy. Later codepoint steps must cite both when describing row
status or Recommended-column handling. IANA XML contains draft-backed
references, so downstream extraction must label draft, private-use, unassigned,
reserved, discouraged, and GREASE-shaped rows explicitly rather than exporting
them as stable constants by default.

## Selected Source Sections

| Source | Sections to review before code uses facts |
| --- | --- |
| RFC 5246 | Sec. 4 presentation language; sec. 6 record protocol, especially 6.2 and 6.2.1; sec. 7 handshake protocol, especially 7.4 and hello/certificate messages; sec. 7.2 alerts; Appendix A syntax blocks. |
| RFC 8446 | Sec. 3 presentation language; sec. 4 handshake protocol; sec. 4.1 ClientHello, ServerHello, and HelloRetryRequest; sec. 4.2 extension framework and selected extensions; sec. 4.3 through 4.6 TLS 1.3 handshake messages; sec. 5 record protocol; sec. 6 alerts; sec. 11 IANA considerations; Appendix B syntax. |
| RFC 6066 | Sec. 3 server_name; sec. 4 max_fragment_length; sec. 8 status_request; sec. 10 IANA considerations. |
| RFC 7301 | Sec. 3 ALPN extension syntax and negotiation; sec. 6 IANA considerations. |
| RFC 8449 | Sec. 4 record_size_limit extension; sec. 5.1 relationship to max_fragment_length; sec. 6 IANA considerations. |
| RFC 8879 | Sec. 3 negotiating certificate compression; sec. 4 CompressedCertificate message; sec. 5 certificate compression algorithms; IANA considerations. |
| RFC 8447 and RFC 9847 | Registry policy, Recommended-column handling, and expert-review guidance for TLS/DTLS registries. |
| RFC 8701 | GREASE codepoint pattern and unknown-tolerant interoperability guidance for registry-backed values. |
| RFC 7685 | ClientHello padding extension syntax if later selected. |
| RFC 7919 | Supported group entries for finite-field Diffie-Hellman groups if later selected. |
| RFC 6520 | Heartbeat message and extension grammar only if later selected; no endpoint behavior is implied. |

## Datatracker Relationship Review

Datatracker relationship checks on 2026-06-30 found:

- RFC 8446 obsoletes RFC 5246, RFC 5077, and RFC 6961; it updates RFC 5705 and
  RFC 6066.
- RFC 5246 is obsoleted by RFC 8446. Datatracker records it as updated by
  RFC 5746, RFC 5878, RFC 6176, RFC 7465, RFC 7507, RFC 7568, RFC 7627,
  RFC 7685, RFC 7905, RFC 7919, RFC 8447, and RFC 9155.
- RFC 5246 obsoletes RFC 3268, RFC 4346, and RFC 4366, and updates RFC 4492.
- RFC 6066 is updated by RFC 8446, RFC 8449, and RFC 9325, and obsoletes
  RFC 4366.
- RFC 7301 is updated by RFC 8447.
- RFC 8449 updates RFC 6066.
- RFC 8447 is updated by RFC 9847 and updates RFC 3749, RFC 4680, RFC 5077,
  RFC 5246, RFC 5705, RFC 5878, RFC 6520, and RFC 7301.
- RFC 9847 updates RFC 8447.
- No update, updated-by, obsoletes, or obsoleted-by edge was found for RFC 8879
  in the reviewed Datatracker page.

## Errata Review

RFC Editor errata state reviewed on 2026-06-30:

| Source | Errata status summary | Implementation note |
| --- | --- | --- |
| RFC 5246 | Verified (10), Held for Document Update (5), Rejected (7). | Any TLS 1.2 record, handshake, hello, or certificate behavior must check affected errata before coding. |
| RFC 8446 | Verified (16), Held for Document Update (19), Rejected (14). | Any TLS 1.3 record, extension, key_share, PSK, NewSessionTicket, certificate, or alert behavior must check affected errata before coding. |
| RFC 6066 | Verified (2), Reported (1). | SNI, max_fragment_length, and status_request behavior must check affected errata before coding. |
| RFC 7301 | Rejected (1). | No accepted errata blocker found for ALPN syntax during this review. |
| RFC 8449 | No errata buckets returned. | No errata blocker found for record_size_limit during this review. |
| RFC 8879 | Reported (2). | Certificate compression implementation must review reported errata before coding. |
| RFC 8447 | Held for Document Update (1). | Registry-policy wording must be cross-checked with RFC 9847 before codepoint extraction. |
| RFC 8701 | No errata buckets returned. | No errata blocker found for GREASE candidate evidence during this review. |
| RFC 7685 | No errata buckets returned. | No errata blocker found for padding candidate evidence during this review. |
| RFC 7919 | Verified (1), Held for Document Update (1). | Supported group extraction from FFDHE sources must check affected errata before coding. |
| RFC 6520 | Verified (1). | Heartbeat must not be implemented until the heartbeat step resolves the verified erratum and safety boundary. |

## Reviewed Rejected Or Deferred Candidates

| Candidate | Decision |
| --- | --- |
| RFC 9147 DTLS 1.3 and RFC 6347 DTLS 1.2 | Deferred. DTLS is datagram TLS and out of scope for this TLS-over-TCP packet-layer plan. |
| RFC 9001 QUIC TLS binding | Rejected for this plan. QUIC already has separate packet-layer support; QUIC TLS transcript internals are not TLS-over-TCP records. |
| RFC 9849 TLS Encrypted ClientHello and RFC 9848 ECH bootstrapping | Deferred. ECH is current TLS work, but it is outside the first packet-layer TLS scope unless a later source-backed step selects it. |
| Application profiles such as DNS-over-TLS, HTTP over TLS, SMTP TLS, MQTT over TLS, EAP-TLS, SNMP-TLS, and OAuth mutual TLS | Rejected for crate primitives. They combine TLS with higher-layer workflows and belong in generated tools, examples, or separate protocol plans. |
| Certificate validation and service identity sources such as RFC 5280, RFC 6125, RFC 9325, and RFC 9525 | Documentation context only unless a later plan explicitly changes scope. The crate will model packet bytes, not trust decisions. |

## Implementation Guardrails

- Follow existing packet primitive patterns instead of creating a parallel API:
  QUIC for source-backed codepoint evidence and opaque protected payloads, BGP
  for structured decode errors and unknown preservation, and MQTT for TCP
  application-layer builders with length-field handling.
- User-facing TLS docs belong under `docs/`; generated-tool operating guidance
  belongs under `.agents/docs/`.
- Offline examples, fixtures, oracle profiles, and probe plans must use
  documentation address space, deterministic bytes, dry-run behavior, or
  checked-in synthetic pcaps.
- Live TLS validation must be externally executed, explicitly confirmed,
  artifact-preserving, and safe to skip. This evidence step performs no live
  traffic and adds no live defaults.
- Length fields and registry-backed values must preserve explicit caller
  overrides, including intentionally malformed values. Validation helpers may
  be fallible, but `compile()` must not silently repair a caller-specified
  malformed field.
- Short buffers must return structured errors that identify context, required
  length, and available length whenever the failure mode is truncation.

## Unresolved Questions

- RFC 8446 has many verified and held errata. Each later grammar step must cite
  the specific errata decision for any affected section before implementation.
- Current IANA TLS registries include draft-backed rows and Recommended-column
  state changes. Later codepoint extraction must classify those rows explicitly
  before exporting names or constants.
- RFC 6066 SNI has TLS 1.3 contexts expanded by IANA and RFC 9261. Later SNI
  code must decide which contexts are typed and which remain raw-preserved.
- RFC 8879 has reported errata. Certificate compression must not be implemented
  until those reports are reviewed against the selected sections.
- Heartbeat record messages are selected only as a packet primitive after the
  heartbeat step resolved RFC 6520 errata and documented a safe packet-primitive
  boundary.
