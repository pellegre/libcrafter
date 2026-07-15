# CoAP RFC Source Manifest

Authoritative evidence gate for the planned `crafter` CoAP packet primitives.
Later CoAP code, tests, fixtures, oracle specifications, probe plans, and
documentation must trace wire behavior to this manifest, a reviewed IANA
snapshot, or a later source note that cites the same official evidence.

No CoAP implementation existed when this review was completed. In the tables
below, **implement** means that a later plan step may implement the cited
packet-layer behavior. **Preserve opaquely** means retain bytes or numeric
values without assigning unsupported semantics. **Operational-only** means the
source informs validation or documentation but does not belong in the packet
primitive. **Out of scope** means the behavior must not be added to `crafter`.

## Review provenance and authority

Reviewed on **2026-07-14** against these official source families:

- RFC Editor RFC information and document pages for publication status,
  normative text, and the canonical Updates/Updated by metadata.
- IETF Datatracker document pages for current document state and relationship
  metadata.
- RFC Editor Errata records, including Verified, Reported, Held for Document
  Update, and Rejected records.
- IANA's [Constrained RESTful Environments (CoRE) Parameters registry](https://www.iana.org/assignments/core-parameters/core-parameters.xhtml),
  last updated 2026-07-02.

RFC and Datatracker relationship metadata agreed for the selected documents.
No selected RFC is obsolete or obsoleted. RFC 9876, published in November
2025, is a current update to RFC 7252 and is therefore part of the evidence
set even though it was not in the initial candidate list.

IANA is the current assignment authority for CoAP codes, option numbers,
Content-Formats, signaling codes and options, and OSCORE flag bits. The RFCs
below define grammar and semantics; later exported constants must be checked
against a dated IANA snapshot rather than copied from an RFC table alone.

## Selected source matrix

| Source | Packet-layer use and wire-gating sections | Current relationship and Errata status | Disposition |
| --- | --- | --- | --- |
| [RFC 7252](https://www.rfc-editor.org/info/rfc7252), [Datatracker](https://datatracker.ietf.org/doc/rfc7252/) | Core datagram grammar in Sections 3, 3.1, and 3.2; message identity and matching in Sections 4.1, 4.4, and 5.3; option and payload rules in Sections 5.4 and 5.5; method, response, and base-option semantics in Sections 5.8 through 5.10; URI and discovery behavior in Sections 6 through 8; registries and ports in Section 12; examples in Appendices A and B. | Updated by RFCs 7959, 8613, 8974, 9175, and 9876. [Errata](https://www.rfc-editor.org/errata/rfc7252): Verified 4948, 4949, 5078, 4954; Held 4895; Rejected 4946, 4947, 5284, 5429. | **Implement** datagram parse, serialize, build, inspect, matching metadata, and conservative dispatch. **Preserve opaquely** unknown codepoints, options, formats, explicit malformed overrides, and secure ciphertext. Retransmission, caching, proxying, and services are **operational-only** or **out of scope**. |
| [RFC 6690](https://www.rfc-editor.org/info/rfc6690), [Datatracker](https://datatracker.ietf.org/doc/rfc6690/) | CoRE Link Format grammar and lossless extensions in Section 2, link attributes in Section 3, `/.well-known/core` and query filtering in Section 4, and assignments in Section 7. | No formal update or obsolescence relation. [Errata](https://www.rfc-editor.org/errata/rfc6690): Held 3751; Rejected 5254. | **Implement** typed link-format parse/serialize and discovery packet helpers. **Preserve opaquely** unknown link extensions. Resource-directory storage and discovery services are **out of scope**. |
| [RFC 7641](https://www.rfc-editor.org/info/rfc7641), [Datatracker](https://datatracker.ietf.org/doc/rfc7641/) | Observe option format in Section 2; request, notification, and serial-order rules in Sections 3.1 through 3.4 and 4.1 through 4.5; registration cancellation in Section 3.6. Reliable-transport changes come from RFC 8323 Section 7. | Updated by RFC 8323. [Errata](https://www.rfc-editor.org/errata/rfc7641): no records found. | **Implement** the option value, packet classification, and stateless 24-bit serial comparison. Observer lists, subscriptions, notification scheduling, and cache state are **operational-only** and **out of scope**. |
| [RFC 7959](https://www.rfc-editor.org/info/rfc7959), [Datatracker](https://datatracker.ietf.org/doc/rfc7959/) | Block1, Block2, Size1, and Size2 option grammar and semantics in Sections 2 through 4; Observe interaction in Section 5; assignments in Section 7. BERT changes come from RFC 8323 Section 6. | Updates RFC 7252; updated by RFC 8323. [Errata](https://www.rfc-editor.org/errata/rfc7959): Verified 7523; Held 6083. | **Implement** lossless block fields, offsets, validation, and packet helpers. Transfer assembly, retransmission, and persistent reassembly state are **operational-only** and **out of scope**. |
| [RFC 7967](https://www.rfc-editor.org/info/rfc7967), [Datatracker](https://datatracker.ietf.org/doc/rfc7967/) | No-Response option and response-class suppression mask in Sections 2 and 2.1; token, cache, and proxy considerations in Section 3; assignment in Section 5. | No formal update or obsolescence relation. [Errata](https://www.rfc-editor.org/errata/rfc7967): no records found. | **Implement** the option and stateless mask inspection. Actual response suppression, token lifecycle, and proxy behavior are **operational-only**. |
| [RFC 8132](https://www.rfc-editor.org/info/rfc8132), [Datatracker](https://datatracker.ietf.org/doc/rfc8132/) | FETCH in Section 2; PATCH and iPATCH in Section 3; method-set classification in Section 4; method and Content-Format assignments in Section 6. | No formal update or obsolescence relation. [Errata](https://www.rfc-editor.org/errata/rfc8132): no records found. | **Implement** lossless code metadata and builders for assigned methods, including PATCH and iPATCH. Patch-document application semantics are **out of scope**. |
| [RFC 8323](https://www.rfc-editor.org/info/rfc8323), [Datatracker](https://datatracker.ietf.org/doc/rfc8323/) | One complete reliable frame in Sections 3.1 through 3.3, especially Section 3.2; signaling code and option spaces in Sections 5.1 through 5.6; BERT in Section 6; reliable Observe changes in Section 7; reliable URI and port evidence in Section 8; assignments in Section 11. | Updates RFCs 7641 and 7959; updated by RFC 8974. [Errata](https://www.rfc-editor.org/errata/rfc8323): no records found. | **Implement** one typed TCP/TLS frame, consumed-length reporting, signaling, BERT metadata, and conservative complete-frame dispatch. TCP stream reassembly, connections, TLS, WebSocket framing, health, and signaling sessions are **out of scope**. |
| [RFC 8613](https://www.rfc-editor.org/info/rfc8613), [Datatracker](https://datatracker.ietf.org/doc/rfc8613/) | OSCORE option and context inputs in Sections 2 and 3; protected field classes in Section 4; COSE object, nonce, plaintext, and AAD in Section 5; compressed option and payload encoding in Section 6; binding and sequence inputs in Section 7; protection/unprotection processing in Section 8; assignments in Section 13; official vectors in Appendix C. | Updates RFC 7252. [Errata](https://www.rfc-editor.org/errata/rfc8613): Verified 8229; Held 8230. | **Implement** explicit typed protect/unprotect transforms and immutable context inputs for the admitted algorithm profile. **Preserve opaquely** unknown algorithms and unsupported security metadata. Context enrollment, global replay databases, key lifecycle, ACE, and EDHOC are **out of scope**. |
| [RFC 8768](https://www.rfc-editor.org/info/rfc8768), [Datatracker](https://datatracker.ietf.org/doc/rfc8768/) | Hop-Limit option in Section 3 and option/response assignments in Section 6. | No formal update or obsolescence relation. [Errata](https://www.rfc-editor.org/errata/rfc8768): no records found. | **Implement** typed option inspection and explicit safe decrement semantics. Proxy loops and forwarding are **operational-only**. |
| [RFC 8974](https://www.rfc-editor.org/info/rfc8974), [Datatracker](https://datatracker.ietf.org/doc/rfc8974/) | Extended TKL grammar in Sections 2 and 2.1; capability signaling in Section 2.2; signaling assignment in Section 6; updated UDP and reliable layouts in Appendix A. | Updates RFCs 7252 and 8323. [Errata](https://www.rfc-editor.org/errata/rfc8974): no records found. | **Implement** checked extended-token encoding and decoding for datagram and reliable layers. Stateless-client state serialization and intermediary workflows in Sections 3 and 4 are **operational-only**. |
| [RFC 9175](https://www.rfc-editor.org/info/rfc9175), [Datatracker](https://datatracker.ietf.org/doc/rfc9175/) | Echo option format in Section 2.2.1; Request-Tag format and blockwise association in Sections 3.2 through 3.8; secure token binding changes in Sections 4.1 and 4.2; assignments in Section 7. | Updates RFC 7252. [Errata](https://www.rfc-editor.org/errata/rfc9175): no records found. | **Implement** opaque Echo and Request-Tag values, stateless request-tag metadata, and validation of secure token use. Freshness policy and anti-amplification challenge state are **operational-only**. |
| [RFC 9176](https://www.rfc-editor.org/info/rfc9176), [Datatracker](https://datatracker.ietf.org/doc/rfc9176/) | Resource-directory discovery and content-format context in Section 4, registration and lookup interfaces in Sections 5 and 6, and RD assignments in Section 9. It reuses RFC 6690 link-format payloads rather than defining the base CoAP message grammar. | No formal update or obsolescence relation. [Errata](https://www.rfc-editor.org/errata/rfc9176): no records found. | RD request/response workflows, storage, lookup, registration lifetime, and server policy are **operational-only** and **out of scope**. Generic link-format extension bytes remain **preserved opaquely** by the RFC 6690 model. |
| [RFC 9177](https://www.rfc-editor.org/info/rfc9177), [Datatracker](https://datatracker.ietf.org/doc/rfc9177/) | Q-Block1 and Q-Block2 properties and bit layout in Sections 4.1 and 4.2; their interactions in Sections 4.3 through 4.8; response/token constraints in Sections 5 and 6; assignments in Section 12; reliable examples in Appendix B. | No formal update or obsolescence relation. [Errata](https://www.rfc-editor.org/errata/rfc9177): no records found. | **Implement** lossless Q-Block fields, boundaries, and stateless burst metadata. Congestion control, burst scheduling, recovery, and transfer assembly are **operational-only** and **out of scope**. |
| [RFC 9203](https://www.rfc-editor.org/info/rfc9203), [Datatracker](https://datatracker.ietf.org/doc/rfc9203/) | ACE OSCORE profile, including OSCORE input material in Section 3.2.1, token provisioning and context setup in Sections 3 through 6, and ACE registries in Section 9. It does not replace RFC 8613 packet protection grammar. | No formal update or obsolescence relation. [Errata](https://www.rfc-editor.org/errata/rfc9203): Reported 8678, affecting an operational cross-reference in Section 4.2. | ACE authorization, token provisioning, context enrollment, and lifecycle are **out of scope**. Do not use this RFC as authority for Group OSCORE packet grammar. Unsupported enrollment metadata is **preserved opaquely** only when encountered inside an otherwise supported value. |
| [RFC 9876](https://www.rfc-editor.org/info/rfc9876), [Datatracker](https://datatracker.ietf.org/doc/rfc9876/) | Current CoAP Content-Format registration policy in Sections 4.1 through 4.3, including the Media Type column, temporary entries, expert review, and documentation IDs 64998 and 64999. It changes registry authority, not the on-wire unsigned-integer encoding. | Updates RFC 7252. [Errata](https://www.rfc-editor.org/errata/rfc9876): no records found. | **Implement** current registry metadata and documentation-reserved classification in the later IANA snapshot. Unknown Content-Format values remain **preserved opaquely**. Registration workflow is **operational-only**. |

## Formal update graph

The complete formal update graph among the reviewed sources is:

- RFC 7252 is updated by RFC 7959, RFC 8613, RFC 8974, RFC 9175, and
  RFC 9876.
- RFC 7641 is updated by RFC 8323.
- RFC 7959 is updated by RFC 8323.
- RFC 8323 is updated by RFC 8974.
- No reviewed source obsoletes another source, and none is currently
  obsoleted.

Relationship metadata sometimes renders RFC 7959 twice on the RFC 8323 info
page. The RFC 8323 document header and Datatracker metadata identify the
unique update targets as RFC 7641 and RFC 7959.

## Errata decisions that gate later work

- RFC 7252 Verified Errata 4948, 4949, and 5078 change cache-key,
  response-option handling, and discovery attribute requirements. Verified
  Erratum 4954 corrects Content-Format terminology and registry columns and
  is also cited by RFC 9876 and IANA. Later URI helpers must review Held
  Erratum 4895, but must not treat held text as an incorporated RFC update.
- RFC 6690 Held Erratum 3751 is an ABNF rule-name case typo; ABNF rule names
  are case-insensitive. Rejected Erratum 5254 must not change the grammar.
- RFC 7959 Verified Erratum 7523 corrects prose describing block size.
  Held Erratum 6083 clarifies the option-property table and non-repeatability;
  later tests must cite the normative RFC text as well as the held record.
- RFC 8613 Verified Erratum 8229 repairs a negation in the server-aliveness
  explanation. Held technical Erratum 8230 identifies unusable or invalid
  Recipient Context handling as a review point; later unprotect code must
  return an explicit error without claiming that held text is normative.
- RFC 9203 Reported Erratum 8678 corrects a reference for access-token expiry.
  It is neither verified nor packet-layer authority and remains outside the
  crate's OSCORE transform.
- The other selected RFCs had no errata records on the review date.

## IANA registry boundary

The CoRE Parameters registry was reviewed as the current authority for:

- CoAP Method and Response Codes;
- CoAP Option Numbers;
- CoAP Content-Formats;
- CoAP Signaling Codes and Signaling Option Numbers; and
- OSCORE Flag Bits.

The registry includes permanent RFC-backed rows, unassigned ranges,
experimental ranges, and rows whose references are still Internet-Drafts or
RFC Editor queue placeholders. A registered number is not by itself evidence
that `crafter` may implement draft semantics. The later registry snapshot must
record row status and reference authority, expose unknown numeric values, and
avoid treating provisional or draft-backed rows as stable exported behavior.

## Work in progress and unresolved authority

The current Group OSCORE specification is
[draft-ietf-core-oscore-groupcomm-28](https://datatracker.ietf.org/doc/draft-ietf-core-oscore-groupcomm/),
which Datatracker places in the RFC Editor queue. IANA currently references it
with the placeholder `RFC-ietf-core-oscore-groupcomm-28`, including OSCORE flag
bit 2 and the `gosc` target attribute. It did not have a final RFC number on
the review date.

Consequently:

- do not freeze a Group OSCORE serializer, signature grammar, algorithm set,
  or exported constants from the Internet-Draft;
- the already assigned IANA Group Flag may be represented only as explicitly
  provisional metadata and otherwise preserved opaquely;
- the planned Group OSCORE step must re-check Datatracker, RFC Editor, Errata,
  and IANA before implementation and stop if the final RFC is still absent or
  differs from draft 28; and
- RFC 9203 is an ACE profile for pairwise OSCORE provisioning, not a substitute
  source for Group OSCORE wire behavior.

The active CoAP corrections-and-clarifications and OSCORE key-update work are
also Internet-Drafts. They are search leads, not authority for current wire
behavior. Later work must not silently incorporate their text before RFC
publication and relationship review.

## Scope and safety guardrails

- Unknown structurally valid codes, options, Content-Formats, signaling
  values, and security metadata remain lossless; unsupported semantics never
  become a decode rejection by default.
- Explicit caller values survive compilation, including malformed values.
  Validation is opt-in and reports inconsistencies without rewriting bytes.
- Reliable CoAP means one complete frame with a consumed length, not TCP
  stream reassembly or connection management.
- OSCORE is a typed packet-to-packet transform. ACE, EDHOC, key enrollment,
  global replay state, group membership, and key distribution remain outside
  the crate.
- Offline fixtures and documentation use documentation address space. This
  evidence review performs no live traffic and authorizes none.
