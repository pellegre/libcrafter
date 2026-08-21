# SNMP RFC Manifest

This manifest records the Simple Network Management Protocol source evidence
that may be used for `crafter` SNMP packet-layer work. It is intentionally a
wire manifest, not an SNMP product plan: `crafter` may build, compile, decode,
summarize, show, and validate individual SNMP messages as packet layers, but it
does not implement a manager, scanner, polling workflow, MIB compiler/browser,
long-running agent daemon, access-control engine, or credential store.

Only facts backed by this manifest may be used downstream in code, tests,
fixtures, examples, docs, oracle specs, probe expectations, or live-validation
plans. Model memory and uncited folklore are not source authority. If a later
slice needs an SNMP fact that is not listed here with an RFC section, an IANA
registry row, a Datatracker/RFC-Editor relationship, or an errata record, update
this manifest first or stop that behavior slice as unsupported.

Date checked: 2026-06-24.

Generated source handoff:
`target/rfc-protocol-spec/snmp/protocol-manifest.json`, generated
2026-06-24T23:06:33Z by `rfc-protocol-spec`.

## Scope Rules

- `crafter` models packet bytes: BER identifiers and lengths, object
  identifiers, SNMP values, variable bindings, PDUs, top-level SNMPv1,
  community-based SNMPv2, and SNMPv3 message wrappers where source-backed.
- MIB object semantics are out of crate scope unless a cited RFC section uses a
  MIB object identifier as packet content, such as notification varbinds.
- Polling, walks, retries, trap receiving services, table rendering, inventory,
  alerting, credential/key storage, key rotation, access-control decisions, and
  engine state machines are generated-tool or operator behavior, not `crafter`
  primitives.
- Authentication and privacy algorithms are in scope only as wire structures or
  byte-preserving fields until a later slice proves that a cryptographic helper
  is a packet primitive and can be implemented without credential storage or
  policy.
- Obsolete, historical, ambiguous, or missing evidence cannot authorize new
  behavior. Such sources may be used for lineage notes or for explicitly
  cited legacy wire formats only.

## Classification Terms

- **Core wire behavior**: defines bytes that may be constructed, auto-filled,
  decoded, preserved, summarized, or validated.
- **Registry authority**: IANA is the authoritative source for numeric or named
  assignments used by the wire model.
- **Extension**: defines an optional security, transport, discovery, or
  related extension. It needs a dedicated implementation slice before use.
- **Mapping**: maps SNMP to a transport, link layer, or other protocol family.
- **Operational guidance**: describes applications, MIBs, configuration, or
  deployment behavior. Do not use it for crate behavior unless it defines
  packet bytes that a later slice cites here.
- **Obsolete/historical**: superseded or historic material. Use only for
  lineage or explicitly supported legacy wire shapes.
- **Ambiguous**: selected by discovery but not sufficiently classified. Do not
  use downstream until a later manifest update resolves the ambiguity.

## Core Wire Sources

### RFC 1157 - SNMPv1 message and PDU syntax

Classification: core wire behavior for SNMPv1, with historical status noted.
Relationship: obsoletes RFC 1098.
Source: https://www.rfc-editor.org/rfc/rfc1157.html

- Section 3.2.2: SNMP uses ASN.1 and a subset of BER; all encodings use the
  definite-length form, and non-constructor encodings are used where permitted.
- Section 4: protocol message construction and serialization through ASN.1 BER.
- Section 4.1.1: `RequestID`, `ErrorStatus`, `ErrorIndex`, `VarBind`, and
  `VarBindList`; retrieval requests still require syntactically valid values,
  with NULL recommended.
- Sections 4.1.2 through 4.1.6 and Section 5: SNMPv1 Message, GetRequest,
  GetNextRequest, GetResponse, SetRequest, Trap PDU tags and fields, generic
  trap values, and version value 0.
- UDP ports 161 and 162 are recorded here for lineage, but the current registry
  authority is IANA Service Name and Transport Protocol Port Number Registry.

Downstream use: SNMPv1 builders, decoders, golden vectors, trap PDU wire fields,
and malformed BER tests may cite these sections. Community policy, access
policy, polling, and agent behavior remain out of scope.

### RFC 1901 - community-based SNMPv2 wrapper

Classification: core wire behavior only for the SNMPv2c top-level wrapper.
Relationship: no obsoletes/updates recorded in the generated handoff.
Source: https://www.rfc-editor.org/rfc/rfc1901.html

- Section 3: SNMPv2c reuses the SNMPv1 community administrative framework and
  message wrapper shape, with version value 1 and PDUs defined elsewhere.

Downstream use: community-based SNMPv2 message construction and decode may use
this source for the top-level `{ version, community, data }` wrapper only.

### RFC 2578 - SMIv2 base syntax used by SNMP values

Classification: core wire behavior for value type names, OBJECT IDENTIFIER
rules, and application syntax referenced by RFC 3416.
Relationship: obsoletes RFC 1902.
Source: https://www.rfc-editor.org/rfc/rfc2578.html

- Sections 2 and 2.2: SMIv2 administrative identifiers, `ObjectSyntax`,
  `SimpleSyntax`, `ApplicationSyntax`, and the base ASN.1/application types.
- Section 3.5: OBJECT IDENTIFIER values are ordered sub-identifiers, with at
  most 128 sub-identifiers and each sub-identifier at most 2^32-1.
- Sections 7.1.1 through 7.1.11: value constraints for INTEGER/Integer32,
  OCTET STRING, OBJECT IDENTIFIER, BITS, IpAddress, Counter32, Gauge32,
  TimeTicks, Opaque, Counter64, and Unsigned32.

Downstream use: SNMP values and OIDs may cite this source only for packet value
syntax. MIB module authoring, table semantics, and conformance text are out of
scope.

### RFC 3411 - SNMP architecture number spaces

Classification: core wire behavior for SNMPv3 architecture identifiers and
IANA-controlled number spaces; operational guidance otherwise.
Relationship: obsoletes RFC 2571; updated by RFC 5343 and RFC 5590.
Source: https://www.rfc-editor.org/rfc/rfc3411.html

- Sections 3.1 through 3.4: names used by the SNMPv3 message model, including
  securityModel, messageProcessingModel, contextEngineID, contextName,
  scopedPDU, and securityLevel.
- Section 5: SNMP-FRAMEWORK-MIB textual conventions for SnmpEngineID,
  SnmpSecurityModel, SnmpMessageProcessingModel, SnmpSecurityLevel, and
  SnmpAdminString where those names appear as wire fields in RFC 3412.
- Section 6: IANA-managed Security Models, Message Processing Models, and
  SnmpEngineID formats.

Downstream use: SNMPv3 labels and unknown-value preservation may cite these
sections. Architecture, application roles, and access-control subsystem behavior
are not crate features.

### RFC 3412 - SNMPv3 message wrapper

Classification: core wire behavior.
Relationship: obsoletes RFC 2572; updated by RFC 5590.
Source: https://www.rfc-editor.org/rfc/rfc3412.html

- Section 5.1: message processing and dispatching definitions used by v3MP.
- Section 6: `SNMPv3Message`, `HeaderData`, `ScopedPduData`, and `ScopedPDU`.
- Sections 6.1 through 6.8: `msgVersion` value 3, `msgID`,
  `msgMaxSize`, `msgFlags` bit meanings and reserved auth/priv combination,
  `msgSecurityModel`, `msgSecurityParameters`, plaintext/encrypted scoped data,
  context engine ID/name, and PDU payload.

Downstream use: SNMPv3 top-level messages, global data, flags, raw security
parameters, scoped PDUs, encrypted scoped data preservation, Report PDU shapes,
and malformed decode coverage may cite this source.

### RFC 3414 - SNMPv3 User-based Security Model

Classification: core wire behavior for USM security-parameter bytes; extension
or operational guidance for authentication/privacy processing.
Relationship: obsoletes RFC 2574; updated by RFC 5590.
Source: https://www.rfc-editor.org/rfc/rfc3414.html

- Section 2.4: `msgSecurityParameters` is the BER serialization of
  `UsmSecurityParameters`.
- Section 2.4 fields: `msgAuthoritativeEngineID`,
  `msgAuthoritativeEngineBoots`, `msgAuthoritativeEngineTime`, `msgUserName`,
  `msgAuthenticationParameters`, and `msgPrivacyParameters`.
- Section 4: discovery Report exchange shapes for engine ID and time
  synchronization.
- Sections 6, 7, and 8: HMAC-MD5-96, HMAC-SHA-96, and CBC-DES wire parameter
  treatment, including fixed authentication-parameter lengths and privacy
  parameter bytes.
- Appendix A.4: sample encoding of `msgSecurityParameters`.

Downstream use: USM structure decode/encode, exact byte preservation of
authentication parameters, raw security parameters, and encrypted PDU payloads
may cite these sections. `crafter` must not store keys, maintain user tables,
enforce timeliness policy, or perform access control.

### RFC 3416 - SNMPv2 protocol operations and PDU matrix

Classification: core wire behavior.
Relationship: obsoletes RFC 1905.
Source: https://www.rfc-editor.org/rfc/rfc3416.html

- Section 2.5: SMIv2 data type mappings into SNMP protocol value choices.
- Section 3: `ObjectSyntax`, `SimpleSyntax`, `ApplicationSyntax`, application
  tags, PDU CHOICE tags, `PDU`, `BulkPDU`, `VarBind`, and `VarBindList`.
- Section 4.1: request ID and response/error-index conventions.
- Sections 4.2.1 through 4.2.7: GetRequest, GetNextRequest, GetBulkRequest,
  Response, SetRequest, SNMPv2-Trap, and InformRequest PDU fields and
  operation-specific ignored fields.
- Section 3 and Section 4.2 note that Report-PDU tag 8 is defined, with usage
  supplied by an administrative framework rather than RFC 3416 itself.

Downstream use: v2c/v3 PDU tags, values, error status labels, GetBulk fields,
notification PDU fields, report PDU byte shape, unknown tag preservation, and
structured malformed decode tests may cite this source. Application workflow
semantics remain out of scope.

### RFC 3417 - transport mapping and BER restrictions

Classification: core wire behavior for BER restrictions and UDP/IPv4 mapping;
mapping source for other legacy transports.
Relationship: obsoletes RFC 1906; updated by RFC 4789 and RFC 5590.
Source: https://www.rfc-editor.org/rfc/rfc3417.html

- Section 3: preferred UDP over IPv4 mapping, single UDP datagram
  serialization, and minimum accepted message sizes.
- Section 8: BER serialization restrictions: definite length only; primitive
  form for simple types; constructed form for SEQUENCE and IMPLICIT SEQUENCE;
  BITS encoded as OCTET STRING.
- Section 8.1: non-minimal definite long-form lengths are valid, which means
  decoders must not reject otherwise well-formed BER only because a length is
  non-minimal.
- Section 11: IANA considerations for SNMP transport domain registrations.

Downstream use: BER identifier/length/value codec behavior, non-minimal length
tests, UDP payload dispatch, pcap fixtures, and transport-domain labels may cite
this source.

### RFC 3418 - SNMP MIB identifiers used by notification/report bytes

Classification: core wire behavior only for object identifiers that RFC 3416
or RFC 3414 requires inside SNMP messages; operational guidance otherwise.
Relationship: obsoletes RFC 1907.
Source: https://www.rfc-editor.org/rfc/rfc3418.html

- Section 5 definitions include `sysUpTime.0`, `snmpInASNParseErrs`,
  `snmpSilentDrops`, and notification objects such as `snmpTrapOID` and
  `snmpTrapEnterprise`.
- `snmpTrapOID` is the second varbind in every SNMPv2-Trap-PDU and
  InformRequest-PDU, which makes its object identifier relevant to packet
  builders and fixtures.

Downstream use: only required notification/report object identifiers and
counter OIDs may cite this source. The crate must not implement SNMP entity
counters or MIB instrumentation.

## Registry Authority

### IANA Simple Network Management Protocol (SNMP) Number Spaces

Classification: registry authority.
Source: https://www.iana.org/assignments/snmp-number-spaces
Registry last updated by IANA: 2016-05-03.

Use these rows for labels and unknown preservation:

| Registry | Rows relevant to packet bytes |
| --- | --- |
| Security Models | 0 reserved for any; 1 SNMPv1; 2 SNMPv2c; 3 USM; 4 TSM; 5-255 unassigned. |
| Message Processing Models | 0 SNMPv1; 1 SNMPv2c; 2 SNMPv2u/SNMPv2*; 3 SNMPv3; 4-255 unassigned. |
| SnmpEngineID Formats | 0 reserved; 1 IPv4; 2 IPv6; 3 MAC; 4 administratively assigned text; 5 administratively assigned octets; 6 local engine; 7-127 unassigned; 128-255 enterprise-specific. |
| SnmpAuthProtocols | 0 reserved; 1 no authentication; 2 HMAC-MD5-96; 3 HMAC-SHA-96; 4 HMAC-SHA-224-128; 5 HMAC-SHA-256-192; 6 HMAC-SHA-384-256; 7 HMAC-SHA-512-384. |
| SnmpPrivProtocols | 0 reserved; 1 no privacy; 2 CBC-DES; 3 reserved; 4 AES-CFB-128. |
| SNMP Transport Domains | `udp` snmpUDPDomain; `clns`; `cons`; `ddp`; `ipx`; `prxy`; `ssh`; `tls`; `dtls`. |

Downstream use: generated code may expose stable labels and preserve unknown
values from these registries. Unassigned or enterprise-specific values must not
be rejected when their enclosing TLV is well-formed.

### IANA Service Name and Transport Protocol Port Number Registry

Classification: registry authority.
Source: https://www.iana.org/assignments/service-names-port-numbers
Registry last updated by IANA: 2026-06-17.

Rows relevant to SNMP packet composition and conservative UDP dispatch:

| Service | Port | Transport | Description | Reference |
| --- | ---: | --- | --- | --- |
| snmp | 161 | tcp | SNMP | IANA registry row |
| snmp | 161 | udp | SNMP | IANA registry row |
| snmptrap | 162 | tcp | SNMPTRAP | IANA registry row |
| snmptrap | 162 | udp | SNMPTRAP | IANA registry row |
| snmpssh | 5161 | tcp | SNMP over SSH Transport Model | RFC 5592 |
| snmpssh-trap | 5162 | tcp | SNMP Notification over SSH Transport Model | RFC 5592 |
| snmptls | 10161 | tcp | SNMP-TLS | RFC 6353 |
| snmpdtls | 10161 | udp | SNMP-DTLS | RFC 6353 |
| snmptls-trap | 10162 | tcp | SNMP-Trap-TLS | RFC 6353 |
| snmpdtls-trap | 10162 | udp | SNMP-Trap-DTLS | RFC 6353 |

Downstream use: UDP port constants and labels cite the `snmp`/UDP and
`snmptrap`/UDP rows. The initial built-in registry may dispatch only
conservative UDP/161 and UDP/162 SNMP payloads unless a later mapping slice
cites and tests additional transports.

### IANA Structure of Management Information (SMI) Numbers

Classification: registry authority for MIB module and object-identity
registrations.
Source: https://www.iana.org/assignments/smi-numbers
Registry last updated by IANA: 2026-06-23.

Use only rows needed to name packet-relevant object identifiers, such as
`snmpModules`, `snmpAuthProtocols`, `snmpPrivProtocols`, `snmpDomains`, or
specific module OID assignments cited by RFC 3411, RFC 3414, RFC 3418,
RFC 3826, RFC 4789, or RFC 7860. Do not treat this registry as permission to
implement MIB semantics.

## Extension And Mapping Sources

The following sources are recognized but not broad permission to implement
application behavior:

- RFC 3826, Sections 3 and 5: AES-CFB-128 privacy wire parameters and IANA
  `SnmpPrivProtocols` assignment. Use only for raw/encrypted scoped-PDU bytes
  or a later source-backed crypto helper with no key storage.
- RFC 7860, Sections 4, 8, and 10: SHA-2 USM authentication protocol names,
  output lengths, object identities, and IANA `SnmpAuthProtocols` assignments.
  RFC 7860 obsoletes RFC 7630.
- RFC 5343: contextEngineID discovery updates RFC 3411. Treat as an extension
  for v3 discovery/report byte shapes only.
- RFC 5590: transport subsystem updates RFC 3411, RFC 3412, RFC 3414, and
  RFC 3417. It may inform transport-model labeling but not live transport
  behavior without a dedicated mapping implementation.
- RFC 5591: Transport Security Model source for security model value 4. Do not
  implement TSM policy or sessions in `crafter`.
- RFC 5592: SSH transport model source for `snmpssh` and `snmpssh-trap` port
  rows and SNMP transport domain labels. Do not implement SSH sessions in
  `crafter`.
- RFC 6353 and RFC 9456: TLS/DTLS transport model and updates. Use for
  registry labels and optional later mapping work only; no TLS state belongs in
  the packet primitive.
- RFC 4789, Sections 3 and 5: SNMP over IEEE 802 mapping, EtherType 0x814c,
  and snmpIeee802Domain assignment. It updates RFC 3417 and obsoletes RFC
  1089. This is a mapping slice, not part of initial UDP decode.
- RFC 1420 and RFC 3430: IPX and TCP transport mappings. These require
  dedicated mapping support and tests before use.
- RFC 5675 and RFC 5676: SYSLOG/SNMP notification mappings. These do not
  authorize a notification service in `crafter`.
- RFC 2741 and RFC 2742: AgentX/extensible-agent material. This is a separate
  protocol family and not part of SNMP message layer support unless a future
  plan explicitly scopes AgentX.

## Datatracker And RFC-Editor Relationships

The generated handoff records RFC relationship metadata from the RFC Editor
index. Treat these relationships as source-selection constraints:

| Current source | Recorded relationship |
| --- | --- |
| RFC 1157 | Obsoletes RFC 1098. RFC 1067 was obsoleted by RFC 1098, which was obsoleted by RFC 1157. |
| RFC 1901 | Community-based SNMPv2 wrapper source; no replacement recorded in handoff, but it is historical/experimental and must be used only for wrapper bytes. |
| RFC 2578 | Obsoletes RFC 1902. |
| RFC 3411 | Obsoletes RFC 2571; updated by RFC 5343 and RFC 5590. |
| RFC 3412 | Obsoletes RFC 2572; updated by RFC 5590. |
| RFC 3414 | Obsoletes RFC 2574; updated by RFC 5590. |
| RFC 3416 | Obsoletes RFC 1905. |
| RFC 3417 | Obsoletes RFC 1906; updated by RFC 4789 and RFC 5590. |
| RFC 3418 | Obsoletes RFC 1907. |
| RFC 3584 | Obsoletes RFC 2576; coexistence guidance only unless cited for exact wire mappings. |
| RFC 3826 | Adds AES privacy object identity and registry assignment for USM. |
| RFC 4789 | Obsoletes RFC 1089 and updates RFC 3417. |
| RFC 5590 | Updates RFC 3411, RFC 3412, RFC 3414, and RFC 3417. |
| RFC 5953 | Obsoleted by RFC 6353; do not use except lineage. |
| RFC 6353 | Obsoletes RFC 5953; updated by RFC 8996 and RFC 9456. |
| RFC 7630 | Obsoleted by RFC 7860; do not use except lineage. |
| RFC 7860 | Obsoletes RFC 7630. |
| RFC 8996 | Updates RFC 6353 by deprecating TLS 1.0/1.1 in TLS-using protocols; transport security guidance only. |
| RFC 9141 | Updates FTP references in several MIB documents; no SNMP packet bytes. |
| RFC 9456 | Updates RFC 6353. |

If a later implementation slice needs a relationship not listed here, update
this manifest with the RFC or Datatracker evidence before implementing.

## Selected Source Inventory

The generated source handoff selected 217 RFC documents. Each selected source
is classified below. The `registry authority` class is IANA-only for this
manifest, so no RFC appears under that class.

### Core wire behavior

RFC 1157, RFC 1901, RFC 2578, RFC 3411, RFC 3412, RFC 3414, RFC 3416,
RFC 3417, RFC 3418.

### Extension

RFC 2741, RFC 2742, RFC 3826, RFC 4192, RFC 5343, RFC 5590, RFC 5591,
RFC 5592, RFC 6353, RFC 7860, RFC 8996, RFC 9141, RFC 9456.

### Mapping

RFC 1420, RFC 3430, RFC 4036, RFC 4131, RFC 4323, RFC 4546, RFC 4547,
RFC 4639, RFC 4789, RFC 5675, RFC 5676.

### Operational guidance

RFC 1381, RFC 1382, RFC 1559, RFC 1592, RFC 1593, RFC 1748, RFC 2127,
RFC 2707, RFC 2720, RFC 2788, RFC 2790, RFC 2856, RFC 3014, RFC 3083,
RFC 3410, RFC 3413, RFC 3415, RFC 3433, RFC 3434, RFC 3440, RFC 3512,
RFC 3584, RFC 3591, RFC 3592, RFC 3638, RFC 3780, RFC 3781, RFC 3805,
RFC 3806, RFC 4011, RFC 4088, RFC 4188, RFC 4268, RFC 4545, RFC 4682,
RFC 4710, RFC 4712, RFC 4878, RFC 5066, RFC 5098, RFC 5345, RFC 5428,
RFC 5607, RFC 5608, RFC 5833, RFC 5834, RFC 5935, RFC 6643, RFC 6765,
RFC 6766, RFC 6767, RFC 6768, RFC 6933, RFC 7124, RFC 7407, RFC 7448,
RFC 8038, RFC 8502, RFC 8503.

### Obsolete or historical

RFC 1067, RFC 1089, RFC 1098, RFC 1161, RFC 1227, RFC 1228, RFC 1231,
RFC 1232, RFC 1233, RFC 1234, RFC 1239, RFC 1243, RFC 1269, RFC 1271,
RFC 1283, RFC 1284, RFC 1285, RFC 1286, RFC 1289, RFC 1298, RFC 1351,
RFC 1352, RFC 1353, RFC 1368, RFC 1398, RFC 1406, RFC 1407, RFC 1414,
RFC 1418, RFC 1419, RFC 1441, RFC 1442, RFC 1443, RFC 1444, RFC 1445,
RFC 1446, RFC 1447, RFC 1448, RFC 1449, RFC 1450, RFC 1451, RFC 1452,
RFC 1461, RFC 1493, RFC 1512, RFC 1513, RFC 1514, RFC 1515, RFC 1516,
RFC 1525, RFC 1565, RFC 1595, RFC 1596, RFC 1604, RFC 1623, RFC 1643,
RFC 1657, RFC 1665, RFC 1666, RFC 1742, RFC 1743, RFC 1747, RFC 1749,
RFC 1759, RFC 1902, RFC 1903, RFC 1904, RFC 1905, RFC 1906, RFC 1907,
RFC 1908, RFC 2037, RFC 2064, RFC 2089, RFC 2248, RFC 2257, RFC 2261,
RFC 2262, RFC 2263, RFC 2264, RFC 2265, RFC 2271, RFC 2272, RFC 2273,
RFC 2274, RFC 2275, RFC 2495, RFC 2496, RFC 2558, RFC 2570, RFC 2571,
RFC 2572, RFC 2573, RFC 2574, RFC 2575, RFC 2576, RFC 2669, RFC 2670,
RFC 2737, RFC 2787, RFC 3159, RFC 3636, RFC 4133, RFC 4369, RFC 4441,
RFC 5953, RFC 7630.

### Ambiguous

RFC 1187, RFC 1215, RFC 1270, RFC 1303, RFC 1503, RFC 2024, RFC 2072,
RFC 2108, RFC 2662, RFC 2954, RFC 2962, RFC 3216, RFC 4097, RFC 4273,
RFC 6173, RFC 6527, RFC 7076, RFC 7241.

Ambiguous sources are not source authority for downstream behavior. RFC 1187
defines an experimental bulk retrieval design but cannot override the RFC 3416
GetBulkRequest PDU without a later gap review. RFC 1215 defines a trap
convention for SMIv1, but SNMPv1 Trap-PDU bytes are already sourced from
RFC 1157 and SNMPv2 notification bytes from RFC 3416/RFC 3418.

## Errata

The generated handoff recorded no errata records (`errata: []`). Treat this as
"no errata evidence in the handoff", not as proof that none exist forever.
Before using an erratum as source authority, update this manifest with the
errata ID, errata status, affected RFC section, and the resulting downstream
rule. Unverified, rejected, or unresolved errata cannot silently change packet
behavior.

## Unresolved Questions And Source Gaps

- The handoff reported `selected_registries: []` and `extracted_facts: []`.
  This manifest therefore adds explicit IANA registry authority above, and later
  implementation slices must cite the relevant rows directly.
- The handoff reported missing cached RFC text for many selected RFCs. Core
  sources used above were reviewed through official RFC Editor text during this
  manifest pass; operational, obsolete, historical, mapping, and ambiguous
  sources with only index evidence remain insufficient for packet behavior until
  their exact sections are reviewed.
- SNMP over IPv6 was mentioned by RFC 3417 as work in progress but no IPv6
  transport mapping RFC was selected by the generated handoff. Do not implement
  an IPv6-specific transport mapping until source evidence is added here.
- Unknown PDU tags, unknown value tags, unknown error statuses, unknown message
  processing models, unknown security models, and enterprise-specific registry
  values must remain inspectable and byte-preserving when the enclosing BER TLV
  is valid.
- BER indefinite lengths, truncated BER lengths, malformed constructed values,
  malformed object identifiers, and malformed SNMPv3 security parameters must
  produce structured decode errors with context, required length, and available
  length.
- Caller-set versions, tags, request IDs, error statuses, flags, lengths,
  security parameters, authentication bytes, and encrypted scoped-PDU bytes must
  survive compile even when deliberately malformed.

## Explicit Exclusions

This manifest does not authorize a scanner, manager application, polling loop,
walk implementation, retry scheduler, trap receiver service, MIB compiler,
MIB browser, monitoring product, device inventory, alerting workflow, VACM
evaluator, USM user/key database, credential store, live target default, or
host-originated raw traffic workflow. Those belong in generated tools or
external operator tooling, not in the `crafter` crate.
