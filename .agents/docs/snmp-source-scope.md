# SNMP source scope

This note turns `.agents/docs/snmp-rfc-manifest.md` into an implementation scope for
SNMP work in `crafter`. The crate may model SNMP packet bytes, compile them,
decode them, preserve unknown but well-formed values, and validate them through
offline and externally executed packet workflows. It must not become an SNMP
manager, scanner, trap receiver, MIB engine, credential store, or policy
implementation.

Before adding any SNMP tag, PDU, value type, security field, transport mapping,
oracle expectation, or live probe behavior, update `.agents/docs/snmp-rfc-manifest.md`
with the RFC section, IANA registry row, Datatracker/RFC-Editor relationship, or
errata record that authorizes the exact wire fact. If the manifest does not
support the behavior, stop the slice as unsupported instead of guessing.

## Source-backed implementation order

1. Build the BER foundation first: identifier octets, definite lengths,
   integers, octet strings, NULL, object identifiers, sequences, application
   tags, and malformed/truncation errors from RFC 1157, RFC 2578, and RFC 3417.
2. Add SMI value and varbind primitives before PDUs: `SnmpOid`, `SnmpValue`,
   application values, unknown value preservation, varbinds, summaries, and
   `show()` fields.
3. Implement community message families after the shared value layer:
   SNMPv1 message and Trap-PDU bytes from RFC 1157, the SNMPv2c wrapper from
   RFC 1901, and SNMPv2/v3 protocol operation PDUs from RFC 3416 and RFC 3418
   where notification/report object identifiers are packet content.
4. Add the top-level `Snmp` layer only after PDUs can compile and decode through
   the existing `Packet` abstraction with caller overrides preserved.
5. Add SNMPv3 message wrappers, global data, flags, scoped PDUs, raw security
   parameters, and encrypted scoped-data preservation from RFC 3411 and
   RFC 3412.
6. Add USM security-parameter wire structures from RFC 3414 after raw SNMPv3
   security parameters exist. Authentication and privacy bytes are preserved as
   packet fields; keys, user tables, timeliness policy, and access control are
   out of scope.
7. Add conservative UDP dispatch for SNMP message and notification ports from
   RFC 3417 and the IANA service-name registry. Other transports require their
   own source-backed mapping slice.
8. Add validation in offline-first order: Rust tests and fixtures, oracle specs,
   reference backend comparisons, pcap checks, probe dry-runs, external environment dry-runs, and
   only then guarded externally executed live validation.

## Unresolved wire questions

- The generated handoff had no selected IANA registries or extracted facts, so
  every numeric assignment used in code or tests must cite the manifest's IANA
  rows directly.
- Many selected RFCs were only classified from index metadata. They are not
  authority for packet behavior until exact sections are reviewed and recorded
  in the manifest.
- SNMP over IPv6 is not source-backed by the current manifest. Do not add an
  IPv6-specific transport mapping without first adding source evidence.
- The handoff recorded no errata. Treat that as absence of recorded errata, not
  proof that errata can never affect SNMP behavior.
- Unknown PDU tags, value tags, error statuses, message processing models,
  security models, and enterprise-specific registry values must remain
  inspectable and byte-preserving when their enclosing BER TLV is valid.
- BER indefinite lengths, truncated lengths, malformed constructed values,
  malformed object identifiers, and malformed SNMPv3 security parameters must
  decode as structured errors with context, required length, and available
  length.

## Unsupported by default

These extensions and behaviors are unsupported unless a later manifest update
and implementation slice prove the packet-layer wire scope:

- SNMP over SSH, TLS, DTLS, TCP, IPX, IEEE 802, SYSLOG notification mappings, or
  any non-UDP transport behavior.
- Transport Security Model session behavior, TLS/DTLS/SSH session setup, and
  transport subsystem policy.
- VACM evaluation, USM user/key databases, engine timeliness enforcement,
  credential storage, key rotation, and authentication/privacy policy.
- MIB compilation, MIB browsing, table rendering, polling, walks, retries,
  inventory, alerting, monitoring-product behavior, trap receiver services, or
  manager workflows.
- AgentX and extensible-agent protocol behavior, unless a future plan scopes it
  as a separate protocol family.
- Host-originated raw live traffic defaults. Live behavior belongs behind
  explicit externally executed oracle, probe, or external environment workflows.

## Obsolete and historical material

Obsolete or historical RFCs can document lineage, but they do not authorize
default implementation. Use the current manifest sources instead: RFC 1157 for
SNMPv1 message and PDU bytes, RFC 2578 for SMIv2 value syntax, RFC 3411 through
RFC 3418 for the SNMPv3 architecture and SNMPv2 protocol operations, RFC 6353
instead of obsolete TLS mapping RFC 5953, and RFC 7860 instead of obsolete
SHA-2 USM RFC 7630.

Ambiguous sources are also not implementation authority. RFC 1187 cannot
override RFC 3416 GetBulk behavior, and RFC 1215 cannot override SNMPv1 Trap-PDU
bytes from RFC 1157 or SNMPv2 notification bytes from RFC 3416 and RFC 3418
without a later gap review.

## Requires later proof

- Cryptographic helpers for HMAC-MD5-96, HMAC-SHA-96, SHA-2 USM, DES, or AES
  require proof that the helper is a packet primitive and can operate without
  credential storage or policy state.
- AES and SHA-2 protocol identifiers may be labeled from RFC 3826, RFC 7860,
  and IANA, but byte-transform helpers need a dedicated slice.
- Report-PDU convenience builders, engine discovery examples, and notification
  helpers must stay wire-shaped; discovery state machines and retry policy are
  generated-tool behavior.
- Reference-backend, Wireshark, or other oracle expectations must be backed by
  executable specs and recorded source authority before they become acceptance
  evidence.
- Any live probe behavior must have a dry-run plan, external runner capability
  evidence, explicit live confirmation, artifact collection under ignored
  paths, and teardown evidence before it can validate real traffic.
