# SNMP Implementation Inventory

This inventory maps the planned `crafter` SNMP packet-layer surface to the
source-backed facts recorded in
[`docs/snmp-rfc-manifest.md`](snmp-rfc-manifest.md). It is a pre-implementation
audit map: no row below claims that SNMP build, compile, decode, dispatch,
oracle, probe, or live validation support has landed.

Every implementable row is planned until the named code path and the matching
tests land. Unsupported behavior is marked out of scope instead of being
guessed from uncited SNMP knowledge.

Date checked: 2026-06-24, against `docs/snmp-rfc-manifest.md`.

## Module and Export Status

`crafter/src/protocols/mod.rs` now exposes the SNMP namespace with
`pub mod snmp;` so later source-backed slices have the stable module home
`crafter::protocols::snmp`.

No SNMP symbols are re-exported through `crafter::protocols::exports`, the crate
root, or `crafter::prelude::*` in this step. The existing files under
`crafter/src/protocols/snmp/` remain private scaffolding with no packet layer,
builders, decode entrypoint, UDP dispatch, constants, or placeholder public
types.

## Status Labels

| Status | Meaning |
| --- | --- |
| source-backed planned | The manifest cites source authority for this wire fact, but the code and tests have not landed. |
| source-backed implemented | The source-backed code path and focused tests have landed for this wire fact. |
| source-backed preserve planned | The manifest requires unknown or caller-supplied bytes to stay inspectable and byte-preserving; the preservation code and tests have not landed. |
| source-backed validation planned | The validation case is planned and must cite the manifest before it becomes executable evidence. |
| source-gap out of scope | The current manifest does not authorize implementation; update the manifest first or keep it unsupported. |
| out of scope | The spec and manifest exclude this behavior from the `crafter` packet primitive. |

## Planned Implementation Paths

- `crafter/src/protocols/snmp/mod.rs` - top-level `Snmp` layer, module exports,
  `Layer` implementation, summary/show integration, and decode entrypoint.
- `crafter/src/protocols/snmp/error.rs` - SNMP/BER structured decode errors
  with context, required length, and available length.
- `crafter/src/protocols/snmp/ber.rs` - BER identifier, definite-length,
  primitive, constructed SEQUENCE, and raw TLV helpers.
- `crafter/src/protocols/snmp/constants.rs` - source-backed tags, version
  values, PDU tags, error-status values, and UDP port constants.
- `crafter/src/protocols/snmp/oid.rs` - `SnmpOid` object identifier type and
  BER OBJECT IDENTIFIER codec.
- `crafter/src/protocols/snmp/value.rs` - `SnmpValue` enum, SMI simple syntax,
  application values, exception values, and unknown value preservation.
- `crafter/src/protocols/snmp/varbind.rs` - `SnmpVarBind` and
  `SnmpVarBindList` construction, decode, and inspection.
- `crafter/src/protocols/snmp/pdu.rs` - `SnmpPdu` enum, request/response/trap
  builders, PDU decode, error-status metadata, and override preservation.
- `crafter/src/protocols/snmp/v3.rs` - SNMPv3 message wrapper, global data,
  flags, scoped PDU, and plaintext/encrypted scoped-data handling.
- `crafter/src/protocols/snmp/security.rs` - raw security parameters and USM
  security-parameter wire structures.
- `crafter/src/protocols/snmp/registry.rs` - conservative SNMP payload
  detection, UDP port labels, security/message model labels, and codepoint
  metadata.
- `crafter/src/protocols/mod.rs`, `crafter/src/lib.rs`, and
  `crafter/src/registry.rs` - crate exports and built-in UDP dispatch once the
  typed SNMP layer can compile and decode.

## BER Primitives

| Item | Source | Planned path | Status | Notes |
| --- | --- | --- | --- | --- |
| BER identifier octets for universal, application, context-specific, and constructed tags used by SNMP | RFC 1157 Section 3.2.2; RFC 3417 Section 8 | `crafter/src/protocols/snmp/ber.rs` | source-backed planned | Decode must preserve tag class, constructed bit, and tag number needed by SNMP. |
| Definite short-form and long-form BER lengths | RFC 1157 Section 3.2.2; RFC 3417 Sections 8 and 8.1 | `crafter/src/protocols/snmp/ber.rs` | source-backed planned | Indefinite lengths are not valid for SNMP; non-minimal long-form definite lengths remain valid. |
| INTEGER / Integer32 encoding for versions, request IDs, status values, counters, and v3 global data | RFC 1157 Section 4.1.1; RFC 2578 Section 7.1.1; RFC 3416 Section 3 | `crafter/src/protocols/snmp/ber.rs`; `crafter/src/protocols/snmp/value.rs` | source-backed planned | Preserve caller-set byte widths when explicit malformed output is requested. |
| OCTET STRING encoding for communities, opaque bytes, engine IDs, names, and security parameters | RFC 1157 Section 4.1.1; RFC 2578 Section 7.1.2; RFC 3412 Section 6; RFC 3414 Section 2.4 | `crafter/src/protocols/snmp/ber.rs`; `crafter/src/protocols/snmp/value.rs` | source-backed planned | No credential or secret handling beyond packet bytes. |
| NULL encoding for request varbind placeholders and exception values | RFC 1157 Section 4.1.1; RFC 3416 Section 3 | `crafter/src/protocols/snmp/ber.rs`; `crafter/src/protocols/snmp/value.rs` | source-backed planned | Request helpers may default values to NULL where source-backed. |
| OBJECT IDENTIFIER encoding | RFC 2578 Sections 3.5 and 7.1.3 | `crafter/src/protocols/snmp/oid.rs` | source-backed implemented | `SnmpOid` validates root arcs, maximum arc width, and the 128-arc limit; BER TLV decode/encode returns structured malformed-input errors. |
| Constructed SEQUENCE helpers for messages, varbind lists, scoped PDUs, and security parameters | RFC 1157 Section 4; RFC 3412 Section 6; RFC 3417 Section 8 | `crafter/src/protocols/snmp/ber.rs` | source-backed planned | Auto-fill unset lengths while preserving explicit overrides. |
| Raw TLV escape hatch for unsupported but well-formed values | Manifest unresolved questions | `crafter/src/protocols/snmp/ber.rs`; `crafter/src/protocols/snmp/value.rs` | source-backed preserve planned | Unknown TLVs must remain inspectable instead of being dropped. |
| Structured BER truncation and malformed errors | Manifest edge cases | `crafter/src/protocols/snmp/error.rs`; `crafter/src/protocols/snmp/ber.rs` | source-backed planned | Errors must include context, required bytes, and available bytes. |

## SNMP Versions

| Item | Source | Planned path | Status | Notes |
| --- | --- | --- | --- | --- |
| SNMPv1 version value 0 | RFC 1157 Sections 4.1.2 through 4.1.6 | `crafter/src/protocols/snmp/constants.rs`; `crafter/src/protocols/snmp/mod.rs` | source-backed planned | Used by v1 message builders and decode. |
| SNMPv2c version value 1 | RFC 1901 Section 3 | `crafter/src/protocols/snmp/constants.rs`; `crafter/src/protocols/snmp/mod.rs` | source-backed planned | Applies only to the community-based wrapper. |
| SNMPv3 version value 3 | RFC 3412 Sections 6.1 through 6.8 | `crafter/src/protocols/snmp/constants.rs`; `crafter/src/protocols/snmp/v3.rs` | source-backed planned | Used by the v3 message wrapper and global data. |
| Unknown or caller-set version values | Manifest unresolved questions | `crafter/src/protocols/snmp/mod.rs` | source-backed preserve planned | Decode should preserve well-formed wrappers; compile should honor caller overrides. |

## Message Wrappers

| Item | Source | Planned path | Status | Notes |
| --- | --- | --- | --- | --- |
| Top-level `Snmp` packet layer | Plan architecture | `crafter/src/protocols/snmp/mod.rs` | source-backed planned | Must compose with `/`, compile through `Packet`, and expose `summary()` and `show()`. |
| SNMPv1 message wrapper `{ version, community, data }` | RFC 1157 Section 4.1.2 | `crafter/src/protocols/snmp/mod.rs`; `crafter/src/protocols/snmp/pdu.rs` | source-backed planned | Message data is a source-backed v1 PDU. |
| SNMPv2c community wrapper | RFC 1901 Section 3 | `crafter/src/protocols/snmp/mod.rs`; `crafter/src/protocols/snmp/pdu.rs` | source-backed planned | Wrapper only; no manager session behavior. |
| SNMPv3 message wrapper | RFC 3412 Section 6 | `crafter/src/protocols/snmp/v3.rs`; `crafter/src/protocols/snmp/mod.rs` | source-backed planned | Includes msgVersion, HeaderData, security parameters, and scoped data. |
| Message-level explicit length and tag overrides | Manifest edge cases | `crafter/src/protocols/snmp/mod.rs`; `crafter/src/protocols/snmp/ber.rs` | source-backed preserve planned | Deliberately malformed caller values must survive compile. |

## Values

| Item | Source | Planned path | Status | Notes |
| --- | --- | --- | --- | --- |
| `SnmpValue` enum for SMI simple syntax | RFC 2578 Sections 2, 2.2, and 7.1.1 through 7.1.3; RFC 3416 Section 2.5 | `crafter/src/protocols/snmp/value.rs` | source-backed planned | INTEGER/Integer32, OCTET STRING, OBJECT IDENTIFIER, and NULL. |
| BITS as OCTET STRING | RFC 2578 Section 7.1.4; RFC 3417 Section 8 | `crafter/src/protocols/snmp/value.rs` | source-backed planned | Model as packet bytes, not MIB semantics. |
| Application syntax: IpAddress, Counter32, Gauge32, TimeTicks, Opaque, Counter64, Unsigned32 | RFC 2578 Sections 7.1.5 through 7.1.11; RFC 3416 Section 3 | `crafter/src/protocols/snmp/value.rs`; `crafter/src/protocols/snmp/constants.rs` | source-backed planned | Include source-backed application tag labels. |
| SNMPv2 exception values `noSuchObject`, `noSuchInstance`, and `endOfMibView` | RFC 3416 Section 3 | `crafter/src/protocols/snmp/value.rs`; `crafter/src/protocols/snmp/constants.rs` | source-backed planned | Encode and decode as packet-level value choices only. |
| Unknown value tags and raw value bytes | Manifest unresolved questions | `crafter/src/protocols/snmp/value.rs`; `crafter/src/protocols/snmp/ber.rs` | source-backed preserve planned | Do not reject unknown well-formed values. |

## Variable Bindings

| Item | Source | Planned path | Status | Notes |
| --- | --- | --- | --- | --- |
| `SnmpOid` public type | RFC 2578 Section 3.5 | `crafter/src/protocols/snmp/oid.rs`; `crafter::protocols::snmp::SnmpOid` | source-backed implemented | Object identifiers are packet content, not MIB database lookups. The type exposes `from_arcs`, dotted parsing, `Display`, arc accessors, BER TLV decode/encode, and invalid-input errors. |
| `SnmpVarBind` as name plus value | RFC 1157 Section 4.1.1; RFC 3416 Section 3 | `crafter/src/protocols/snmp/varbind.rs` | source-backed planned | The value may be NULL, an SMI value, an exception, or unknown raw TLV. |
| Ordered `SnmpVarBindList` | RFC 1157 Section 4.1.1; RFC 3416 Section 3 | `crafter/src/protocols/snmp/varbind.rs` | source-backed planned | Auto-fill list SEQUENCE lengths while preserving explicit overrides. |
| Notification and report object IDs used as packet content | RFC 3418 Section 5 | `crafter/src/protocols/snmp/constants.rs`; `crafter/src/protocols/snmp/varbind.rs` | source-backed planned | Only required packet OIDs, not MIB instrumentation. |

## OID Field Mapping

| Field | Source | Rust surface | BER owner | Status | Notes |
| --- | --- | --- | --- | --- | --- |
| VarBind `name` / ObjectName | RFC 1157 Section 4.1.1; RFC 3416 Section 3; RFC 2578 Section 3.5 | `SnmpOid` | `crafter/src/protocols/snmp/oid.rs` | source-backed implemented | This field is an ordered OBJECT IDENTIFIER. Name resolution, MIB lookup, table semantics, and enterprise instrumentation remain out of scope. |
| OBJECT IDENTIFIER value choice | RFC 2578 Sections 3.5 and 7.1.3 | `SnmpOid` through internal `SnmpValue::ObjectIdentifier` until the value surface is public | `crafter/src/protocols/snmp/oid.rs`; `crafter/src/protocols/snmp/value.rs` | source-backed planned | The OID codec has landed; public value/varbind integration lands in later slices. |

## PDUs

| Item | Source | Planned path | Status | Notes |
| --- | --- | --- | --- | --- |
| `SnmpPdu` enum and PDU tag metadata | RFC 1157 Sections 4.1.2 through 4.1.6; RFC 3416 Section 3 | `crafter/src/protocols/snmp/pdu.rs`; `crafter/src/protocols/snmp/constants.rs` | source-backed planned | Tags must be inspectable and source-labeled. |
| GetRequest, GetNextRequest, Response, and SetRequest PDUs | RFC 1157 Sections 4.1.2 through 4.1.5; RFC 3416 Sections 4.2.1 through 4.2.4 | `crafter/src/protocols/snmp/pdu.rs` | source-backed planned | Include request-id, error-status, error-index, and varbind-list fields. |
| SNMPv1 Trap PDU | RFC 1157 Sections 4.1.6 and 5 | `crafter/src/protocols/snmp/pdu.rs` | source-backed planned | Enterprise, agent address, generic trap, specific trap, timestamp, and varbinds. |
| GetBulkRequest PDU | RFC 3416 Sections 3 and 4.2.3 | `crafter/src/protocols/snmp/pdu.rs` | source-backed planned | Non-repeaters and max-repetitions are packet fields only. |
| InformRequest, SNMPv2-Trap, and Report PDU shapes | RFC 3416 Sections 3, 4.2.6, and 4.2.7; RFC 3418 Section 5 | `crafter/src/protocols/snmp/pdu.rs` | source-backed planned | Report usage belongs to administrative frameworks; packet bytes stay in scope. |
| Error-status labels and unknown error statuses | RFC 1157 Section 4.1.1; RFC 3416 Section 4.1 | `crafter/src/protocols/snmp/registry.rs`; `crafter/src/protocols/snmp/pdu.rs` | source-backed preserve planned | Unknown values remain inspectable. |
| Unknown PDU tags | Manifest unresolved questions | `crafter/src/protocols/snmp/pdu.rs`; `crafter/src/protocols/snmp/ber.rs` | source-backed preserve planned | Well-formed unknown PDU TLVs must preserve original bytes. |

## SNMPv3 Global Data

| Item | Source | Planned path | Status | Notes |
| --- | --- | --- | --- | --- |
| `HeaderData` with msgID, msgMaxSize, msgFlags, and msgSecurityModel | RFC 3412 Section 6 | `crafter/src/protocols/snmp/v3.rs` | source-backed planned | No policy enforcement beyond source-backed malformed checks. |
| msgFlags bits and reserved auth/priv combination label | RFC 3412 Sections 6.4 and 6.5 | `crafter/src/protocols/snmp/v3.rs`; `crafter/src/protocols/snmp/constants.rs` | source-backed planned | Preserve caller-set flags, including deliberately bad combinations. |
| Message processing model and security model labels | RFC 3411 Sections 5 and 6; IANA SNMP Number Spaces | `crafter/src/protocols/snmp/registry.rs`; `crafter/src/protocols/snmp/constants.rs` | source-backed preserve planned | Unknown and enterprise values are labels/preserved bytes, not policy. |
| Plaintext `ScopedPDU` | RFC 3412 Section 6 | `crafter/src/protocols/snmp/v3.rs` | source-backed planned | Contains contextEngineID, contextName, and a PDU. |
| Plaintext SNMPv3 Report wrapper helpers | RFC 3412 Section 6; RFC 3414 Section 4; RFC 3416 Section 3 | `crafter/src/protocols/snmp/message.rs` | source-backed implemented | Wrap caller-supplied Report-PDU varbinds in plaintext ScopedPDU messages for packet construction/decode only; no named discovery/statistics shortcuts are added without explicit source coverage. |
| Encrypted scoped data as opaque bytes | RFC 3412 Sections 6.6 through 6.8 | `crafter/src/protocols/snmp/v3.rs` | source-backed preserve planned | No decryption or credential storage in `crafter`. |

## Security Parameters

| Item | Source | Planned path | Status | Notes |
| --- | --- | --- | --- | --- |
| Raw `msgSecurityParameters` bytes | RFC 3412 Section 6; RFC 3414 Section 2.4 | `crafter/src/protocols/snmp/security.rs`; `crafter/src/protocols/snmp/v3.rs` | source-backed preserve planned | Required before model-specific decoding. |
| USM security-parameter SEQUENCE | RFC 3414 Section 2.4 | `crafter/src/protocols/snmp/security.rs` | source-backed planned | Fields are authoritative engine ID, boots, time, user name, auth params, and privacy params. |
| USM authoritative engine boots/time helpers | RFC 3414 Sections 2.4 and 4 | `crafter/src/protocols/snmp/message.rs`; `tools/probe/engine/protocols/snmp.py` | source-backed implemented | `crafter` exposes constructor/accessor helpers for the wire INTEGER fields only; validation windows, time synchronization, and authoritative engine discovery belong to generated tools, oracle/probe cases, or lab runs. |
| Authentication-parameter byte preservation | RFC 3414 Sections 6 and 7; RFC 7860 Sections 4, 8, and 10 | `crafter/src/protocols/snmp/message.rs` | source-backed implemented | Preserve bytes and lengths exactly; key storage, digest verification, digest construction helpers, and authentication policy require a later explicit slice if they ever fit crate scope. |
| Privacy-parameter byte preservation | RFC 3414 Section 8; RFC 3826 Sections 3 and 5 | `crafter/src/protocols/snmp/message.rs` | source-backed implemented | Preserve DES/AES parameter bytes and encrypted scoped data as opaque bytes only; decryption, key storage, and privacy-policy checks are out of scope. |
| TSM, SSH, TLS, DTLS, and transport session behavior | RFC 5591; RFC 5592; RFC 6353; RFC 9456 | none | out of scope | Registry labels may be source-backed later; sessions are not packet primitives. |
| USM user tables, key localization, timeliness enforcement, VACM, and access control | Manifest explicit exclusions | none | out of scope | Generated tools may own policy outside the crate. |

## UDP Dispatch

| Item | Source | Planned path | Status | Notes |
| --- | --- | --- | --- | --- |
| SNMP message UDP port 161 constant and label | IANA Service Name and Transport Protocol Port Number Registry; RFC 3417 Section 3 | `crafter/src/protocols/snmp/constants.rs`; `crafter/src/protocols/snmp/registry.rs` | source-backed planned | Use for conservative UDP payload detection and examples. |
| SNMP notification UDP port 162 constant and label | IANA Service Name and Transport Protocol Port Number Registry | `crafter/src/protocols/snmp/constants.rs`; `crafter/src/protocols/snmp/registry.rs` | source-backed planned | Dispatch only packet decode, not a trap receiver service. |
| Built-in UDP/161 and UDP/162 decode binding | RFC 3417 Section 3; IANA port registry | `crafter/src/registry.rs`; `crafter/src/protocols/snmp/registry.rs` | source-backed planned | Conservative detection should fall back to `Raw` for unsupported payloads. |
| SNMP over IPv6-specific transport mapping | Manifest unresolved questions | none | source-gap out of scope | Add source evidence before implementation. |
| SNMP over TCP, SSH, TLS, DTLS, IPX, IEEE 802, or SYSLOG mappings | Manifest unsupported by default | none | out of scope | Dedicated mapping slices and tests are required before any support claim. |

## Tests

| Test area | Planned path | Status | Notes |
| --- | --- | --- | --- |
| BER roundtrip and malformed corpus | `crafter/tests/snmp_ber.rs`; `crafter/tests/snmp_malformed.rs` | source-backed validation planned | Covers definite lengths, non-minimal lengths, OIDs, sequences, truncation, and unknown TLVs. |
| Value, OID, varbind, and summary/show coverage | `crafter/tests/snmp_values.rs`; `crafter/tests/snmp_public_api.rs` | source-backed validation planned | Protects `crafter::prelude::*` surface after exports land. |
| PDU matrix golden and malformed tests | `crafter/tests/snmp_pdu_golden.rs`; `crafter/tests/snmp_malformed.rs` | source-backed validation planned | Covers every implemented source-backed PDU variant and unknown PDU preservation. |
| v1 and v2c message golden vectors | `crafter/tests/snmp_golden.rs` | source-backed validation planned | Uses documentation address space only where packets include IP/UDP wrappers. |
| SNMPv3 decode and golden vectors | `crafter/tests/snmp_v3.rs`; `crafter/tests/snmp_v3_golden.rs` | source-backed validation planned | Covers plaintext, raw security, USM, and encrypted scoped-data preservation. |
| Property and resilience tests | `crafter/tests/snmp_property.rs`; `crafter/tests/snmp_malformed.rs` | source-backed validation planned | Bounded generated inputs only; no live traffic. |
| Pcap fixture roundtrips | `crafter/tests/fixtures/bytes/ipv4-udp-snmp-*.hex`; `crafter/tests/fixtures/pcaps/snmp-*.pcap`; `crafter/tests/fixture_suite.rs` | source-backed validation planned | Deterministic fixture bytes and summaries only. |
| Examples and Rustdoc | `crafter/examples/snmp_v1_v2c.rs`; `crafter/examples/snmp_v3.rs`; `crafter/src/lib.rs` | source-backed validation planned | Offline build/inspect examples, not live sends. |
| Release gate | `.agents/scripts/check-crafter-release --static` | source-backed validation planned | Required before the branch can be declared ready, not part of this step. |

## Oracle Specs

| Oracle area | Planned path | Status | Notes |
| --- | --- | --- | --- |
| SNMP layer schema | `tools/oracle/specs/layers/snmp.yaml` | source-backed validation planned | Defines layer fields only after source-backed Rust model is scoped. |
| Basic message and value features | `tools/oracle/specs/features/snmp-basic.yaml`; `tools/oracle/specs/features/snmp-values.yaml` | source-backed validation planned | Deterministic offline vectors first. |
| PDU matrix features | `tools/oracle/specs/features/snmp-pdus.yaml` | source-backed validation planned | Covers Get, GetNext, Set, Response, Trap, GetBulk, Inform, Trapv2, and Report once implemented. |
| SNMPv3 features | `tools/oracle/specs/features/snmp-v3.yaml` | source-backed validation planned | Covers global data, scoped PDU, raw/USM security parameters, and encrypted opaque data. |
| Stack and profile fragments | `tools/oracle/specs/stacks.d/snmp.yaml`; `tools/oracle/specs/profiles.d/snmp-smoke.yaml` | source-backed validation planned | Offline and pcap profiles before any provider-backed run. |
| Oracle generator and backend plugins | `tools/oracle/engine/protocols/snmp.py`; `tools/oracle/engine/backends/scapy/protocols/snmp.py`; `tools/oracle/engine/backends/wireshark/protocols/snmp.py` | source-backed validation planned | Backend gaps must be recorded, not papered over. |
| Oracle tests | `tools/oracle/tests/test_snmp_oracle.py` | source-backed validation planned | Should validate specs, offline bytes, and pcap behavior without live traffic. |

## Probe Cases

| Probe area | Planned path | Status | Notes |
| --- | --- | --- | --- |
| SNMP probe planning plugin | `tools/probe/engine/protocols/snmp.py` | source-backed validation planned | Dry-run request/response planning only at first. |
| Rust stimulus endpoint adapter | `tools/probe/adapters/src/snmp.rs` | source-backed validation planned | Builds and decodes SNMP packets through `crafter`, not ad hoc bytes. |
| Probe acceptance tests | `tools/probe/tests/test_snmp_probe.py`; `tools/probe/testing/probe_acceptance.py` | source-backed validation planned | Verifies dry-run shape and provider capability skips. |
| Target service material | `tools/probe/target_services/snmp/README.md` | source-backed validation planned | Only controlled lab/service notes; no default real target. |
| Polling, walks, scanning, retries, inventory, and trap receiver workflows | none | out of scope | These belong in generated tools, not `crafter`. |

## Live Artifacts

| Artifact area | Planned path | Status | Notes |
| --- | --- | --- | --- |
| Oracle offline and pcap artifacts | `target/oracle/snmp/` | source-backed validation planned | Ignored output only; deterministic seeds and no sensitive captures. |
| Probe dry-run artifacts | `target/probe/snmp/` | source-backed validation planned | Must be produced before any live provider invocation. |
| Lab dry-run and provider metadata | `target/lab/snmp/` | source-backed validation planned | Provider capability evidence, plan, and teardown records live under ignored paths. |
| Guarded live oracle/probe/lab artifacts | `target/live/snmp/` | source-backed validation planned | Requires explicit confirmation and provider-backed execution; skipped when prerequisites are unavailable. |
| Tracked credentials, public live host identifiers, sensitive pcaps, or host-originated raw default traffic | none | out of scope | The repository must not store real credentials or sensitive network captures. |

## Current Support Statement

As of this inventory, SNMP remains planned except for the standalone
`crafter::protocols::snmp::SnmpOid` object identifier type and its BER
OBJECT IDENTIFIER codec. The manifest and this inventory authorize later
implementation slices to add the remaining source-backed packet primitives
under `crafter/src/protocols/snmp`. No SNMP packet layer, message builders,
UDP decode dispatch, oracle specs, probe cases, or live artifacts should be
treated as supported until the corresponding implementation and validation rows
land.
