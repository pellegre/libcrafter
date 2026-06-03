# TCP Implementation Inventory

This inventory maps the current `crafter` TCP implementation to the
source-backed facts recorded in [`docs/tcp-rfc-manifest.md`](tcp-rfc-manifest.md)
and to the enrich-tcp-stack plan. It is the durable map the reorganization and
enrichment steps work against. Every gap row points at the manifest source that
justifies the work.

All current TCP code lives in a single file,
`crafter/src/protocols/transport/tcp.rs`, re-exported through
`crafter/src/protocols/transport/mod.rs`. The plan moves this into a folder
module `crafter/src/protocols/transport/tcp/` mirroring
`crafter/src/protocols/transport/udp/`.

Each item is marked with exactly one status:

- **already source-backed** — implemented and traceable to a manifest source;
  no behavior change needed.
- **needs source citation only** — implemented correctly but documentation or a
  manifest/test citation is missing; no code behavior change.
- **needs code expansion** — partially implemented; the manifest authorizes
  additional typed, classified, or sizing behavior.
- **compatibility-only** — a stable public name that must be preserved as an
  alias even when the current registry name differs; no semantic change allowed.
- **out of scope** — explicitly excluded by the spec and manifest; must not be
  added to the crate.

Date checked: 2026-06-02 (against `docs/tcp-rfc-manifest.md`, reviewed the same
date against RFC Editor, IANA TCP Parameters, and Datatracker).

## Current `Tcp` layer (`segment.rs` target)

| Item | Current location | Status | Notes |
| --- | --- | --- | --- |
| `Tcp` struct (ports, seq, ack, data_offset, reserved, flags, window, checksum, urgent_pointer, raw options) | `tcp.rs` lines ~439-452 | already source-backed | RFC 9293 §3.1 header layout; fields stored as `Field<T>` for set/unset tracking. |
| `Tcp::new` defaults (sport 20, dport 80, SYN, window 8192, unset data_offset/checksum) | `tcp.rs` ~454-470 | already source-backed | Defaults are packet-builder conveniences, not wire requirements. |
| Builders + compatibility aliases (`source_port`/`sport`, `destination_port`/`dport`, `sequence_number`/`seq`, `acknowledgment_number`/`ack`, `data_offset`/`dataofs`, `checksum`/`chksum`, `urgent_pointer`/`urgptr`) | `tcp.rs` ~472-622 | compatibility-only | Both long and short names are public; aliases must survive the move unchanged. |
| Flag builders (`fin`, `syn`, `rst`, `psh`, `ack_flag`, `urg`, `ece`, `cwr`, `ns`, `flag`, `flags`) | `tcp.rs` ~534-594 | already source-backed | `ns` maps to the `0x100` bit; see flags table for AE/NS reconciliation. |
| Getters (`*_value`, `has_flag`, `header_len`, `option_bytes`, `option_iter`, `parsed_options`) | `tcp.rs` ~648-721 | already source-backed | Inspectable surface required by the packet abstraction. |
| `effective_data_offset` / `effective_header_len` / `padded_options_len` | `tcp.rs` ~723-736, ~1052-1054 | already source-backed | Fills Data Offset from padded options when unset (RFC 9293 §3.1). |
| `effective_checksum` (IPv4/IPv6 pseudo-header via `transport_checksum_context`) | `tcp.rs` ~738-750 | already source-backed | Manifest "Checksum Scope"; zero without network context; explicit value preserved. |
| `validate` (data offset 5..15, header 20..60, option budget, reserved 3 bits, flags 9 bits, segment <= 65535) | `tcp.rs` ~752-809 | already source-backed | Covers manifest data-offset/option edge cases; structured `CrafterError`. |
| `Layer` impl: `summary`, `inspection_fields`, `encoded_len`, `compile` | `tcp.rs` ~818-887 | already source-backed | `compile()` fills data offset, padding, checksum; preserves explicit overrides. |
| `impl_layer_div!` / `impl_layer_object!` integration | `tcp.rs` ~886-889 | already source-backed | Keeps `/` composition and decode entrypoints uniform. |

## TCP option types (`option.rs` target)

| Item | Current location | Status | Notes |
| --- | --- | --- | --- |
| `TcpOption` enum (EndOfList, NoOperation, MaximumSegmentSize, WindowScale, SackPermitted, Sack, Timestamp, MultipathTcp, ExtendedDataOffset, FastOpen, Generic) | `tcp.rs` ~117-157 | needs code expansion | Stable variants kept; manifest authorizes typed/classified User Timeout, TCP-AO, TCP-ENO, AccECN (172/174), and ExID (253/254) handling currently falling into `Generic`. |
| `TcpOption` constructors + `mss` alias | `tcp.rs` ~159-237 | already source-backed | Public constructors must survive the move. |
| `TcpOption::kind`, `encoded_len`, `encode`, `decode_all` | `tcp.rs` ~239-362 | already source-backed | RFC 9293 §3.1 kind/length encoding; MPTCP subtype packing in `encode`. |
| `TcpOptionIter` (EOL stops, NOP single byte, length>=2, overrun -> error) | `tcp.rs` ~364-436 | already source-backed | Manifest option decode edge cases; structured errors not panics. |
| `decode_tcp_option` dispatch (MSS, WS, SACK-Permitted, SACK, Timestamp, MPTCP, EDO, Fast Open, Generic fallback) | `tcp.rs` ~959-1002 | needs code expansion | Add typed/classified branches for kinds 28 (UTO), 29 (TCP-AO preserve), 69 (TCP-ENO preserve), 172/174 (AccECN), 253/254 (ExID); keep unknown kinds as `Generic`. |
| `decode_tcp_sack_option` | `tcp.rs` ~1004-1020 | already source-backed | RFC 2018 8-byte left/right blocks; RFC 2883 D-SACK at block level. |
| `decode_tcp_edo_option` | `tcp.rs` ~1022-1040 | needs source citation only | EDO is a draft kind (237), not RFC-published; manifest "EDO Status Reconciliation" requires documenting draft status, not removal. |
| `validate_tcp_options`, `validate_tcp_option_len` | `tcp.rs` ~952-957, ~1042-1050 | already source-backed | Shared validation used by `validate` and decode. |
| Option kind classification helper (e.g. `tcp_option_kind_class`) | not present | needs code expansion | Manifest IANA Option Kind table marks obsolete/reserved/historic/unauthorized/unassigned kinds; mirror UDP's `udp_option_kind_class` / `UdpOptionKindClass` so they stay inspectable instead of silently `Generic`. |

## `TcpSackBlock` (`option.rs` target)

| Item | Current location | Status | Notes |
| --- | --- | --- | --- |
| `TcpSackBlock` struct + `new` (left_edge, right_edge) | `tcp.rs` ~68-85 | already source-backed | RFC 2018 §3; D-SACK (RFC 2883) reuses the same block shape. Public name preserved. |

## `TcpExtendedDataOffset` (`option.rs` target)

| Item | Current location | Status | Notes |
| --- | --- | --- | --- |
| `TcpExtendedDataOffset` enum (Request, HeaderLength, HeaderAndSegmentLength) + `option_len` | `tcp.rs` ~87-115 | compatibility-only | EDO is draft (draft-ietf-tcpm-tcp-edo), kind 237 unassigned in IANA as of 2026-06-02. Manifest "EDO Status Reconciliation": preserve the public API and document draft status; do not remove or redefine. |
| `TcpOption::ExtendedDataOffset` constructors (`extended_data_offset_request`, `extended_data_offset`, `extended_data_offset_ext`) | `tcp.rs` ~208-224 | compatibility-only | Stable public constructors retained alongside new source-backed ExID support. |
| `TCP_OPTION_EDO`, `TCP_EDO_REQUEST_LEN`, `TCP_EDO_HEADER_LEN`, `TCP_EDO_HEADER_AND_SEGMENT_LEN` constants | `tcp.rs` ~52-60 | compatibility-only | Exported draft constants kept; documented as draft, not RFC-published. |

EDO source status and compatibility rationale: the TCP Extended Data Offset
(EDO) kind 237 is draft-derived (draft-ietf-tcpm-tcp-edo) and is **not** a
current IANA Option-Kind assignment — `tcp_option_kind_class(237)` reports
`Unassigned`. The entire EDO public surface above (`TcpExtendedDataOffset`, the
`extended_data_offset*` constructors, the `extended_data_offset_value` accessor,
and the `TCP_OPTION_EDO` / `TCP_EDO_*` constants) is preserved purely for
**backward compatibility**: downstream tools may already depend on these names,
so the crate keeps them rather than removing or redefining them. The additive,
source-backed **current** path is RFC 6994 experimental ExID support (kinds
253/254, added in step 17 via `TcpOption::Experimental` / `experimental*`); new
experimental codepoints should use the RFC 6994 ExID options, not the
draft-derived EDO kind. The preserved EDO API is exercised end-to-end by the
`tcp_edo_compatibility_public_api` test (tcp/tests.rs), which proves constructors,
constants, the `ExtendedDataOffset` variant encode/decode, and byte-exact
round-trip still work. See `docs/tcp-rfc-manifest.md` "Extended Data Offset (EDO)
Status Reconciliation".

## Flag constants (`flags.rs` target)

| Item | Current location | Status | Notes |
| --- | --- | --- | --- |
| `TCP_FLAG_FIN/SYN/RST/PSH/ACK/URG/ECE/CWR` | `tcp.rs` ~16-30 | already source-backed | RFC 9293, RFC 3168 (ECE/CWR). |
| `TCP_FLAG_NS` (`0x100`) | `tcp.rs` ~32 | compatibility-only | IANA registry now names this bit AE (RFC 9768); `TCP_FLAG_NS` must stay a permanent alias (spec edge case: the name must not disappear). |
| `TCP_FLAG_AE` (`0x100`, current IANA name) | not present | needs code expansion | Manifest flags table and plan require adding the current AE name as an alias for the same bit; summaries may show AE. |
| `flags_summary` (NS/CWR/ECE/URG/ACK/PSH/RST/SYN/FIN) | `tcp.rs` ~1056-1091 | needs source citation only | May display the current AE name per manifest while tests keep `NS`; behavior otherwise correct. |
| `flag` / per-flag helper methods on `Tcp` | `tcp.rs` ~539-594 | already source-backed | Listed here for locality; the methods stay on `Tcp` in `segment.rs`. |

## Wire and option-kind constants (`constants.rs` target)

| Item | Current location | Status | Notes |
| --- | --- | --- | --- |
| `TCP_OPTION_EOL/NOP/MSS/WINDOW_SCALE/SACK_PERMITTED/SACK/TIMESTAMP/MPTCP/FAST_OPEN/EDO` | `tcp.rs` ~34-53 | already source-backed | RFC 9293 / 7323 / 2018 / 8684 / 7413; EDO is draft (see EDO section). |
| Option kind constants for User Timeout (28), TCP-AO (29), TCP-ENO (69), AccECN (172/174), ExID (253/254) | not present | needs code expansion | Manifest IANA Option Kind table; needed so kinds 172/174 are not confused with generic private data (spec edge case). |
| `TCP_MIN_HEADER_LEN` (20), `TCP_MAX_HEADER_LEN` (60), `TCP_MAX_DATA_OFFSET` (15), `TCP_MAX_RESERVED` (0x07), `TCP_MAX_FLAGS` (0x01ff) | `tcp.rs` ~62-66 | already source-backed | RFC 9293 §3.1 bounds; currently private module constants. |

## Decode helpers (`decode.rs` target)

| Item | Current location | Status | Notes |
| --- | --- | --- | --- |
| `append_tcp_packet_with_registry` (push `Tcp`, then dispatch payload via application registry) | `tcp.rs` ~891-905 | already source-backed | Application decoders receive only post-header TCP payload bytes (manifest "Data Offset, Options Area, And Padding"). |
| `decode_tcp_parts` (min 20 bytes, data offset >= 5, header bounds, option validation, field extraction) | `tcp.rs` ~907-950 | already source-backed | Manifest decode edge cases; structured `CrafterError`, no panic. |

## Sizing helpers (`sizing.rs` target)

| Item | Current location | Status | Notes |
| --- | --- | --- | --- |
| Segment-length / sequence-space / MSS / option-budget helpers | not present | needs code expansion | Manifest "Segment Sizing And Fragmentation-Adjacent Guidance" authorizes documentation-only sizing helpers (MSS, 40-octet option budget, IPv6 1280 minimum, IPv4 DF guidance). Must not become a fragmenter or state machine. |

## Tests (`tests.rs` target plus integration tests)

| Item | Current location | Status | Notes |
| --- | --- | --- | --- |
| Unit module `tcp` (checksum autofill, decode fields/payload, explicit checksum preserved, malformed rejection) | `tcp.rs` ~1093-1188 | already source-backed | Move into `tcp/tests.rs` during folderization. |
| Unit module `tcp_options` (typed encode/decode, EDO/MPTCP/FastOpen/Generic round-trip, malformed length rejection, iterator reuse) | `tcp.rs` ~1190-1311 | needs code expansion | Extend with new typed/classified options (UTO, TCP-AO, TCP-ENO, AccECN 172/174, ExID 253/254) once added. |
| Unit module `option_padding` (EOL/32-bit alignment) | `tcp.rs` ~1313-1361 | already source-backed | Move into `tcp/tests.rs`. |
| `transport_checksums` IPv6 TCP context test | `transport/mod.rs` ~114-145 | already source-backed | Stays at the transport module level; relies on stable `Tcp` API. |
| `tcp_public_api_paths_are_usable` | `crafter/tests/public_api.rs` ~273-289 | compatibility-only | Asserts `prelude`, `core`, root, `protocols`, and `protocols::transport` TCP paths stay usable; folderization must keep all five compiling. |
| Resilience TCP decode targets (short header, data offset underflow/overrun, option overrun, invalid fixed option length) + `TcpOptions` corpus target + property round-trip | `crafter/tests/resilience.rs` (~83, 331-335, 403-407, 1386-1411) | needs code expansion | Add resilience entries for new typed/classified option kinds while preserving existing structured-error expectations. |

## Fixtures and validation coverage

| Item | Current location | Status | Notes |
| --- | --- | --- | --- |
| Fixture `ipv4-tcp-syn-options` (hex + expected layers + summary) | `crafter/tests/fixtures/bytes/ipv4-tcp-syn-options.hex`, `summaries/ipv4-tcp-syn-options.summary.txt`, asserted in `fixture_suite.rs` ~471-477, 1401-1427 | needs code expansion | Existing MSS/WS/Timestamp/SACK-Permitted/SACK SYN fixture; add fixtures for new typed options and AccECN once supported. |
| Fixture `ipv6-tcp-raw` (hex + expected layers) | `crafter/tests/fixtures/bytes/ipv6-tcp-raw.hex`, asserted in `fixture_suite.rs` ~658-662, 1961-1981 | already source-backed | IPv6 TCP segment with payload; also exercises next-header path. |
| Malformed corpus TCP entries | `crafter/tests/fixtures/malformed/core-decode-corpus.hex` (mapped in `resilience.rs`) | already source-backed | Drives structured-error decode coverage. |
| Oracle layer spec `tools/oracle/specs/layers/tcp.yaml` | tracked | needs code expansion | Option domains currently end at `edo`/`generic`; add new typed kinds and AccECN as typed support lands. Backend note "advanced option kinds may normalize as generic" should narrow. |
| Oracle feature spec `tools/oracle/specs/features/tcp-options.yaml` | tracked | needs code expansion | Add behaviors for User Timeout, TCP-AO, TCP-ENO, AccECN, ExID once typed. |
| Offline / dry-run validation (oracle, probe) | `tools/oracle/...`, probe profiles | already source-backed | Spec requires offline/dry-run defaults; live runs stay opt-in and human-authorized. |

## Out-of-scope (must not be added to the crate)

| Item | Status | Notes |
| --- | --- | --- |
| TCP connection state machine, retransmission engine, congestion control | out of scope | Spec Scope; manifest "Explicit Exclusions". |
| TCP stream reassembly | out of scope | Spec Scope. |
| IP fragmentation, IP reassembly, fragment cache | out of scope | Spec Scope; only IPv6 non-initial-fragment preservation (raw) is in scope, not reassembly. |
| TCP-AO MAC computation/verification, key derivation | out of scope | Manifest: TCP-AO bytes preserved for inspection only. |
| TCP-ENO encryption negotiation, tcpcrypt | out of scope | Manifest: TCP-ENO bytes preserved only; no negotiation. |
| MPTCP connection logic | out of scope | Manifest: subtype parsed and bytes preserved; no multipath connection logic. |
| PMTUD/PLPMTUD probing | out of scope | Manifest "Guidance only"; sizing helpers are documentation, not probes. |
| Scanner, fuzzer, packet-analyzer workflow | out of scope | Spec/manifest: those are generated tools built on the crate, not crate modules. |

## Priority-ordered gap list

This order matches the enrich-tcp-stack plan sequence (folderization first, then
registry coverage, typed helpers, sizing, fixtures, docs, validation).

1. **Folderization** — split `crafter/src/protocols/transport/tcp.rs` into
   `tcp/{mod,constants,flags,segment,option,decode,sizing,tests}.rs` mirroring
   the UDP folder module, with `transport/mod.rs` re-exporting every current
   stable name unchanged. Status: needs code expansion (mechanical move).
2. **Option/flag registry coverage** — add IANA-backed option-kind constants
   (28, 29, 69, 172, 174, 253, 254) and a `tcp_option_kind_class` /
   `TcpOptionKindClass` classifier (mirroring UDP) so obsolete, reserved,
   historic, unauthorized, and unassigned kinds stay inspectable; add
   `TCP_FLAG_AE` as the current IANA name aliasing the `0x100` bit while keeping
   `TCP_FLAG_NS`.
3. **Typed option helpers** — add typed decode/build for User Timeout (28),
   TCP-AO preservation (29), TCP-ENO preservation (69), AccECN (172/174), and
   experimental ExID (253/254), keeping unknown valid kinds as `Generic`; ensure
   kinds 172/174 are never confused with generic private data.
4. **Sizing helpers** — add documentation-only segment-length, sequence-space,
   MSS, and option-budget helpers in `sizing.rs`; no fragmenter or state machine.
5. **Fixtures** — add round-trip fixtures and summaries for the new typed
   options and AccECN, using documentation address space, alongside the existing
   `ipv4-tcp-syn-options` and `ipv6-tcp-raw` fixtures.
6. **Docs** — keep `docs/tcp-rfc-manifest.md` and this inventory in sync, record
   the EDO draft-status reconciliation and the AE/NS naming note, and cite the
   manifest rather than model memory.
7. **Validation** — extend `crafter/tests/resilience.rs`, the fixture suite, and
   the oracle TCP layer/feature specs; run offline/dry-run oracle and probe
   profiles. Live provider validation stays opt-in and human-authorized.
</content>
</invoke>
