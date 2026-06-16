# RIP Implementation Inventory

This inventory maps the implemented `crafter` RIP / RIPng surface to the
source-backed facts recorded in
[`docs/rip-rfc-manifest.md`](rip-rfc-manifest.md). For every layer, entry, RTE,
and authentication field it records the wire offset and width and the public
libcrafter accessor, so the implementation is auditable against its sources. The
user-facing wire guide is [`docs/rip.md`](rip.md).

Each item is marked with exactly one status:

- **source-backed** — implemented and traceable to a manifest source.
- **preserve-don't-reject** — unknown/odd values are preserved verbatim
  (round-tripped) rather than rejected or rewritten, per the crate policy.
- **out of scope** — explicitly excluded by the spec and manifest; not in the
  crate.

Offsets and widths below are confirmed against the implementation sources, not
inferred. All multi-octet fields are big-endian.

Date checked: 2026-06-16, against `docs/rip-rfc-manifest.md`.

Primary implementation paths:

- `crafter/src/protocols/rip/mod.rs` — the `Rip` IPv4 layer (RFC 1058 / 2453),
  its builders, accessors, `Layer` impl, `decode`, the UDP/520 binding
  (`append_rip_packet` / `looks_like_rip_payload`), and the packet convenience
  helpers.
- `crafter/src/protocols/rip/entry.rs` — the `RipEntry` 20-octet route entry.
- `crafter/src/protocols/rip/message.rs` — the `RipCommand` enum.
- `crafter/src/protocols/rip/auth.rs` — RIPv2 authentication (`RipAuth`,
  `RipAuthPayload`, `RipKeyedDigestHeader`, `RipDigestAlgorithm`, `verify`).
- `crafter/src/protocols/rip/constants.rs` — RIP wire constants.
- `crafter/src/protocols/rip/registry.rs` — command / address-family / auth-type
  codepoint metadata.
- `crafter/src/protocols/rip/ripng/mod.rs` — the `Ripng` IPv6 layer (RFC 2080),
  its `decode`, and the UDP/521 binding.
- `crafter/src/protocols/rip/ripng/rte.rs` — the `RipngRte` 20-octet RTE.
- `crafter/src/protocols/rip/ripng/constants.rs` — RIPng wire constants.
- `crafter/src/registry.rs` — UDP/520 and UDP/521 decode dispatch.
- `crafter/src/protocols/mod.rs` and `crafter/src/lib.rs` — `protocols`, root,
  `core`, and `prelude` re-exports.
- `crafter/tests/rip_public_api.rs`, `rip_golden.rs`, `rip_malformed.rs`,
  `ripng_public_api.rs`, `ripng_golden.rs`, `ripng_malformed.rs`,
  `fixture_suite.rs` — public API, golden vectors, malformed resilience, and
  byte/summary/pcap fixtures.
- `tools/oracle/specs/` — the offline oracle data for the `rip-smoke` profile.

## `Rip` layer header (`rip/mod.rs`)

The `Rip` layer is the 4-octet RIP header plus zero or more `RipEntry` records.
It composes with `/`, compiles with `compile()`, decodes through
`Packet::decode_from_l3`, and stays inspectable through `summary()` / `show()`.

| Field | Offset | Width | Accessor / builder | Status | Notes |
| --- | ---: | ---: | --- | --- | --- |
| Command | 0 | 1 octet | `command()` → `RipCommand`, `command_value()` → `u8`; builders `with_command(RipCommand)`, `command_code(u8)` | source-backed | RFC 1058 §3.1; default `RipCommand::Response`. |
| Version | 1 | 1 octet | `version_value()`; builder `version(u8)` | source-backed | RFC 1058 §3.1 / RFC 2453 §4; default 2. |
| Reserved / Sequence | 2 | 2 octets | `reserved_value()`; builder `reserved(u16)`; demand view `demand_sequence(u16)` / `demand_sequence_value()` → `Option<u16>` | source-backed | RFC 1058 §3.1 (zero) / RFC 2091 §2.3 (Sequence Number for Update* commands). |
| Entries | 4 | 20 × n | `entries()` → `&[RipEntry]`; builders `entry(RipEntry)`, `with_entries(...)` | source-backed | RFC 2453 §4. |
| Authentication | (leading entry / trailing block) | — | `auth_config()` → `Option<&RipAuth>`; builder `auth(RipAuth, key)` | source-backed | RFC 2453 §4.1 / RFC 2082 / RFC 4822 §3. |

Layer plumbing: `Layer::name()` = `"Rip"`, `encoded_len()`, `compile()`,
`summary()` (e.g. `"Rip v2 Response (2 entries)"`), `inspection_fields()`
(`command`/`version`/`reserved`/`entries`). Message-builder conveniences:
`Rip::new`, `request`, `response`, `update_request`, `update_response`,
`update_acknowledge`. `compile()` fills version and reserved when unset and
preserves caller-set values, including deliberately wrong ones.

## `RipCommand` (`rip/message.rs`)

| Item | Accessor | Status | Notes |
| --- | --- | --- | --- |
| `RipCommand` enum (`Request`, `Response`, `UpdateRequest`, `UpdateResponse`, `UpdateAcknowledge`, `Other(u8)`) | `RipCommand::from_code(u8)`, `code()` → `u8`, `name()` → `&str` | preserve-don't-reject | RFC 1058 §3.1 (1/2), RFC 2091 §3.2 (9/10/11); any other code is `Other(code)`. |

## `RipEntry` route entry (`rip/entry.rs`)

A fixed 20-octet, big-endian record.

| Field | Offset | Width | Accessor / builder | Status | Notes |
| --- | ---: | ---: | --- | --- | --- |
| Address Family Identifier | 0 | 2 octets | `address_family_value()`; builder `address_family(u16)` | preserve-don't-reject | RFC 2453 §4.1; default IP = 2. Unknown AFIs preserved. |
| Route Tag | 2 | 2 octets | `route_tag_value()`; builders `route_tag(u16)`, `with_route_tag(u16)` | source-backed | RFC 2453 §3.1; zero in RIPv1. |
| IPv4 Address | 4 | 4 octets | `address_value()`; builder `address(Ipv4Addr)` | source-backed | RFC 1058 §3.1 / RFC 2453 §4. |
| Subnet Mask | 8 | 4 octets | `subnet_mask_value()`, `prefix_len()` → `u8`; builders `subnet_mask(Ipv4Addr)`, `with_prefix_len(u8)` | source-backed | RFC 2453 §4; `prefix_len()` counts set bits (non-contiguous masks preserved). |
| Next Hop | 12 | 4 octets | `next_hop_value()`, `next_hop_is_default()`; builders `next_hop(Ipv4Addr)`, `with_next_hop(Ipv4Addr)` | source-backed | RFC 2453 §4.4; 0.0.0.0 = route originator. |
| Metric | 16 | 4 octets | `metric_value()`, `is_unreachable()`; builder `metric(u32)` | source-backed | RFC 1058 §3.1; ≥ 16 is unreachable. |

Constructors and predicates: `RipEntry::new`, `ipv1_route(address, metric)`,
`ipv2_route(address, mask, metric)`, `whole_table_request()` /
`is_whole_table_request()` (AFI 0, metric 16 sentinel; RFC 1058 §3.4.1 /
RFC 2453 §3.9.1), `is_auth_marker()` (AFI 0xFFFF). A buffer shorter than 20
octets returns `buffer_too_short` with context `"RIP route entry"`.

## RIPv2 authentication (`rip/auth.rs`)

The authentication entry replaces the first route entry (AFI 0xFFFF); the
Authentication Type rides in the route-tag octets.

| Type / form | Accessor / builder | Status | Notes |
| --- | --- | --- | --- |
| `RipAuth` (auth_type + payload) | `auth_type_value()` → `u16`, `auth_type()` → `RipAuthType`, `auth_data_len()` → `u8`, `as_entry()` → `RipEntry` | source-backed | RFC 2453 §4.1. |
| Simple password (type 2) | `RipAuth::simple_password(&[u8])`; decode `decode_auth_entry(&RipEntry)` | source-backed | RFC 2453 §4.1; 16 octets padded/truncated, laid into the entry's address/mask/next-hop/metric slots. |
| Keyed digest (type 3) | `RipAuth::keyed_digest(key_id, auth_data_len)`, `keyed_digest_with(RipDigestAlgorithm, key_id)`; `keyed_digest_header_entry()` → `RipEntry`, `trailing_digest_block(&[u8])` → `Vec<u8>` | source-backed | RFC 2082 / RFC 4822 §3. |

Keyed-digest leading-entry layout (`RipKeyedDigestHeader`), within the 20-octet
entry:

| Field | Offset in entry | Width | Accessor | Notes |
| --- | ---: | ---: | --- | --- |
| AFI marker (0xFFFF) | 0 | 2 octets | (via `as_entry` / `keyed_digest_header_entry`) | RFC 2453 §4.1. |
| Authentication Type (3) | 2 | 2 octets | `auth_type_value()` | RFC 2082 / RFC 4822 §3.1. |
| Offset to digest | 4 | 2 octets | `offset_value()` | RFC 4822 §3.1. |
| Key Identifier | 6 | 1 octet | `key_id_value()` | RFC 4822 §3.1. |
| Authentication Data Length | 7 | 1 octet | `auth_data_len_value()` | RFC 4822 §3.1; reflects the algorithm length (16/20/32) when unset. |
| Sequence Number | 8 | 4 octets | `sequence_value()` | RFC 4822 §3.1. |
| Reserved word 1 | 12 | 4 octets | `reserved1` field | RFC 4822 §3.1; zero. |
| Reserved word 2 | 16 | 4 octets | `reserved2` field | RFC 4822 §3.1; zero. |

Trailing digest block: a 4-octet introduction (AFI 0xFFFF + trailer marker
`RIP_AUTH_TRAILER_MARKER` = 0x0001) followed by the raw digest. The digest is
auto-computed on `compile()` when unset and the pinned `digest:
Option<[u8; 16]>` survives untouched when set.

- `RipDigestAlgorithm` (`KeyedMd5`, `HmacSha1`, `HmacSha256`) with
  `digest_len()` → 16 / 20 / 32 octets. RFC 2082 §3.2.1 / RFC 4822 §3.
- `verify(message_bytes, key)` → `RipAuthVerification`
  (`Unauthenticated`, `SimplePasswordOk`, `SimplePasswordMismatch`, `DigestOk`,
  `DigestMismatch`). Constant-time comparison; never panics on truncated input.

## `Ripng` layer header (`rip/ripng/mod.rs`)

| Field | Offset | Width | Accessor / builder | Status | Notes |
| --- | ---: | ---: | --- | --- | --- |
| Command | 0 | 1 octet | `command()` → `RipCommand`, `command_value()`; builders `with_command(RipCommand)`, `command_code(u8)` | source-backed | RFC 2080 §2.1; reuses `RipCommand`. |
| Version | 1 | 1 octet | `version_value()`; builder `version(u8)` | source-backed | RFC 2080 §2; default 1. |
| Reserved | 2 | 2 octets | `reserved_value()`; builder `reserved(u16)` | source-backed | RFC 2080 §2; zero. |
| RTEs | 4 | 20 × n | `rtes()` → `&[RipngRte]`; builders `rte(RipngRte)`, `with_rtes(...)` | source-backed | RFC 2080 §2.1. |

Layer plumbing: `Layer::name()` = `"Ripng"`, `encoded_len()`, `compile()`,
`summary()` (e.g. `"Ripng v1 Response (2 RTEs)"`), `inspection_fields()`
(`command`/`version`/`reserved`/`rtes`). Builders: `Ripng::new`, `request`,
`response`.

## `RipngRte` route table entry (`rip/ripng/rte.rs`)

A fixed 20-octet, big-endian record.

| Field | Offset | Width | Accessor / builder | Status | Notes |
| --- | ---: | ---: | --- | --- | --- |
| IPv6 Prefix | 0 | 16 octets | `prefix_value()`; builder `prefix(Ipv6Addr)` | source-backed | RFC 2080 §2.1; next-hop address in a next-hop RTE. |
| Route Tag | 16 | 2 octets | `route_tag_value()`; builder `route_tag(u16)` | source-backed | RFC 2080 §2.1. |
| Prefix Length | 18 | 1 octet | `prefix_len_value()`; builder `prefix_len(u8)` | preserve-don't-reject | RFC 2080 §2.1; out-of-range values preserved. |
| Metric | 19 | 1 octet | `metric_value()`; builder `metric(u8)` | source-backed | RFC 2080 §2.1 / §2.1.1; 16 infinity, 0xFF next-hop marker. |

Constructors and predicates: `RipngRte::new`, `route(prefix, prefix_len,
metric)`, `next_hop(address)` / `is_next_hop()` / `next_hop_address()` →
`Option<Ipv6Addr>` (RFC 2080 §2.1.1), `whole_table_request()` /
`is_whole_table_request()` (prefix ::, len 0, metric 16; RFC 2080 §2.4.1). A
buffer shorter than 20 octets returns `buffer_too_short` with context
`"RIPng route table entry"`.

## Wire constants (`rip/constants.rs`, `rip/ripng/constants.rs`)

| Constant | Value | Source |
| --- | ---: | --- |
| `RIP_UDP_PORT` | 520 | RFC 1058 §3.1 |
| `RIP_HEADER_LEN` | 4 | RFC 1058 §3.1 |
| `RIP_ENTRY_LEN` | 20 | RFC 1058 §3.1 / RFC 2453 §4 |
| `RIP_MAX_ENTRIES` | 25 | RFC 2453 §4 (generation guideline) |
| `RIP_METRIC_INFINITY` | 16 | RFC 1058 §3.1 |
| `RIP_COMMAND_REQUEST` / `RIP_COMMAND_RESPONSE` | 1 / 2 | RFC 1058 §3.1 |
| `RIP_COMMAND_UPDATE_REQUEST` / `_RESPONSE` / `_ACK` | 9 / 10 / 11 | RFC 2091 §3.2 |
| `RIP_VERSION_1` / `RIP_VERSION_2` | 1 / 2 | RFC 1058 §3.1 / RFC 2453 §4 |
| `RIP_AFI_IP` | 2 | IANA Address Family Numbers |
| `RIP_AFI_AUTH` | 0xFFFF | RFC 2453 §4.1 |
| `RIP_V2_MULTICAST` | 224.0.0.9 | RFC 2453 §3.5 |
| `RIP_SIMPLE_PASSWORD_LEN` | 16 | RFC 2453 §4.1 |
| `RIP_AUTH_TYPE_SIMPLE` / `RIP_AUTH_TYPE_KEYED_DIGEST` | 2 / 3 | RFC 2453 §4.1 / RFC 2082 / RFC 4822 §3 |
| `RIP_AUTH_TRAILER_MARKER` | 0x0001 | RFC 4822 §3.1 |
| `RIP_MD5_DIGEST_LEN` | 16 | RFC 2082 §3.2.1 |
| `RIPNG_UDP_PORT` | 521 | RFC 2080 §2 |
| `RIPNG_HEADER_LEN` | 4 | RFC 2080 §2 |
| `RIPNG_RTE_LEN` | 20 | RFC 2080 §2.1 |
| `RIPNG_METRIC_INFINITY` | 16 | RFC 2080 §2.1 |
| `RIPNG_NEXT_HOP_METRIC` | 0xFF | RFC 2080 §2.1.1 |
| `RIPNG_VERSION_1` | 1 | RFC 2080 §2 |
| `RIPNG_MULTICAST` | ff02::9 | RFC 2080 §2 |

## Codepoint registries (`rip/registry.rs`)

| Item | Accessor | Status | Notes |
| --- | --- | --- | --- |
| Command metadata | `rip_command_meta(u8)` → `RipCommandMeta { code, name, status }`, `rip_command_name(u8)` → `Option<&str>`, `RipCommandStatus` | preserve-don't-reject | RFC 1058 §3.1 / appendix, RFC 2091 §3.2. Every code yields a non-empty name. |
| Address family | `rip_address_family(u16)` → `RipAddressFamily` (`Ip`, `AuthMarker`, `Other(u16)`), `is_rip_auth_marker(u16)` | preserve-don't-reject | IANA Address Family Numbers (IP = 2), RFC 2453 §4.1 (0xFFFF). |
| Authentication type | `rip_auth_type(u16)` → `RipAuthType` (`SimplePassword`, `KeyedMessageDigest`, `Other(u16)`), `rip_auth_type_code(RipAuthType)` | preserve-don't-reject | RFC 2453 §4.1 (2), RFC 2082 / RFC 4822 §3 (3). |

## Decode bindings (`rip/mod.rs`, `rip/ripng/mod.rs`, `registry.rs`)

| Item | Accessor | Status | Notes |
| --- | --- | --- | --- |
| RIP decode | `crate::protocols::rip::decode(&[u8])` → `Result<Rip>` | source-backed | 4-octet header then whole 20-octet entries; structured error on truncation. Recognizes a leading AFI-0xFFFF auth entry. |
| RIP UDP/520 binding | `append_rip_packet`, `looks_like_rip_payload` | source-backed | Conservative: known command + valid version + 20-multiple body, else `Raw`. |
| RIPng decode | `crate::protocols::rip::ripng::decode(&[u8])` → `Result<Ripng>` | source-backed | 4-octet header then whole 20-octet RTEs; structured error on truncation. |
| RIPng UDP/521 binding | `append_ripng_packet`, `looks_like_ripng_payload` | source-backed | Conservative, mirrors RIP/520. |

## Packet convenience helpers (`rip/mod.rs`, `rip/ripng/mod.rs`)

| Helper | Returns | Source |
| --- | --- | --- |
| `rip_v1_whole_table_request(source, destination)` | `Packet` | RFC 1058 §3.4.1 |
| `rip_v2_whole_table_request(source)` | `Packet` | RFC 2453 §3.9.1 |
| `rip_v2_multicast_response(source, entries)` | `Packet` | RFC 2453 §3.5 |
| `rip_update_request(source, dest, sequence)` | `Packet` | RFC 2091 §2.3 |
| `rip_update_response(source, dest, sequence, entries)` | `Packet` | RFC 2091 §2.3 |
| `rip_update_acknowledge(source, dest, sequence)` | `Packet` | RFC 2091 §2.3 |
| `ripng_whole_table_request(source)` | `Packet` | RFC 2080 §2.4.1 |

The layer/entry/RTE types and the wire constants reach agent code through
`crafter::prelude::*`; the auth, verification, registry, decode, and
packet-convenience helpers are reached through the
`crafter::protocols::rip` (and `::ripng`) module paths.

## Validation commands

```sh
cargo test -p crafter --test rip_public_api
cargo test -p crafter --test rip_golden
cargo test -p crafter --test rip_malformed
cargo test -p crafter --test ripng_public_api
cargo test -p crafter --test ripng_golden
cargo test -p crafter --test ripng_malformed
cargo test -p crafter --test fixture_suite rip
tools/oracle/run offline --profile rip-smoke --seed 1
tools/oracle/run pcap --profile rip-smoke --seed 1
tools/probe/run --profile rip-smoke --provider local-dry-run
```

Broad validation and release gate:

```sh
cargo test --workspace
.agents/scripts/check-crafter-release --static
```

## Out of scope

| Item | Status | Notes |
| --- | --- | --- |
| RIP routing engine, route table, distance-vector computation | out of scope | Spec Non-Goals; manifest "Explicit Exclusions". |
| Convergence, split-horizon, poison-reverse, route/garbage timers | out of scope | Router behavior, not packet behavior. |
| Triggered-update timing / on-demand circuit state machine | out of scope | The RFC 2091 demand *messages* and Sequence Number are modeled; the circuit timing/state machine is not. |
| Authentication key management / rotation | out of scope | Keys are used only to compute or verify a digest. |
| Live RIP exchange in automated acceptance | out of scope | Offline + dry-run by default; real wire runs are provider-backed and human-confirmed. |
| Scanner, fuzzer, packet-analyzer workflow | out of scope | Generated tools built on the crate, not crate modules. |
