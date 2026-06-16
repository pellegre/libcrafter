# RIP / RIPng scope and feature matrix

The shared definition of "fully implemented" for RIP (IPv4) and RIPng (IPv6) in
the `crafter` crate. Each in-scope row below names the RFC that defines it and
the plan step that delivers it; a feature is done only when its step's acceptance
gate passes. This matrix is derived from `spec.md` and the codepoint authority in
[`rip-codepoints.md`](rip-codepoints.md) and [`rip-manifest.md`](rip-manifest.md).

`crafter` is a wire-level primitive. The matrix scopes message construction,
compilation, decoding, `summary()`/`show()`, golden fixtures, oracle validation,
and provider-backed live validation. It deliberately excludes the RIP routing
engine, the route table, distance-vector convergence, and timer state: those are
agent-built tools, not crate surface.

Step numbers reference the files under `.clew/plans/rip-protocol/`.

## In scope (build + decode + golden + oracle)

### RIP message structure (IPv4, UDP 520)

| Feature | Codepoint | RFC | Step(s) |
| --- | --- | --- | --- |
| 4-octet header (command, version, reserved) | `RIP_HEADER_LEN = 4` | RFC 1058 §3.1; RFC 2453 §4 | 12-18 |
| 20-octet route entry (AFI, IP address, metric) | `RIP_ENTRY_LEN = 20` | RFC 1058 §3.1 | 07-11 |
| Request command | `RIP_COMMAND_REQUEST = 1` | RFC 1058 §3.1 | 11, 23 |
| Response command | `RIP_COMMAND_RESPONSE = 2` | RFC 1058 §3.1 | 12-16 |
| UDP/520 registry dispatch (guarded predicate) | `RIP_UDP_PORT = 520` | RFC 1058 §3.1 | 17 |

The 4-octet header and 20-octet route entry establish the layer trait and shared
framing. A single `Rip` layer parameterized by `version` covers RIPv1 and RIPv2,
since they share the header and the 20-octet entry slot (RFC 2453 §4). Decode is
a conservative UDP application decoder guarded by a `looks_like_rip` predicate so
unrelated UDP/520 traffic falls through to `Raw`.

### RIPv2 per-entry fields (RFC 2453)

| Feature | Codepoint | RFC | Step(s) |
| --- | --- | --- | --- |
| Route tag | — | RFC 2453 §4 | 19 |
| Subnet mask | — | RFC 2453 §4 | 20 |
| Next hop | — | RFC 2453 §4 | 21 |
| Multicast response convenience | `RIP_V2_MULTICAST = 224.0.0.9` | RFC 2453 §3.5 | 22 |
| Whole-table request sentinel (AFI 0, metric 16) | — | RFC 2453 §3.4.1 | 11, 23 |

### RIPv2 authentication (RFC 2453 / RFC 2082 / RFC 4822)

| Feature | Codepoint | RFC | Step(s) |
| --- | --- | --- | --- |
| Authentication entry framing (AFI 0xFFFF) | `RIP_AFI_AUTH = 0xFFFF` | RFC 2453 §4.1 | 24 |
| Simple password | `RIP_AUTH_TYPE_SIMPLE = 2` | RFC 2453 §4.1 | 25 |
| Keyed message-digest layout + trailing digest | `RIP_AUTH_TYPE_KEYED_DIGEST = 3` | RFC 2082 §3; RFC 4822 §3 | 26 |
| Keyed-MD5 digest | `RIP_DIGEST_LEN_KEYED_MD5 = 16` | RFC 2082 §3 | 27 |
| HMAC-SHA digest | `RIP_DIGEST_LEN_HMAC_SHA1 = 20`, `RIP_DIGEST_LEN_HMAC_SHA256 = 32` | RFC 4822 §3 | 28 |
| Decode-side verification helper | — | RFC 2082 §3; RFC 4822 §3 | 29 |
| Auth layer integration (auto-compute digest, honor override) | — | RFC 4822 §3 | 30 |

The digest is auto-computed on `compile()` when the caller did not set it and
preserved untouched when the caller did, so generated tools can emit a
deliberately wrong digest. The verification helper accepts the digest for the
correct key and rejects it for a wrong key.

### RIPng (IPv6, UDP 521)

| Feature | Codepoint | RFC | Step(s) |
| --- | --- | --- | --- |
| 4-octet header | `RIPNG_HEADER_LEN = 4` | RFC 2080 §2 | 31-32, 37-39 |
| 20-octet RTE (IPv6 prefix, route tag, prefix len, metric) | `RIPNG_RTE_LEN = 20` | RFC 2080 §2.1 | 33-35 |
| Next-hop RTE | `RIPNG_NEXT_HOP_METRIC = 0xFF` | RFC 2080 §2.1.1 | 36 |
| UDP/521 registry dispatch | `RIPNG_UDP_PORT = 521` | RFC 2080 §2 | 40 |
| Multicast response | `RIPNG_MULTICAST = ff02::9` | RFC 2080 §2 | 38, 75 |
| Whole-table request sentinel | — | RFC 2080 §2.1 | 42 |

RIPng is a separate `Ripng` layer (project v4/v6 naming convention), reusing the
`RipCommand` enum but with its own UDP port, IPv6 multicast group, and
single-octet metric.

### Demand / triggered RIP (RFC 2091)

| Feature | Codepoint | RFC | Step(s) |
| --- | --- | --- | --- |
| Update Request / Response / Acknowledge commands | `RIP_COMMAND_UPDATE_REQUEST = 9`, `_RESPONSE = 10`, `_ACK = 11` | RFC 2091 §3.2 | 43 |
| Demand-RIP sequence number (carried in reserved field) | — | RFC 2091 §2.3 | 44 |
| Demand-RIP message helpers | — | RFC 2091 §3.2 | 45 |

The demand-RIP commands are modeled as wire commands and sequencing, layered on
the RIPv2 core; the on-demand-circuit state machine is **not** in scope.

### Behaviors

| Feature | RFC / spec basis | Step(s) |
| --- | --- | --- |
| Malformed / edge handling (truncated header, non-multiple-of-20 body, unknown command/AFI/auth-type, over-25-entry message) | RFC 1058 §3.1; spec Edge Cases | 16, 77, 79 |
| Override of auto-filled fields (reserved, version, AFI, lengths, digest) to emit deliberately wrong bytes | CLAUDE.md "honored overrides"; spec Requirements | 14, 30 |
| Prelude exports | spec Requirements | 18, 41 |
| Golden hex / summary / pcap fixture suite | spec Acceptance | 76, 78, 80 |
| Examples (request, response, auth, RIPng) | spec Requirements | 67, 71, 73-75 |
| Oracle validation (layer + feature specs, profiles, scapy + libcrafter backends, offline + pcap runs) | spec Acceptance | 46-61 |
| Live validation (probe profile, FRR `ripd`/`ripngd` target service, dry-run-first) | spec Acceptance | 62-72 |
| User + agent docs and the final release gate | spec Acceptance | 81-85 |

Unknown commands, unknown address families, unknown authentication types,
reserved/odd trailing bytes, and over-length messages round-trip as preserved
data or surface as structured `context`/`required`/`available` errors; decode
never panics. Live work uses disposable lab/endpoint providers with dry-run plans
first and is gated behind `--confirm-live-run` and provider credentials. All
examples, tests, and defaults use documentation address space.

## Out of scope (state, not wire)

These are routing-control-plane state and analysis concerns. They are not
wire-construction primitives and are intentionally excluded; agents build them as
tools on top of `crafter`.

| Excluded item | Why excluded |
| --- | --- |
| RIP routing engine / route table / RIB | Route storage and bookkeeping; the crate emits and decodes messages, it does not maintain routes. |
| Distance-vector computation / convergence | Route-selection state machine (RFC 2453 §3.4); not a wire primitive. |
| Split-horizon / poisoned reverse | Update-generation policy (RFC 2453 §3.4.3); a generated-tool concern. |
| Timers (update, timeout, garbage-collection) | Interface/route timer state (RFC 2453 §3.8); not wire bytes. |
| Triggered-update / demand-circuit state machine | RFC 2091 commands 9-11 are modeled as wire commands and sequencing only, not as a circuit state machine. |
| Interface state / classful auto-summarization policy | Router configuration and behavior, not message encoding. |
| TCP-based or proprietary RIP variants | Outside the RFC 1058 / 2453 / 2080 / 2082 / 4822 / 2091 wire scope. |

## Deferred (note only)

| Deferred item | Note |
| --- | --- |
| HMAC-SHA digest algorithms beyond SHA-1 / SHA-256 | RFC 4822 §3 generalizes the keyed-digest algorithm; the crate models Keyed-MD5 (RFC 2082), HMAC-SHA-1, and HMAC-SHA-256. Other HMAC families are deferred but the shared authentication-entry layout already accommodates them. |
| RIPng native reference-backend cross-validation | The reference oracle backend (scapy) has no native RIPng dissector; RIPng cross-validation falls back to parser-backend decode plus libcrafter internal round-trip, recorded explicitly rather than silently skipped (spec Edge Cases). |
