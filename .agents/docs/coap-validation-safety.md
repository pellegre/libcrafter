# CoAP validation and live-safety matrix

This note defines the validation boundary for CoAP packet work. It is operating
policy for agents and generated tools, not a new source of CoAP wire facts.
Field layouts, assignments, defaults, extension semantics, and stable error
contexts continue to come from `.agents/docs/coap-rfc-manifest.md`,
`.agents/docs/coap-codepoints.md`, `.agents/docs/coap-wire-grammar.md`,
`.agents/docs/coap-extensions.md`, `.agents/docs/coap-api-design.md`, and
`.agents/docs/coap-error-policy.md`.

CoAP remains a packet primitive. Validation may build, compile, decode,
round-trip, persist, compare, and inspect typed `Coap` and `CoapReliable`
layers. It must not add a client or server runtime, retransmission scheduler,
Observe subscription manager, block assembler, discovery scanner, proxy,
security-context service, TCP stream reassembler, or multicast membership
workflow.

## Validation rules

- Offline evidence is the correctness gate. A live exchange may corroborate
  behavior, but it never replaces a golden vector, malformed corpus,
  preservation round trip, property check, or synthetic pcap.
- Every fixture and plan records the source-manifest entry, RFC section, IANA
  snapshot row, or official vector that authorizes its expected bytes.
- Compilation tests distinguish unset fields from explicit fields. Tests for
  intentionally malformed explicit values assert emitted bytes and opt-in
  validation findings separately.
- Direct decoders assert typed success or the exact structured error contract.
  Registry tests feed the same candidates through service-port dispatch and
  assert an unchanged `Raw` fallback when the conservative shape gate fails.
- Unknown but structurally valid codes, options, content formats, signaling
  values, and security metadata are successful preservation cases, not
  malformed cases.
- Property and arbitrary-input tests complement the named deterministic corpus;
  they do not replace it.
- No automated acceptance command may require credentials, raw-socket
  privileges, provider reachability, a live responder, or any live network.

## Source, address, and capture policy

Tracked unicast examples, generated plans, and pcaps use RFC 5737 IPv4 ranges
such as `192.0.2.0/24` and `198.51.100.0/24`, RFC 3849 IPv6
`2001:db8::/32`, deterministic documentation MAC addresses, synthetic
interface names such as `dry-run0`, and synthetic payloads. They never contain
public provider addresses or addresses learned from the developer machine.

Protocol-defined CoAP multicast constants may appear only in non-sending byte
fixtures, synthetic pcaps, or provider-backed plans whose target is an isolated
controlled lab segment. Do not replace a protocol-defined multicast constant
with a documentation unicast address when the multicast value itself is under
test. Conversely, never use that constant as a reason to send multicast from
the developer host, join a local group, or discover uncontrolled responders.

Committed captures are deterministic synthetic fixtures. Provider pcaps remain
ignored run artifacts until they have been minimized, regenerated with
documentation-safe values where possible, and reviewed for sensitive metadata.

## Core datagram evidence matrix

The identifiers below are stable coverage labels for later fixture, oracle,
and probe work. `N/A` means that a validation surface cannot establish the
named property; it does not waive the offline evidence in the same row.

| ID | Feature | Golden and fixture evidence | Malformed and preservation evidence | Property and boundary evidence | Pcap evidence |
| --- | --- | --- | --- | --- | --- |
| C01 | Fixed header, version, type, code, Message ID, empty messages, and unset defaults | RFC 7252 request, response, acknowledgement, reset, and empty-message bytes; compile/decode/recompile identity | Preserve explicit non-default version, unusual type/code pairs, unknown code bytes, and explicit Message ID; exact four-byte prefix truncations | Exhaustive bit packing for version/type/TKL and all code bytes; arbitrary Message IDs | Synthetic IPv4 and IPv6 UDP records for request, response, ACK, and reset |
| C02 | Base and extended tokens | Zero, 1..8-byte base tokens and RFC 8974 TKL 12, 13, 14 boundary vectors | Reserved TKL 15, truncated extension bytes/tokens, explicit logical-length mismatch, zero-length versus absence | Round trip token lengths 0..65804 with bounded allocation; shortest canonical discriminator; overflow checks | Base and extended-token messages persisted without changing TKL bytes |
| C03 | Codepoints, ordered options, option headers, and opaque values | Delta/length boundaries 0..12, 13, and 14; repeated, empty, UTF-8, binary, and current assigned options | Reserved nibble 15, truncated extensions/value, cumulative-number overflow, out-of-order explicit raw headers, unknown option and noncanonical uint preservation | Encode/decode arbitrary ordered option sequences and derive Critical/Unsafe/NoCacheKey from number bits | Ordered repeated and unknown options survive classic pcap read/write |
| C04 | Payload marker and binary payload | No marker/no payload, marker plus payload, and binary payload vectors | Marker without payload is a structured error on strict decode; explicit payload with a missing-marker override compiles unchanged and validates separately | Arbitrary binary payload round trip and marker-state partition checks | Marker and payload bytes remain exact through capture persistence |
| C05 | Strict direct decode and stable errors | Successful `decode_coap` and `Coap::decode` typed-layer fixtures | Prefix corpus for every fixed-header, TKL, option, marker, and payload boundary; exact context, `required`, and `available`; `catch_unwind` around every case | Arbitrary slices never panic or overread; arithmetic boundaries remain checked | Truncated records decode to the documented error without corrupting adjacent records |
| C06 | Conservative UDP registry dispatch | Cleartext complete messages on assigned service ports become typed CoAP | Wrong port, reserved version, malformed candidate, secure-port ciphertext, and unrelated service-port data remain byte-identical `Raw` | Shape predicate implies a complete direct decode; failed predicates consume no prefix | Mixed candidate/non-candidate capture proves per-record dispatch and Raw fallback |
| C07 | Packet composition, autofill, inspectability, and typed access | `Ethernet / Ipv4|Ipv6 / Udp / Coap` via `crafter::prelude::*`; deterministic `summary()`, `show()`, and `hexdump()` | Explicit IP/UDP/CoAP override values remain untouched; unknown application data remains inspectable | Compile/decode/recompile whole-stack identity for generated documentation addresses | Classic pcap write/read and `PacketWire` preserve layer stack and link type |
| C08 | Registry metadata and semantic validation | Current assigned labels/status and typed request/response classification tables | Unknown/reserved values retain numeric identity; semantic findings never mutate or block compilation | Table-driven option-property, code-class/detail, request/response matching, and validation checks | Representative assigned and unknown metadata remains visible after pcap decode |

| ID | Oracle evidence | Probe evidence | Guarded-live evidence |
| --- | --- | --- | --- |
| C01 | Strict-byte core datagrams in both encode and decode directions where a backend declares support | Deterministic confirmable request/controlled response plans plus dry-run mismatch cases | Optional one-request controlled unicast exchange; no retransmission engine claim |
| C02 | Core tokens only unless backend capability tests prove RFC 8974 support; official vectors remain authoritative | Plan base and extended tokens, but adapter bytes must be checked offline before live candidacy | Base token echo/match may be observed; extended-token live is capability-gated and optional |
| C03 | Compare canonical assigned options; raw/crafter comparison owns unknown, repeated, and noncanonical representations | Deterministic URI/representation plans and explicit unsupported-case metadata | Only options understood by the controlled responder; unknown/noncanonical cases stay offline |
| C04 | Compare marker and payload bytes, never only decoded text | Binary request/response plan with bounded payload | Optional controlled binary echo/response; no arbitrary payload injection |
| C05 | Oracle malformed cases run direct crafter decode; reference parser diagnostics are informational only | Dry-run failure taxonomy, not a malformed-byte oracle | N/A; malformed traffic is not needed to prove parser safety |
| C06 | Feed equal bytes through direct and registry paths; backend port heuristics are not authoritative | Plan cleartext candidate, unrelated UDP, and secure-port Raw cases without sending the latter two | Only the cleartext controlled case is live-capable; classification negatives stay offline |
| C07 | Compare complete IPv4/IPv6 UDP bytes and normalized decoded stacks; save oracle pcap artifacts | Adapter materialization, documentation-address rewrite, count, capture, and artifact plan checks | Optional bounded full-stack exchange on disposable endpoints |
| C08 | Compare only labels backed by the same reviewed registry snapshot; numeric bytes are primary | Request/response matching and expected-code plan assertions | N/A for registry labels and validation findings |

## Advanced feature evidence matrix

| ID | Feature | Golden and fixture evidence | Malformed and preservation evidence | Property and boundary evidence | Pcap evidence |
| --- | --- | --- | --- | --- | --- |
| A01 | URI, conditional, representation, location, size, and proxy options | Source-backed examples for Uri-*, If-Match, ETag, If-None-Match, Content-Format, Accept, Max-Age, Location-*, Size1/2, Proxy-Uri, and Proxy-Scheme | Length violations, noncanonical uints, unknown Content-Formats, repeated occurrences, and Proxy-Uri coexistence preservation with semantic findings | URI segment/query composition, option format/length boundaries, and unknown registry-value round trips | Synthetic request/response capture with ordered URI and representation metadata |
| A02 | CoRE Link Format discovery | `/.well-known/core` GET and source-backed link-format payloads with known and extension attributes | Unterminated URI/quote, invalid separators/escapes, non-UTF8 raw payload, and caller-selected raw-form preservation | Parse/serialize canonical identity for generated valid links; comma/quote/angle-bracket boundary properties | Discovery request and synthetic link-format response, unicast by default |
| A03 | Observe | Register, deregister, notification, and reliable empty-Observe fixtures | Values over three bytes, inappropriate role/code use, and unknown raw values remain inspectable | Exhaustive/modular 24-bit serial comparison including equality, wraparound, and 128-second rule | Synthetic registration and multiple notification records without subscription state |
| A04 | Block1, Block2, Size1/2, and BERT | SZX 0..6 boundaries, maximum NUM/offset, and reliable BERT control/descriptive examples | Overlong values, invalid BERT transport/payload lengths, Size mismatch, and explicit mixed metadata preserved | Bit-field round trips, offsets without overflow, next-NUM calculation, and BERT chunk boundaries | Independent message records for a transfer; no pcap-level reassembly assertion |
| A05 | No-Response, FETCH, PATCH, and iPATCH | Suppression masks 0/2/8/16/26 and assigned method/response-code fixtures | Unknown mask bits, overlong No-Response, missing/unknown patch Content-Format, and unusual code combinations | Response-class mask classification and method/code table coverage | Synthetic request/response records; no resource mutation |
| A06 | Hop-Limit, Echo, and Request-Tag | Hop-Limit default/boundaries, 5.08 response, Echo 1/40 bytes, Request-Tag empty/8 bytes | Zero/multi-byte Hop-Limit, Echo 0/>40, Request-Tag >8, repeated/non-repeatable cases, and Inner/Outer preservation | Safe decrement/exhausted result and opaque byte round trips | Synthetic proxy-shaped and blockwise-shaped messages without forwarding |
| A07 | Q-Block1 and Q-Block2 | Minimum/maximum fields, missing-block representation, stable Request-Tag/Size1 examples | Same-level Block/Q-Block conflicts, malformed values, invalid repetition, and cross-level Inner/Outer preservation | Bit-field/offset boundaries and stateless burst metadata; no scheduler property | Separate burst-message records and missing-block response fixture; no assembly |
| A08 | Reliable framing, extended lengths, signaling, and one-frame boundaries | Len nibbles 0..15, complete CSM/Ping/Pong/Release/Abort, contextual options, and trailing-frame consumed-length fixtures | Truncated Len/TKL extensions, token/body, size overflow, unknown signaling code/options, explicit length mismatch, and partial/multiple-frame boundaries | Frame-size arithmetic, canonical Len/TKL selection, one-frame decode/recompile identity | Synthetic TCP records containing one frame and multiple frames; no stream reassembly claim |
| A09 | Pairwise OSCORE option, derivation, protect, and unprotect | RFC 8613 Appendix C vectors for option, HKDF, nonce, AAD, ciphertext, and typed outer/inner messages | Reserved flags, truncated fields, unsupported algorithms, missing context, wrong identifiers/binding/AAD/key/tag, tampering, and redacted failures | Deterministic protect/unprotect inverse for valid contexts; nonce and length bounds; unauthenticated plaintext is never returned | Synthetic protected CoAP records retain exact outer bytes; secrets and plaintext are excluded from capture metadata |
| A10 | Group request/response and provisional Group OSCORE metadata | Non-confirmable multicast request plus unicast response metadata; provisional raw Group Flag/identifier/ciphertext fixtures only | Confirmable group request validation, Token mismatch, unknown/provisional flag and signature/algorithm material preservation | Stateless Token-only response matching and unicast/multicast classification | Protocol multicast constants only in non-sending synthetic pcaps or isolated provider plans |

| ID | Oracle evidence | Probe evidence | Guarded-live evidence |
| --- | --- | --- | --- |
| A01 | Canonical common options may use Scapy/Wireshark when capability-pinned; byte fixtures own raw/noncanonical cases | Controlled GET/response plans with deterministic URI and representation options | Optional controlled unicast request; proxy, cache, and mutation behavior are excluded |
| A02 | Compare link-format payload bytes and crafter typed model; backend text parsing is secondary | Controlled discovery responder plan using a fixed synthetic resource set | Optional unicast discovery only; multicast discovery requires an isolated provider segment |
| A03 | Compare option bytes and stateless ordering results; backend subscription state is out of scope | Planned register/notification pair with bounded messages and no retained subscription | Optional one bounded controlled notification; no long-lived observer |
| A04 | Compare individual block option/message bytes; backend reassembly is ignored | Planned single Block1/Block2 exchange and optional BERT capability plan | Optional one bounded block exchange; BERT requires a controlled reliable responder |
| A05 | Compare method/code/option bytes; endpoint suppression or patch application is not oracle behavior | Plans describe expected response class and media type without mutating a real resource | Optional response-code check against a disposable synthetic resource only |
| A06 | Compare bytes and typed helper outputs; freshness and forwarding policy remain N/A | Plan one proxy-shaped decrement and opaque echo/tag exchange, normally dry-run only | Optional Echo round trip; Hop-Limit forwarding and tag lifecycle remain out of scope |
| A07 | Official bytes plus crafter round trips are primary; no backend may claim transfer scheduling | Plan a bounded set of individual Q-Block messages and missing-block response | Optional only when the controlled responder explicitly advertises Q-Block; otherwise stable skip |
| A08 | Raw strict-byte framing plus any capability-pinned decoder; no backend stream buffering or connection claims | Plan one complete TCP frame per send and signaling-only controlled cases | Optional bounded CSM/Ping exchange; no TLS, WebSocket, or stream reassembly |
| A09 | Official RFC vectors are the independent authority; external backends may corroborate outer fields only | Dry-run with ephemeral fixture context identifiers and redacted plan fields; never serialize secrets into JSON | Optional only with a controlled OSCORE responder and ephemeral fixture context; otherwise stable skip |
| A10 | Base group metadata can be compared as raw datagrams; provisional Group OSCORE has no encode/reference claim | Group request stays plan-only unless the provider exposes an isolated controlled multicast segment | Optional base group request only on that segment; Group OSCORE live is prohibited until final authority is re-reviewed |

## Reference-backend limits

The CoAP oracle generator, libcrafter adapter, partial Scapy/Wireshark reference
adapters, and probe plugin are implemented. Support remains declared per
feature and direction; the existence of a native layer name is not evidence
that a backend supports the complete grammar.

- Scapy is an encode/decode reference only for the canonical datagram fields,
  ordinary UDP stacks, and options that a capability test proves it preserves.
  Native normalization may discard explicit raw option headers, noncanonical
  integers, unknown ordering details, extended TKL metadata, or payload-marker
  state. Those cases use source-backed bytes and crafter round trips instead.
- Wireshark/tshark is decode-only and version-dependent. It cannot prove
  compile defaults or explicit override preservation. Heuristic/port
  classification is not the crafter registry contract, and expert-info text is
  not a stable replacement for `CrafterError` context and size data.
- Reliable CoAP framing/signaling, RFC 8974 extended tokens, BERT, Q-Block,
  OSCORE transforms, and provisional Group OSCORE remain unsupported unless a
  pinned backend/version capability test demonstrates the exact case. TCP
  stream reassembly performed by a reference tool must not be attributed to
  `CoapReliable`.
- RFC 8613 Appendix C is the independent OSCORE byte authority. A backend that
  can display the outer OSCORE option or ciphertext does not independently
  validate HKDF, nonce, AAD, authentication, or plaintext handling.
- No backend may serialize provisional Group OSCORE from draft memory. Raw
  metadata preservation and an explicit unsupported result are the expected
  evidence until the source stop condition is cleared.
- Pcap decode proves persistence and framing, not semantic correctness. Probe
  responses prove bounded controlled behavior, not byte authority. Unsupported
  cases are recorded with backend, version, direction, feature, and stable skip
  reason; they are never silently removed from coverage or replaced by live
  traffic.

Reference logic belongs under `tools/oracle/engine/backends/`, and support
metadata belongs in the oracle specs and backend registry. Do not add ad hoc
Scapy/tshark snippets to tests or generated tools.

## Required offline profiles

`coap-smoke` is the fast deterministic developer profile. It contains at least:

- one IPv4 confirmable GET with Uri-Path and token, one IPv6 response with
  Content-Format and payload, one empty ACK/reset case, and one unrelated UDP
  Raw-fallback case;
- one repeated/unknown option and binary payload preservation case;
- representative fixed-header, TKL, option, and marker truncations;
- one classic pcap round trip with deterministic summary/show output;
- one complete reliable CSM frame and one trailing-frame boundary case; and
- the smallest complete RFC 8613 protect/unprotect vector, entirely offline.

`coap-ci` is the deterministic offline release profile. It is a superset of
`coap-smoke` and covers every C01-C08 and A01-A10 row, the named malformed
corpus, property/boundary suites, IPv4/IPv6 and UDP/TCP pcaps, public-prelude
compilation, full oracle capability/skip reporting, probe plan snapshots, and
all official/reference vectors. It uses fixed seeds and counts in CI artifacts;
changing a seed or a golden digest is a reviewed fixture change.

Typical offline and local dry-run invocations are:

```sh
tools/oracle/run offline --profile coap-smoke --seed 5683 --count 10 --out target/oracle/coap-smoke
tools/oracle/run offline --profile coap-ci --seed 7252 --count 100 --out target/oracle/coap-ci
tools/probe/run --provider local-dry-run --dry-run --profile coap-smoke --seed 5683 --count 12 --out target/probe/coap-smoke
tools/oracle/run live --provider local-dry-run --dry-run --family coap --profile coap-live-dry-run --seed 5683 --count 10 --out target/oracle/coap-live-local-dry-run
```

The bare Python oracle/probe unit gates, Rust tests, fixture suite, and static
release gate remain part of `coap-ci`. A missing optional Scapy/tshark backend
produces a capability-scoped skip; a missing required offline executable or a
failed crafter comparison fails the profile.

## `coap-live-dry-run` plan profile

`coap-live-dry-run` contains only bounded live-candidate plans. The name does
not grant live permission: `--dry-run` remains mandatory while planning. Its
baseline cases are a controlled UDP request/response, an optional unicast
discovery response, one bounded blockwise exchange, one complete reliable
frame, and optional OSCORE/group cases guarded by explicit responder
capabilities. Malformed packets, unrelated service-port payloads, provisional
Group OSCORE, public discovery, and unbounded Observe/block workflows are not
live candidates.

Before any protected live CoAP run, lab, oracle, and probe dry-runs must succeed
or produce an inspected stable skip artifact for every provider currently
registered by the lab runner: `docker`, `hetzner`, `qemu`, and `virtualbox`.
Provider names must come from `tools/lab/run providers`, not a permanently
hard-coded list. For the current registry this produces twelve tool/provider
records:

```sh
for provider in docker hetzner qemu virtualbox; do
  tools/lab/run plan --provider "$provider" --dry-run --profile smoke --seed 1 --role stimulus --role target --json
  tools/oracle/run live --provider "$provider" --dry-run --family coap --profile coap-live-dry-run --seed 5683 --count 10 --out "target/oracle/coap-live-dry-run/$provider"
  tools/probe/run --provider "$provider" --dry-run --profile coap-smoke --seed 5683 --count 12 --out "target/probe/coap-live-dry-run/$provider"
done
```

The QEMU and VirtualBox endpoints request the coarse `lan-raw` appliance
profile. Hetzner requests `wan-raw` only when the selected case needs WAN
placement; provider names and capabilities come from the lab registry. A
controlled CoAP responder is workload readiness recorded by the target-service
plan, not a new protocol-specific provider capability.

Each record must show provider and appliance runtime metadata, stimulus/target
roles, planned documentation-safe or provider-assigned addresses, exact cases,
packet and time bounds, capture point and bound, controlled-responder setup,
artifact roots, confirmation requirements, and teardown commands. A missing
virtualization prerequisite, provider credential, or responder capability
blocks live promotion but must retain the available dry-run plan and stable
skip reason.

## Protected live gate

Live CoAP traffic is optional and may start only when all of these conditions
are true:

1. The relevant `coap-smoke` and `coap-ci` offline evidence has passed.
2. All current provider `coap-live-dry-run` records have been inspected, and the exact
   provider, seed, count, case set, endpoint roles, capture envelope, artifact
   root, and teardown plan selected for live promotion are unchanged.
3. The operator selects an explicit provider from the lab registry. There is
   no implicit provider, local provider, or developer-host fallback.
4. The operator-facing runbook requires
   `LIBCRAFTER_PROBE_LIVE_COAP_CONFIRM=yes`; the live-capable command includes
   `--confirm-live-run`; and the probe runner separately receives its enforced
   protocol gate `LIBCRAFTER_COAP_LIVE_CONFIRM=yes`. Provider selection,
   credentials, raw-socket availability, or any one confirmation alone is not
   sufficient.
5. Session metadata proves a controlled responder is ready for every selected
   case. The responder is disposable test infrastructure, not a public or
   production CoAP endpoint.
6. The plan has explicit finite send, response, wall-clock, capture-duration,
   and capture-size limits. The baseline envelope is at most 10 planned sends,
   one response window per send, 30 seconds of workload time, 60 seconds of
   capture time, and 16 MiB of captured data; any increase requires a newly
   reviewed dry-run artifact and operator authorization.
7. Traffic originates and is captured only on disposable provider-backed
   endpoints. Base multicast, when selected, stays inside an isolated
   provider-owned segment. No raw packet originates from the developer host.
8. Artifact collection and teardown are part of the same runbook. Collection
   is attempted before teardown, and teardown is attempted after success,
   failure, timeout, or partial provisioning.

A fail-closed manual probe invocation may use the reviewed plan profile as
follows. This snippet is documentation only and must never appear in automated
acceptance, CI, or unattended scripts:

```sh
provider=${LIBCRAFTER_PROBE_LIVE_PROVIDER:-}
if [ -n "$provider" ] && [ "${LIBCRAFTER_PROBE_LIVE_COAP_CONFIRM:-}" = yes ]; then
  LIBCRAFTER_COAP_LIVE_CONFIRM=yes tools/probe/run --provider "$provider" --confirm-live-run --profile coap-smoke --seed 5683 --count 7 --out "target/probe/coap-live/$provider"
else
  tools/probe/run --provider qemu --dry-run --profile coap-smoke --seed 5683 --count 7 --out target/probe/coap-live-dry-run/qemu
fi
```

Do not set these environment variables from automation. The runner must still
enforce its own confirmation and provider guards even when all are present.

## Retained step-98 dry-run record

The documentation pass ran the current provider matrix with no live
authorization. All four lab plans, four CoAP oracle plans, and four CoAP probe
plans exited successfully with `dry_run=true`; they created no endpoints. Each
probe plan retained all twelve `coap-smoke` cases. Oracle capability filtering
kept six of ten generated cases wire-eligible on Docker, QEMU, and VirtualBox
and four of ten on Hetzner; the skipped cases record unavailable IPv6 and, on
Hetzner, L2/broadcast/provider-MAC requirements.

Endpoint `doctor --dry-run` records were retained for every registered
provider/exposure pair. Docker (`private`, `lan`, `wan`), Hetzner (`private`,
`wan`), QEMU (`private`, `wan`), and VirtualBox `private` passed their dry-run
checks. VirtualBox `lan` recorded the stable prerequisite skip
`bridge_discovery` because the host VirtualBox driver/bridged-interface check
was unavailable. Hetzner plans record missing `HETZNER_API_TOKEN` or
`HCLOUD_TOKEN` as a live prerequisite while remaining valid dry-runs.

Artifacts are under ignored `target/lab/coap-step98`,
`target/oracle/coap-step98-*`, `target/probe/coap-step98-*`, and
`target/endpoint/coap-step98`. Every live gate remained closed: no provider was
selected through `LIBCRAFTER_PROBE_LIVE_PROVIDER`,
`LIBCRAFTER_PROBE_LIVE_COAP_CONFIRM=yes` and
`LIBCRAFTER_COAP_LIVE_CONFIRM=yes` were absent, and no command included
`--confirm-live-run`. Therefore the result is dry-run evidence plus explicit
live skips, not live CoAP coverage.

## Skip reporting, artifacts, teardown, and redaction

An unavailable live prerequisite is an expected skip, not passing live
coverage. Use stable reasons such as `offline-gate-incomplete`,
`dry-run-matrix-incomplete`, `provider-not-explicit`,
`confirm-live-run-missing`, `coap-confirmation-missing`,
`controlled-responder-unavailable`, `responder-feature-unsupported`,
`capture-envelope-unbounded`, `artifact-root-unavailable`,
`provider-prerequisite-missing`, or `teardown-plan-missing`. The summary records
the profile/case, provider considered, reason, retained dry-run artifact path,
whether any endpoint was created, and teardown status.

Provider-backed artifacts retain enough evidence to debug offline:

- lab session and endpoint manifests, appliance runtime metadata, provider
  workflow/command records, repository bootstrap logs, and cleanup state;
- immutable workload request/response JSON with seed, count, bounds, case IDs,
  expected match rules, and backend capability/skip metadata;
- compiled packet bytes, decoded summaries, `show()` output, hexdumps,
  structured errors, bounded pcaps, controlled-responder logs, and exit status;
  and
- per-endpoint collection status followed by teardown status, including partial
  provisioning and failed workloads.

Live artifacts stay under ignored roots such as `target/lab/coap-*`,
`target/oracle/coap-*`, and `target/probe/coap-*`. Before any artifact is
promoted into tracked fixtures or documentation, remove or replace provider
credentials/account data, public addresses and host identifiers, SSH details,
absolute personal paths, interface names from protected networks, uncontrolled
payloads, sensitive pcap metadata, and organization-specific names.

OSCORE Master Secret, Master Salt, sender/recipient keys, Common IV, sequence
state, plaintext, and authentication diagnostics that distinguish secret
values must never be logged or stored in plans. Group identifiers,
countersignatures, and captures are treated as sensitive unless they were
created from documented synthetic fixture inputs. If safe redaction makes an
artifact ambiguous, regenerate the evidence offline instead of committing the
live artifact.
