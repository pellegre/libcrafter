# NTP probe scope

This document defines the behavior boundary for generated-tool NTP probe work.
It is not a source of NTP wire facts. Header fields, modes, strata, reference
identifiers, extension fields, NTS packet extensions, legacy MAC bytes, and
malformed-shape rules remain gated by `.agents/docs/ntp-rfc-manifest.md`,
`.agents/docs/ntp-wire-grammar.md`, `.agents/docs/ntp-codepoints.md`, and the
public sources those documents cite.

NTP probe support is controlled peer exchange validation around the `crafter`
packet primitive. It may plan and, after protected confirmation, run bounded
provider-backed exchanges between lab roles. It is not a time-sync client,
daemon, pool selector, clock discipline engine, scanner, NTS key-establishment
workflow, or association state machine.

## Default dry-run behavior

Every NTP probe case must have a dry-run path before any live behavior is
eligible. Dry-runs must require no provider credentials, raw-socket privilege,
real NTP peer, public server, or local network reachability. Output must include
the selected case, endpoint roles, packet intent, documentation-safe addresses,
serialized packet bytes or fixture references, expected decode outcome, artifact
locations, provider capability requirements, skip reasons, and a no-send marker.

Planned dry-run cases in scope:

| Case family | Purpose | Required dry-run evidence |
| --- | --- | --- |
| Client request/server response | Plan a bounded client-mode request and controlled server-mode response over UDP/123. | Request and response `Packet` summaries, `show()` output, timestamp/reference-field intent, UDP/NTP bytes or fixture references, stimulus and target roles, and a no-send marker. |
| Kiss-o'-Death response | Plan a controlled server response with a Kiss-o'-Death stratum/reference identifier. | Encoded response bytes, decoded reference identifier label, expected client-observation report, and proof that no retry or clock behavior is inferred by the probe. |
| Extension echo or preservation | Plan packets with source-backed NTP extension fields that a controlled peer may echo, preserve, or report without interpretation. | Extension field type, length, raw body bytes, compile/decode round trip, expected peer observation, and unknown-extension preservation expectations. |
| Malformed request handling | Plan short, malformed, or conservative-shape-boundary requests as observation-only cases. | Structured parse-error or raw-fallback expectation, target behavior expectation, and a no-live marker unless a later provider case explicitly marks the malformed exchange live-capable. |
| NTS packet-extension planning | Plan raw-preserving NTS packet extension fields, including unique identifier, cookie, and authenticator-shaped bodies. | Extension ordering, raw body preservation, decode labels, and an explicit note that no NTS-KE, AEAD, cookie construction, replay cache, or cryptographic verification is performed. |

## Live-capable behavior

Live-capable NTP probe behavior may run only after provider-backed dry-run
planning has succeeded and the probe/lab workflow has Rust stimulus support,
controlled peer assets, address rewrite, capture configuration, capability
checks, artifact collection, teardown, and protected confirmation in place. A
live-capable label is not permission to send from the developer host.

Live-capable cases in scope:

| Case | Roles | Live behavior |
| --- | --- | --- |
| `ntp-client-server-exchange` | `stimulus`, `target` | The stimulus endpoint sends one source-backed client-mode request to a controlled target endpoint. The target captures it and emits one deterministic server-mode response using documentation-safe substituted values. |
| `ntp-kod-response` | `stimulus`, `target` | The stimulus endpoint sends one bounded request. The target emits a deterministic Kiss-o'-Death response so the probe can validate decode, summary, show, and artifact reporting only. |
| `ntp-extension-preservation` | `stimulus`, `target` | The endpoints exchange a packet with source-backed extension fields and verify raw-preserving decode or echo behavior without interpreting unknown extension contents. |
| `ntp-nts-extension-plan` | `stimulus`, `target` | The endpoints validate packet-extension serialization, decode, and artifact reporting for NTS-shaped fields without NTS key exchange or cryptographic processing. |

Live runs must fail closed or remain dry-run when provider capability,
controlled peer setup, UDP/123 reachability inside the lab, packet capture,
protected confirmation, artifact isolation, or teardown cannot be proven. Live
artifacts stay under ignored output paths until redacted or regenerated from
documentation-safe inputs.

## Probe plan contract

NTP probe plans must keep their cross-language JSON fields stable once a Rust
adapter consumes them. New fields should be optional, and case names should stay
stable after they are added to snapshots. Plans should record:

- `case_name`, `profile`, `seed`, and sequence metadata;
- `planned_only` or `live_capable`;
- `stimulus` and `target` role requirements;
- source and destination address family, UDP/123 transport, and NTP mode;
- serialized packet bytes or a fixture identifier for deterministic cases;
- expected decode outcome, including `Raw` fallback or structured error;
- extension and NTS packet-extension preservation expectations; and
- provider capability requirements and ordered failure reasons.

## Non-goals

- No NTP client, time-sync service, daemon, server selection, pool behavior,
  clock discipline, association state machine, retry scheduler, or scanner.
- No NTS key exchange, AEAD encryption or decryption, cookie construction,
  replay cache, Autokey validation, or trust-chain verification.
- No local developer-host raw sends, public NTP server probes, uncontrolled
  amplification behavior, or live traffic without disposable provider-backed
  endpoints and protected confirmation.
- No promotion of live captures, provider addresses, credentials, hostnames,
  interface identifiers, public peers, or sensitive timestamps into tracked
  fixtures or docs without redaction or offline regeneration.
- No rejection of unknown but structurally valid versions, modes, reference
  identifiers, extension types, NTS packet-extension bodies, legacy MAC bytes,
  or payload tails solely because the probe case does not interpret them.
