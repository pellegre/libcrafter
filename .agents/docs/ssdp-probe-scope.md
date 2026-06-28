# SSDP probe scope

This document defines the behavior boundary for SSDP probe work. It is not a
source of SSDP wire facts. Methods, headers, multicast groups, ports, message
grammar, and fixture values remain gated by `.agents/docs/ssdp-source-manifest.md`,
`.agents/docs/ssdp-wire-grammar.md`, `.agents/docs/ssdp-codepoints.md`, and the
public sources those documents cite.

SSDP probe support is generated-tool validation around the `crafter` packet
primitive. Probe may plan and, after protected confirmation, run controlled
provider-backed exchanges. It must not move discovery workflow behavior into
the crate API.

## Default dry-run behavior

Every SSDP probe case must have a dry-run path that needs no provider
credentials, raw-socket privilege, real responder, or local network reachability.
Dry-run output must include the selected case, endpoint roles, packet intent,
documentation-safe addresses, expected artifacts, skip reasons, and whether a
case is planned-only or live-capable.

Dry-run cases in scope:

| Case family | Purpose | Required dry-run evidence |
| --- | --- | --- |
| IPv4 search plan | Plan a source-backed SSDP search stimulus over the SSDP IPv4 multicast destination. | `Packet` stack summary, `show()` output, UDP/SSDP payload bytes or fixture reference, stimulus and target roles, and a no-send marker. |
| IPv6 search plan | Plan a source-backed SSDP search stimulus over admitted IPv6 SSDP multicast scope. | IPv6 stack summary, hop-limit intent, source-backed `HOST` form, role layout, and provider capability requirements. |
| Notification plan | Plan source-backed SSDP notification messages as packet construction and capture expectations. | Serialized SSDP bytes, decoded summary, advertised target fields, and an explicit note that no advertisement scheduler or cache is involved. |
| Controlled response plan | Plan a deterministic target response to a search stimulus. | Response fixture bytes, decoded headers in wire order, body length, and the target-service setup that would emit the response. |
| Raw-fallback plan | Exercise unrelated UDP payloads on SSDP-related ports. | Proof that the payload remains `Raw` unless the conservative SSDP shape gate accepts it. |
| Malformed observation plan | Carry malformed SSDP-like payload fixtures through probe reporting without treating them as valid exchanges. | Structured parse-error expectation and a no-live marker unless a later source-backed live case explicitly needs it. |

## Live-capable behavior

Live-capable means the case may be run only by the probe/lab provider workflow
after the dry-run plan, Rust stimulus adapter, target-service assets, address
rewrite, capability checks, artifact collection, and protected confirmation are
all present. A live-capable label is not permission to send from the developer
host.

Live-capable cases in scope:

| Case | Roles | Live behavior |
| --- | --- | --- |
| `ssdp-ipv4-search-exchange` | `stimulus`, `target` | The stimulus endpoint sends one source-backed SSDP search datagram to the controlled lab segment. The target endpoint captures it and emits a deterministic SSDP response using documentation-safe substituted values. |
| `ssdp-ipv6-search-exchange` | `stimulus`, `target` | The stimulus endpoint sends one source-backed IPv6 SSDP search datagram when the provider reports IPv6 multicast and capture capability. The target endpoint captures and responds with deterministic documentation-safe values. |
| `ssdp-notify-capture` | `target`, `stimulus` | The target endpoint emits a bounded source-backed SSDP notification. The stimulus endpoint captures and decodes it for summary, show, and pcap artifacts. |

Live runs must fail closed or remain dry-run when provider capability,
controlled target setup, multicast reachability, capture support, protected
confirmation, or teardown cannot be proven. Live artifacts stay under ignored
output paths until redacted or regenerated from documentation-safe inputs.

## Probe plan contract

SSDP probe plans must keep their cross-language JSON fields stable once a Rust
adapter consumes them. New fields should be optional, and case names should stay
stable after they are added to snapshots. Plans should record:

- `case_name`, `profile`, `seed`, and sequence metadata;
- `planned_only` or `live_capable`;
- `stimulus` and `target` role requirements;
- source and destination address family, transport, and SSDP message kind;
- serialized packet bytes or a fixture identifier for deterministic cases;
- expected decode outcome, including `Raw` fallback or structured error; and
- provider capability requirements and ordered failure reasons.

## Non-goals

- No SSDP scanner, service inventory, discovery cache, retry scheduler,
  advertisement daemon, UPnP control point, or device monitor.
- No UPnP XML description fetch, SOAP control, eventing, Device Protection, or
  generic HTTP client behavior.
- No uncontrolled multicast traffic, local developer-host raw sends, or live
  traffic without disposable provider-backed endpoints and protected
  confirmation.
- No target discovery across real networks, public devices, or host identifiers
  outside the controlled lab roles.
- No multicast membership manager, route manager, interface-selection policy, or
  response-timing engine beyond what a bounded provider case needs to execute.
- No promotion of live captures, provider addresses, credentials, hostnames,
  interface identifiers, serial numbers, UUIDs, `LOCATION` URLs, or `SERVER`
  strings into tracked fixtures or docs without redaction or offline
  regeneration.
- No rejection of unknown but structurally valid SSDP methods, statuses,
  headers, extension values, duplicate fields, or body bytes solely because the
  probe case does not understand them.
