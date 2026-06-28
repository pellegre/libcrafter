# SSDP Probe Controlled Responder

This directory documents the probe-owned target-service assets for SSDP live
behavior cases. The target service is a controlled UDP responder planned by the
SSDP probe plugin as `ssdp-controlled-responder`; it is for disposable
provider-backed lab endpoints only, not for the developer host.

The current SSDP probe cases remain dry-run/planned-first. Their plans describe
the deterministic responder behavior and artifact paths, while live execution
is still protected by later address-rewrite, capability, and confirmation steps.
This directory intentionally does not add a runnable responder script in this
step.

## Planned service contract

- Service kind: `ssdp-controlled-responder`
- Runtime label: `probe-ssdp-reference`
- Transport: UDP
- Port: `1900`
- Live-capable behaviors:
  - `search_response` for IPv4 `M-SEARCH` stimuli
  - `search_response_ipv6` for IPv6 `M-SEARCH` stimuli
  - `notify_emit` for bounded NOTIFY capture validation
- Offline-only behaviors:
  - `offline_raw_fallback`
  - `offline_malformed_observation`

The responder emits only deterministic SSDP payloads already recorded in probe
plans. Search responses use documentation-safe `LOCATION` URLs under
`192.0.2.0/24`, documentation IPv4 pairs under `198.51.100.0/24`, and
documentation IPv6 addresses under `2001:db8::/32`. Multicast destinations are
the source-backed SSDP groups used by the probe plan, including
`239.255.255.250:1900` and `[ff02::c]:1900`.

## Safety policy

Dry-runs must not bind UDP sockets, join multicast groups, send packets, or
start processes. Live use requires the probe/lab provider workflow, disposable
stimulus and target roles, provider-declared multicast and controlled-service
capabilities, artifact collection, and protected confirmation.

Do not commit endpoint-specific hostnames, public IPs, provider IDs,
credentials, live interface names, UUIDs observed from real devices, or packet
captures from lab runs.
