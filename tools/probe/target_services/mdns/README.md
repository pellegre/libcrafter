# mDNS Target Service

The mDNS probe target service is lab-only. Live runs generate a disposable
Python UDP/5353 responder on the target endpoint from the dry-run probe plan.

The generated responder emits Bonjour-style PTR, SRV, TXT, A, and AAAA records,
handles QU unicast replies, records known-answer suppression decisions, emits
announcement and goodbye packets, and writes deterministic stdout/stderr logs
under `live-artifacts/probe/target-services/`.

Do not run this service on a developer machine or production network. It is
intended for disposable provider-backed probe targets only.
