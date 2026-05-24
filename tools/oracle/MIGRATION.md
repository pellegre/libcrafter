# Oracle Final State

`tools/oracle/run` is the supported entrypoint for packet behavior validation.
It is the place to run offline vector checks, pcap checks, live provider checks,
backend metadata inspection, spec validation, and self checks.

## Stable Model

Executable specs drive generated stacks, profiles, cases, feature sampling,
roots, pcap link types, and backend support metadata. The generator samples from
those specs and writes reports that include enough coordinates to reproduce a
failure with the same mode, backend, profile, seed, count, direction, and packet
index.

Packet behavior coverage should be added through specs and backend adapters, not
by adding one-off Scapy code to tests or scripts. Direct Scapy imports belong
only in `tools/oracle/engine/backends/scapy/`.

## Backend Capabilities

Backends register their capabilities before a mode runs:

- Scapy is the full reference backend. It supports encode, decode, pcap read,
  pcap write, and live endpoint execution.
- Wireshark/tshark is parser-only. It supports decode and pcap read paths when
  `tshark` is available, and it is not used to encode packets, write pcaps, or
  act as a live endpoint.
- libcrafter is represented in executable spec support metadata so specs can
  declare the Rust side of a comparison independently from reference backends.

Unsupported mode/backend combinations produce oracle support reports with the
missing backend capability instead of falling through to another validation
path.

## CI And Live Providers

Pull request CI runs deterministic offline and pcap validation:

```sh
tools/oracle/run offline --backend scapy --profile ci --seed 12345 --count 2000
tools/oracle/run pcap --backend scapy --profile smoke --seed 12345 --count 250
```

Live validation is still invoked through `tools/oracle/run live`. Normal CI runs
provider planning in dry-run mode only:

```sh
tools/oracle/run live --backend scapy --provider local-dry-run --profile smoke --seed 1 --count 10
tools/oracle/run live --backend scapy --provider hetzner --dry-run --profile smoke --seed 12345 --count 10
```

Real Hetzner exchanges are limited to the protected manual live-lab workflow
with explicit confirmation and credentials. Provider code must keep lifecycle,
bootstrap, artifact collection, and teardown under `tools/live-lab/` and
`tools/oracle/engine/providers/`.

## Agent Rule

Agents should extend oracle behavior by changing the relevant spec files first,
then implementing or adjusting backend adapters. Do not create new packet
behavior coverage by embedding ad hoc Scapy snippets outside the Scapy backend.
