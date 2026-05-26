# Probe Validation

Probe validates behavior from kernels and controlled services in a disposable
lab. It is separate from oracle validation: oracle checks writer/parser
agreement against a reference backend, while probe sends libcrafter packets and
expects the peer endpoint or service to answer.

The command surface is:

```sh
tools/probe/run --provider hetzner --dry-run --profile smoke --seed 1 --count 10
```

Dry-runs are CI-safe. They write deterministic plans and reports below
`target/probe/` without creating hosts, sending packets, starting services, or
requiring provider credentials.

## Cases

The smoke profile currently samples these cases:

- `icmp-echo`: send an ICMP echo request and validate the echo reply from the
  peer kernel.
- `tcp-syn-open`: send a raw TCP SYN to a controlled listener and validate the
  SYN/ACK response.
- `tcp-syn-closed`: send a raw TCP SYN to an unbound port and validate the RST
  response.
- `dns-query`: send a DNS query to a controlled UDP DNS responder and validate
  the matching answer.
- `ttl-expired`: send a low-TTL packet and validate ICMP time exceeded from a
  controlled routed hop when the lab advertises that capability.

The default Hetzner two-endpoint lab has no controlled router hop, so
`ttl-expired` is skipped with `requires_controlled_router`. Skips remain in the
report and do not count as failures when the provider lacks the capability.

## Protected Hetzner Runs

Real probe runs use the same two-endpoint Hetzner lab as wire oracle validation.
Run local static checks and dry-runs first:

```sh
cargo test --workspace
tools/probe/run --provider hetzner --dry-run --profile smoke --seed 1 --count 10
tools/wire/wire doctor --provider hetzner --exposure private --dry-run
tools/wire/wire create-endpoint --provider hetzner --exposure private --role probe-stimulus --private-group probe-smoke --private-ip 10.0.25.10 --dry-run --write-manifest
```

Start a protected live run only when disposable resources are intended:

```sh
tools/probe/run --provider hetzner --confirm-live-run --profile smoke --seed 21 --count 25
```

The probe runner uses `tools/wire` to create both endpoints, configure the
private network, start target services, install temporary TCP RST guards on the
stimulus endpoint, run the `stimulus_endpoint` binary from
`tools/probe/adapters`, collect artifacts, and clean up endpoint resources.

## Artifacts

Probe reports include selected cases, generated probe plans, execution counts,
skip counts, provider command metadata, observed responses, and per-case
failure reasons. Local reports are written below `target/probe/`. Provider
artifacts are written below `tools/wire/artifacts/` for local runs or the
configured wire artifact directory in CI.

Do not commit provider state, public host addresses, live host identifiers,
packet captures from non-disposable networks, or credentials.
