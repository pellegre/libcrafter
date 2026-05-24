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
tools/live-lab/libcrafter-live-lab doctor --provider hetzner --dry-run
tools/live-lab/libcrafter-live-lab create --provider hetzner --dry-run
```

Start a protected live run only when disposable resources are intended:

```sh
LIBCRAFTER_LIVE_LAB_CONFIRM=run \
tools/live-lab/libcrafter-live-lab run --provider hetzner --suite probe \
  --confirm-live-run --profile smoke --seed 21 --count 25
```

The provider wrapper bootstraps both endpoints, configures the private network,
starts target services, installs temporary TCP RST guards on the stimulus
endpoint, runs the `probe_endpoint` binary from `tools/probe/adapters`, collects
artifacts, and cleans up probe services. Destroy the lab when the run is
complete:

```sh
LIBCRAFTER_LIVE_LAB_CONFIRM=run tools/live-lab/libcrafter-live-lab artifact --provider hetzner
LIBCRAFTER_LIVE_LAB_CONFIRM=run tools/live-lab/libcrafter-live-lab destroy --provider hetzner
```

## Artifacts

Probe reports include selected cases, generated probe plans, execution counts,
skip counts, provider command metadata, observed responses, and per-case
failure reasons. Local reports are written below `target/probe/`. Provider
artifacts are written below `tools/live-lab/artifacts/hetzner/` for local runs
or the configured live-lab artifact directory in CI.

Do not commit provider state, public host addresses, live host identifiers,
packet captures from non-disposable networks, or credentials.
