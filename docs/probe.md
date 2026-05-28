# Probe Validation

Probe validates behavior from kernels and controlled services on disposable
lab sessions. It is separate from oracle validation: oracle checks
writer/parser agreement against a reference backend, while probe sends
libcrafter packets and expects the peer endpoint or service to answer.

The command surface is:

```sh
tools/probe/run --provider hetzner --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider qemu --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider virtualbox --dry-run --profile smoke --seed 1 --count 10
```

Dry-runs are CI-safe. They write deterministic plans and reports below
`target/probe/` without creating hosts, sending packets, starting services, or
requiring provider credentials. Provider-backed dry-runs use `tools/lab` to
plan the `stimulus` and `target` roles and rewrite probe plans with lab
endpoint addresses. Dry-run remains the default safety boundary; live provider
runs require `--confirm-live-run`.

## Bootstrap Boundary

Lab provider adapters own substrate lifecycle only. They plan, create, connect,
describe, and tear down disposable endpoints, but they do not install probe
packages, build `stimulus_endpoint`, start target services, or choose
role-specific workload commands.

`tools/lab` owns repository archive transfer, remote unpack, bootstrap context,
artifacts, and cleanup records. Probe owns the workload bootstrap for the
`stimulus` and `target` roles after the repository is unpacked. The
`stimulus` role builds the probe adapter binary and prepares packet stimulus;
the `target` role prepares the controlled service runtime and target-side
state.

This refactor does not introduce Docker. If Docker or another runner is added
later, it belongs behind probe workload bootstrap for `stimulus` or `target`,
not in the provider abstraction.

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
  controlled routed hop when the provider advertises that capability.

The current lab providers do not advertise a controlled router hop, so
`ttl-expired` is skipped with `requires_controlled_router` for Hetzner, QEMU,
and VirtualBox. Skips remain in the report and do not count as failures when
the provider lacks the capability.

## Protected Lab Runs

Real probe runs use a two-endpoint lab session. Run local static checks and
dry-runs first:

```sh
cargo test --workspace
tools/probe/run --provider hetzner --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider qemu --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider virtualbox --dry-run --profile smoke --seed 1 --count 10
tools/lab/run plan --provider hetzner --dry-run --profile smoke --seed 1 --role stimulus --role target --json
tools/lab/run plan --provider qemu --dry-run --profile smoke --seed 1 --role stimulus --role target --json
tools/lab/run plan --provider virtualbox --dry-run --profile smoke --seed 1 --role stimulus --role target --json
```

Start a protected live run only when disposable resources are intended:

```sh
tools/probe/run --provider hetzner --confirm-live-run --profile smoke --seed 21 --count 25
tools/probe/run --provider qemu --confirm-live-run --profile smoke --seed 21 --count 25
tools/probe/run --provider virtualbox --confirm-live-run --profile smoke --seed 21 --count 25
```

The probe runner uses `tools/lab` to create both endpoints, transfer and unpack
the repository, run probe-owned bootstrap hooks, collect artifacts, and clean
up endpoint resources. Probe keeps ownership of target service setup, temporary
TCP RST guards on the stimulus endpoint, the `stimulus_endpoint` binary from
`tools/probe/adapters`, response parsing, and result assembly.

## Artifacts

Probe reports include selected cases, generated probe plans, execution counts,
skip counts, lab session metadata, provider command metadata, observed
responses, and per-case failure reasons. Local reports are written below
`target/probe/`. Provider artifacts are collected through lab/wire into ignored
artifact directories or the configured runner output directory.

Do not commit provider state, public host addresses, live host identifiers,
packet captures from non-disposable networks, or credentials.
