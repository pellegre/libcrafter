---
name: endpoint-provider
description: Provision and use one disposable remote endpoint provider target for libcrafter packet work. Use for single-endpoint raw sends, captures, debugging, artifact collection, or endpoint teardown; use lab-session for coordinated multi-endpoint oracle/probe workflows.
---

# Endpoint Provider

Use this skill when a task requires one disposable remote endpoint for
wire-level packet generation, raw sockets, sniffing, packet injection,
traceroute-style workflows, legacy libcrafter packet checks, or manual
endpoint debugging.

Use `lab-session` instead when the work needs coordinated provider-backed
oracle/probe execution, multiple endpoints, repository push/bootstrap, shared
session metadata, artifact collection across endpoints, or provider-neutral
teardown. Use `lab-provider` for adding or maintaining lab provider adapters.

Work that can send, receive, or capture real packets must not run on the
developer machine. Run local static checks first, then use disposable endpoint
provider targets for provider-backed execution.

## Required Order

1. Run local static checks before any provider action:
   - `cargo test --workspace`
   - `.agents/scripts/check-crafter-release --static` for release-like changes
   - any relevant fixture, golden-byte, pcap, decode, or example compile tests
2. Run provider dry-runs before creating endpoints:
   - `tools/endpoint/run doctor --provider hetzner --exposure wan --dry-run`
   - `tools/endpoint/run doctor --provider hetzner --exposure private --dry-run`
   - use `lab-session` dry-runs for multi-endpoint oracle/probe workflows
   - `tools/oracle/run live --provider hetzner --dry-run --profile smoke --seed 1 --count 10`
   - `tools/probe/run --provider hetzner --dry-run --profile smoke --seed 1 --count 10`
3. Create only disposable endpoint provider targets, and only with an explicit
   protected live-run confirmation such as `--confirm-live-run`.
4. Run the requested packet exchange, reference backend, Rust, probe,
   traceroute-style workflow, or legacy libcrafter check through `tools/oracle`,
   `tools/probe`, `tools/endpoint`, or a bounded command on the endpoint.
5. Collect logs, pcaps, decoded summaries, command output, reports, and provider
   metadata as artifacts.
6. Destroy disposable endpoint provider targets after every live run, including
   failed runs.

## Secrets

Never write, print, commit, or log secret values. Redact provider tokens from
command output before including it in reports.

For the Hetzner endpoint provider, use `HETZNER_API_TOKEN` or `HCLOUD_TOKEN`
from the process environment. Do not put tokens, account identifiers, local
personal paths, host IDs, public IP addresses from a personal account, or
provider-specific defaults in tracked repo files.

If credentials are missing, skip provider-backed live tests with a clear
message and keep running local static and dry-run checks where possible.

## Endpoint Provider Contract

Endpoint providers should expose the same high-level workflow:

- `doctor`: verify CLI tools, credentials, exposure, regions, images, and
  permissions.
- `create --dry-run`: show what would be created without changing
  provider state.
- `create`: provision a fresh disposable endpoint provider target.
- `exec`, `upload`, and `download`: operate on one endpoint for debugging or
  runner orchestration.
- `collect-artifacts`: collect pcaps, logs, summaries, and result files.
- `destroy`: tear down disposable endpoint resources.

Endpoint provider targets are the lower-level single-endpoint primitive.
Multi-endpoint provider-backed validation should use lab-session so
provider-specific endpoint mechanics do not leak into oracle or probe.

## Endpoint Provider Rules

Prefer loopback, network namespaces, veth pairs, private networks, or explicit
test destinations inside disposable endpoints. Use root only inside the
endpoint. Avoid open-ended sniffers and sends; every live packet command must
have a timeout.

Reference validation should compare Rust packet bytes and decoded summaries
against the configured reference backend where exact equality is meaningful.
Use legacy libcrafter checks when they help validate compatibility with
existing examples.

Always capture enough artifacts to debug a failed live run offline. The minimum
artifact set is command logs, generated packet bytes, pcaps, decoded summaries,
tool versions, runner reports, and provider resource manifests with secret
fields redacted.

## Failure Handling

On any failure, collect artifacts first when possible, then destroy disposable
endpoint provider targets. If teardown fails, report the provider, resource
type, redacted resource identifier, and the exact `tools/endpoint/run destroy`
command to retry. Do not start a new live run while a previous disposable
endpoint may still exist.
