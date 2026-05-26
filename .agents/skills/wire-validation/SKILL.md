---
name: wire-validation
description: Run libcrafter wire-level packet validation through disposable endpoints with local checks, provider dry-runs, artifacts, secret handling, and endpoint teardown. Use when a task needs real packet send, receive, capture, injection, probe, or provider-hosted network validation.
---

# Wire Validation

Use this skill when a task requires wire-level packet generation, raw sockets,
sniffing, packet injection, reference backend checks, legacy libcrafter wire
checks, probe validation, or provider-hosted network validation.

Wire work that can send, receive, or capture real packets must not run on the
developer machine. Run local static checks first, then use disposable wire
endpoints for provider-backed validation.

## Required Order

1. Run local static checks before any provider action:
   - `cargo test --workspace`
   - `.agents/scripts/check-crafter-release --static` for release-like changes
   - any relevant fixture, golden-byte, pcap, decode, or example compile tests
2. Run provider dry-runs before creating endpoints:
   - `tools/wire/run doctor --provider hetzner --exposure wan --dry-run`
   - `tools/wire/run doctor --provider hetzner --exposure private --dry-run`
   - `tools/oracle/run live --provider hetzner --dry-run --profile smoke --seed 1 --count 10`
   - `tools/probe/run --provider hetzner --dry-run --profile smoke --seed 1 --count 10`
3. Create only disposable wire endpoints, and only with an explicit protected
   wire-run confirmation such as `--confirm-live-run`.
4. Run the requested wire packet exchange, reference backend, Rust, probe, and
   legacy libcrafter validation through `tools/oracle`, `tools/probe`, or
   `tools/wire`.
5. Collect logs, pcaps, decoded summaries, command output, reports, and provider
   metadata as artifacts.
6. Destroy disposable wire endpoints after every wire run, including failed runs.

## Secrets

Never write, print, commit, or log secret values. Redact provider tokens from
command output before including it in reports.

For the Hetzner wire provider, use `HETZNER_API_TOKEN` or `HCLOUD_TOKEN` from
the process environment. Do not put tokens, account identifiers, local personal
paths, host IDs, public IP addresses from a personal account, or
provider-specific defaults in tracked repo files.

If credentials are missing, skip provider-backed wire tests with a clear
message and keep running local static and dry-run checks where possible.

## Wire Contract

Wire providers should expose the same high-level workflow:

- `doctor`: verify CLI tools, credentials, exposure, regions, images, and
  permissions.
- `create-endpoint --dry-run`: show what would be created without changing
  provider state.
- `create-endpoint`: provision a fresh disposable wire endpoint.
- `exec`, `upload`, and `download`: operate on one endpoint for debugging or
  runner orchestration.
- `collect-artifacts`: collect pcaps, logs, summaries, and result files.
- `destroy-endpoint`: tear down disposable endpoint resources.

Hetzner is the current provider-backed endpoint implementation, but the
workflow must stay provider-agnostic so additional providers can be added
without changing test semantics.

## Wire Test Rules

Prefer loopback, network namespaces, veth pairs, private networks, or explicit
test destinations inside disposable endpoints. Use root only inside the
endpoint. Avoid open-ended sniffers and sends; every wire command must have a
timeout.

Reference validation should compare Rust packet bytes and decoded summaries
against the configured reference backend where exact equality is meaningful.
Use legacy libcrafter checks when they help validate compatibility with
existing examples.

Always capture enough artifacts to debug a failed wire run offline. The minimum
artifact set is command logs, generated packet bytes, pcaps, decoded summaries,
tool versions, runner reports, and provider resource manifests with secret
fields redacted.

## Failure Handling

On any failure, collect artifacts first when possible, then destroy disposable
wire endpoints. If teardown fails, report the provider, resource type, redacted
resource identifier, and the exact `tools/wire/run destroy-endpoint` command to
retry. Do not start a new wire run while a previous disposable endpoint may
still exist.
