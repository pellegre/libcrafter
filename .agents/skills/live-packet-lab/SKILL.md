---
name: live-packet-lab
description: Run libcrafter live packet tests only inside disposable provider labs with dry runs, artifacts, and teardown.
---

# Live Packet Lab

Use this skill when a task requires live packet generation, raw sockets,
sniffing, packet injection, reference backend checks, legacy libcrafter live
checks, or provider-hosted network validation.

Live raw packet work must not run on the developer machine. Run local static
tests first, then use an isolated disposable lab for live validation.

## Required Order

1. Run local static checks before any provider action:
   - `cargo test --workspace`
   - any relevant fixture, golden-byte, pcap, decode, or example compile tests
2. Load provider configuration only from:
   - already-exported environment variables
   - `~/.config/libcrafter/live-test.env`
3. Run the provider doctor or dry-run command before creating hosts.
4. Create only disposable live-test resources.
5. Run the requested live packet, reference backend, Rust, and legacy
   libcrafter validation.
6. Collect logs, pcaps, decoded summaries, command output, and provider metadata
   as artifacts.
7. Destroy disposable resources after every live run, including failed runs.

## Secrets

Never write, print, commit, or log secret values. Redact provider tokens from
command output before including it in reports.

For the Hetzner provider, use `HETZNER_API_TOKEN`. The token may be provided in
the process environment or in `~/.config/libcrafter/live-test.env`. Do not put
the token, account identifiers, local personal paths, host IDs, IP addresses
from a personal account, or provider-specific defaults in tracked repo files.

If credentials are missing, skip live tests with a clear message and keep
running local static tests where possible.

## Provider Contract

Live lab providers should expose the same high-level workflow:

- `doctor`: verify CLI tools, credentials, regions, images, and permissions.
- `dry-run`: show what would be created without changing provider state.
- `create`: provision a fresh disposable host or isolated lab.
- `run`: execute the test bundle on the disposable target.
- `artifact`: collect pcaps, logs, summaries, and result files.
- `destroy`: tear down all disposable resources.

Hetzner is the first provider, but the workflow must stay provider-agnostic so
additional providers can be added without changing test semantics.

## Live Test Rules

Prefer loopback, network namespaces, veth pairs, private networks, or explicit
test destinations inside the disposable host. Use root only inside the lab.
Avoid open-ended sniffers and sends; every live command must have a timeout.

Reference validation should compare Rust packet bytes and decoded summaries
against the configured reference backend where exact equality is meaningful.
Use legacy libcrafter checks when they help validate compatibility with
existing examples.

Always capture enough artifacts to debug a failed live run offline. The minimum
artifact set is command logs, generated packet bytes, pcaps, decoded summaries,
tool versions, and the provider resource manifest with secret fields redacted.

## Failure Handling

On any failure, collect artifacts first when possible, then destroy disposable
resources. If teardown fails, report the provider, resource type, redacted
resource identifier, and the exact cleanup command to retry. Do not start a new
live run while a previous disposable resource may still exist.
