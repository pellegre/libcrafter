# Libcrafter Live Lab

`tools/live-lab/libcrafter-live-lab` is the provider-agnostic entrypoint for
live packet validation. It keeps raw packet tests away from the developer
machine by routing live work through disposable labs.

## Command Contract

Every provider implements the same commands:

- `doctor`: check provider tools, credentials, local configuration, and whether
  the provider can create an isolated lab.
- `create`: create or register a fresh disposable lab target.
- `run`: execute the live validation bundle on the lab target.
- `artifact`: print or collect logs, pcaps, summaries, and provider metadata.
- `destroy`: tear down disposable resources. This command must be safe to run
  after partial failures.

The entrypoint dispatches to `tools/live-lab/providers/<provider>`:

```sh
tools/live-lab/libcrafter-live-lab doctor --provider local-dry-run
tools/live-lab/libcrafter-live-lab create --provider local-dry-run
tools/live-lab/libcrafter-live-lab run --provider local-dry-run
tools/live-lab/libcrafter-live-lab artifact --provider local-dry-run
tools/live-lab/libcrafter-live-lab destroy --provider local-dry-run
```

Provider names may contain only letters, numbers, dots, underscores, and
hyphens. Providers receive the command as their first argument and any remaining
arguments after provider selection unchanged.

## Providers

`local-dry-run` creates no infrastructure, sends no packets, and writes only
local state and artifact files. Use it to validate the contract before invoking
a real provider.

`hetzner` is the first real provider. It provisions a disposable Linux host,
runs the selected validation suite there, collects artifacts, and tears the host
down through the same command contract. Additional providers should implement
the same executable interface without changing the Rust packet library.

## Configuration

The entrypoint loads environment values from the process environment and then
from a local env file when it exists:

- `LIBCRAFTER_LIVE_LAB_ENV`: optional path to a local env file. Defaults to
  `~/.config/libcrafter/live-test.env`.
- `LIBCRAFTER_LIVE_LAB_PROVIDER`: optional default provider when `--provider`
  is omitted.
- `LIBCRAFTER_LIVE_LAB_STATE_DIR`: optional state directory. Defaults to
  `tools/live-lab/.state`.
- `LIBCRAFTER_LIVE_LAB_ARTIFACT_DIR`: optional artifact directory. Defaults to
  `tools/live-lab/artifacts`.
- `LIBCRAFTER_PROJECT_ROOT`: optional project root override. Defaults to the
  repository root inferred from this tool.
- `HETZNER_API_TOKEN`: required only by non-dry-run Hetzner commands.

Do not store provider token values, account identifiers, host IDs, public IPs,
or personal defaults in tracked files. Local env files and generated live-lab
state are ignored by git.

## Artifact Layout

By default, providers write artifacts below:

```text
tools/live-lab/artifacts/<provider>/
```

Expected artifact types include:

- command logs such as `create.log`, `run.log`, and `destroy.log`
- generated packet bytes
- pcaps
- decoded summaries
- tool version reports
- provider resource manifests with secret fields redacted

Artifacts should be sufficient to debug a failed live run offline. Secrets must
not be printed or written to artifact files.

## Cleanup

`destroy` must remove provider resources even when `create`, `run`, or
`artifact` failed earlier. It may keep local artifacts for debugging, but it must
remove provider state that could cause later agents to believe live resources
still exist.

The dry-run provider removes only its local state directory and leaves artifacts
under `tools/live-lab/artifacts/local-dry-run/`.
