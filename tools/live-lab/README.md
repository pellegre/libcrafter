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
tools/live-lab/libcrafter-live-lab run --provider local-dry-run --suite oracle-live
tools/live-lab/libcrafter-live-lab artifact --provider local-dry-run
tools/live-lab/libcrafter-live-lab destroy --provider local-dry-run
```

Provider names may contain only letters, numbers, dots, underscores, and
hyphens. Providers receive the command as their first argument and any remaining
arguments after provider selection unchanged.

Oracle validation itself is driven by `tools/oracle/run`. Use the live-lab
entrypoint for provider lifecycle, bootstrap, and artifact collection; use the
oracle runner for deterministic offline, pcap, and live reports:

```sh
tools/oracle/run offline --backend scapy --profile smoke --seed 1 --count 10
tools/oracle/run pcap --backend scapy --profile smoke --seed 1 --count 10
tools/oracle/run live --backend scapy --provider local-dry-run --profile smoke --seed 1 --count 10
```

Scapy is a backend selected by the oracle runner, not a general live-lab coding
pattern. Provider scripts may install or bootstrap Scapy only as backend
infrastructure.

## Providers

`local-dry-run` creates no infrastructure, sends no packets, and writes only
local state and artifact files. Use it to validate the two-endpoint oracle live
contract before invoking a real provider. The `oracle-live` suite runs oracle
live orchestration in dry-run mode and writes endpoint protocol artifacts.

`hetzner` is the first real provider. It provisions disposable Linux endpoints,
bootstraps the `libcrafter` and `reference_backend` roles, collects endpoint
artifacts, and tears the lab down through the same command contract. Additional
providers should implement the same executable interface without changing the
Rust packet library.

Use dry-run checks before invoking Hetzner, then run oracle live validation
through the oracle entrypoint:

```sh
tools/live-lab/libcrafter-live-lab doctor --provider hetzner --dry-run
tools/live-lab/libcrafter-live-lab create --provider hetzner --dry-run
tools/oracle/run live --backend scapy --provider hetzner --dry-run --profile smoke --seed 1 --count 10
tools/oracle/run live --backend scapy --provider hetzner --profile smoke --seed 1 --count 10
```

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

Oracle commands write reports and generated packet artifacts below:

```text
target/oracle/
target/oracle/offline/
target/oracle/pcap/
target/oracle/live/
```

Live reports also include per-endpoint request, response, log, and capture
artifacts for the `libcrafter` and `reference_backend` roles.

Expected artifact types include:

- command logs such as `create.log`, `run.log`, and `destroy.log`
- generated packet bytes
- pcaps
- decoded summaries
- tool version reports
- provider resource manifests with secret fields redacted

Artifacts should be sufficient to debug a failed live run offline. Secrets must
not be printed or written to artifact files.

Oracle reports include the profile, seed, count, direction, and packet index.
Use those coordinates with the same backend, for example `--backend scapy
--seed 1 --index 3`, to reproduce one packet plan.

## Cleanup

`destroy` must remove provider resources even when `create`, `run`, or
`artifact` failed earlier. It may keep local artifacts for debugging, but it must
remove provider state that could cause later agents to believe live resources
still exist.

The dry-run provider removes only its local state directory and leaves artifacts
under `tools/live-lab/artifacts/local-dry-run/`.
