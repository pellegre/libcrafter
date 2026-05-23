# Live Lab

The live lab runs packet tests away from the developer machine. The entrypoint is
provider agnostic:

```sh
tools/live-lab/libcrafter-live-lab doctor --provider local-dry-run
tools/live-lab/libcrafter-live-lab doctor --provider hetzner --dry-run
```

Local static tests should run before any live lab command. Live providers are
for tests that need root privileges, raw sockets, packet capture, or oracle
comparison on disposable infrastructure. The oracle is the validation system;
Scapy is selected explicitly as a reference backend with `--backend scapy`.

## Hetzner Setup

The Hetzner provider reads `HETZNER_API_TOKEN` from the process environment. If
the variable is not already set, it also supports the ignored local env file at
`~/.config/libcrafter/live-test.env`:

```sh
mkdir -p ~/.config/libcrafter
chmod 700 ~/.config/libcrafter
printf 'HETZNER_API_TOKEN=replace-with-token\n' > ~/.config/libcrafter/live-test.env
chmod 600 ~/.config/libcrafter/live-test.env
```

Do not place real token values in repo files, shell history snippets, logs, or
examples. The provider prints only whether a token is configured.

Run dry-run checks first:

```sh
tools/live-lab/libcrafter-live-lab doctor --provider hetzner --dry-run
tools/live-lab/libcrafter-live-lab create --provider hetzner --dry-run
```

Oracle offline and pcap validation should pass before creating infrastructure:

```sh
tools/oracle/run offline --backend scapy --profile smoke --seed 1 --count 10
tools/oracle/run pcap --backend scapy --profile smoke --seed 1 --count 10
```

Real creation uses provider defaults that can be overridden. Choose values that
belong to the disposable test environment and do not commit account-specific
settings:

```sh
HETZNER_SERVER_TYPE=replace-with-server-type \
HETZNER_IMAGE=replace-with-image \
HETZNER_LOCATION=replace-with-location \
tools/live-lab/libcrafter-live-lab create --provider hetzner
```

Plan oracle live validation without creating infrastructure:

```sh
tools/oracle/run live --backend scapy --provider hetzner --dry-run --profile smoke --seed 12345 --count 10
```

Run oracle live validation through the provider suite when disposable resources
are intentionally available:

```sh
tools/live-lab/libcrafter-live-lab run --provider hetzner --suite oracle-live
```

Generated provider state is written below `tools/live-lab/.state/hetzner/`.
Artifacts are written below `tools/live-lab/artifacts/hetzner/`. Both locations
are ignored by git. Oracle reports and packet artifacts are written below
`target/oracle/`, with live reports under `target/oracle/live`.

Use the same `--profile`, `--seed`, `--count`, and reported `--index` to
reproduce a single failed oracle packet plan.

## CI Secrets

Use `HETZNER_API_TOKEN` as the CI secret name. CI jobs should run dry-run
commands for pull requests and reserve real host creation for explicit,
protected workflows.

Recommended CI flow:

```sh
cargo test --workspace
tools/oracle/run offline --backend scapy --profile ci --seed 12345 --count 2000
tools/oracle/run pcap --backend scapy --profile smoke --seed 12345 --count 250
tools/oracle/run live --backend scapy --provider hetzner --dry-run --profile smoke --seed 12345 --count 10
tools/live-lab/libcrafter-live-lab doctor --provider hetzner --dry-run
tools/live-lab/libcrafter-live-lab create --provider hetzner --dry-run
```

Pull request CI should run offline and pcap oracle validation only. Real live
runs should be manual, protected, and wrap `create`, `run`, `artifact`, and
`destroy` in cleanup logic so `destroy` still executes after a failed validation
step.

See also `docs/supported-platforms.md` for the alpha support matrix and known
release gaps.

## Cleanup

Destroy disposable hosts as soon as live validation finishes:

```sh
tools/live-lab/libcrafter-live-lab destroy --provider hetzner
```

If a command fails before cleanup, keep the ignored state directory until
`destroy` succeeds. The manifest contains the provider resource id needed for
cleanup. After cleanup, artifacts can be kept locally for debugging and removed
manually when no longer needed.
