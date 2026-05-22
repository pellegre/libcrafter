# Live Lab

The live lab runs packet tests away from the developer machine. The entrypoint is
provider agnostic:

```sh
tools/live-lab/libcrafter-live-lab doctor --provider local-dry-run
tools/live-lab/libcrafter-live-lab doctor --provider hetzner --dry-run
```

Local static tests should run before any live lab command. Live providers are
for tests that need root privileges, raw sockets, packet capture, Scapy
comparison, or legacy libcrafter validation on disposable infrastructure.

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

Real creation uses generic provider defaults that can be overridden:

```sh
HETZNER_SERVER_TYPE=cx22 \
HETZNER_IMAGE=ubuntu-24.04 \
HETZNER_LOCATION=fsn1 \
tools/live-lab/libcrafter-live-lab create --provider hetzner
```

Generated provider state is written below `tools/live-lab/.state/hetzner/`.
Artifacts are written below `tools/live-lab/artifacts/hetzner/`. Both locations
are ignored by git.

## CI Secrets

Use `HETZNER_API_TOKEN` as the CI secret name. CI jobs should run dry-run
commands for pull requests and reserve real host creation for explicit,
protected workflows.

Recommended CI flow:

```sh
cargo test --workspace
tools/live-lab/libcrafter-live-lab doctor --provider hetzner --dry-run
tools/live-lab/libcrafter-live-lab create --provider hetzner --dry-run
```

Real live runs should wrap `create`, `run`, `artifact`, and `destroy` in cleanup
logic so `destroy` still executes after a failed validation step.

## Cleanup

Destroy disposable hosts as soon as live validation finishes:

```sh
tools/live-lab/libcrafter-live-lab destroy --provider hetzner
```

If a command fails before cleanup, keep the ignored state directory until
`destroy` succeeds. The manifest contains the provider resource id needed for
cleanup. After cleanup, artifacts can be kept locally for debugging and removed
manually when no longer needed.
