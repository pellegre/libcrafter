# Wire Provider Lab

Disposable provider lifecycle is owned by `tools/wire`. Oracle and probe own the
packet workload, reports, and reproduction coordinates. Use wire for endpoint
creation, command execution, artifact collection, SSH details, and cleanup.

Local static tests should run before any provider command. Live providers are
for tests that need root privileges, raw sockets, packet capture, reference
comparison, or kernel/service replies on disposable infrastructure. See
[validation.md](validation.md) for oracle modes and CI expectations, and
[probe.md](probe.md) for behavioral probe cases.

## Hetzner Setup

The Hetzner wire provider reads `HETZNER_API_TOKEN` or `HCLOUD_TOKEN` from the
process environment. Do not place real token values in repo files, shell history
snippets, logs, or examples. The provider prints only whether credentials are
configured.

Run dry-run checks first:

```sh
tools/wire/wire doctor --provider hetzner --exposure wan --dry-run
tools/wire/wire doctor --provider hetzner --exposure private --dry-run
tools/wire/wire create-endpoint --provider hetzner --exposure wan --dry-run --write-manifest
```

Oracle offline and pcap validation plus probe dry-runs should pass before
creating infrastructure. The validation commands are documented in
[validation.md](validation.md) and [probe.md](probe.md).

Plan provider-backed oracle and probe live validation without creating
infrastructure:

```sh
tools/oracle/run live --provider hetzner --dry-run --profile smoke --seed 12345 --count 10
tools/probe/run --provider hetzner --dry-run --profile smoke --seed 1 --count 10
```

Start protected live validation only when disposable resources are intended:

```sh
tools/oracle/run live --provider hetzner --confirm-live-run --profile smoke --seed 12345 --count 10
tools/probe/run --provider hetzner --confirm-live-run --profile smoke --seed 21 --count 25
```

Generated endpoint state is written below `tools/wire/.state/`. Artifacts are
written below `tools/wire/artifacts/`. Both locations are ignored by git.
Oracle reports and packet artifacts are written below `target/oracle/`; probe
reports are written below `target/probe/`.

Use the same `--profile`, `--seed`, `--count`, and reported `--index` to
reproduce a single failed oracle packet plan. For probe, preserve the reported
sequence number, case name, seed, and profile.

## Direct Endpoint Operations

The high-level oracle and probe runners create and destroy their own endpoints.
Use direct wire commands only for debugging, inspection, or manual provider
maintenance:

```sh
tools/wire/wire create-endpoint --provider hetzner --exposure wan --confirm-live-run --json
tools/wire/wire list-endpoints --json
tools/wire/wire ssh-info ENDPOINT_ID --json
tools/wire/wire collect-artifacts ENDPOINT_ID
tools/wire/wire destroy-endpoint ENDPOINT_ID --json
```

For private endpoint experiments, pass the same `--private-group` to each
endpoint and unique `--private-ip` values inside the supported private range.

## Artifacts

Collect artifacts through wire or the owning oracle/probe runner. Keep artifacts
local. Do not commit provider account data, public host addresses, live host
identifiers, packet captures from non-disposable networks, private keys, or
credentials.

## CI Secrets

Use `HETZNER_API_TOKEN` as the CI secret name. CI jobs should run dry-run
commands for pull requests and reserve real host creation for explicit,
protected workflows with environment approval.

Recommended provider dry-run flow:

```sh
tools/wire/wire doctor --provider hetzner --exposure private --dry-run
tools/oracle/run live --provider hetzner --dry-run --profile smoke --seed 12345 --count 10
tools/probe/run --provider hetzner --dry-run --profile smoke --seed 1 --count 10
```

Pull request CI should run corpus, offline, pcap, Hetzner wire dry-run, and
probe dry-run validation through [validation.md](validation.md). Real live runs
should be manual, protected, and keep cleanup logic around wire endpoint
destruction so resources are still torn down after a failed validation step.

See also [supported-platforms.md](supported-platforms.md) for the alpha support
matrix and known release gaps.

## Cleanup

Destroy disposable hosts as soon as live validation finishes:

```sh
tools/wire/wire destroy-endpoint ENDPOINT_ID --json
```

If a command fails before cleanup, keep the ignored state directory until
`destroy-endpoint` succeeds. The endpoint manifest contains the provider
resource ids needed for cleanup. After cleanup, artifacts can be kept locally
for debugging and removed manually when no longer needed.
