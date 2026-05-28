# Lab Sessions

`tools/lab` is the standalone multi-endpoint substrate tool for libcrafter
provider-backed work. It composes lower-level `wire` endpoints into named
roles, persists a lab session manifest, records provider workflow and command
metadata, and owns repository push/bootstrap, artifact collection, and cleanup.

Oracle and probe use lab sessions so their live behavior is independent of the
machine where libcrafter or an agent is running. Oracle still owns reference
packet validation. Probe still owns kernel and controlled-service behavior
validation. Wire still owns one endpoint and transport operations.

## Tool Split

| Tool | Owns |
| --- | --- |
| `tools/wire` | One disposable endpoint: doctor, create, exec, upload, download, collect artifacts, destroy. |
| `tools/lab` | Multi-endpoint sessions: roles, provider capabilities, endpoint topology, repository push/bootstrap, session manifests, cleanup. |
| `tools/oracle` | Reference packet corpus, offline/pcap/live packet comparison, backend policy, oracle reports. |
| `tools/probe` | Kernel/service probe cases, target service setup, RST guards, stimulus execution, probe reports. |

Provider adapters live under `tools/lab/engine/providers/` and are registered by
name. The current lab-backed providers are:

- `hetzner`: private cloud endpoints.
- `qemu`: local private VM segment.
- `virtualbox`: bridged LAN VM endpoints.

## Dry-Run Planning

Dry-run planning is the safe default. It validates the provider contract and
emits deterministic metadata without creating infrastructure:

```sh
tools/lab/run providers --json
tools/lab/run plan --provider hetzner --dry-run --profile smoke --seed 1 --role stimulus --role target --json
tools/lab/run plan --provider qemu --dry-run --profile smoke --seed 1 --role stimulus --role target --json
tools/lab/run plan --provider virtualbox --dry-run --profile smoke --seed 1 --role stimulus --role target --json
```

Oracle and probe dry-runs call the same lab provider substrate:

```sh
tools/oracle/run live --provider hetzner --dry-run --profile smoke --seed 12345 --count 10
tools/oracle/run live --provider qemu --dry-run --profile smoke --seed 12345 --count 10
tools/oracle/run live --provider virtualbox --dry-run --profile smoke --seed 12345 --count 10
tools/probe/run --provider hetzner --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider qemu --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider virtualbox --dry-run --profile smoke --seed 1 --count 10
```

## Live Sessions

Live lab creation requires explicit confirmation:

```sh
tools/lab/run create --provider qemu --profile smoke --seed 1 --role stimulus --role target --confirm-live-run --json
tools/lab/run list-sessions --json
tools/lab/run session-info SESSION_ID --json
tools/lab/run destroy SESSION_ID --json
```

Most packet validation should enter through oracle or probe rather than direct
lab commands. Those runners create lab sessions, push the repository, bootstrap
endpoints, run the workload, collect artifacts, and tear down the session.

## Metadata And Artifacts

Lab-backed reports include:

- `lab_session`: provider, wire provider/exposure, roles, endpoints,
  capabilities, validation checks, remote paths, command records, and cleanup
  state.
- `planned_infrastructure`: dry-run-safe provider topology metadata.
- `wire_endpoint_plan`: normalized endpoint plan and lab session id.
- provider workflow and command records.
- endpoint role/address metadata used by oracle or probe.

Artifacts are written under the selected runner output directory and ignored
lab/wire state roots. Do not commit credentials, provider account data, public
host identifiers, live public IPs, or packet captures from sensitive networks.

For agent operating guidance, use the repo-local `lab-session` and
`lab-provider` skills.
