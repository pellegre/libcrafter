# Lab Sessions

`tools/lab` is the standalone multi-endpoint substrate tool for libcrafter
provider-backed work. It composes lower-level `wire` endpoints into named
roles, persists a lab session manifest, records provider workflow and command
metadata, and owns repository archive transfer, remote unpack, bootstrap
context, artifact collection, and cleanup records.

Oracle and probe use lab sessions so their live behavior is independent of the
machine where libcrafter or an agent is running. Oracle still owns reference
packet validation. Probe still owns kernel and controlled-service behavior
validation. Wire still owns one endpoint and transport operations.

## Tool Split

| Tool | Owns |
| --- | --- |
| `tools/endpoint` | One disposable endpoint: doctor, create, exec, upload, download, collect artifacts, destroy. |
| `tools/lab` | Multi-endpoint sessions: roles, provider capabilities, endpoint topology, repository archive transfer, remote unpack, bootstrap context, session manifests, artifacts, cleanup records. |
| `tools/oracle` | Reference packet corpus, offline/pcap/live packet comparison, `libcrafter` and `reference_backend` workload setup, backend policy, oracle reports. |
| `tools/probe` | Kernel/service probe cases, `stimulus` and `target` workload setup, target service setup, RST guards, stimulus execution, probe reports. |

Provider adapters live under `tools/lab/engine/providers/` and are registered by
name. The current lab-backed providers are:

- `hetzner`: private cloud endpoints.
- `qemu`: local private VM segment.
- `virtualbox`: bridged LAN VM endpoints.
- `docker`: local constrained containers on an isolated `docker/private`
  bridge.

The Docker lab provider maps provider `docker` to the wire provider/exposure
pair `docker/private`. It is the Docker mode intended for coordinated
multi-endpoint lab sessions. Docker `lan` and `wan` are direct wire endpoint
modes for single-endpoint smokes, not lab-backed multi-endpoint modes.

## Bootstrap Ownership

Lab providers own endpoint substrate lifecycle only: provider-specific planning,
creation, connectivity, capability reporting, and teardown. They do not install
workload packages, build binaries, start services, or decide which role-specific
commands run after the repository is unpacked.

`tools/lab` owns the provider-neutral repository bootstrap boundary. It builds
and transfers the repository archive, unpacks it on each endpoint, constructs
the bootstrap context passed to workload hooks, records command metadata, tracks
artifacts, and writes cleanup records. Workload bootstrap happens after this
repository bootstrap step.

Oracle owns the `libcrafter` and `reference_backend` workload setup. Probe owns
the `stimulus` and `target` workload setup. Docker does not change that
boundary: the Docker lab adapter owns only the constrained private endpoint
substrate, while oracle and probe still own role-specific bootstrap commands.

## Docker Private Capability Model

The Docker lab provider creates role endpoints on a provider-owned internal
Docker bridge. Endpoints in the same lab session share one private group,
receive deterministic private IPv4 addresses, record provider MAC metadata,
and remain reachable through the existing SSH transport on localhost port
forwards. Live containers run with `--cap-drop ALL`,
`--security-opt no-new-privileges`, and only the packet capabilities required
for `docker/private`.

`docker/private` advertises IPv4 unicast, link-layer send, link-layer capture,
broadcast, provider MAC knowledge, and controlled services. It does not
advertise IPv6 unicast or a controlled routed hop. Cases that require a router
capability, such as TTL-expired probe cases, are skipped by provider
capability checks.

Docker socket access is still host-root equivalent. Use the narrow provider
commands from the host; do not mount the Docker socket into provider
containers.

## Dry-Run Planning

Dry-run planning is the safe default. It validates the provider contract and
bootstrap ownership boundary, then emits deterministic metadata without
creating infrastructure:

```sh
tools/lab/run providers --json
tools/lab/run plan --provider hetzner --dry-run --profile smoke --seed 1 --role stimulus --role target --json
tools/lab/run plan --provider qemu --dry-run --profile smoke --seed 1 --role stimulus --role target --json
tools/lab/run plan --provider virtualbox --dry-run --profile smoke --seed 1 --role stimulus --role target --json
tools/lab/run plan --provider docker --dry-run --profile smoke --seed 1 --role stimulus --role target --json
```

Oracle and probe dry-runs call the same lab provider substrate:

```sh
tools/oracle/run live --provider hetzner --dry-run --profile smoke --seed 12345 --count 10
tools/oracle/run live --provider qemu --dry-run --profile smoke --seed 12345 --count 10
tools/oracle/run live --provider virtualbox --dry-run --profile smoke --seed 12345 --count 10
tools/oracle/run live --provider docker --dry-run --profile smoke --seed 12345 --count 10
tools/probe/run --provider hetzner --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider qemu --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider virtualbox --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider docker --dry-run --profile smoke --seed 1 --count 10
```

Docker LAN and WAN reachability checks are direct wire smokes because they
exercise one container's NAT-backed L3 path through Docker bridge routing:

```sh
tools/endpoint/smoke/live_docker_lan_icmp.py --plan-only
tools/endpoint/smoke/live_docker_wan_dns.py --plan-only
```

Those scripts default to plan output. Live LAN/WAN smokes require their own
explicit `--live --i-understand-isolated-lab` flags and do not imply lab
support for LAN L2, WAN L2, public inbound reachability, or multi-endpoint
LAN/WAN sessions.

## Live Sessions

Live lab creation requires explicit confirmation:

```sh
tools/lab/run create --provider qemu --profile smoke --seed 1 --role stimulus --role target --confirm-live-run --json
tools/lab/run create --provider docker --profile smoke --seed 1 --role stimulus --role target --confirm-live-run --json
tools/lab/run list-sessions --json
tools/lab/run session-info SESSION_ID --json
tools/lab/run destroy SESSION_ID --json
```

Most packet validation should enter through oracle or probe rather than direct
lab commands. Those runners create lab sessions, ask lab to transfer and unpack
the repository, supply workload-owned bootstrap hooks, run the workload, collect
artifacts, and tear down the session.

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
