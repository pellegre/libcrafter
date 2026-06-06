# Wire Endpoint Provider Guide

`tools/endpoint` defines the provider contract for one disposable endpoint:
provision, command execution, upload, download, artifact collection, SSH access,
and destroy. It is the lower-level endpoint primitive used by `tools/lab`.

Use `tools/lab` for coordinated multi-endpoint provider sessions. Oracle and
probe own the workload, reports, and reproduction coordinates; lab owns the
multi-endpoint session; wire owns one endpoint and transport operations. The
current wire providers are Hetzner, QEMU, VirtualBox, and Docker.

Local static tests should run before any provider command. Provider-backed wire
endpoints are for tests that need root privileges, raw sockets, packet capture,
reference comparison, or kernel/service replies on disposable infrastructure.
See [validation.md](validation.md) for oracle modes and CI expectations, and
[probe.md](probe.md) for behavioral probe cases. See [lab.md](lab.md) for the
multi-endpoint session layer.

## Provider Setup

Hetzner uses `hetzner/private` for oracle live exchange. QEMU uses
`qemu/private` with private group `oracle-live-private` and deterministic
oracle role addresses `10.77.0.10` and `10.77.0.20`. VirtualBox uses
`virtualbox/lan`; the guest LAN address is discovered from the bridged
interface manifest and is not requested by oracle. Docker supports
`docker/private`, `docker/lan`, and `docker/wan` as direct wire endpoint modes.
`docker/private` is the isolated multi-endpoint mode: endpoints in the same
private group join a provider-owned internal bridge with static private IPv4
and deterministic MAC metadata. `docker/lan` and `docker/wan` use Docker bridge
routing for NAT-backed IPv4 L3 reachability and do not provide true LAN L2,
physical LAN broadcast, WAN link-layer fidelity, public addresses, or inbound
internet reachability.

Run provider checks before real endpoint creation:

```sh
tools/endpoint/run doctor --provider hetzner --exposure private --json
tools/endpoint/run doctor --provider qemu --exposure private --json
tools/endpoint/run doctor --provider virtualbox --exposure lan --json
tools/endpoint/run doctor --provider docker --exposure private --json
tools/endpoint/run doctor --provider docker --exposure lan --json
tools/endpoint/run doctor --provider docker --exposure wan --json
```

VM provider prerequisites are documented in `tools/endpoint/README.md`. In short,
QEMU needs `qemu-system-x86_64`, `qemu-img`, `cloud-localds`, and SSH tooling.
VirtualBox needs `VBoxManage`, `qemu-img`, `cloud-localds`, SSH tooling, and a
usable bridged interface. Set `LIBCRAFTER_VBOX_BRIDGE_IFACE` to request a
specific bridge. Docker needs the Docker CLI, a reachable daemon, SSH tooling,
and permission for the user running `tools/endpoint` to use Docker.

Treat Docker daemon and Docker socket access as host-root equivalent. The
Docker provider should be invoked from the host through the narrow wire
commands; provider containers must not mount the Docker socket. The provider
also avoids `--privileged`, host networking, host PID mode, and broad host
filesystem mounts. Containers run with `--cap-drop ALL`,
`--security-opt no-new-privileges`, and only the packet capabilities for the
selected exposure: `NET_RAW` plus `NET_ADMIN` for `docker/private`, and
`NET_RAW` only for NAT-backed LAN and WAN.

Docker environment overrides:

| Variable | Meaning |
| --- | --- |
| `LIBCRAFTER_DOCKER_COMMAND` | Docker CLI path, default `docker` |
| `LIBCRAFTER_DOCKER_IMAGE` | Endpoint image tag, default `libcrafter-wire-endpoint:local` |
| `LIBCRAFTER_DOCKER_REBUILD` | Rebuild the endpoint image when set to `1` |
| `LIBCRAFTER_DOCKER_PRIVATE_CIDR` | Private bridge CIDR, default `10.79.0.0/24` |
| `LIBCRAFTER_DOCKER_LAN_NETWORK` | Docker network for NAT-backed LAN L3, default `bridge` |
| `LIBCRAFTER_DOCKER_WAN_NETWORK` | Docker network for NAT-backed WAN L3, default `bridge` |

Plan Docker endpoints without side effects:

```sh
tools/endpoint/run create-endpoint --provider docker --exposure private --private-group lab-a --private-ip 10.79.0.10 --dry-run --json
tools/endpoint/run create-endpoint --provider docker --exposure lan --dry-run --json
tools/endpoint/run create-endpoint --provider docker --exposure wan --dry-run --json
```

Create Docker endpoints only after the normal live confirmation gate:

```sh
tools/endpoint/run create-endpoint --provider docker --exposure private --private-group lab-a --private-ip 10.79.0.10 --confirm-live-run --json
tools/endpoint/run create-endpoint --provider docker --exposure lan --confirm-live-run --json
tools/endpoint/run create-endpoint --provider docker --exposure wan --confirm-live-run --json
```

For `docker/private`, pass the same `--private-group` to endpoints that should
share one isolated bridge; `--private-ip` is optional and must be inside
`LIBCRAFTER_DOCKER_PRIVATE_CIDR`. Docker LAN and WAN do not accept private
group or private IP options because they attach to configured Docker networks
and discover the container IPv4.

## Hetzner Setup

The Hetzner wire provider reads `HETZNER_API_TOKEN` or `HCLOUD_TOKEN` from the
process environment. Do not place real token values in repo files, shell history
snippets, logs, or examples. The provider prints only whether credentials are
configured.

Run dry-run checks first:

```sh
tools/endpoint/run doctor --provider hetzner --exposure wan --dry-run
tools/endpoint/run doctor --provider hetzner --exposure private --dry-run
tools/endpoint/run create-endpoint --provider hetzner --exposure wan --dry-run --write-manifest
```

Oracle offline and pcap validation plus lab-backed oracle/probe dry-runs should
pass before creating infrastructure. The validation commands are documented in
[validation.md](validation.md), [probe.md](probe.md), and [lab.md](lab.md).

Plan provider-backed oracle and probe validation without creating
infrastructure:

```sh
tools/lab/run plan --provider hetzner --dry-run --profile smoke --seed 1 --role stimulus --role target --json
tools/oracle/run live --provider hetzner --dry-run --profile smoke --seed 12345 --count 10
tools/probe/run --provider hetzner --dry-run --profile smoke --seed 1 --count 10
```

Start protected provider validation only when disposable resources are intended:

```sh
tools/oracle/run live --provider hetzner --confirm-live-run --profile smoke --seed 12345 --count 10
python3 tools/oracle/engine/live_provider_matrix.py --providers qemu,virtualbox --profile smoke --seed 12345 --count 2 --real --skip-unavailable --out target/oracle/provider-matrix-vm-real
tools/probe/run --provider hetzner --confirm-live-run --profile smoke --seed 21 --count 25
```

Generated wire endpoint state is written below `tools/endpoint/.state/`. Lab
session state and artifacts are written below ignored lab state/artifact roots.
Oracle reports and packet artifacts are written below `target/oracle/`; probe
reports are written below `target/probe/`.

The VM matrix writes `target/oracle/provider-matrix-vm-real/matrix-summary.json`
plus per-provider reports under
`target/oracle/provider-matrix-vm-real/providers/<provider>/live/report.json`.
The summary preserves doctor results, report paths, endpoint lifecycle
metadata, endpoint IDs, artifact roots, and cleanup status. By default a
missing VM prerequisite or disabled VM creation is recorded as a structured
skip. Add `--allow-vm-create` or set
`LIBCRAFTER_ORACLE_VM_SMOKE_ALLOW_CREATE=1` when a lab run should actually
create disposable local VMs. Set `LIBCRAFTER_ORACLE_VM_SMOKE_STRICT=1` or pass
`--strict-vm-smoke` when a lab qualification run should fail on skipped VM
providers.

Use the same `--profile`, `--seed`, `--count`, and reported `--index` to
reproduce a single failed oracle packet plan. For probe, preserve the reported
sequence number, case name, seed, and profile.

## Direct Endpoint Operations

The high-level oracle and probe runners create and destroy lab sessions.
Use direct wire commands only for debugging, inspection, or manual provider
maintenance of one endpoint:

```sh
tools/endpoint/run create-endpoint --provider hetzner --exposure wan --confirm-live-run --json
tools/endpoint/run create-endpoint --provider docker --exposure private --private-group lab-a --confirm-live-run --json
tools/endpoint/run create-endpoint --provider docker --exposure lan --confirm-live-run --json
tools/endpoint/run create-endpoint --provider docker --exposure wan --confirm-live-run --json
tools/endpoint/run list-endpoints --json
tools/endpoint/run ssh-info ENDPOINT_ID --json
tools/endpoint/run collect-artifacts ENDPOINT_ID
tools/endpoint/run destroy-endpoint ENDPOINT_ID --json
```

For private endpoint experiments, pass the same `--private-group` to each
endpoint and unique `--private-ip` values inside the supported private range.
For Docker, SSH still uses the normal wire transport through a localhost
forward to `sshd` inside the container, so `exec`, `upload`, `download`, and
`collect-artifacts` work the same way as other providers.

## Artifacts

Collect artifacts through wire or the owning oracle/probe runner. Keep artifacts
local. Do not commit provider account data, public host addresses, live host
identifiers, packet captures from non-disposable networks, private keys, or
credentials.

Docker endpoint artifacts include manifests, SSH identity and known-hosts paths,
command stdout/stderr from wire operations, Docker image inspect/build command
logs, container and network metadata, interface discovery data, and cleanup
state. The provider records enough metadata to destroy tracked containers after
partial failures and to remove provider-owned private networks only when safe.

## CI Secrets

Use `HETZNER_API_TOKEN` as the CI secret name. CI jobs should run dry-run
commands for pull requests and reserve real host creation for explicit,
protected workflows with environment approval.

Recommended provider dry-run flow:

```sh
tools/endpoint/run doctor --provider hetzner --exposure private --dry-run
tools/endpoint/run doctor --provider qemu --exposure private --dry-run
tools/endpoint/run doctor --provider virtualbox --exposure lan --dry-run
tools/endpoint/run doctor --provider docker --exposure private --dry-run
tools/endpoint/run doctor --provider docker --exposure lan --dry-run
tools/endpoint/run doctor --provider docker --exposure wan --dry-run
tools/lab/run plan --provider hetzner --dry-run --profile smoke --seed 1 --role stimulus --role target --json
tools/lab/run plan --provider qemu --dry-run --profile smoke --seed 1 --role stimulus --role target --json
tools/lab/run plan --provider virtualbox --dry-run --profile smoke --seed 1 --role stimulus --role target --json
tools/endpoint/run create-endpoint --provider docker --exposure private --private-group ci-plan --dry-run --json
tools/endpoint/run create-endpoint --provider docker --exposure lan --dry-run --json
tools/endpoint/run create-endpoint --provider docker --exposure wan --dry-run --json
tools/oracle/run live --provider hetzner --dry-run --profile smoke --seed 12345 --count 10
python3 tools/oracle/engine/live_provider_matrix.py --providers hetzner,qemu,virtualbox --profile smoke --seed 12345 --count 5 --dry-run --out target/oracle/provider-matrix-dry-run
tools/probe/run --provider hetzner --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider qemu --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider virtualbox --dry-run --profile smoke --seed 1 --count 10
```

Pull request CI should run corpus, offline, pcap, Hetzner wire dry-run, and
probe dry-run validation through [validation.md](validation.md). Real provider
runs should be manual, protected, and keep cleanup logic around wire endpoint
destruction so resources are still torn down after a failed validation step.

## Cleanup

Destroy disposable hosts as soon as provider validation finishes:

```sh
tools/endpoint/run destroy-endpoint ENDPOINT_ID --json
```

If a command fails before cleanup, keep the ignored state directory until
`destroy-endpoint` succeeds. The endpoint manifest contains the provider
resource ids needed for cleanup. After cleanup, artifacts can be kept locally
for debugging and removed manually when no longer needed.

Docker cleanup removes tracked containers and only removes provider-owned
private bridge networks when their private group is safe to delete. It preserves
local state and artifacts, including Docker command logs, so failed image,
network, SSH, or interface-discovery work can be inspected after cleanup.
