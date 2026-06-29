# Endpoint Provider Guide

`tools/endpoint` defines the provider contract for one endpoint target:
disposable provider provisioning, command execution, upload, download,
artifact collection, SSH access, appliance execution, persistent asset leases,
and destroy. It is the lower-level endpoint primitive used by `tools/lab`.

Use `tools/lab` for coordinated multi-endpoint provider sessions. Oracle and
probe own the workload, reports, and reproduction coordinates; lab owns the
multi-endpoint session; the endpoint provider layer owns one provider-backed
endpoint and transport operations. The current endpoint providers are Hetzner,
QEMU, VirtualBox, and Docker.

Local static tests should run before any provider command. Provider-backed
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
`docker/private`, `docker/lan`, and `docker/wan` as direct endpoint modes.
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
Docker provider should be invoked from the host through the narrow endpoint
commands; provider containers must not mount the Docker socket. The provider
also avoids `--privileged`, host networking, host PID mode, and broad host
filesystem mounts. Containers run with `--cap-drop ALL`, no privileged or
host-network mode, no Docker socket mount, and only the packet capabilities
for the selected exposure: `NET_RAW` plus `NET_ADMIN` for `docker/private`,
and `NET_RAW` only for NAT-backed LAN and WAN.

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
tools/endpoint/run create --provider docker --exposure private --private-group lab-a --private-ip 10.79.0.10 --dry-run --json
tools/endpoint/run create --provider docker --exposure lan --dry-run --json
tools/endpoint/run create --provider docker --exposure wan --dry-run --json
```

Create Docker endpoints only after the normal live confirmation gate:

```sh
tools/endpoint/run create --provider docker --exposure private --private-group lab-a --private-ip 10.79.0.10 --confirm-live-run --json
tools/endpoint/run create --provider docker --exposure lan --confirm-live-run --json
tools/endpoint/run create --provider docker --exposure wan --confirm-live-run --json
```

For `docker/private`, pass the same `--private-group` to endpoints that should
share one isolated bridge; `--private-ip` is optional and must be inside
`LIBCRAFTER_DOCKER_PRIVATE_CIDR`. Docker LAN and WAN do not accept private
group or private IP options because they attach to configured Docker networks
and discover the container IPv4.

## Hetzner Setup

The Hetzner endpoint provider reads `HETZNER_API_TOKEN` or `HCLOUD_TOKEN` from the
process environment. Do not place real token values in repo files, shell history
snippets, logs, or examples. The provider prints only whether credentials are
configured.

Run dry-run checks first:

```sh
tools/endpoint/run doctor --provider hetzner --exposure wan --dry-run
tools/endpoint/run doctor --provider hetzner --exposure private --dry-run
tools/endpoint/run create --provider hetzner --exposure wan --dry-run --write-manifest
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

Generated endpoint state is written below `tools/endpoint/.state/`. Lab
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

## Endpoint Appliance Runs

Endpoint appliance commands run the standard libcrafter Docker appliance on one
endpoint manifest or one acquired asset lease. They are mechanical transport
operations: check the selected profile, prepare remote roots, sync a workspace,
run a container, and collect artifacts. They do not decide packet semantics and
do not replace the live confirmation required by oracle, probe, RF tools, or a
generated workload.

Start with dry-run plans:

```sh
tools/endpoint/run appliance check --dry-run --json ENDPOINT_ID wan-raw
tools/endpoint/run appliance plan --dry-run --json ENDPOINT_ID wan-raw -- \
  sh -lc 'printf "endpoint appliance plan for 192.0.2.10\n" > /artifacts/summary.txt'
tools/endpoint/run appliance deploy --dry-run --json ENDPOINT_ID wan-raw
tools/endpoint/run appliance run --dry-run --json ENDPOINT_ID wan-raw -- \
  sh -lc 'printf "appliance run dry-run\n" > /artifacts/summary.txt'
tools/endpoint/run appliance collect --dry-run --json ENDPOINT_ID wan-raw
```

`plan` renders the deploy, optional sync, and run records without SSH, SCP,
Docker, or tar. `check` renders Docker and profile readiness checks, including
profile-specific requirements for `whad-serial` and `dot11-monitor`. `deploy`
prepares one endpoint for the appliance image. `run` executes the selected
container command when `--dry-run` is omitted. `collect` downloads the remote
artifact directory when `--dry-run` is omitted.

Use `wan-raw` for public or NAT-backed raw packet work, `lan-raw` for a
prepared LAN-visible VM or host, `whad-serial` for WHAD serial dongle work, and
`dot11-monitor` for a host or VM that already owns monitor-mode Wi-Fi setup.
Docker gives the appliance userland; the host or VM still owns kernel modules,
USB passthrough, interface state, monitor mode, RF channel configuration, and
any local live-transmit acknowledgement.

## Persistent Assets And Leases

Persistent assets are prepared reusable endpoint targets stored below the
ignored endpoint state root. Use them for a generic SSH Docker host, a QEMU VM,
a VirtualBox VM, or a local hardware-backed target that should not be recreated
for every agent session. Asset records contain SSH coordinates, supported
profiles, Docker command metadata, hardware readiness summaries, and optional
profile environment overrides. Keep real host identifiers, public addresses,
hardware serials, SSIDs, private keys, and credentials out of tracked files.

Register a generic SSH Docker host:

```sh
tools/endpoint/run asset register doc-ssh-host \
  --substrate generic-ssh \
  --profile wan-raw \
  --ssh-host 192.0.2.50 \
  --ssh-user appliance \
  --identity-file /home/operator/.ssh/libcrafter_doc_key \
  --known-hosts-file /home/operator/.ssh/libcrafter_doc_known_hosts \
  --json
```

Register a QEMU persistent asset with a WHAD serial profile:

```sh
tools/endpoint/run asset register doc-qemu-whad \
  --substrate qemu \
  --profile whad-serial \
  --ssh-host 192.0.2.51 \
  --ssh-user appliance \
  --identity-file /home/operator/.ssh/libcrafter_doc_key \
  --known-hosts-file /home/operator/.ssh/libcrafter_doc_known_hosts \
  --metadata-json '{"appliance":{"profile_environments":{"whad-serial":{"LIBCRAFTER_WHAD_DEVICE":"/dev/ttyACM0"}}}}' \
  --json
```

Register a VirtualBox persistent asset with a prepared monitor interface:

```sh
tools/endpoint/run asset register doc-vbox-dot11 \
  --substrate virtualbox \
  --profile dot11-monitor \
  --ssh-host 192.0.2.52 \
  --ssh-user appliance \
  --identity-file /home/operator/.ssh/libcrafter_doc_key \
  --known-hosts-file /home/operator/.ssh/libcrafter_doc_known_hosts \
  --metadata-json '{"appliance":{"profile_environments":{"dot11-monitor":{"LIBCRAFTER_DOT11_IFACE":"dot11mon-doc"}}}}' \
  --json
```

Check, lease, run a dry plan through the lease, and release:

```sh
tools/endpoint/run asset check doc-qemu-whad --profile whad-serial --json
tools/endpoint/run asset acquire --profile whad-serial --lease-ttl 2h --owner doc-operator --json
tools/endpoint/run appliance plan --dry-run --json --lease LEASE_ID whad-serial -- \
  sh -lc 'printf "leased WHAD plan only\n" > /artifacts/summary.txt'
tools/endpoint/run asset release LEASE_ID --json
```

`asset check` locks one asset, verifies SSH Docker access, and renders the
selected profile readiness checks. `asset acquire` creates a TTL lease for one
available asset that supports the requested profile. `asset release` frees the
lease. Release leases as soon as the run is complete so later sessions do not
block on stale ownership; expired leases can be recovered by later acquire
operations.

## Hetzner Appliance Deploy

Hetzner appliance runs are for disposable WAN or private endpoints. The
provider still reads `HETZNER_API_TOKEN` or `HCLOUD_TOKEN` from the process
environment only, and live creation still requires `--confirm-live-run`.
Plan both the provider endpoint and the appliance deploy before creating
infrastructure:

```sh
tools/endpoint/run create --provider hetzner --exposure wan --dry-run --write-manifest --json
tools/endpoint/run appliance deploy --dry-run --json ENDPOINT_ID wan-raw
tools/endpoint/run appliance plan --dry-run --json ENDPOINT_ID wan-raw -- \
  sh -lc 'printf "hetzner appliance deploy plan only\n" > /artifacts/summary.txt'
```

After an operator intentionally creates a live disposable endpoint, use the
reported endpoint ID with `tools/endpoint/run appliance deploy`,
`tools/endpoint/run appliance run`, and `tools/endpoint/run appliance collect`.
Keep workload commands in dry-run or plan mode until their own live gate is
explicitly confirmed.

## Direct Endpoint Operations

The high-level oracle and probe runners create and destroy lab sessions.
Use direct endpoint commands only for debugging, inspection, or manual provider
maintenance of one endpoint:

```sh
tools/endpoint/run create --provider hetzner --exposure wan --confirm-live-run --json
tools/endpoint/run create --provider docker --exposure private --private-group lab-a --confirm-live-run --json
tools/endpoint/run create --provider docker --exposure lan --confirm-live-run --json
tools/endpoint/run create --provider docker --exposure wan --confirm-live-run --json
tools/endpoint/run list --json
tools/endpoint/run ssh-info ENDPOINT_ID --json
tools/endpoint/run collect-artifacts ENDPOINT_ID
tools/endpoint/run destroy ENDPOINT_ID --json
```

For private endpoint experiments, pass the same `--private-group` to each
endpoint and unique `--private-ip` values inside the supported private range.
For Docker, SSH still uses the normal endpoint transport through a localhost
forward to `sshd` inside the container, so `exec`, `upload`, `download`, and
`collect-artifacts` work the same way as other providers.

## Artifacts

Collect artifacts through endpoint operations or the owning oracle/probe
runner. Keep artifacts local. Do not commit provider account data, public host
identifiers, packet captures from non-disposable networks, private keys, or
credentials.

Docker endpoint artifacts include manifests, SSH identity and known-hosts paths,
command stdout/stderr from endpoint operations, Docker image inspect/build command
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
tools/endpoint/run create --provider docker --exposure private --private-group ci-plan --dry-run --json
tools/endpoint/run create --provider docker --exposure lan --dry-run --json
tools/endpoint/run create --provider docker --exposure wan --dry-run --json
tools/oracle/run live --provider hetzner --dry-run --profile smoke --seed 12345 --count 10
python3 tools/oracle/engine/live_provider_matrix.py --providers hetzner,qemu,virtualbox --profile smoke --seed 12345 --count 5 --dry-run --out target/oracle/provider-matrix-dry-run
tools/probe/run --provider hetzner --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider qemu --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider virtualbox --dry-run --profile smoke --seed 1 --count 10
```

Pull request CI should run corpus, offline, pcap, Hetzner endpoint dry-run, and
probe dry-run validation through [validation.md](validation.md). Real provider
runs should be manual, protected, and keep cleanup logic around endpoint
destruction so resources are still torn down after a failed validation step.

## Cleanup

Destroy disposable hosts as soon as provider validation finishes:

```sh
tools/endpoint/run destroy ENDPOINT_ID --json
```

If a command fails before cleanup, keep the ignored state directory until
`destroy` succeeds. The endpoint manifest contains the provider
resource ids needed for cleanup. After cleanup, artifacts can be kept locally
for debugging and removed manually when no longer needed.

Docker cleanup removes tracked containers and only removes provider-owned
private bridge networks when their private group is safe to delete. It preserves
local state and artifacts, including Docker command logs, so failed image,
network, SSH, or interface-discovery work can be inspected after cleanup.
