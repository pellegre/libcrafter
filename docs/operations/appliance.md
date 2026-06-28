# Appliance Operations

The appliance system gives libcrafter packet tools one repeatable Linux
userland without turning the public `crafter` crate into an analyzer, scanner,
or provider client. Operators build or select the standard Docker image, choose
a coarse runtime profile, and run the workload on a local Docker host, an
SSH-accessible Docker host, a disposable endpoint, or a persistent prepared
asset.

The appliance is an execution substrate. It does not decide packet semantics,
start live traffic by itself, configure RF hardware, flash firmware, or make a
Docker container own host kernel state. Packet-generating tools still keep their
own dry-run defaults and explicit live gates.

## Architecture

The operational stack is:

```text
oracle / probe / generated tool
          |
          v
tools/lab role session, when multiple endpoints are needed
          |
          v
tools/endpoint one endpoint or persistent asset
          |
          v
tools/appliance Docker image, profiles, modules, checks, and run plans
          |
          v
local Docker host, SSH Docker host, QEMU, VirtualBox, or Hetzner
```

Ownership stays narrow:

- `tools/appliance` owns the image metadata, profile registry, module registry,
  local run plans, readiness check plans, and SSH Docker command shapes.
- `tools/endpoint` owns one target: endpoint manifests, SSH transport,
  workspace sync, remote Docker execution, artifact collection, persistent
  assets, and leases.
- `tools/lab` composes endpoint-backed appliance runtimes into role sessions for
  oracle and probe.
- Oracle, probe, or a generated tool own the packet workload and any protocol
  or service-specific live gate.

## Standard Docker Image

The standard image is built from `tools/appliance/Dockerfile` and contains the
shared libcrafter userland: Rust build tooling, packet utility dependencies,
the appliance entrypoint, and userland helpers. The image does not configure
host interfaces, Wi-Fi monitor mode, USB passthrough, kernel modules, Docker
daemon policy, or cloud provider resources.

Inspect the deterministic image plan without invoking Docker:

```sh
tools/appliance/run image plan --json
```

Build or inspect the configured image only when the local Docker daemon is the
intended target:

```sh
LIBCRAFTER_APPLIANCE_IMAGE=libcrafter/appliance:latest tools/appliance/run image build
LIBCRAFTER_APPLIANCE_IMAGE=libcrafter/appliance:latest tools/appliance/run image inspect
```

`LIBCRAFTER_APPLIANCE_IMAGE` selects the image tag. `LIBCRAFTER_DOCKER_COMMAND`
selects the Docker-compatible CLI. Keep real registry credentials, daemon
configuration, and host-specific Docker state out of tracked files.

## Profiles

Profiles are coarse placement profiles, not protocol capability lists:

| Profile | Use | Key runtime shape |
| --- | --- | --- |
| `wan-raw` | Raw packet work from a WAN-capable Linux Docker host. | Host networking, `NET_RAW`, selected interface through `LIBCRAFTER_IFACE`. |
| `lan-raw` | Raw packet work from a bridged VM or prepared host with LAN-visible interface access. | Host networking, `NET_RAW`, selected interface through `LIBCRAFTER_IFACE`; Docker bridge NAT is not true LAN L2. |
| `whad-serial` | WHAD serial dongle work for BLE or IEEE 802.15.4 workflows. | Docker bridge networking, serial device placeholder `/dev/ttyACM0`, override through `LIBCRAFTER_WHAD_DEVICE`. |
| `dot11-monitor` | IEEE 802.11 radiotap capture or gated injection from a prepared monitor-mode interface. | Host networking, `NET_RAW`, `NET_ADMIN`, interface through `LIBCRAFTER_DOT11_IFACE`; host or VM owns driver, channel, and monitor-mode setup. |

List or inspect profiles:

```sh
tools/appliance/run profiles list
tools/appliance/run profiles show wan-raw --json
```

## Modules

Modules describe optional userland, host preparation, devices, interfaces, and
checks for hardware families. They are not local configuration files.

- `base` describes the shared appliance userland for raw WAN and LAN profiles.
- `nrf52840-whad` describes nRF-style WHAD serial readiness and discovery for
  `whad-serial`; it does not flash firmware or commit real USB identifiers.
- `wifi-monitor` describes generic monitor-mode Wi-Fi readiness for
  `dot11-monitor`; concrete adapter assignment, channel, driver source, and
  passthrough details stay in ignored local state.

```sh
tools/appliance/run modules list
tools/appliance/run modules show wifi-monitor --json
```

## Local Substrate

The local substrate renders Docker command plans. It is useful for reviewing
the exact container flags, mounts, environment, and command before anything is
run. The examples below write only synthetic text to `/artifacts` inside the
planned container.

`wan-raw` plan:

```sh
tools/appliance/run run-plan \
  --profile wan-raw \
  --work-dir /home/operator/libcrafter-workspace \
  --artifact-dir /tmp/libcrafter-appliance/wan-raw \
  --env LIBCRAFTER_IFACE=wan-doc0 \
  -- \
  sh -lc 'printf "wan-raw dry-run for 192.0.2.10\n" > /artifacts/summary.txt'
```

`lan-raw` plan:

```sh
tools/appliance/run run-plan \
  --profile lan-raw \
  --work-dir /home/operator/libcrafter-workspace \
  --artifact-dir /tmp/libcrafter-appliance/lan-raw \
  --env LIBCRAFTER_IFACE=lan-doc0 \
  -- \
  sh -lc 'printf "lan-raw dry-run for 198.51.100.10\n" > /artifacts/summary.txt'
```

`whad-serial` plan:

```sh
tools/appliance/run run-plan \
  --profile whad-serial \
  --work-dir /home/operator/libcrafter-workspace \
  --artifact-dir /tmp/libcrafter-appliance/whad-serial \
  --env LIBCRAFTER_WHAD_DEVICE=/dev/ttyACM0 \
  -- \
  sh -lc 'printf "whad-serial readiness plan only\n" > /artifacts/summary.txt'
```

`dot11-monitor` plan:

```sh
tools/appliance/run run-plan \
  --profile dot11-monitor \
  --work-dir /home/operator/libcrafter-workspace \
  --artifact-dir /tmp/libcrafter-appliance/dot11-monitor \
  --env LIBCRAFTER_DOT11_IFACE=dot11mon-doc \
  --env LIBCRAFTER_DOT11_CHANNEL=6 \
  -- \
  sh -lc 'printf "dot11 monitor readiness plan only\n" > /artifacts/summary.txt'
```

## SSH Docker Hosts

An SSH Docker host is any reachable Linux machine where the operator account can
run Docker. QEMU, VirtualBox, Hetzner, and generic SSH assets all normalize to
this shape once a machine is reachable over SSH.

Endpoint appliance planning uses endpoint manifests or asset leases:

```sh
tools/endpoint/run appliance check --dry-run --json ENDPOINT_ID wan-raw
tools/endpoint/run appliance plan --dry-run --json ENDPOINT_ID wan-raw -- \
  sh -lc 'printf "endpoint appliance dry-run\n" > /artifacts/summary.txt'
```

The deploy plan checks Docker, creates remote work and artifact roots, inspects
the image, and plans image build or load when needed. Workspace sync archives
the repository, excludes generated state and artifacts, uploads the archive,
and unpacks it under a run-specific remote workspace. Remote runs mount the
workspace at `/work` and the remote artifact directory at `/artifacts`.

Omitting `--dry-run` from `deploy`, `run`, or `collect` performs SSH, SCP,
Docker, or artifact download operations. That is an operator action, not an
automatic packet live gate; the workload inside the appliance must still keep
its own dry-run or live confirmation flags.

## Provider Substrates

QEMU, VirtualBox, and Hetzner endpoint providers attach appliance metadata to
their endpoint manifests so the same endpoint appliance commands can run
against each substrate.

- Local Docker is for local plan rendering and constrained direct Docker
  endpoint modes. Docker endpoint containers do not mount the Docker socket and
  do not become nested Docker hosts unless metadata explicitly marks them
  appliance-capable.
- Generic SSH Docker hosts use an existing machine that already has SSH and
  Docker. They are registered as persistent assets with substrate `ssh-docker`
  or `generic-ssh`.
- QEMU can provide disposable private endpoints or persistent prepared local VM
  assets. VM preparation owns disks, networking, USB passthrough, and any
  hardware-specific setup.
- VirtualBox can provide bridged LAN endpoints or persistent prepared VM
  assets. VM preparation owns bridged interface selection and USB filter setup.
- Hetzner can provide disposable WAN or private endpoints. Credentials are read
  from `HETZNER_API_TOKEN` or `HCLOUD_TOKEN` in the operator environment and
  must never appear in tracked files or command examples.

Safe provider dry-runs:

```sh
tools/endpoint/run create --provider qemu --exposure private --private-cidr 192.0.2.0/24 --private-ip 192.0.2.10 --dry-run --json
tools/endpoint/run create --provider virtualbox --exposure lan --dry-run --json
tools/endpoint/run create --provider hetzner --exposure wan --dry-run --json
```

Live endpoint creation requires `--confirm-live-run` and a disposable target.
Run provider-backed packet validation through oracle or probe whenever a
multi-endpoint workload is involved.

## Persistent Assets And Leases

Persistent assets represent prepared local VMs, dongle machines, or generic SSH
Docker hosts that can be reused across sessions. Asset records live under the
ignored endpoint state root, not in tracked source files. They store substrate,
supported profiles, SSH coordinates, Docker command metadata, hardware
readiness summaries, last check state, and optional profile environment
overrides.

Register a documentation-safe WHAD VM asset:

```sh
tools/endpoint/run asset register doc-whad-vm \
  --substrate qemu \
  --profile whad-serial \
  --ssh-host 192.0.2.44 \
  --ssh-user appliance \
  --identity-file /home/operator/.ssh/libcrafter_doc_key \
  --known-hosts-file /home/operator/.ssh/libcrafter_doc_known_hosts \
  --metadata-json '{"appliance":{"profile_environments":{"whad-serial":{"LIBCRAFTER_WHAD_DEVICE":"/dev/ttyACM0"}}}}' \
  --json
```

Check and lease an asset:

```sh
tools/endpoint/run asset check doc-whad-vm --profile whad-serial --json
tools/endpoint/run asset acquire --profile whad-serial --lease-ttl 2h --owner doc-operator --json
tools/endpoint/run appliance plan --dry-run --json --lease LEASE_ID whad-serial -- \
  sh -lc 'printf "leased asset dry-run\n" > /artifacts/summary.txt'
tools/endpoint/run asset release LEASE_ID --json
```

Leases use per-asset file locks and TTLs so two sessions do not use the same
prepared dongle or VM at the same time. Release leases when the run is finished;
expired leases can be recovered by later acquire operations.

## Checks

Profile checks are readiness checks and plans, not packet workloads. Common
checks include Docker daemon access, selected interface presence, raw socket
permission, pcap open, LAN reachability planning, serial device presence, WHAD
discovery, monitor-mode interface validation, and a gated dot11 injection smoke
plan.

```sh
tools/endpoint/run appliance check --dry-run --json ENDPOINT_ID dot11-monitor
tools/endpoint/run asset check doc-whad-vm --profile whad-serial --json
```

Asset checks may contact the prepared host over SSH to verify Docker access, but
they do not transmit packets. RF checks report required devices, interfaces,
privileges, host preparation, and live-gate requirements without committing
real hardware identifiers.

## Artifacts

Appliance artifacts are local by default and ignored by the repository. Endpoint
appliance runs record deploy logs, sync archive logs, run stdout and stderr,
run metadata, collected remote artifacts, and optional cleanup logs. Remote
workspace and artifact roots default to appliance-specific directories such as
`/var/tmp/libcrafter-appliance/work` and
`/var/tmp/libcrafter-appliance/artifacts`, with run-specific subdirectories.

Collect remote artifacts only after an intentional run:

```sh
tools/endpoint/run appliance collect --dry-run --json ENDPOINT_ID wan-raw
```

Do not commit provider account data, public addresses, real host identifiers,
hardware serials, SSIDs, credentials, or packet captures from sensitive
networks. Promote only sanitized, synthetic artifacts that are meant to become
fixtures.

## Dry-Run Defaults And Live Gates

Start with plan output:

- `tools/appliance/run run-plan` renders a local Docker command plan and does
  not execute Docker.
- `tools/endpoint/run appliance plan --dry-run` renders deploy, sync, and run
  plans and does not run SSH, SCP, Docker, or tar.
- Oracle, probe, lab, and endpoint provider dry-runs create no infrastructure
  and send no packets.

Live gates remain explicit:

- Endpoint and lab provider creation require `--confirm-live-run`.
- Oracle and probe live provider runs require `--confirm-live-run`.
- RF transmit tools should keep their own `--live` and isolated-lab
  acknowledgement flags, plus any backend environment marker documented by the
  corresponding live manual.
- Removing `--dry-run` from endpoint appliance `run`, `deploy`, or `collect`
  performs the mechanical remote operation only; it does not waive the
  workload's packet or RF live gate.

Use documentation address space, placeholder interfaces, placeholder paths, and
synthetic payloads in tracked examples. Put real targets, credentials, host
names, hardware identifiers, RF settings, and local captures only in ignored
operator configuration or disposable provider state.
