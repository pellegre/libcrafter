# Libcrafter Wire

`tools/wire` is the shared endpoint layer for live provider work. It creates,
tracks, uses, and destroys one runnable endpoint at a time for callers such as
`tools/oracle`, `tools/probe`, and agents.

`tools/wire` owns only mechanical endpoint lifecycle:

- creating and destroying provider resources
- recording provider cleanup metadata
- executing commands over SSH
- uploading and downloading files
- collecting endpoint artifacts
- reporting SSH connection details for debugging

`tools/oracle` and `tools/probe` own workload semantics. Packet correctness,
backend comparison, reference tool behavior, probe case generation, expected
responses, reports, and reproduction coordinates must stay in those tools, not
in `tools/wire`.

## Terms

- Provider: the system that creates the endpoint, such as `hetzner`,
  `virtualbox`, or `qemu`.
- Exposure: where the endpoint is placed on the wire, such as `wan`, `lan`,
  `private`, or `wifi`.
- Endpoint: one runnable machine with SSH access, a manifest, local identity
  files, local state, artifacts, and enough provider metadata to destroy it
  after partial failures.
- Artifact: local diagnostic output produced while creating, using, or
  destroying an endpoint, such as logs, manifests, request files, response
  files, and collected remote files.

Every public request names a provider, exposure, and endpoint intent
explicitly. `tools/wire` does not select providers automatically and does not
hide the real machine behind a topology abstraction.

## Supported Pairs

| Provider | Exposure | Status |
| --- | --- | --- |
| `hetzner` | `wan` | Supported public VPS path |
| `hetzner` | `private` | Supported for controlled oracle/probe endpoint exchange |
| `virtualbox` | `lan` | Supported bridged LAN VM with its own guest IP and MAC |
| `qemu` | `wan` | Supported host-NAT outbound internet from a local VM |
| `qemu` | `private` | Supported local private VM segment keyed by `--private-group` |
| `hetzner` | `lan`, `wifi` | Rejected with an explicit incompatibility error |
| `virtualbox` | `wan`, `private`, `wifi` | Rejected until those paths are intentionally promoted |
| `qemu` | `lan`, `wifi` | Rejected until dongle/raw Wi-Fi support is promoted later |

For `private`, callers may pass a small private group string so separately
created endpoints attach to the same provider private network. The group is a
coordination key only; it is not a public topology or session object.

QEMU `wan` means the guest gets outbound internet through QEMU user networking
and host NAT. It is not a public IP, does not accept unsolicited inbound
internet traffic, and is not a replacement for a public VPS provider such as
Hetzner.

## Prerequisites

Common VM provider prerequisites:

- `ssh`, `scp`, and `ssh-keygen` on the host.
- `qemu-img` for VM disk conversion or overlays.
- `cloud-localds` from `cloud-image-utils` for NoCloud seed ISOs.
- Network access to download the Ubuntu Server 24.04 cloud image unless the
  endpoint-local cache already contains it.

VirtualBox LAN additionally requires `VBoxManage` on `PATH` and at least one
usable bridged interface reported by `VBoxManage list bridgedifs`. The created
guest uses two NICs: a NAT control NIC with SSH forwarded to `127.0.0.1`, and a
bridged LAN NIC for packet work on the local network.

QEMU additionally requires `qemu-system-x86_64`. QEMU defaults to TCG so it can
run without host root or KVM access. KVM is opt-in and only works on Linux hosts
with usable `/dev/kvm`; the doctor check also reports running VirtualBox VMs
because they can conflict with KVM acceleration.

Hetzner requires `hcloud` and either `HETZNER_API_TOKEN` or `HCLOUD_TOKEN`.

Run provider checks before live creation:

```sh
tools/wire/run doctor --provider virtualbox --exposure lan --json
tools/wire/run doctor --provider qemu --exposure wan --json
tools/wire/run doctor --provider qemu --exposure private --json
```

## Environment Overrides

| Variable | Used by | Meaning |
| --- | --- | --- |
| `LIBCRAFTER_WIRE_STATE_ROOT` | all providers | Override endpoint manifest and state root |
| `LIBCRAFTER_WIRE_ARTIFACT_ROOT` | all providers | Override endpoint artifact root |
| `LIBCRAFTER_WIRE_STATE_DIR` | all providers | Legacy state-root override |
| `LIBCRAFTER_WIRE_ARTIFACT_DIR` | all providers | Legacy artifact-root override |
| `LIBCRAFTER_WIRE_UBUNTU_CLOUD_IMAGE_URL` | VM providers | Override the Ubuntu cloud image URL |
| `LIBCRAFTER_VBOX_BRIDGE_IFACE` | VirtualBox LAN | Request a specific host bridge interface |
| `LIBCRAFTER_QEMU_ACCEL` | QEMU | `tcg` by default, or `kvm` on compatible Linux hosts |
| `LIBCRAFTER_QEMU_MEMORY_MB` | QEMU | Guest memory in MiB, default `2048` |
| `LIBCRAFTER_QEMU_CPUS` | QEMU | Guest vCPU count, default `2` |
| `LIBCRAFTER_QEMU_PRIVATE_CIDR` | QEMU private | Private segment CIDR, default `10.77.0.0/24` |
| `LAN_ROUTER` | VirtualBox smoke | Router target for the opt-in `network_ping` smoke |

## Endpoint Creation

Dry-runs plan an endpoint without creating provider resources:

```sh
tools/wire/run create-endpoint --provider virtualbox --exposure lan --dry-run --json
tools/wire/run create-endpoint --provider qemu --exposure wan --dry-run --json
tools/wire/run create-endpoint --provider qemu --exposure private --private-group lab-a --dry-run --json
```

Live creation is protected and requires `--confirm-live-run`:

```sh
tools/wire/run create-endpoint --provider virtualbox --exposure lan --confirm-live-run --json
tools/wire/run create-endpoint --provider qemu --exposure wan --confirm-live-run --json
tools/wire/run create-endpoint --provider qemu --exposure private --private-group lab-a --confirm-live-run --json
```

For real QEMU private endpoints, `--private-group` is required. `--private-ip`
is optional and requests a specific IPv4 inside the configured private CIDR.

Unsupported QEMU LAN and Wi-Fi requests fail before provider side effects:

```sh
tools/wire/run create-endpoint --provider qemu --exposure lan --dry-run --json
tools/wire/run create-endpoint --provider qemu --exposure wifi --dry-run --json
```

Those commands return an unsupported provider/exposure error because QEMU LAN,
USB dongle, monitor mode, raw Wi-Fi, and 802.11 injection are not part of this
phase.

## Endpoint Operations

Every operation uses the stored manifest for the endpoint ID returned by
`create-endpoint`. Upload and download paths must be absolute on both sides.

```sh
tools/wire/run list-endpoints
tools/wire/run ssh-info <endpoint_id>
tools/wire/run exec <endpoint_id> -- uname -a
tools/wire/run upload <endpoint_id> /absolute/local/path /absolute/remote/path
tools/wire/run download <endpoint_id> /absolute/remote/path /absolute/local/path
tools/wire/run collect-artifacts <endpoint_id>
tools/wire/run destroy-endpoint <endpoint_id>
```

`exec` writes `stdout` and `stderr` artifacts under the endpoint artifact
directory. Transfers write `upload.*` or `download.*` artifacts. Destroy is
idempotent where provider state allows it and preserves local state and
artifacts for debugging.

## VirtualBox LAN Smoke

The VirtualBox LAN `network_ping` smoke is opt-in because it creates a VM and
sends one live ICMP echo request on the local LAN. Inspect the command sequence
without side effects:

```sh
python3 tools/wire/smoke/live_virtualbox_network_ping.py --plan-only
```

Run it only in an isolated lab where live LAN traffic is expected:

```sh
LAN_ROUTER=192.168.0.1 \
python3 tools/wire/smoke/live_virtualbox_network_ping.py \
  --live \
  --i-understand-isolated-lab
```

The smoke creates a VirtualBox LAN endpoint, builds
`cargo build -p crafter --example network_ping`, uploads the binary, runs it
with `LIBCRAFTER_WIRE_ENDPOINT=1`, collects guest state, and destroys the
endpoint in a `finally` path. Step stdout, stderr, and JSON reports are written
to the endpoint artifact directory. If creation fails before an endpoint
artifact directory exists, failure artifacts are written below
`tools/wire/artifacts/live-virtualbox-network-ping/`.

## Local State

Endpoint manifests must use absolute paths for identity files, state files,
artifact directories, and local request or response files. They must also carry
enough lifecycle metadata for idempotent destroy operations after failed or
partial creates.

Generated local files live below ignored paths:

```text
tools/wire/.state/
tools/wire/artifacts/
```

Do not put provider state, private keys, account identifiers, public host
identifiers, credentials, personal network names, or personal defaults in
tracked files or normal documentation examples.
