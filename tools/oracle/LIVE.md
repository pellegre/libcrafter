# Oracle Live Protocol

This document defines the live validation contract for `tools/oracle/run live`.
The oracle runner owns the live report, packet plan, backend capability checks,
and reproduction coordinates. `tools/lab` owns multi-endpoint provider
sessions, repository push/bootstrap, artifact collection, and cleanup.
`tools/endpoint` owns one endpoint and transport operations.

## Live Mode Invariant

Oracle live validation requires two communicating endpoints. A test that only
writes and reads packets on one machine, loopback interface, or shared network
namespace may be useful as a smoke check, but it is not a complete oracle live
exchange.

Each live run must create or select at least these endpoint roles:

| Role | Purpose |
| --- | --- |
| `libcrafter` | Runs libcrafter-built send, receive, decode, or capture commands. This endpoint is the Rust side of the exchange. |
| `reference_backend` | Runs the selected reference backend. With `--backend scapy`, this endpoint sends, receives, decodes, or captures packets through Scapy-owned tooling. |

The roles must run in separate isolated instances or network namespaces with a
private route between them. A provider may place both roles on one physical host
only when the isolation boundary gives each role its own network namespace and
virtual interface pair.

## Oracle Live Provider Adapters

Provider-backed live mode is selected through oracle live provider adapters
registered under `tools/oracle/engine/providers/`. The `--provider` name
selects an oracle-side adapter, not direct branches in packet generation or
report assembly. The adapter owns oracle-specific capabilities and provider
transit/comparison policy while delegating endpoint topology and lifecycle to
`tools/lab`.

The generic oracle runner keeps ownership of packet plan generation, endpoint
protocol batching, repository archiving, upload/download orchestration,
response parsing, comparison, and live report assembly. Adding another
provider-backed oracle live mode should mean registering a lab provider adapter
and an oracle policy adapter for that provider name. It should not require
edits to packet generation, endpoint protocol comparison, report assembly, or
the generic provider execution flow.

`local-dry-run` is intentionally separate from this provider-backed adapter
registry. It is a CI-safe planning mode that does not create endpoints and
does not represent a provider-backed live exchange.

The current provider-backed adapters share the same oracle execution path:

| Oracle provider | Wire provider | Wire exposure | Packet exchange |
| --- | --- | --- | --- |
| `hetzner` | `hetzner` | `private` | Routed private cloud segment |
| `docker` | `docker` | `private` | Local container bridge |
| `qemu` | `qemu` | `private` | Local private VM segment `oracle-live-private` |
| `virtualbox` | `virtualbox` | `lan` | Bridged LAN guest interface |

Run the three-provider planning matrix without side effects before creating
infrastructure:

```sh
tools/lab/run plan --provider hetzner --dry-run --profile smoke --seed 12345 --role libcrafter --role reference_backend --json
python3 tools/oracle/engine/live_provider_matrix.py --providers hetzner,qemu,virtualbox --backend scapy --profile smoke --seed 12345 --count 5 --dry-run --out target/oracle/provider-matrix-dry-run
```

Run guarded real VM smoke to verify the local VM prerequisites and matrix
reporting path:

```sh
python3 tools/oracle/engine/live_provider_matrix.py --providers qemu,virtualbox --backend scapy --profile smoke --seed 12345 --count 2 --real --skip-unavailable --confirm-live-run --out target/oracle/provider-matrix-vm-real
```

The real VM matrix runs provider doctors first, skips unavailable VM providers
by default, and also skips actual VM creation unless `--allow-vm-create` or
`LIBCRAFTER_ORACLE_VM_SMOKE_ALLOW_CREATE=1` is set. When VM creation is allowed,
the matrix records doctor output, live report paths, endpoint lifecycle
metadata, artifact roots, endpoint IDs, and cleanup status in
`matrix-summary.json`. Use `--strict-vm-smoke` or
`LIBCRAFTER_ORACLE_VM_SMOKE_STRICT=1` for lab qualification where skips should
fail the command.

`--real` is a protected confirmation gate: it refuses to run and creates no
infrastructure unless `--confirm-live-run` is also passed. `--dry-run` never
sends packets and never requires `--confirm-live-run`. This keeps real live
exchange opt-in while leaving dry-run planning unconditionally safe.

## IGMP Live Exchange Shape

IGMP live validation is a packet-equivalence smoke for IPv4 protocol 2 traffic.
It is not a multicast router, snooper, proxy, scanner, or IGMP state-machine
test. The packet corpus stays rooted at IPv4/IGMP through `--family igmp` and
the `igmp-live-dry-run` profile, which keeps ordinary validation dry-run and
offline-safe unless a protected provider gate is explicitly enabled.

Use the provider matrix in dry-run mode first. This creates no endpoints and
sends no packets:

```sh
python3 tools/oracle/engine/live_provider_matrix.py --providers qemu,docker,virtualbox --backend scapy --family igmp --profile igmp-live-dry-run --seed 3601 --count 2 --dry-run --out target/oracle/igmp-vm-live-dry-run
```

### Guarded IGMP VM/Docker Live Exchange

The real local-provider smoke path is intentionally wrapped in an environment
gate so unattended acceptance takes the skip branch. The enabled path still
requires `--confirm-live-run`, runs provider doctor checks first, skips
unavailable providers through `--skip-unavailable`, validates the live report's
capability, artifact, lifecycle, and teardown metadata, and writes all run
artifacts below an ignored `target/oracle/` directory:

```sh
if [ "${LIBCRAFTER_RUN_IGMP_VM_LIVE:-0}" = "1" ]; then
  python3 tools/oracle/engine/live_provider_matrix.py \
    --providers qemu,docker,virtualbox --backend scapy \
    --family igmp --profile igmp-live-dry-run \
    --seed 3601 --count 2 \
    --real --skip-unavailable --confirm-live-run \
    --out target/oracle/igmp-vm-live
else
  echo "skipping protected IGMP VM live run"
fi
```

For the IGMP family, `LIBCRAFTER_RUN_IGMP_VM_LIVE=1` is the family-specific
approval for QEMU and VirtualBox VM creation in this guarded matrix. The generic
`--allow-vm-create` and `LIBCRAFTER_ORACLE_VM_SMOKE_ALLOW_CREATE=1` controls
remain available for other VM smoke runs. Do not commit endpoint IDs, provider
account data, public IPs, live host identifiers, or packet captures from this
run; keep them under the requested `--out` path and rely on the matrix summary
for structured skip/pass evidence.

### Guarded IGMP Hetzner Live Exchange

The real Hetzner smoke path uses the same focused IPv4/IGMP packet corpus, but
runs through `tools/oracle/run live --provider hetzner` so the endpoint provider
owns provisioning, artifact collection, and teardown. Always plan the Hetzner
path with `--dry-run` first; that command creates no cloud endpoints and sends
no packets:

```sh
tools/oracle/run live --backend scapy --provider hetzner --dry-run --family igmp --profile igmp-live-dry-run --seed 3602 --count 2 --direction live_exchange --out target/oracle/igmp-hetzner-dry-run
```

Keep the real Hetzner path behind an IGMP-specific environment gate so
unattended acceptance takes the skip branch:

```sh
if [ "${LIBCRAFTER_RUN_IGMP_HETZNER_LIVE:-0}" = "1" ]; then
  tools/oracle/run live \
    --backend scapy --provider hetzner --family igmp \
    --profile igmp-live-dry-run --seed 3602 --count 2 \
    --direction live_exchange --confirm-live-run \
    --out target/oracle/igmp-hetzner-live
else
  echo "skipping protected IGMP Hetzner live run"
fi
```

With `LIBCRAFTER_RUN_IGMP_HETZNER_LIVE` unset, no command beyond the echo branch
runs. When it is `1`, the live runner still refuses non-dry-run provider
execution without `--confirm-live-run`, and the Hetzner provider reads
credentials only from `HETZNER_API_TOKEN` or `HCLOUD_TOKEN`. Confirmed runs
provision disposable private Hetzner lab endpoints, execute the libcrafter and
Scapy reference-backend roles over that lab network, collect artifacts under
`target/oracle/igmp-hetzner-live`, and tear endpoints down on success, skip, or
failure. Keep endpoint IDs, account data, public IPs, live host identifiers, and
captures in the ignored `target/` artifact tree, not tracked files.

## DHCP Live Exchange Shape

Live DHCP validation is a one-way packet-equivalence exchange, not a DHCP
client, server, lease negotiation, or reply workflow. The packet under test is
the `ipv4 / udp / dhcp` stack (root `l3:ipv4`, UDP ports 68 to 67), selected
with `--case dhcp-discover`. It runs in both standard directions:

- `libcrafter_to_reference`: libcrafter sends the DHCP packet, the reference
  backend captures and decodes it.
- `reference_to_libcrafter`: the reference backend sends the DHCP packet,
  libcrafter captures and decodes it.

Each direction sends one DHCP packet and compares the receiver's normalized
decoded model. No DHCP reply is expected and no lease state is established.
Because the packet is rooted at IPv4 unicast, it is wire-eligible without
Ethernet framing, link-layer broadcast, or provider MAC discovery. The
`ethernet / ipv4 / udp / dhcp` stack (root `link:ethernet`) is reserved for
offline/link-layer/pcap coverage and stays link-layer-gated for live runs
(`requires_l2`, `requires_provider_mac`, `requires_broadcast`).

Scapy is the live reference backend. Wireshark/tshark is parser-only and never
acts as a live endpoint for DHCP.

### Guarded DHCP VM Live Exchange

DHCP live exchange (the `ipv4 / udp / dhcp` packet, selected with
`--case dhcp-discover`) runs through the same guarded VM matrix. Keep it opt-in
behind an explicit environment gate so unattended CI never sends real DHCP
packets or creates VMs:

```sh
if [ "${LIBCRAFTER_RUN_DHCP_VM_LIVE:-0}" = "1" ]; then
  python3 tools/oracle/engine/live_provider_matrix.py \
    --providers qemu,virtualbox --backend scapy --profile smoke \
    --seed 132 --count 2 --case dhcp-discover \
    --real --skip-unavailable --allow-vm-create --confirm-live-run \
    --out target/oracle/dhcp-vm-live
else
  echo "skipping protected VM DHCP live run; set LIBCRAFTER_RUN_DHCP_VM_LIVE=1 to execute"
fi
```

With `LIBCRAFTER_RUN_DHCP_VM_LIVE` unset (the default), the gate takes the
echo-skip branch and nothing runs. When it is `1`, the matrix runs provider
doctors first, skips any unavailable VM provider cleanly, refuses to send
packets without `--confirm-live-run`, creates VMs only because
`--allow-vm-create` is present, collects artifacts under `--out`, and tears the
endpoints down. Always validate the focused DHCP path with `--dry-run` first:

```sh
python3 tools/oracle/engine/live_provider_matrix.py --providers qemu,virtualbox --backend scapy --profile smoke --seed 132 --count 2 --case dhcp-discover --dry-run --out target/oracle/dhcp-vm-dry-run
```

### Guarded DHCP Hetzner Live Exchange

The same `ipv4 / udp / dhcp` packet (selected with `--case dhcp-discover`) runs
against Hetzner private cloud networking through `tools/oracle/run live
--provider hetzner`. Hetzner is a routed private cloud segment: the DHCP packet
under test is wire-eligible there because it is IPv4 unicast, while the
Ethernet-root DHCP stack stays skipped for `requires_l2` and
`requires_provider_mac`. Always plan the focused DHCP path with `--dry-run`
first; it creates no cloud resources and sends no packets:

```sh
tools/oracle/run live --backend scapy --provider hetzner --dry-run --profile smoke --seed 133 --count 2 --case dhcp-discover --out target/oracle/dhcp-hetzner-dry-run
```

Keep the real Hetzner live run opt-in behind an explicit environment gate so
unattended CI never provisions cloud endpoints or sends real DHCP packets:

```sh
if [ "${LIBCRAFTER_RUN_DHCP_HETZNER_LIVE:-0}" = "1" ]; then
  tools/oracle/run live \
    --backend scapy --provider hetzner --profile smoke \
    --seed 133 --count 2 --case dhcp-discover \
    --confirm-live-run \
    --out target/oracle/dhcp-hetzner-live
else
  echo "skipping protected Hetzner DHCP live run; set LIBCRAFTER_RUN_DHCP_HETZNER_LIVE=1 to execute"
fi
```

With `LIBCRAFTER_RUN_DHCP_HETZNER_LIVE` unset (the default), the gate takes the
echo-skip branch and nothing runs. When it is `1`, the run still refuses to
exchange packets unless `--confirm-live-run` is passed, and it refuses again
unless Hetzner credentials are present in the environment: the endpoint provider
reads `HETZNER_API_TOKEN` or `HCLOUD_TOKEN`. Credentials are never hardcoded,
committed, or written to tracked files. When confirmed and credentialed, the
run provisions disposable Hetzner endpoints, runs the libcrafter and
reference-backend roles over the private cloud segment, collects artifacts under
`--out`, and tears the endpoints down on success or failure. Do not record
provider account data, public IPs, host IDs, or captures from the live run in
tracked files; keep those artifacts under `--out` (an ignored `target/` path).

## Exchange Directions

Live reports use the same backend-neutral direction names as offline and pcap
reports.

### `libcrafter_to_reference`

The `libcrafter` endpoint is the sender. It materializes a generated packet plan
with libcrafter, transmits it on the private test interface, and records sender
logs. The `reference_backend` endpoint is the receiver. It captures the packet,
decodes it with the backend, and emits a normalized decoded observation.

The exchange passes when the received observation satisfies the selected live
feature spec, including stack, field, payload, direction, and strict byte rules
where those rules apply.

### `reference_to_libcrafter`

The `reference_backend` endpoint is the sender. It materializes the generated
packet plan with the selected backend, transmits it on the private test
interface, and records sender logs. The `libcrafter` endpoint is the receiver.
It captures or decodes the packet with libcrafter and emits a normalized decoded
observation.

The exchange passes when libcrafter observes the packet behavior declared by the
spec and the normalized model compares cleanly with the reference expectation.

### Bidirectional Protocol Flows

Some live behavior is naturally bidirectional, such as request/reply traffic or
stateful setup before the packet under test. These flows are represented as a
`live_exchange` made of ordered phases. Each phase declares:

- `phase`: stable phase name.
- `direction`: `libcrafter_to_reference` or `reference_to_libcrafter`.
- `sender_role`: `libcrafter` or `reference_backend`.
- `receiver_role`: the opposite endpoint role.
- `packet_plan`: generated plan or response expectation for this phase.
- `timeout_ms`: maximum wait time for the receiver observation.
- `expected_observation`: normalized model constraints for the receiver.

Bidirectional flows must still identify which phase failed and must preserve the
artifacts for all phases needed to reproduce the failure.

## Provider Capabilities

A provider that claims live support must expose these capabilities to the oracle
runner through its oracle live provider adapter:

- Create at least two isolated instances or network namespaces.
- Assign the `libcrafter` role to one endpoint and `reference_backend` to the
  other endpoint.
- Install, build, or expose the Rust toolchain and libcrafter commands on the
  `libcrafter` endpoint.
- Install or bootstrap Scapy on the `reference_backend` endpoint when the
  selected backend is `scapy`.
- Set up private networking between the two endpoints, including interface names
  and addresses visible to both roles.
- Run commands on each endpoint with captured stdout, stderr, exit status, and
  start/end timestamps.
- Collect artifacts from each endpoint after success or failure.
- Run teardown after success or failure, including failed setup, failed command
  execution, timeout, or artifact collection errors.

If credentials or provider resources are unavailable, the provider should return
a clear skipped report. It must not silently downgrade a live run into a
single-endpoint loopback test.

`tools/lab` remains the owner of disposable multi-endpoint session lifecycle,
repository push/bootstrap, artifact collection, and cleanup. `tools/endpoint`
remains the owner of one endpoint and artifact transport. An oracle live
provider adapter maps oracle roles and comparison policy onto lab sessions; it
does not replace the lab or endpoint provider implementation.

## Backend Capabilities

Live mode requires a backend capability set with `encode`, `decode`, and
`live_endpoint`. Scapy provides those capabilities and is the supported live
reference backend. Scapy live code is centralized under
`tools/oracle/engine/backends/scapy/`.

Wireshark/tshark is parser-only. It can participate in decode and pcap-read
oracle checks, but it cannot materialize live packet sends, write pcaps, or run
as `reference_backend` for `tools/oracle/run live`.

## Live Artifact Schema

Live artifacts are written under the selected `--out` directory, defaulting to
`target/oracle/live`. The report should reference artifact paths rather than
embedding large logs or capture files inline.

Each exchange stores a JSON-compatible artifact record:

```json
{
  "mode": "live",
  "backend": "scapy",
  "provider": "hetzner",
  "profile": "smoke",
  "seed": 1,
  "count": 10,
  "index": 0,
  "direction": "libcrafter_to_reference",
  "endpoints": {
    "libcrafter": {
      "endpoint_id": "node-a",
      "role": "libcrafter",
      "interface": "eth1",
      "address": "10.10.0.10"
    },
    "reference_backend": {
      "endpoint_id": "node-b",
      "role": "reference_backend",
      "interface": "eth1",
      "address": "10.10.0.11"
    }
  },
  "packet_plan": {},
  "sender": {
    "role": "libcrafter",
    "command": [],
    "exit_status": 0,
    "stdout_path": "artifacts/000/sender.stdout.log",
    "stderr_path": "artifacts/000/sender.stderr.log"
  },
  "receiver": {
    "role": "reference_backend",
    "command": [],
    "exit_status": 0,
    "stdout_path": "artifacts/000/receiver.stdout.log",
    "stderr_path": "artifacts/000/receiver.stderr.log"
  },
  "captures": [
    {
      "role": "reference_backend",
      "path": "artifacts/000/receiver.pcap",
      "link_type": "ethernet"
    }
  ],
  "observations": [
    {
      "role": "reference_backend",
      "decoded_model": {}
    }
  ],
  "teardown": {
    "attempted": true,
    "status": "passed",
    "logs": []
  }
}
```

Required live artifact fields:

- Generated packet plan: stored as `packet_plan` with profile, seed, index,
  stack, fields, feature tags, direction, and strictness.
- Sender logs: command line, stdout, stderr, exit status, timing, and endpoint
  role for the sender.
- Receiver logs: command line, stdout, stderr, exit status, timing, and endpoint
  role for the receiver.
- Capture files when available: pcap or pcapng paths, link type, capture role,
  and timestamp policy.
- Normalized decoded observations: `DecodedModel` records for each receiver or
  protocol phase, plus backend-native diagnostics only under metadata.
- Teardown result: whether teardown ran, whether it succeeded, and paths to
  teardown logs when cleanup fails.

Artifacts for failed runs must be retained even when successful live runs would
normally clean intermediate files.
