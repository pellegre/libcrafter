# Oracle Live Protocol

This document defines the live validation contract for `tools/oracle/run live`.
The oracle runner owns the live report, packet plan, backend capability checks,
and reproduction coordinates. `tools/wire` owns disposable endpoint lifecycle
and artifact collection.

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
registered under `tools/oracle/engine/providers/`. The `--provider` name selects
an oracle-side adapter, not direct branches in packet generation or report
assembly. The adapter owns provider-specific capabilities, endpoint plans,
wire lifecycle command plans, endpoint bootstrap commands, remote endpoint
commands, and provider transit/comparison policy.

The generic oracle runner keeps ownership of packet plan generation, endpoint
protocol batching, repository archiving, upload/download orchestration,
response parsing, comparison, and live report assembly. Adding another
provider-backed oracle live mode should mean registering another adapter for
that provider name. It should not require edits to packet generation, endpoint
protocol comparison, report assembly, or the generic provider execution flow.

`local-dry-run` is intentionally separate from this provider-backed adapter
registry. It is a CI-safe planning mode that does not create wire endpoints and
does not represent a provider-backed live exchange.

The current provider-backed adapters share the same oracle execution path:

| Oracle provider | Wire provider | Wire exposure | Packet exchange |
| --- | --- | --- | --- |
| `hetzner` | `hetzner` | `private` | Routed private cloud segment |
| `qemu` | `qemu` | `private` | Local private VM segment `oracle-live-private` |
| `virtualbox` | `virtualbox` | `lan` | Bridged LAN guest interface |

Run the three-provider planning matrix without side effects before creating
infrastructure:

```sh
python3 tools/oracle/tests/live_provider_matrix.py --providers hetzner,qemu,virtualbox --backend scapy --profile smoke --seed 12345 --count 5 --dry-run --out target/oracle/provider-matrix-dry-run
```

Run guarded real VM smoke to verify the local VM prerequisites and matrix
reporting path:

```sh
python3 tools/oracle/tests/live_provider_matrix.py --providers qemu,virtualbox --backend scapy --profile smoke --seed 12345 --count 2 --real --skip-unavailable --out target/oracle/provider-matrix-vm-real
```

The real VM matrix runs provider doctors first, skips unavailable VM providers
by default, and also skips actual VM creation unless `--allow-vm-create` or
`LIBCRAFTER_ORACLE_VM_SMOKE_ALLOW_CREATE=1` is set. When VM creation is allowed,
the matrix records doctor output, live report paths, endpoint lifecycle
metadata, artifact roots, endpoint IDs, and cleanup status in
`matrix-summary.json`. Use `--strict-vm-smoke` or
`LIBCRAFTER_ORACLE_VM_SMOKE_STRICT=1` for lab qualification where skips should
fail the command.

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

`tools/wire` remains the owner of disposable endpoint lifecycle and artifact
transport. An oracle live provider adapter maps oracle roles and provider
policy onto `tools/wire` commands; it does not replace the wire provider
implementation.

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
