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

BLE advertising coverage is intentionally limited to this dry-run boundary in
the oracle. The `smoke` corpus includes a BLE advertising plan so
`local-dry-run` records that no network provider owns BLE radio traffic, and
the plan is skipped for provider-backed exchange rather than transmitted. Real
on-air BLE validation belongs to the ignored `.scratch/ble-whad-smoke` WHAD
dongle harness, not to the Hetzner, QEMU, or VirtualBox live providers.

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

## SSDP Live Exchange Shape

SSDP live validation is a bounded packet-equivalence exchange for UDP-carried
SSDP discovery payloads. It is not a discovery scan, service cache, UPnP control
point, retry workflow, or device daemon. The SSDP oracle corpus is selected with
`--family ssdp`; source-backed packet facts remain owned by the SSDP oracle
specs and source documents, while live execution remains provider-backed and
explicitly confirmed.

Start with the local dry-run path. This command generates the SSDP live plan,
validates backend and provider policy, writes the local report under the default
oracle target directory, creates no endpoints, and sends no packets:

```sh
tools/oracle/run live --backend scapy --provider local-dry-run --dry-run --family ssdp --profile smoke --seed 1905 --count 3
```

Inspect the dry-run report before any protected run. The report should show
`live_packet_exchange: false`, local-dry-run endpoint metadata, SSDP packet
plans with UDP/1900 application payloads, selected backend capabilities, skip
reasons for live-ineligible cases, and artifact paths under `target/oracle/`.
Do not promote a real run until the report identifies only authorized SSDP
cases and no local-machine live traffic.

### Guarded SSDP VM/Docker Live Exchange

Run provider matrix planning first for the local providers. The dry-run matrix
does not create containers or VMs and does not send multicast or unicast SSDP
traffic:

```sh
python3 tools/oracle/engine/live_provider_matrix.py \
  --providers qemu,docker,virtualbox --backend scapy \
  --family ssdp --profile smoke \
  --seed 1905 --count 3 \
  --dry-run \
  --out target/oracle/ssdp-provider-matrix-dry-run
```

Keep real local-provider SSDP exchange behind an SSDP-specific environment gate
and the generic live confirmation flag. The enabled path runs provider doctors,
skips unavailable providers cleanly, records provider capabilities and endpoint
metadata, collects artifacts from each role, and tears down created endpoints:

```sh
if [ "${LIBCRAFTER_RUN_SSDP_VM_LIVE:-0}" = "1" ]; then
  python3 tools/oracle/engine/live_provider_matrix.py \
    --providers qemu,docker,virtualbox --backend scapy \
    --family ssdp --profile smoke \
    --seed 1905 --count 3 \
    --real --skip-unavailable --allow-vm-create --confirm-live-run \
    --out target/oracle/ssdp-vm-live
else
  echo "skipping protected SSDP VM/Docker live run; set LIBCRAFTER_RUN_SSDP_VM_LIVE=1 to execute"
fi
```

### Guarded SSDP Hetzner Live Exchange

Always plan the cloud-provider path with `--dry-run` before provisioning any
cloud endpoint. The planning command creates no infrastructure and sends no
packets:

```sh
tools/oracle/run live \
  --backend scapy --provider hetzner --dry-run \
  --family ssdp --profile smoke \
  --seed 1906 --count 3 \
  --out target/oracle/ssdp-hetzner-dry-run
```

Keep the real Hetzner path behind a separate SSDP-specific environment gate.
When the gate is set, `--confirm-live-run` is still required and credentials
must come from `HETZNER_API_TOKEN` or `HCLOUD_TOKEN`:

```sh
if [ "${LIBCRAFTER_RUN_SSDP_HETZNER_LIVE:-0}" = "1" ]; then
  tools/oracle/run live \
    --backend scapy --provider hetzner \
    --family ssdp --profile smoke \
    --seed 1906 --count 3 \
    --confirm-live-run \
    --out target/oracle/ssdp-hetzner-live
else
  echo "skipping protected SSDP Hetzner live run; set LIBCRAFTER_RUN_SSDP_HETZNER_LIVE=1 to execute"
fi
```

Before considering a protected SSDP oracle run usable, inspect the provider
capability report, `metadata.lab_session` fields, endpoint role metadata,
packet plans, normalized observations, pcaps when present, command logs,
artifact index, and teardown result. The live report must show the
`libcrafter` and `reference_backend` roles, the selected provider and wire
exposure, SSDP-related capability or skip metadata, and teardown attempted on
success, skip, or failure. Keep endpoint IDs, provider account data, public IPs,
live host identifiers, and captures under the ignored `target/oracle/ssdp-*`
artifact roots; never copy them into tracked docs, fixtures, specs, or reports.

## mDNS IPv4 Live Exchange Shape

mDNS live validation is a bounded multicast DNS and DNS-SD packet exchange for
UDP/5353. It is not a LAN discovery scan, service browser, cache daemon, or
Bonjour-compatible responder. The mDNS oracle corpus is selected with
`--family mdns`; source-backed packet facts remain owned by the mDNS oracle
specs, while live execution remains provider-backed and explicitly confirmed.

Start with dry-runs. The local dry-run sends no packets, and the provider
dry-run adds lab session metadata, provider capabilities, endpoint roles,
command records, artifact roots, and wire eligibility:

```sh
tools/oracle/run live --backend scapy --provider local-dry-run --dry-run --family mdns --profile ci --seed 6766 --count 20 --direction live_exchange --out target/oracle/mdns-ipv4-local-dry-run
tools/oracle/run live --backend scapy --provider qemu --dry-run --family mdns --profile ci --seed 6766 --count 20 --direction live_exchange --out target/oracle/mdns-ipv4-qemu-dry-run
tools/oracle/run live --backend scapy --provider qemu --dry-run --family mdns --profile ci --seed 6767 --count 20 --direction live_exchange --out target/oracle/mdns-ipv6-qemu-dry-run
```

Inspect the reports before any protected run. The provider-backed report should
show `metadata.live_packet_exchange`, `metadata.provider_capabilities`,
`metadata.lab_session`, endpoint role metadata, skip reasons such as
`requires_multicast`, `requires_l2`, `requires_provider_mac`, or
`requires_ipv6`, and artifact paths under the selected `target/oracle/mdns-*`
root. For IPv4-only acceptance, IPv6-required corpus entries may skip; supported
IPv4 entries must not be hidden as skips if packet build, decode, or comparison
fails.

IPv6 mDNS rides the link-local multicast destination `ff02::fb`. Before a
protected IPv6 run, the provider-backed report must make
`mdns_ipv6_multicast` / `mdns_ipv6_link_local_scope` eligibility explicit and
show whether a skip came from missing link-local scope metadata rather than from
a packet failure. Preserve the report and any wire-eligible corpus artifact
under an ignored `target/oracle/mdns-ipv6-*` root for review.

Keep real mDNS exchange behind mDNS-specific environment gates and the generic
live confirmation flag:

```sh
if [ "${LIBCRAFTER_RUN_MDNS_IPV4_LIVE:-0}" = "1" ]; then
  tools/oracle/run live \
    --backend scapy --provider qemu --family mdns \
    --profile ci --seed 6766 --count 20 \
    --direction live_exchange --confirm-live-run \
    --out target/oracle/mdns-ipv4-live
elif [ "${LIBCRAFTER_RUN_MDNS_IPV6_LIVE:-0}" = "1" ]; then
  tools/oracle/run live \
    --backend scapy --provider qemu --family mdns \
    --profile ci --seed 6767 --count 20 \
    --direction live_exchange --confirm-live-run \
    --out target/oracle/mdns-ipv6-live
else
  echo "skipping protected mDNS live run"
fi
```

When enabled, the live runner still refuses provider packet exchange without
`--confirm-live-run`. Confirmed runs must use disposable provider-backed
endpoints, collect artifacts from both roles, and tear endpoints down on
success, skip, or failure. Keep endpoint IDs, account data, public IPs, real
hostnames, live interface names, and packet captures in ignored `target/`
artifact paths only.

## DHCP Live Exchange Shape

Live DHCP validation is a one-way packet-equivalence exchange, not a DHCP
client, server, lease negotiation, or reply workflow. The packet under test is
the `ipv4 / udp / dhcpv4` stack (root `l3:ipv4`, UDP ports 68 to 67), selected
with `--case dhcpv4-discover`. It runs in both standard directions:

- `libcrafter_to_backend`: libcrafter sends the DHCPv4 packet, the reference
  backend captures and decodes it.
- `backend_to_libcrafter`: the reference backend sends the DHCPv4 packet,
  libcrafter captures and decodes it.

Each direction sends one DHCPv4 packet and compares the receiver's normalized
decoded model. No DHCPv4 reply is expected and no lease state is established.
Because the packet is rooted at IPv4 unicast, it is wire-eligible without
Ethernet framing, link-layer broadcast, or provider MAC discovery. The
`ethernet / ipv4 / udp / dhcpv4` stack (root `link:ethernet`) is reserved for
offline/link-layer/pcap coverage and stays link-layer-gated for live runs
(`requires_l2`, `requires_provider_mac`, `requires_broadcast`).

Scapy is the live reference backend. Wireshark/tshark is parser-only and never
acts as a live endpoint for DHCP.

### Guarded DHCP VM Live Exchange

DHCPv4 live exchange (the `ipv4 / udp / dhcpv4` packet, selected with
`--case dhcpv4-discover`) runs through the same guarded VM matrix. Keep it opt-in
behind an explicit environment gate so unattended CI never sends real DHCP
packets or creates VMs:

```sh
if [ "${LIBCRAFTER_RUN_DHCPV4_VM_LIVE:-0}" = "1" ]; then
  python3 tools/oracle/engine/live_provider_matrix.py \
    --providers qemu,virtualbox --backend scapy --profile smoke \
    --seed 132 --count 2 --case dhcpv4-discover \
    --real --skip-unavailable --allow-vm-create --confirm-live-run \
    --out target/oracle/dhcpv4-vm-live
else
  echo "skipping protected VM DHCPv4 live run; set LIBCRAFTER_RUN_DHCPV4_VM_LIVE=1 to execute"
fi
```

With `LIBCRAFTER_RUN_DHCPV4_VM_LIVE` unset (the default), the gate takes the
echo-skip branch and nothing runs. When it is `1`, the matrix runs provider
doctors first, skips any unavailable VM provider cleanly, refuses to send
packets without `--confirm-live-run`, creates VMs only because
`--allow-vm-create` is present, collects artifacts under `--out`, and tears the
endpoints down. Always validate the focused DHCPv4 path with `--dry-run` first:

```sh
python3 tools/oracle/engine/live_provider_matrix.py --providers qemu,virtualbox --backend scapy --profile smoke --seed 132 --count 2 --case dhcpv4-discover --dry-run --out target/oracle/dhcpv4-vm-dry-run
```

### Guarded DHCP Hetzner Live Exchange

The same `ipv4 / udp / dhcpv4` packet (selected with `--case dhcpv4-discover`) runs
against Hetzner private cloud networking through `tools/oracle/run live
--provider hetzner`. Hetzner is a routed private cloud segment: the DHCPv4 packet
under test is wire-eligible there because it is IPv4 unicast, while the
Ethernet-root DHCPv4 stack stays skipped for `requires_l2` and
`requires_provider_mac`. Always plan the focused DHCPv4 path with `--dry-run`
first; it creates no cloud resources and sends no packets:

```sh
tools/oracle/run live --backend scapy --provider hetzner --dry-run --profile smoke --seed 133 --count 2 --case dhcpv4-discover --out target/oracle/dhcpv4-hetzner-dry-run
```

Keep the real Hetzner live run opt-in behind an explicit environment gate so
unattended CI never provisions cloud endpoints or sends real DHCPv4 packets:

```sh
if [ "${LIBCRAFTER_RUN_DHCPV4_HETZNER_LIVE:-0}" = "1" ]; then
  tools/oracle/run live \
    --backend scapy --provider hetzner --profile smoke \
    --seed 133 --count 2 --case dhcpv4-discover \
    --confirm-live-run \
    --out target/oracle/dhcpv4-hetzner-live
else
  echo "skipping protected Hetzner DHCPv4 live run; set LIBCRAFTER_RUN_DHCPV4_HETZNER_LIVE=1 to execute"
fi
```

With `LIBCRAFTER_RUN_DHCPV4_HETZNER_LIVE` unset (the default), the gate takes the
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

## DHCPv6 Guarded Live Planning

DHCPv6 live validation is provider-backed packet-equivalence planning for
`ipv6 / udp / dhcpv6` and `ethernet / ipv6 / udp / dhcpv6` cases selected with
`--case dhcpv6-solicit` under the `dhcpv6-smoke` profile. It is not a DHCPv6
server, client state machine, prefix-delegation workflow, or lease negotiation.
The Solicit packet uses UDP 546 to 547 and DHCPv6 multicast; providers must
report IPv6 and multicast support before a real exchange is eligible.

Always run the dry-run path first. It creates no endpoints and sends no
packets; unavailable provider capabilities are reported as stable skip reasons
such as `requires_ipv6`, `requires_multicast`, `requires_l2`, or
`requires_provider_mac`:

```sh
tools/oracle/run live --backend scapy --provider qemu --dry-run --profile dhcpv6-smoke --seed 9917 --count 2 --case dhcpv6-solicit --out target/oracle/dhcpv6-guarded-doc-dry-run
tools/oracle/run live --backend scapy --provider docker --dry-run --profile dhcpv6-smoke --seed 9917 --count 2 --case dhcpv6-solicit --out target/oracle/dhcpv6-docker-dry-run
tools/oracle/run live --backend scapy --provider hetzner --dry-run --profile dhcpv6-smoke --seed 9917 --count 2 --case dhcpv6-solicit --out target/oracle/dhcpv6-hetzner-dry-run
```

Keep real VM execution behind a DHCPv6-specific environment gate plus the
generic live confirmation flag. The VM matrix must run from disposable QEMU or
VirtualBox lab endpoints, collect artifacts under `target/oracle/dhcpv6-*`, and
skip cleanly when provider IPv6 or multicast support is absent:

```sh
if [ "${LIBCRAFTER_RUN_DHCPV6_VM_LIVE:-0}" = "1" ]; then
  python3 tools/oracle/engine/live_provider_matrix.py \
    --providers qemu,virtualbox --backend scapy --profile dhcpv6-smoke \
    --seed 9917 --count 2 --case dhcpv6-solicit \
    --real --skip-unavailable --allow-vm-create --confirm-live-run \
    --out target/oracle/dhcpv6-vm-live
else
  echo "skipping protected VM DHCPv6 live run; set LIBCRAFTER_RUN_DHCPV6_VM_LIVE=1 to execute"
fi
```

Hetzner remains separately guarded because it uses cloud endpoints and
credentials. A real run still refuses to exchange packets unless
`--confirm-live-run` is present, provider credentials are available in the
environment, and the live capability report says IPv6 and multicast are
supported:

```sh
if [ "${LIBCRAFTER_RUN_DHCPV6_HETZNER_LIVE:-0}" = "1" ]; then
  tools/oracle/run live \
    --backend scapy --provider hetzner --profile dhcpv6-smoke \
    --seed 9917 --count 2 --case dhcpv6-solicit \
    --confirm-live-run \
    --out target/oracle/dhcpv6-hetzner-live
else
  echo "skipping protected Hetzner DHCPv6 live run; set LIBCRAFTER_RUN_DHCPV6_HETZNER_LIVE=1 to execute"
fi
```

Do not commit provider account data, endpoint IDs, public IPs, live hostnames,
or captures. Keep DHCPv6 live reports, pcaps, decoded models, provider
capability reports, and teardown logs under the requested ignored
`target/oracle/dhcpv6-*` artifact directory.

Before declaring a real DHCPv6 oracle or probe exchange complete, audit the
artifact root. A passing live audit requires provider session metadata,
endpoint/provider manifests, planned topology, stimulus and reply bytes, pcaps,
decoded `summary()` and `show()` text, normalized comparison JSON, command logs,
final reports, and teardown records. Dry-run and capability-skipped roots audit
as `skipped` rather than `passed`.

```sh
python3 tools/oracle/engine/dhcpv6_artifacts.py \
  --input target/oracle/dhcpv6-vm-live \
  --out target/oracle/dhcpv6-artifact-audit
```

## Exchange Directions

Live reports use the same backend-neutral direction names as offline and pcap
reports.

### `libcrafter_to_backend`

The `libcrafter` endpoint is the sender. It materializes a generated packet plan
with libcrafter, transmits it on the private test interface, and records sender
logs. The `reference_backend` endpoint is the receiver. It captures the packet,
decodes it with the backend, and emits a normalized decoded observation.

The exchange passes when the received observation satisfies the selected live
feature spec, including stack, field, payload, direction, and strict byte rules
where those rules apply.

### `backend_to_libcrafter`

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
- `direction`: `libcrafter_to_backend` or `backend_to_libcrafter`.
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
  "direction": "libcrafter_to_backend",
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
