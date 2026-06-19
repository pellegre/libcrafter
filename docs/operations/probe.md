# Probe Validation

Probe validates behavior from kernels and controlled services on disposable
lab sessions. It is separate from oracle validation: oracle checks
writer/parser agreement against a reference backend, while probe sends
libcrafter packets and expects the peer endpoint or service to answer.

The command surface is:

```sh
tools/probe/run --provider hetzner --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider qemu --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider virtualbox --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider docker --dry-run --profile smoke --seed 1 --count 10
```

Dry-runs are CI-safe. They write deterministic plans and reports below
`target/probe/` without creating hosts, sending packets, starting services, or
requiring provider credentials. Provider-backed dry-runs use `tools/lab` to
plan the `stimulus` and `target` roles and rewrite probe plans with lab
endpoint addresses. Dry-run remains the default safety boundary; live provider
runs require `--confirm-live-run`.

## Profiles and cases

`tools/probe/run` selects cases through `--profile`; `--count` bounds how many
of the profile's ordered cases run, and `--case` runs a named subset under any
profile. The flags are `--provider`, `--profile`, `--seed`, `--count`, `--case`,
`--dry-run`, `--confirm-live-run`, and `--out`. The profiles are:

- `smoke` (default, default `--count` 5) — the legacy ICMP/TCP/DNS/TTL/ARP
  sample: `icmp-echo`, `tcp-syn-open`, `tcp-syn-closed`, `dns-query`,
  `ttl-expired`, `arp-resolution`.
- `behavior` (default `--count` 44) — the full DNS/DHCP/ARP/NDP/UDP/OSPF behavioral
  suite in deterministic DNS → DHCP → ARP → NDP → UDP order: ten DNS cases, ten
  DHCP cases, ten ARP cases, three NDP cases, and ten UDP cases.
- `bgp-smoke` (default `--count` 1) — the `bgp-session-smoke` case, which plans a
  BGP session exchange against a probe-owned FRR peer target service.
- `ipsec` (default `--count` 4) — the IPSec behavioral suite (`esp-transport-echo`,
  `esp-tunnel-echo`, `ah-transport-verify`, `ikev2-sa-init`) against a controlled
  IPSec-capable peer.

A provider-capability skip is the only way a supported case becomes a skip.
Hetzner plans the IPv4 unicast DNS and UDP service cases but skips the DHCP, ARP,
and NDP link-layer cases (and `ttl-expired`, which needs a controlled router);
QEMU, VirtualBox, and Docker private sessions plan the full private-lab behavior
suite when local prerequisites are available, though Docker advertises no IPv6 so
it skips the NDP cases. Skips stay in the report and never count as failures when
the provider lacks the declared capability.

Inspect the profiles with dry-run plans, which need no provider credentials and
send no packets:

```sh
tools/probe/run --provider qemu --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider qemu --dry-run --profile behavior --seed 1052 --count 44
tools/probe/run --provider local-dry-run --dry-run --profile bgp-smoke
tools/probe/run --provider qemu --dry-run --profile ipsec --seed 1
```

## Bootstrap Boundary

Lab provider adapters own substrate lifecycle only. They plan, create, connect,
describe, and tear down disposable endpoints, but they do not install probe
packages, build `stimulus_endpoint`, start target services, or choose
role-specific workload commands.

`tools/lab` owns repository archive transfer, remote unpack, bootstrap context,
artifacts, and cleanup records. Probe owns the workload bootstrap for the
`stimulus` and `target` roles after the repository is unpacked. The
`stimulus` role builds the probe adapter binary and prepares packet stimulus;
the `target` role prepares the controlled service runtime and target-side
state.

Docker is a lab provider for private multi-endpoint probe sessions. The Docker
adapter maps provider `docker` to `docker/private`, so lab owns only the
constrained private endpoint substrate while probe still owns `stimulus` and
`target` workload bootstrap. Docker `lan` and `wan` stay direct endpoint smoke
modes for NAT-backed L3 reachability, not probe lab-backed multi-endpoint
modes. See [docs/operations/endpoint.md](endpoint.md) for endpoint provider lifecycle and
artifact handling.

## Cases

### Smoke Profile

The smoke profile currently samples these cases:

- `icmp-echo`: send an ICMP echo request and validate the echo reply from the
  peer kernel.
- `tcp-syn-open`: send a raw TCP SYN to a controlled listener and validate the
  SYN/ACK response.
- `tcp-syn-closed`: send a raw TCP SYN to an unbound port and validate the RST
  response.
- `dns-query`: send a DNS query to a controlled UDP DNS responder and validate
  the matching answer.
- `ttl-expired`: send a low-TTL packet and validate ICMP time exceeded from a
  controlled routed hop when the provider advertises that capability.

The current lab providers, including Docker, do not advertise a controlled
router hop, so `ttl-expired` is skipped with `requires_controlled_router` for
Hetzner, QEMU, VirtualBox, and Docker. Skips remain in the report and do not
count as failures when the provider lacks the capability. Docker private probe
sessions advertise IPv4 unicast, link-layer send and capture, broadcast,
provider MAC knowledge, and controlled services; they do not advertise IPv6 or
a controlled router.

### Behavior Profile

The `behavior` profile is the full DNS/DHCP/ARP/NDP/UDP/OSPF behavioral suite. It
selects forty-three cases in deterministic DNS, DHCP, ARP, NDP, UDP order and
defaults `--count` to all forty-three cases when no explicit count is supplied:

```sh
tools/probe/run --provider qemu --dry-run --profile behavior --seed 1052 --count 44
tools/probe/run --provider qemu --dry-run --profile behavior --seed 1052 --case dns-a-success
```

DNS behavior cases use a controlled UDP DNS responder and validate decoded UDP
and DNS responses for peer addresses, ports, transaction id, flags, questions,
answer content, negative codes, EDNS metadata, and transaction-id/source-port
matching:

- `dns-a-success`
- `dns-aaaa-success`
- `dns-cname-chain`
- `dns-nxdomain`
- `dns-nodata`
- `dns-txt-answer`
- `dns-mx-answer`
- `dns-srv-answer`
- `dns-edns-opt`
- `dns-repeat-transaction`

DHCP behavior cases use a controlled DHCP/BOOTP responder on a private
link-layer segment and validate decoded UDP, BOOTP, and DHCP responses for
message type, transaction id, client identity, address assignment, server
identifier, lease/configuration options, and response direction:

- `dhcp-discover-offer`
- `dhcp-request-ack`
- `dhcp-client-identifier`
- `dhcp-hostname`
- `dhcp-parameter-request-list`
- `dhcp-lease-time`
- `dhcp-renewal-unicast-ack`
- `dhcp-inform-ack`
- `dhcp-request-nak`
- `dhcp-rapid-repeat`

ARP behavior cases use a private link-layer segment and validate decoded
Ethernet and ARP replies from the target kernel, including sender preservation,
alias handling, padding, neighbor-cache setup, provider MAC matching, and
filtered capture:

- `arp-basic-who-has`
- `arp-repeat-two-replies`
- `arp-source-address-preserved`
- `arp-alias-address-reply`
- `arp-unicast-request-reply`
- `arp-padding-reply`
- `arp-cache-flush-reply`
- `arp-mac-validation`
- `arp-spa-variation`
- `arp-broadcast-filtered-capture`

NDP behavior cases use the same private link-layer segment as ARP and validate
the target kernel's IPv6 Neighbor Discovery responses (RFC 4861): a Neighbor
Solicitation to the solicited-node multicast group expects a Neighbor
Advertisement, a Router Solicitation expects a Router Advertisement from a
configured router, and a Duplicate Address Detection probe sourced from `::`
expects a defending Neighbor Advertisement:

- `ndp-neighbor-solicitation`
- `ndp-router-solicitation`
- `ndp-duplicate-address-detection`

UDP behavior cases use controlled UDP services or target kernel ICMP behavior
and validate decoded UDP or ICMP responses for peer addresses, ports, payload,
ordering, checksum status, and surplus option handling:

- `udp-echo-empty`
- `udp-echo-short`
- `udp-echo-binary`
- `udp-echo-large`
- `udp-source-port-reflection`
- `udp-multi-shot-order`
- `udp-closed-port-icmp`
- `udp-zero-checksum-ipv4`
- `udp-options-surplus-echo`
- `udp-length-boundary-echo`

## Provider Capabilities

The probe runner derives provider capabilities from the lab provider and stores
them in reports. Capability checks are the only way a supported behavioral case
becomes a skip. A case that can run on the provider but emits the wrong packet,
receives an undecodable response, or fails validation remains a failure so
libcrafter or probe infrastructure can be fixed.

DNS and UDP behavior cases need IPv4 unicast and controlled services. Large UDP
payload cases also require the provider's advertised safe payload size to cover
the planned datagram, while zero-checksum and surplus-option cases require the
matching provider capabilities. DHCP cases need IPv4 unicast, controlled
services, link-layer send/capture, and broadcast. ARP cases need link-layer
send/capture and broadcast; `arp-unicast-request-reply` and
`arp-mac-validation` also need provider MAC metadata. NDP cases ride the same
same-segment link-layer multicast substrate as ARP (derived `ipv6_multicast`
capability = link-layer send/capture plus broadcast), so they plan wherever ARP
plans and skip wherever ARP skips.

Expected provider behavior:

- Hetzner plans IPv4 unicast DNS and UDP service cases, and skips DHCP, ARP, and
  NDP link-layer cases with stable capability reasons.
- QEMU and VirtualBox private lab sessions are expected to plan the full
  behavior suite when local VM prerequisites are available.
- Docker private sessions advertise IPv4 unicast, link-layer send/capture,
  broadcast, provider MAC knowledge, and controlled services, but no IPv6 or
  controlled router.
- Any provider missing link-layer send/capture, broadcast, provider MAC
  metadata, controlled services, or UDP payload/option support reports a
  stable capability skip instead of a failure.

Run the dry-run provider matrix to compare planning and skip reasons across
providers without live traffic:

```sh
python3 tools/probe/engine/provider_matrix.py --providers hetzner,qemu,virtualbox,docker --dry-run --profile behavior --seed 1052 --count 44 --out target/probe/provider-matrix
```

## Target Services

Probe owns target workload setup after `tools/lab` has created, connected, and
described the disposable endpoints. The target service plan is included in
dry-run reports and rendered into the live setup script only after
`--confirm-live-run`.

Controlled target behavior is intentionally local to the lab segment:

- DNS uses a generated Python UDP responder bound to the target endpoint.
- DHCP uses a generated responder scoped to the planned DHCP contracts, not a
  general DHCP server.
- UDP uses generated echo/transform responders for service cases.
- Closed UDP port behavior relies on the target kernel's ICMP port-unreachable
  response.
- ARP relies on the target kernel, with probe-owned setup for aliases, sysctls,
  neighbor-cache flushes, alternate sender addresses, and decoy events where a
  case needs them.
- BGP uses a probe-owned FRR peer service for `bgp-smoke` under
  `tools/probe/target_services/bgp/`, including `provision-peer.sh` and
  `frr.conf.template`.

Dry-runs never start services or send packets. Live runs run setup and cleanup
on disposable lab endpoints and collect responder stdout, stderr, pid files,
packet artifacts, and report JSON under the configured output directory.

The BGP smoke profile exposes the FRR peer setup in the probe target-service
plan. Use a local dry-run when only the service metadata and generated stimulus
intent need inspection:

```sh
tools/probe/run --provider local-dry-run --dry-run --profile bgp-smoke
```

Use a lab-backed provider dry-run to verify endpoint roles and provider
capabilities without installing FRR or opening TCP sessions:

```sh
tools/probe/run --provider qemu --dry-run --profile bgp-smoke --seed 1
tools/probe/run --provider docker --dry-run --profile bgp-smoke --seed 1
```

## Protected Lab Runs

Real probe runs use a two-endpoint lab session. Run local static checks and
dry-runs first:

```sh
cargo test --workspace
tools/probe/run --provider hetzner --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider qemu --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider virtualbox --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider docker --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider qemu --dry-run --profile behavior --seed 1052 --count 44
python3 tools/probe/engine/provider_matrix.py --providers hetzner,qemu,virtualbox,docker --dry-run --profile behavior --seed 1052 --count 44 --out target/probe/provider-matrix
tools/lab/run plan --provider hetzner --dry-run --profile smoke --seed 1 --role stimulus --role target --json
tools/lab/run plan --provider qemu --dry-run --profile smoke --seed 1 --role stimulus --role target --json
tools/lab/run plan --provider virtualbox --dry-run --profile smoke --seed 1 --role stimulus --role target --json
tools/lab/run plan --provider docker --dry-run --profile smoke --seed 1 --role stimulus --role target --json
```

Docker LAN and WAN checks use direct endpoint smokes instead of probe lab sessions:

```sh
tools/endpoint/run doctor --provider docker --exposure lan --dry-run
tools/endpoint/smoke/live_docker_lan_icmp.py --plan-only
tools/endpoint/smoke/live_docker_wan_dns.py --plan-only
```

Those smokes default to plan output. Live runs require explicit
`--live --i-understand-isolated-lab` flags and do not assert LAN L2, WAN L2, or
public inbound reachability.

Start a protected live run only when disposable resources are intended:

```sh
tools/probe/run --provider hetzner --confirm-live-run --profile smoke --seed 21 --count 25
tools/probe/run --provider qemu --confirm-live-run --profile smoke --seed 21 --count 25
tools/probe/run --provider virtualbox --confirm-live-run --profile smoke --seed 21 --count 25
tools/probe/run --provider docker --confirm-live-run --profile smoke --seed 21 --count 25
```

The full DNS/DHCP/ARP/UDP behavior suite has a guarded command path. It runs a
live provider only when `LIBCRAFTER_PROBE_LIVE_PROVIDER` is set; otherwise it
keeps the default dry-run boundary:

```sh
if [ -n "${LIBCRAFTER_PROBE_LIVE_PROVIDER:-}" ]; then
  tools/probe/run --provider "$LIBCRAFTER_PROBE_LIVE_PROVIDER" --confirm-live-run --profile behavior --seed 1051 --count 44 --out target/probe/acceptance/51-live-behavior-suite
else
  tools/probe/run --provider qemu --dry-run --profile behavior --seed 1051 --count 44 --out target/probe/acceptance/51-live-behavior-suite-dry-run
fi
```

The probe runner uses `tools/lab` to create both endpoints, transfer and unpack
the repository, run probe-owned bootstrap hooks, collect artifacts, and clean
up endpoint resources. Probe keeps ownership of target service setup, temporary
TCP RST guards on the stimulus endpoint, the `stimulus_endpoint` binary from
`tools/probe/adapters`, response parsing, and result assembly.

## Artifacts

Probe reports include selected cases, generated probe plans, execution counts,
skip counts, lab session metadata, provider command metadata, observed
responses, and per-case failure reasons. Local reports are written below
`target/probe/`. Provider artifacts are collected through lab/endpoint
workflows into ignored artifact directories or the configured runner output
directory. See [docs/operations/endpoint.md](endpoint.md) for single-endpoint provider
credentials, artifacts, and cleanup.

Do not commit provider state, public host addresses, live host identifiers,
packet captures from non-disposable networks, or credentials.
