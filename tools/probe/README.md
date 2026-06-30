# Probe Tool

`tools/probe/` owns behavioral probe validation. Probe sends libcrafter packets
through disposable lab sessions and verifies kernel or controlled service
replies.

Probe is separate from oracle validation. Oracle checks libcrafter packet
construction and decode agreement with reference backends. Probe checks peer
behavior: a packet built by libcrafter is sent to a controlled endpoint, one or
more responses are captured, decoded by libcrafter, and validated against the
case contract.

The Python runner under `tools/probe/engine/` generates deterministic probe
plans, writes request artifacts, orchestrates provider execution, and builds
reports. The Rust endpoint binary lives in `tools/probe/adapters/`; it is tool
infrastructure, not a public `crafter` example.

## Protocol plugins

Each protocol's full surface lives in one auto-discovered plugin module,
`tools/probe/engine/protocols/<name>.py` (e.g. `arp.py`, `dns.py`, `tcp.py`).
A single `ProtocolPlugin` per module bundles that protocol's cases, plan
builders, target-service setup, stimulus routing, live-path address rewrite,
failure reasons, and lab-capability derivation, and registers itself at import
through `PROTOCOL_REGISTRY` in `tools/probe/engine/protocols/base.py`. The
engine's central dispatchers fold over the registry rather than carrying
per-protocol branches, so adding a protocol means writing that one file — no
central dispatcher or shared lookup table to edit.

The emitted plan JSON each builder produces is the stable cross-language wire
contract consumed by the Rust adapter under `tools/probe/adapters/`; its field
names and shapes must stay byte-identical or the Rust decode breaks. See
[`docs/adding-a-protocol.md`](docs/adding-a-protocol.md) for the full recipe.

Common dry-run commands:

```sh
tools/probe/run --provider hetzner --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider qemu --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider virtualbox --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider qemu --dry-run --profile behavior --seed 1052 --count 40
tools/probe/run --provider qemu --dry-run --profile ipsec --out target/probe/ipsec-dry-run
tools/probe/run --provider qemu --dry-run --profile ssdp-smoke --seed 1904 --count 3
python3 tools/probe/engine/provider_matrix.py --providers hetzner,qemu,virtualbox,docker --dry-run --profile behavior --seed 1052 --count 40 --out target/probe/provider-matrix
```

The `behavior` profile is the DNS/DHCPv4/ARP/UDP peer-response suite. It selects
forty cases in a stable order, ten per protocol:

- DNS: success and negative answers for A, AAAA, CNAME, NXDOMAIN, NODATA, TXT,
  MX, SRV, EDNS OPT, and repeated transaction ids over separate source ports.
- DHCPv4: Discover/Offer, Request/Ack, client identifier, hostname, parameter
  request list, lease timing, renewal, Inform/Ack, invalid-address Nak, and
  repeated Discover.
- ARP: broadcast and unicast who-has exchanges, repeated replies, sender
  address preservation, alias address replies, padded requests, cache flush,
  MAC validation, alternate SPA, and filtered capture on noisy segments.
- UDP: empty, short, binary, large, source-port, ordered multi-shot,
  closed-port ICMP, IPv4 zero-checksum, surplus options, and length-boundary
  datagram cases.

The `ipsec` profile is the IPSec peer-exchange suite (kept separate from
`behavior` because it needs an IPSec-capable peer): ESP transport-mode echo,
ESP tunnel-mode echo, AH transport-mode verify, and an IKE_SA_INIT exchange.
ESP/AH need a peer holding the matching Security Association (the `ipsec_esp` /
`ipsec_ah` capabilities); IKEv2 needs the peer to run an IKE responder on
UDP/500 (the `ikev2` capability). All three derive from IPv4 unicast plus a
controlled service, so a substrate without a configurable peer skips the cases
with the stable `requires_ipsec_peer` / `requires_ikev2_responder` reasons. The
peer is realized live as the Linux kernel xfrm / strongSwan stack or a
oracle reference peer on the disposable target endpoint; the dry-run plans
the exchange shape (ESP/AH protocol numbers, IKEv2 UDP port, per-exchange SPI,
peer addresses) without provisioning the peer or sending any traffic. The live
path is opt-in through `lab-session` / providers — provision the peer, run from
there, collect artifacts, and tear it down — never from the developer machine.
The IPSec stimulus/response cases are `planned_only` in the plan until the
crate-side stimulus builders and the cross-crypto parity check land in later
probe steps.

The `ssdp-smoke` profile label is used for SSDP discovery planning. SSDP cases cover
IPv4 `M-SEARCH` response planning, IPv6 link-local multicast search planning,
bounded `NOTIFY` capture planning, unrelated UDP/1900 raw fallback, and
malformed SSDP-like payload reporting. Start with a dry-run and pin the SSDP
cases you intend to inspect:

```sh
tools/probe/run --provider qemu --dry-run --profile ssdp-smoke --seed 1904 --case ssdp-ipv4-search-exchange --case ssdp-ipv6-search-exchange --case ssdp-notify-capture --out target/probe/ssdp-dry-run
```

Before any live SSDP run, inspect the dry-run report under the selected `--out`
directory. Confirm that `metadata.provider_capabilities` and
`metadata.lab_session.provider_capabilities` include the required SSDP
capabilities for the selected cases: `ssdp_controlled_responder`,
`ssdp_ipv4_multicast`, `ssdp_ipv6_multicast`, and, for IPv6 link-local search,
`ssdp_ipv6_link_local_scope`. Also inspect `metadata.probe_plans` for
`live_address_rewrite`, `target_service`, `capture_filter`, and
`wire_requirements` so the planned multicast destination, controlled UDP/1900
responder, and response validation are visible before traffic is allowed.

Live SSDP probing is protected and provider-backed only. Run it from a
disposable lab provider after the dry-run metadata has been reviewed, and gate
the command with both an explicit provider selection and a local SSDP
confirmation:

```sh
if [ -n "${LIBCRAFTER_PROBE_LIVE_PROVIDER:-}" ] && [ "${LIBCRAFTER_PROBE_LIVE_SSDP_CONFIRM:-}" = "yes" ]; then
  tools/probe/run --provider "$LIBCRAFTER_PROBE_LIVE_PROVIDER" --confirm-live-run --profile ssdp-smoke --seed 1904 --case ssdp-ipv4-search-exchange --case ssdp-notify-capture --out target/probe/ssdp-live
else
  tools/probe/run --provider qemu --dry-run --profile ssdp-smoke --seed 1904 --case ssdp-ipv4-search-exchange --case ssdp-notify-capture --out target/probe/ssdp-dry-run
fi
```

Keep the SSDP artifact set together: `report.json`, request artifacts, provider
command metadata, target-service logs such as
`live-artifacts/probe/target-services/ssdp-1900.stdout.txt`, capture summaries,
and cleanup records. After a live run, verify the report's lab-session cleanup
metadata shows artifact collection and teardown were attempted. If a manual lab
session was kept for debugging, collect artifacts first and then destroy it with
`tools/lab/run destroy SESSION_ID --json`. Do not commit provider endpoint
addresses, credentials, live interface names, real device UUIDs, or packet
captures from live SSDP runs.

The `mdns-smoke` profile label is used for multicast DNS and DNS-SD behavior
planning. For IPv4 live preparation, `mdns-ipv4-browse` is accepted as a
focused shorthand for the canonical `mdns-ipv4-multicast-browse` case. Always
start with a provider-backed dry-run and inspect the artifact root before any
live traffic:

```sh
tools/probe/run --provider qemu --dry-run --profile mdns-smoke --seed 6766 --case mdns-ipv4-browse --out target/probe/mdns-ipv4-live-dry-run
tools/probe/run --provider qemu --dry-run --profile mdns-smoke --seed 6767 --case mdns-ipv6-browse --out target/probe/mdns-ipv6-live-dry-run
```

Before a live IPv4 mDNS run, confirm that the dry-run report shows
`metadata.provider_capabilities.mdns_ipv4_multicast`,
`metadata.provider_capabilities.mdns_controlled_responder`, and, for QU
response cases, `metadata.provider_capabilities.mdns_unicast_response`. Inspect
`metadata.probe_plans` for `target_service`, `capture_filter`,
`wire_requirements`, `expected_mdns`, and `live_address_rewrite` so the
multicast destination (`224.0.0.251:5353`), controlled UDP/5353 responder,
expected response path, and provider interface are visible before traffic is
allowed. Unsupported providers should skip with stable capability reasons such
as `requires_multicast`, `requires_controlled_service`, or
`requires_ipv6_link_local_scope_metadata`; a non-dry-run request without
`--confirm-live-run` must skip with confirmation-required metadata rather than
sending packets.

IPv6 mDNS uses the link-local multicast group `ff02::fb`, so a live-capable
provider must expose both `mdns_ipv6_multicast` and
`mdns_ipv6_link_local_scope`. The dry-run report for `mdns-ipv6-browse` should
show `address_family=ipv6`, `destination_ipv6=ff02::fb`, `multicast_group`,
`capture_filter`, `required_capabilities`, `wire_requirements`, and artifact
paths even when the provider skips the case. A qemu private-network dry-run may
legitimately skip with `requires_multicast` when IPv6 multicast is unavailable.
A provider that grants IPv6 multicast but lacks provider MAC or scoped
link-local metadata should skip with
`requires_ipv6_link_local_scope_metadata`; either skip is a capability result,
not a packet failure.

Keep protected mDNS live runs behind an mDNS-specific operator gate in addition
to the generic confirmation flag:

```sh
if [ -n "${LIBCRAFTER_PROBE_LIVE_PROVIDER:-}" ] && [ "${LIBCRAFTER_PROBE_LIVE_MDNS_IPV4_CONFIRM:-}" = "yes" ]; then
  tools/probe/run --provider "$LIBCRAFTER_PROBE_LIVE_PROVIDER" --confirm-live-run --profile mdns-smoke --seed 6766 --case mdns-ipv4-browse --case mdns-qu-unicast-response --out target/probe/mdns-ipv4-live
elif [ -n "${LIBCRAFTER_PROBE_LIVE_PROVIDER:-}" ] && [ "${LIBCRAFTER_PROBE_LIVE_MDNS_IPV6_CONFIRM:-}" = "yes" ]; then
  tools/probe/run --provider "$LIBCRAFTER_PROBE_LIVE_PROVIDER" --confirm-live-run --profile mdns-smoke --seed 6767 --case mdns-ipv6-browse --out target/probe/mdns-ipv6-live
else
  tools/probe/run --provider qemu --dry-run --profile mdns-smoke --seed 6766 --case mdns-ipv4-browse --out target/probe/mdns-ipv4-live-dry-run
  tools/probe/run --provider qemu --dry-run --profile mdns-smoke --seed 6767 --case mdns-ipv6-browse --out target/probe/mdns-ipv6-live-dry-run
fi
```

Keep the mDNS artifact set together under the selected ignored `target/` root:
`report.json`, `artifacts/stimulus-endpoint/stimulus.request.json`, provider
command metadata, target-service logs such as
`live-artifacts/probe/target-services/mdns-5353.stdout.txt`, capture summaries,
and cleanup records. After a live run, verify artifact collection and endpoint
teardown metadata before deleting the disposable lab session. Do not commit
provider endpoint IDs, public addresses, interface names from real networks,
hostnames discovered from real mDNS traffic, or live packet captures.

Provider-backed probe dry-runs use `tools/lab` to plan `stimulus` and `target`
roles, derive endpoint addresses and interfaces, and include lab session
metadata in the report. Probe still owns target service setup, TCP RST guards,
stimulus execution, response parsing, and result assembly.

Those dry-run reports also surface appliance runtime metadata for each
lab-backed role: execution mode, appliance profile, image tag, remote workspace,
artifact root, and planned readiness checks. The appliance profile describes
where the role runs (`lan-raw`, `wan-raw`, `whad-serial`, or `dot11-monitor`);
it does not choose probe cases or packet behavior. Probe `--profile` and
`--case` still select validation semantics.

Docker private differs from VM and cloud appliance runs: the constrained
endpoint container is the appliance runtime and nested Docker is disabled.
QEMU, VirtualBox, Hetzner, and generic SSH Docker hosts run the standard
appliance image on the remote host through SSH. In both cases, provider-backed
live work still requires `--confirm-live-run`; the runtime metadata is
inspectable planning data, not a live-traffic approval.

Provider capability checks decide whether a case can run. DNS and UDP need IPv4
unicast plus controlled services. DHCPv4 needs a private link-layer segment with
broadcast and controlled services. ARP needs link-layer send/capture and
broadcast; some ARP cases also need provider MAC metadata. IPSec ESP/AH need a
peer that holds the matching Security Association, and IKEv2 needs an IKE
responder; absent either, the cases skip with `requires_ipsec_peer` /
`requires_ikev2_responder`. Unsupported cases skip with stable capability
reasons and do not count as failures. Build, send, decode, or validation errors
on supported cases must remain failures.

Target setup is controlled and disposable. The target endpoint runs generated
Python DNS, DHCPv4, and UDP responders where needed, and uses kernel behavior for
ARP and closed UDP port ICMP responses. Dry-runs report the exact setup plan
without starting services. Live runs start services only on disposable lab
endpoints and collect their artifacts.

Guard live behavior runs with an explicit provider environment variable:

```sh
if [ -n "${LIBCRAFTER_PROBE_LIVE_PROVIDER:-}" ]; then
  tools/probe/run --provider "$LIBCRAFTER_PROBE_LIVE_PROVIDER" --confirm-live-run --profile behavior --seed 1051 --count 40 --out target/probe/acceptance/51-live-behavior-suite
else
  tools/probe/run --provider qemu --dry-run --profile behavior --seed 1051 --count 40 --out target/probe/acceptance/51-live-behavior-suite-dry-run
fi
```

Build the Rust adapter directly:

```sh
cargo build -p probe-adapters --bin stimulus_endpoint
```
