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

Common dry-run commands:

```sh
tools/probe/run --provider hetzner --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider qemu --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider virtualbox --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider qemu --dry-run --profile behavior --seed 1052 --count 40
python3 tools/probe/engine/provider_matrix.py --providers hetzner,qemu,virtualbox,docker --dry-run --profile behavior --seed 1052 --count 40 --out target/probe/provider-matrix
```

The `behavior` profile is the DNS/DHCP/ARP/UDP peer-response suite. It selects
forty cases in a stable order, ten per protocol:

- DNS: success and negative answers for A, AAAA, CNAME, NXDOMAIN, NODATA, TXT,
  MX, SRV, EDNS OPT, and repeated transaction ids over separate source ports.
- DHCP: Discover/Offer, Request/Ack, client identifier, hostname, parameter
  request list, lease timing, renewal, Inform/Ack, invalid-address Nak, and
  repeated Discover.
- ARP: broadcast and unicast who-has exchanges, repeated replies, sender
  address preservation, alias address replies, padded requests, cache flush,
  MAC validation, alternate SPA, and filtered capture on noisy segments.
- UDP: empty, short, binary, large, source-port, ordered multi-shot,
  closed-port ICMP, IPv4 zero-checksum, surplus options, and length-boundary
  datagram cases.

Provider-backed probe dry-runs use `tools/lab` to plan `stimulus` and `target`
roles, derive endpoint addresses and interfaces, and include lab session
metadata in the report. Probe still owns target service setup, TCP RST guards,
stimulus execution, response parsing, and result assembly.

Provider capability checks decide whether a case can run. DNS and UDP need IPv4
unicast plus controlled services. DHCP needs a private link-layer segment with
broadcast and controlled services. ARP needs link-layer send/capture and
broadcast; some ARP cases also need provider MAC metadata. Unsupported cases
skip with stable capability reasons and do not count as failures. Build, send,
decode, or validation errors on supported cases must remain failures.

Target setup is controlled and disposable. The target endpoint runs generated
Python DNS, DHCP, and UDP responders where needed, and uses kernel behavior for
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
