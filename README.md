<h1 align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/libcrafter-lockup-dark.svg">
    <img src="docs/assets/libcrafter-lockup.svg" alt="libcrafter" width="560">
  </picture>
</h1>

`libcrafter` is a Rust workspace for packet-level network interaction. Agents
and Rust tools can build protocol-correct packets, generate traffic on the
wire, decode what comes back, and correlate live network stimuli and responses.

The framework gives agents direct packet construction, send/receive, capture,
pcap, oracle, and probe capabilities. Instead of calling only fixed protocol
clients, agents can generate the packets themselves and decide how to interact
with the network at the protocol level.

## Version 2.0.0

The public crate is `crafter`:

```toml
crafter = "2.0.0"
```

The repository is still named `libcrafter`, but Cargo users should depend on
the `crafter` crate and import the prelude in most generated tools and examples:

```rust
use crafter::prelude::*;
```

## What Agents Can Do

- Generate packet stacks across link, network, transport, control, and
  application protocols.
- Compile packets with auto-filled lengths, protocol numbers, header lengths,
  and checksums while preserving fields that were set explicitly.
- Decode observed traffic back into typed layers for inspection and follow-up
  decisions.
- Send packets, match replies, batch traffic, resolve interfaces, parse target
  ranges, and capture packets through bounded pcap workflows.
- Use oracle and probe tooling to compare packet behavior against reference
  backends and real network stacks.
- Run packet work from one endpoint or a fleet of provider-backed endpoints
  when raw sockets, capture privileges, or external network reachability are
  needed.

## Packet Construction

Build protocol stacks with explicit builders or `/` composition:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Icmp::echo_request().id(0x4242).seq(1)
        / Raw::from("hello");

    let bytes = packet.compile()?;
    println!("{}", packet.summary());
    println!("{}", bytes.hexdump());
    Ok(())
}
```

`compile` fills dependent fields such as checksums and lengths. Explicit user
values are preserved so agents can choose either protocol-correct defaults or
deliberately shaped packets.

## Decode, Capture, And Pcap

Decode raw bytes from explicit link or network contexts:

```rust
use crafter::prelude::*;

fn inspect(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let reader = PcapReader::open(path)?;
    for record in reader.records() {
        let packet = record?.decode()?;
        println!("{}", packet.summary());
    }
    Ok(())
}
```

The pcap APIs support classic pcap read/write, libpcap BPF filters, offline
sniffing, bounded live capture hooks, and stable packet summaries for tests and
agent logs.

## Send And Receive

Local examples use dry-run planning unless live traffic is requested explicitly:

```rust
let plan = packet.send_dry_run(
    SendOptions::new()
        .iface("dry-run0")
        .network_layer(),
)?;
println!("{:?}", plan.target());
```

Live workflows expose raw send, send/receive matching, batch sends, interface
helpers, route hints, reply filters, and timeout-bounded capture. Run live
traffic only in networks where you are authorized to send and capture packets.

## Agent-Directed Wire Workflows

Wire tooling lives under `tools/wire`, `tools/oracle`, and `tools/probe`.
Together they let an agent create endpoints, transfer adapters, execute packet
work, collect artifacts, and destroy provider resources when the run is done.

The important capability is not the endpoint lifecycle itself. The endpoint is
where an agent can generate traffic, observe responses from real stacks, and use
that feedback to continue exploring the surrounding network environment at the
packet level.

```sh
tools/wire/run doctor --provider hetzner --exposure wan --dry-run
tools/oracle/run live --provider hetzner --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider hetzner --dry-run --profile smoke --seed 1 --count 10
```

Hetzner is the current provider-backed endpoint implementation. QEMU and
VirtualBox providers are not part of version 2.0.0.

## Crate And Modules

| Module | Purpose |
| --- | --- |
| `crafter::prelude` | Common imports for examples and agent-written tools. |
| `crafter::core` | Packet model, layer composition, encode/decode, checksums, protocol registry, formatting. |
| `crafter::pcap` | Classic pcap read/write, libpcap BPF filters, offline sniffing, bounded live capture hooks. |
| `crafter::net` | Interface helpers, raw send planning, live send backends, send/receive matching, batch workflows. |

## Protocol Coverage

| Layer | Coverage |
| --- | --- |
| Link | Ethernet, 802.1Q VLAN, Linux cooked capture, null/loopback |
| Network and control | ARP, IPv4, IPv4 options, IPv6, IPv6 fragment headers, IPv6 routing headers, IPv6 mobile routing headers, IPv6 segment routing headers, ICMP, ICMPv6, ICMP extensions |
| Transport | TCP, TCP options, UDP, UDP checksums |
| Application and payload | DNS, DHCP, raw payloads |

Unknown or unsupported next protocols are preserved as `Raw` payloads when the
enclosing header is valid.

## Examples

Rust examples live under `crafter/examples/` and build against the public
`crafter` crate:

```sh
cargo build -p crafter --examples
cargo run -p crafter --example hello_world
cargo run -p crafter --example send_plan
cargo run -p crafter --example dns_query -- --name example.com
```

The example set covers packet construction, protocol options, decode entry
points, pcap workflows, send planning, send/receive matching, batch traffic,
interface helpers, and bounded validation flows.

## Validation

Local validation does not require provider credentials:

```sh
cargo test --workspace
cargo doc --workspace --no-deps
```

The full local release gate is:

```sh
.agents/scripts/check-crafter-release --static
```

Provider-backed packet validation should start with dry-runs:

```sh
tools/wire/run doctor --provider hetzner --exposure wan --dry-run
tools/oracle/run live --provider hetzner --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider hetzner --dry-run --profile smoke --seed 1 --count 10
```

The Hetzner wire provider reads `HETZNER_API_TOKEN` or `HCLOUD_TOKEN` from the
environment. Do not store real credentials, provider account data, public IPs,
live host IDs, or packet captures from sensitive networks in tracked files.

## Documentation

- [docs/README.md](docs/README.md) is the documentation index.
- [docs/api.md](docs/api.md) describes the public Rust API shape.
- [docs/examples.md](docs/examples.md) lists example commands and workflows.
- [docs/validation.md](docs/validation.md) describes oracle validation modes
  and CI expectations.
- [docs/probe.md](docs/probe.md) describes wire-backed kernel and service
  behavior probes.
- [docs/wire.md](docs/wire.md) covers provider endpoint setup, credentials,
  artifacts, and cleanup.
- [CHANGELOG.md](CHANGELOG.md) records the version 2.0.0 scope.

## Publishing

For package-content checks only, run:

```sh
.agents/scripts/check-crafter-release --package-only
```

For agent-assisted publishing, use `$agent-cargo-publish`. The skill runs the
local release gate, performs a `cargo publish` dry run, summarizes the
crate/version/commit and package contents, and requires explicit ask-tool
approval before the real upload.

For a fully manual publish, make the explicit crates.io publishing decision
with:

```sh
cargo publish -p crafter --dry-run
cargo publish -p crafter
```

Do not run the real publish command from unattended automation. It is a final
maintainer action, either manual or explicitly ask-confirmed through the
repo-local publish skill.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
