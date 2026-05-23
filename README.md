# libcrafter

`libcrafter` is a Rust alpha workspace for building, decoding, capturing, and
testing network packets.

The Rust API keeps a packet-stacking style: protocol layers compose directly,
dependent fields are filled during compile, raw bytes can be decoded back into
typed layers, and compiled packets can be sent on live interfaces.

## Rust Alpha

The only public crate is `crafter`. The API is alpha and may change before a
stable release. Most generated tools and examples should import:

```rust
use crafter::prelude::*;
```

Build a packet with explicit builders:

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

Read and write pcaps without root:

```rust
use crafter::prelude::*;

fn inspect(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    for captured in read_pcap_filtered(path, "icmp")? {
        println!("{}", captured.packet().summary());
    }
    Ok(())
}
```

Examples use dry-run send paths by default. Use dry-run plans for local tools
and reserve live sends for disposable labs:

```rust
let plan = packet.send_dry_run(
    SendOptions::new()
        .iface("dry-run0")
        .network_layer(),
)?;
println!("{:?}", plan.target());
```

## Crate And Modules

Install and depend on `crafter` only. The repository is still named
`libcrafter`, but the public Rust surface is organized as modules inside the
one crate:

| Module | Purpose |
| --- | --- |
| `crafter::prelude` | Common imports for examples and generated tools. |
| `crafter::core` | Packet model, layer composition, encode/decode, checksums, protocol registry, formatting. |
| `crafter::pcap` | Classic pcap read/write, libpcap BPF filters, offline sniffing, bounded live capture hooks. |
| `crafter::net` | Interface helpers, raw send planning, live send backends, send/receive matching, batch workflows. |
| `crafter::live` | Disposable live-lab integration support. |

## Protocol Coverage

The alpha covers the protocols needed by the current Rust example set:

| Link | Network | Transport | Application |
| --- | --- | --- | --- |
| Ethernet | IPv4 | TCP | DNS |
| 802.1Q VLAN | IPv6 | UDP | DHCP |
| Linux cooked capture | ARP | TCP options | Raw payloads |
| Null/loopback | ICMP | UDP checksums | |
| | ICMPv6 | | |
| | IPv4 options | | |
| | IPv6 fragment, routing, mobile routing, and segment routing headers | | |
| | ICMP extensions | | |

Unknown or unsupported next protocols are preserved as `Raw` payloads where the
enclosing header is valid.

## Examples

Rust examples live under `crates/crafter/examples/` and build against the
public `crafter` crate:

```sh
cargo build --examples
cargo run --example hello_world -- --dry-run
cargo run --example ping -- --iface dry-run0
cargo run --example dns_query -- --dry-run --name example.com
```

The example set focuses on packet construction, offline pcap workflows, and
bounded validation flows that are dry-run by default.
See [docs/examples.md](docs/examples.md).

## Live Testing

Local tests do not require root or provider credentials:

```sh
cargo test --workspace
cargo doc --workspace --no-deps
```

Live raw-packet validation must run in a disposable provider lab:

```sh
tools/live-lab/libcrafter-live-lab doctor --provider local-dry-run
tools/live-lab/libcrafter-live-lab run --provider local-dry-run --suite all
```

The Hetzner provider reads `HETZNER_API_TOKEN` from the environment or from the
ignored local file documented in [docs/live-lab.md](docs/live-lab.md). Do not
store real credentials, provider account data, public IPs, or live host IDs in
tracked files.

## Release Notes And Platform Support

- [CHANGELOG.md](CHANGELOG.md) records the Rust alpha scope.
- [docs/supported-platforms.md](docs/supported-platforms.md) lists supported
  platforms, live-test requirements, and protocol coverage gaps.
- [docs/agent-cookbook.md](docs/agent-cookbook.md) gives copyable recipes for
  generated packet tools.

### Release Checklist

From a clean reviewed checkout, an authenticated maintainer should run the
offline release gate from the repository root:

```sh
tools/check-crafter-release --static
```

For package-content checks only, run:

```sh
tools/check-crafter-release --package-only
```

Then make the explicit crates.io publishing decision with:

```sh
cargo publish -p crafter --dry-run
cargo publish -p crafter
```

Do not run the real publish command from automation; it is a final manual
maintainer action.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
