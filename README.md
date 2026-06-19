<h1 align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/libcrafter-lockup-dark.svg">
    <img src="docs/assets/libcrafter-lockup.svg" alt="libcrafter" width="560">
  </picture>
</h1>

`libcrafter` is a Rust workspace for packet-level network interaction. Its
public crate, `crafter` (version 0.3.0), lets agents and Rust tools build
protocol-correct packets, place them on real networks, decode what comes back,
and act on what they observe.

This README is a progressive walkthrough: build your first packet, inspect and
decode bytes, read and write pcap, plan a send, and reach for disposable
endpoints and labs when traffic cannot live on the developer machine. Every
snippet uses documentation address space (`192.0.2.0/24`, `198.51.100.0/24`,
`2001:db8::/32`) and offline or dry-run defaults; live traffic is always an
explicit opt-in.

## Your first packet

A `Packet` is a typed stack of layers. Build one with `/` composition, then
`compile()` to fill the dependent fields (lengths, protocol numbers, header
lengths, checksums) that you did not set yourself:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Icmpv4::echo_request().id(0x4242).seq(1)
        / Raw::from("hello");

    let compiled = packet.compile()?;

    println!("{}", packet.summary());       // one-line stack summary
    println!("{}", packet.show());           // full field-by-field view
    println!("{}", compiled.hexdump());      // the bytes on the wire
    Ok(())
}
```

`compile()` fills only what you left unset. Anything you set explicitly survives
untouched — including values that are wrong on purpose — so the same builder
emits both protocol-correct packets and deliberately malformed ones.

## Inspect and decode

Reach into a packet by layer type, and decode raw bytes from an explicit link
or network context. Decoding never guesses the entry point: you name the link
type or network layer.

```rust
use crafter::prelude::*;

fn inspect(frame: &[u8], datagram: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // From an Ethernet frame:
    let packet = Packet::decode_from_link(LinkType::Ethernet, frame)?;
    if let Some(ip) = packet.layer::<Ipv4>() {
        println!("{} -> {}", ip.source(), ip.destination());
    }

    // From a bare IPv4 datagram:
    let l3 = Packet::decode_from_l3(NetworkLayer::Ipv4, datagram)?;
    println!("{}", l3.summary());
    Ok(())
}
```

A malformed enclosing header surfaces as a structured error with `context`,
`required`, and `available` rather than a panic, and any next protocol the
decoder does not model is preserved as a `Raw` payload when the header around it
is valid. See [docs/reference/api.md](docs/reference/api.md) for the full decode
contract and typed-layer accessors.

## Capture and pcap

Read classic pcap files through the packet-wire API, apply a libpcap BPF
filter string, and iterate records with a `Sniffer`:

```rust
use crafter::prelude::*;

fn read_pcap(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let source = PacketWire::pcap_file(path)
        .filter("tcp or udp")   // libpcap BPF filter string
        .open()?
        .source()?;

    for record in Sniffer::new(source).collect_records()? {
        println!("{}", record.packet().summary());
        println!("link type: {:?}", record.metadata().link_type());
    }
    Ok(())
}
```

Writing pcap is just as direct: compile packets, hand them to a pcap writer
through `PacketWire`, and replay them later. The packet-wire layer covers
classic pcap read/write, libpcap BPF filters, offline sniffing, and bounded live
capture hooks. Full pcapng and a full BPF parser are out of scope for 0.3.0. See
[docs/reference/wire.md](docs/reference/wire.md) for sources, writers,
transmitters, and transform chains.

## Send and receive

Sending is offline by default. `SendRecv` plans a send/receive without touching
the wire; `.dry_run()` is the default-safe mode, so no packet leaves the host.
The report still carries the attempts, the auto-derived reply filter, and any
matched reply:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;
use std::time::Duration;

fn plan() -> Result<(), Box<dyn std::error::Error>> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Icmpv4::echo_request().id(0x4242).seq(1)
        / Raw::from("ping");

    // SendRecv derives the BPF reply filter from the packet automatically.
    let report = packet.send_recv_report(
        SendRecv::new()
            .iface("eth0")
            .network_layer()
            .dry_run()                     // offline default: no packet leaves
            .timeout(Duration::from_millis(250))
            .retries(1),
    )?;

    println!("attempts: {}", report.attempts());
    println!("reply filter: {}", report.effective_filter().unwrap_or(""));
    match report.reply() {
        Some(reply) => println!("reply: {}", reply.summary()),
        None => println!("reply: none"),
    }
    Ok(())
}
```

The live path is the same call with one explicit change — swap `.dry_run()` for
`.live()`:

```rust
use crafter::prelude::*;

fn live(packet: &Packet) -> Result<(), Box<dyn std::error::Error>> {
    let report = packet.send_recv_report(
        SendRecv::new()
            .iface("eth0")
            .network_layer()
            .live(),                       // explicit opt-in: real raw send
    )?;

    if let Some(reply) = report.reply() {
        println!("{}", reply.summary());
    }
    Ok(())
}
```

Live raw sends and captures require platform privileges, and you must be
authorized to send and capture on the target network. Keep live work off the
developer host — provision a disposable endpoint instead.

## Tools: endpoint, lab, oracle, probe

The live path does not have to originate from your machine. Four modules under
`tools/` provision disposable network positions, run packet work from them,
collect artifacts, and tear the resources down when the run is done:

- **endpoint** — one disposable endpoint: doctor, create, exec, upload,
  download, collect artifacts, destroy.
- **lab** — multi-endpoint lab sessions that coordinate several endpoints for
  one run.
- **oracle** — packet-equivalence validation against reference backends
  (offline, pcap, and live modes).
- **probe** — peer-behavior validation against a live peer using seeded
  profiles.

The stack layers as endpoint ← lab ← oracle/probe. Every invocation is offline
by default; live traffic is an explicit opt-in. Start every provider-backed run
with `--dry-run`:

```sh
tools/endpoint/run doctor --provider hetzner --exposure wan --dry-run
tools/lab/run doctor --provider hetzner --dry-run
tools/oracle/run live --provider hetzner --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider hetzner --dry-run --profile smoke --seed 1 --count 10
```

Opt into live traffic only when an authorized human or agent has said so. The
Hetzner provider reads `HETZNER_API_TOKEN` or `HCLOUD_TOKEN` from the
environment; never commit credentials, public IPs, or captures from sensitive
networks.

- [docs/operations/tools.md](docs/operations/tools.md) — the four-tool stack,
  when to use which, and safe dry-run examples (start here).
- [docs/operations/endpoint.md](docs/operations/endpoint.md) — disposable
  endpoint setup, credentials, artifacts, and cleanup.
- [docs/operations/lab.md](docs/operations/lab.md) — provider-backed
  multi-endpoint lab sessions for oracle and probe workflows.

## Protocol coverage

Every layer below is exported from `crafter::prelude` and slots into the same
builder, decode, and summary surface. Unknown or unsupported next protocols are
preserved as `Raw` payloads when the enclosing header is valid.

| Layer | Coverage | Guide |
| --- | --- | --- |
| Ethernet / VLAN | Ethernet II and 802.1Q VLAN, Linux cooked capture, null/loopback | — |
| IEEE 802.11 | Management, control, and data frames with radiotap and LLC/SNAP, EAPOL and RSN (802.11i) key-exchange fields; monitor-mode radiotap injection (transmit on the air) supported behind explicit live gates | [dot11](docs/guide/dot11.md) |
| ARP | Request/reply construction and decode | [arp](docs/guide/arp.md) |
| IPv4 | DSCP/ECN, protocol labels, checksum status, typed options, fragment fields (no automatic reassembly) | [ipv4](docs/guide/ipv4.md) |
| IPv6 | Base header plus hop-by-hop, destination, fragment, routing, mobile-routing, and segment-routing extension headers | [ipv6](docs/guide/ipv6.md) |
| ICMPv4 / ICMPv6 | ICMPv4 (with `Icmp` deprecated alias) and ICMP extensions (RFC 4884); ICMPv6 echo/errors, Neighbor Discovery (RFC 4861), MLD v1/v2, Extended Echo, experimental Node Information | [icmpv6](docs/guide/icmpv6.md) |
| TCP | Segment construction, typed options, checksums | [tcp](docs/guide/tcp.md) |
| UDP | UDP with options (RFC 9868) and checksum status | [udp](docs/guide/udp.md) |
| DNS | EDNS(0), SVCB/HTTPS, DNSSEC record types | [dns](docs/guide/dns.md) |
| DHCPv4 | Option overload, RFC 3396 long options, relay agent option 82, client identifiers, authentication, leasequery fields | — |
| BGP | OPEN, UPDATE, KEEPALIVE, NOTIFICATION, ROUTE-REFRESH, path attributes, capabilities | [bgp](docs/guide/bgp.md) |
| OSPF | OSPFv2 Hello/DD/LSR/LSU/LSAck packets, Router/Network/Summary/AS-External/NSSA/Opaque (TE, RI) LSAs, null/simple/keyed-MD5/HMAC-SHA authentication, plus an OSPFv3 base layer; wire-level build and decode only (no state machine, SPF, or LSDB) | [ospf](docs/guide/ospf.md) |
| IPsec | ESP, AH, and IKEv2 (IKE header and payload set) with SA and transform primitives | [ipsec](docs/guide/ipsec.md) |

IP fragmentation and reassembly are explicit `IpFragment` / `IpDefrag` wire
transforms, not automatic decode-time behavior. TCP stream reassembly, full
pcapng, full BPF parsing, and a complete TCP/IP stack are not in scope for
0.3.0.

## Examples

Rust examples live under `crafter/examples/` and build against the public
`crafter` crate. They are offline or dry-run unless an example is explicitly
live-gated:

```sh
cargo build -p crafter --examples
cargo run -p crafter --example hello_world          # build, compile, hexdump
cargo run -p crafter --example decode_bytes         # decode entry points
cargo run -p crafter --example pcap_read            # pcap + Sniffer
cargo run -p crafter --example send_recv_icmp       # dry-run send/receive
cargo run -p crafter --example dns_query -- --name example.com
```

By category:

- Core packet model — `hello_world`, `packet_building`, `packet_inspection`,
  `decode_bytes`, `custom_registry`.
- Net workflows — `send_plan`, `send_packet`, `send_recv_icmp`, `network_ping`,
  `batch_send`, `batch_send_recv`, `interface_helpers`, `ip_ranges`.
- Pcap and sniffing — `pcap_write`, `pcap_read`, `wire_pcap_sniffer`,
  `wire_transform_chain`, `ip_defrag_offline`, `ip_fragment_offline`,
  `wpa_decrypt_offline`.
- Protocols — `arp_who_has`, `dns_query`, `dhcp_discover`, `icmpv4_error`,
  `icmpv6_echo`, `vlan`, `dot11_beacon_rsn`, `ipsec_esp`, `bgp_session`.

The full annotated table, with safety modes and commands, is in
[docs/reference/examples.md](docs/reference/examples.md).

## Documentation

- [docs/README.md](docs/README.md) is the documentation index.
- [docs/guide/](docs/guide/) — per-protocol wire coverage for everyday packet
  work (IPv4, IPv6, TCP, UDP, ARP, ICMPv6, DNS, BGP, OSPF, 802.11, IPsec); UDP,
  ARP, and ICMPv6 now have their own guides.
- [docs/reference/](docs/reference/) — the public API
  ([api.md](docs/reference/api.md)), the wire I/O layer
  ([wire.md](docs/reference/wire.md)), and the example catalog
  ([examples.md](docs/reference/examples.md)).
- [docs/operations/](docs/operations/) — live, provider-backed, and manual
  testing workflows (validation, probes, lab sessions, endpoints).
- [docs/operations/tools.md](docs/operations/tools.md) — tools overview tying
  the endpoint, lab, oracle, and probe modules together.
- [CHANGELOG.md](CHANGELOG.md) records the version 0.3.0 scope and boundaries.

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

Provider-backed validation starts with dry-runs against the oracle, probe, and
endpoint runners before any live invocation. Oracle modes, backends, and CI
expectations are documented in
[docs/operations/validation.md](docs/operations/validation.md).

## Publishing

For package-content checks only:

```sh
.agents/scripts/check-crafter-release --package-only
```

For agent-assisted publishing, use the repo-local `agent-cargo-publish` skill:
it runs the local release gate, performs a `cargo publish` dry run, summarizes
the crate/version/commit and package contents, and requires explicit ask-tool
approval before the real upload.

For a fully manual publish:

```sh
cargo publish -p crafter --dry-run
cargo publish -p crafter
```

Publishing to crates.io is a final maintainer action — never run the real
publish command from unattended automation.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
