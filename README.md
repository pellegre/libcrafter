<h1 align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/pellegre/libcrafter/HEAD/docs/assets/libcrafter-lockup-dark.svg">
    <img src="https://raw.githubusercontent.com/pellegre/libcrafter/HEAD/docs/assets/libcrafter-lockup.svg" alt="libcrafter" width="560">
  </picture>
</h1>

`libcrafter` is a Rust workspace for packet-level network interaction. Its
public crate, `crafter`, lets agents and Rust tools build protocol-correct
packets, place them on real networks, decode what comes back, and act on what
they observe.

This README is a progressive walkthrough: build your first packet, inspect and
decode bytes, read and write pcap, and plan a send. Every snippet uses
documentation address space (`192.0.2.0/24`, `198.51.100.0/24`,
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

    println!("{}", packet.summary());      // one-line stack summary
    println!("{}", packet.show());         // full field-by-field view
    println!("{}", compiled.hexdump());    // the bytes on the wire
    Ok(())
}
```

`compile()` fills only what you left unset. Anything you set explicitly survives
untouched — including values that are wrong on purpose — so the same builder
emits both protocol-correct packets and deliberately malformed ones.

SCTP uses the same stack shape. This example builds one DATA chunk, compiles it
offline, decodes the bare IPv4 datagram, and inspects the typed SCTP layer:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn sctp_data_packet() -> Result<(), Box<dyn std::error::Error>> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 44))
        .dst(Ipv4Addr::new(198, 51, 100, 44))
        / Sctp::data(
            0x0102_0304,
            1,
            1,
            SCTP_PPID_WEBRTC_STRING,
            b"hello-sctp".to_vec(),
        )
        .sport(5_000)
        .dport(5_001)
        .vtag(0x1122_3344);

    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let sctp = decoded.layer::<Sctp>().expect("SCTP layer");

    println!("{}", decoded.summary());
    println!("SCTP checksum status: {}", sctp.checksum_status());
    Ok(())
}
```

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
capture hooks. Full pcapng and a full BPF parser are not currently in scope. See
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
authorized to send and capture on the target network. Machine selection and
execution topology are deliberately outside this repository.

For repeated raw sends, open a reusable `PacketSender` or a raw socket
`PacketWire` writer instead of calling the one-shot `send_packet` path in a
loop. Dry-run planning stays offline:

```rust
use crafter::prelude::*;

fn plan_many(packet: &Packet) -> Result<(), Box<dyn std::error::Error>> {
    let mut sender = PacketSender::open(
        SendOptions::new()
            .iface("eth0")
            .network_layer()
            .dry_run(),
    )?;

    let report = sender.send(packet)?;
    assert!(report.is_dry_run());
    Ok(())
}
```

Live reusable senders must choose one send class with `.link_layer()` or
`.network_layer()` before `.live()`. A link-layer sender handles Ethernet and
radiotap frames through one opened backend; a network-layer sender currently
handles bare IPv4 packets. Mixed link/network traffic needs separate senders,
and full-header IPv6 network-layer live sends remain unsupported.

## Validation tools

Tracked validation is deterministic and infrastructure-free:

- **oracle** generates source-backed corpora and compares libcrafter with
  independent reference implementations offline or through pcap artifacts.
- **probe** emits deterministic packet-workload plans and never selects a
  machine or sends traffic.
- **smoke** is a small bounded libcrafter workload suitable for an external
  runner to build from an exact candidate revision.

```sh
tools/oracle/run specs validate --strict
tools/oracle/run corpus --profile ci --seed 12345 --count 100 --out target/oracle/corpus
tools/oracle/run offline --corpus target/oracle/corpus/plans.json --out target/oracle/offline
tools/probe/run --profile smoke --seed 1 --count 10 --out target/probe/plan
cargo run -p crafter-smoke
```

An external execution fabric can consume the candidate revision and plan,
satisfy its runtime requirements, invoke a bounded executor with concrete
interfaces and addresses, and return artifacts. Credentials, machine
lifecycle, hardware leases, peer preparation, and topology remain outside this
repository.

- [docs/operations/tools.md](docs/operations/tools.md) — validation tool
  boundaries and local commands.
- [docs/operations/validation.md](docs/operations/validation.md) — the offline
  gate and the external execution contract.

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
| IGMP | IPv4 packet-layer membership queries/reports, IGMPv1/v2 compatibility, IGMPv3 query/report records, generic extensions, and multicast router discovery packet shapes; not a router, snooper, proxy, or scanner | [igmp](docs/guide/igmp.md) |
| IPv6 | Base header plus hop-by-hop, destination, fragment, routing, mobile-routing, and segment-routing extension headers | [ipv6](docs/guide/ipv6.md) |
| ICMPv4 / ICMPv6 | ICMPv4 (with `Icmp` deprecated alias) and ICMP extensions (RFC 4884); ICMPv6 echo/errors, Neighbor Discovery (RFC 4861), MLD v1/v2, Extended Echo, experimental Node Information | [icmpv6](docs/guide/icmpv6.md) |
| TCP | Segment construction, typed options, checksums | [tcp](docs/guide/tcp.md) |
| TLS | TLS-over-TCP record layer with typed records, handshakes, extensions, alerts, ChangeCipherSpec, heartbeat, opaque application data, and unknown preservation; not a TLS endpoint, scanner, certificate validator, or TCP stream reassembler | [tls](docs/guide/tls.md) |
| UDP | UDP with options (RFC 9868) and checksum status | [udp](docs/guide/udp.md) |
| SCTP | Native IPv4/IPv6 SCTP and RFC 6951 UDP encapsulation, CRC32c checksum status, DATA/INIT/SACK/control chunks, parameters, causes, padding, pcap fixtures, and unknown-codepoint preservation; not an association stack or socket API | [sctp](docs/guide/sctp.md) |
| QUIC | UDP-carried QUIC datagrams, long/short headers, Version Negotiation, Retry, Initial/Handshake/0-RTT packets, frames, transport parameters, protected-payload preservation, and deterministic probe planning; not a QUIC endpoint stack | [quic](docs/guide/quic.md) |
| DNS | EDNS(0), SVCB/HTTPS, DNSSEC record types | [dns](docs/guide/dns.md) |
| mDNS / DNS-SD | UDP/5353 DNS message construction and decode, multicast constants and stack builders, QU/cache-flush class-bit helpers, DNS-SD service names, PTR/SRV/TXT/A/AAAA packet shapes, known answers, probes, announcements, and goodbyes; not a resolver, responder, cache, scanner, or service registry | [mdns](docs/guide/mdns.md) |
| DHCPv4 | BOOTP/DHCPv4 packet construction and decode, option overload, RFC 3396 long options, relay agent option 82, client identifiers, authentication, and leasequery packet fields; not a client, server, or lease engine | [dhcpv4](docs/guide/dhcpv4.md) |
| DHCPv6 | DHCPv6 client/server and relay packet construction and decode, DUIDs, status codes, IA_NA, IA_PD, IA Address, IA Prefix, relay message encapsulation, leasequery families, and unknown option preservation; not a client, server, relay daemon, or lease engine | [dhcpv6](docs/guide/dhcpv6.md) |
| BGP | OPEN, UPDATE, KEEPALIVE, NOTIFICATION, ROUTE-REFRESH, path attributes, capabilities | [bgp](docs/guide/bgp.md) |
| MQTT | MQTT 3.1.1 and 5.0 control packets over TCP/1883, typed properties, reason codes, and stacked payload decode | [mqtt](docs/guide/mqtt.md) |
| NTP | NTP fixed headers over UDP/123, LI/version/mode/stratum/reference metadata, timestamps, extension fields, NTS packet extension wrappers, legacy MAC tails, Kiss-o'-Death labels, and raw fallback; not a clock, daemon, scanner, NTS-KE client, or Autokey verifier | [ntp](docs/guide/ntp.md) |
| SNMP | BER values, VarBinds, SNMPv1/v2c PDUs, SNMPv3 wire framing, UDP/161 and UDP/162 decode dispatch, unknown preservation, and offline pcap fixtures; not a scanner, manager, agent daemon, MIB engine, credential store, or VACM evaluator | [snmp](docs/guide/snmp.md) |
| OSPF | OSPFv2 Hello/DD/LSR/LSU/LSAck packets, Router/Network/Summary/AS-External/NSSA/Opaque (TE, RI) LSAs, null/simple/keyed-MD5/HMAC-SHA authentication, plus an OSPFv3 base layer; wire-level build and decode only (no state machine, SPF, or LSDB) | [ospf](docs/guide/ospf.md) |
| IPsec | ESP, AH, and IKEv2 (IKE header and payload set) with SA and transform primitives | [ipsec](docs/guide/ipsec.md) |

IP fragmentation and reassembly are explicit `IpFragment` / `IpDefrag` wire
transforms, not automatic decode-time behavior. TCP stream reassembly, full
pcapng, full BPF parsing, and a complete TCP/IP stack are not currently in
scope.

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
- Protocols — `arp_who_has`, `dns_query`, `dhcpv4_discover`,
  `dhcpv4_option82`, `dhcpv4_leasequery`, `dhcpv6_solicit`,
  `dhcpv6_information_request`, `dhcpv6_prefix_delegation`, `dhcpv6_relay`,
  `icmpv4_error`, `icmpv6_echo`, `ntp_decode`, `ntp_request_plan`,
  `snmp_get`, `snmp_trap`, `snmpv3_message`, `vlan`, `dot11_beacon_rsn`,
  `ipsec_esp`, `bgp_session`, `mqtt_session`. NTP and SNMP wire guidance also
  lives in [docs/guide/ntp.md](docs/guide/ntp.md) and
  [docs/guide/snmp.md](docs/guide/snmp.md), and examples stay offline or
  dry-run by default.

The full annotated table, with safety modes and commands, is in
[docs/reference/examples.md](docs/reference/examples.md).

## Documentation

- [docs/README.md](docs/README.md) is the documentation index.
- [docs/guide/](docs/guide/) — per-protocol wire coverage for everyday packet
  work (IPv4, IGMP, IPv6, TCP, UDP, SCTP, ARP, ICMPv6, DHCPv6, DNS, mDNS/DNS-SD,
  BGP, MQTT, NTP, SNMP, OSPF, 802.11, IPsec); UDP, ARP, ICMPv6, IGMP, DHCPv6,
  DNS, mDNS, NTP, SNMP, OSPF, and SCTP now have their own guides.
- [docs/reference/](docs/reference/) — the public API
  ([api.md](docs/reference/api.md)), the wire I/O layer
  ([wire.md](docs/reference/wire.md)), and the example catalog
  ([examples.md](docs/reference/examples.md)).
- [docs/operations/](docs/operations/) — release and validation workflows.
- [docs/operations/tools.md](docs/operations/tools.md) — oracle, probe, smoke,
  and the external execution boundary.
- [CHANGELOG.md](CHANGELOG.md) records release scope and boundaries.

## Validation

Local validation requires no infrastructure credentials:

```sh
cargo test --workspace
cargo doc --workspace --no-deps
```

The full local release gate is:

```sh
.agents/scripts/check-crafter-release --static
```

Hardware-backed validation is requested through operator-supplied tooling only
after the local gate passes. Oracle modes, plan contracts, and CI expectations
are documented in
[docs/operations/validation.md](docs/operations/validation.md).

## Publishing

The final maintainer release checklist, including crates.io guardrails, is in
[docs/operations/release.md](docs/operations/release.md).

Run package-content checks before preparing a release:

```sh
.agents/scripts/check-crafter-release --package-only
```

Run the full local release gate before declaring the branch ready:

```sh
.agents/scripts/check-crafter-release --static
```

Prepare and validate a candidate version with the guarded release helper:

```sh
.agents/scripts/prepare-crafter-release --validate VERSION
```

For agent-assisted publishing, use the repo-local `agent-cargo-publish` skill.
It runs the release gate, performs the guarded `cargo publish -p crafter
--dry-run --locked`, summarizes the crate/version/commit and package contents,
and requires explicit ask-tool approval before the real upload.

The maintainer publish entrypoint is:

```sh
.agents/scripts/publish-crafter-release VERSION
```

Publishing to crates.io is a final maintainer action. The publish script and
skill enforce confirmation; do not run a real publish from unattended
automation.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
