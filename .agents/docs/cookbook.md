# Agent Cookbook

This cookbook is for generated packet tools. Prefer the public `crafter`
facade and `crafter::prelude::*`, keep local behavior offline or dry-run by
default, and require an explicit external execution path before sending packets.

Generated tools should expose structured errors instead of panicking. For small
CLIs, returning `Result<(), Box<dyn std::error::Error>>` is enough. For services
or agent tools, match concrete errors such as `CrafterError::BufferTooShort` and
return fields like `context`, `required`, and `available` to the caller.

## Build A Packet

Use builder-style setters for generated code. The `/` composition operator is
stable and concise, but `Packet::new().push(...)` is also available when a tool
needs conditional layers.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Icmpv4::echo_request().id(0x4242).seq(1)
        / Raw::from("agent-ping");

    let bytes = packet.compile()?;
    println!("{}", packet.summary());
    println!("{}", bytes.hexdump());
    Ok(())
}
```

Use documentation addresses such as `192.0.2.0/24`, `198.51.100.0/24`, and
`2001:db8::/32` in examples and tests. Do not use real targets in generated
defaults.

## Build A Protocol Flow

Use `crafter-flow` when a generated tool needs a stateful packet conversation
instead of a single packet. Keep the default path offline: build the `Flow`,
feed deterministic documentation-space input through a memory source when the
flow needs observed traffic, run it with default `RunOptions`, and print the
`FlowReport` for inspection.

```rust
use crafter::prelude::*;
use crafter_flow::prelude::*;
use std::net::Ipv4Addr;

fn doc_udp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    body: &'static str,
) -> crafter::Packet {
    Ipv4::new()
        .src(src)
        .dst(dst)
        .ipv4_protocol(Ipv4Protocol::Udp)
        / Udp::new().source_port(sport).destination_port(dport)
        / Raw::from(body)
}

fn main() -> crafter_flow::Result<()> {
    let client = Ipv4Addr::new(192, 0, 2, 10);
    let service = Ipv4Addr::new(198, 51, 100, 20);
    let probe = doc_udp(client, service, 49_200, 5353, "probe");
    let followup = doc_udp(client, service, 49_200, 5353, "follow-up");
    let reply = doc_udp(service, client, 5353, 49_200, "ack");

    let mut flow = Flow::new("documentation-protocol")
        .role(Role::Responder)
        .state(FlowState::new("WaitProbe").on(
            Transition::on(
                PredicateMatcher::new("documentation UDP probe", |packet, _ctx| {
                    packet.layer::<Udp>().is_some()
                }),
                move |_packet, _ctx| Ok(Step::send(reply.clone()).goto("WaitFollowup")),
            )
            .targets(["WaitFollowup"]),
        ))
        .state(FlowState::new("WaitFollowup").on(
            Transition::on(
                PredicateMatcher::new("documentation follow-up payload", |packet, _ctx| {
                    packet.layer::<Raw>().is_some()
                }),
                |_packet, _ctx| Ok(Step::goto("Done")),
            )
            .targets(["Done"]),
        ))
        .state(
            FlowState::new("Done")
                .on_entry(|_ctx| Ok(Step::done()))
                .entry_terminal(),
        )
        .initial("WaitProbe");

    let mut runner = Runner::with_source(
        RunOptions::default(),
        MemoryCaptureSource::new(vec![probe, followup]),
    )?;
    let report = runner.run(&mut flow)?;

    println!("{}", report.show());
    Ok(())
}
```

Choose the role deliberately: `Role::Initiator` sends first, `Role::Responder`
waits for another party, and `Role::Injector` observes traffic and emits from
its position. The default binding is dry-run and bounded; live traffic must be a
separate opt-in such as
`RunOptions::default().binding(Binding::interface("lab0").link_layer().live())`
inside an authorized external environment or externally executed run. See
[`tools/flow/README.md`](../../tools/flow/README.md) for the full model.

## Build IPv4 Datagrams

Keep generated IPv4 tools offline or dry-run by default: compile and hexdump the
packet, write deterministic pcap fixtures, run oracle `offline` or
`local-dry-run`, or use `send_dry_run` with an interface such as `dry-run0`.
IPv4 examples and tests should use documentation ranges `192.0.2.0/24`,
`198.51.100.0/24`, and `203.0.113.0/24`; real targets belong only in an
explicitly authorized external execution path.

Use the DS field helpers instead of hand-shifting the historical TOS octet:
`Dscp::new(...)`, `Ecn::{NotEct,Ect1,Ect0,Ce}`, `.dscp(...)`, `.ecn(...)`,
and `.ds_field(...)` cover normal and deliberate raw-byte cases. After decode,
surface `dscp_value()`, `ecn_value()`, and `ds_field_value()` so callers can see
which DSCP and ECN state was actually present on the wire.

Expose IPv4 checksum inspection as packet state, not as a decode failure.
`compile()` fills the header checksum unless the tool set one explicitly, and
decoded packets report `Ipv4ChecksumStatus` through `checksum_status()` so
invalid checksums remain inspectable.

Fragment fields are metadata on the IPv4 layer itself. Generated tools may set
and read identification, reserved/DF/MF flags, `fragment_offset`, and
`fragment_info()`. Use the packet-stream `IpFragment` and `IpDefrag` wire
transforms when a tool needs fragmentation or reassembly; they keep bounded
state, metadata, overlap policy, and timers out of the layer builder.

## Build CoAP Packet Primitives

Generated CoAP tools should return typed `Packet` or `Coap` values and keep
their first path offline. Use the standard prelude, documentation addresses,
and the IP/UDP/CoAP helpers instead of returning raw bytes plus assembly
instructions.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn status_request(message_id: u16, token: [u8; 2]) -> Packet {
    coap_ipv4_request(
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(198, 51, 100, 20),
        Coap::get()
            .message_id(message_id)
            .token(CoapToken::from_bytes(token))
            .uri_path("status")
            .accept(CoapAccept::new(50)),
    )
}

fn main() -> crafter::Result<()> {
    let packet = status_request(0x1234, [0xaa, 0xbb]);
    let plan = packet.send_dry_run(
        SendOptions::new().iface("dry-run0").network_layer(),
    )?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, plan.bytes())?;

    println!("mode=dry-run");
    println!("{}", decoded.summary());
    println!("{}", decoded.show());
    Ok(())
}
```

Use `decode_coap` for a known datagram and `decode_coap_reliable` for one
complete reliable frame. The latter returns a consumed length so a generated
tool can own its stream buffer explicitly. Normal registry decode is the right
choice for mixed traffic: malformed candidates, secure-port ciphertext,
partial or concatenated reliable frames, and unrelated service-port payloads
remain `Raw`.

Keep typed extension work packet-local. `coap_discovery_request` and
`coap_discovery_response` build CoRE Link Format messages; `CoapObserve`,
`CoapBlock`, and the Q-Block helpers expose stateless metadata; and
`OscoreContext::protect`/`unprotect` return ordinary typed `Coap` layers. A
generated tool may retain transaction state, schedule retransmissions, compare
Observe serials, select the next Block/Q-Block request, buffer TCP frames, or
assemble bodies. Those are tool-level workflows because they require endpoint
identity, timers, congestion policy, storage, or transport state; they do not
belong in the packet layer.

Persist deterministic packets with `PacketWire` or the classic pcap backend,
and include `summary()`, `show()`, exact compiled bytes, and structured errors
in tool reports. Never log OSCORE secrets or unauthenticated plaintext.

Plan validation before considering a external runner:

```sh
tools/probe/run --profile smoke --seed 1 --count 10 --out target/probe/plan
```

Live CoAP is optional, externally executed, and never a developer-host raw send.
The manual wrapper must require `LIBCRAFTER_PROBE_LIVE_PROVIDER`,
`LIBCRAFTER_PROBE_LIVE_COAP_CONFIRM=yes`, the runner protocol gate
`LIBCRAFTER_COAP_LIVE_CONFIRM=yes`, and explicit external authorization. Promote only
cases with a disposable controlled responder and finite send/capture bounds;
collect plan, byte, pcap, response, log, external runner, and cleanup artifacts below
ignored `target/` paths, then tear down every endpoint after success, failure,
or timeout. If credentials, virtualization, responder features, or other
capabilities are unavailable, retain the dry-run artifact with a stable skip
reason and do not create infrastructure.

The user-facing API and complete guarded runbook are in
[`docs/guide/coap.md`](../../docs/guide/coap.md). Source authority and detailed
agent validation policy remain in the neighboring CoAP manifest and validation
documents.

## Build MQTT Sessions

MQTT is an application layer over cleartext TCP/1883. Generated tools should
build it as `Ipv4 / Tcp / Mqtt` or `Ipv6 / Tcp / Mqtt`, keep the default path
offline, and reserve live broker sessions for an explicit `--peer` or an
operator-supplied external run. Use documentation IP addresses in examples and
fixtures.

```rust
use crafter::prelude::*;
use crafter::protocols::mqtt::{MqttProperty, MQTT_5_PROTOCOL_LEVEL, MQTT_PUBLISH_QOS_1};
use std::net::Ipv4Addr;

fn main() -> crafter::Result<()> {
    let connect = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        .protocol(IPPROTO_TCP)
        / Tcp::new().sport(49_194).dport(MQTT_PORT).ack_segment()
        / Mqtt::connect()
            .client_id("crafter-agent")
            .keep_alive(30)
            .clean_session(true);

    let publish = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        .protocol(IPPROTO_TCP)
        / Tcp::new().sport(49_194).dport(MQTT_PORT).ack_segment()
        / Mqtt::publish()
            .topic("crafter/demo/outbound")
            .qos(MQTT_PUBLISH_QOS_1)
            .packet_id(2)
            .payload(b"hello from crafter".to_vec());

    for packet in [connect, publish] {
        let bytes = packet.compile()?;
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;
        println!("{}", decoded.summary());
        println!("{}", decoded.show());
    }

    let mqtt5_connect = Mqtt::connect()
        .version(MQTT_5_PROTOCOL_LEVEL)
        .client_id("crafter-agent-v5")
        .connect_property(MqttProperty::SessionExpiryInterval(60))
        .connect_property(MqttProperty::ReceiveMaximum(10));
    println!("{}", mqtt5_connect.summary());

    Ok(())
}
```

For standalone MQTT payloads that do not carry a version marker, choose the
default version explicitly. MQTT 3.1.1 uses protocol level 4; MQTT 5.0 uses
protocol level 5:

```rust
use crafter::prelude::*;

let reply = [0x20, 0x03, 0x00, 0x00, 0x00]; // MQTT 5 CONNACK success + empty props
let decoded = Mqtt::decode_payload_with_default_version(&reply, MQTT_5_PROTOCOL_LEVEL)?;
let mqtt = decoded.layer::<Mqtt>().expect("MQTT layer");
assert_eq!(mqtt.reason_code_value(), Some(0));
```

Keep the first validation pass offline. The example prints packet plans without
opening a socket unless `--peer` is supplied, the oracle compares generated MQTT
corpora against the reference backend, and the probe profile plans a controlled
Mosquitto exchange without starting a broker in local dry-run mode:

```sh
tools/probe/run --profile smoke --seed 1 --count 10 --out target/probe/plan
```

Live MQTT runs must stay opt-in: use `mqtt_session --peer IP:PORT` only against
an authorized broker, or use an externally executed probe/external session that prepares
the broker, collects artifacts under `target/`, and tears the endpoint down.

## Build NTP Packet Primitives

NTP is a packet primitive over UDP/123, not a time synchronization workflow.
Generated tools should build and decode `Ntp` layers, inspect summaries, and
start with offline bytes or dry-run send plans. Use documentation addresses in
defaults and keep live traffic behind externally executed gates.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> crafter::Result<()> {
    let packet =
        Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Udp::new().source_port(49_152).destination_port(NTP_PORT)
        / Ntp::client()
            .transmit_timestamp(NtpTimestamp::from_parts(0xecc0_0000, 0x1234_5678));

    let plan = packet.send_dry_run(
        SendOptions::new().iface("dry-run0").network_layer(),
    )?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, plan.bytes())?;

    println!("mode=dry-run");
    println!("{}", decoded.summary());
    println!("{}", decoded.show());
    Ok(())
}
```

Decode deterministic fixture bytes directly when a generated tool is consuming
payload fixtures instead of a full IP packet:

```rust
use crafter::prelude::*;

const NTP_CLIENT_FIXTURE: [u8; NTP_FIXED_HEADER_LEN] = [
    0x23, 0x00, 0x06, 0xec, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x02, 0x00, 0x00, b'L', b'O', b'C', b'L',
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xec, 0xc0, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78,
];

let ntp = Ntp::decode(&NTP_CLIENT_FIXTURE)?;
let packet = Packet::from_layer(ntp);
println!("{}", packet.summary());
println!("{}", packet.show());
# Ok::<(), crafter::CrafterError>(())
```

Use `Ntp::decode` for direct payload parsing when a generated tool wants
structured errors. Standard UDP decode only claims UDP/123 payloads that pass
the conservative NTP shape gate; unrelated bytes stay `Raw`.

Do not add a pool client, peer state machine, NTS key exchange, Autokey
verification, scanner, or live default. Externally executed live validation for NTP
requires explicit external runner selection, dry-run review,
explicit external authorization, an NTP-specific confirmation such as
`LIBCRAFTER_NTP_LIVE_CONFIRM=yes`, artifact collection, and endpoint teardown.

## Build TLS Packet Primitives

TLS is a packet primitive over TCP, not a TLS endpoint, certificate validator,
scanner, decryptor, or TCP stream reassembler. Generated tools should build and
inspect records, handshakes, extensions, alerts, and opaque application data
through `crafter::prelude::*`, then keep the first run offline or dry-run.
Always use documentation addresses such as `192.0.2.10` and `198.51.100.20` in
defaults.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> crafter::Result<()> {
    let hello = TlsClientHello::new()
        .with_random([0x54; TLS_CLIENT_HELLO_RANDOM_LEN])
        .with_session_id([0x54, 0x4c, 0x53, 0x01])
        .with_raw_cipher_suites([
            TLS_CIPHER_SUITE_AES_128_GCM_SHA256,
            TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256,
        ])
        .with_extensions(vec![
            TlsRawExtension::server_name(TlsServerNameList::from_host_name(
                "tls.agent.example.test",
            )?)?,
            TlsRawExtension::alpn(TlsAlpnProtocols::h2_then_http_1_1())?,
            TlsRawExtension::supported_versions_client(vec![
                TlsVersion::tls_1_3(),
                TlsVersion::tls_1_2(),
            ])?,
            TlsRawExtension::key_share_client(vec![
                TlsKeyShareEntry::x25519([0x54; 32]),
            ])?,
        ]);
    let record = TlsRecord::handshake_messages([
        TlsHandshake::from_client_hello(hello)?,
    ])?;

    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        .ipv4_protocol(Ipv4Protocol::Tcp)
        / Tcp::new().sport(49_171).dport(TLS_PORT_HTTPS).syn()
        / Tls::from_record(record);

    let plan = packet.send_dry_run(
        SendOptions::new().iface("dry-run0").network_layer(),
    )?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, plan.bytes())?;

    println!("mode=dry-run");
    println!("target={:?}", plan.target());
    println!("{}", decoded.summary());
    println!("{}", decoded.show());
    println!("{}", plan.compiled_packet().hexdump());
    Ok(())
}
```

For pcap input, read deterministic fixtures through `PacketWire` and a TCP BPF
filter. Do not start from live capture:

```rust
use crafter::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let source = PacketWire::pcap_file(
        "crafter/tests/fixtures/pcaps/raw-ipv4-tcp-tls-client-hello.pcap",
    )
        .filter("tcp port 443")
        .open()?
        .source()?;

    for record in Sniffer::new(source).no_timeout().collect_records()? {
        let tls = record.packet().layer::<Tls>().expect("TLS layer");
        println!("{}", record.packet().summary());
        for tls_record in tls.records() {
            println!("{}", tls_record.summary());
        }
    }

    Ok(())
}
```

Encrypted TLS payloads are opaque packet bytes. Use
`TlsRecord::application_data(...)` for encrypted application data and raw
extensions or raw handshake bodies when a generated tool needs unknown,
reserved, GREASE, private-use, or future codepoints. Preserve those bytes and
surface `summary()` / `show()` output instead of guessing keys, certificates,
ALPN policy, SNI meaning, or handshake state.

Keep validation offline first:

```sh
tools/probe/run --profile smoke --seed 1 --count 10 --out target/probe/plan
```

Live TLS work belongs behind externally executed gates. Prepare a disposable
execution environment, review the dry-run bytes and pcap artifacts under `target/`,
require an explicit live confirmation flag in the generated tool, and destroy
the external runner resources after the run. Never send crafted TLS traffic from the
developer host by default and never embed real credentials, public hostnames,
private certificates, or sensitive captures in tracked files.

Use an environment-gated command so unattended runs stay offline:

```sh
tools/probe/run --profile smoke --seed 1 --count 10 --out target/probe/plan
```

## Build SSDP Discovery Packets

SSDP is a UDP/1900 application payload. Generated tools should use
`crafter::prelude::*`, build `Ssdp` inside the normal packet stack, and prefer
the public multicast helpers such as `ssdp_ipv4_multicast_packet` when they want
source-backed defaults. Keep generated defaults offline or dry-run, use
documentation addresses and synthetic device identifiers, and keep discovery
workflows outside the crate.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> crafter::Result<()> {
    let packet = ssdp_ipv4_multicast_packet(
        Ipv4Addr::new(192, 0, 2, 10),
        Ssdp::m_search_all().mx(1),
    );

    let plan = packet.send_dry_run(
        SendOptions::new().iface("dry-run0").network_layer(),
    )?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, plan.bytes())?;

    println!("mode=dry-run");
    println!("target={:?}", plan.target());
    println!("{}", decoded.summary());
    println!("{}", decoded.show());
    println!("{}", plan.compiled_packet().hexdump());
    Ok(())
}
```

For decode and fixture validation, start from deterministic bytes: parse
standalone SSDP payloads with `Ssdp::parse`, decode compiled IPv4 or IPv6
datagrams through `Packet::decode_from_l3`, and read or write only synthetic
classic pcap fixtures. UDP/1900 dispatch is deliberately conservative:
structurally valid SSDP messages decode as `Ssdp`, unrelated UDP payloads remain
`Raw`, and malformed explicit parses should be surfaced as structured errors.

The checked-in SSDP examples are offline or dry-run entrypoints for generated
tools:

```sh
cargo run -p crafter --example ssdp_search_plan -- --iface dry-run0
cargo run -p crafter --example ssdp_notify
```

Before any protected live SSDP validation, plan the externally executed work through
the existing dry-run oracle, probe, or external environment flows and keep artifacts under ignored
`target/` paths:

```sh
tools/probe/run --profile smoke --seed 1 --count 10 --out target/probe/plan
```

Do not build an SSDP scanner, discovery daemon, service cache, retry scheduler,
UPnP control point, or live multicast default in `crafter` or in generated
default paths. Real SSDP traffic must be explicitly authorized and routed
through disposable externally executed oracle, probe, or external environment flows with artifact
collection and teardown; do not send live multicast from the developer host by
default.

## Build IGMP

IGMP is an IPv4 packet layer. Generated tools should build it as `Ipv4 / Igmp`
through `crafter::prelude::*`, set the enclosing IPv4 protocol explicitly to
`Ipv4Protocol::Igmp`, and keep the first path offline or dry-run. The IGMP layer
owns the IGMP Type, Code/Max Response Code, checksum, group address, v3 query
body, v3 report records, generic extensions, and MRD packet bytes; it does not
own the enclosing IPv4 TTL, destination address, or Router Alert option.

Use documentation IPv4 sources and RFC 5771 documentation multicast group
addresses such as `233.252.0.0/24` in generated defaults. Add
`Ipv4Option::router_alert(0)` only when the packet shape needs Router Alert,
and make that choice visible in the IPv4 layer instead of hiding it in an IGMP
helper.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> crafter::Result<()> {
    let group = Ipv4Addr::new(233, 252, 0, 42);
    let query_body = IgmpQuery::group_and_source_specific(vec![
        Ipv4Addr::new(192, 0, 2, 50),
        Ipv4Addr::new(192, 0, 2, 51),
    ])
    .with_suppress_router_side_processing(true)
    .with_querier_robustness_variable(2)
    .with_querier_query_interval_seconds(125);

    let ipv4 = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(group)
        .ttl(1)
        .ipv4_protocol(Ipv4Protocol::Igmp)
        .ipv4_option(Ipv4Option::router_alert(0))?;

    let packet = ipv4 / Igmp::v3_membership_query(100, group, query_body);
    let bytes = packet.compile()?;

    println!("{}", packet.summary());
    println!("{}", bytes.hexdump());
    Ok(())
}
```

For reports, compose the common IGMP report header and typed report body as
separate layers. Let counts and checksums auto-fill unless the tool is
deliberately emitting malformed bytes:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let group = Ipv4Addr::new(233, 252, 0, 60);
let report = Igmp::v3_membership_report()
    / IgmpReport::from_group_records(vec![
        IgmpGroupRecord::mode_is_include(group)
            .with_source_address(Ipv4Addr::new(192, 0, 2, 60)),
    ]);
```

Decode IGMP from the normal IPv4 entrypoints and expose packet state directly to
the caller. Unknown valid IGMP payloads remain inspectable as `Raw`; malformed
headers, source lists, records, auxiliary data, extension blocks, and IPv4
wrappers surface as structured `CrafterError` values.

```rust
use crafter::prelude::*;

let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;
if let Some(igmp) = decoded.layer::<Igmp>() {
    println!("type={:?} checksum={:?}", igmp.igmp_type(), igmp.checksum_status());
    println!("group_class={}", igmp_group_address_class_name(igmp.group_address_value()));
}
if let Some(query) = decoded.layer::<IgmpQuery>() {
    println!("sources={}", query.source_addresses().len());
}
if decoded.layer::<Raw>().is_some() {
    println!("raw_tail=true");
}
```

Dry-run send planning is the generated-tool default. Use a documentation
interface name, inspect the compiled bytes and derived filter, and do not send
IGMP from the developer host:

```rust
use crafter::prelude::*;

let plan = packet.send_dry_run(SendOptions::new().iface("dry-run0").network_layer())?;
println!("target={:?}", plan.target());
println!("filter={}", reply_filter(&packet).unwrap_or_default());
println!("{}", plan.compiled_packet().hexdump());
```

Keep IGMP validation offline until the IGMP oracle/probe profiles are present in
the repo, then start with deterministic offline, pcap, and local dry-run modes:

```sh
tools/probe/run --profile smoke --seed 1 --count 10 --out target/probe/plan
```

Live IGMP belongs behind operator-supplied external runners with
explicit confirmation, capability checks, artifact collection under `target/`,
and teardown. Do not generate a multicast router, snooper, proxy, scanner, or
state machine inside the crate or a default tool path.

## Build IPv6 Base And Extension Packets

For general IPv6 packets, start with `Ipv6`, compose extension headers as normal
layers before the transport or `Raw` payload, and keep generated defaults
offline or dry-run. Use documentation IPv6 address space (`2001:db8::/32`) in
examples, fixtures, and dry-run send plans.

Use the typed DSCP/ECN helpers instead of hand-packing Traffic Class bits:
`dscp(Dscp::ef())`, `dscp(Dscp::cs3())`, `dscp(Dscp::class_selector(3)?)`, and
`ecn(Ecn::not_ect() | Ecn::ect0() | Ecn::ect1() | Ecn::ce())`.
`traffic_class(...)` remains the raw override escape hatch, and `dscp_value()` /
`ecn_value()` make decode results inspectable.

```rust
use crafter::prelude::*;

let packet = Ipv6::new()
    .src_str("2001:db8:10::1")?
    .dst_str("2001:db8:20::1")?
    .dscp(Dscp::ef())
    .ecn(Ecn::ect0())
    .try_flow_label(0x12345)?
    / Ipv6HopByHopOptionsHeader::new()
        .option(Ipv6Option::router_alert(IPV6_ROUTER_ALERT_MLD))
        .option(Ipv6Option::padn(2)?)
    / Ipv6DestinationOptionsHeader::new()
        .option(Ipv6Option::generic(0x22, [0xab, 0xcd])?)
    / Udp::new().sport(54049).dport(1049)
    / Raw::from("agent-ipv6");

let bytes = packet.compile()?;
let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes())?;
println!("{}", decoded.show());
```

`compile()` auto-fills payload length and Next Header chaining across supported
extension headers unless the tool set explicit values. Compose
`Ipv6HopByHopOptionsHeader`, `Ipv6DestinationOptionsHeader`, generic routing,
Mobile Routing, Segment Routing, and Fragment Header layers in the order the
packet needs; `crafter` preserves caller order and explicit overrides.

For Fragment Header work, build `Ipv6FragmentHeader::new()` with
`fragment_offset(...)`, `more_fragments(...)`, and `identification(...)` (or the
short aliases) and inspect `fragment_status()` / `fragment_status_label()`.
The crate exposes fragment fields and atomic/initial/non-initial classification,
while packet-stream fragmentation and reassembly belong to `IpFragment` and
`IpDefrag`.

Focused IPv6 validation stays offline unless a human explicitly asks for a live
external run:

```sh
cargo run -p crafter --example ipv6_extensions
cargo test -p crafter --test ipv6_public_api ipv6
tools/oracle/run offline --profile ipv6-enrichment --seed 2 --count 20 --root l3:ipv6 --out target/oracle/ipv6-enrichment-offline
```

For the user-facing IPv6 coverage boundary, see
[`docs/guide/ipv6.md`](../../docs/guide/ipv6.md).

## Build ARP

ARP is a link-layer (L2) protocol, so wrap the `Arp` layer in an `Ethernet`
frame with `ETHERTYPE_ARP`. The `who_has` / `is_at` helpers cover the common
Ethernet/IPv4 request and reply; `compile()` fills the protocol-correct HRD,
PRO, HLN, PLN, and operation defaults. Use RFC 7042 documentation MAC space
(`00:00:5e:00:53:00`–`ff`) and documentation IPv4 for generated defaults.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let me = MacAddr::from([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]);

let request = Ethernet::new()
    .src(me)
    .dst(MacAddr::BROADCAST)
    .ethertype(ETHERTYPE_ARP)
    / Arp::who_has(
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(192, 0, 2, 1),
        me,
    );

println!("{}", request.summary());
```

Named operation codepoints (`ArpOperation`) coexist with the raw `opcode(u16)`
escape hatch, and unknown numeric values round-trip byte-for-byte. ARP-family
opcodes (RARP/DRARP/InARP/ARP-NAK/MAPOS) are named codepoints only — there is no
extension-specific behavior, so do not build tools that assume one. For
nonstandard hardware/protocol families, use the generic raw setters
(`sender_hardware`/`target_hardware`/`sender_protocol`/`target_protocol`); the
matching length field auto-fills from the byte count unless set explicitly, and
a deliberate length mismatch is honored until it fails `compile()` with a
structured `BufferTooShort`.

```rust
use crafter::prelude::*;

let exotic = Arp::new()
    .hardware_type(ARP_HRD_INFINIBAND)
    .protocol_type(ETHERTYPE_IPV6)
    .opcode(1)
    .sender_hardware([0u8; 8])
    .target_protocol([0u8; 16]);

assert!(exotic.sender_mac().is_none());            // typed view declines
assert_eq!(exotic.sender_hardware_bytes_value().len(), 8); // raw view stays
```

ARP dry-run sends use the link-layer plan; never send raw ARP from the
developer host. Reserve the live path for a disposable external environment (see External Execution
Sending below):

```rust
use crafter::prelude::*;

let plan = request.send_dry_run(
    SendOptions::new()
        .iface("dry-run0")
        .link_layer(),
)?;

println!("target={:?}", plan.target());
println!("filter={}", reply_filter(&request).unwrap_or_default());
println!("{}", plan.compiled_packet().hexdump());
```

`reply_filter` emits BPF host terms only for standard 4-byte IPv4 addresses and
degrades to a bare `arp` filter for variable-length or non-IPv4 forms, so
generated matchers stay correct on nonstandard ARP.

Live ARP validation is L2-only. External operator tooling must satisfy
`link_layer_send` + `link_layer_capture`, protected confirmation, artifact
collection, and teardown. When those prerequisites are absent, retain the
deterministic plan rather than faking a live run. The user-facing coverage
boundary lives in [`docs/guide/arp.md`](../../docs/guide/arp.md).

## Build IPv6 Neighbor Discovery (NDP)

NDP is the IPv6 analog of ARP (RFC 4861). Its messages are ICMPv6 messages, so
compose `Ipv6 / Icmpv6::<message>(...)`; the `Icmpv6::router_solicitation`,
`router_advertisement`, `neighbor_solicitation`, `neighbor_advertisement`, and
`redirect` builders return the `Icmpv6` header `/` typed body, and `compile()`
auto-fills the ICMPv6 checksum (over the IPv6 pseudo-header) and every NDP option
length. NDP options are an ordered TLV list built with `NdpOption` constructors;
unknown option types round-trip byte-for-byte.

**Set the IPv6 Hop Limit to 255 on every NDP packet.** RFC 4861 section 11.2
requires NDP messages to be sent with Hop Limit 255, and conformant receivers
**silently discard** any NDP message whose Hop Limit is not 255 (this is the
anti-spoofing check). The NDP builders return the ICMPv6 header and body and do
**not** own the enclosing `Ipv6` layer, so by the crate's honored-overrides rule
they cannot set the Hop Limit for you — the caller must. This is not optional: a
Neighbor Solicitation built with the IPv6 default Hop Limit (64) compiles and
serializes fine but is dropped by a real kernel and never answered. Every NDP
recipe below sets `.hop_limit(255)`.

Use link-local source addresses (`fe80::/10`) and documentation space
(`2001:db8::/32`) in generated defaults, and the solicited-node multicast group
(`ff02::1:ffXX:XXXX`) or all-routers (`ff02::2`) as appropriate.

### Router Advertisement with Prefix Information and MTU

```rust
use crafter::prelude::*;
use std::net::Ipv6Addr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let prefix: Ipv6Addr = "2001:db8:1::".parse()?;

    // router_advertisement_with(cur_hop_limit, managed, other, lifetime, body)
    let body = NdpOptions::new()
        .push(NdpOption::prefix_information(
            prefix, 64, /* on_link */ true, /* autonomous */ true,
            /* valid */ 2_592_000, /* preferred */ 604_800,
        ))
        .push(NdpOption::mtu(1500));

    let ra = Ipv6::new()
        .src("fe80::1".parse::<Ipv6Addr>()?)
        .dst("ff02::1".parse::<Ipv6Addr>()?) // all-nodes
        .hop_limit(255) // REQUIRED for NDP
        / Icmpv6::router_advertisement_with(64, false, false, 1800, body);

    let bytes = ra.compile()?;
    println!("{}", ra.summary());
    println!("{}", bytes.hexdump());
    Ok(())
}
```

### Neighbor Solicitation, matching the Neighbor Advertisement

Send an NS to the target's solicited-node multicast group and match the returned
NA. Keep the live path in a disposable external environment (see External Execution Sending); use dry-run
for generated defaults.

```rust
use crafter::prelude::*;
use std::net::Ipv6Addr;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let me = MacAddr::from([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]);
    let target: Ipv6Addr = "2001:db8::20".parse()?;
    let solicited_node: Ipv6Addr = "ff02::1:ff00:20".parse()?; // ff02::1:ffXX:XXXX

    // NS carrying a Source Link-Layer Address option, addressed to the
    // solicited-node multicast (33:33:ff:XX:XX:XX at L2 per RFC 2464).
    let ns = Ethernet::new()
        .src(me)
        .dst_str("33:33:ff:00:00:20")?
        / Ipv6::new()
            .src("2001:db8::10".parse::<Ipv6Addr>()?)
            .dst(solicited_node)
            .hop_limit(255) // REQUIRED: receivers drop NDP with hop limit != 255
        / Icmpv6::neighbor_solicitation_with_source_link_layer(target, me);

    // Dry-run plan by default; only the external environment path actually transmits.
    let plan = ns.send_dry_run(SendOptions::new().iface("dry-run0").link_layer())?;
    println!("{}", plan.compiled_packet().hexdump());

    // In a external execution, send/receive and inspect the Neighbor Advertisement:
    let options = SendRecv::new()
        .iface("eth0")
        .link_layer()
        .dry_run() // drop for a real external environment send
        .timeout(Duration::from_secs(1))
        .filter("icmp6");
    let report = ns.send_recv_report(options)?;
    if let Some(reply) = report.reply() {
        if let Some(icmpv6) = reply.layer::<Icmpv6>() {
            if let Icmpv6Body::NeighborAdvertisement {
                router, solicited, override_flag, ..
            } = icmpv6.body()
            {
                println!("NA solicited={solicited} override={override_flag} router={router}");
            }
        }
        if let Some(na) = reply.layer::<NeighborAdvertisement>() {
            // Target Link-Layer Address option carries the resolved MAC.
            for option in na.options_ref().iter() {
                if let Some(mac) = option.link_layer_address() {
                    println!("resolved {target} -> {mac}");
                }
            }
        }
    }
    Ok(())
}
```

For Duplicate Address Detection (DAD) the NS source is the unspecified address
`::` and it carries **no** Source Link-Layer Address option; a defending host
answers with an NA. Build it with `Icmpv6::neighbor_solicitation(target)` over an
`Ipv6` layer whose `src` is `::` (still `.hop_limit(255)`).

### Run the NDP behavior probe

The repo ships three NDP behavior cases that exercise a real kernel through the
external runners, modeled on the ARP `who-has` -> `is-at` case:

- `ndp-neighbor-solicitation` — NS -> NA (the reliable kernel analog of ARP)
- `ndp-router-solicitation` — RS -> RA (needs an RA-emitting router on the target)
- `ndp-duplicate-address-detection` — NS from `::` -> defending NA

Dry-run is the safety boundary; start there on either external runner:

```sh
tools/probe/run --profile smoke --seed 1 --count 10 --out target/probe/plan
```

NDP probe cases require `link_layer_send`, `link_layer_capture`, and the derived
`ipv6_multicast` capability, so they plan on authorized L2 environments and skip cleanly
on endpoints without link-layer access. A real exchange needs
explicit external authorization plus a prepared two-endpoint external session; collect
artifacts and tear the session down afterward (see External Execution Sending and the
operator-supplied tooling). The user-facing NDP/ICMPv6 coverage boundary lives in
[`docs/guide/icmpv6.md`](../../docs/guide/icmpv6.md).

## Build Dot11 Stacks

Generated Wi-Fi tools should use the normal packet stack shape. For radiotap
captures and dry-run injection candidates, build `Radiotap / Dot11 / LlcSnap /
...`; for bare IEEE 802.11 pcap fixtures, start with `Dot11`. Do not generate
`Dot11 / Ipv4` as IP-over-Wi-Fi: `LlcSnap` is the explicit LLC/SNAP bridge to
EtherType protocols.

Use documentation MAC addresses (`00:00:5e:00:53:00`-`ff`) and synthetic
payloads in fixtures, examples, and dry-run plans. Do not store real SSIDs,
BSSIDs, credentials, public IPs, or live captures in tracked files.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> crafter::Result<()> {
    let sta = MacAddr::from([0x00, 0x00, 0x5e, 0x00, 0x53, 0x10]);
    let ap = MacAddr::from([0x00, 0x00, 0x5e, 0x00, 0x53, 0x20]);

    let packet = Radiotap::new()
        / Dot11::data()
            .addr1(ap) // receiver/BSSID for this synthetic ToDS=false frame
            .addr2(sta)
            .addr3(ap)
            .sequence_number(7)
        / LlcSnap::new().ethertype(ETHERTYPE_IPV4)
        / Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Udp::new().sport(53000).dport(33434)
        / Raw::from("dot11-agent-payload");

    let bytes = packet.compile()?;
    let decoded = Packet::decode_from_link(LinkType::Radiotap, bytes.as_bytes())?;
    assert!(decoded.layer::<Radiotap>().is_some());
    assert!(decoded.layer::<Dot11>().is_some());
    assert!(decoded.layer::<LlcSnap>().is_some());

    let writer = PacketWire::pcap_recorder("target/dot11-agent-dry-run.pcap", LinkType::Radiotap)
        .open()?
        .writer()?;
    let mut tx = Transmitter::new(writer);
    tx.send(packet.clone())?;

    let plan = packet.send_dry_run(
        SendOptions::new()
            .iface("dot11-monitor-dry-run")
            .link_layer(),
    )?;
    println!("target={:?}", plan.target());
    println!("{}", plan.compiled_packet().hexdump());
    Ok(())
}
```

Keep validation offline first. Use deterministic pcap fixtures and the focused
Dot11 oracle profiles before any live discussion:

```sh
tools/probe/run --profile smoke --seed 1 --count 10 --out target/probe/plan
```

Protected Dot11 data is not decrypted in this phase. If the protected bit is
set, decode stops before LLC/SNAP and keeps the protected body as `Raw` until a
later decrypt phase. Generated analyzers should display `is_protected()`,
`encrypted_body_len()`, and the Raw byte length instead of guessing at inner
IPv4, EAPOL, or RSN layers.

```rust
use crafter::prelude::*;

let sta = MacAddr::from([0x00, 0x00, 0x5e, 0x00, 0x53, 0x11]);
let ap = MacAddr::from([0x00, 0x00, 0x5e, 0x00, 0x53, 0x21]);
let protected_fc = Dot11::data().frame_control_value().with_protected(true);

let protected = Dot11::data()
    .frame_control(protected_fc)
    .addr1(ap)
    .addr2(sta)
    .addr3(ap)
    / Raw::from_bytes([0xaa, 0xaa, 0x03, 0xde, 0xad, 0xbe, 0xef]);

let bytes = protected.compile()?;
let decoded = Packet::decode_from_link(LinkType::Ieee80211, bytes.as_bytes())?;
let dot11 = decoded.layer::<Dot11>().expect("Dot11 layer");
assert!(dot11.is_protected());
assert!(decoded.layer::<LlcSnap>().is_none());
assert!(decoded.layer::<Raw>().is_some());
```

Live radiotap injection is not an automatic generated-tool path. The built-in
sender can produce dry-run link-layer plans for `Radiotap / Dot11`, but current
live radiotap transmission returns an unsupported-send error. Do not add a
generated `--live` mode that assumes monitor-mode injection works. External
operator tooling must own RF authorization, isolated setup, interface
preparation, execution, artifact collection, and cleanup.

## Build BLE Advertising

Generated BLE tools should use the public `crafter` facade:
`crafter::prelude::*`, `BleRadio / BleLlAdv / AdStructure`, `PacketWire`,
`Sniffer`, and `Transmitter`. Keep examples synthetic with documentation BLE
addresses from `00:00:5e:00:53:*`, and do not commit real captures, device
addresses, local names, dongle identifiers, or RF observations.

```rust
use crafter::prelude::*;

fn main() -> crafter::Result<()> {
    let packet = BleRadio::advertising(37)
        / BleLlAdv::adv_ind()
            .tx_add(false)
            .adv_a_str("00:00:5e:00:53:46")?
            .push_ad(AdStructure::flags_general_disc())
            .push_ad(AdStructure::complete_local_name("crafter-ble"));

    let bytes = packet.compile()?;
    println!("{}", packet.summary());
    println!("{}", bytes.hexdump());

    let writer = PacketWire::pcap_recorder("target/ble-agent.pcap", LinkType::BluetoothLeLl)
        .open()?
        .writer()?;
    let mut tx = Transmitter::new(writer);
    tx.send(packet.clone())?;

    let source = PacketWire::pcap_file("target/ble-agent.pcap")
        .open()?
        .source()?;
    for record in Sniffer::new(source).collect_records()? {
        println!("{}", record.packet().summary());
    }

    Ok(())
}

fn decode_sniffed_ble_record(sniffed_record: &[u8]) -> crafter::Result<()> {
    let decoded = Packet::decode_from_link(LinkType::BluetoothLeLl, sniffed_record)?;
    println!("{}", decoded.show());
    Ok(())
}
```

BLE pcap uses `LinkType::BluetoothLeLl`, the BLE LE Link Layer link type with
pseudo-header. Treat pcap input and output as the default path for generated
tools and tests; keep fixtures deterministic and sanitized.

The WHAD serial backend is feature-gated and offline by default. A generated
tool that offers live BLE injection or sniffing should compile `crafter` with
the `whad` feature, expose a local `--live` opt-in, and otherwise stop after
packet construction, decode, pcap work, or a dry-run WHAD target open.

```rust
use crafter::prelude::*;

fn whad_ble_paths(packet: Packet, live: bool) -> crafter::Result<()> {
    let port = "/dev/ttyACM0";
    let channel = 37;

    let dry_run = PacketWire::whad_serial(port)
        .ble_inject()
        .channel(channel);
    assert!(dry_run.is_dry_run());
    let dry_wire = dry_run.open()?;
    assert!(!dry_wire.has_writer());

    if live {
        let inject = PacketWire::whad_serial(port)
            .ble_inject()
            .channel(channel)
            .live()
            .open()?;
        let mut writer = inject.writer()?;
        writer.write_record(&PacketRecord::new(packet))?;

        let sniff = PacketWire::whad_serial(port)
            .ble_sniff(channel)
            .live()
            .open()?;
        for record in Sniffer::new(sniff.source()?).count(10).collect_records()? {
            println!("{}", record.packet().summary());
        }
    }

    Ok(())
}
```

Only call `.live()` in an authorized RF environment with bounded sniff counts
or timeouts. Live WHAD paths are for manual or operator-gated runs, not default
generated-tool behavior.

## Build 802.15.4 and Zigbee

Generated 802.15.4/Zigbee tools should use the public `crafter` facade:
`crafter::prelude::*`, `Dot15d4Radio / Dot15d4 / ZigbeeNwk / ZigbeeAps`,
`PacketWire`, `Sniffer`, and `Transmitter`. Keep examples synthetic with
test-safe 2.4 GHz channels (11 through 26) and documentation PAN ids and short
addresses, and do not commit real captures, device addresses, dongle
identifiers, or RF observations.

```rust
use crafter::prelude::*;

fn main() -> crafter::Result<()> {
    let packet = Dot15d4Radio::on_channel(20)
        / Dot15d4::data()
            .seq(7)
            .dest_short(0x1234, 0x0002)
            .src_short(0x1234, 0x0001)
        / ZigbeeNwk::data()
            .dest(0x0000)
            .src(0x1234)
            .radius(30)
            .seq(42)
        / ZigbeeAps::data()
            .dest_endpoint(1)
            .cluster(0x0006)
            .profile(0x0104)
            .src_endpoint(1)
            .counter(0xaa)
            .payload(&[0x01, 0x02]);

    let bytes = packet.compile()?;
    println!("{}", packet.summary());
    println!("{}", bytes.hexdump());

    let writer = PacketWire::pcap_recorder("target/dot15d4-agent.pcap", LinkType::Ieee802154Tap)
        .open()?
        .writer()?;
    let mut tx = Transmitter::new(writer);
    tx.send(packet.clone())?;

    let source = PacketWire::pcap_file("target/dot15d4-agent.pcap")
        .open()?
        .source()?;
    for record in Sniffer::new(source).collect_records()? {
        println!("{}", record.packet().summary());
    }

    Ok(())
}

fn decode_sniffed_dot15d4_record(sniffed_record: &[u8]) -> crafter::Result<()> {
    let decoded = Packet::decode_from_link(LinkType::Ieee802154Tap, sniffed_record)?;
    println!("{}", decoded.show());
    Ok(())
}
```

`Dot15d4::data()` selects the Data frame type; `dest_short` / `src_short` set
the addressing mode, PAN id, and 16-bit address together (use `dest_extended` /
`src_extended` for 64-bit addresses). `compile()` fills the FCF addressing-mode
bits, the PAN-ID-compression bit, and the CRC-16 FCS, while leaving any field
the tool set explicitly untouched, including values that are wrong on purpose.
`ZigbeeNwk` and `ZigbeeAps` stack on the MAC payload through the same `/`
composition; only header framing plus basic cluster/profile/endpoint fields are
modeled.

802.15.4 pcap uses `LinkType::Ieee802154Tap` (DLT 283, the TAP radio
pseudo-header carried by `Dot15d4Radio`) and `LinkType::Ieee802154` for a bare
MAC frame (DLT 195 with FCS, DLT 230 without). Treat pcap input and output as
the default path for generated tools and tests; keep fixtures deterministic and
sanitized.

The WHAD serial backend is feature-gated and offline by default. A generated
tool that offers live 802.15.4 injection or sniffing should compile `crafter`
with the `whad` feature, expose a local `--live` opt-in, and otherwise stop
after packet construction, decode, pcap work, or a dry-run WHAD target open.

```rust
use crafter::prelude::*;

fn whad_dot15d4_paths(packet: Packet, live: bool) -> crafter::Result<()> {
    let port = "/dev/ttyACM0";
    let channel = 15;

    let dry_run = PacketWire::whad_serial(port)
        .dot15d4_send()
        .channel(channel);
    assert!(dry_run.is_dry_run());
    let dry_wire = dry_run.open()?;
    assert!(!dry_wire.has_writer());

    if live {
        let inject = PacketWire::whad_serial(port)
            .dot15d4_send()
            .channel(channel)
            .live()
            .open()?;
        let mut writer = inject.writer()?;
        writer.write_record(&PacketRecord::new(packet))?;

        let sniff = PacketWire::whad_serial(port)
            .dot15d4_sniff(channel)
            .live()
            .open()?;
        for record in Sniffer::new(sniff.source()?).count(10).collect_records()? {
            println!("{}", record.packet().summary());
        }
    }

    Ok(())
}
```

Only call `.live()` in an authorized RF environment with bounded sniff counts
or timeouts and test-safe channel and PAN/address values. Live WHAD 802.15.4
paths are for manual or operator-gated runs, not default generated-tool
behavior.

## Build QUIC Packet Primitives

Generated QUIC tools should treat `crafter` as a packet primitive, not as an
HTTP/3, QPACK, MASQUE, DoQ, or endpoint stack. Build UDP/QUIC datagrams, frames,
transport parameters, and opaque protected or stream bytes through
`crafter::prelude::*`; keep application semantics in the generated tool that
needs them.

Use `Raw` for bytes whose enclosing QUIC structure is not being modeled, and
use QUIC STREAM or DATAGRAM frame helpers when a fixture needs a packet-level
frame boundary. Do not add an in-crate HTTP/3 parser, QPACK encoder, resolver,
scanner, or stream reassembler to make one generated experiment easier.

```rust
use crafter::prelude::*;

fn main() -> crafter::Result<()> {
    let stream = QuicFrame::stream(
        QuicVarInt::from_u64_unchecked(0),
        b"opaque application stream bytes",
    )?;
    let initial = QuicLongHeaderPacket::initial_builder()
        .packet_number(QuicPacketNumber::new(1))
        .frames([stream])
        .build()?;

    let packet = Ipv4::new()
        .src("192.0.2.10".parse().unwrap())
        .dst("198.51.100.10".parse().unwrap())
        / Udp::new().sport(49152).dport(4433)
        / Quic::new().packet(QuicPacket::from_long_header(initial));

    println!("{}", packet.compile()?.hexdump());
    Ok(())
}
```

For encrypted or unsupported QUIC content, preserve bytes instead of guessing:

```rust
use crafter::prelude::*;

let packet = Ipv4::new()
    / Udp::new().sport(49152).dport(4433)
    / Quic::from_bytes([0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]);
let bytes = packet.compile()?;
assert!(!bytes.as_bytes().is_empty());
# Ok::<(), crafter::CrafterError>(())
```

Keep validation offline first: golden bytes, malformed cases, pcap fixtures,
and oracle/probe dry-runs. Use external execution tooling for any later live
traffic; do not send crafted QUIC traffic from the developer machine by default.

The `quic-smoke` probe profile is the generated-tool behavior path. Only
`quic-initial-udp-observation` has a Rust stimulus adapter today; it sends an
IPv4/UDP/QUIC datagram to a controlled UDP echo target on port 4433. Version
Negotiation, Retry, stateless reset, and protected-flow cases are planned-only
until a stateful controlled QUIC target exists.

```sh
tools/probe/run --profile smoke --seed 1 --count 10 --out target/probe/plan
```

## Build UDP Options

Generated tools should build UDP options as a separate `UdpOptions` layer after
the UDP user payload. Do not append RFC 9868 surplus bytes to `Raw`; doing that
hides the UDP Length boundary from `compile()`, checksum generation, decode,
and oracle normalization.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> crafter::Result<()> {
    let options = UdpOptions::new()
        .udp_option(UdpOption::maximum_datagram_size(1200))?
        .udp_option(UdpOption::echo_request(0x0102_0304))?
        .udp_option(UdpOption::generic(10, [0xaa, 0xbb]))?
        .additional_payload_checksum();

    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Udp::new().sport(53000).dport(33434)
        / Raw::from("agent-udp-options")
        / options;

    let bytes = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;

    if let Some(udp) = decoded.layer::<Udp>() {
        println!("udp_checksum_status={:?}", udp.checksum_status());
    }
    if let Some(options) = decoded.layer::<UdpOptions>() {
        println!("udp_option_status={:?}", options.status());
        for option in options.options() {
            println!("udp_option={option}");
        }
    }

    Ok(())
}
```

Use `UdpOptions::from_options(...)` or `udp_option(...)` for typed cases, and
`UdpOptions::from_bytes(...)` only when the generated tool intentionally needs
already encoded, malformed, unknown, or unsupported bytes. Use
`UdpOption::generic(...)` for unknown SAFE/UNSAFE options and return the
resulting `UdpOptionStatus` to the caller. Treat `UnknownUnsafe`,
`UnsupportedFragmentation`, `OptionChecksumInvalid`, and
`AdditionalPayloadChecksumInvalid` as inspectable packet results, not panics.

`UdpOptions::additional_payload_checksum()` lets `compile()` fill APC from UDP
user data. Use `additional_payload_checksum_value(...)`,
`UdpOption::additional_payload_checksum(...)`, `UdpOptions::option_checksum(...)`,
or explicit `Udp::checksum(...)` only when a test or generated tool is
deliberately emitting fixed or malformed bytes.

## Build SCTP Packet Primitives

SCTP is a packet primitive, not an association stack, socket API, scanner,
stream reassembler, retransmission engine, congestion controller, or AUTH
cryptography implementation. Generated tools should build SCTP bytes through
`Sctp`, `SctpChunk`, `SctpParameter`, and `SctpErrorCause`, then compile,
decode, summarize, and validate them offline or through dry-run plans first.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> crafter::Result<()> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 132))
        .dst(Ipv4Addr::new(198, 51, 100, 132))
        / Sctp::data(
            0x0102_0392,
            1,
            1,
            SCTP_PPID_WEBRTC_STRING,
            b"agent-sctp".to_vec(),
        )
        .sport(5_000)
        .dport(5_001)
        .vtag(0x1122_3392);

    let plan = packet.send_dry_run(
        SendOptions::new().iface("dry-run0").network_layer(),
    )?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, plan.bytes())?;
    let sctp = decoded.layer::<Sctp>().expect("SCTP layer");

    println!("mode=dry-run");
    println!("checksum_status={}", sctp.checksum_status().label());
    println!("{}", decoded.summary());
    Ok(())
}
```

Let `compile()` fill the IPv4 protocol / IPv6 next-header value, SCTP chunk
lengths, padding, and CRC32c checksum unless the tool intentionally needs a
fixed or malformed value. Preserve explicit checksums, verification tags,
ports, flags, lengths, PPIDs, chunk types, parameter types, and cause codes;
surface `SctpChecksumStatus` and unknown-codepoint details to the caller
instead of treating them as panics.

Use typed SCTP layers for RFC 6951 UDP encapsulation too. Do not append SCTP
bytes as an opaque `Raw` payload when the tool needs SCTP decode, checksum
status, oracle normalization, or fixture round trips:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let packet = Ipv4::new()
    .src(Ipv4Addr::new(192, 0, 2, 133))
    .dst(Ipv4Addr::new(198, 51, 100, 133))
    / Udp::new().sport(49_152).dport(SCTP_UDP_ENCAPSULATION_PORT)
    / Sctp::data(0x1111_2233, 1, 2, SCTP_PPID_WEBRTC_STRING, b"udp-sctp".to_vec())
        .sport(5_010)
        .dport(5_011)
        .vtag(0x1020_3040);

let bytes = packet.compile()?;
let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;
assert!(decoded.layer::<Sctp>().is_some());
# Ok::<(), crafter::CrafterError>(())
```

For future, private, reserved, or malformed codepoints, use raw-preserving
helpers such as `SctpChunk::unknown`, `SctpParameter::unknown`,
`SctpUnknownParameter`, and `SctpErrorCause::unknown`. Keep the packet data
inside `Packet` or typed SCTP values so `summary()`, `show()`, pcap fixtures,
and oracle/probe artifacts remain inspectable.

Start SCTP validation with offline byte fixtures, pcap fixtures, and dry-run
oracle and probe plans. The planned SCTP oracle profile uses a reference
backend and documentation-safe packet bytes:

```sh
tools/probe/run --profile smoke --seed 1 --count 10 --out target/probe/plan
```

Real SCTP traffic must be externally executed and explicitly authorized. Do not add
a generated `--live` path that sends from the developer host. Require
explicit external authorization, controlled stimulus and target endpoints, bounded
captures, artifact output below ignored `target/` paths, and teardown in the
same runbook. Never commit external runner credentials, public endpoint addresses,
live host identifiers, live host identifiers, or pcaps from sensitive networks.

## Build TCP Segments

Generated tools should build TCP segments with the typed `Tcp` builder and add
options with `tcp_option(...)`. Each `tcp_option(...)` call encodes one
`TcpOption` and returns `Result`, so option errors surface before `compile()`.
`compile()` fills the unset data offset, pads options to a 32-bit boundary, and
computes the checksum from the IPv4 or IPv6 pseudo-header — do not set those by
hand unless a tool is intentionally emitting malformed bytes. The control-bit
builders (`syn_segment`, `syn_ack_segment`, `ack_segment`, `rst_ack_segment`,
`fin_ack_segment`) set the exact flag set, replacing the default SYN.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> crafter::Result<()> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Tcp::new()
            .sport(40000)
            .dport(443)
            .syn_segment()
            .window(64240)
            .tcp_option(TcpOption::maximum_segment_size(1460))?
            .tcp_option(TcpOption::sack_permitted())?
            .tcp_option(TcpOption::window_scale(7))?
            .tcp_option(TcpOption::timestamp(0x0102_0304, 0))?;

    let bytes = packet.compile()?;
    println!("{}", packet.summary());
    println!("{}", bytes.hexdump());
    Ok(())
}
```

Use the typed `TcpOption` constructors (`maximum_segment_size`,
`window_scale`, `sack_permitted`, `timestamp`, `sack`, `user_timeout`,
`fast_open`, `multipath_tcp`, and the experimental/AO/ENO/AccECN forms) so the
option length and wire layout fill correctly. For an unknown or deliberately
malformed kind, use `TcpOption::generic(kind, data)` or the raw
`Tcp::option(bytes)` / `Tcp::options(bytes)` setters; decode still classifies
the result with `TcpOptionKindClass` instead of discarding it.

## Decode TCP Replies

Decode a reply with the entrypoint that matches the bytes (`NetworkLayer::Ipv4`
or `NetworkLayer::Ipv6` for raw IP sockets). Pull the `Tcp` layer with
`layer::<Tcp>()`, read the control bits and ports with the typed accessors, and
walk options with `parsed_options()`. Valid unknown options round-trip as typed
data, and malformed headers or options surface as structured errors.

```rust
use crafter::prelude::*;

fn inspect_reply(bytes: &[u8]) -> crafter::Result<()> {
    let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes)?;
    println!("{}", packet.show());

    if let Some(tcp) = packet.layer::<Tcp>() {
        println!(
            "tcp {} -> {} syn={} ack={}",
            tcp.source_port_value(),
            tcp.destination_port_value(),
            tcp.has_flag(TCP_FLAG_SYN),
            tcp.has_flag(TCP_FLAG_ACK),
        );

        for option in tcp.parsed_options()? {
            if let Some(mss) = option.maximum_segment_size_value() {
                println!("peer_mss={mss}");
            }
            if let Some(shift) = option.window_scale_shift() {
                println!("peer_window_scale={shift}");
            }
            println!("option={} class={:?}", option.kind_name(), option.kind_class());
        }
    }

    Ok(())
}
```

## Size TCP Payloads

`crafter` never discovers a path MTU; the caller supplies it. Use the pure
sizing helpers to budget options and payload before building. They live on
`crafter::protocols::transport` (the prelude already re-exports `Tcp`,
`TcpOption`, and the classic option constants):

```rust
use crafter::prelude::*;
use crafter::protocols::transport::{
    effective_mss, max_tcp_payload, option_budget, remaining_option_budget, tcp_header_len,
};

fn budget(path_mtu: usize) {
    // 40-octet option ceiling and what is left after MSS + SACK-OK + WScale.
    let used = 4 + 2 + 3; // MSS(4) + SACK-Permitted(2) + Window Scale(3)
    println!("option_budget={} remaining={}", option_budget(), remaining_option_budget(used));

    // Largest user-data payload for this path MTU over IPv4 (20) + TCP header.
    let header = tcp_header_len(used);
    let payload = max_tcp_payload(path_mtu, 20, header);
    println!("tcp_header_len={header} max_payload={payload}");

    // Source-backed MSS guidance; `None` falls back to the RFC default.
    println!("effective_mss_ipv4={}", effective_mss(false, Some(path_mtu)));
    println!("effective_mss_ipv4_default={}", effective_mss(false, None));
}
```

## Build BGP Messages

BGP is a TCP application payload. Generated tools should build individual BGP
messages with `Bgp` and keep any session state, negotiated capabilities, RIB
state, or policy outside `crafter`. The crate builds and decodes wire messages;
it is not a BGP finite state machine.

The BGP layer and helper types are available through `crafter::prelude::*`:
`Bgp`, `BgpCapability`, `BgpPathAttribute`, `BgpPrefix`, `AsPathSegment`, and
the origin/AS-path helper constants. Defaults use documentation prefixes and
private ASNs.

```rust
use crafter::prelude::*;
use std::net::{Ipv4Addr, Ipv6Addr};

fn main() -> crafter::Result<()> {
    let ipv4 = BgpPrefix::from_ipv4(Ipv4Addr::new(203, 0, 113, 0), 24)?;
    let ipv6 = BgpPrefix::from_ipv6("2001:db8::".parse::<Ipv6Addr>()?, 32)?;

    let open = Packet::from_layer(
        Bgp::open()
            .my_as(65000)
            .hold_time(90)
            .bgp_id(Ipv4Addr::new(192, 0, 2, 1))
            .capabilities([
                BgpCapability::ipv4_unicast(),
                BgpCapability::ipv6_unicast(),
                BgpCapability::route_refresh(),
                BgpCapability::four_octet_as(65000),
            ]),
    );

    let update = Packet::from_layer(
        Bgp::update()
            .attribute(BgpPathAttribute::origin(BGP_ORIGIN_IGP))
            .attribute(BgpPathAttribute::as_sequence(&[65000]))
            .attribute(BgpPathAttribute::next_hop(Ipv4Addr::new(192, 0, 2, 1)))
            .nlri(ipv4),
    );

    let mp_update = Packet::from_layer(
        Bgp::update()
            .attribute(BgpPathAttribute::origin(BGP_ORIGIN_IGP))
            .attribute(BgpPathAttribute::as_sequence4(&[65000]))
            .attribute(BgpPathAttribute::mp_reach_ipv6(
                "2001:db8::1".parse::<Ipv6Addr>()?,
                &[ipv6],
            )),
    );

    for packet in [open, Packet::from_layer(Bgp::keepalive()), update, mp_update] {
        let bytes = packet.compile()?;
        println!("{}", packet.summary());
        println!("{}", bytes.hexdump());
    }

    Ok(())
}
```

Use `BgpCapability::raw` and `BgpPathAttribute::unknown(...).with_flags(...)`
when a tool needs to preserve an unknown codepoint or deliberately emit unusual
bytes. Use `marker`, `length`, `opt_params_len`, `withdrawn_len`, and `attr_len`
only for malformed-on-purpose tests; the normal path should let `compile()`
fill them.

BGP decode goes through the default TCP registry when either TCP port is 179:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let packet = Ipv4::new()
    .src(Ipv4Addr::new(192, 0, 2, 10))
    .dst(Ipv4Addr::new(198, 51, 100, 20))
    / Tcp::new().sport(49152).dport(179).ack_segment()
    / Bgp::keepalive();

let bytes = packet.compile()?;
let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;
for bgp in decoded.layers::<Bgp>() {
    println!("{}", bgp.summary());
}
```

### BGP Session Example

Use the `bgp_session` example as the generated-tool reference for sequencing
OPEN, KEEPALIVE, UPDATE, inbound decode, and Cease teardown. With no `--peer`,
it is offline and only prints the planned documentation-safe messages:

```sh
cargo run -p crafter --example bgp_session
cargo run -p crafter --example bgp_session -- --ipv6
```

The live form is opt-in and belongs only inside a disposable external environment endpoint:

```sh
cargo run -p crafter --example bgp_session -- \
  --peer 192.0.2.20:179 \
  --ipv6 \
  --linger-seconds 45 \
  --out target/bgp/manual
```

Do not use a real internet peer in generated defaults. Do not write live public
IPs, external runner IDs, credentials, or packet captures into tracked files.

### BGP external qualification

Generate the deterministic `bgp-smoke` plan locally. If wire evidence is
required, an operator-supplied external runner must provide the controlled peer
and execute the exact candidate revision.

## Build RIP / RIPng Messages

RIP is a UDP application payload: RIPv1/RIPv2 ride over UDP/520
(`Ipv4 / Udp / Rip`), and RIPng rides over UDP/521 and IPv6
(`Ipv6 / Udp / Ripng`). Generated tools should build individual RIP messages
with the typed `Rip`/`Ripng` builders and keep any route table, distance-vector
convergence, split-horizon, or timer state outside `crafter`. The crate builds
and decodes wire messages; it is not a routing engine.

The layers and route-entry types are available through `crafter::prelude::*`:
`Rip`, `RipEntry`, `RipCommand`, `Ripng`, `RipngRte`, plus the codepoint
constants (`RIP_UDP_PORT`, `RIP_V2_MULTICAST`, `RIP_METRIC_INFINITY`,
`RIPNG_UDP_PORT`, `RIPNG_MULTICAST`, ...). The whole-table-request and multicast
convenience helpers (`rip_v2_whole_table_request`, `rip_v2_multicast_response`)
and the authentication types (`RipAuth`, `RipDigestAlgorithm`) are reached
through the `crafter::protocols::rip` module path. Defaults use documentation
addresses.

```rust
use crafter::prelude::*;
use crafter::protocols::rip::{rip_v2_multicast_response, rip_v2_whole_table_request};
use std::net::Ipv4Addr;

fn main() -> crafter::Result<()> {
    // RIPv2 whole-table request: a single AFI-0 / metric-16 sentinel entry
    // addressed to the 224.0.0.9 multicast group.
    let request = rip_v2_whole_table_request(Ipv4Addr::new(192, 0, 2, 10));

    // RIPv2 response advertising documentation-range routes with route tag,
    // subnet mask, and next hop set per entry.
    let response = rip_v2_multicast_response(
        Ipv4Addr::new(192, 0, 2, 10),
        vec![
            RipEntry::ipv2_route(
                Ipv4Addr::new(198, 51, 100, 0),
                Ipv4Addr::new(255, 255, 255, 0),
                1,
            )
            .with_route_tag(0xABCD)
            .with_next_hop(Ipv4Addr::new(192, 0, 2, 1)),
            RipEntry::ipv2_route(
                Ipv4Addr::new(198, 51, 100, 128),
                Ipv4Addr::new(255, 255, 255, 128),
                2,
            ),
        ],
    );

    for packet in [request, response] {
        let bytes = packet.compile()?;
        println!("{}", packet.summary());
        println!("{}", bytes.hexdump());
    }

    Ok(())
}
```

Attach RIPv2 authentication with the `Rip::auth(auth, key)` builder. Build the
`RipAuth` either as a simple password (`RipAuth::simple_password`) or as a keyed
message digest (`RipAuth::keyed_digest_with(RipDigestAlgorithm::KeyedMd5, key_id)`,
or an HMAC-SHA variant). When the caller does not pin a digest, `compile()`
computes it over the message; a caller-set digest survives untouched.
**Authentication keys are caller-supplied test material — fixed bytes in
examples and fixtures, never a real secret, and never committed.**

```rust
use crafter::prelude::*;
use crafter::protocols::rip::{RipAuth, RipDigestAlgorithm};
use std::net::Ipv4Addr;

fn main() -> crafter::Result<()> {
    // Keyed-MD5 (RFC 2082): a leading auth header entry plus a trailing digest
    // block that compile() fills. The key here is documentation-only.
    let authed = Packet::from_layer(
        Rip::response()
            .version(RIP_VERSION_2)
            .with_entries(vec![RipEntry::ipv2_route(
                Ipv4Addr::new(198, 51, 100, 0),
                Ipv4Addr::new(255, 255, 255, 0),
                1,
            )])
            .auth(
                RipAuth::keyed_digest_with(RipDigestAlgorithm::KeyedMd5, 7),
                b"md5-test-key".to_vec(),
            ),
    );

    let bytes = authed.compile()?;
    println!("{}", authed.summary()); // key bytes are never printed
    println!("{}", bytes.hexdump());
    Ok(())
}
```

RIPng builds the same way over IPv6: compose `Ipv6 / Udp / Ripng`, push
`RipngRte` route entries, and mark a next-hop RTE with `RipngRte::next_hop(...)`
(metric 0xFF). `RipngRte::whole_table_request()` is the RIPng sentinel.

RIP and RIPng decode goes through the default UDP registry when the port is 520
(RIP) or 521 (RIPng); unrelated traffic on those ports falls through to `Raw`.
Decode a captured datagram with `decode_from_l3` and inspect with
`summary()`/`show()`:

```rust
use crafter::prelude::*;

fn inspect_rip(bytes: &[u8]) -> crafter::Result<()> {
    let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes)?;
    println!("{}", packet.show());

    if let Some(rip) = packet.layer::<Rip>() {
        println!("rip command={:?} version={}", rip.command(), rip.version_value());
        for entry in rip.entries() {
            println!(
                "  route {} mask {} metric {}",
                entry.address_value(),
                entry.subnet_mask_value(),
                entry.metric_value(),
            );
        }
    }
    Ok(())
}
```

Use `command(u8)`, `version(u8)`, `reserved(u16)`, and the per-entry raw setters
only for malformed-on-purpose tests; the normal path lets `compile()` fill the
reserved fields, version, address families, and digest. A truncated or
non-multiple-of-20 body decodes to a structured `CrafterError::BufferTooShort`
(`context`/`required`/`available`), never a panic, and unknown commands or
address families round-trip as preserved values.

Keep generated RIP validation offline first. The `rip-smoke` oracle profile
covers RIP and RIPng byte vectors and decode models, and the `rip-smoke` probe
profile plans the live exchange against an FRR `ripd` target service — all
without a network:

```sh
tools/probe/run --profile smoke --seed 1 --count 10 --out target/probe/plan
```

A real RIP exchange is opt-in only and must run from disposable infrastructure,
never raw from the developer host. Start with the probe dry-run above, then
prepare an externally executed routing daemon through operator-supplied tooling (see External Execution
Sending and the operator-supplied tooling); collect artifacts and tear the session
down afterward. For the user-facing coverage boundary, see
[`docs/guide/rip.md`](../../docs/guide/rip.md), and for the RFC/IANA source mapping see
[`.agents/docs/rip-manifest.md`](rip-manifest.md).

## Build IPSec (ESP, AH, IKEv2)

IPSec is a set of ordinary layers: `Esp`, `Ah`, the `IkeHeader` plus the typed
IKEv2 payload set, and the `NatTraversal` marker, all reachable through
`crafter::prelude::*`. They compose with `/` over IPv4 and IPv6 and slot into the
same builder/decode/summary shape as every other protocol. `crafter` is a
**wire-level primitive**, not a kernel IPSec stack: there is no SAD/SPD, no
replay window, and IKEv2 is message wire format only (no negotiation, no
Diffie-Hellman, no key derivation).

A `SecurityAssociation` is the per-packet crypto context that drives ESP/AH and
the IKEv2 Encrypted (SK) payload. **Keys are caller-supplied test material — fixed
repeated bytes in examples and fixtures, never a real secret, and never
committed.** Build one with the consuming fluent builder and a documentation SPI:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // AES-GCM-16 (AEAD) transport SA. AEAD carries its own integrity, so the
    // pair is `IntegrityAlgorithm::None`; AEAD/CTR suites also carry a salt.
    // The 0x24 / 0xA1B2C3D4 bytes are documentation-only key material.
    let sa = SecurityAssociation::new(0x0000_2100)
        .encryption(EncryptionAlgorithm::AesGcm16, vec![0x24u8; 16])
        .salt(vec![0xA1, 0xB2, 0xC3, 0xD4])
        .transport();
    sa.validate()?; // checks key/salt lengths; never mutates the caller's bytes

    // `Esp::secured(sa)` seals the layers that follow; the IP layer advertises
    // ESP (protocol 50). The TCP / Raw tail is encrypted *inside* the ESP body,
    // so there is no cleartext copy on the wire. The IV is pinned for a
    // deterministic fixture.
    let esp = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        .protocol(IPPROTO_ESP)
        / Esp::secured(sa).spi(0x0000_2100).sequence(1)
            .iv(vec![1, 2, 3, 4, 5, 6, 7, 8])
        / Tcp::new().sport(40001).dport(443)
        / Raw::from("agent-esp");

    let bytes = esp.compile()?;
    println!("{}", esp.summary()); // key/salt bytes are never printed
    println!("{}", bytes.hexdump());
    Ok(())
}
```

`compile()` fills the pad, pad-length, next-header, and ICV; an explicit `.spi`,
`.sequence`, `.iv`, `.pad`, `.icv`, or `.next_header` is emitted verbatim,
including a deliberately wrong value for malformed testing. AH (`Ah::secured(sa)`,
protocol 51) is the integrity-only analog — it authenticates but never encrypts,
so the upper layer travels in the clear. Tunnel mode (`.tunnel()` on the SA)
protects a whole inner IP datagram placed after `Esp`/`Ah`.

An `IKE_SA_INIT` is the `IkeHeader` plus the composed payload chain over
UDP/500; `compile()` derives the Next Payload chain from layer order and fills
the IKE message length. SK payloads (`IkeEncryptedPayload::new(sa)`) own their
inner chain and seal it under the same SA shape.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proposal = Proposal::new(1, PROTOCOL_ID_IKE)
        .with_transform(
            Transform::new(TRANSFORM_TYPE_ENCR, 20)
                .with_attribute(TransformAttribute::key_length(128)),
        )
        .with_transform(Transform::new(TRANSFORM_TYPE_DH, DH_GROUP_MODP_2048));

    let header = IkeHeader::new()
        .initiator_spi(0x0102_0304_0506_0708)
        .exchange(IKE_SA_INIT)
        .initiator();

    let ike = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        .protocol(IPPROTO_UDP)
        / Udp::new().sport(500).dport(500)
        / header
        / IkeSaPayload::new().with_proposal(proposal)
        / IkeKePayload::new(DH_GROUP_MODP_2048, vec![0xAB; 32])
        / IkeNoncePayload::new(vec![0x5A; 16]);

    let bytes = ike.compile()?;
    println!("{}", ike.summary());
    println!("{}", bytes.hexdump());
    Ok(())
}
```

Decoding follows the registry rule: the built-in registry carries no SA, so ESP
and AH decode as typed headers with the encrypted body preserved as opaque
ciphertext that re-compiles byte-for-byte (an SK payload decodes opaquely, and
unknown IKE payload types decode as a preserved `Raw`). Register the matching SA
to decrypt and verify — `ProtocolRegistry::with_security_association(sa)` (or
`register_security_association`) keys SAs by SPI:

```rust
use crafter::prelude::*;

fn inspect_esp(bytes: &[u8], sa: SecurityAssociation) -> Result<(), CrafterError> {
    // No SA: the ESP header is typed but the body stays opaque.
    let opaque = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes)?;
    let esp = opaque.layer::<Esp>().expect("typed ESP header");
    println!("spi={:?} opaque={}", esp.spi_value(), esp.opaque_body().is_some());

    // With the SA: the ICV is verified (constant-time), the body is decrypted,
    // padding is stripped, and the inner layers are dispatched as typed layers.
    // A one-bit change to the ciphertext or ICV fails closed with a structured
    // `CrafterError` (`ipsec.sa.icv` / `ipsec.ah.icv`) — never a panic and never
    // a silently wrong plaintext.
    let registry = ProtocolRegistry::new().with_security_association(sa);
    let decoded =
        Packet::decode_from_l3_with_registry(&registry, NetworkLayer::Ipv4, bytes)?;
    if let Some(tcp) = decoded.layer::<Tcp>() {
        println!("inner tcp dport={}", tcp.destination_port_value());
    }
    Ok(())
}
```

Keep generated IPSec validation offline first. The oracle compares libcrafter
bytes and the decode model against the oracle reference backend, and the `ipsec`
probe profile plans the ESP/AH/IKEv2 behavioral exchange plus an engine-level
cross-crypto parity check — all without a network:

```sh
tools/probe/run --profile smoke --seed 1 --count 10 --out target/probe/plan
```

Any live IPSec exchange is opt-in only and must run from disposable
infrastructure, never raw from the developer host. Start with the probe dry-run
above, then prepare a controlled IPSec-capable peer through operator-supplied tooling
(see External Execution Sending and the operator-supplied tooling); collect artifacts and tear
the session down afterward. For the user-facing coverage boundary, see
[`docs/guide/ipsec.md`](../../docs/guide/ipsec.md).

## Validate TCP

Validate TCP builder and decode behavior locally first:

```sh
tools/oracle/run offline --family tcp --profile smoke --seed 1 --count 20
tools/probe/run --profile tcp-smoke --seed 1 --count 3 --out target/probe/tcp
```

Wire qualification is external and uses the exact candidate revision.

## Decode Bytes

Pick the decode entrypoint from the context that produced the bytes. Link-layer
pcaps usually use `LinkType::Ethernet`; raw IP sockets usually use
`NetworkLayer::Ipv4` or `NetworkLayer::Ipv6`.

```rust
use crafter::prelude::*;

fn decode_ipv4(bytes: &[u8]) -> Result<(), CrafterError> {
    let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes)?;
    println!("{}", packet.show());

    if let Some(tcp) = packet.layer::<Tcp>() {
        println!(
            "tcp {} -> {}",
            tcp.source_port_value(),
            tcp.destination_port_value()
        );
    }

    Ok(())
}
```

Malformed input should be reported as data, not hidden. For example:

```rust
match Packet::decode_from_l3(NetworkLayer::Ipv4, bytes) {
    Ok(packet) => println!("{}", packet.summary()),
    Err(CrafterError::BufferTooShort { context, required, available }) => {
        eprintln!("decode_error context={context} required={required} available={available}");
    }
    Err(error) => eprintln!("decode_error {error}"),
}
```

## Read A pcap

Use `PacketWire` with `Sniffer` for full offline reads. Add `.filter(...)`
before opening when a libpcap BPF filter should be applied while reading.

```rust
use crafter::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let source = PacketWire::pcap_file("capture.pcap")
        .filter("tcp or udp")
        .open()?
        .source()?;

    let records = Sniffer::new(source).collect_records()?;
    for captured in records {
        println!(
            "metadata={:?} summary={}",
            captured.metadata(),
            captured.packet().summary()
        );
    }
    Ok(())
}
```

## Write A pcap

Use a packet wire recorder for deterministic fixtures. Use an explicit link
type so the file can be decoded later without guessing.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let packet = Ethernet::new()
        .src_str("02:00:5e:00:53:01")?
        .dst_str("02:00:5e:00:53:ff")?
        / Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Udp::new().sport(53000).dport(33434)
        / Raw::from("payload");

    let writer = PacketWire::pcap_recorder("target/agent-fixture.pcap", LinkType::Ethernet)
        .open()?
        .writer()?;
    let mut tx = Transmitter::new(writer);
    tx.send(packet)?;
    Ok(())
}
```

## Sniff With A Filter

Prefer offline sniffing for generated code and tests. It exercises the same
packet decode paths without requiring root or interfaces.

```rust
use crafter::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let packets = Sniffer::offline("target/agent-fixture.pcap")
        .filter("udp")
        .count(10)
        .collect()?;

    for packet in packets {
        println!("{}", packet.packet().summary());
    }
    Ok(())
}
```

Live sniffing must be bounded and external-only:

```rust
use crafter::prelude::*;
use std::time::Duration;

let packets = Sniffer::interface("eth0")
    .filter("icmp")
    .count(3)
    .timeout(Duration::from_secs(2))
    .collect()?;
```

Only run that form inside a disposable external execution.

## Dry-Run Sending

Dry-run is the default mode generated tools should choose. It compiles the
packet, derives the send target, and returns a plan without transmitting.

```rust
use crafter::prelude::*;

let plan = packet.send_dry_run(
    SendOptions::new()
        .iface("dry-run0")
        .network_layer(),
)?;

println!("target={:?}", plan.target());
println!("{}", plan.compiled_packet().hexdump());
```

Expose a `--live` flag only when the tool also checks for an isolated external environment marker
or is run through `tools/external execution/`.

## External execution boundary

Tracked examples and generated tools default to dry-run. When real traffic is
required, an operator-supplied external runner selects the authorized machine,
satisfies the declared runtime requirements, invokes the bounded workload, and
returns artifacts. Do not add machine lifecycle, credentials, remote access,
hardware leases, or topology to this repository.

## Oracle Validation

Use the oracle runner when generated tools change packet behavior. The oracle is
the validation system. Backend-specific names and implementation details belong
inside `tools/oracle/`; agents should not add ad hoc reference-backend imports
to tests or scripts when an oracle mode covers the same behavior.

Adding an oracle protocol is plug-and-play: drop in the per-stage plugin modules
under `engine/protocols/` and the matching `engine/backends/*/protocols/`
packages, plus spec files, with no central dispatcher edits. See
`tools/oracle/docs/adding-a-protocol.md` for the full recipe and exact paths (ARP
worked example, plugin callback signatures, the `StackEncoder` raw-bytes option,
spec files, and the test gate).

Offline validation compares generated raw packet vectors and normalized decode
models without root privileges:

```sh
tools/oracle/run offline --profile smoke --seed 1 --count 10
```

Pcap validation exercises pcap writer, reader, and roundtrip behavior:

```sh
tools/oracle/run pcap --profile smoke --seed 1 --count 10
```

For UDP options, keep generated-tool validation offline or dry-run unless a
human has explicitly authorized a disposable execution endpoint:

```sh
tools/probe/run --profile smoke --seed 1 --count 10 --out target/probe/plan
```

Live validation routes through a external runner. Use `local-dry-run` for agent and CI
planning, and reserve real external runners for explicit external execution workflows:

```sh
tools/probe/run --profile smoke --seed 1 --count 10 --out target/probe/plan
```

Guard real UDP option live validation with an environment opt-in and keep the
external runner disposable:

```sh
tools/probe/run --profile smoke --seed 1 --count 10 --out target/probe/plan
```

Artifacts default below `target/oracle/`, with mode-specific reports under
`target/oracle/offline`, `target/oracle/pcap`, and `target/oracle/live`. Every
failing oracle command should be rerunnable with the same `--profile`, `--seed`,
`--count`, and, when the report identifies one packet, `--index`.

Pull request CI runs deterministic oracle offline coverage and pcap smoke
coverage with the configured backend. Externally executed live traffic must stay
behind explicit external execution confirmation or dry-run workflows.

## send_recv Matching

Use `send_recv_report` when the tool needs the derived reply filter and timeout
state. In dry-run mode it builds the request and filter without sending.

```rust
use crafter::prelude::*;
use std::time::Duration;

let options = SendRecv::new()
    .iface("dry-run0")
    .network_layer()
    .dry_run()
    .timeout(Duration::from_secs(1))
    .retries(1)
    .filter("icmp");

let report = packet.send_recv_report(options)?;
println!("filter={}", report.effective_filter().unwrap_or(""));
println!("timed_out={}", report.timed_out());

if let Some(reply) = report.reply() {
    println!("reply={}", reply.summary());
}
```

For offline tests, build a synthetic reply and use `reply_matches(&request,
&reply)` to validate matching logic without live traffic.

## Batch Scans

Use `BatchSendRecv` for ping sweeps, traceroute probes, and ARP scans. Keep
timeouts short, cap the packet list, and return per-request reports to the
caller.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let src = Ipv4Addr::new(192, 0, 2, 10);
let dst = Ipv4Addr::new(198, 51, 100, 20);
let packets = (1..=4)
    .map(|ttl| {
        Ipv4::new().src(src).dst(dst).ttl(ttl)
            / Icmpv4::echo_request().id(0x4242).seq(ttl as u16)
    })
    .collect::<Vec<_>>();

let report = send_recv_packets(
    &packets,
    BatchSendRecv::new()
        .iface("dry-run0")
        .network_layer()
        .dry_run()
        .retries(1)
        .filter("icmp"),
)?;

for entry in report.entries() {
    println!(
        "request={} attempts={} matched={}",
        entry.request_index(),
        entry.attempts(),
        entry.reply().is_some()
    );
}
```

## Oracle Comparison

Use oracle offline artifacts to validate byte-level behavior for deterministic
packets. Offline generation does not require root.

```sh
tools/oracle/run offline --profile smoke --seed 1 --count 10
```

A generated Rust tool can write its compiled bytes to a target file and compare
against the raw vector artifacts under `target/oracle/offline/`. Prefer exact
byte comparison for stable headers and structured field comparison when
timestamps, random ids, route state, or OS-assigned values are expected to vary.
