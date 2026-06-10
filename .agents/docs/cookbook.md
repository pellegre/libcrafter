# Agent Cookbook

This cookbook is for generated packet tools. Prefer the public `crafter`
facade and `crafter::prelude::*`, keep local behavior offline or dry-run by
default, and require an explicit live-lab path before sending packets.

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

## Build IPv4 Datagrams

Keep generated IPv4 tools offline or dry-run by default: compile and hexdump the
packet, write deterministic pcap fixtures, run oracle `offline` or
`local-dry-run`, or use `send_dry_run` with an interface such as `dry-run0`.
IPv4 examples and tests should use documentation ranges `192.0.2.0/24`,
`198.51.100.0/24`, and `203.0.113.0/24`; real targets belong only in an
explicitly authorized live-lab path.

Use the DS field helpers instead of hand-shifting the historical TOS octet:
`Dscp::new(...)`, `Ecn::{NotEct,Ect1,Ect0,Ce}`, `.dscp(...)`, `.ecn(...)`,
and `.ds_field(...)` cover normal and deliberate raw-byte cases. After decode,
surface `dscp_value()`, `ecn_value()`, and `ds_field_value()` so callers can see
which DSCP and ECN state was actually present on the wire.

Expose IPv4 checksum inspection as packet state, not as a decode failure.
`compile()` fills the header checksum unless the tool set one explicitly, and
decoded packets report `Ipv4ChecksumStatus` through `checksum_status()` so
invalid checksums remain inspectable.

Fragment fields are metadata, not a reassembly API. Generated tools may set and
read identification, reserved/DF/MF flags, `fragment_offset`, and
`fragment_info()`, but `crafter` does not split payloads into fragments,
reassemble fragments, or model fragment caches, overlap handling, or timers.

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
but it does not split payloads or perform IPv6 reassembly.

Focused IPv6 validation stays offline unless a human explicitly asks for a live
provider run:

```sh
cargo run -p crafter --example ipv6_extensions
cargo test -p crafter --test ipv6_public_api ipv6
tools/oracle/run offline --profile ipv6-enrichment --seed 2 --count 20 --root l3:ipv6 --out target/oracle/ipv6-enrichment-offline
```

For the user-facing IPv6 coverage boundary, see
[`docs/ipv6.md`](../../docs/ipv6.md).

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
developer host. Reserve the live path for a disposable lab (see Live-Lab
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

Live ARP validation is L2-only and must run through provider-backed QEMU or
VirtualBox lab sessions with `link_layer_send` + `link_layer_capture`
capability checks, protected confirmation, artifact collection, and teardown.
When authorization or VM prerequisites are absent, plan with `--dry-run` and
record a skip artifact rather than faking a live run. The user-facing coverage
boundary lives in [`docs/arp-rfc-coverage.md`](../../docs/arp-rfc-coverage.md).

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
NA. Keep the live path in a disposable lab (see Live-Lab Sending); use dry-run
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

    // Dry-run plan by default; only the lab path actually transmits.
    let plan = ns.send_dry_run(SendOptions::new().iface("dry-run0").link_layer())?;
    println!("{}", plan.compiled_packet().hexdump());

    // In a live lab, send/receive and inspect the Neighbor Advertisement:
    let options = SendRecv::new()
        .iface("eth0")
        .link_layer()
        .dry_run() // drop for a real lab send
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
lab/probe runners, modeled on the ARP `who-has` -> `is-at` case:

- `ndp-neighbor-solicitation` — NS -> NA (the reliable kernel analog of ARP)
- `ndp-router-solicitation` — RS -> RA (needs an RA-emitting router on the target)
- `ndp-duplicate-address-detection` — NS from `::` -> defending NA

Dry-run is the safety boundary; start there on either VM provider:

```sh
tools/probe/run --provider qemu --dry-run --profile behavior --seed 1052 --case ndp-neighbor-solicitation
tools/probe/run --provider qemu --dry-run --profile behavior --seed 1052 --case ndp-duplicate-address-detection
tools/probe/run --provider virtualbox --dry-run --profile behavior --seed 1052 --case ndp-router-solicitation
```

NDP probe cases require `link_layer_send`, `link_layer_capture`, and the derived
`ipv6_multicast` capability, so they plan on QEMU and VirtualBox and skip cleanly
on endpoints without link-layer access. A real exchange needs
`--confirm-live-run` plus a provisioned two-endpoint lab session; collect
artifacts and tear the session down afterward (see Live-Lab Sending and the
`lab-session` skill). The user-facing NDP/ICMPv6 coverage boundary lives in
[`docs/icmpv6-coverage.md`](../../docs/icmpv6-coverage.md).

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

    dump_pcap("target/dot11-agent-dry-run.pcap", [&packet], LinkType::Radiotap)?;

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
tools/oracle/run offline --profile dot11-smoke --seed 1101 --count 20 --out target/oracle/dot11-agent-offline
tools/oracle/run pcap --profile dot11-pcap --seed 1201 --count 20 --out target/oracle/dot11-agent-pcap
tools/oracle/run live --provider local-dry-run --profile dot11-smoke --seed 1301 --count 5 --dry-run --out target/oracle/dot11-agent-live-local-dry-run
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

Live radiotap injection is a manual gate, not an automatic generated-tool path.
The built-in sender can produce dry-run link-layer plans for `Radiotap / Dot11`,
but current live radiotap transmission returns an unsupported-send error. Do
not add a generated `--live` mode that assumes monitor-mode injection works.
Use the manual gate in [`docs/dot11-live-manual.md`](../../docs/dot11-live-manual.md)
only after human authorization, isolated RF setup, dry-run byte review, artifact
cleanup, and explicit live confirmation.

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
bytes and the decode model against the Scapy reference backend, and the `ipsec`
probe profile plans the ESP/AH/IKEv2 behavioral exchange plus an engine-level
cross-crypto parity check — all without a network:

```sh
tools/oracle/run offline --profile ipsec-smoke --seed 1 --count 20 --out target/oracle/ipsec-agent-offline
tools/oracle/run offline --profile esp --seed 1 --count 20 --root l3:ipv4 --out target/oracle/esp-agent-offline
tools/oracle/run pcap --profile ipsec-smoke --seed 1 --count 20 --out target/oracle/ipsec-agent-pcap
tools/probe/run --provider local-dry-run --dry-run --profile ipsec --seed 1 --case esp-transport-echo
```

Any live IPSec exchange is opt-in only and must run from disposable
infrastructure, never raw from the developer host. Start with the probe dry-run
above, then provision a controlled IPSec-capable peer through a `lab-session`
(see Live-Lab Sending and the `lab-session` skill); collect artifacts and tear
the session down afterward. For the user-facing coverage boundary, see
[`docs/ipsec.md`](../../docs/ipsec.md).

## Validate TCP: Dry-Run First, Provider Live Opt-In

Dry-run is the default for TCP, exactly as for every other layer. `send_dry_run`
compiles the segment, derives the send target, and returns a plan without
transmitting. Use a documentation interface name (`dry-run0`) and documentation
address space so nothing touches a real network:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn plan_syn() -> Result<(), Box<dyn std::error::Error>> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Tcp::new().sport(40000).dport(443).syn_segment()
            .tcp_option(TcpOption::maximum_segment_size(1460))?;

    let plan = packet.send_dry_run(
        SendOptions::new()
            .iface("dry-run0")
            .network_layer(),
    )?;

    println!("target={:?}", plan.target());
    println!("{}", plan.compiled_packet().hexdump());
    Ok(())
}
```

Use `send_recv_report(...).dry_run()` (see `send_recv Matching` below) when the
tool also needs the derived BPF reply filter without sending.

Live TCP traffic is the opt-in path and must run from disposable infrastructure,
never raw from the developer host. Start with a provider dry-run, then run the
real provider only after explicit authorization, and destroy the resource after:

```sh
tools/live-lab/libcrafter-live-lab doctor --provider local-dry-run
tools/oracle/run live --provider local-dry-run --profile smoke --seed 1 --count 10
tools/oracle/run live --provider hetzner --dry-run --profile smoke --seed 1 --count 10
```

Only inside that disposable provider host does live code add `.live()` to
`SendOptions` (see `Live-Lab Sending`).

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

Use `read_pcap` for full offline reads and `read_pcap_filtered` when a libpcap
BPF filter should be applied while reading.

```rust
use crafter::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let packets = read_pcap_filtered("capture.pcap", "tcp or udp")?;
    for captured in packets {
        println!(
            "ts={} summary={}",
            captured.timestamp().seconds(),
            captured.packet().summary()
        );
    }
    Ok(())
}
```

## Write A pcap

Use `dump_pcap` for deterministic fixtures. Use an explicit link type so the
file can be decoded later without guessing.

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

    dump_pcap("target/agent-fixture.pcap", [&packet], LinkType::Ethernet)?;
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

Live sniffing must be bounded and lab-only:

```rust
use crafter::prelude::*;
use std::time::Duration;

let packets = Sniffer::interface("eth0")
    .filter("icmp")
    .count(3)
    .timeout(Duration::from_secs(2))
    .collect()?;
```

Only run that form inside a disposable live lab.

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

Expose a `--live` flag only when the tool also checks for an isolated lab marker
or is run through `tools/live-lab/`.

## Live-Lab Sending

Live sending belongs in disposable infrastructure, not on the developer
machine. Run local checks first, then use the provider-agnostic lab command:

```sh
cargo test --workspace
tools/live-lab/libcrafter-live-lab doctor --provider local-dry-run
tools/live-lab/libcrafter-live-lab run --provider local-dry-run --suite all
```

When credentials are configured outside the repo, the same suite can run on a
disposable provider host:

```sh
tools/live-lab/libcrafter-live-lab doctor --provider hetzner --dry-run
tools/live-lab/libcrafter-live-lab run --provider hetzner --suite all
```

Inside that disposable host, live code can opt in explicitly:

```rust
let report = packet.send(
    SendOptions::new()
        .iface("eth0")
        .network_layer()
        .live(),
)?;
println!("bytes_sent={}", report.bytes_sent());
```

Always destroy provider resources after the run.

## Choose Docker Provider Modes

Use Docker through the wire, lab, oracle, or probe provider commands, not
through arbitrary `docker run` access from generated tools. Docker socket access
is host-root equivalent; do not mount the socket into provider containers or
generated workloads.

Prefer `docker/private` when an agent needs a local, safe packet lab before
using heavier VM or cloud providers. It runs endpoints on an isolated
provider-owned bridge and is the Docker mode for same-segment packet work.
Use `docker/lan` only as a NAT-backed L3 reachability smoke to LAN targets, and
use `docker/wan` only as a NAT-backed L3 egress smoke to internet targets. Do
not treat either mode as true LAN/WAN link-layer access.

Live Docker runs still require `--confirm-live-run`. Start with dry-run plans,
run the provider command that creates the endpoint or lab, collect artifacts,
then destroy the endpoint with the matching provider cleanup command. If a live
run fails halfway through, keep local artifacts for debugging but still run
cleanup so containers and provider-owned private networks do not linger.

## Oracle Validation

Use the oracle runner when generated tools change packet behavior. The oracle is
the validation system. Backend-specific names and implementation details belong
inside `tools/oracle/`; agents should not add ad hoc reference-backend imports
to tests or scripts when an oracle mode covers the same behavior.

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
human has explicitly authorized a disposable provider endpoint:

```sh
tools/oracle/run offline --profile smoke --seed 9868 --count 100 --family udp --out target/oracle/udp-options-agent-offline
tools/oracle/run pcap --profile smoke --seed 9868 --count 100 --family udp --out target/oracle/udp-options-agent-pcap
tools/oracle/run live --provider local-dry-run --profile smoke --seed 9868 --count 20 --family udp --out target/oracle/udp-options-agent-live-local-dry-run
python3 tools/oracle/engine/live_provider_matrix.py --providers hetzner,qemu,virtualbox --profile smoke --seed 9868 --count 20 --dry-run --out target/oracle/udp-options-agent-live-dry-run-matrix
```

Live validation routes through a provider. Use `local-dry-run` for agent and CI
planning, and reserve real providers for explicit live-lab workflows:

```sh
tools/oracle/run live --provider local-dry-run --profile smoke --seed 1 --count 10
tools/oracle/run live --provider hetzner --dry-run --profile smoke --seed 12345 --count 10
```

Guard real UDP option live validation with an environment opt-in and keep the
provider disposable:

```sh
if [ "${LIBCRAFTER_RUN_LIVE_UDP_OPTIONS:-0}" = "1" ]; then
  tools/oracle/run live --provider "${LIBCRAFTER_LIVE_PROVIDER:-qemu}" --confirm-live-run --direction reference_to_libcrafter --profile smoke --seed 9868 --count 20 --family udp --out target/oracle/udp-options-live-reference-to-libcrafter
  tools/oracle/run live --provider "${LIBCRAFTER_LIVE_PROVIDER:-qemu}" --confirm-live-run --direction libcrafter_to_reference --profile smoke --seed 9868 --count 20 --family udp --out target/oracle/udp-options-live-libcrafter-to-reference
else
  echo "set LIBCRAFTER_RUN_LIVE_UDP_OPTIONS=1 to run guarded live UDP option validation"
fi
```

Artifacts default below `target/oracle/`, with mode-specific reports under
`target/oracle/offline`, `target/oracle/pcap`, and `target/oracle/live`. Every
failing oracle command should be rerunnable with the same `--profile`, `--seed`,
`--count`, and, when the report identifies one packet, `--index`.

Pull request CI runs deterministic oracle offline coverage and pcap smoke
coverage with the configured backend. Provider-backed live traffic must stay
behind explicit live-lab confirmation or dry-run workflows.

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
