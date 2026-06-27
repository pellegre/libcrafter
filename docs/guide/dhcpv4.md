# DHCPv4 Wire Coverage

`crafter` exposes DHCPv4 as packet data: build a typed `Dhcpv4` layer, compose
it under IPv4/UDP, compile it, decode it, and inspect it. It is not a DHCP
client, server, relay daemon, lease database, scanner, or policy engine.

Options use a code-plus-value model rather than one enum variant per code. A
`Dhcpv4Option` carries its registered `Dhcpv4OptionCode`, a typed
`Dhcpv4OptionValue` for the wire formats the codec understands, and the raw
payload bytes for everything else. Unknown, private-use, removed, ambiguous, and
vendor-specific option payloads are preserved as raw bytes so they remain
inspectable and re-encodable. Authentication (option 90) and leasequery fields
are packet data only: the crate never derives, signs, or verifies
authentication, and never runs a leasequery state machine.

All examples below use documentation IPv4 address space (`192.0.2.0/24`,
`198.51.100.0/24`) and synthetic MAC bytes.

## Coverage at a glance

| Area | Status | Notes |
| --- | --- | --- |
| BOOTP/DHCP fixed header | Supported | `op`, `htype`/`hlen`, `xid`, `flags`, `ciaddr`/`yiaddr`/`siaddr`/`giaddr`, `chaddr`, magic cookie, all with protocol-correct defaults. |
| Message types (option 53) | Supported | IANA codes 1–18: RFC 2132 (1–8), RFC 3203 (9), RFC 4388 (10–13), RFC 6926 (14–15), RFC 7724 (16–18); unknown values preserved as `Unknown(u8)`. |
| Named constructors | Supported | `discover`, `offer`, `request`, `decline`, `ack`, `nak`, `release`, `inform`, `force_renew`, and the three RFC 4388 leasequery constructors. |
| Typed options | Supported | Subnet, routers, DNS, lease/renewal/rebinding timers, classless routes (121), relay agent info (82), client identifier (61), authentication (90), status/state/data-source, and more — see `dhcpv4_option_meta`. |
| Option overload (52) | Supported | Push options into the BOOTP `file`/`sname` fields with `file_option`/`sname_option`; `compile()` marks the area and `option_overload()` reports it. |
| RFC 3396 long options | Supported | Values split into 255-byte segments on encode and concatenated on decode; raw segments stay inspectable via `scan_dhcpv4_option_segments` / `concatenated_option`. |
| Unknown / private / removed | Preserved | Raw payloads round-trip without rejection; status is reported by `dhcpv4_option_status`. |
| Decode dispatch | Supported | Carried over UDP/67 and UDP/68; `Packet::decode_from_l3` / `decode_from_link` reach the layer. |
| Client / server / lease engine | Out of scope | Build a generated tool on top of these primitives instead. |

## Discover

`Udp::dhcpv4_client()` sets UDP source port 68 and destination port 67 while
still allowing explicit overrides. `Dhcpv4::discover` seeds the message type and
a default parameter request list for an Ethernet client.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let client_mac = MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]);
let discover = Dhcpv4::discover(client_mac)
    .xid(0x0102_0304)
    .flags(0x8000)
    .host_name("libcrafter-rust");

let packet = Ethernet::new()
        .src(client_mac)
        .dst(MacAddr::BROADCAST)
        .ethertype(ETHERTYPE_IPV4)
    / Ipv4::new()
        .src(Ipv4Addr::UNSPECIFIED)
        .dst(Ipv4Addr::BROADCAST)
        .ipv4_protocol(Ipv4Protocol::Udp)
    / Udp::dhcpv4_client()
    / discover;

let wire = packet.compile()?;
let dhcp = packet.layer::<Dhcpv4>().unwrap();
assert_eq!(dhcp.message_type_value(), Some(Dhcpv4MessageType::Discover));
assert_eq!(dhcp.transaction_id_value(), 0x0102_0304);
# Ok::<(), crafter::CrafterError>(())
```

## Offer And Ack

Server-side replies use `Udp::dhcpv4_server()` (source port 67, destination
port 68). The `offer`/`ack` constructors set the `BOOTREPLY` opcode, place the
assigned address in `yiaddr`, and name the responding server (option 54). Add
typed configuration options with `option`.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let client_mac = MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]);
let server_id: Ipv4Addr = "192.0.2.1".parse()?;
let offered: Ipv4Addr = "192.0.2.50".parse()?;

let offer = Dhcpv4::offer(client_mac, offered, server_id)
    .xid(0x0102_0304)
    .lease_time(3600)
    .option(Dhcpv4Option::subnet_mask("255.255.255.0".parse()?))
    .option(Dhcpv4Option::router(vec!["192.0.2.1".parse::<Ipv4Addr>()?]))
    .option(Dhcpv4Option::domain_name_server(vec![
        "192.0.2.2".parse::<Ipv4Addr>()?,
    ]));

assert_eq!(offer.message_type_value(), Some(Dhcpv4MessageType::Offer));
assert_eq!(offer.your_ip_address_value(), offered);
assert_eq!(offer.lease_time_value(), Some(3600));
assert_eq!(offer.server_identifier_value(), Some(server_id));
# Ok::<(), crafter::CrafterError>(())
```

## Request, Release, Inform, Decline

The remaining DORA and lifecycle messages have constructors that fill the
fields each message type requires (RFC 2131). They are packet shapes only — no
timers, state, or retransmission.

```rust
use crafter::prelude::*;

let client_mac = MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]);
let request = Dhcpv4::request(
    client_mac,
    "192.0.2.50".parse()?,
    "192.0.2.1".parse()?,
);
assert_eq!(request.message_type_value(), Some(Dhcpv4MessageType::Request));
assert_eq!(request.requested_ip_address_value(), Some("192.0.2.50".parse()?));

let release = Dhcpv4::release(client_mac, "192.0.2.50".parse()?, "192.0.2.1".parse()?);
let inform = Dhcpv4::inform(client_mac, "192.0.2.50".parse()?);
let decline = Dhcpv4::decline(client_mac, "192.0.2.50".parse()?, "192.0.2.1".parse()?);
assert_eq!(release.message_type_value(), Some(Dhcpv4MessageType::Release));
assert_eq!(inform.message_type_value(), Some(Dhcpv4MessageType::Inform));
assert_eq!(decline.message_type_value(), Some(Dhcpv4MessageType::Decline));
# Ok::<(), crafter::CrafterError>(())
```

## Relay Agent Information And Option Overload

A relay agent adds option 82 (RFC 3046) sub-options when forwarding a client
message. Registered sub-options decode to typed values; unknown codes survive
verbatim through `Dhcpv4RelaySuboption::other`. This example also carries RFC
3442 classless static routes (option 121) and pushes an option into the
overloaded `sname` field — `compile()` auto-inserts the option-overload option
(52) to mark the area.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let relay_info = Dhcpv4RelayAgentInfo::new(vec![
    Dhcpv4RelaySuboption::circuit_id(b"eth0:vlan100".to_vec()),
    Dhcpv4RelaySuboption::remote_id(b"relay-1".to_vec()),
    Dhcpv4RelaySuboption::other(254, b"vendor-bytes".to_vec()),
]);

let routes = vec![
    Dhcpv4ClasslessRoute::new(24, "198.51.100.0".parse()?, "192.0.2.1".parse()?),
    Dhcpv4ClasslessRoute::new(0, Ipv4Addr::UNSPECIFIED, "192.0.2.254".parse()?),
];
let routes_option = Dhcpv4Option::typed(
    Dhcpv4OptionKind::ClasslessStaticRoute,
    Dhcpv4OptionValue::ClasslessRoutes(routes),
);

let giaddr: Ipv4Addr = "192.0.2.1".parse()?;
let dhcp = Dhcpv4::discover(MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]))
    .xid(0x0102_0304)
    .giaddr(giaddr)
    .relay_agent_info(relay_info)
    .sname_option(routes_option);

let packet = Ipv4::new()
        .src(giaddr)
        .dst(Ipv4Addr::BROADCAST)
        .ipv4_protocol(Ipv4Protocol::Udp)
    / Udp::new().sport(DHCPV4_SERVER_PORT).dport(DHCPV4_SERVER_PORT)
    / dhcp;

let wire = packet.compile()?;
let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, wire.as_bytes())?;
let dhcp = decoded.layer::<Dhcpv4>().unwrap();

assert_eq!(dhcp.option_overload(), Some(OptionOverload::Sname));
assert_eq!(dhcp.relay_agent_information().unwrap()?.suboptions.len(), 3);
assert_eq!(dhcp.classless_static_routes().unwrap()?.len(), 2);
# Ok::<(), crafter::CrafterError>(())
```

`option_overload()`, `relay_agent_information()`, and
`classless_static_routes()` read the typed values back from a decoded packet.
See `crafter/examples/dhcpv4_option82.rs` for the full decode walk.

## Leasequery, Client Identifier, And Authentication

Leasequery (RFC 4388) lets a requestor ask by IP, MAC, or client identifier.
Option 61 carries a typed `Dhcpv4ClientIdentifier` (Ethernet MAC, RFC 4361
node-specific, or raw), and option 90 (RFC 3118) carries authentication packet
fields. The crate assembles and decodes these fields; it never derives, signs,
or verifies them.

```rust
use crafter::prelude::*;

let client_mac = MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]);
let client_id = Dhcpv4ClientIdentifier::ethernet_mac(client_mac.octets());
let auth = Dhcpv4Authentication::new(
    Dhcpv4AuthProtocol::Delayed,
    Dhcpv4AuthAlgorithm::HmacMd5,
    Dhcpv4ReplayDetectionMethod::MonotonicCounter,
    0x0000_0000_0000_0001,
    b"\x00\x00\x00\x01placeholder-mac".to_vec(),
);
let query = Dhcpv4::lease_query_by_client_id(client_id)
    .xid(0x4c51_0001)
    .option(Dhcpv4Option::authentication(auth));

assert_eq!(query.message_type_value(), Some(Dhcpv4MessageType::LeaseQuery));

let reply = Dhcpv4::lease_query_by_mac(client_mac)
    .op(BOOTP_REPLY)
    .ciaddr("192.0.2.50".parse()?)
    .server_identifier("192.0.2.1".parse()?)
    .lease_time(3600)
    .option(Dhcpv4Option::status_code(Dhcpv4StatusCodeOption::new(
        Dhcpv4StatusCode::Success,
        b"ok".to_vec(),
    )))
    .option(Dhcpv4Option::dhcp_state(Dhcpv4State::Active));

assert_eq!(reply.your_ip_address_value(), "0.0.0.0".parse()?);
# Ok::<(), crafter::CrafterError>(())
```

See `crafter/examples/dhcpv4_leasequery.rs` for the full decode walk, including
`client_identifier_value()`, `authentication()`, `associated_ip()`,
`status_code()`, and `dhcp_state()`.

## Unknown Options

Use `Dhcpv4Option::generic` for unassigned, private-use, removed, or
intentionally malformed payloads. Builders do not reject constructible packet
data just because it is unusual, and decode preserves the raw bytes.

```rust
use crafter::prelude::*;

let stack = Ipv4::new().ipv4_protocol(Ipv4Protocol::Udp)
    / Udp::dhcpv4_client()
    / Dhcpv4::discover(MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]))
        .option(Dhcpv4Option::generic(224, [0xde, 0xad, 0xbe, 0xef]));

let wire = stack.compile()?;
let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, wire.as_bytes())?;
let dhcp = decoded.layer::<Dhcpv4>().unwrap();
let option = dhcp
    .options_value()
    .iter()
    .find(|opt| opt.option_code().code() == 224)
    .unwrap();
assert_eq!(option.payload()?, vec![0xde, 0xad, 0xbe, 0xef]);
# Ok::<(), crafter::CrafterError>(())
```

RFC 3396 long options (values longer than 255 bytes) are split into segments on
encode and rejoined on decode; reach the raw segments with
`scan_dhcpv4_option_segments` and the rejoined value with
`Dhcpv4::concatenated_option`.

## Decode And Inspect

Decode from the layer that appears in the bytes. Raw IPv4 pcaps and byte
fixtures use `Packet::decode_from_l3(NetworkLayer::Ipv4, bytes)`; Ethernet
captures use `Packet::decode_from_link(LinkType::Ethernet, bytes)`. DHCPv4 is
dispatched when the UDP ports are the client/server pair (67/68).

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let client_mac = MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]);
let packet = Ipv4::new()
        .src(Ipv4Addr::UNSPECIFIED)
        .dst(Ipv4Addr::BROADCAST)
        .ipv4_protocol(Ipv4Protocol::Udp)
    / Udp::dhcpv4_client()
    / Dhcpv4::discover(client_mac).xid(0x0102_0304);
let wire = packet.compile()?;
let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, wire.as_bytes())?;
let dhcp = decoded.layer::<Dhcpv4>().unwrap();

assert_eq!(dhcp.message_type_value(), Some(Dhcpv4MessageType::Discover));
assert_eq!(decoded.compile()?.as_bytes(), wire.as_bytes());
# Ok::<(), crafter::CrafterError>(())
```

## Summary And Show

`summary()` stays compact for packet lists; `show()` exposes the typed header
fields and option count for inspection.

```rust
use crafter::prelude::*;

let packet = Packet::from_layer(
    Dhcpv4::discover(MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]))
        .xid(0x0102_0304),
);

let summary = packet.summary();
let show = packet.show();
assert!(summary.contains("Dhcpv4(type=discover, xid=0x01020304, yiaddr=0.0.0.0)"));
assert!(show.contains("message_type: discover"));
# Ok::<(), crafter::CrafterError>(())
```

## Dry-Run Send/Receive Planning

Offline planning is the default. Use `SendRecv::new().dry_run()` to inspect the
compiled DHCPv4 request, the derived reply filter, the target, and the retry
settings without opening capture or putting packets on the wire. DHCPv4 reply
matching keys on the UDP port pair.

```rust
use crafter::prelude::*;
use std::time::Duration;

let client_mac = MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]);
let packet = Ethernet::new()
        .src(client_mac)
        .dst(MacAddr::BROADCAST)
        .ethertype(ETHERTYPE_IPV4)
    / Ipv4::new()
        .src("192.0.2.10".parse()?)
        .dst("192.0.2.1".parse()?)
        .ipv4_protocol(Ipv4Protocol::Udp)
    / Udp::dhcpv4_client()
    / Dhcpv4::discover(client_mac).xid(0x0102_0304);

let report = packet.send_recv_report(
    SendRecv::new()
        .iface("dry-run0")
        .link_layer()
        .dry_run()
        .timeout(Duration::from_millis(250))
        .retries(1),
)?;

assert_eq!(report.attempts(), 1);
assert!(report.reply().is_none());
assert_eq!(
    report.effective_filter(),
    Some("udp and src port 67 and dst port 68"),
);
assert!(report.send_reports().iter().all(|send| send.is_dry_run()));
# Ok::<(), crafter::net::NetError>(())
```

Live DHCPv4 validation should start from the provider-backed lab, oracle, or
probe workflows in `docs/operations/`, which create disposable endpoints,
preserve artifacts, and tear them down. Do not turn DHCPv4 examples into
developer-host raw traffic examples.

## Standards and RFCs implemented

The implementation is source-backed by the IANA *BOOTP/DHCP Parameters*
registry. The in-crate registry (`dhcpv4_option_meta`, `dhcpv4_option_name`,
`dhcpv4_option_status`) is the option codepoint authority; known options are
named and typed for ergonomics, and every unknown, private-use, removed, or
ambiguous codepoint is accepted and preserved.

- **RFC 2131 — DHCP** — BOOTP/DHCP fixed header, opcode semantics, and the
  DISCOVER/OFFER/REQUEST/DECLINE/ACK/NAK/RELEASE/INFORM message flow.
- **RFC 2132 — DHCP Options and BOOTP Vendor Extensions** — the message-type
  option (53), the base option set (subnet mask, routers, DNS, host name, lease
  time, parameter request list, and the rest), and option overload (52).
- **RFC 3203 — DHCP Reconfigure Extension** — FORCERENEW message type (9).
- **RFC 4388 / RFC 6926 / RFC 7724 — Leasequery family** — message types 10–18
  (leasequery, bulk leasequery, active leasequery) and the associated
  status-code, state, data-source, and base-time packet fields.
- **RFC 3046 — Relay Agent Information Option (82)** — typed circuit-ID,
  remote-ID, and the broader sub-option set, with unknown sub-options preserved.
- **RFC 3118 — Authentication for DHCP Messages (90)** — authentication packet
  fields (protocol, algorithm, RDM, replay detection, auth information) as data
  only; never derived, signed, or verified.
- **RFC 4361 — Node-specific Client Identifiers (61)** — typed Ethernet-MAC,
  RFC 4361, and raw client identifiers.
- **RFC 3396 — Encoding Long DHCP Options** — split on encode, concatenated on
  decode, with raw segments inspectable.
- **RFC 3442 — Classless Static Route Option (121)** — typed destination/mask/
  router route entries.
- **IANA registries / further options** — additional typed and named option
  codepoints (for example RFC 3925 vendor-identifying options, RFC 6225
  geolocation, RFC 8910 captive portal, RFC 8925 IPv6-only preferred) are
  carried through the registry; consult `dhcpv4_option_meta` for the current
  set.

Intentional gaps — deliberately excluded so the crate stays a wire-level
primitive, not a DHCP stack:

- DHCP client, server, and relay daemons; lease databases; and address-pool or
  policy engines. These are generated tools, not crate features.
- Authentication and leasequery *behavior* — the crate carries the packet fields
  but runs no key derivation, signing, verification, or query state machine.
- A complete one-variant-per-codepoint option enum; the code-plus-typed-value
  model keeps unknown and future options first-class.
- IPv6 address configuration, which is a separate protocol — see the
  [DHCPv6 guide](dhcpv6.md).
