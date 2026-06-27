# DHCPv6 Wire Coverage

`crafter` exposes DHCPv6 as packet data: build a typed `Dhcpv6` layer, compose
it under IPv6/UDP, compile it, decode it, and inspect it. It is not a DHCP
client, server, relay daemon, lease database, scanner, or policy engine.

The implementation follows the packet shapes and registry model documented in
[the DHCPv6 RFC manifest](../dhcpv6-rfc-manifest.md). Unknown but well-formed
message types, option codepoints, DUID types, status codes, and nested option
payloads are preserved as packet data.

All examples below use documentation IPv6 address space and synthetic DUID/MAC
bytes.

## Solicit

Use `Udp::dhcpv6_client()` for client-to-server messages. It sets UDP source
port 546 and destination port 547 while still allowing explicit overrides.

```rust
use crafter::prelude::*;
use std::net::Ipv6Addr;

let client_duid = Dhcpv6Duid::ll(1, [0x02, 0x00, 0x5e, 0x00, 0x06, 0x01]);
let solicit = Dhcpv6::solicit(0x010203)
    .client_duid(client_duid)
    .oro([DHCPV6_OPTION_DNS_SERVERS, DHCPV6_OPTION_DOMAIN_LIST])
    .elapsed_time(1);

let packet =
    Ipv6::new()
        .src(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x10))
        .dst(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x01))
    / Udp::dhcpv6_client()
    / solicit;

let wire = packet.compile()?;
# Ok::<(), crafter::CrafterError>(())
```

## Information Request

Information-request uses the same client/server header shape and can carry
Client ID, ORO, Elapsed Time, and related options.

```rust
use crafter::prelude::*;

let request = Dhcpv6::information_request(0x030405)
    .client_duid(Dhcpv6Duid::ll(1, [0x02, 0x00, 0x5e, 0x00, 0x06, 0x02]))
    .oro([DHCPV6_OPTION_DNS_SERVERS, DHCPV6_OPTION_DOMAIN_LIST])
    .elapsed_time(2);

assert_eq!(request.message_type_value(), Dhcpv6MessageType::InformationRequest);
# Ok::<(), crafter::CrafterError>(())
```

## IA_NA And IA Address

Identity associations are typed option containers. Nested options remain
inspectable and round-trip safe.

```rust
use crafter::prelude::*;
use std::net::Ipv6Addr;

let ia_addr = Dhcpv6IaAddr::new(
    Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x100),
    300,
    600,
);
let ia_na = Dhcpv6IaNa::new(0x0102_0304, 60, 120).ia_addr(ia_addr)?;
let reply = Dhcpv6::reply(0x040506)
    .client_duid(Dhcpv6Duid::ll(1, [0x02, 0x00, 0x5e, 0x00, 0x06, 0x03]))
    .server_duid(Dhcpv6Duid::ll(1, [0x02, 0x00, 0x5e, 0x00, 0x06, 0x04]))
    .ia_na(ia_na)?
    .status(Dhcpv6StatusCode::Success);

assert_eq!(reply.ia_na_value()?.unwrap().iaid(), 0x0102_0304);
# Ok::<(), crafter::CrafterError>(())
```

## Prefix Delegation

Prefix delegation uses `Dhcpv6IaPd` and nested `Dhcpv6IaPrefix` packet data.
The crate builds and decodes the packet fields; it does not assign prefixes.

```rust
use crafter::prelude::*;
use std::net::Ipv6Addr;

let prefix = Dhcpv6IaPrefix::new(
    300,
    600,
    56,
    Ipv6Addr::new(0x2001, 0x0db8, 0x0200, 0, 0, 0, 0, 0),
);
let ia_pd = Dhcpv6IaPd::new(0x0506_0708, 90, 180).ia_prefix(prefix)?;

let reply = Dhcpv6::reply(0x050607)
    .client_id([0x00, 0x03, 0x00, 0x01, 0x02, 0x00, 0x5e, 0x00, 0x06, 0x05])
    .server_id([0x00, 0x03, 0x00, 0x01, 0x02, 0x00, 0x5e, 0x00, 0x06, 0x06])
    .ia_pd(ia_pd)?;

assert_eq!(reply.ia_pd_value()?.unwrap().timers(), (90, 180));
# Ok::<(), crafter::CrafterError>(())
```

## Relay Encapsulation

Relay-forward and Relay-reply use the fixed relay header plus an
`OPTION_RELAY_MSG` payload. The inner DHCPv6 message can be built as a typed
`Dhcpv6` layer.

```rust
use crafter::prelude::*;
use std::net::Ipv6Addr;

let relay = Dhcpv6::relay_forward(
    Ipv6Addr::new(0x2001, 0x0db8, 0x0100, 0, 0, 0, 0, 0),
    Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x10),
)
.hop_count(1)
.interface_id(b"uplink-1".to_vec())
.relay_message(
    Dhcpv6::solicit(0x0a0b0c)
        .client_duid(Dhcpv6Duid::ll(1, [0x02, 0x00, 0x5e, 0x00, 0x06, 0x07])),
)?;

assert_eq!(
    relay.relay().unwrap().peer_address_value(),
    Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x10)
);
# Ok::<(), crafter::CrafterError>(())
```

## Unknown Options

Use raw options when exercising unassigned, private-use, obsolete, future, or
intentionally malformed payloads. Builders do not reject constructible packet
data just because it is unusual.

```rust
use crafter::prelude::*;

let message = Dhcpv6::new()
    .message_type_code(250)
    .transaction_id(0x0c0d0e)
    .raw_option(65_000u16, [0xde, 0xad, 0xbe, 0xef])
    .empty_option(65_001u16);

assert_eq!(message.message_type_code_value(), 250);
assert_eq!(message.options_ref()[0].payload(), &[0xde, 0xad, 0xbe, 0xef]);
# Ok::<(), crafter::CrafterError>(())
```

## Decode And Inspect

Decode from the layer that appears in the bytes. Raw IPv6 pcaps and byte
fixtures use `Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)`.

```rust
use crafter::prelude::*;

let packet = Ipv6::new()
    / Udp::dhcpv6_client()
    / Dhcpv6::solicit(0x010203).client_id([
        0x00, 0x03, 0x00, 0x01, 0x02, 0x00, 0x5e, 0x00, 0x06, 0x08,
    ]);
let wire = packet.compile()?;
let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, wire.as_bytes())?;
let dhcpv6 = decoded.layer::<Dhcpv6>().unwrap();

assert_eq!(dhcpv6.message_type_value(), Dhcpv6MessageType::Solicit);
assert_eq!(decoded.compile()?.as_bytes(), wire.as_bytes());
# Ok::<(), crafter::CrafterError>(())
```

## Summary And Show

`summary()` stays compact for packet lists; `show()` exposes typed fields and
option summaries for inspection.

```rust
use crafter::prelude::*;

let packet = Packet::from_layer(
    Dhcpv6::reply(0x0a0b0c)
        .status_message(Dhcpv6StatusCode::NoAddrsAvail, b"no addresses")
        .raw_option(65_000u16, [0xde, 0xad]),
);

let summary = packet.summary();
let show = packet.show();
assert!(summary.contains("Dhcpv6(type=reply"));
assert!(show.contains("OPTION_STATUS_CODE"));
# Ok::<(), crafter::CrafterError>(())
```

## Dry-Run Send Planning

Offline planning is the default. Opening a raw socket writer without `.live()`
builds dry-run reports instead of putting packets on the wire.

```rust
use crafter::prelude::*;
use std::net::Ipv6Addr;

let writer = PacketWire::raw_socket_interface("dry-run0")
    .network_layer()
    .open()?
    .writer()?;

let packet =
    Ipv6::new()
        .src(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x10))
        .dst(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x01))
    / Udp::dhcpv6_client()
    / Dhcpv6::solicit(0x010203);

let reports = Transmitter::new(writer).send(packet)?;
assert!(reports.iter().all(|report| report.is_dry_run()));
# Ok::<(), crafter::CrafterError>(())
```

Live transmission requires an explicit live opt-in and should be run from an
authorized provider-backed lab or endpoint, not from a default developer host.
