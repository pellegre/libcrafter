# BGP Wire Coverage

This page describes the Border Gateway Protocol support in the `crafter` crate:
what the `Bgp` layer builds and decodes, how BGP rides over TCP port 179 in the
default registry, and how to keep BGP workflows offline by default.

`crafter` treats each BGP message as a packet layer. It builds, compiles,
decodes, summarizes, and shows like the other protocol layers. It is not a BGP
speaker, a route server, a RIB, a decision process, or a TCP connection state
machine. Session sequencing belongs in a generated tool or in the
`bgp_session` example; the crate surface is the wire primitive.

## Coverage At A Glance

| Area | State | Notes |
| --- | --- | --- |
| Shared header | Supported | 16-octet Marker, Length, and Type; marker and length auto-fill unless explicitly set. |
| Message types | Supported | OPEN, UPDATE, NOTIFICATION, KEEPALIVE, and ROUTE-REFRESH. |
| OPEN optional parameters | Supported | Raw optional parameters and RFC 5492 capability containers. |
| Capabilities | Supported | Multiprotocol, Route-Refresh, Graceful Restart, 4-octet AS, ADD-PATH; unknown capabilities preserved. |
| UPDATE NLRI and withdrawn routes | Supported | Prefix codec for IPv4 base UPDATEs and IPv6 MP-BGP attributes. |
| Path attributes | Supported | Framing, extended length, common well-known attributes, communities, MP-BGP, AS4 attributes, and unknown attributes. |
| Registry dispatch | Supported | TCP payloads decode as BGP when either TCP port is 179. |
| Stream payloads | Supported | Consecutive complete BGP messages become stacked `Bgp` layers; trailing partial bytes remain inspectable as `Raw`. |
| Live sessions | Example only | `crafter/examples/bgp_session.rs` uses a kernel TCP socket and lab endpoints; no BGP FSM is in the crate. |

## Public API

The BGP types are exported through `crafter::prelude::*`:

- `Bgp` builds the message layer.
- `BgpCapability` and `BgpOptParam` build OPEN optional parameters.
- `BgpPathAttribute`, `BgpAttrValue`, `AsPathSegment`, and `BgpPrefix` build
  UPDATE attributes and prefixes.
- `BgpOpen`, `BgpUpdate`, `BgpNotification`, and `BgpRouteRefresh` are the
  typed message-body structs exposed for inspection and documentation.

Use the same packet shape as the rest of the crate: build a layer, wrap it in a
`Packet`, call `compile()`, and inspect `summary()` or `show()`.

```rust
use crafter::prelude::*;
use std::net::{Ipv4Addr, Ipv6Addr};

fn main() -> crafter::Result<()> {
    let ipv4 = BgpPrefix::from_ipv4(Ipv4Addr::new(203, 0, 113, 0), 24)?;
    let ipv6 = BgpPrefix::from_ipv6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32)?;

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
            .attribute(BgpPathAttribute::communities(&[0xffff_ff01]))
            .nlri(ipv4),
    );

    let mp_update = Packet::from_layer(
        Bgp::update()
            .attribute(BgpPathAttribute::origin(BGP_ORIGIN_IGP))
            .attribute(BgpPathAttribute::as_sequence4(&[65000]))
            .attribute(BgpPathAttribute::mp_reach_ipv6(
                Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
                &[ipv6],
            )),
    );

    let messages = [
        ("OPEN", open),
        ("KEEPALIVE", Packet::from_layer(Bgp::keepalive())),
        ("UPDATE", update),
        ("MP-BGP UPDATE", mp_update),
        ("ROUTE-REFRESH", Packet::from_layer(Bgp::route_refresh(1, 1))),
        ("NOTIFICATION", Packet::from_layer(Bgp::cease())),
    ];

    for (label, packet) in messages {
        let bytes = packet.compile()?;
        println!("{label}: {}", packet.summary());
        println!("{}", bytes.hexdump());
    }

    Ok(())
}
```

All examples use documentation address space and private-use ASNs. Use real
neighbors only in an explicitly authorized lab session.

## Message Construction

`Bgp::open()` creates an OPEN message. Set version, peer AS, hold time, BGP
identifier, optional-parameter length overrides, raw optional parameters, and
capability containers with the chainable builders:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let open = Bgp::open()
    .my_as(65000)
    .hold_time(90)
    .bgp_id(Ipv4Addr::new(192, 0, 2, 1))
    .capabilities([
        BgpCapability::ipv4_unicast(),
        BgpCapability::route_refresh(),
        BgpCapability::four_octet_as(65000),
    ]);
```

`Bgp::keepalive()` emits the 19-octet header-only KEEPALIVE. `Bgp::notification`
builds a NOTIFICATION with error code, subcode, and optional diagnostic data,
and `Bgp::cease()` is the common Cease form. `Bgp::route_refresh(afi, safi)`
builds the Route-Refresh body and `.subtype(...)` preserves the RFC 7313 subtype
byte when needed.

```rust
use crafter::prelude::*;

let keepalive = Packet::from_layer(Bgp::keepalive());
let route_refresh = Packet::from_layer(Bgp::route_refresh(1, 1));
let cease = Packet::from_layer(Bgp::cease().data(vec![0xde, 0xad]));
```

## UPDATE Attributes

`Bgp::update()` starts with empty withdrawn routes, path attributes, and NLRI.
Attach prefixes with `.withdraw(...)` and `.nlri(...)`, and attach path
attributes with `.attribute(...)`.

Typed path-attribute constructors cover:

- `origin`, `as_sequence`, `as_set`, `as_sequence4`, `as_set4`, `as4_path`
- `next_hop`, `multi_exit_disc`, `local_pref`, `atomic_aggregate`
- `aggregator`, `as4_aggregator`
- `communities`, `extended_communities`, `large_communities`
- `mp_reach_ipv6`, `mp_unreach_ipv6`
- `unknown(...).with_flags(...)` for preserve-only or malformed-on-purpose
  attributes

`compile()` fills UPDATE sub-lengths from the encoded withdrawn routes and path
attributes unless the caller uses `.withdrawn_len(...)` or `.attr_len(...)`.
Attribute flags are filled from the known type code unless forced with
`.with_flags(...)`; values longer than 255 octets use extended length
automatically unless the caller forced non-extended flags.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn announce() -> crafter::Result<Packet> {
    Ok(Packet::from_layer(
        Bgp::update()
            .attribute(BgpPathAttribute::origin(BGP_ORIGIN_IGP))
            .attribute(BgpPathAttribute::as_sequence(&[65000, 65001]))
            .attribute(BgpPathAttribute::next_hop(Ipv4Addr::new(192, 0, 2, 1)))
            .attribute(BgpPathAttribute::large_communities(&[[65000, 1, 100]]))
            .nlri(BgpPrefix::from_ipv4(Ipv4Addr::new(203, 0, 113, 0), 24)?),
    ))
}
```

## MP-BGP

MP-BGP support is a wire attribute and capability surface. Advertise the
multiprotocol capability in OPEN, then use `mp_reach_ipv6` or
`mp_unreach_ipv6` attributes in UPDATE messages. The crate does not decide
which AFI/SAFI a session negotiated; generated tools must keep that state
outside the packet primitive.

```rust
use crafter::prelude::*;
use std::net::Ipv6Addr;

fn announce_ipv6() -> crafter::Result<Packet> {
    let prefix = BgpPrefix::from_ipv6("2001:db8::".parse::<Ipv6Addr>()?, 32)?;
    let next_hop = "2001:db8::1".parse::<Ipv6Addr>()?;

    Ok(Packet::from_layer(
        Bgp::update()
            .attribute(BgpPathAttribute::origin(BGP_ORIGIN_IGP))
            .attribute(BgpPathAttribute::as_sequence4(&[65000]))
            .attribute(BgpPathAttribute::mp_reach_ipv6(next_hop, &[prefix])),
    ))
}
```

When a real peer advertises four-octet AS capability, build outbound AS_PATH
attributes with `as_sequence4`/`as_set4` or AS4 attributes as appropriate for
the tool's negotiation state.

## Decode And Registry Dispatch

The built-in registry binds BGP to TCP port 179. If an IPv4 or IPv6 packet
decodes to a TCP segment where either source or destination port is 179, the TCP
payload is parsed as one or more BGP messages.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn decode_bgp_stack() -> crafter::Result<()> {
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

    Ok(())
}
```

The decoder preserves unknown attributes and capabilities as structured raw
items. Malformed BGP framing returns typed errors with context such as
`bgp header`, `bgp message`, or the specific attribute/NLRI field. A trailing
partial BGP message after complete messages is kept as `Raw` so stream captures
remain inspectable rather than silently truncated.

## Offline And Live Surfaces

The offline path is the default. `crafter/examples/bgp_session.rs` prints a
documentation-safe BGP message plan without opening a socket:

```sh
cargo run -p crafter --example bgp_session
cargo run -p crafter --example bgp_session -- --ipv6
```

Live mode is explicit and uses a kernel TCP connection to a provided peer:

```sh
cargo run -p crafter --example bgp_session -- \
  --peer 192.0.2.20:179 \
  --ipv6 \
  --linger-seconds 45 \
  --out target/lab/bgp/manual
```

That live form is intended for disposable provider-backed lab endpoints, not
the developer host. The BGP lab flow provisions an FRR peer with
`tools/lab/workloads/bgp/provision-peer.sh`, runs the example from the stimulus
endpoint, captures port 179 traffic, reads the peer RIB, saves artifacts under
`target/lab/bgp/<provider>/`, and destroys the session. Never commit live public
IPs, endpoint identifiers, credentials, or packet captures.

Use dry-run planning before any provider run:

```sh
tools/lab/run plan --provider qemu --dry-run --profile bgp-smoke --seed 1 --role stimulus --role target
```

For the agent-facing live procedure and generated-tool guidance, see
[`.agents/docs/cookbook.md`](../.agents/docs/cookbook.md).

## Explicit Exclusions

The crate intentionally does not implement:

- BGP finite state machine, hold-timer management, connection collision logic,
  route reflection behavior, or confederation semantics.
- Adj-RIB-In, Loc-RIB, Adj-RIB-Out, best-path selection, policy, filtering, or
  route server behavior.
- TCP-MD5 or TCP-AO authentication for BGP sessions.
- BMP, BGP-LS, FlowSpec, MRT dump parsing, or a monitoring tool.

Those are tools built on top of `crafter` packets. The crate stays focused on
constructing, decoding, preserving, and inspecting protocol-correct wire bytes.
