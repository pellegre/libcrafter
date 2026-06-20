# IGMP Wire Coverage

This page describes how to compose IGMP packets with IPv4 in the `crafter`
packet abstraction. IGMP is an IPv4 protocol body: build the enclosing `Ipv4`
layer explicitly, then compose it with `Igmp` and any typed IGMP body layers
using `/`.

`Igmp` owns only the IGMP message bytes and checksum. It does not own the
enclosing IPv4 header, and it does not silently force the IPv4 TTL, destination,
Protocol field, or Router Alert option. Generated tools must set those IPv4
fields themselves when the packet shape requires them.

## IPv4 Envelope

IGMP control traffic that is intended for the local link normally uses IPv4
Protocol IGMP (`2`), TTL `1`, and the IPv4 Router Alert option. In `crafter`,
that envelope is ordinary IPv4 construction:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let all_systems = Ipv4Addr::new(224, 0, 0, 1);

let packet = Ipv4::new()
    .src(Ipv4Addr::new(192, 0, 2, 10))
    .dst(all_systems)
    .ttl(1)
    .ipv4_protocol(Ipv4Protocol::Igmp)
    .ipv4_option(Ipv4Option::router_alert(0))?
    / Igmp::membership_query().with_v2_max_response_time_tenths(10);

let compiled = packet.compile()?;
println!("{}", packet.summary());
println!("{}", compiled.hexdump());
# Ok::<(), crafter::CrafterError>(())
```

The destination is part of the IPv4 layer, not the IGMP layer. Choose it from
the packet's protocol role:

| Packet shape | Typical IPv4 destination |
| --- | --- |
| General Membership Query | All-systems `224.0.0.1` |
| Leave Group | All-routers `224.0.0.2` |
| Multicast Router Advertisement | All-snoopers `224.0.0.106` |
| Multicast Router Solicitation | All-routers `224.0.0.2` |
| Multicast Router Termination | All-snoopers `224.0.0.106` |

Group-specific queries and reports need the destination required by the protocol
case the tool is modeling. Keep that choice explicit in the `Ipv4` builder so
the compiled packet remains inspectable and intentionally malformed envelopes
can still be represented.

## Dry-Run First

Do not make IGMP examples send live traffic by default. Use documentation source
addresses such as `192.0.2.0/24` and inspect an offline packet or dry-run send
plan before any provider-backed live workflow:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let packet = Ipv4::new()
    .src(Ipv4Addr::new(192, 0, 2, 20))
    .dst(Ipv4Addr::new(224, 0, 0, 2))
    .ttl(1)
    .ipv4_protocol(Ipv4Protocol::Igmp)
    .ipv4_option(Ipv4Option::router_alert(0))?
    / Igmp::mrd_solicitation();

let plan = packet.send_dry_run(SendOptions::new().iface("igmp-dry-run0").network_layer())?;

println!("mode: dry-run");
println!("interface: {}", plan.interface());
println!("target: {:?}", plan.target());
println!("compiled bytes: {}", plan.len());
# Ok::<(), crafter::CrafterError>(())
```

Live IGMP validation belongs behind the lab, oracle, or probe protected-live
gates. A generated tool that needs real multicast traffic should first produce a
dry-run plan, then run from an authorized provider-backed endpoint with explicit
confirmation and artifact collection.
