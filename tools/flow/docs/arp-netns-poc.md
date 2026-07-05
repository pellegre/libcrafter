# ARP Network Namespace Bridge POC

This is a manual, root-gated proof of concept for observing the benign ARP
injector on an isolated Linux bridge. It is not part of automated tests:
creating namespaces, veth devices, and a bridge requires privileges, and live
packet sends must remain an explicit human action.

The no-root path is the offline injector example from the ARP flow work:

```sh
cargo run -p crafter-flow --example arp_injector_flow
```

Use that example for routine sanity checks. The bridge run below is only for a
manual live check. All IP addresses and MAC addresses are documentation values,
and the bridge has no route to the host LAN.

## Topology

- `crafter-arp-injector`: namespace that runs the ARP injector.
- `crafter-arp-peer`: namespace that runs a crafter-built ARP peer and observes
  neighbor-cache changes.
- `br-crafter-arp`: host bridge joining only the two veth bridge ends.
- `veth-arp-injector`: injector-side link, MAC `02:00:5e:10:00:66`.
- `veth-arp-peer`: peer-side link, MAC `02:00:5e:10:00:01`,
  address `192.0.2.10/24`.
- The injected ARP identity is `192.0.2.1` at `02:00:5e:10:00:66`.

## Setup

Run as root or with `sudo`:

```sh
ip netns add crafter-arp-injector
ip netns add crafter-arp-peer

ip link add br-crafter-arp type bridge
ip link set br-crafter-arp type bridge stp_state 0
ip link set br-crafter-arp up

ip link add veth-arp-injector type veth peer name veth-arp-injector-br
ip link add veth-arp-peer type veth peer name veth-arp-peer-br

ip link set veth-arp-injector netns crafter-arp-injector
ip link set veth-arp-peer netns crafter-arp-peer

ip link set veth-arp-injector-br master br-crafter-arp
ip link set veth-arp-peer-br master br-crafter-arp
ip link set veth-arp-injector-br up
ip link set veth-arp-peer-br up

ip netns exec crafter-arp-injector ip link set lo up
ip netns exec crafter-arp-peer ip link set lo up

ip netns exec crafter-arp-injector ip link set veth-arp-injector address 02:00:5e:10:00:66
ip netns exec crafter-arp-peer ip link set veth-arp-peer address 02:00:5e:10:00:01

ip netns exec crafter-arp-injector ip addr add 192.0.2.66/24 dev veth-arp-injector
ip netns exec crafter-arp-peer ip addr add 192.0.2.10/24 dev veth-arp-peer

ip netns exec crafter-arp-injector ip link set veth-arp-injector up
ip netns exec crafter-arp-peer ip link set veth-arp-peer up

ip netns exec crafter-arp-peer sysctl -w net.ipv4.conf.veth-arp-peer.arp_accept=1
ip netns exec crafter-arp-peer ip neigh replace 192.0.2.1 lladdr 02:00:5e:10:00:02 nud stale dev veth-arp-peer
ip netns exec crafter-arp-peer ip neigh show 192.0.2.1 dev veth-arp-peer
```

The `arp_accept` setting is scoped to the peer namespace and lets the peer cache
the injector's gratuitous ARP. The seeded stale neighbor entry gives the manual
run an obvious before/after value to inspect.

## Manual Injector Shape

The tracked crate does not create namespaces or elevate privileges. A manual
live harness should run from the injector side and construct its binding through
the public API:

```rust
use std::net::Ipv4Addr;
use std::time::Duration;

use crafter::MacAddr;
use crafter_flow::flows::arp::injector_flow;
use crafter_flow::{Binding, Bound, RunOptions, Runner};

let binding = Binding::netns("crafter-arp-injector")
    .link_layer()
    .live();
let options = RunOptions::default()
    .binding(binding)
    .bound(Bound::Count(1))
    .step_timeout(Duration::from_secs(2));
let mut runner = Runner::with_options(options)?;
let mut flow = injector_flow(
    Ipv4Addr::new(192, 0, 2, 1),
    MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, 0x66]),
);
let report = runner.run(&mut flow)?;
println!("{}", report.show());
# Ok::<(), crafter_flow::FlowError>(())
```

The namespace helper introduced with the earlier netns POC can build the same
validated dry-run binding before the explicit live opt-in:

```rust
let binding = crafter_flow::netns::link_layer("crafter-arp-injector")?.live();
```

Run the harness under the namespace selected for the injector side:

```sh
ip netns exec crafter-arp-injector ./target/debug/arp-netns-injector
```

## Peer Observation

Start a neighbor monitor on the peer side before launching the injector:

```sh
ip netns exec crafter-arp-peer ip monitor neigh dev veth-arp-peer
```

In a second peer-side terminal, run a crafter-built peer that emits a
documentation-space ARP who-has for `192.0.2.1` on `veth-arp-peer`. Its packet
shape should match the offline example's observed request:

```rust
use crafter::net::PacketSendExt;

let packet = crafter::Ethernet::new()
    .src(crafter::MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, 0x01]))
    .dst(crafter::MacAddr::BROADCAST)
    / crafter::Arp::who_has(
        std::net::Ipv4Addr::new(192, 0, 2, 10),
        std::net::Ipv4Addr::new(192, 0, 2, 1),
        crafter::MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, 0x01]),
    );
let report = packet.send(
    crafter::net::SendOptions::new()
        .iface("veth-arp-peer")
        .link_layer()
        .live(),
)?;
println!("{report:?}");
# Ok::<(), crafter::Error>(())
```

After the injector sends the gratuitous ARP, inspect the peer cache:

```sh
ip netns exec crafter-arp-peer ip neigh show 192.0.2.1 dev veth-arp-peer
```

The expected manual observation is that the neighbor entry for `192.0.2.1`
changes from the seeded stale MAC `02:00:5e:10:00:02` to the injector MAC
`02:00:5e:10:00:66`. Keep this confined to the bridge namespaces and tear the
topology down after the run.

## Cleanup

Run as root or with `sudo`:

```sh
ip netns del crafter-arp-injector
ip netns del crafter-arp-peer
ip link del br-crafter-arp
```

Deleting the namespaces removes their veth ends; deleting the bridge removes
the isolated L2 segment.
