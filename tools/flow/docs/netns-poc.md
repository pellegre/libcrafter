# Network Namespace POC Harness

This is a manual, root-gated closed-loop proof of concept for running a flow
inside Linux network namespaces. It is intentionally not part of automated
tests: creating namespaces and veth devices requires privileges, and live packet
sends must remain an explicit human action.

All addresses and MACs below are documentation values. Do not replace them with
production network identifiers in tracked files.

## Topology

- `crafter-flow-client`: runs a flow with
  `Binding::netns("crafter-flow-client").link_layer().live()`.
- `crafter-flow-peer`: runs a crafter-built responder on the other side.
- `veth-flow-client` and `veth-flow-peer`: a private veth pair connecting only
  those namespaces.

## Setup

Run as root or with `sudo`:

```sh
ip netns add crafter-flow-client
ip netns add crafter-flow-peer

ip link add veth-flow-client type veth peer name veth-flow-peer
ip link set veth-flow-client netns crafter-flow-client
ip link set veth-flow-peer netns crafter-flow-peer

ip netns exec crafter-flow-client ip link set lo up
ip netns exec crafter-flow-peer ip link set lo up

ip netns exec crafter-flow-client ip link set veth-flow-client address 02:00:5e:10:00:01
ip netns exec crafter-flow-peer ip link set veth-flow-peer address 02:00:5e:10:00:02

ip netns exec crafter-flow-client ip addr add 192.0.2.10/24 dev veth-flow-client
ip netns exec crafter-flow-peer ip addr add 198.51.100.20/24 dev veth-flow-peer

ip netns exec crafter-flow-client ip link set veth-flow-client up
ip netns exec crafter-flow-peer ip link set veth-flow-peer up
```

## Manual Run Shape

The tracked crate only builds bindings and flow definitions. It does not shell
out, create namespaces, or elevate privileges. A manual live client runner should
construct its binding through the public API:

```rust
use crafter_flow::{Binding, RunOptions, Runner};
use crafter_flow::flows::dhcpv4::client_flow;

let binding = Binding::netns("crafter-flow-client")
    .link_layer()
    .live();
let options = RunOptions::default().binding(binding);
let mut runner = Runner::with_options(options)?;
let mut flow = client_flow(crafter_flow::docaddr::CLIENT_MAC);
let report = runner.run(&mut flow)?;
println!("{}", report.show());
# Ok::<(), crafter_flow::FlowError>(())
```

Run a paired crafter-built responder in `crafter-flow-peer` that emits a DHCPv4
OFFER and ACK using documentation addresses. Keep that responder bounded to the
namespace and tear the namespaces down after the run.

## Cleanup

```sh
ip netns del crafter-flow-client
ip netns del crafter-flow-peer
```

Deleting the namespaces also removes the veth devices.
