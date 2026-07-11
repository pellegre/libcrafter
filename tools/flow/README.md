# crafter-flow

`crafter-flow` is the tracked state-machine engine for multi-step packet
conversations built beside the `crafter` packet primitive. It lets tools model
what to send, what to wait for, which observed values to carry forward, and
where the conversation runs while keeping `crafter` focused on packet
construction, decoding, and send primitives.

## Core Concepts

The engine vocabulary is deliberately small:

- `Flow`: a named protocol state graph.
- `Transition`: a packet matcher plus action that may update `PacketContext`,
  send a packet, move to another state, or finish the run.
- `Role`: the participant mode: `Initiator`, `Responder`, or `Injector`.
- `Runner`: the single execution loop that keeps one send-and-receive position
  open and produces a `FlowReport`.
- `Binding`: the dry-run or live execution position, using a namespace-style
  default or an explicit interface.

An offline sketch using documentation address space:

```rust
use crafter_flow::prelude::*;

fn main() -> crafter_flow::Result<()> {
    let observed = crafter::Ipv4::new()
        .src(docaddr::CLIENT_IPV4)
        .dst(docaddr::DNS_IPV4)
        / crafter::Udp::new().source_port(53000).destination_port(crafter::DNS_PORT)
        / crafter::Dns::query("service.example.", crafter::DNS_TYPE_A).id(0x1234);

    let transition = Transition::on(
        PredicateMatcher::new("documentation DNS query", |packet, _ctx| {
            packet.layer::<crafter::Dns>().is_some()
        }),
        |_packet, ctx| {
            ctx.set_dns_transaction_id(0x1234);
            Ok(Step::done())
        },
    )
    .terminal();

    let mut flow = Flow::new("offline-dns-watch")
        .role(Role::Responder)
        .state(FlowState::new("WaitForQuery").on(transition))
        .initial("WaitForQuery");

    let options = RunOptions::default().binding(Binding::default());
    let mut runner = Runner::with_source(options, MemoryCaptureSource::new(vec![observed]))?;
    let report = runner.run(&mut flow)?;

    println!("{}", report.show());
    Ok(())
}
```

The default `Binding` is dry-run, so the sketch opens no real socket and sends
no packet.

## Roles

`Initiator` acts first. The tracked DHCP client flow uses this role: it emits a
DISCOVER, waits for an OFFER, carries the offered address and server identifier
through `PacketContext`, emits a REQUEST, and finishes on ACK.

`Responder` waits first. The tracked DHCP responder flow is the symmetric side
of the same conversation: it waits for DISCOVER, emits OFFER, waits for REQUEST,
then emits ACK. The client and responder examples validate that both sides can
be expressed as ordinary flows driven by the same `Runner`.

`Injector` observes traffic and emits packets from an off-path or on-path
position. The tracked ARP and DNS flows use this role for benign, closed-loop
demonstrations.

## Tracked Examples

The repository tracks only benign examples that run offline or against scripted
documentation-space input:

```sh
cargo run -p crafter-flow --example dhcp_client_flow
cargo run -p crafter-flow --example dhcp_responder_flow
cargo run -p crafter-flow --example arp_injector_flow
cargo run -p crafter-flow --example dns_spoof_flow
cargo run -p crafter-flow --example quic_initial_client_flow
cargo run -p crafter-flow --example quic_initial_server_flow
```

Each example prints the flow shape, dry-run send plans where packets are
emitted, and the final `FlowReport`.

The QUIC examples exchange deterministic protected Initial fixtures entirely
in memory. They inspect Initial packets only and do not establish a QUIC
connection.

## Safety Model

Safe offline execution is the default. `RunOptions::default()` uses
`Binding::default()`, which targets a namespace-style `flow0` binding in dry-run
mode. Dry-run conversations compile and plan packets, may consume
`MemoryCaptureSource` input, and never open a real socket or touch a real
interface.

Live traffic is an explicit opt-in through the public binding API: a caller must
choose an interface, choose link-layer or network-layer sending when needed, and
call `.live()`. The engine must not be patched to make a tool live; a tool
expresses that choice in its own binding. Generated defaults, tracked examples,
and documentation snippets stay offline and use documentation address space.

Bounded execution is also the default. Repetition is controlled by `Bound`,
`RunOptions::run_timeout`, `RunOptions::step_timeout`, and `send_repeat`; any
unbounded or live behavior belongs in an explicitly authorized tool or isolated
lab run.

## Scratch Lab And Tools

The isolated lab and concrete offensive tools are intentionally untracked under
`tools/flow/.scratch/`. See [`docs/scratch-layout.md`](docs/scratch-layout.md)
for the local-only layout:

- `tools/flow/.scratch/lab/`: QEMU lab assets for an internal-only VM topology
  with no route to real networks.
- `tools/flow/.scratch/tools/dhcp-starvation/`
- `tools/flow/.scratch/tools/dhcp-hijack/`
- `tools/flow/.scratch/tools/arp-poison/`
- `tools/flow/.scratch/tools/dns-spoof/`

Those crates call the tracked public API and follow the shared single-main
shape documented in [`docs/single-main.md`](docs/single-main.md). The tracked
manual namespace proof of concepts are
[`docs/netns-poc.md`](docs/netns-poc.md) for DHCP and
[`docs/arp-netns-poc.md`](docs/arp-netns-poc.md) for ARP.

## Governance Boundary

The tracked repository contains the neutral engine, protocol flow definitions,
tests, documentation, and benign closed-loop examples. These files must remain
safe to build and run without real targets, credentials, sensitive captures, or
host network changes.

Concrete tools that drive real clients, lab images, run artifacts, packet
captures, and generated binaries stay under `.scratch/` and out of version
control. They prove the abstraction by calling `Flow`, `Transition`, `Role`,
`Runner`, and `Binding` rather than by adding private behavior to the tracked
crate.

## Promotion Policy

`crafter-flow` is the proving ground. Candidate pieces for eventual promotion
into `crafter` include matcher adapters and combinators, capture-filter
derivation, the persistent send-and-receive `Conversation` primitive, and
inspectable reporting formats that are useful beyond stateful flows.

Promotion requires evidence from offline tests, benign examples, and the
isolated lab; a stable API shape that preserves the `Packet` abstraction; and
the same safe-default, explicit-live model as `crafter`. Whole offensive
workflows, scratch lab scripts, and flow-specific orchestration stay outside
`crafter`.
