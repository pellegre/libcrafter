# Single Main Shape

Generated tools should differ by the `Flow` they build, not by bespoke runner
orchestration. The shared shape is:

```rust
use crafter_flow::prelude::*;

let binding = Binding::default();
let options = RunOptions::default().binding(binding);
let mut flow = build_flow();
let result = run_tool(&mut flow, ToolRun::new(options))?;

println!("{}", result.report().show());
for send in result.send_reports() {
    println!("{}", send.plan().summary());
}
# Ok::<(), crafter_flow::FlowError>(())
```

When a tool needs scripted offline input or an outgoing packet mutation, it adds
that declaratively before the run:

```rust
# use crafter_flow::prelude::*;
# let options = RunOptions::default();
# let mut flow = crafter_flow::flows::dhcpv4::client_flow(crafter_flow::docaddr::CLIENT_MAC);
# let source = MemoryCaptureSource::default();
let run = ToolRun::new(options)
    .source(source)
    .mutator(Identity);
let result = run_tool(&mut flow, run)?;
# let _ = result;
# Ok::<(), crafter_flow::FlowError>(())
```

The helper lives in `crafter_flow::tool` and is re-exported by the prelude. It is
a thin wrapper around `Runner::run`: it keeps the default dry-run binding, accepts
an explicit live `Binding` only through `RunOptions`, and returns both the
`FlowReport` and ordered send reports.

## Tool Mapping

| Tool | Role | State Graph | Mutation | Binding |
| --- | --- | --- | --- | --- |
| DHCP starvation | `Initiator` | DHCP client `Selecting -> Requesting -> Bound`, repeated by a count bound | Per-iteration client MAC and transaction-id stamp | Dry-run namespace by default; live L2 interface only with explicit confirmation |
| DHCP hijack | `Responder` | DHCP server `WaitDiscover -> WaitRequest -> Done` | Reply options stamp configured router/DNS where the base flow does not expose option knobs | Dry-run namespace by default; live L2 interface only with explicit confirmation |
| ARP poison | `Injector` | Two ARP injector flows, one per cache direction | None for base gratuitous/reply packets | Dry-run namespace by default; live L2 interface only with explicit confirmation |
| DNS spoof | `Injector` | DNS watch state that emits a forged response to a matching query | None; the transition echoes query values into the response | Dry-run namespace by default; live network-layer interface only with explicit confirmation |

The scratch tools under `tools/flow/.scratch/tools/` may have local CLI parsing
and artifact printing, but their protocol behavior follows this same model:
build a flow, optionally attach source/mutation, then call the shared runner
shape. See [`../README.md`](../README.md) for the concepts and safety model.
