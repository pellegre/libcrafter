# Probe plans

`tools/probe/run` turns protocol cases into deterministic JSON plans:

```sh
tools/probe/run --profile smoke --seed 1 --count 10 --out target/probe/smoke
tools/probe/run --profile behavior --seed 1052 --count 40 --out target/probe/behavior
tools/probe/run --profile ipsec --seed 1 --out target/probe/ipsec
```

The command is plan-only. It does not send traffic, choose an execution target,
or change machine state. A plan contains packet intent, expected responses,
capture filters, deterministic documentation addresses, runtime requirements,
and the local executor cases that understand it.

Protocol cases live under `tools/probe/engine/protocols/`. Packet construction
and response validation for bounded execution live under
`tools/probe/adapters/src/`. An external runner may map declared requirements
to its own authorized environment, but that mapping is not part of the plan or
this repository.
