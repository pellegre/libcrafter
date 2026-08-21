# Packet validation

Packet behavior is validated in layers. The first three layers are tracked,
deterministic, and required for ordinary development:

1. Rust unit and integration tests cover builder, compile, decode, error, and
   public API behavior.
2. Oracle specs and independent backends cover byte and normalized-model
   agreement.
3. Pcap checks cover persisted framing and decode entrypoints.

```sh
cargo test --workspace
tools/oracle/run specs validate --strict
tools/oracle/run corpus --profile ci --seed 12345 --count 100 --out target/oracle/corpus
tools/oracle/run offline --corpus target/oracle/corpus/plans.json --out target/oracle/offline
tools/oracle/run pcap --corpus target/oracle/corpus/plans.json --out target/oracle/pcap
tools/probe/run --profile smoke --seed 1 --count 10 --out target/probe/plan
```

Run `.agents/scripts/check-crafter-release --static` before declaring a change
ready.

## IP Fragment Transform Validation

IP fragmentation and reassembly are deterministic `IpFragment` and `IpDefrag`
wire transforms. Validate them with the focused Rust tests, committed synthetic
fixtures, and the offline oracle feature specification:

```sh
cargo test -p crafter ip_fragment
cargo test -p crafter --test fixture_suite fragment
tools/oracle/run specs validate --strict
tools/oracle/run offline --profile fragmentation-smoke --seed 1 --count 20 \
  --out target/oracle/fragmentation
```

Tracked fixtures use documentation address space. Any externally collected
capture remains an ignored artifact and is not required for deterministic
development.

## External wire qualification

Some behavior requires a real kernel, peer, network position, or radio. The
public repository describes that requirement through capabilities, packet
plans, bounded executor inputs, and artifact schemas. It does not describe or
control the machines that satisfy it.

An external runner is responsible for:

- selecting an authorized execution target;
- checking out the exact candidate revision;
- preparing concrete interfaces, addresses, peers, and hardware;
- invoking the bounded workload with explicit live authorization;
- collecting reports and captures before restoring external state;
- recording the candidate revision and workload digest with the result.

External qualification is additional evidence, not a substitute for the local
gate. Its credentials, topology, host identifiers, and lifecycle code must not
be committed here.
