# Oracle validation

`tools/oracle/run` is libcrafter's deterministic packet-equivalence entrypoint.
It owns spec loading, corpus generation, reference-backend comparison, pcap
checks, reports, and reproduction coordinates.

Packet behavior is data-driven. Add coverage through `tools/oracle/specs/` and
backend adapters under `tools/oracle/engine/backends/`; do not add ad hoc
reference snippets elsewhere.

```sh
tools/oracle/run specs validate --strict
tools/oracle/run corpus --backend scapy --profile smoke --seed 1 --count 10
tools/oracle/run offline --backend scapy --profile smoke --seed 1 --count 10
tools/oracle/run pcap --backend scapy --profile smoke --seed 1 --count 10
tools/oracle/run report target/oracle/offline/report.json
```

Scapy is the full read/write reference backend. Wireshark/tshark is parser-only
and may be used for decode and pcap-read comparisons when available.

Oracle deliberately has no machine-selection or live-orchestration command.
Hardware or wire qualification is performed by operator-supplied external
tooling that checks out an exact candidate revision and invokes a bounded
adapter with concrete inputs.

See `tools/oracle/docs/adding-a-protocol.md` for the protocol plugin recipe and
`docs/operations/validation.md` for the validation boundary.
