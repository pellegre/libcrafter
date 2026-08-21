# NTP validation

NTP follows the same repository boundary as every other protocol:

- source-backed wire cases live in `tools/oracle/specs/`;
- deterministic peer-behavior plans live in the NTP probe plugin;
- typed packet construction and bounded response validation live in the Rust
  probe adapter;
- execution target selection and controlled responder preparation are external.

```sh
tools/oracle/run specs suite --family ntp
tools/oracle/run offline --family ntp --profile ci --seed 1 --count 20
tools/oracle/run pcap --family ntp --profile ci --seed 1 --count 20
tools/probe/run --profile ntp-smoke --seed 1 --out target/probe/ntp
```

The malformed NTP case remains offline. Wire qualification, when requested,
must use an authorized environment and an exact candidate revision.
