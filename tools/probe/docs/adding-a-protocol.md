# Adding a probe protocol

1. Add or extend the protocol's module under
   `tools/probe/engine/protocols/`. Register deterministic cases, builders,
   profile membership, and supported bounded-executor cases.
2. Keep every plan deterministic for `(case, profile, seed, sequence)` and use
   documentation address space by default.
3. Express environmental needs as capability names or peer contracts. Do not
   add host selection, credentials, SSH, machine lifecycle, topology, hardware
   leases, or shell commands.
4. If the case is executable, add typed packet materialization and bounded
   response validation under `tools/probe/adapters/src/`.
5. Add source-backed oracle coverage under `tools/oracle/specs/` when the wire
   behavior is independently comparable.
6. Run:

   ```sh
   python3 -m unittest discover -s tools/probe/tests -p 'test_*.py'
   cargo test -p probe-adapters
   tools/oracle/run specs validate --strict
   ```

External wire qualification is requested only after deterministic validation
passes. The external runner owns the execution target and returns artifacts for
the exact candidate revision; no integration-specific details belong in the
protocol plugin.
