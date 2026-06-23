# Per-protocol stack-grammar fragments

Drop a `*.yaml` file here to add a protocol's `roots`, `families`, `stacks`, and
`constraints` without editing the monolithic [`../stacks.yaml`](../stacks.yaml).

The spec loader (`tools/oracle/engine/spec_loader.py`) globs `stacks.d/*.yaml` in
sorted order after loading `stacks.yaml` and merges each fragment's entries into
the same collections, then runs the same cross-reference and backend-mapping
validation over the merged result.

A fragment is a partial stack-grammar document. It uses the same header as
`stacks.yaml` (`version: 1`, `kind: stack_grammar`, `name: <unique>`) and may
declare any subset of `roots`, `families`, `stacks`, and `constraints`:

```yaml
version: 1
kind: stack_grammar
name: example_protocol_stacks

stacks:
  - name: ipv4_example
    root: "l3:ipv4"
    layers:
      - ipv4
      - example
```

Rules:

- Root, family, stack, and constraint names must be unique across `stacks.yaml`
  and every fragment. A duplicate name is rejected with a clear error rather than
  silently overriding.
- A missing `stacks.d/` directory means no fragments (pure back-compatibility).
- Fragments do not move content out of `stacks.yaml`; they only extend it.
