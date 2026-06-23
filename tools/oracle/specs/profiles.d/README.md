# Per-protocol sampling-profile fragments

Drop a `*.yaml` file here to add a protocol's sampling `profiles` without editing
the monolithic [`../profiles.yaml`](../profiles.yaml).

The spec loader (`tools/oracle/engine/spec_loader.py`) globs `profiles.d/*.yaml`
in sorted order after loading `profiles.yaml` and merges each fragment's profiles
into the same collection, then runs the same cross-reference and backend-mapping
validation over the merged result.

A fragment is a partial profiles document. It uses the same header as
`profiles.yaml` (`version: 1`, `kind: profiles`, `name: <unique>`) and declares a
`profiles` list with the same schema:

```yaml
version: 1
kind: profiles
name: example_protocol_profiles

profiles:
  - name: example-smoke
    purpose: example per-protocol boundary coverage
    default_count: 10
    family_weights:
      - name: ipv4
        weight: 1
    payload_length:
      min: 0
      max: 32
    feature_weights:
      baseline: 10
      boundary: 1
```

Rules:

- Profile names must be unique across `profiles.yaml` and every fragment. A
  duplicate name is rejected with a clear error rather than silently overriding.
- A missing `profiles.d/` directory means no fragments (pure back-compatibility).
- Fragments do not move content out of `profiles.yaml`; they only extend it.
