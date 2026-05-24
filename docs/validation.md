# Oracle Validation

The oracle validates packet behavior against reference backends owned by
`tools/oracle/`. Keep backend-specific logic and backend names inside that tool
tree; crate tests, public docs, and fixture docs should describe only the
oracle boundary.

## Corpus Generation

Corpus generation writes the ordered packet plans shared by validation modes:

```sh
tools/oracle/run corpus --profile smoke --seed 1 --count 10
```

The artifact is written to `target/oracle/corpus/plans.json` by default and
records the corpus id, selected specs, requested filters, backend metadata, and
libcrafter metadata.

## Offline Validation

Offline validation compares generated raw packet vectors and normalized decode
models without root privileges or live traffic:

```sh
tools/oracle/run offline --profile smoke --seed 1 --count 10
```

Use `--profile`, `--seed`, and `--count` to make failures reproducible. When a
report identifies a packet index, rerun with the same inputs and `--index`.

The checked-in fixture suite complements oracle validation. Fixture tests decode
committed bytes and pcaps, assert typed layers and stable fields, compare selected
summaries, verify byte-preserving roundtrips where promised, and exercise named
malformed inputs with structured error assertions. These tests run without
reference backend imports or `target/oracle/` artifacts.

Useful focused fixture checks:

```sh
cargo test -p crafter --test fixture_suite
cargo test -p crafter --test resilience malformed_corpus_reports_structured_errors
```

## Pcap Validation

Pcap validation exercises packet materialization, pcap write/read behavior, and
roundtrip decoding:

```sh
tools/oracle/run pcap --profile smoke --seed 1 --count 10
```

Use pcap mode when changes affect link types, timestamps, pcap framing, or
decode behavior that should survive file serialization.

## Live Validation

Live validation routes packet exchange through a provider. Use local dry-runs
for planning and CI-safe checks:

```sh
tools/oracle/run live --provider local-dry-run --profile smoke --seed 1 --count 10
tools/oracle/run live --provider hetzner --dry-run --profile smoke --seed 12345 --count 10
```

Real provider-backed validation is reserved for explicit live-lab workflows on
disposable infrastructure:

```sh
tools/live-lab/libcrafter-live-lab run --provider hetzner --suite oracle-live
```

See [live-lab.md](live-lab.md) for provider credentials, artifacts, and cleanup.

## CI Expectations

Pull request CI should run deterministic offline validation and pcap smoke
validation. Hetzner dry-runs are safe for planning. Real live packet exchange
must stay behind explicit protected workflow confirmation and cleanup logic.

Recommended local preflight:

```sh
cargo test --workspace
tools/oracle/run corpus --profile ci --seed 12345 --count 2000
tools/oracle/run offline --profile ci --seed 12345 --count 2000
tools/oracle/run pcap --profile smoke --seed 12345 --count 250
tools/oracle/run live --provider hetzner --dry-run --profile smoke --seed 12345 --count 10
```

Oracle artifacts default below `target/oracle/`, with mode-specific reports
under `target/oracle/corpus`, `target/oracle/offline`, `target/oracle/pcap`,
and `target/oracle/live`.
Keep promoted fixture bytes under `tests/fixtures/` and reference backend
ownership under `tools/oracle/`.
