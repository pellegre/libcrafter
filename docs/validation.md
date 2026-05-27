# Oracle Validation

The oracle validates packet behavior against reference backends owned by
`tools/oracle/`. Keep backend-specific logic and backend names inside that tool
tree; crate tests, public docs, and fixture docs should describe only the
oracle boundary.

Oracle answers this question: given one packet plan, do libcrafter and a
reference backend agree on the emitted bytes and parsed model? Kernel and
service behavior checks belong to [probe validation](probe.md).

## Corpus Generation

Corpus generation writes the ordered packet plans shared by validation modes:

```sh
tools/oracle/run corpus --profile smoke --seed 1 --count 10
```

The artifact is written to `target/oracle/corpus/plans.json` by default. It
records the corpus id, selected specs, requested filters, backend metadata,
libcrafter metadata, ordered packet plans, and per-packet eligibility for
offline, pcap, and wire modes. Reuse `--corpus <path>` to run the exact same
packet set through multiple validation levels:

```sh
tools/oracle/run offline --corpus target/oracle/corpus/plans.json
tools/oracle/run pcap --corpus target/oracle/corpus/plans.json
tools/oracle/run live --provider hetzner --dry-run --corpus target/oracle/corpus/plans.json
```

## Offline Validation

Offline validation compares generated raw packet vectors and normalized decode
models without root privileges, pcap files, or live traffic:

```sh
tools/oracle/run offline --profile smoke --seed 1 --count 10
```

Use `--profile`, `--seed`, and `--count` to make failures reproducible. When a
report identifies a packet index, rerun with the same inputs and `--index`.
When a corpus exists, prefer `--corpus` so the same packet appears in the same
position across offline, pcap, and live dry-runs.

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

Pcap validation exercises packet materialization, classic pcap write/read
behavior, link type selection, and roundtrip decoding:

```sh
tools/oracle/run pcap --profile smoke --seed 1 --count 10
```

Use pcap mode when changes affect link types, timestamps, pcap framing, or
decode behavior that should survive file serialization.
Packets that cannot be represented in the requested pcap mode are reported as
skipped with a stable reason.

## Wire Validation

Wire validation routes provider-backed packet exchange through an oracle live
provider adapter. It uses the same corpus contract as offline and pcap modes,
then filters each packet by adapter-provided provider capabilities and explicit
mutation policy. Reports keep generated, eligible, skipped, sent, captured,
parsed, byte comparison, decode comparison, passed, and failed counts.

Provider-backed adapters are selected by `--provider` and registered under
`tools/oracle/engine/providers/`. They own provider-specific endpoint plans,
wire lifecycle command plans, bootstrap, remote endpoint commands, capabilities,
and comparison policy. Packet generation, endpoint protocol comparison, report
assembly, and the generic provider execution flow remain in the oracle runner.
`tools/wire` remains responsible for endpoint lifecycle and artifact transport.

Use the non-provider-backed local dry-run or provider-backed dry-runs for
planning and CI-safe checks:

```sh
tools/oracle/run live --provider local-dry-run --profile smoke --seed 1 --count 10
tools/oracle/run live --provider hetzner --dry-run --profile smoke --seed 12345 --count 10
tools/oracle/run live --provider qemu --dry-run --profile smoke --seed 12345 --count 10
tools/oracle/run live --provider virtualbox --dry-run --profile smoke --seed 12345 --count 10
python3 tools/oracle/tests/live_provider_matrix.py --providers hetzner,qemu,virtualbox --backend scapy --profile smoke --seed 12345 --count 5 --dry-run --out target/oracle/provider-matrix-dry-run
```

Real provider-backed validation is reserved for explicit protected workflows on
disposable wire endpoints. Provider selection still uses the same live oracle
command and adapter registry:

```sh
tools/oracle/run live --provider hetzner --confirm-live-run --profile smoke --seed 12345 --count 10
```

For local VM providers, use the guarded matrix smoke path. It runs QEMU and
VirtualBox wire doctor checks first, uses a small corpus, and records
structured skips by default when VM creation is not explicitly enabled:

```sh
python3 tools/oracle/tests/live_provider_matrix.py --providers qemu,virtualbox --backend scapy --profile smoke --seed 12345 --count 2 --real --skip-unavailable --out target/oracle/provider-matrix-vm-real
```

Use `--allow-vm-create` or `LIBCRAFTER_ORACLE_VM_SMOKE_ALLOW_CREATE=1` in a lab
run when the matrix should pass `--confirm-live-run` to the same oracle live
command and create disposable local VMs. Use `--strict-vm-smoke` or
`LIBCRAFTER_ORACLE_VM_SMOKE_STRICT=1` when missing VM prerequisites or disabled
VM creation should fail the qualification run. QEMU uses `qemu/private` with
private group `oracle-live-private`; VirtualBox uses `virtualbox/lan` with the
bridged interface discovered by `VBoxManage` or requested through
`LIBCRAFTER_VBOX_BRIDGE_IFACE`.

See [wire.md](wire.md) for provider credentials, artifacts, and cleanup.

## CI Expectations

Pull request CI should run deterministic corpus, offline, pcap, provider-backed
wire dry-run, and probe dry-run checks. Oracle provider checks are selected
through the live provider adapter registry. Real live packet exchange must stay
behind explicit protected workflow confirmation and cleanup logic.

Recommended local preflight:

```sh
cargo test --workspace
tools/oracle/run corpus --profile ci --seed 12345 --count 100 --out target/oracle/final-corpus
tools/oracle/run offline --corpus target/oracle/final-corpus/plans.json --out target/oracle/final-offline
tools/oracle/run pcap --corpus target/oracle/final-corpus/plans.json --out target/oracle/final-pcap
python3 tools/oracle/tests/live_provider_matrix.py --providers hetzner,qemu,virtualbox --backend scapy --profile ci --seed 12345 --count 100 --dry-run --out target/oracle/final-live-matrix
tools/probe/run --provider hetzner --dry-run --profile smoke --seed 1 --count 10 --out target/probe/final-dry-run
```

Oracle artifacts default below `target/oracle/`, with mode-specific reports
under `target/oracle/corpus`, `target/oracle/offline`, `target/oracle/pcap`,
and `target/oracle/live`.
Keep promoted fixture bytes under `crafter/tests/fixtures/` and reference
backend ownership under `tools/oracle/`.
