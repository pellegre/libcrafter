# Scratch Layout

`tools/flow/.scratch/` is reserved for local flow-engine artifacts that must not
enter version control. The repository-level `.scratch/` gitignore rule ignores
this directory at any depth, so generated tools, packet captures, and
build outputs placed here remain local-only.

## Directory Layout

- `tools/flow/.scratch/tools/dhcp-starvation/`: standalone DHCP starvation tool
  crate.
- `tools/flow/.scratch/tools/dhcp-hijack/`: standalone DHCP hijack tool crate.
- `tools/flow/.scratch/tools/arp-poison/`: standalone ARP poison tool crate.
- `tools/flow/.scratch/tools/dns-spoof/`: standalone DNS spoof tool crate.

The `.scratch/` tree must never be committed. Acceptance for crates under
`tools/flow/.scratch/tools/` uses build, syntax, dry-run, and file-existence
checks only; it must not rely on git status, tracked-file checks, staging, or
other repository-state tests.

## Standalone Crates

Each offensive tool crate is nested beneath the tracked workspace but must build
independently from it. Every
`tools/flow/.scratch/tools/<tool>/Cargo.toml` therefore includes an empty
`[workspace]` table to detach the crate from the root workspace:

```toml
[workspace]
```

From `tools/flow/.scratch/tools/<tool>/`, the exact path dependencies back to the
tracked crates are:

```toml
[dependencies]
crafter-flow = { path = "../../.." }
crafter = { path = "../../../../../crafter" }
```

`../../..` resolves to `tools/flow`, and `../../../../../crafter` resolves to the
tracked `crafter` crate at the repository root.

## Governance Boundary

See `tools/flow/README.md` for the governance boundary. The tracked crate owns
the neutral flow engine and benign closed-loop examples. Concrete experimental
tools stay under `.scratch/` and are built by calling the
public engine API rather than patching tracked engine code.
