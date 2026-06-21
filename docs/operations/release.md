# Release Operations

This checklist is for the maintainer who performs the final public `crafter`
release. It documents the handoff points only; internal workflow execution must not publish
the crate, push to public upstream, create tags, switch default branches, or
create a GitHub release.

## Local Validation

Run the local release gate from a normal source checkout:

```sh
.agents/scripts/check-crafter-release --static
```

The release scripts refresh the ignored root `Cargo.lock` as ephemeral local
validation state before locked offline checks. If you run the crates.io dry run
outside those scripts, first refresh and fetch the lockfile with the same local
preparation pattern, then run:

```sh
cargo publish -p crafter --dry-run --locked
```

The dry run must pass before any crates.io upload. It does not publish the
crate.

## Crates.io Upload

Use one of the guarded maintainer paths for the real upload:

```sh
.agents/scripts/publish-crafter-release VERSION
```

or the repo-local `agent-cargo-publish` skill. Both paths require explicit
confirmation, a valid `CARGO_REGISTRY_TOKEN`, the local release gate, and a
successful `cargo publish -p crafter --dry-run --locked` before the real
publish step.

After publishing, verify the released crate page on crates.io and the rendered
documentation on docs.rs for the published version.

## Public Upstream Migration

The public upstream repository is `git@github.com:pellegre/libcrafter.git`.
The Rust workspace preserves the project lineage locally, but it does not share
commit hashes with current upstream `master`. Before replacing public upstream
`master`, preserve the current upstream tip under a separate branch such as
`legacy-cpp-master`.

Any public upstream branch replacement must be an explicit maintainer action
outside internal workflow execution. Use a reviewed manual sequence, preserve the legacy tip
first, and prefer a guarded push such as `--force-with-lease` if a force push is
approved. A public upstream force push, default-branch switch, tag push, or
GitHub release creation is never part of unattended release automation.
