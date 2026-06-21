# Release Operations

This checklist is for the maintainer who performs the final public `crafter`
release. It documents the handoff points only; publishing, public upstream
pushes, tag creation, default-branch changes, and GitHub release creation are
explicit maintainer actions.

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

## Public Repository

The public repository is `git@github.com:pellegre/libcrafter.git`. After the
public reset, local checkouts should use that repository as `origin`.
