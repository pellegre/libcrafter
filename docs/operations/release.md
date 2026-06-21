# Release Operations

This checklist is for the maintainer who performs the final public `crafter`
release. It documents the handoff points only; Clew execution must not publish
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
The public repository will be reset cleanly to the Rust workspace on `master`;
do not create or preserve a public branch for the old C++ tip.

Perform public ref cleanup and public `master` replacement before enabling
rulesets. If they still exist, delete the legacy public branches `dev`,
`pcap_filter`, and `testing`; delete the legacy public tags `version-0.1`,
`version-0.2`, `version-0.3`, and `version-1.0`; and delete the legacy GitHub
Release named `version 1.0` or any release attached to `version-1.0`.

Any public upstream branch replacement must be an explicit maintainer action
outside Clew execution. Use a reviewed manual sequence, verify the public ref
state immediately before destructive changes, and prefer a guarded push such as
`--force-with-lease` if a force push is approved. A public upstream force push,
default-branch switch, tag push, or GitHub release creation is never part of
unattended release automation.

After the release, retarget local remotes so `origin` points to
`git@github.com:pellegre/libcrafter.git` and remove the local `upstream` remote.
