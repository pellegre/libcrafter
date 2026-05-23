---
name: agent-cargo-publish
description: Publish the libcrafter crafter crate to crates.io only after the local release gate, cargo publish dry-run, package summary, ask-tool confirmation, and crates.io/docs.rs verification.
---

# Agent Cargo Publish

Use this skill when asked to publish the `crafter` crate from this repository to
crates.io.

Publishing is irreversible. Do not run the real `cargo publish` command unless
all gates pass and the user explicitly approves through an ask-capable tool.
Plain-text confirmation is not enough.

## Required Order

1. Verify the release context:
   - `git status --short` must be empty.
   - Record `git rev-parse --abbrev-ref HEAD` and `git rev-parse HEAD`.
   - Read the crate name and version from Cargo metadata and require
     `crafter` as the package.
   - Target crates.io only.
2. Run the local release gate:

```sh
.agents/scripts/check-crafter-release --static
```

3. Run the publish dry run:

```sh
cargo publish -p crafter --dry-run --locked
```

4. Check whether the exact version already exists on crates.io. Prefer:

```sh
curl -fsSL "https://crates.io/api/v1/crates/crafter/<version>"
```

   Stop if the query succeeds.
5. Summarize what will change before asking:
   - crate and version
   - registry
   - git branch and commit
   - package contents summary from the release gate or `cargo package --list`
   - crates.io metadata/readme update from the packaged Cargo metadata
   - docs.rs build expected from the published package
6. Ask for approval with an ask-capable tool immediately before publishing. Use
   `request_user_input` when that tool is available. The question must name the
   exact crate, version, registry, and commit. Provide a non-publish option and
   a publish-now option. Proceed only if the user chooses the publish-now
   option.
7. Publish:

```sh
cargo publish -p crafter --locked
```

8. Verify and report:
   - crates.io package page:
     `https://crates.io/crates/crafter/<version>`
   - docs.rs page:
     `https://docs.rs/crafter/<version>/crafter/`

If docs.rs is still building, report it as pending with the expected URL. Do
not try to force docs.rs.

## Hard Stops

Stop before real publishing if:

- the working tree is dirty
- the release gate or dry run fails
- the crate version is already published
- the ask-capable tool is unavailable
- the user does not explicitly choose the publish-now option
- credentials are missing or cargo reports authentication failure

Never use `--allow-dirty` or `--no-verify` for the real publish. Never print
`CARGO_REGISTRY_TOKEN` or any credential value.
