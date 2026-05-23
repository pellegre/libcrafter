---
name: agent-commits
description: Commit libcrafter changes with the repository's Conventional Commits policy and scoped staging discipline.
---

# Agent Commits

Use this skill whenever you create, amend, reword, split, squash, or otherwise
prepare commits in this repository.

## Commit Subject Format

Every commit subject must use:

```text
type(scope): subject
type: subject
```

Allowed types:

- `build`: build tooling, packaging, generated build metadata
- `chore`: repository maintenance that is not CI, docs, or tests
- `ci`: GitHub Actions, workflow scripts, runner setup
- `docs`: documentation-only changes
- `feat`: new user-facing or API behavior
- `fix`: bug fixes and reliability corrections
- `perf`: performance improvements
- `refactor`: behavior-preserving code restructuring
- `revert`: reverting a prior change
- `style`: formatting-only changes
- `test`: tests, fixtures, validation harnesses

Scopes are lowercase and may use digits, `.`, `_`, `/`, or `-`.

Good examples:

```text
feat(pcap): add nanosecond timestamp writer
fix(ci): install libpcap before workspace tests
test(interop): cover malformed tcp options
docs(live-lab): clarify Hetzner dry runs
```

## Required Local Check

Before committing, install the tracked hook once in the checkout:

```sh
tools/git-hooks/install
```

Before rewording or pushing commit history, validate the affected range:

```sh
tools/policy/check-conventional-commits --range origin/master..HEAD
```

For a single proposed message, validate through the hook or checker rather than
duplicating the regex by hand.

## Staging Discipline

Stage only files that belong to the change being committed. Do not stage
ignored artifacts, provider state, local credentials, generated reports, or
unrelated user edits.

Keep commit subjects short, imperative, and specific. Put details in the body
only when the subject cannot carry the reasoning.
