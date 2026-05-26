---
name: agent-branches
description: Create or rename libcrafter agent branches and worktrees with typed branch names such as feature/slug or fix/slug instead of bare task names.
---

# Agent Branches

Use this skill whenever an agent creates, renames, checks out, or prepares a
branch or worktree for repository work.

## Branch Name Format

Use:

```text
kind/short-slug
```

Allowed kinds:

- `feature`: new behavior, capabilities, protocol support, tooling, or planned
  feature work
- `fix`: bug fixes, regressions, correctness issues, reliability fixes
- `docs`: documentation-only work
- `test`: tests, fixtures, validation harnesses, oracle coverage
- `ci`: GitHub Actions, hooks, commit policy, runner setup
- `chore`: repository maintenance, dependency hygiene, generated metadata
- `refactor`: behavior-preserving restructuring
- `perf`: performance improvements
- `release`: release preparation and publish plumbing

## Slug Rules

Keep slugs lowercase ASCII, hyphen-separated, and specific enough to identify
the work. Prefer 2-5 words. Do not use spaces, underscores, uppercase letters,
PR numbers, personal names, timestamps, or bare plan names.

Good examples:

```text
feature/complete-oracle
fix/normalize-tcp-options
test/oracle-pcap-fixtures
docs/release-checklist
ci/conventional-commit-policy
release/crafter-0-1
```

Bad examples:

```text
complete-oracle
oracle
agent-work
fix stuff
feat_complete_oracle
```

When a tool proposes a bare plan or task branch such as `complete-oracle`,
convert it to the nearest typed branch, usually `feature/complete-oracle` for
new capability work or `fix/<slug>` for corrective work.
