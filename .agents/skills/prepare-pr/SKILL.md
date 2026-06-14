---
name: prepare-pr
description: Open, update, title, review, or prepare libcrafter pull requests so commits are ready for rebase-and-fast-forward landing and required validation is documented.
---

# Prepare PR

Use this skill whenever you open, update, title, review, or prepare a pull
request for this repository.

## Branch Name

Branches created for PR work must follow the repo-local `create-branch` skill:

```text
kind/short-slug
```

Use typed names such as `feature/complete-oracle` or
`fix/normalize-tcp-options`, not bare task names such as `complete-oracle`.

## PR Title

The PR title summarizes the preserved commit series and must follow the same
Conventional Commits policy as regular commits:

```text
type(scope): subject
```

Allowed types are `build`, `chore`, `ci`, `docs`, `feat`, `fix`, `perf`,
`refactor`, `revert`, `style`, and `test`.

Scopes are required. Use the narrowest useful scope, such as `ci`, `pcap`,
`live-lab`, `interop`, `docs`, `net`, or a protocol family. Do not include PR
numbers, reviewer thanks, or branch metadata in the title.

## PR Body

Fill the template with:

- a concise summary of behavior and scope
- exact validation commands and their results
- notes about any skipped validation or known residual risk

Do not mention internal agent workflow unless the user explicitly asks for it.

## Merge Expectations

PRs should be rebased onto the latest protected base branch and then landed by
fast-forwarding the base branch to the PR head. Do not use GitHub squash merge
for normal PR landing.

Every commit in the PR range must pass:

```sh
.agents/scripts/check-conventional-commits --range origin/master..HEAD
```

If a PR targets a renamed default branch such as `main`, substitute that base in
the range.

If a PR accumulates noisy work-in-progress commits, fix up, squash, or reword
them before marking the PR ready, then rebase again onto the latest protected
base.
