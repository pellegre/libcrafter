---
name: agent-pull-requests
description: Prepare libcrafter pull requests so squash commits inherit compliant titles and required validation is documented.
---

# Agent Pull Requests

Use this skill whenever you open, update, title, review, or prepare a pull
request for this repository.

## Branch Name

Branches created for PR work must follow the repo-local `agent-branches` skill:

```text
kind/short-slug
```

Use typed names such as `feature/complete-oracle` or
`fix/normalize-tcp-options`, not bare task names such as `complete-oracle`.

## PR Title

The PR title becomes the squash commit subject, so it must follow the same
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

PRs should be squash-merged. The squash title must be the PR title. Intermediate
commits should also pass:

```sh
.agents/scripts/check-conventional-commits --range origin/master..HEAD
```

If a PR accumulates noisy work-in-progress commits, squash or reword them before
marking the PR ready.
