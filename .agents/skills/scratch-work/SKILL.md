---
name: scratch-work
description: Use ignored .scratch workspaces for experiments, disposable prototypes, network probes, QEMU or dongle labs, generated exploratory code, and any task where the user asks to make a scratch folder or wants code/scripts that should not be committed until promoted.
---

# Scratch Work

Use this skill when work should be explored locally without immediately adding
prototype code, logs, captures, generated files, or one-off scripts to tracked
repo paths.

## Workflow

1. Ensure `.scratch/` is ignored in the repository before creating scratch
   files. Add the ignore rule if it is missing.
2. Create one workspace per experiment:
   `.scratch/<short-topic-slug>/`.
3. Add a `README.md` in the scratch workspace with:
   - goal and date
   - host or lab assumptions
   - exact commands run
   - observed outputs worth preserving
   - cleanup notes
   - candidates for later promotion into `docs/`, `tools/`, or tests
4. Keep ad hoc code under `scripts/`, `src/`, `guest/`, or similarly explicit
   subdirectories inside that workspace.
5. Keep artifacts under `artifacts/`, `state/`, `pcaps/`, or `logs/` inside the
   scratch workspace.
6. Do not commit scratch files directly. Promote only hardened pieces by moving
   them into tracked repo locations and adding tests or docs appropriate for the
   promoted behavior.

## Network Experiments

For QEMU, USB dongle, wire-level packet, or LAN probing work:

- Keep host mutation in documented setup steps. Do not hide root-requiring
  changes inside casual scratch scripts.
- Prefer disposable VMs, provider labs, network namespaces, or explicit lab
  interfaces for raw packet work.
- Record interface names, USB IDs, QEMU options, driver assumptions, and
  observed MAC/IP addresses in the workspace README.
- Put captures and logs in scratch artifacts. Redact secrets before promoting
  any output.
- Use the `endpoint-provider` skill for endpoint-backed raw-packet workflows.

## Script Rules

- Make scratch scripts small, direct, and parameterized with environment
  variables or flags.
- Print commands and paths clearly enough that the user can rerun them.
- Avoid embedding credentials, Wi-Fi passphrases, provider tokens, or private
  network secrets in files.
- Add timeouts to sniffing, scanning, packet generation, or remote commands.
- Treat scratch results as evidence, not final implementation. Summarize what
  worked and what should be promoted.

## Promotion

When a scratch experiment stabilizes, move the durable pieces out of `.scratch/`
and update the repo normally. Typical destinations are `tools/` for reusable
scripts, `docs/` for workflow documentation, `tests/` for fixtures or checks,
and `.agents/skills/` for reusable agent procedure.
