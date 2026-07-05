# crafter-flow

`crafter-flow` is a tracked, public state-machine engine for modeling
multi-step packet conversations beside the `crafter` packet primitive. It lets
tools describe what to send, what to wait for, and which observed values to
carry forward without changing `crafter` itself.

## Core Concepts

- `Flow`: the named state-graph definition for a protocol conversation.
- `Transition`: a matcher plus action plus next state, carrying context forward.
- `Role`: the participant mode, either `Initiator`, `Responder`, or `Injector`.
- `Runner`: the single execution loop holding one send+receive position open.
- `Binding`: where and how the flow runs: namespace vs interface, dry-run vs live.

## Governance Boundary

The tracked repository contains the neutral engine and benign, closed-loop proof
of concept examples. Those examples must use documentation address space, target
only themselves, and remain safe to run without a real network.

Concrete offensive tools and the isolated lab live untracked under
`tools/flow/.scratch/`. They are built by calling the engine's public API, not by
patching the engine or carrying private behavior inside the tracked crate.

## Safety Model

The default binding is namespace + dry-run and opens no socket. Running against a
real interface is an explicit public opt-in, mirroring `crafter`'s dry-run default
and `.live()` opt-in. The engine stays fully capable; a tool opts into live use
through the public interface instead of editing this crate.

## Promotion Policy

Stable pieces such as matchers or the persistent send+receive session may move
into `crafter` later. For now, they live here until the flow engine proves their
shape.
