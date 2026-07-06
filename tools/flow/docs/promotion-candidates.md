# Crate Promotion Candidates

`crafter-flow` is the proving ground for stateful packet conversations. Pieces
move into `crafter` only after they are proven by offline tests, benign examples,
and isolated lab use, and only after their public shape is stable enough for a
published crate contract. `crafter` users depend on exported names and behavior;
promotion is therefore a compatibility decision, not a cleanup step.

The state-machine layer itself stays in this tool crate. `Flow`, `Transition`,
`Role`, `Runner`, protocol-specific flow definitions, scratch lab wiring, and
tool orchestration combine primitives into workflows. Under the `CLAUDE.md`
"Agents write tools; the crate stays a primitive" test, that makes them examples,
docs, skills, or tools rather than new `crafter` modules.

## Criterion

Promote a piece only when it exposes a broadly useful wire-level capability that
cannot be assembled cleanly from existing `crafter` primitives, and when the API
has stopped changing under real flow usage. Do not promote pieces whose main
value is orchestrating a conversation, selecting a role, or driving a whole
tool.

## Matcher And ReplyMatcher

Why it is wire-level enough:

- `Matcher` is a packet predicate abstraction over decoded `Packet` values.
- `ReplyMatcher` generalizes `crafter`'s existing reply predicates into a
  reusable object that can be stored, composed, described, and passed around.
- Layer matchers and combinators are useful outside flows anywhere caller code
  needs to classify captured packets.

What must stabilize first:

- The trait shape, object-safety requirements, naming, and composition API.
- Whether matching is context-free in `crafter` or needs a smaller non-flow
  context type.
- Reporting text from `describe()`, especially if summaries become part of
  user-visible plans or tests.
- Coverage for malformed packets, `Raw` fallbacks, and every reply predicate
  already exposed by `crafter`.

API-contract implications:

- Promoting the trait would create a public extension point, so method names,
  lifetimes, object-safety, and blanket implementations become hard to change.
- Matchers must preserve `crafter`'s decode rules: unknown valid payloads remain
  matchable as `Raw`, and malformed buffers return structured errors before
  matching rather than panicking.
- Any adapter from current reply predicates must keep honoring user-supplied
  packet fields, including intentionally incorrect values.

## Conversation And Persistent Send Plus Capture

Why it is wire-level enough:

- `Conversation` models a single packet I/O position: send packets and keep one
  receive side open long enough to observe replies across multiple steps.
- This fills a primitive gap between write-only send and one-shot send/receive:
  replies that arrive between logical steps can be retained instead of dropped.
- The concept is independent of `Flow`; generated tools and small scripts could
  use it directly for packet-level exchanges.

What must stabilize first:

- Live capture backing, resource lifetime, pending-packet buffering, timeout
  semantics, and error reporting.
- The relationship to `SendOptions`, `PacketSender`, `Sniffer`, dry-run plans,
  and explicit live opt-in.
- Inspectable counters and reports, including what dry-run means for receive
  sources.
- Provider and lab behavior after repeated real runs, not only memory-source
  tests.

API-contract implications:

- Defaults must stay offline or dry-run, with live network use requiring an
  explicit public opt-in.
- The type would own OS resources in live mode, so drop behavior, borrowing, and
  thread-safety need clear guarantees.
- Packet emission must remain exact: the primitive may fill only what `compile()`
  already fills and must not reject intentionally malformed packets.
- Errors should carry enough context to be inspectable without forcing callers to
  parse logs.

## Capture-Filter Derivation

Why it is wire-level enough:

- Deriving a BPF filter from packet shape is a reusable capture primitive, not a
  flow workflow.
- It already builds on `crafter` reply knowledge and can reduce packet loss or
  noise for any caller that sends packets and captures likely replies.
- Batch filter derivation is useful for tools that plan several packets before
  opening capture.

What must stabilize first:

- Semantics for unsupported packets, empty filters, multi-packet filters, and
  filter ordering.
- Link-layer versus network-layer capture behavior across supported input
  formats.
- Tests proving filters are conservative enough not to exclude valid replies.
- Whether generated filters are advisory strings or a stronger typed filter
  representation.

API-contract implications:

- Once public, the meaning of an empty filter and the stability of generated BPF
  strings matter to callers and tests.
- Filters must be conservative: extra captured traffic is acceptable; filtering
  out a legitimate reply is a correctness bug.
- The API should remain inspectable and deterministic so send plans, dry-runs,
  and captured artifacts can explain what filter was used.
