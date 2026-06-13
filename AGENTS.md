# libcrafter

This is the repository for `libcrafter`, a Rust workspace for packet-level
network interaction. It exists so that agents — and the tools agents generate —
can construct protocol-correct packets, place them on real networks, capture
and decode the responses, and act on what they observe.

The public crate is `crafter`. Generated tools should depend on it directly and
import `crafter::prelude::*`.

## Current status

`crafter` 0.3.0 is the first public release. The core surface is in place:
layered packet construction with auto-filled lengths and checksums, decode
entrypoints for Ethernet, Linux cooked capture, null/loopback, and raw IPv4 /
IPv6 inputs, classic pcap read/write with libpcap BPF filters, raw send and
send/receive matching, provider-backed endpoints, and multi-endpoint lab
sessions (Hetzner, QEMU, VirtualBox) for traffic that cannot live on a
developer machine.

TCP stream reassembly, full pcapng, full BPF parsing, and a complete TCP/IP
stack are not in scope yet; IP fragmentation and reassembly ship as explicit
`IpFragment`/`IpDefrag` wire transforms rather than automatic decode-time
behavior. The 0.x Rust API may still evolve as protocol and wire coverage
grows.

## Preserve the packet abstraction

A `Packet` is a typed stack of layers. Composition with `/`, `compile()`,
`decode_from_l3`, `summary()`, and `show()` are the surface most generated
tools see. Keep that abstraction airtight: every protocol addition should slot
into the same builder, decode, and summary shape, and every helper should
return a `Packet` or a typed layer rather than raw bytes plus instructions.

When a new protocol or feature does not fit this shape cleanly, pause and ask
before introducing a parallel API. A second surface fragments the agent's
mental model.

## Protocol-correct defaults, honored overrides

`compile()` fills anything the agent did not set — checksums, lengths, protocol
numbers, header lengths, next-header fields. Anything the agent did set must
survive untouched, including values that are wrong on purpose. Generated tools
often need malformed packets to exercise a stack; refusing to emit them defeats
the point of building at the packet layer.

Decoding follows the same rule. Unknown next-protocols are preserved as `Raw`
when the enclosing header is valid, malformed buffers surface as structured
errors with `context`, `required`, and `available`, and truncation never
becomes a silent panic.

## Two surfaces: safe offline, explicit live

Every workflow has an offline path — dry-run send plans, pcap fixtures, decode
tests, oracle and probe `--dry-run` profiles — and a live path: raw send,
send/receive, bounded capture, provider-backed wire runs. The offline path is
the default. The live path is opt-in through an explicit flag, profile, or
provider credential.

This is not a stylistic preference. Live raw traffic against the wrong network
is a legal and operational problem. Examples, tests, and generated defaults
must use documentation address space (`192.0.2.0/24`, `198.51.100.0/24`,
`2001:db8::/32`) and dry-run plans. Real targets enter the picture only when an
authorized human or agent has said so.

Endpoint providers and lab sessions exist so that the live path does not have to
originate from the developer machine. When an agent needs to send crafted
traffic for real, the correct move is to provision a disposable provider
endpoint or lab session, run the work from there, collect the artifacts, and
destroy it — not to elevate privileges on the host the agent is running on.

## Agents write tools; the crate stays a primitive

`crafter` is not a packet analyzer, a fuzzer, or a scanner. Those are generated
tools a developer's agent can build on top in an afternoon. Resist pulling them
into the crate.

The test for whether something belongs in `crafter`:

- It exposes a new wire-level capability that cannot be assembled from existing
  primitives → in scope.
- It combines existing primitives into a useful workflow → an example, a doc
  snippet, or a skill — not a new module.

Doing less here lets generated tools stay specific to what their developer
needs.

## Inspectable beats clever

Every runtime feature should be inspectable from agent code: `summary()`,
`show()`, `hexdump()`, plan structs, typed errors, deterministic pcap output.
If an agent has to log-fish or guess what happened, the primitive is
incomplete.

Prefer an explicit verbose API over a clever implicit one.
`SendOptions::new().iface("eth0").network_layer()` reads cleanly to an agent;
a magic single-argument send does not.

## Working rules

These are defaults. Deviate when there is a reason, but be loud about it and
get approval first.

- Treat the `crafter` public API as the contract. Internal moves are fine;
  renaming exported types is a breaking change.
- Generated examples and tests use documentation address space and dry-run
  send plans unless explicitly gated.
- Do not store real credentials, provider account data, public IPs, live host
  identifiers, or packet captures from sensitive networks in tracked files.
  The endpoint provider reads `HETZNER_API_TOKEN` or `HCLOUD_TOKEN` from the
  environment.
- Run the local release gate before declaring a change ready to ship:
  `.agents/scripts/check-crafter-release --static`.
- For provider-backed packet validation, start with `--dry-run` against the
  `lab`, `oracle`, `probe`, and `endpoint` runners before any live invocation.
- Use the repo-local skills when the task they describe comes up:
  `agent-cargo-publish`, `commit-changes`, `prepare-pr`, `packet-validation`,
  `lab-session`, `lab-provider`, `endpoint-provider`, `scratch-work`,
  `create-branch`. They encode policy that this file does not repeat.
- Operating guidance for agents writing generated tools belongs in
  [`.agents/docs/cookbook.md`](.agents/docs/cookbook.md). User-facing crate
  documentation belongs in [`docs/`](docs/). Do not mix the two.
- Publishing to crates.io is a final maintainer action. Never run
  `cargo publish` from unattended automation; use `agent-cargo-publish` or an
  explicit human-driven dry-run/publish pair.
