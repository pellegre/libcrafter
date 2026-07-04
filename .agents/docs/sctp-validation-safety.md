# SCTP validation safety

This note defines the validation boundary for SCTP packet work. It is
operating policy for agents, not a new source of SCTP wire facts. Header
fields, chunk layouts, parameter and cause envelopes, codepoint labels,
checksum behavior, UDP encapsulation, and malformed-input expectations must
still come from `.agents/docs/sctp-rfc-manifest.md`,
`.agents/docs/sctp-codepoints.md`, `.agents/docs/sctp-wire-grammar.md`, and
`.agents/docs/sctp-scope.md`.

SCTP support in `crafter` is a packet primitive. Validation may build,
compile, decode, round-trip, persist, compare, and inspect SCTP packets through
the existing `Packet` abstraction, typed SCTP layer values, `compile()`,
decode entrypoints, `summary()`, and `show()`. Validation must not turn the
crate into an SCTP association stack, sender, socket API, endpoint service,
scanner, fuzzer, analyzer, retransmission engine, congestion controller, or
application payload dispatcher.

## Source and address policy

- Use public source evidence only: RFC 9260, current IANA SCTP registries,
  IANA protocol number `132`, RFC 6951 UDP encapsulation on port `9899`, RFC
  9653 zero-checksum context, IETF Datatracker metadata, and RFC Editor
  errata as classified by the SCTP source manifest.
- Use documentation address space in examples, fixtures, generated send plans,
  dry-run oracle/probe/lab records, and pcap fixtures. RFC 5737 IPv4 prefixes
  such as `192.0.2.0/24` and `198.51.100.0/24`, plus RFC 3849 IPv6
  `2001:db8::/32`, are the default address sources.
- Use synthetic ports, verification tags, PPIDs, names, interface labels such
  as `dry-run0`, and deterministic payload bytes created for fixtures.
- Keep committed packet captures deterministic and synthetic. Captures from
  protected live work are evidence artifacts, not fixture sources, until they
  have been minimized, regenerated with documentation-safe values, and
  reviewed.

## Offline-first gate

Every SCTP change starts with offline validation:

- source-backed byte fixtures for native IPv4, native IPv6, guarded UDP
  encapsulation, valid chunks, unknown codepoints, padding boundaries,
  explicit overrides, checksum status, and malformed inputs;
- parser and serializer round trips that preserve explicit checksums, lengths,
  flags, verification tags, chunk types, parameter types, cause codes, PPIDs,
  raw values, and padding bytes;
- structured error checks for truncated common headers, under-length chunks,
  overrun chunk lengths, under-length parameters, overrun parameter lengths,
  under-length causes, and overrun cause lengths;
- packet composition checks using `crafter::prelude::*`, `Packet` layer
  composition with `/`, `compile()`, decode entrypoints, `summary()`, `show()`,
  and pcap read/write paths; and
- reference-backend agreement through oracle offline or pcap modes when
  backend support exists.

Acceptance commands for SCTP must not require provider credentials, live
network reachability, local raw-socket privileges, kernel SCTP configuration,
public peers, or real association state. If a reference backend cannot express
an SCTP case, record the gap as unsupported or parser-only instead of replacing
offline validation with live traffic.

## Lab dry-run gate

Before any live SCTP behavior validation, plan the exchange in dry-run mode for
each tool surface that will participate:

```sh
tools/lab/run plan --provider qemu --dry-run --profile sctp-smoke --seed 132 --role stimulus --role target --json
tools/oracle/run live --backend <oracle-backend> --provider qemu --dry-run --profile sctp-smoke --seed 132 --count 5 --out target/oracle/sctp-dry-run
tools/probe/run --provider qemu --dry-run --profile sctp-smoke --seed 132 --count 5 --out target/probe/sctp-dry-run
```

Dry-run records must show endpoint roles, packet intent, documentation-safe
addresses, SCTP transport shape, capture points, expected artifacts, skip
reasons, and teardown path. For RFC 6951 cases, the plan must state why a
UDP/9899 payload is structurally admitted as SCTP and how unrelated UDP/9899
payloads remain `Raw`. A dry-run that cannot describe the role layout,
confirmation requirements, capture points, or cleanup commands is not ready to
become a live run.

## Protected live gate

Real SCTP traffic is allowed only after all of these conditions are true:

- offline fixture, malformed, pcap, oracle, and probe dry-run validation for
  the relevant packet behavior has passed;
- lab, oracle, probe, or endpoint dry-run plans have been inspected;
- an authorized operator has supplied explicit live confirmation through the
  live-capable tool, such as `--confirm-live-run`;
- packets will originate from disposable provider-backed endpoints through the
  repository lab/session/endpoint workflow, not from the developer host;
- stimulus, target, capture, and teardown roles are isolated, controlled,
  authorized, and limited to the specific SCTP packet behavior under test;
- any SCTP stack, peer, or service used by the validation is controlled test
  infrastructure, not a public or production endpoint; and
- artifact collection and teardown commands are part of the same runbook as
  the live exchange.

Provider credentials, capability discovery, environment variables, selected
provider names, or the presence of raw-socket privileges are not live
confirmation. A live-capable command that lacks explicit confirmation must
stay on the dry-run path or fail closed.

## Skipped-live reporting

When live SCTP validation is skipped, record the skip explicitly in the
relevant oracle, probe, lab, or endpoint artifact summary. The report must name
the case or profile, the provider requested or considered, the missing
confirmation, credential, capability, controlled peer, or authorization
condition, the dry-run artifact path that was produced instead, and whether any
teardown was needed. Skips are expected for unattended automation and must not
be hidden as passing live coverage.

## Artifacts, teardown, and redaction

Live-capable SCTP workflows must collect enough evidence to explain the result:
compiled packets, decoded summaries, `show()` output, hexdumps, pcap files when
available, provider role metadata, command arguments, skip reasons, structured
errors, and teardown status. Store these artifacts under ignored output roots
such as `target/oracle/sctp-*`, `target/probe/sctp-*`, or provider-specific
ignored directories, and refer to those roots only by project-relative path and
case label.

After collection, tear down every provider-backed endpoint created for the run.
The final record must distinguish planned endpoints, created endpoints,
artifact locations, skipped live gates, and teardown status without storing
sensitive identifiers.

Before any artifact is promoted into tracked documentation, fixtures, oracle
specs, probe assets, examples, or generated-tool guidance, redact or replace:

- provider account data, credentials, tokens, and secrets;
- public endpoint addresses, public IPs, live hostnames, endpoint identifiers,
  SSH details, and provider instance IDs;
- live host identifiers, production hostnames, organization names, kernel
  association state, and uncontrolled peer metadata;
- absolute local paths and user-specific machine names;
- sensitive pcaps, capture interface names, uncontrolled payloads, and pcap
  metadata from protected networks; and
- any value that cannot be reproduced from documentation-safe inputs.

If redaction would make an artifact ambiguous, regenerate the case offline with
source-backed documentation-safe values instead of committing the live artifact.
