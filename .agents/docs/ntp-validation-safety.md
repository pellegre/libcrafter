# NTP validation safety

This note defines the validation boundary for NTP packet work. It is operating
policy for agents, not a new source of NTP wire facts. Header fields,
extension-field formats, NTS packet extension labels, MAC-tail behavior,
codepoint labels, and malformed-input expectations must still come from
`.agents/docs/ntp-rfc-manifest.md`, `.agents/docs/ntp-scope.md`,
`.agents/docs/ntp-wire-grammar.md`, and `.agents/docs/ntp-codepoints.md`.

NTP support in `crafter` is a packet primitive. Validation may build, decode,
round-trip, persist, compare, and inspect NTP packets through the existing
`Packet` and `Layer` model, but it must not turn the crate into a clock
synchronization client, server, scheduler, pool scanner, peer-selection engine,
NTS key-exchange implementation, or Autokey verifier.

## Offline-first gate

Every NTP change starts with offline validation:

- source-backed byte fixtures for client, server, NTPv3-compatible,
  SNTP-compatible, extension-field, NTS packet-extension, MAC-tail, unknown
  codepoint, boundary, malformed, and unrelated UDP payload cases;
- parser and serializer round trips that preserve explicit overrides, unknown
  values, extension bodies, reference identifiers, legacy MAC bytes, and raw
  tails;
- structured error checks for truncated fixed headers, invalid extension
  lengths, misaligned extension data, and ambiguous or malformed packet tails;
- deterministic pcap read/write checks using documentation-safe IPv4 and IPv6
  packet stacks; and
- oracle offline, oracle pcap, and probe dry-run validation when backend or
  generated-tool support exists.

Acceptance commands for NTP must not require provider credentials, live network
reachability, local raw-socket privileges, public NTP servers, or real peers.
Fixtures, pcaps, examples, generated send plans, oracle cases, and probe plans
must use documentation address space or synthetic artifacts by default.

## Dry-run planning gate

Before any live NTP behavior validation, plan the exchange in dry-run mode for
each tool surface that will participate:

```sh
tools/lab/run plan --provider qemu --dry-run --profile ntp-smoke --seed 123 --role stimulus --role target --json
tools/oracle/run live --provider qemu --dry-run --profile ntp-smoke --seed 123 --count 5 --out target/oracle/ntp-dry-run
tools/probe/run --provider qemu --dry-run --profile ntp-smoke --seed 123 --count 5 --out target/probe/ntp-dry-run
```

Dry-run records must show endpoint roles, packet intent, documentation-safe
addresses, capture points, expected artifacts, teardown path, and skip reasons.
A plan that cannot describe those details is not ready to become a live run.

## Protected live gate

Real NTP traffic is allowed only after all of these conditions are true:

- offline fixture, malformed, pcap, oracle, and probe dry-run validation for
  the relevant packet behavior has passed;
- an authorized operator has supplied an explicit live confirmation flag such
  as `--confirm-live-run`;
- packets will originate from disposable provider-backed endpoints through
  `tools/lab`, `tools/oracle`, `tools/probe`, or `tools/endpoint`;
- no raw NTP traffic will be sent from the developer machine;
- stimulus, target, capture, and teardown roles are isolated, controlled, and
  authorized for the specific NTP exchange under test; and
- collection and teardown commands are part of the same runbook as the live
  exchange.

Provider credentials, capability discovery, or selecting a provider are not
live confirmation. A live-capable command that lacks explicit confirmation must
stay on the dry-run path or fail closed.

## Skipped-live reporting

When live NTP validation is skipped, record the skip explicitly in the relevant
oracle, probe, lab, or endpoint artifact summary. The report must name the case
or profile, the provider requested or considered, the missing confirmation,
credential, capability, controlled peer, or authorization condition, the
dry-run artifact path that was produced instead, and whether any teardown was
needed. Skips are expected for unattended automation and should not be hidden as
passing live coverage.

## Artifacts, teardown, and redaction

Live-capable NTP workflows must collect enough evidence to explain the result:
compiled packets, decoded summaries, `show()` output, hexdumps, pcap files when
available, provider role metadata, command arguments, skip reasons, structured
errors, and teardown status. Store these artifacts under ignored output roots
such as `target/oracle/ntp-*`, `target/probe/ntp-*`, or provider-specific
ignored directories, and refer to those roots only by project-relative path and
case label.

After collection, tear down every provider-backed endpoint created for the run.
The final record must distinguish planned endpoints, created endpoints,
artifact locations, skipped live gates, and teardown status without storing
sensitive identifiers.

Before any artifact is promoted into tracked documentation, fixtures, oracle
specs, probe assets, or examples, redact or replace:

- provider account data, credentials, tokens, and secrets;
- public endpoint addresses, public IPs, live hostnames, endpoint identifiers,
  SSH details, and provider instance IDs;
- live host identifiers, pool names, production hostnames, and organization
  names;
- absolute local paths and user-specific machine names;
- sensitive pcaps, capture interface names, uncontrolled payloads, and pcap
  metadata from protected networks; and
- any value that cannot be reproduced from documentation-safe inputs.

If redaction would make an artifact ambiguous, regenerate the case offline with
source-backed documentation-safe values instead of committing the live artifact.
