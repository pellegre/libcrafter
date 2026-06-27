# SSDP validation safety

This note defines the validation boundary for SSDP packet work. It is operating
policy, not a new source of SSDP wire facts. Methods, headers, multicast
addresses, service ports, HTTP-like grammar, and fixture expectations must still
come from `.agents/docs/ssdp-source-manifest.md`,
`.agents/docs/ssdp-wire-grammar.md`, `.agents/docs/ssdp-codepoints.md`, and
the public sources those documents cite.

SSDP support in `crafter` is a packet primitive. Validation may build, decode,
round-trip, persist, compare, and inspect packets, but it must not turn the
crate into a scanner, discovery daemon, control point, retry scheduler, or
service cache.

## Source and address policy

- Use public source evidence only: UPnP Device Architecture discovery text,
  current RFC Editor documents, IANA registries, IETF Datatracker metadata, and
  RFC Editor errata as classified by the SSDP source manifest.
- Use documentation address space in examples, fixtures, generated send plans,
  and dry-run validation records: RFC 5737 IPv4 documentation prefixes and RFC
  3849 IPv6 documentation prefixes are the default address sources.
- Use synthetic names, synthetic UUIDs, and documentation-safe interface names
  such as `dry-run0`. Do not record local absolute paths, credentials, public
  provider IPs, live host identifiers, private helper names, or sensitive
  capture identifiers in tracked SSDP files.
- Keep committed packet captures deterministic and synthetic. Captures from
  protected live work are evidence artifacts, not fixture sources, until they
  have been minimized, regenerated with documentation-safe values, and reviewed.

## Offline-first gate

Every SSDP change starts with offline validation:

- source-backed byte fixtures for valid, boundary, malformed, and unrelated UDP
  payloads;
- parser and serializer round trips that preserve explicit overrides, unknown
  values, duplicate headers, extension headers, and body bytes;
- structured error checks for malformed inputs;
- pcap read/write checks using documentation-safe packet stacks; and
- reference-backend agreement through oracle offline or pcap modes when backend
  support exists.

No acceptance command for SSDP may require provider credentials, live network
reachability, local raw-socket privileges, or a real responder. If a reference
backend cannot express an SSDP case, record the gap as unsupported or
parser-only instead of replacing offline validation with live traffic.

## Dry-run planning gate

Before any live SSDP behavior validation, plan the exchange in dry-run mode for
each layer that will participate:

```sh
tools/lab/run plan --provider qemu --dry-run --profile ssdp-smoke --seed 1900 --role stimulus --role target --json
tools/oracle/run live --provider qemu --dry-run --profile ssdp-smoke --seed 1900 --count 5 --out target/oracle/ssdp-dry-run
tools/probe/run --provider qemu --dry-run --profile ssdp-smoke --seed 1900 --count 5 --out target/probe/ssdp-dry-run
```

Dry-run plans must show endpoint roles, packet intent, documentation-safe
addresses, expected artifacts, and skip reasons. A dry-run that cannot describe
the role layout, capture points, or teardown path is not ready to become a live
run.

## Protected live gate

Real SSDP traffic is allowed only after all of these conditions are true:

- offline and pcap validation for the relevant packet behavior has passed;
- lab, oracle, and probe dry-run plans have been inspected;
- an authorized operator has given explicit protected confirmation for the live
  run;
- packets will originate from disposable provider-backed endpoints, not from the
  developer host;
- target and stimulus roles are isolated, controlled, and authorized for the
  specific SSDP exchange; and
- collection and teardown commands are part of the same runbook as the live
  exchange.

Protected confirmation is not a default, environment accident, or implicit
provider selection. A live command that lacks explicit confirmation must remain
a dry-run or fail closed.

## Artifacts, teardown, and redaction

Live-capable SSDP workflows must collect enough evidence to explain the result:
compiled packets, decoded summaries, `show()` output, pcap files when
available, provider role metadata, command arguments, skip reasons, and
structured errors. Store these artifacts under ignored output paths such as
`target/`.

After collection, tear down every provider-backed endpoint created for the run.
The final record must distinguish planned endpoints, created endpoints,
artifact locations, and teardown status without storing sensitive identifiers.

Before any artifact is promoted into tracked documentation, fixtures, oracle
specs, or probe assets, redact or replace:

- provider account data, credentials, tokens, and secrets;
- public IPs, live hostnames, endpoint identifiers, and SSH details;
- absolute local paths and user-specific machine names;
- sensitive pcap metadata, capture interface names, and uncontrolled payloads;
- live UUIDs, serial numbers, device descriptions, `LOCATION` URLs, and
  `SERVER` strings that identify real equipment; and
- any value that cannot be reproduced from documentation-safe inputs.

If redaction would make an artifact ambiguous, regenerate the case offline with
source-backed documentation-safe values instead of committing the live artifact.
