# TLS validation safety

This note defines the validation boundary for TLS packet work. It is operating
policy for agents, not a new source of TLS wire facts. Record framing,
handshake structures, extension formats, codepoint labels, and malformed-input
expectations must still come from `.agents/docs/tls-manifest.md`,
`.agents/docs/tls-codepoints.md`, `.agents/docs/tls-scope.md`, and
`.agents/docs/tls-wire-grammar.md`.

TLS support in `crafter` is a packet primitive. Validation may build, compile,
decode, round-trip, persist, compare, and inspect TLS records through the
existing `Packet` and `Layer` model, but it must not turn the crate into a TLS
client, server, certificate validator, scanner, fuzzer, TCP stream reassembler,
or endpoint policy engine.

## Source and address policy

- Use public source evidence only: RFC Editor documents, IANA TLS registries,
  IETF Datatracker metadata, and RFC Editor errata classified by the TLS source
  manifest.
- Use documentation address space in examples, fixtures, generated send plans,
  dry-run oracle/probe/lab records, and pcap fixtures. RFC 5737 IPv4 prefixes
  such as `192.0.2.0/24` and `198.51.100.0/24`, plus RFC 3849 IPv6
  `2001:db8::/32`, are the default address sources.
- Use synthetic names, synthetic certificates or raw certificate bytes created
  for fixtures, synthetic SNI names such as `example.test`, and documentation
  interfaces such as `dry-run0`.
- Keep committed packet captures deterministic and synthetic. Captures from
  protected live work are evidence artifacts, not fixture sources, until they
  have been minimized, regenerated with documentation-safe values, and reviewed.

## Offline-first gate

Every TLS change starts with offline validation:

- source-backed byte fixtures for valid records, handshakes, extensions,
  unknown codepoints, opaque protected payloads, and malformed inputs;
- parser and serializer round trips that preserve explicit overrides, unknown
  values, duplicate extensions, and raw encrypted or application data;
- structured error checks for truncated record headers, record fragments,
  handshake headers, vectors, and extension bodies;
- packet composition checks using existing `crafter::prelude::*`,
  `Packet`/`Layer` composition, `compile()`, decode entrypoints, `summary()`,
  `show()`, and pcap read/write paths; and
- reference-backend agreement through oracle offline or pcap modes when backend
  support exists.

No TLS acceptance command may require provider credentials, live network
reachability, local raw-socket privileges, a real TLS peer, or a public endpoint.
If a reference backend cannot express a TLS case, record the gap as unsupported
or parser-only instead of replacing offline validation with live traffic.

## Dry-run planning gate

Before any live TLS behavior validation, plan the exchange in dry-run mode for
each layer that will participate:

```sh
tools/lab/run plan --provider qemu --dry-run --profile tls-smoke --seed 443 --role stimulus --role target --json
tools/oracle/run live --backend <oracle-backend> --provider qemu --dry-run --profile tls-smoke --seed 443 --count 5 --out target/oracle/tls-dry-run
tools/probe/run --provider qemu --dry-run --profile tls-smoke --seed 443 --count 5 --out target/probe/tls-dry-run
```

Dry-run plans must show endpoint roles, packet intent, controlled TLS peer
setup, documentation-safe addresses, expected artifacts, skip reasons, and the
teardown path. A dry-run that cannot describe the role layout, capture points,
confirmation requirements, or cleanup commands is not ready to become a live
run.

## Protected live gate

Real TLS traffic is allowed only after all of these conditions are true:

- offline, malformed, pcap, and reference-backend validation for the relevant
  packet behavior has passed;
- lab, oracle, and probe dry-run plans have been inspected;
- an authorized operator has given explicit protected confirmation through
  `--confirm-live-run`;
- packets will originate from disposable provider-backed endpoints, not from
  the developer host;
- stimulus and target roles are isolated, controlled, authorized, and limited to
  the specific TLS exchange under test;
- any target service uses synthetic identities and fixture material suitable for
  validation, not real production certificates or secrets; and
- artifact collection and teardown commands are part of the same runbook as the
  live exchange.

Protected confirmation is not a default, environment accident, implicit
provider selection, or credential presence check. A live command that lacks
explicit confirmation must remain a dry-run or fail closed. Provider credentials
may be read by provider tooling at runtime, but credential values must never be
printed into plans, artifacts, documentation, fixtures, or logs committed to the
repository.

TLS live probe validation uses a two-part environment gate plus the existing
probe confirmation flag. The default branch is intentionally dry-run:

```sh
if [ -n "${LIBCRAFTER_TLS_LIVE_PROVIDER:-}" ] && [ "${LIBCRAFTER_TLS_LIVE_CONFIRM:-}" = "yes" ]; then
  tools/probe/run --provider "$LIBCRAFTER_TLS_LIVE_PROVIDER" --confirm-live-run --profile tls-smoke --seed 8446 --count 1 --out target/probe/tls-live
else
  tools/probe/run --provider qemu --dry-run --profile tls-smoke --seed 8446 --count 1 --out target/probe/tls-live-dry-run
fi
```

Do not set `LIBCRAFTER_TLS_LIVE_PROVIDER` or
`LIBCRAFTER_TLS_LIVE_CONFIRM=yes` from unattended automation. The provider name
selects the disposable lab backend; confirmation records the operator's
authorization to leave the dry-run path.

## Artifacts, teardown, and redaction

Live-capable TLS workflows must collect enough evidence to explain the result:
compiled packets, decoded summaries, `show()` output, hexdumps, pcap files when
available, provider role metadata, target-service logs, command arguments, skip
reasons, and structured errors. Store these artifacts under ignored TLS output
roots such as `target/oracle/tls-*` and `target/probe/tls-*`, and refer to those
roots only by project-relative path and case label.

After collection, tear down every provider-backed endpoint and controlled TLS
service created for the run. The final record must distinguish planned
endpoints, created endpoints, artifact locations, target-service cleanup, and
teardown status without storing sensitive identifiers.

Before any artifact is promoted into tracked documentation, fixtures, oracle
specs, probe assets, or examples, redact or replace:

- provider account data, credentials, tokens, and secrets;
- public IPs, live hostnames, endpoint identifiers, SSH details, and public
  service URLs;
- absolute local paths and user-specific machine names;
- sensitive pcap metadata, capture interface names, and uncontrolled payloads;
- production certificate chains, private keys, session secrets, ticket keys,
  key logs, real SNI values, ALPN values from private services, and identifying
  target-service logs; and
- any value that cannot be reproduced from documentation-safe inputs.

If redaction would make an artifact ambiguous, regenerate the case offline with
source-backed documentation-safe values instead of committing the live artifact.
