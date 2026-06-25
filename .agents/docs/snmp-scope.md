# SNMP agent scope

This note is operating guidance for generated SNMP tools. User-facing packet
coverage belongs in `docs/`; source authority and implementation status are
tracked in `docs/snmp-rfc-manifest.md` and
`docs/snmp-implementation-inventory.md`.

`crafter` SNMP work is wire-level only: build, compile, decode, preserve,
summarize, show, and validate SNMP packet bytes. Generated tools must not turn
the crate into a scanner, manager, trap receiver service, MIB engine, credential
store, access-control engine, or monitoring product.

## Codepoints

- Use only codepoints, tags, versions, PDU kinds, error-status values, security
  model values, transport ports, and object identifiers backed by
  `docs/snmp-rfc-manifest.md`.
- If a needed SNMP fact is missing or ambiguous, update the manifest first or
  stop the slice as unsupported. Do not fill gaps from memory, examples, device
  behavior, or uncited library output.
- Unknown but well-formed SNMP values, PDU tags, status values, security model
  values, enterprise assignments, and raw TLVs must remain inspectable and
  byte-preserving when the enclosing BER structure is valid.
- Compile paths may auto-fill unset BER lengths, tags, counts, and source-backed
  defaults, but caller-set overrides must survive, including deliberately
  malformed values.

## Tool Defaults

- Default generated examples, fixtures, oracle cases, probe plans, and send
  plans to offline or `--dry-run` behavior.
- Use documentation address space such as `192.0.2.10`, `198.51.100.20`, and
  `2001:db8::10`, plus synthetic communities such as `doc-community` and
  placeholder USM names such as `doc-user`.
- Generated tools must not store real communities, USM secrets, credentials,
  public IPs, live host identifiers, or sensitive captures in tracked files.
- Store live-run artifacts only under ignored paths such as `target/`, and keep
  committed fixtures deterministic and non-sensitive.

## Live Work

Live SNMP traffic is lab-only. Plan with dry-run oracle, probe, endpoint, or lab
commands first, then run real traffic only through explicit provider-backed
workflows with authorized targets, protected confirmation, artifact collection,
and teardown evidence. Do not send host-originated live SNMP traffic by default.
