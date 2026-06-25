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

## SNMPv3 Policy Boundary

- SNMPv3 helpers may name msgFlags bits, reserved bit combinations, security
  model values, raw security parameters, scoped-PDU bytes, and USM wire fields
  when the manifest backs the packet format.
- SNMPv3 helpers must not enforce VACM, access-control decisions, timeliness
  policy, user/key lookup, authentication success, privacy decryption,
  authorization, or engine-state transitions. Generated tools may report those
  wire fields, but policy decisions stay outside `crafter`.
- Reserved msgFlags bits, the reserved privacy-without-authentication
  combination, unassigned security models, and unknown security models must
  remain inspectable packet bytes unless a later source-backed slice explicitly
  adds a narrower validation primitive.

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

Generated SNMP send paths start as inspectable plans. Use a documentation
interface such as `dry-run0`, documentation addresses, and `SendOptions`
without calling `.live()`:

```rust
use crafter::prelude::*;

let packet = Ipv4::new()
    .src_str("192.0.2.30")?
    .dst_str("198.51.100.30")?
    / Udp::new().sport(49152).dport(SNMP_PORT)
    / Snmp::v2c_get_request(b"doc-community".to_vec(), 100, SnmpVarBindList::empty())?;

let plan = packet.send_dry_run(SendOptions::new().iface("dry-run0").network_layer())?;
println!("target={:?}", plan.target());
println!("{}", plan.compiled_packet().hexdump());
# Ok::<(), crafter::CrafterError>(())
```

## Live Work

Live SNMP traffic is lab-only. Plan with dry-run oracle, probe, endpoint, or lab
commands first, then run real traffic only through explicit provider-backed
workflows with authorized targets, protected confirmation, artifact collection,
and teardown evidence. Do not send host-originated live SNMP traffic by default.
