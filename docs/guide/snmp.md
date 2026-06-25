# SNMP Wire Coverage

This page describes the Simple Network Management Protocol support in
`crafter`: what the packet primitive builds and decodes, how SNMP rides over UDP
ports 161 and 162 in the default registry, and where the crate deliberately
stops.

`crafter` treats SNMP as packet bytes. It can build, compile, decode,
summarize, show, and preserve SNMP messages as typed layers inside the normal
`Packet` abstraction. It is not a scanner, a manager, an agent daemon, a trap
receiver service, a MIB engine, a credential store, a VACM evaluator, or a
monitoring product. Polling, retries, walks, notification services, access
control, and user/key management belong in generated tools outside the crate.

## Coverage At A Glance

| Area | State | Notes |
| --- | --- | --- |
| BER subset | Supported | Definite-length BER identifier/length/value handling, including non-minimal definite lengths where RFC 3417 permits them. |
| Values | Supported | INTEGER, OCTET STRING, NULL, OBJECT IDENTIFIER, and SNMP application values including IpAddress, Counter32, Gauge32, TimeTicks, Opaque, Counter64, Unsigned32, and exception values. |
| VarBinds | Supported | `SnmpVarBind` and `SnmpVarBindList` build, decode, summarize, and preserve unknown raw value TLVs. |
| SNMPv1 | Supported | Community wrapper, GetRequest, GetNextRequest, GetResponse, SetRequest, and Trap PDU fields. |
| SNMPv2c | Supported | Community wrapper, request/response PDUs, GetBulk, InformRequest, SNMPv2-Trap, Report wire shape, error-status labels, and unknown PDU preservation. |
| SNMPv3 | Supported as wire framing | Global data, flags, security model labels, raw/USM security parameters, plaintext scoped PDUs, Reports, and encrypted scoped-data byte preservation. |
| UDP dispatch | Supported | UDP/161 and UDP/162 decode as SNMP only when the payload looks like one complete SNMP BER message; non-SNMP payloads stay `Raw`. |
| Live behavior | Out of crate scope | Use dry-run plans, oracle/probe fixtures, or provider-backed labs. The crate does not originate live SNMP workflows by itself. |

The source map for these behaviors is in
[`docs/snmp-rfc-manifest.md`](../snmp-rfc-manifest.md), and implementation
status is tracked in
[`docs/snmp-implementation-inventory.md`](../snmp-implementation-inventory.md).

## Public API

SNMP is exported through `crafter::prelude::*`. Compose it like any other
packet layer:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> crafter::Result<()> {
    let sys_descr = SnmpOid::from_dotted("1.3.6.1.2.1.1.1.0")?;
    let varbinds = SnmpVarBindList::new(vec![SnmpVarBind::null(sys_descr)]);
    let snmp = Snmp::v2c_get_request(b"doc-community".to_vec(), 42, varbinds)?;

    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Udp::new().sport(49152).dport(SNMP_PORT)
        / snmp;

    let bytes = packet.compile()?;
    println!("{}", packet.summary());
    println!("{}", bytes.hexdump());
    Ok(())
}
```

`compile()` fills IPv4 protocol fields, UDP lengths/checksums, and SNMP BER
lengths when the caller leaves them unset. Explicit caller overrides survive,
including intentionally malformed UDP checksums or BER lengths for protocol
tests.

Summaries and `show()` output report community and security byte lengths, not
secret bytes. Callers that need raw bytes can use the typed accessors
explicitly.

## Message Shapes

SNMPv1 and SNMPv2c use the community-based message wrapper:

```text
SEQUENCE {
  version INTEGER,
  community OCTET STRING,
  data PDU
}
```

Use `Snmp::v1_get_request`, `Snmp::v1_trap`, `Snmp::v2c_get_request`,
`Snmp::v2c_response`, `Snmp::v2c_get_bulk`, `Snmp::v2c_inform_request`,
`Snmp::v2c_snmpv2_trap`, and related builders for common PDUs. Unknown but
well-formed context-specific PDU tags decode as preserve-only SNMP PDUs instead
of being discarded.

SNMPv3 uses the RFC 3412 wrapper:

```text
SEQUENCE {
  msgVersion INTEGER,
  msgGlobalData HeaderData,
  msgSecurityParameters OCTET STRING,
  msgData ScopedPduData
}
```

The crate exposes `SnmpV3GlobalData`, `SnmpV3Flags`,
`SnmpSecurityModel`, `SnmpUsmSecurityParameters`, `SnmpScopedPdu`, and
`SnmpEncryptedScopedData` for wire inspection. It names known flags and
security models, reports reserved flag combinations, preserves raw security
parameters, and preserves encrypted scoped data as bytes. It does not look up
users, store keys, authenticate messages, decrypt privacy payloads, enforce
timeliness, or make VACM access-control decisions.

```rust
use crafter::prelude::*;

fn build_v3_report() -> crafter::Result<Snmp> {
    let scoped = SnmpScopedPdu::new(
        vec![0x80, 0x00, 0x5e, 0x00, 0x53, 0x01],
        b"doc-context".to_vec(),
        SnmpPdu::report(7, SnmpVarBindList::empty())?,
    );

    Snmp::v3_plaintext(
        7,
        1500,
        [SNMP_V3_FLAG_REPORTABLE],
        SNMP_SECURITY_MODEL_USM,
        Vec::<u8>::new(),
        scoped,
    )
}
```

## BER, Values, And Unknowns

The SNMP layer is intentionally byte-preserving where the enclosing structure is
valid:

- non-minimal definite BER lengths decode and recompile;
- unknown application values keep their original identifier and content bytes;
- unknown PDU tags keep their raw TLV bytes;
- unknown error-status and security-model numbers stay numeric and labeled;
- malformed lengths and truncation return structured errors instead of panics.

Unsupported or malformed payloads are not normalized into a different message.
When a UDP payload on an SNMP port is not a complete SNMP wrapper, registry
decode keeps it as `Raw`.

## UDP And Pcap Decode

The default registry dispatches UDP payloads as SNMP when either source or
destination port is:

- `SNMP_PORT` (`161`) for request/response traffic;
- `SNMP_TRAP_PORT` (`162`) for trap, inform, and notification traffic.

Dispatch is conservative: the payload must look like exactly one BER SEQUENCE
with an SNMP version field and a source-backed wrapper shape. Custom registries
can override or disable application decode just like other UDP protocols.

Offline validation includes byte fixtures, pcap fixtures, malformed corpora, and
golden vectors. The checked-in SNMP pcap fixtures are synthetic and use only
documentation addresses; they exercise Ethernet and RawIp pcap paths without
using live captures.

## Dry-Run First

Examples and generated tools should default to offline or dry-run behavior.
Use documentation addresses and synthetic communities or USM names:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> crafter::Result<()> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 30))
        .dst(Ipv4Addr::new(198, 51, 100, 30))
        / Udp::new().sport(49152).dport(SNMP_PORT)
        / Snmp::v2c_get_request(
            b"doc-community".to_vec(),
            100,
            SnmpVarBindList::empty(),
        )?;

    let plan = packet.send_dry_run(SendOptions::new().iface("dry-run0").network_layer())?;
    println!("mode: dry-run");
    println!("target: {:?}", plan.target());
    println!("compiled bytes: {}", plan.len());
    Ok(())
}
```

Live SNMP traffic is lab-only. A generated tool that needs real packets should
first produce dry-run plans and pcap artifacts, then run against authorized
targets through provider-backed endpoint, oracle, probe, or lab workflows with
explicit confirmation and teardown. Do not store real communities, USM keys,
provider identifiers, public IPs, live hostnames, or sensitive packet captures
in tracked files.

## Guarded Live Validation

The SNMP oracle live workflow is dry-run by default. The first command uses the
local dry-run provider and never creates infrastructure. The guarded provider
command takes the dry-run branch unless `LIBCRAFTER_RUN_SNMP_LIVE=1` is set; a
real run still requires `--confirm-live-run` and a registered lab provider.

```sh
tools/oracle/run live --backend <reference-backend> --provider local-dry-run --family snmp --profile snmp-live-dry-run --seed 4205 --count 10 --out target/oracle/snmp-live-local-dry-run

if [ "${LIBCRAFTER_RUN_SNMP_LIVE:-0}" = "1" ]; then
  tools/oracle/run live \
    --backend <reference-backend> \
    --provider "${LIBCRAFTER_SNMP_LIVE_PROVIDER:-qemu}" \
    --family snmp \
    --profile snmp-live-dry-run \
    --seed 4206 \
    --count 10 \
    --direction live_exchange \
    --confirm-live-run \
    --out target/oracle/snmp-live-confirmed
else
  tools/oracle/run live \
    --backend <reference-backend> \
    --provider qemu \
    --dry-run \
    --family snmp \
    --profile snmp-live-dry-run \
    --seed 4206 \
    --count 10 \
    --direction live_exchange \
    --out target/oracle/snmp-live-guarded-dry-run
fi
```

Keep live artifacts under ignored `target/` paths. A confirmed run must collect
the oracle report, endpoint artifacts, and teardown records before the lab
session is considered complete.
