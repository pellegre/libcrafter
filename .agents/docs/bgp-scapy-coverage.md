# BGP scapy backend coverage

Maps every BGP message type, path attribute, and capability in the BGP-4
manifest ([`bgp-manifest.md`](bgp-manifest.md)) to what the oracle's **scapy**
reference backend can natively materialize. Later oracle specs (plan steps
68-72) **must** only set `backend_support.scapy.status: supported` for a case
when this file says the relevant primitive is **scapy-native** and the
round-trip column is `OK`. Everything classified `scapy-raw` or `unsupported`
must be marked `unsupported` (or built from explicit bytes) in the spec, never
silently claimed.

This step records the gap only. **No oracle code was changed.**

## Coverage classification

- **scapy-native** — `scapy.contrib.bgp` exposes a dedicated layer/field for the
  item; the oracle can build it from structured fields and re-dissect it.
- **scapy-raw** — no dedicated layer; scapy carries the item as opaque
  bytes (generic container or trailing payload). The oracle must hand it raw
  bytes; structured field assertions are not available.
- **unsupported** — scapy cannot represent the item even as raw bytes within the
  surrounding BGP structure without manual byte surgery.

## Environment probed

The classifications below were produced by importing `scapy.contrib.bgp` in the
**same Python environment the oracle scapy backend uses**, then building and
re-dissecting each primitive.

- Runner: `tools/oracle/run` → `uv run --no-project --with "scapy>=2.5,<3"`
  (see `tools/oracle/engine/backends/scapy/bootstrap.py`,
  `BACKEND_PYTHON_REQUIREMENTS` = scapy + PyYAML + pytest + cryptography).
- `uv` version: 0.7.19; resolved **scapy 2.7.0**.
- `import scapy.contrib.bgp` — **succeeded** (no install failure).
- Round-trip test: `raw(pkt)` then re-parse with the owning class and compare
  bytes (`OK` = byte-identical re-dissection).

### Import-time caveat (affects ASN-width cases)

Importing `scapy.contrib.bgp` emits:

```
WARNING: [bgp.py] use_2_bytes_asn: True
```

Scapy decodes BGP AS numbers using a **module-global** `use_2_bytes_asn` switch
that defaults to **2-octet** ASNs. This is not a per-packet field. AS_PATH (2),
AGGREGATOR (7), and any 2-vs-4-octet ASN encoding therefore depend on this
global being toggled to match the negotiated 4-octet-AS capability. The oracle
scapy backend must set this switch explicitly for 4-octet-ASN cases; otherwise
AS_PATH / AGGREGATOR bytes will silently use 2-octet ASNs. AS4_PATH (17) and
AS4_AGGREGATOR (18) are always 4-octet by definition and have dedicated layers.

## Message types (manifest "Message Types")

scapy class registry: `_bgp_cls_by_type = {1:BGPOpen, 2:BGPUpdate,
3:BGPNotification, 4:BGPKeepAlive, 5:BGPRouteRefresh}`.

| Type | Name | scapy class | Coverage | Round-trip |
| --- | --- | --- | --- | --- |
| 1 | OPEN | `BGPHeader`/`BGPOpen` | scapy-native | OK |
| 2 | UPDATE | `BGPHeader`/`BGPUpdate` | scapy-native | OK |
| 3 | NOTIFICATION | `BGPHeader`/`BGPNotification` | scapy-native | OK |
| 4 | KEEPALIVE | `BGPHeader`/`BGPKeepAlive` | scapy-native | OK |
| 5 | ROUTE-REFRESH | `BGPHeader`/`BGPRouteRefresh` | scapy-native | OK |

Notes:
- `BGPHeader` carries the 16-octet marker + length + type; the message body is a
  payload layer. All five types build and re-dissect byte-identically.
- `BGPRouteRefresh` exposes `afi`, `subtype`, `safi`, `orf_data`. The middle
  octet is modeled as `subtype`, so Enhanced Route Refresh BoRR(1)/EoRR(2)
  subtypes (manifest `rr_message_subtypes`) are scapy-native.
- NOTIFICATION error/subcode registries in scapy
  (`_error_codes`, `_error_subcodes`) match the manifest for codes 1-7. Codes
  **8** (Send Hold Timer Expired) and **9** (Loss of LSDB Sync) are newer than
  scapy 2.7.0's table — the numeric value still encodes (the field is a raw
  byte) so they are scapy-native at the byte level but lack a scapy label.

## OPEN optional parameters / capabilities (manifest "Capability Codes")

scapy class registry: `_capabilities_objects = {1:BGPCapMultiprotocol,
2:BGPCapGeneric, 3:BGPCapORF, 64:BGPCapGracefulRestart, 65:BGPCapFourBytesASN,
70:BGPCapGeneric, 130:BGPCapORF}`. Optional-parameter type 2 (Capabilities) is
modeled by `BGPOptParam` + `BGPCapability`.

| Code | Name | Manifest scope | scapy class | Coverage | Round-trip |
| --- | --- | --- | --- | --- | --- |
| 1 | MP-BGP (Multiprotocol) | yes | `BGPCapMultiprotocol` (afi/safi) | scapy-native | OK |
| 2 | Route Refresh | yes | `BGPCapGeneric(code=2)` | scapy-native | OK |
| 64 | Graceful Restart | yes | `BGPCapGracefulRestart` | scapy-native | OK |
| 65 | 4-octet AS number | yes | `BGPCapFourBytesASN(asn)` | scapy-native | OK |
| 69 | ADD-PATH | yes | `BGPCapGeneric(code=69, cap_data=...)` | scapy-raw | OK |
| 70 | Enhanced Route Refresh | preserve only | `BGPCapGeneric(code=70)` | scapy-raw | OK |
| 128 | Prestandard Route Refresh | preserve only | `BGPCapGeneric(code=128)` | scapy-raw | OK |

Notes:
- **ADD-PATH (69)** has **no dedicated** scapy layer (no entry in
  `_capabilities_objects`). scapy carries the capability value as opaque
  `cap_data` bytes via `BGPCapGeneric` — so it is **scapy-raw**: the
  `<AFI, SAFI, Send/Receive>` triples must be supplied as bytes, not fields. Its
  oracle case should be `unsupported` for structured scapy assertions, or built
  from explicit bytes only.
- Codes 2, 70, 128 ride `BGPCapGeneric` (code + length + raw value). Code 2
  (Route Refresh) has a zero-length value, so the generic container is
  byte-equivalent to a dedicated layer and is treated as scapy-native above;
  70 and 128 are preserve-only in the manifest and only need raw round-trip.
- Unknown capability codes round-trip verbatim through `BGPCapGeneric`
  (satisfies RFC 5492 §5 / manifest "Unknown capability codes MUST round-trip").

## Path attributes (manifest "Path Attribute Type Codes")

scapy class registry: `_path_attr_objects = {1:BGPPAOrigin, 2:BGPPAASPath,
3:BGPPANextHop, 4:BGPPAMultiExitDisc, 5:BGPPALocalPref, 6:BGPPAAtomicAggregate,
7:BGPPAAggregator, 8:BGPPACommunity, 9:BGPPAOriginatorID, 10:BGPPAClusterList,
14:BGPPAMPReachNLRI, 15:BGPPAMPUnreachNLRI, 16:BGPPAExtComms, 17:BGPPAAS4Path,
25:BGPPAIPv6AddressSpecificExtComm, 32:BGPPALargeCommunity}`.

| Type | Name | Manifest scope | scapy class | Coverage | Round-trip |
| --- | --- | --- | --- | --- | --- |
| 1 | ORIGIN | yes | `BGPPAOrigin` | scapy-native | OK |
| 2 | AS_PATH | yes | `BGPPAASPath` | scapy-native* | OK |
| 3 | NEXT_HOP | yes | `BGPPANextHop` | scapy-native | OK |
| 4 | MULTI_EXIT_DISC | yes | `BGPPAMultiExitDisc` | scapy-native | OK |
| 5 | LOCAL_PREF | yes | `BGPPALocalPref` | scapy-native | OK |
| 6 | ATOMIC_AGGREGATE | yes | `BGPPAAtomicAggregate` | scapy-native | OK |
| 7 | AGGREGATOR | yes | `BGPPAAggregator` | scapy-native* | OK |
| 8 | COMMUNITIES | yes | `BGPPACommunity` | scapy-native | OK |
| 9 | ORIGINATOR_ID | preserve only | `BGPPAOriginatorID` | scapy-native | OK |
| 10 | CLUSTER_LIST | preserve only | `BGPPAClusterList` | scapy-native | OK |
| 14 | MP_REACH_NLRI | yes | `BGPPAMPReachNLRI` | scapy-native | OK |
| 15 | MP_UNREACH_NLRI | yes | `BGPPAMPUnreachNLRI` | scapy-native | OK |
| 16 | EXTENDED COMMUNITIES | yes | `BGPPAExtComms` | scapy-native | OK |
| 17 | AS4_PATH | yes | `BGPPAAS4Path` | scapy-native | OK |
| 18 | AS4_AGGREGATOR | yes | `BGPPAAS4Aggregator` | scapy-native | OK |
| 32 | LARGE_COMMUNITY | yes | `BGPPALargeCommunity` | scapy-native | OK |

`*` AS_PATH (2) and AGGREGATOR (7) ASN width follows the module-global
`use_2_bytes_asn` switch (see import-time caveat). Set it to match the case's
negotiated capability before asserting bytes.

### Large Communities are scapy-native (manifest call-out resolved)

The step text flagged Large Communities as an attribute "scapy cannot encode
natively." That is **not true for scapy 2.7.0**: type 32 maps to
`BGPPALargeCommunity` in `_path_attr_objects`, with `BGPLargeCommunitySegment`
fields `global_administrator`, `local_data_part1`, `local_data_part2` (the exact
12-octet RFC 8092 §3 triple). A built LARGE_COMMUNITY attribute round-trips
byte-identically. **Its oracle case may be marked
`backend_support.scapy.status: supported`.** (The caution may have applied to an
older scapy; with the pinned `scapy>=2.5,<3` resolving to 2.7.0 it is native.)
If a future bootstrap resolves an older scapy (2.5.x) lacking
`BGPPALargeCommunity`, downgrade type 32 to scapy-raw and re-check.

### Extended Communities (type 16) — value sub-types are raw

`BGPPAExtComms` builds and re-dissects, and scapy ships many extended-community
sub-type layers (`BGPPAExtCommTwoOctetASSpecific`, `...FourOctetASSpecific`,
`...IPv4AddressSpecific`, `...Opaque`, FlowSpec, etc.). The manifest keeps the
8-octet item as opaque raw bytes ("Extended-community sub-type tables ... out of
scope ... round-trip as raw 8-octet items"). So the attribute container is
scapy-native, but crafter and the oracle only assert the raw 8-octet value;
do not assert scapy's decoded sub-type fields.

## NLRI / withdrawn-route prefix codec (manifest "NLRI / Withdrawn-route")

scapy-native via `BGPNLRI_IPv4` / `BGPNLRI_IPv6`
(and `BGPNLRI_IPv4_AP` / `BGPNLRI_IPv6_AP` for ADD-PATH). Verified:

- `BGPNLRI_IPv4(prefix='192.0.2.0/24')` → `18 c0 00 02` (len-in-bits `0x18`=24,
  then `ceil(24/8)=3` prefix octets) — matches manifest RFC 4271 §4.3 codec.
- `BGPNLRI_IPv6(prefix='2001:db8::/32')` → `20 2001 0db8` (len `0x20`=32, 4
  octets) — matches.

## AFI / SAFI (manifest "AFI / SAFI")

scapy-native: `address_family_identifiers` includes AFI 1 (IPv4) and 2 (IPv6);
`subsequent_afis` includes SAFI 1 (unicast) and 2 (multicast). The in-scope
`<1,1>` and `<2,1>` combinations are directly settable on `BGPCapMultiprotocol`,
`BGPPAMPReachNLRI`, `BGPPAMPUnreachNLRI`, and `BGPRouteRefresh`.

## AS_PATH segment types (manifest "AS_PATH segment types")

scapy `as_path_segment_types = {1:AS_SET, 2:AS_SEQUENCE, 3:AS_CONFED_SEQUENCE,
4:AS_CONFED_SET}` — all four are recognized codepoints. Confederation segments
(3,4) encode at the byte level (manifest treats them as "recognized ... no
confederation processing"), so they are scapy-native for byte assertions.

## Summary of non-native gaps

The only manifest in-scope items that are **not** structured-native in scapy
2.7.0 and whose oracle cases must therefore avoid claiming structured scapy
support:

| Item | Manifest scope | Why not native | Oracle action |
| --- | --- | --- | --- |
| ADD-PATH capability (69) | yes | no dedicated layer; raw `cap_data` only | mark `unsupported` for structured scapy assert, or supply bytes |
| Enhanced Route Refresh cap (70) | preserve only | generic raw container | raw round-trip only |
| Prestandard Route Refresh cap (128) | preserve only | generic raw container | raw round-trip only |
| Ext-community sub-type values (type 16) | out of scope | item kept as raw 8 octets | assert raw bytes, not scapy sub-type fields |
| AS_PATH/AGGREGATOR 4-octet ASN | yes | depends on global `use_2_bytes_asn` | set ASN-width switch per case before asserting |
| NOTIFICATION codes 8, 9 | (newer than scapy table) | byte encodes, no label | byte-level only |

Everything else in the BGP-4 manifest is **scapy-native** in the pinned oracle
environment and may be claimed `supported`.
