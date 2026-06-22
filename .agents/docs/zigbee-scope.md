# 802.15.4 + Zigbee scope boundary

This document bounds the IEEE 802.15.4 and Zigbee work for the `crafter` crate.
The crate remains a wire-level primitive: it builds, compiles, decodes,
summarizes, captures, and writes packet bytes, while higher-level Zigbee
workflows remain agent-built tools on top. It depends on the terminology fixed
in `dot15d4-manifest.md`, `zigbee-manifest.md`, `dot15d4-codepoints.md`, and
`whad-dot15d4-manifest.md`.

## In scope

The implementation covers 802.15.4 MAC framing, the Zigbee NWK/APS header
framing that rides on it, and the offline/live surfaces needed to exercise them:

| Feature | Scope |
| --- | --- |
| 802.15.4 MAC frame | `Dot15d4` build and decode for the MAC frame: Frame Control Field (frame type, flags, addressing modes, PAN ID compression, frame version), sequence number, short/extended addressing, dest/src PAN IDs and addresses, payload, and the 16-bit frame check sequence (FCS), including malformed-on-purpose overrides. |
| Radio descriptor | `Dot15d4Radio` pseudo-header fields (channel, RSSI, FCS validity/type, LQI) serialized as the IEEE 802.15.4 TAP pseudo-header and mapped to/from live-backend receive metadata. |
| Zigbee NWK header | `ZigbeeNwk` build and decode of the Network-layer header framing: NWK frame control, 16-bit dest/src addresses, radius, sequence number, optional extended addresses/source-route fields, and payload. |
| Zigbee APS header | `ZigbeeAps` build and decode of the Application Support sublayer header framing: APS frame control, delivery mode/ack flags, dest endpoint, cluster id, profile id, src endpoint, APS counter, and payload. |
| Link registration | `LinkType::Ieee802154` (bare MAC) and `LinkType::Ieee802154Tap` (TAP pseudo-header) as the public link types used by `Packet::decode_from_link` and registry dispatch. |
| pcap support | Read/write support for pcap DLT 195 (`LINKTYPE_IEEE802_15_4_WITHFCS`), DLT 230 (`LINKTYPE_IEEE802_15_4_NOFCS`), and DLT 283 (`LINKTYPE_IEEE802_15_4_TAP`), round-tripping through the existing pcap machinery. |
| WHAD live backend | A feature-gated `whad` backend that can sniff 802.15.4 frames on a selected channel and send/inject a crafted frame through a WHAD-compatible dongle, reusing the existing WHAD discovery, transport, and framing. |
| Validation | Offline oracle specs (reference-backend cross-check), committed pcap fixtures, and non-committed `.scratch` live smoke tests against the dongle. |

The `Dot15d4Radio` pseudo-header, the `Dot15d4` MAC frame, and the `ZigbeeNwk`
and `ZigbeeAps` layers must compose as normal `Packet` layers and preserve the
project's override rule: caller-set fields are emitted unchanged, even when
intentionally invalid.

## Out of scope

These items are outside this plan and must not be pulled into the crate as part
of the 802.15.4/Zigbee effort:

| Excluded item | Why excluded |
| --- | --- |
| Zigbee routing and route discovery | Routing, route discovery, and route tables are stack behavior beyond the header-framing primitive surface. |
| NWK/APS/link/network key management, security, and decryption | Key management, frame-security processing, and decryption require protocol state and security workflows beyond the packet primitive. |
| Association and commissioning state machines | Association, joining, and commissioning are stateful stack workflows, not packet framing. |
| Full ZCL attribute/command set | Only the cluster/profile/endpoint header fields are modeled; the complete Zigbee Cluster Library attribute and command set is not. |
| Touchlink | Touchlink commissioning is a higher-level workflow built on the sniff/inject primitives, not a crate feature. |
| WHAD `Jam`, `EnergyDetection`, and `ManInTheMiddle` commands | The backend exposes sniff and send/inject only; jamming, energy detection, and MITM are out of scope. |
| Energy-detection scans | Channel energy-detection scans are not part of the sniff/inject surface. |
| Non-802.15.4 radio | BLE, Bluetooth Classic, sub-GHz/SDR, and any other radio are outside this plan. |

Out-of-scope attacks and workflows — touchlink, network-key extraction, jamming,
MITM, routing manipulation, and similar — are generated tools a developer's
agent builds on top of the sniff/inject and build/decode primitives, not crate
features.

## Naming rule

802.15.4 and Zigbee public types use family-explicit prefixes: `Dot15d4` and
`Dot15d4Radio` for the IEEE 802.15.4 MAC and radio descriptor, and `ZigbeeNwk`
and `ZigbeeAps` for the Zigbee Network and Application Support layers. This keeps
the families distinct and leaves room for future radio families without
collision, matching the project's convention of keeping protocol families
distinct (as with `Ble*` naming and ICMP v4/v6 naming).

## Two-surface rule

Offline build, decode, pcap read/write, fixtures, and oracle checks are the
default committed surface and must remain hardware-free; the default crate build
stays dependency-identical. Live sniff and transmit are explicit opt-in behind
the existing `whad` feature; without that opt-in the backend produces a send
plan and does not transmit.

Live dongle behavior is validated only with non-committed `.scratch` smoke
harnesses and disposable artifacts. No live captures, device identifiers, or
hardware-specific host details from those runs belong in tracked files.
