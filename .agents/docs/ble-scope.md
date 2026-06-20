# BLE scope boundary

This document bounds the Bluetooth Low Energy work for the `crafter` crate. The
crate remains a wire-level primitive: it builds, compiles, decodes, summarizes,
captures, and writes packet bytes, while higher-level Bluetooth workflows remain
agent-built tools on top.

## In scope

The BLE implementation covers advertising-channel packet primitives and the
offline/live transport surfaces needed to exercise them:

| Feature | Scope |
| --- | --- |
| Radio descriptor | `BleRadio` pseudo-header fields for channel, access address, PHY, whitening, CRC metadata, and receive-side metadata needed for pcap and live backends. |
| Advertising PDU | `BleLlAdv` construction and decode for BLE advertising-channel PDUs, including addressing flags, advertiser address fields, payload length, and malformed-on-purpose overrides. |
| GAP AD structures | Flags, local name, service UUIDs, manufacturer-specific data, TX power, service data, appearance, and raw/unknown AD structures carried inside advertising payloads. |
| Link registration | `LinkType::BluetoothLeLl` as the public link type used by `Packet::decode_from_link` and registry dispatch. |
| pcap support | Read/write support for pcap DLT 256, `DLT_BLUETOOTH_LE_LL_WITH_PHDR`, round-tripping through the existing pcap machinery. |
| WHAD live backend | A feature-gated `whad` backend that can inject crafted advertising PDUs and sniff advertising PDUs through a WHAD-compatible dongle. |

The first implementation phase is advertising-channel BLE only. The radio
descriptor plus advertising PDU plus GAP AD list must compose as normal
`Packet` layers and preserve the project's override rule: caller-set fields are
emitted unchanged, even when intentionally invalid.

## Out of scope

These items are outside this plan and must not be pulled into the crate as part
of the BLE advertising-channel effort:

| Excluded item | Why excluded |
| --- | --- |
| Bluetooth Classic / BR-EDR | The target nRF52840-class hardware cannot do Classic, and the plan is LE-only. |
| BLE data-channel PDUs | Data-channel packet families are a later phase after advertising support lands. |
| Connection establishment or following | Connection state, channel maps, hopping, and following belong to a future data-channel phase. |
| Hijacking, encryption, pairing | These require protocol state and security workflows beyond the packet primitive surface. |
| L2CAP, ATT, GATT, SMP | These are higher BLE stack layers and are deferred until the link-layer foundation exists. |
| Full WHAD command surface | The backend exposes raw inject and sniff only; it does not reimplement WHAD scan, central, peripheral, or MITM workflows. |
| Extended advertising PDUs | Legacy advertising-channel PDUs land first; extended advertising is deferred. |

## Naming rule

BLE-specific public types use the LE-explicit `Ble*` prefix, such as `BleRadio`
and `BleLlAdv`. This leaves room for a future Bluetooth Classic family to use
its own names without collision, matching the project's convention of keeping
IPv4 and IPv6 protocol families distinct, as with ICMP v4/v6 naming.

## Two-surface rule

Offline build, decode, pcap read/write, fixtures, and oracle checks are the
default committed surface and must remain hardware-free. Live transmit is
explicit opt-in behind the `whad` feature; without that opt-in the backend
produces a send plan and does not transmit.

Live dongle behavior is validated only with non-committed `.scratch` smoke
harnesses and disposable artifacts. No live captures, device identifiers, or
hardware-specific host details from those runs belong in tracked files.
