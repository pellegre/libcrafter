# IEEE 802.15.4 / Zigbee Fixture Corpus

These fixtures are synthetic, deterministic IEEE 802.15.4 frames for offline
decode tests, mirroring the BLE fixture corpus in `../ble/`. Each `.hex` file
holds one full frame as raw hex octets (whitespace- and comment-tolerant, one
byte per two hex digits), and is decoded through the public
`Packet::decode_from_link` entrypoint by `crafter/tests/dot15d4_decode.rs`.

The bare-MAC fixtures decode via `LinkType::Ieee802154` (raw MAC bytes with a
trailing 2-octet Frame Check Sequence; no TAP radio pseudo-header). The
`decode_from_link` entrypoint auto-dispatches the Zigbee NWK/APS layers when a
MAC Data frame carries a Zigbee NWK Data payload.

All addresses, PAN identifiers, clusters, and profiles are lab-safe synthetic
values; none are captured from a real network.

## Derivation / provenance

The reference backend is not importable in this environment, so each frame's
bytes are hand-built by composing the crate's own builders (`Dot15d4` / `ZigbeeNwk` /
`ZigbeeAps` from `crafter::prelude::*`), compiling the packet, and recording the
compiled bytes. The field layout and the auto-filled CRC-16/CCITT Frame Check
Sequence are grounded in `.agents/docs/dot15d4-manifest.md`,
`.agents/docs/dot15d4-codepoints.md`, and `.agents/docs/zigbee-manifest.md`
(IEEE Std 802.15.4-2020, Clause 7.2, and the Zigbee NWK/APS frame formats). The
decode test re-derives the same field values, so the fixtures lock the wire
contract round-trip (compile -> bytes -> decode -> fields).

## Fixtures

- `mac-data-short.hex`: 802.15.4 Data frame, short (16-bit) addressing, PAN-ID
  compression (both addresses share PAN `0x1234`, so the source PAN ID is
  omitted on the wire). Sequence number `0x2a`, destination short address
  `0x0000`, source short address `0xABCD`, MAC payload `de ad be ef`, trailing
  auto-filled FCS.
- `mac-data-extended.hex`: 802.15.4 Data frame, extended (64-bit) addressing
  with PAN-ID compression. Sequence number `0x11`, shared PAN `0xABCD`,
  destination extended address `0x0011223344556677`, source extended address
  `0x8899AABBCCDDEEFF`, MAC payload `ca fe`, trailing auto-filled FCS.
- `zigbee-nwk-aps.hex`: full MAC / Zigbee NWK / Zigbee APS Data stack. MAC Data
  frame (short addressing, PAN `0x1234`, dest `0x0000`, src `0xABCD`, seq
  `0x07`) carrying a Zigbee NWK Data frame (dest `0x0000`, src `0xABCD`, radius
  `30`, NWK sequence `0x42`) carrying a Zigbee APS Data frame (cluster `0x0006`,
  profile `0x0104`, destination endpoint `1`, source endpoint `1`, APS counter
  `0x09`, payload `01 02`), with the trailing auto-filled MAC FCS.
