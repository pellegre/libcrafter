# IEEE 802.15.4 + Zigbee Codepoint Authority Table

Compact, code-facing authority for the `crafter` IEEE 802.15.4 MAC, Zigbee NWK,
and Zigbee APS layers. This table is the source later Rust constants, enums,
fixtures, and oracle specs copy from. Names are SCREAMING_SNAKE_CASE so they
transfer unchanged into Rust.

Every value here is derived from and must match the wire evidence in
[`dot15d4-manifest.md`](dot15d4-manifest.md) (802.15.4 MAC) and
[`zigbee-manifest.md`](zigbee-manifest.md) (Zigbee NWK/APS). Those manifests
carry the broader wire evidence; this file is the condensed codepoint contract.
On any disagreement, this table is corrected to the manifest and the cited
primary source, never the reverse.

## 802.15.4 MAC Frame Types (IEEE Std 802.15.4-2020, Clause 7.2.2.1)

The Frame Type sub-field occupies bits 0-2 of the 16-bit MAC Frame Control
field. The values below are the frame types this crate models; reserved and
extended values are preserved by the decoder rather than modeled as typed
builders.

| Name | Value | Scope | Source |
| --- | ---: | --- | --- |
| `FRAME_TYPE_BEACON` | `0b000` (0) | Beacon frame. | IEEE Std 802.15.4-2020, Clause 7.2.2.1, Table 7-1 (Frame Type field values). |
| `FRAME_TYPE_DATA` | `0b001` (1) | Data frame. | IEEE Std 802.15.4-2020, Clause 7.2.2.1, Table 7-1. |
| `FRAME_TYPE_ACK` | `0b010` (2) | Acknowledgment frame. | IEEE Std 802.15.4-2020, Clause 7.2.2.1, Table 7-1. |
| `FRAME_TYPE_MAC_COMMAND` | `0b011` (3) | MAC command frame. | IEEE Std 802.15.4-2020, Clause 7.2.2.1, Table 7-1. |
| `FRAME_TYPE_RESERVED_4` | `0b100` (4) | Reserved (used by Multipurpose / extended frame versions). | IEEE Std 802.15.4-2020, Clause 7.2.2.1, Table 7-1 (reserved/extended values). |
| `FRAME_TYPE_MULTIPURPOSE` | `0b101` (5) | Multipurpose frame (extended frame versions). | IEEE Std 802.15.4-2020, Clause 7.2.2.1, Table 7-1. |
| `FRAME_TYPE_FRAGMENT` | `0b110` (6) | Fragment or Frak frame (extended frame versions). | IEEE Std 802.15.4-2020, Clause 7.2.2.1, Table 7-1. |
| `FRAME_TYPE_EXTENDED` | `0b111` (7) | Extended frame. | IEEE Std 802.15.4-2020, Clause 7.2.2.1, Table 7-1. |

Frame types 4-7 are not modeled as typed builders in this phase; the decoder
preserves their payload as raw rather than failing (see `dot15d4-manifest.md`).

## 802.15.4 Addressing Modes (IEEE Std 802.15.4-2020, Clause 7.2.2.8 / 7.2.2.10)

Both the Destination Addressing Mode (Frame Control bits 10-11) and the Source
Addressing Mode (Frame Control bits 14-15) are 2-bit fields that take the same
value set. The mode determines whether a PAN ID and an address field are
present and, if so, the address width.

| Name | Value | Meaning | Source |
| --- | ---: | --- | --- |
| `ADDR_MODE_NONE` | `0b00` (0) | PAN identifier and address fields are not present. | IEEE Std 802.15.4-2020, Clause 7.2.2.8 / 7.2.2.10, Table 7-3. |
| `ADDR_MODE_RESERVED` | `0b01` (1) | Reserved. | IEEE Std 802.15.4-2020, Clause 7.2.2.8 / 7.2.2.10, Table 7-3. |
| `ADDR_MODE_SHORT` | `0b10` (2) | Short address present (16-bit / 2-octet address). | IEEE Std 802.15.4-2020, Clause 7.2.2.8 / 7.2.2.10, Table 7-3. |
| `ADDR_MODE_EXTENDED` | `0b11` (3) | Extended address present (64-bit / 8-octet IEEE address). | IEEE Std 802.15.4-2020, Clause 7.2.2.8 / 7.2.2.10, Table 7-3. |

When present, a PAN ID field is 16 bits (2 octets), a short address is 2 octets,
and an extended address is 8 octets (`dot15d4-manifest.md`, Addressing Modes).

## 802.15.4 Frame Version (IEEE Std 802.15.4-2020, Clause 7.2.2.9)

The Frame Version sub-field occupies bits 12-13 of the MAC Frame Control field.

| Name | Value | Meaning | Source |
| --- | ---: | --- | --- |
| `FRAME_VERSION_2003` | `0b00` (0) | IEEE Std 802.15.4-2003 frames. | IEEE Std 802.15.4-2020, Clause 7.2.2.9, Table 7-4 (Frame Version field values). |
| `FRAME_VERSION_2006` | `0b01` (1) | IEEE Std 802.15.4-2006 frames. | IEEE Std 802.15.4-2020, Clause 7.2.2.9, Table 7-4. |
| `FRAME_VERSION_2015` | `0b10` (2) | IEEE Std 802.15.4-2015 (and later) frames. | IEEE Std 802.15.4-2020, Clause 7.2.2.9, Table 7-4. |
| `FRAME_VERSION_RESERVED` | `0b11` (3) | Reserved. | IEEE Std 802.15.4-2020, Clause 7.2.2.9, Table 7-4. |

## 802.15.4 MAC Command Frame Identifiers (IEEE Std 802.15.4-2020, Clause 7.5.1)

A MAC command frame (`FRAME_TYPE_MAC_COMMAND`) carries a 1-octet Command Frame
Identifier as the first byte of its MAC payload. The common identifiers below
are the ones a sniffing/injection workflow most often needs; unmodeled command
identifiers are preserved as raw payload by the decoder.

| Name | Value | Meaning | Source |
| --- | ---: | --- | --- |
| `MAC_CMD_ASSOCIATION_REQUEST` | `0x01` | Association Request command. | IEEE Std 802.15.4-2020, Clause 7.5.1, Table 7-49 (Command Frame Identifiers). |
| `MAC_CMD_ASSOCIATION_RESPONSE` | `0x02` | Association Response command. | IEEE Std 802.15.4-2020, Clause 7.5.1, Table 7-49. |
| `MAC_CMD_DISASSOCIATION_NOTIFICATION` | `0x03` | Disassociation Notification command. | IEEE Std 802.15.4-2020, Clause 7.5.1, Table 7-49. |
| `MAC_CMD_DATA_REQUEST` | `0x04` | Data Request command. | IEEE Std 802.15.4-2020, Clause 7.5.1, Table 7-49. |
| `MAC_CMD_PAN_ID_CONFLICT_NOTIFICATION` | `0x05` | PAN ID Conflict Notification command. | IEEE Std 802.15.4-2020, Clause 7.5.1, Table 7-49. |
| `MAC_CMD_ORPHAN_NOTIFICATION` | `0x06` | Orphan Notification command. | IEEE Std 802.15.4-2020, Clause 7.5.1, Table 7-49. |
| `MAC_CMD_BEACON_REQUEST` | `0x07` | Beacon Request command. | IEEE Std 802.15.4-2020, Clause 7.5.1, Table 7-49. |
| `MAC_CMD_COORDINATOR_REALIGNMENT` | `0x08` | Coordinator Realignment command. | IEEE Std 802.15.4-2020, Clause 7.5.1, Table 7-49. |
| `MAC_CMD_GTS_REQUEST` | `0x09` | GTS Request command. | IEEE Std 802.15.4-2020, Clause 7.5.1, Table 7-49. |

Command identifiers 0x0a and above (including TSCH and enhanced-beacon
commands) are out of scope for this phase and are preserved as raw payload.

## Zigbee NWK Frame Types (Zigbee Specification R23, Section 3.3.1.1.1)

The NWK Frame Type sub-field occupies bits 0-1 of the 16-bit NWK Frame Control
field.

| Name | Value | Meaning | Source |
| --- | ---: | --- | --- |
| `NWK_FRAME_TYPE_DATA` | `0b00` (0) | NWK data frame. | Zigbee Specification R23 (05-3474-23), Section 3.3.1.1.1, Table 3-48 (Values of the Frame Type Sub-Field). |
| `NWK_FRAME_TYPE_COMMAND` | `0b01` (1) | NWK command frame. | Zigbee Specification R23, Section 3.3.1.1.1, Table 3-48. |
| `NWK_FRAME_TYPE_RESERVED` | `0b10` (2) | Reserved. | Zigbee Specification R23, Section 3.3.1.1.1, Table 3-48. |
| `NWK_FRAME_TYPE_INTER_PAN` | `0b11` (3) | Inter-PAN frame. | Zigbee Specification R23, Section 3.3.1.1.1, Table 3-48. |

## Zigbee NWK Protocol Version (Zigbee Specification R23, Section 3.3.1.1.2)

The Protocol Version sub-field occupies bits 2-5 (4 bits) of the NWK Frame
Control field.

| Name | Value | Meaning | Source |
| --- | ---: | --- | --- |
| `NWK_PROTOCOL_VERSION` | `0x02` | `nwkcProtocolVersion`; the version used to recognize a Zigbee PRO NWK frame (allowed range 0x00-0x0f). | Zigbee Specification R23, Section 3.3.1.1.2 (`nwkcProtocolVersion` = 0x02, range 0x00-0x0f). |

## Zigbee NWK Discover Route (Zigbee Specification R23, Section 3.3.1.1.3)

The Discover Route sub-field occupies bits 6-7 (2 bits) of the NWK Frame
Control field.

| Name | Value | Meaning | Source |
| --- | ---: | --- | --- |
| `NWK_DISCOVER_ROUTE_SUPPRESS` | `0x00` | Suppress route discovery. | Zigbee Specification R23, Section 3.3.1.1.3, Table 3-49 (Values of the Discover Route Sub-Field). |
| `NWK_DISCOVER_ROUTE_ENABLE` | `0x01` | Enable route discovery. | Zigbee Specification R23, Section 3.3.1.1.3, Table 3-49. |
| `NWK_DISCOVER_ROUTE_RESERVED_2` | `0x02` | Reserved. | Zigbee Specification R23, Section 3.3.1.1.3, Table 3-49. |
| `NWK_DISCOVER_ROUTE_RESERVED_3` | `0x03` | Reserved. | Zigbee Specification R23, Section 3.3.1.1.3, Table 3-49. |

## Zigbee APS Frame Types (Zigbee Specification R23, Section 2.2.5.1.1.1)

The APS Frame Type sub-field occupies bits 0-1 of the 8-bit APS Frame Control
field.

| Name | Value | Meaning | Source |
| --- | ---: | --- | --- |
| `APS_FRAME_TYPE_DATA` | `0b00` (0) | APS data frame. | Zigbee Specification R23 (05-3474-23), Section 2.2.5.1.1.1, Table 2-20 (Values of the Frame Type Sub-Field). |
| `APS_FRAME_TYPE_COMMAND` | `0b01` (1) | APS command frame. | Zigbee Specification R23, Section 2.2.5.1.1.1, Table 2-20. |
| `APS_FRAME_TYPE_ACKNOWLEDGEMENT` | `0b10` (2) | APS acknowledgement frame. | Zigbee Specification R23, Section 2.2.5.1.1.1, Table 2-20. |
| `APS_FRAME_TYPE_INTER_PAN` | `0b11` (3) | Inter-PAN APS frame. | Zigbee Specification R23, Section 2.2.5.1.1.1, Table 2-20. |

## Zigbee APS Delivery Modes (Zigbee Specification R23, Section 2.2.5.1.1.2)

The Delivery Mode sub-field occupies bits 2-3 of the 8-bit APS Frame Control
field.

| Name | Value | Meaning | Source |
| --- | ---: | --- | --- |
| `APS_DELIVERY_MODE_UNICAST` | `0b00` (0) | Normal unicast delivery. | Zigbee Specification R23, Section 2.2.5.1.1.2, Table 2-21 (Values of the Delivery Mode Sub-Field). |
| `APS_DELIVERY_MODE_RESERVED` | `0b01` (1) | Reserved. | Zigbee Specification R23, Section 2.2.5.1.1.2, Table 2-21. |
| `APS_DELIVERY_MODE_BROADCAST` | `0b10` (2) | Broadcast delivery. | Zigbee Specification R23, Section 2.2.5.1.1.2, Table 2-21. |
| `APS_DELIVERY_MODE_GROUP` | `0b11` (3) | Group addressing. | Zigbee Specification R23, Section 2.2.5.1.1.2, Table 2-21. |

## Sources

- IEEE Std 802.15.4-2020, IEEE Standard for Low-Rate Wireless Networks
  (Clause 7 MAC frame formats — frame types Clause 7.2.2.1 Table 7-1,
  addressing modes Clause 7.2.2.8 / 7.2.2.10 Table 7-3, frame version
  Clause 7.2.2.9 Table 7-4, MAC command identifiers Clause 7.5.1 Table 7-49):
  <https://standards.ieee.org/ieee/802.15.4/7029/>
- Zigbee Specification, Revision 23 (Connectivity Standards Alliance, Zigbee
  Document 05-3474-23, March 15, 2023) — NWK frame types/protocol
  version/discover route (Section 3.3.1.1), APS frame types/delivery modes
  (Section 2.2.5.1.1):
  <https://csa-iot.org/wp-content/uploads/2023/04/05-3474-23-csg-zigbee-specification-compressed.pdf>
- Connectivity Standards Alliance — Zigbee Specification download/request page:
  <https://csa-iot.org/developer-resource/specifications-download-request/>
