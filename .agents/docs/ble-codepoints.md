# BLE Advertising Codepoint Authority Table

Compact, code-facing authority for the `crafter` BLE advertising layer. This
table is the source later Rust constants, enums, fixtures, and oracle specs
copy from. Names are SCREAMING_SNAKE_CASE so they transfer unchanged into Rust.

Every value here is derived from and must match [`ble-manifest.md`](ble-manifest.md).
The manifest carries the broader wire evidence; this file is the condensed
codepoint contract. On any disagreement, this table is corrected to the
manifest and the cited primary source, never the reverse.

## Advertising PDU Types (Core Vol 6, Part B, Section 2.3)

The advertising physical channel PDU header uses bits 0 through 3 as the PDU
Type field. This phase models legacy primary-advertising PDUs plus the primary
request/response PDUs needed to parse advertising-channel traffic. Extended
advertising PDUs, including `ADV_EXT_IND` and auxiliary PDUs, are out of scope
for this phase and should be preserved or rejected according to the later
decoder contract rather than modeled as full typed builders.

| Name | Value | Scope | Source |
| --- | ---: | --- | --- |
| `ADV_IND` | `0x0` | Connectable and scannable undirected legacy advertising PDU. | Bluetooth Core Specification v5.4, Vol 6, Part B, Section 2.3, Table 2.3; Section 2.3.1.1. |
| `ADV_DIRECT_IND` | `0x1` | Connectable directed legacy advertising PDU. | Bluetooth Core Specification v5.4, Vol 6, Part B, Section 2.3, Table 2.3; Section 2.3.1.2. |
| `ADV_NONCONN_IND` | `0x2` | Non-connectable and non-scannable undirected legacy advertising PDU. | Bluetooth Core Specification v5.4, Vol 6, Part B, Section 2.3, Table 2.3; Section 2.3.1.3. |
| `SCAN_REQ` | `0x3` | Primary advertising scan request PDU. | Bluetooth Core Specification v5.4, Vol 6, Part B, Section 2.3, Table 2.3; Section 2.3.2. |
| `SCAN_RSP` | `0x4` | Primary advertising scan response PDU. | Bluetooth Core Specification v5.4, Vol 6, Part B, Section 2.3, Table 2.3; Section 2.3.2. |
| `CONNECT_IND` | `0x5` | Primary advertising connection request PDU. | Bluetooth Core Specification v5.4, Vol 6, Part B, Section 2.3, Table 2.3; Section 2.3.3. |
| `ADV_SCAN_IND` | `0x6` | Scannable undirected legacy advertising PDU. | Bluetooth Core Specification v5.4, Vol 6, Part B, Section 2.3, Table 2.3; Section 2.3.1.4. |

## Advertising Header Bits (Core Vol 6, Part B, Section 2.3)

| Name | Bit | Mask | Meaning | Source |
| --- | ---: | ---: | --- | --- |
| `PDU_TYPE` | `0..=3` | `0x0F` | Advertising physical channel PDU type. | Bluetooth Core Specification v5.4, Vol 6, Part B, Section 2.3, Figure 2.5 and Table 2.3. |
| `RFU` | `4` | `0x10` | Reserved for future use in the legacy advertising header shape. | Bluetooth Core Specification v5.4, Vol 6, Part B, Section 2.3, Figure 2.5. |
| `CH_SEL` | `5` | `0x20` | Channel Selection Algorithm #2 indication where that field is defined by the PDU type. | Bluetooth Core Specification v5.4, Vol 6, Part B, Sections 2.3 and 2.3.1.1. |
| `TX_ADD` | `6` | `0x40` | Transmitter address type where that field is defined: `0` = public device address, `1` = random device address. | Bluetooth Core Specification v5.4, Vol 6, Part B, Sections 2.3.1.1 through 2.3.1.4. |
| `RX_ADD` | `7` | `0x80` | Receiver or target address type where that field is defined: `0` = public device address, `1` = random device address. | Bluetooth Core Specification v5.4, Vol 6, Part B, Sections 2.3 and 2.3.1.2. |

If `CH_SEL`, `TX_ADD`, or `RX_ADD` is not defined for a given PDU type, the
Bluetooth Core Specification treats that field as reserved for future use for
that PDU.

## GAP AD Types (Assigned Numbers, Common Data Types)

AD type values are assigned by the Bluetooth SIG Assigned Numbers "Generic
Access Profile / Common Data Types" registry. AD structures themselves are
encoded by the Core GAP rules as `Length | AD Type | AD Data`; the length
includes the AD Type octet and AD Data octets, but not the Length octet.

| Name | Value | AD data shape for this phase | Source |
| --- | ---: | --- | --- |
| `AD_FLAGS` | `0x01` | Flags bitfield. | Bluetooth SIG Assigned Numbers, Generic Access Profile / Common Data Types; Core Spec v5.4, Vol 3, Part C, Section 11; CSS v11 Part A, Section 1.3. |
| `AD_INCOMPLETE_16_BIT_SERVICE_UUIDS` | `0x02` | Incomplete list of 16-bit Service UUIDs. | Bluetooth SIG Assigned Numbers, Generic Access Profile / Common Data Types; CSS v11 Part A, Section 1.1. |
| `AD_COMPLETE_16_BIT_SERVICE_UUIDS` | `0x03` | Complete list of 16-bit Service UUIDs. | Bluetooth SIG Assigned Numbers, Generic Access Profile / Common Data Types; CSS v11 Part A, Section 1.1. |
| `AD_INCOMPLETE_32_BIT_SERVICE_UUIDS` | `0x04` | Incomplete list of 32-bit Service UUIDs. | Bluetooth SIG Assigned Numbers, Generic Access Profile / Common Data Types; CSS v11 Part A, Section 1.1. |
| `AD_COMPLETE_32_BIT_SERVICE_UUIDS` | `0x05` | Complete list of 32-bit Service UUIDs. | Bluetooth SIG Assigned Numbers, Generic Access Profile / Common Data Types; CSS v11 Part A, Section 1.1. |
| `AD_INCOMPLETE_128_BIT_SERVICE_UUIDS` | `0x06` | Incomplete list of 128-bit Service UUIDs. | Bluetooth SIG Assigned Numbers, Generic Access Profile / Common Data Types; CSS v11 Part A, Section 1.1. |
| `AD_COMPLETE_128_BIT_SERVICE_UUIDS` | `0x07` | Complete list of 128-bit Service UUIDs. | Bluetooth SIG Assigned Numbers, Generic Access Profile / Common Data Types; CSS v11 Part A, Section 1.1. |
| `AD_SHORTENED_LOCAL_NAME` | `0x08` | Shortened UTF-8 local name. | Bluetooth SIG Assigned Numbers, Generic Access Profile / Common Data Types; CSS v11 Part A, Section 1.2. |
| `AD_COMPLETE_LOCAL_NAME` | `0x09` | Complete UTF-8 local name. | Bluetooth SIG Assigned Numbers, Generic Access Profile / Common Data Types; CSS v11 Part A, Section 1.2. |
| `AD_TX_POWER_LEVEL` | `0x0A` | Signed 8-bit TX power level in dBm. | Bluetooth SIG Assigned Numbers, Generic Access Profile / Common Data Types; CSS v11 Part A, Section 1.5. |
| `AD_SERVICE_DATA_16_BIT_UUID` | `0x16` | 16-bit Service UUID followed by service data. | Bluetooth SIG Assigned Numbers, Generic Access Profile / Common Data Types; CSS v11 Part A, Section 1.11. |
| `AD_APPEARANCE` | `0x19` | 16-bit Appearance value. | Bluetooth SIG Assigned Numbers, Generic Access Profile / Common Data Types; CSS v11 Part A, Section 1.12. |
| `AD_SERVICE_DATA_32_BIT_UUID` | `0x20` | 32-bit Service UUID followed by service data. | Bluetooth SIG Assigned Numbers, Generic Access Profile / Common Data Types; CSS v11 Part A, Section 1.11. |
| `AD_SERVICE_DATA_128_BIT_UUID` | `0x21` | 128-bit Service UUID followed by service data. | Bluetooth SIG Assigned Numbers, Generic Access Profile / Common Data Types; CSS v11 Part A, Section 1.11. |
| `AD_MANUFACTURER_SPECIFIC_DATA` | `0xFF` | 16-bit Company Identifier Code followed by manufacturer-defined bytes. | Bluetooth SIG Assigned Numbers, Generic Access Profile / Common Data Types and Company Identifiers; CSS v11 Part A, Section 1.4. |

Company identifiers, 16-bit UUIDs, 32-bit UUIDs, 128-bit UUIDs, and Appearance
subregistries are large assigned-number registries. This file references those
registries by AD type and does not duplicate their entries.

## Flags AD Bitfield (CSS v11 Part A, Section 1.3)

The Flags AD structure carries a variable-length boolean bitfield. This phase
names the common LE discovery bits below and preserves other flag bits when
round-tripping raw values.

| Name | Bit | Mask | Meaning | Source |
| --- | ---: | ---: | --- | --- |
| `FLAG_LE_LIMITED_DISCOVERABLE` | `0` | `0x01` | LE Limited Discoverable Mode. | Supplement to the Bluetooth Core Specification v11, Part A, Section 1.3, Table 1.4. |
| `FLAG_LE_GENERAL_DISCOVERABLE` | `1` | `0x02` | LE General Discoverable Mode. | Supplement to the Bluetooth Core Specification v11, Part A, Section 1.3, Table 1.4. |
| `FLAG_BR_EDR_NOT_SUPPORTED` | `2` | `0x04` | BR/EDR Not Supported. | Supplement to the Bluetooth Core Specification v11, Part A, Section 1.3, Table 1.4. |

## Sources

- Bluetooth Core Specification v5.4, Vol 6, Part B, Link Layer Specification,
  Section 2.3, Figures 2.4 and 2.5, Table 2.3, Sections 2.3.1 through 2.3.3:
  <https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/low-energy-controller/link-layer-specification.html>
- Bluetooth Core Specification v5.4, Vol 3, Part C, Generic Access Profile,
  Section 11, Advertising and Scan Response Data Format:
  <https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host/generic-access-profile.html>
- Supplement to the Bluetooth Core Specification v11, Part A, Data Types
  Specification, Sections 1.1 through 1.5, 1.11, and 1.12:
  <https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/CSS_v11/out/en/supplement-to-the-bluetooth-core-specification/data-types-specification.html>
- Bluetooth SIG Assigned Numbers Document, Generic Access Profile / Common Data
  Types and Company Identifiers, Version Date 2026-06-18:
  <https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Assigned_Numbers/out/en/Assigned_Numbers.pdf>
- Bluetooth SIG Assigned Numbers landing page and public YAML repository:
  <https://www.bluetooth.com/specifications/assigned-numbers/>
