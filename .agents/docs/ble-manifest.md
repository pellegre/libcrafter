# BLE Advertising Wire Manifest

Source-backed wire facts for the `crafter` BLE advertising layer. Later code,
fixtures, oracle specs, and pcap handling should cite this manifest for the
BLE advertising facts below instead of relying on model memory.

## Advertising Physical Channel PDU

| Fact | Citation |
| --- | --- |
| An advertising physical channel PDU is a 16-bit header followed by a variable-size payload. | Bluetooth Core Specification v5.4, Vol 6, Part B, Section 2.3, Figures 2.4 and 2.5. |
| The header contains PDU Type in bits 0-3, then RFU, ChSel, TxAdd, RxAdd, and an 8-bit Length field. | Bluetooth Core Specification v5.4, Vol 6, Part B, Section 2.3, Figure 2.5 and Table 2.3. |
| The Length field records the payload length in octets. | Bluetooth Core Specification v5.4, Vol 6, Part B, Section 2.3. |
| ADV_IND, ADV_NONCONN_IND, and ADV_SCAN_IND payloads contain AdvA followed by AdvData. ADV_DIRECT_IND contains AdvA followed by TargetA. | Bluetooth Core Specification v5.4, Vol 6, Part B, Sections 2.3.1.1 through 2.3.1.4. |
| Legacy advertising AdvData is 0 to 31 octets. | Bluetooth Core Specification v5.4, Vol 6, Part B, Sections 2.3.1.1, 2.3.1.3, and 2.3.1.4, Figures 2.6, 2.8, and 2.9. |

## Access Address

| Fact | Citation |
| --- | --- |
| Advertising physical channel packets other than periodic-advertising exceptions use the access address `0x8E89BED6`. | Bluetooth Core Specification v5.4, Vol 6, Part B, Section 2.1.2. |
| Data-channel access addresses are generated per connection and are distinct from the advertising access address. | Bluetooth Core Specification v5.4, Vol 6, Part B, Section 2.1.2. |

## CRC

| Fact | Citation |
| --- | --- |
| The Link Layer CRC is a 24-bit CRC calculated over the PDU. | Bluetooth Core Specification v5.4, Vol 6, Part B, Sections 2.1.4 and 3.1.1. |
| The CRC polynomial is `x^24 + x^10 + x^9 + x^6 + x^4 + x^3 + x + 1`. | Bluetooth Core Specification v5.4, Vol 6, Part B, Section 3.1.1. |
| Non-periodic Advertising Physical Channel PDUs use advertising CRCInit `0x555555`. | Bluetooth Core Specification v5.4, Vol 6, Part B, Section 3.1.1. |

## Data Whitening

| Fact | Citation |
| --- | --- |
| Whitening applies to the PDU and CRC of Link Layer packets; the preamble and access address are not whitened. | Bluetooth Core Specification v5.4, Vol 6, Part B, Section 3.2. |
| The whitening LFSR is 7 bits with polynomial `x^7 + x^4 + 1`. | Bluetooth Core Specification v5.4, Vol 6, Part B, Section 3.2. |
| The whitening seed is derived from the physical channel index: position 0 is set to one, and positions 1 through 6 are set from the channel index. | Bluetooth Core Specification v5.4, Vol 6, Part B, Section 3.2. |

## Advertising Channels

| Fact | Citation |
| --- | --- |
| BLE has primary advertising channel indices 37, 38, and 39. | Bluetooth Core Specification v5.4, Vol 6, Part A, Physical Layer Specification; Vol 6, Part B, Section 1.4.1. |
| The primary advertising channel center frequencies are channel 37 at 2402 MHz, channel 38 at 2426 MHz, and channel 39 at 2480 MHz. | Bluetooth Core Specification v5.4, Vol 6, Part A, Physical Layer Specification; Vol 6, Part B, Section 1.4.1, Table 1.3. |

## GAP Advertising Data

| Fact | Citation |
| --- | --- |
| Advertising data is a sequence of AD structures. | Bluetooth Core Specification v5.4, Vol 3, Part C, Section 11. |
| Each AD structure is encoded as `Length`, `AD Type`, and `AD Data`; the length covers the AD Type and AD Data octets, not the length octet itself. | Bluetooth Core Specification v5.4, Vol 3, Part C, Section 11. |
| AD Type numeric values are assigned by the Bluetooth SIG Assigned Numbers. | Bluetooth Core Specification v5.4, Vol 3, Part C, Section 11; Bluetooth SIG Assigned Numbers, Generic Access Profile data types. |

## Pcap Link Type

| Fact | Citation |
| --- | --- |
| The pcap link type for Bluetooth Low Energy Link Layer with pseudo-header is `LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR`. | tcpdump.org Link-Layer Header Types registry. |
| `LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR` has numeric value 256. | tcpdump.org Link-Layer Header Types registry. |
| This link type prepends a radio pseudo-header before the Bluetooth Low Energy Link Layer payload. | tcpdump.org `LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR` link-layer header type description. |

## Sources

- Bluetooth Core Specification v5.4, Vol 6, Part A, Physical Layer Specification; Vol 6, Part B, Link Layer Specification; Vol 3, Part C, Generic Access Profile: <https://www.bluetooth.com/specifications/specs/core-specification-5-4/>
- Bluetooth Core Specification v5.4 HTML, Vol 6, Part B, Link Layer Specification: <https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/low-energy-controller/link-layer-specification.html>
- Bluetooth Core Specification v5.4 HTML, Vol 6, Part A, Physical Layer Specification: <https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/low-energy-controller/physical-layer-specification.html>
- Bluetooth Core Specification v5.4 HTML, Vol 3, Part C, Generic Access Profile: <https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host/generic-access-profile.html>
- Bluetooth SIG Assigned Numbers: <https://www.bluetooth.com/specifications/assigned-numbers/>
- Bluetooth SIG Assigned Numbers, Generic Access Profile data types: <https://www.bluetooth.com/specifications/assigned-numbers/generic-access-profile/>
- tcpdump.org Link-Layer Header Types registry: <https://www.tcpdump.org/linktypes.html>
- tcpdump.org `LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR` header type page: <https://www.tcpdump.org/linktypes/LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR.html>
