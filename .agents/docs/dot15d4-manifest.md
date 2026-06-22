# IEEE 802.15.4 MAC Wire Manifest

Source-backed wire facts for the `crafter` IEEE 802.15.4 MAC layer. Later code,
fixtures, oracle specs, and pcap handling should cite this manifest for the
802.15.4 MAC facts below instead of relying on model memory. 802.15.4 is an
IEEE standard, so the authoritative sources are IEEE Std 802.15.4-2020, the
tcpdump.org Link-Layer Header Types registry, and the IEEE 802.15.4 TAP
pseudo-header specification.

## MAC Frame Format

| Fact | Citation |
| --- | --- |
| The general MAC frame is laid out as MAC Header (MHR) followed by MAC Payload followed by MAC Footer (MFR). | IEEE Std 802.15.4-2020, Clause 7.2.1, General MAC frame format. |
| The MHR begins with a 16-bit (2-octet) Frame Control field, followed by a Sequence Number field, then the Addressing fields, then optional Auxiliary Security Header. | IEEE Std 802.15.4-2020, Clause 7.2.1, Figure 7-2 (General MAC frame format). |
| The Sequence Number field is 1 octet. | IEEE Std 802.15.4-2020, Clause 7.2.1 and Clause 7.2.3, Sequence Number field. |
| The MAC Payload field is variable length and carries the upper-layer payload. | IEEE Std 802.15.4-2020, Clause 7.2.1, MAC Payload field. |
| The MFR is the 2-octet Frame Check Sequence (FCS) and is the trailing field of the frame. | IEEE Std 802.15.4-2020, Clause 7.2.1 and Clause 7.2.10, FCS field. |
| Overall wire order is therefore: 16-bit Frame Control + 1-byte Sequence Number + variable Addressing fields + variable MAC Payload + 2-byte FCS. | IEEE Std 802.15.4-2020, Clause 7.2.1, Figure 7-2. |

## Frame Control Field (FCF)

The 16-bit Frame Control field bit layout (least-significant bit first within
the 2 octets):

| Fact | Citation |
| --- | --- |
| Frame Type occupies bits 0-2. | IEEE Std 802.15.4-2020, Clause 7.2.2.1, Frame Type field (Figure 7-3 / Table 7-1). |
| Security Enabled occupies bit 3. | IEEE Std 802.15.4-2020, Clause 7.2.2.2, Security Enabled field. |
| Frame Pending occupies bit 4. | IEEE Std 802.15.4-2020, Clause 7.2.2.3, Frame Pending field. |
| AR (Acknowledgment Request) occupies bit 5. | IEEE Std 802.15.4-2020, Clause 7.2.2.4, AR field. |
| PAN ID Compression occupies bit 6. | IEEE Std 802.15.4-2020, Clause 7.2.2.5, PAN ID Compression field. |
| Bits 7-8 are reserved / Sequence Number Suppression and IE Present (frame-version dependent). | IEEE Std 802.15.4-2020, Clause 7.2.2.6 and 7.2.2.7. |
| Destination Addressing Mode occupies bits 10-11. | IEEE Std 802.15.4-2020, Clause 7.2.2.8, Destination Addressing Mode field. |
| Frame Version occupies bits 12-13. | IEEE Std 802.15.4-2020, Clause 7.2.2.9, Frame Version field. |
| Source Addressing Mode occupies bits 14-15. | IEEE Std 802.15.4-2020, Clause 7.2.2.10, Source Addressing Mode field. |

## Addressing Modes

| Fact | Citation |
| --- | --- |
| Addressing Mode value 0b00 = PAN identifier and address fields are not present. | IEEE Std 802.15.4-2020, Clause 7.2.2.8 / 7.2.2.10, Table 7-3 (addressing-mode values). |
| Addressing Mode value 0b10 = short address present (16-bit / 2-octet address). | IEEE Std 802.15.4-2020, Clause 7.2.2.8 / 7.2.2.10, Table 7-3. |
| Addressing Mode value 0b11 = extended address present (64-bit / 8-octet IEEE address). | IEEE Std 802.15.4-2020, Clause 7.2.2.8 / 7.2.2.10, Table 7-3. |
| Addressing Mode value 0b01 is reserved. | IEEE Std 802.15.4-2020, Clause 7.2.2.8 / 7.2.2.10, Table 7-3. |
| When present, a PAN ID field is 16 bits (2 octets); a short address is 2 octets and an extended address is 8 octets. | IEEE Std 802.15.4-2020, Clause 7.2.4 through 7.2.8, Addressing fields. |
| The Addressing fields appear in the order: Destination PAN ID, Destination Address, Source PAN ID, Source Address, each present only as implied by the addressing-mode bits and PAN ID Compression. | IEEE Std 802.15.4-2020, Clause 7.2.1 and 7.2.4 through 7.2.8. |

## PAN ID Compression

| Fact | Citation |
| --- | --- |
| When PAN ID Compression is set and both destination and source addresses are present, the Source PAN ID is omitted and the source uses the destination PAN ID. | IEEE Std 802.15.4-2020, Clause 7.2.2.5, PAN ID Compression field, and Table 7-2 (PAN ID Compression field value for frame version 0b00/0b01). |
| The presence/absence of the Destination PAN ID, Source PAN ID, and the two address fields is fully determined by the destination/source addressing modes together with the PAN ID Compression bit (and Frame Version). | IEEE Std 802.15.4-2020, Clause 7.2.1.5 / Table 7-2, PAN ID Compression field value table. |

## Frame Check Sequence (FCS)

| Fact | Citation |
| --- | --- |
| The FCS is a 16-bit ITU-T CRC computed over the MAC header and MAC payload (the MHR and MAC Payload fields). | IEEE Std 802.15.4-2020, Clause 7.2.10, FCS field. |
| The 16-bit FCS generator polynomial is x^16 + x^12 + x^5 + 1 (the ITU-T / CRC-CCITT polynomial, 0x1021). | IEEE Std 802.15.4-2020, Clause 7.2.10, FCS generation. |
| The FCS is transmitted as the trailing 2 octets of the frame. | IEEE Std 802.15.4-2020, Clause 7.2.1 and 7.2.10. |

Note: the 16-bit FCS is the default; some revisions also define a 32-bit FCS
option, but the 2.4 GHz O-QPSK PHY frames this crate targets use the 16-bit
FCS.

## Channels (2.4 GHz O-QPSK PHY)

| Fact | Citation |
| --- | --- |
| The 2.4 GHz band defines channels numbered 11 through 26. | IEEE Std 802.15.4-2020, Clause 10.1.3.3 / 10.1.2, channel assignments (2450 MHz band, channel page 0). |
| The channel center frequency for channel k is Fc = 2405 + 5*(k - 11) MHz, for k = 11..26. | IEEE Std 802.15.4-2020, Clause 10.1.3.3, channel center-frequency equation. |
| Channel 11 = 2405 MHz, channel 12 = 2410 MHz, ..., channel 26 = 2480 MHz (5 MHz spacing). | IEEE Std 802.15.4-2020, Clause 10.1.3.3, channel center-frequency equation. |

## Pcap Link Types

| Fact | Citation |
| --- | --- |
| `LINKTYPE_IEEE802_15_4_WITHFCS` has numeric DLT value 195 and carries an IEEE 802.15.4 frame including its trailing FCS. | tcpdump.org Link-Layer Header Types registry. |
| `LINKTYPE_IEEE802_15_4_NOFCS` has numeric DLT value 230 and carries an IEEE 802.15.4 frame without the trailing FCS. | tcpdump.org Link-Layer Header Types registry. |
| `LINKTYPE_IEEE802_15_4_TAP` has numeric DLT value 283 and prepends a TLV pseudo-header before the IEEE 802.15.4 frame. | tcpdump.org Link-Layer Header Types registry. |

## TAP Pseudo-Header (DLT 283)

| Fact | Citation |
| --- | --- |
| The TAP pseudo-header begins with a fixed 4-octet header: version (uint8), reserved (uint8), and length (uint16, total length of the pseudo-header including the fixed header and all TLVs). | IEEE 802.15.4 TAP specification (Exegin), pseudo-header layout. |
| The fixed header is followed by zero or more TLV records; each TLV has a 16-bit type, a 16-bit length, and a value padded to a 32-bit boundary. | IEEE 802.15.4 TAP specification (Exegin), TLV structure. |
| TLV type 0 = FCS Type. | IEEE 802.15.4 TAP specification (Exegin), defined TLV types. |
| TLV type 1 = Received Signal Strength (RSSI). | IEEE 802.15.4 TAP specification (Exegin), defined TLV types. |
| TLV type 3 = Channel Assignment. | IEEE 802.15.4 TAP specification (Exegin), defined TLV types. |
| The TAP form lets a capture report FCS validity/type, RSSI, and channel as metadata separate from the 802.15.4 frame body. | IEEE 802.15.4 TAP specification (Exegin); tcpdump.org `LINKTYPE_IEEE802_15_4_TAP` description. |

## Sources

- IEEE Std 802.15.4-2020, IEEE Standard for Low-Rate Wireless Networks (Clause 7 MAC frame formats, Clause 10 PHY / channel assignments): <https://standards.ieee.org/ieee/802.15.4/7029/>
- tcpdump.org Link-Layer Header Types registry: <https://www.tcpdump.org/linktypes.html>
- tcpdump.org `LINKTYPE_IEEE802_15_4_TAP` header type page: <https://www.tcpdump.org/linktypes/LINKTYPE_IEEE802_15_4_TAP.html>
- IEEE 802.15.4 TAP pseudo-header specification (Exegin): <https://gitlab.com/exegin/ieee802-15-4-tap>
