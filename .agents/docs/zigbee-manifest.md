# Zigbee NWK/APS Wire Manifest

Source-backed wire facts for the `crafter` Zigbee Network (NWK) and Application
Support sublayer (APS) layers. Later code, fixtures, oracle specs, and decode
dispatch should cite this manifest for the Zigbee NWK/APS facts below instead
of relying on model memory. Zigbee is a Connectivity Standards Alliance (CSA,
formerly Zigbee Alliance) specification — not IEEE and not an RFC — so the
authoritative source is the official "Zigbee Specification", Revision 23
(Zigbee Document 05-3474-23, March 15, 2023). The NWK and APS sublayers ride on
top of the IEEE 802.15.4 MAC payload documented in `dot15d4-manifest.md`.

All clause/section, figure, and table references below are to Zigbee
Specification Revision 23 (05-3474-23) unless noted.

## NWK Frame Format and Header Field Order

| Fact | Citation |
| --- | --- |
| The NWK frame is composed of a NWK header followed by a NWK payload; the NWK header fields appear in a fixed order. | Section 3.3.1, General NPDU Frame Format. |
| The NWK header field order is: Frame Control (2 octets), Destination Address (2 octets), Source Address (2 octets), Radius (1 octet), Sequence Number (1 octet), Destination IEEE Address (0/8 octets), Source IEEE Address (0/8 octets), Source Route Subframe (variable), Frame Payload (variable). | Section 3.3.1, Figure 3-4 (General NWK Frame Format). |
| The Destination Address field is always present and is 2 octets, holding the 16-bit network (short) address or a broadcast address. | Section 3.3.1.2, Destination Address Field. |
| The Source Address field is always present and is always 2 octets, holding the 16-bit network address of the source. | Section 3.3.1.3, Source Address Field. |
| The Radius field is always present, is 1 octet, and is decremented by 1 by each receiving device. | Section 3.3.1.4, Radius Field. |
| The Sequence Number field is present in every frame and is 1 octet, incremented by 1 with each new frame transmitted. | Section 3.3.1.5, Sequence Number Field. |
| The Destination IEEE Address field, when present, is the 64-bit IEEE address corresponding to the destination short address; it SHALL NOT be present when the destination short address is a broadcast or multicast address. | Section 3.3.1.6, Destination IEEE Address Field. |
| The Source IEEE Address field, when present, is the 64-bit IEEE address corresponding to the source short address. | Section 3.3.1.7, Source IEEE Address Field. |

## NWK Frame Control Field (16 bits)

The NWK Frame Control field is 16 bits in length. Bit positions (LSB first):

| Fact | Citation |
| --- | --- |
| The Frame Control field is 16 bits and defines the frame type, addressing/sequencing fields, and other control flags. | Section 3.3.1.1, Frame Control Field. |
| Frame Type occupies bits 0-1. | Section 3.3.1.1, Figure 3-5; Section 3.3.1.1.1. |
| Protocol Version occupies bits 2-5 (4 bits). | Section 3.3.1.1, Figure 3-5; Section 3.3.1.1.2. |
| Discover Route occupies bits 6-7 (2 bits). | Section 3.3.1.1, Figure 3-5; Section 3.3.1.1.3. |
| Bit 8 is the deprecated Multicast flag. | Section 3.3.1.1, Figure 3-5 ("Deprecated (Multicast flag)"). |
| Security occupies bit 9. | Section 3.3.1.1, Figure 3-5; Section 3.3.1.1.4. |
| Source Route occupies bit 10 (1 = source route subframe present). | Section 3.3.1.1, Figure 3-5; Section 3.3.1.1.5. |
| Destination IEEE Address flag occupies bit 11 (1 = destination IEEE address included). | Section 3.3.1.1, Figure 3-5; Section 3.3.1.1.6. |
| Source IEEE Address flag occupies bit 12 (1 = source IEEE address included). | Section 3.3.1.1, Figure 3-5; Section 3.3.1.1.7. |
| End Device Initiator occupies bit 13. | Section 3.3.1.1, Figure 3-5; Section 3.3.1.1.8. |
| Bits 14-15 are Reserved. | Section 3.3.1.1, Figure 3-5. |

## NWK Frame Types, Discover Route, and Protocol Version Code Points

| Fact | Citation |
| --- | --- |
| NWK Frame Type 0b00 = Data. | Section 3.3.1.1.1, Table 3-48 (Values of the Frame Type Sub-Field). |
| NWK Frame Type 0b01 = NWK command. | Section 3.3.1.1.1, Table 3-48. |
| NWK Frame Type 0b10 = Reserved. | Section 3.3.1.1.1, Table 3-48. |
| NWK Frame Type 0b11 = Inter-PAN. | Section 3.3.1.1.1, Table 3-48. |
| The Protocol Version sub-field reflects the Zigbee NWK protocol version in use, exposed as the NWK constant `nwkcProtocolVersion`. | Section 3.3.1.1.2, Protocol Version Sub-Field. |
| `nwkcProtocolVersion` has the value 0x02 (the protocol version used to recognize a Zigbee PRO NWK frame); its allowed range is 0x00-0x0f. | Section 3.3.1.1.2; NIB constant table (`nwkcProtocolVersion` = 0x02, type Integer, range 0x00-0x0f). |
| Discover Route 0x00 = Suppress route discovery; 0x01 = Enable route discovery; 0x02-0x03 = Reserved. | Section 3.3.1.1.3, Table 3-49 (Values of the Discover Route Sub-Field). |

## NWK Source Route Subframe

| Fact | Citation |
| --- | --- |
| The Source Route Subframe is present only when the Source Route sub-field of the frame control is 1, and is laid out as Relay Count (1 octet), Relay Index (1 octet), Relay List (variable). | Section 3.3.1.8, Figure 3-6 (Source Route Subframe Format). |
| Relay Count is the number of relays in the Relay List; Relay Index is the index of the next relay; the Relay List holds the relay addresses, the relay closest to the destination listed first. | Sections 3.3.1.8.1, 3.3.1.8.2, 3.3.1.8.3. |

## NWK Frame Type Formats

| Fact | Citation |
| --- | --- |
| There are two defined NWK frame types — data and NWK command. | Section 3.3.2, Format of Individual Frame Types. |
| A NWK data frame is Frame Control (2 octets) + Routing fields (variable) + Data payload (variable), in general-frame order. | Section 3.3.2.1, Figure 3-7 (Data Frame Format). |
| A NWK command frame is Frame Control (2 octets) + Routing fields (variable) + NWK command identifier (1 octet) + NWK command payload (variable). | Section 3.3.2.2, Figure 3-8 (NWK Command Frame Format). |

## APS Frame Format and Header Field Order

| Fact | Citation |
| --- | --- |
| The APS frame is composed of an APS header and an APS payload; APS header fields appear in a fixed order, but the addressing fields may not be present in all frames. | Section 2.2.5.1, General APDU Frame Format. |
| The APS header field order is: Frame Control (1 octet), Destination Endpoint (0/1 octet), Group Address (0/2 octets), Cluster Identifier (0/2 octets), Profile Identifier (0/2 octets), Source Endpoint (0/1 octet), APS Counter (1 octet), Extended Header (0/variable), Frame Payload (variable). | Section 2.2.5.1, Figure 2-3 (General APS Frame Format). |
| The Destination Endpoint field is 8 bits and is present only when the delivery mode is 0b00 (unicast) or 0b10 (broadcast); 0x00 addresses the ZDO, 0x01-0xfe addresses an application endpoint, 0xff addresses all active endpoints. | Section 2.2.5.1.2, Destination Endpoint Field. |
| The Group Address field is 16 bits and is present only when the delivery mode sub-field is 0b11; in that case the Destination Endpoint SHALL NOT be present. | Section 2.2.5.1.3, Group Address Field. |
| The Cluster Identifier field is 16 bits and is present only for data or acknowledgement frames. | Section 2.2.5.1.4, Cluster Identifier Field. |
| The Profile Identifier field is 2 octets and is present only for data or acknowledgement frames. | Section 2.2.5.1.5, Profile Identifier Field. |
| The Source Endpoint field is 8 bits; 0x00 indicates the ZDO, 0x01-0xfe indicates an application endpoint. | Section 2.2.5.1.6, Source Endpoint Field. |
| The APS Counter field is 8 bits and is incremented by one for each new transmission to prevent duplicate-frame reception. | Section 2.2.5.1.7, APS Counter. |

## APS Frame Control Field (8 bits)

The APS Frame Control field is 8 bits in length. Bit positions (LSB first):

| Fact | Citation |
| --- | --- |
| The Frame Control field is 8 bits and defines the frame type, addressing fields, and other control flags. | Section 2.2.5.1.1, Frame Control Field. |
| Frame Type occupies bits 0-1. | Section 2.2.5.1.1, Figure 2-4; Section 2.2.5.1.1.1. |
| Delivery Mode occupies bits 2-3. | Section 2.2.5.1.1, Figure 2-4; Section 2.2.5.1.1.2. |
| ACK Format occupies bit 4. | Section 2.2.5.1.1, Figure 2-4; Section 2.2.5.1.1.3. |
| Security occupies bit 5. | Section 2.2.5.1.1, Figure 2-4; Section 2.2.5.1.1.4. |
| ACK Request occupies bit 6. | Section 2.2.5.1.1, Figure 2-4; Section 2.2.5.1.1.5. |
| Extended Header Present occupies bit 7. | Section 2.2.5.1.1, Figure 2-4; Section 2.2.5.1.1.6. |

## APS Frame-Type, Delivery-Mode, and Sub-Field Code Points

| Fact | Citation |
| --- | --- |
| APS Frame Type 0b00 = Data. | Section 2.2.5.1.1.1, Table 2-20 (Values of the Frame Type Sub-Field). |
| APS Frame Type 0b01 = Command. | Section 2.2.5.1.1.1, Table 2-20. |
| APS Frame Type 0b10 = Acknowledgement. | Section 2.2.5.1.1.1, Table 2-20. |
| APS Frame Type 0b11 = Inter-PAN APS. | Section 2.2.5.1.1.1, Table 2-20. |
| APS Delivery Mode 0b00 = Normal unicast delivery; 0b01 = Reserved; 0b10 = Broadcast; 0b11 = Group addressing. | Section 2.2.5.1.1.2, Table 2-21 (Values of the Delivery Mode Sub-Field). |
| ACK Format = 0 for data-frame acknowledgement, 1 for APS command-frame acknowledgement; it controls whether the destination endpoint, cluster id, profile id, and source endpoint are present in the acknowledgement frame. | Section 2.2.5.1.1.3, ACK Format Field. |
| ACK Request = 1 requests an acknowledgement frame from the recipient; it SHALL be 0 for all broadcast or multicast frames. | Section 2.2.5.1.1.5, Acknowledgement Request Sub-Field. |
| Extended Header Present = 1 includes the extended header sub-frame in the frame. | Section 2.2.5.1.1.6, Extended Header Present. |

## APS Extended Header Sub-Frame

| Fact | Citation |
| --- | --- |
| When present, the Extended Header Sub-Frame is Extended Frame Control (1 octet) + Block Number (0/1 octet) + ACK Bitfield (0/1 octet). | Section 2.2.5.1.8, Figure 2-5 (Format of the Extended Header Sub-Frame). |
| The Extended Frame Control field is 8 bits with Fragmentation in bits 0-1 (00 = not fragmented, 01 = first fragment, 10 = subsequent fragment, 11 = reserved) and bits 2-7 reserved. | Section 2.2.5.1.8.1, Figure 2-6 and Table 2-22 (Values of the Fragmentation Sub-Field). |

## Recognizing a Zigbee NWK Frame Inside the 802.15.4 MAC Payload

| Fact | Citation |
| --- | --- |
| A Zigbee NWK frame rides as the payload of an IEEE 802.15.4 MAC data frame; the NWK header begins with the 16-bit NWK Frame Control field. | Section 3.3.1 (NWK header on the MAC payload); IEEE 802.15.4 MAC payload, see `dot15d4-manifest.md`. |
| A NWK data frame is recognized by Frame Type 0b00 (bits 0-1 of the NWK frame control) together with a Protocol Version of `nwkcProtocolVersion` = 0x02 (bits 2-5). | Sections 3.3.1.1.1 (Table 3-48), 3.3.1.1.2; `nwkcProtocolVersion` = 0x02. |
| The APS frame rides as the payload of the NWK frame; the APS header begins with the 8-bit APS Frame Control field whose frame type occupies bits 0-1. | Sections 2.2.5.1, 2.2.5.1.1.1 (Table 2-20). |

## Sources

- Zigbee Specification, Revision 23 (Connectivity Standards Alliance, Zigbee Document 05-3474-23, March 15, 2023) — Chapter 2 (APS sublayer, Section 2.2.5.1 General APS frame format) and Chapter 3 (NWK layer, Section 3.3.1 General NPDU frame format): <https://csa-iot.org/wp-content/uploads/2023/04/05-3474-23-csg-zigbee-specification-compressed.pdf>
- Connectivity Standards Alliance — Zigbee Specification download/request page: <https://csa-iot.org/developer-resource/specifications-download-request/>
