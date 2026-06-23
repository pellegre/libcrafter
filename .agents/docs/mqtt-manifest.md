# MQTT 3.1.1 Source Manifest

Source-backed evidence record for the initial `crafter` MQTT layer. Later
constants, builders, decoders, oracle specs, fixtures, and tests must cite this
manifest or the compact authority table in
[`mqtt-codepoints.md`](mqtt-codepoints.md), not model memory.

This baseline covers MQTT Version 3.1.1. MQTT Version 5.0 properties, reason
codes, four-byte integer fields, enhanced authentication, and version-specific
framing extensions are intentionally deferred to the MQTT 5.0 manifest extension
step.

## Provenance

Evidence was gathered using the repo's `rfc-protocol-bootstrap` and
`rfc-protocol-spec` workflows before adding MQTT code. `rfc-protocol-spec`
discovery for "MQTT" found IETF documents such as RFC 9431 (an ACE/TLS profile
for MQTT) and RFC 9006 (TCP usage guidance), but no IETF RFC defining the MQTT
3.1.1 wire format. The normative core source selected for this baseline is the
OASIS Standard:

- OASIS, "MQTT Version 3.1.1", 29 October 2014, OASIS Standard:
  <https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html>
- IANA, "Service Name and Transport Protocol Port Number Registry", queried for
  MQTT service names on 2026-06-23:
  <https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=mqtt>

## Packet Structure

OASIS MQTT 3.1.1 sec. 2.1 defines every MQTT Control Packet as up to three
ordered parts: fixed header, optional variable header, and optional payload.
OASIS sec. 2.2 states that every MQTT Control Packet contains a fixed header.

## Fixed Header

OASIS sec. 2.2 and Figure 2.2 define byte 1 as the MQTT Control Packet Type in
bits 7-4 and type-specific flags in bits 3-0. OASIS sec. 2.2.1 defines the type
field as a 4-bit unsigned value. OASIS sec. 2.2.2 defines the flags nibble and
requires reserved flag bits to be set to the values in Table 2.2; receivers close
the network connection on invalid flags.

OASIS sec. 2.2.3 defines the Remaining Length field starting at byte 2. It is
the number of bytes after the fixed header's Remaining Length field, including
variable header and payload bytes and excluding the bytes used to encode the
Remaining Length field itself.

## Remaining Length Encoding

OASIS sec. 2.2.3 defines Remaining Length as a variable length encoding:

| Encoded bytes | Value range | Wire range |
| --- | --- | --- |
| 1 | 0 through 127 | 0x00 through 0x7F |
| 2 | 128 through 16,383 | 0x80 0x01 through 0xFF 0x7F |
| 3 | 16,384 through 2,097,151 | 0x80 0x80 0x01 through 0xFF 0xFF 0x7F |
| 4 | 2,097,152 through 268,435,455 | 0x80 0x80 0x80 0x01 through 0xFF 0xFF 0xFF 0x7F |

Source: OASIS sec. 2.2.3, Table 2.4.

Encoding rules from OASIS sec. 2.2.3:

- Each byte contributes seven data bits.
- The most significant bit is the continuation bit.
- Values are encoded least-significant group first.
- The maximum field width is four bytes.
- The maximum representable Remaining Length is 268,435,455, encoded as
  `0xFF 0xFF 0xFF 0x7F`.
- During decode, a multiplier greater than `128*128*128` is malformed.

## MQTT 3.1.1 Data Representations

| Representation | Wire shape | Source |
| --- | --- | --- |
| Bit numbering | Bits are numbered 7 through 0; bit 7 is most significant. | OASIS sec. 1.5.1 |
| Two-byte integer | 16-bit unsigned integer in network byte order: MSB then LSB. | OASIS sec. 1.5.2 |
| UTF-8 encoded string | Two-byte length prefix followed by that many UTF-8 bytes; length is 0 through 65,535 bytes unless stated otherwise. | OASIS sec. 1.5.3, Figure 1.1 |
| Binary data with two-byte length | Two-byte length prefix followed by that many opaque bytes. Used by CONNECT Will Message and Password fields. | OASIS sec. 3.1.3.3 and sec. 3.1.3.5 |

MQTT 3.1.1 does not define a general four-byte integer data representation in
sec. 1.5. Version 5.0 four-byte integer fields and any 5.0 property-specific
integer encodings are deferred to the MQTT 5.0 manifest extension.

UTF-8 string validity rules are part of OASIS sec. 1.5.3: string data must be
well-formed UTF-8, must not include U+0000, and must not skip or strip a leading
UTF-8 byte order mark sequence.

## Baseline Control Packet Types and Fixed Header Flags

OASIS sec. 2.2.1 Table 2.1 defines the MQTT 3.1.1 control packet type values.
OASIS sec. 2.2.2 Table 2.2 defines the fixed header flag bits.

| Type | Name | Direction | Flags nibble | Source |
| --- | --- | --- | --- | --- |
| 0 | Reserved | Forbidden | n/a | OASIS sec. 2.2.1 Table 2.1 |
| 1 | CONNECT | Client to Server | 0x0 | OASIS sec. 2.2.1 Table 2.1; sec. 2.2.2 Table 2.2; sec. 3.1.1 |
| 2 | CONNACK | Server to Client | 0x0 | OASIS sec. 2.2.1 Table 2.1; sec. 2.2.2 Table 2.2; sec. 3.2.1 |
| 3 | PUBLISH | Both directions | variable: DUP bit 3, QoS bits 2-1, RETAIN bit 0 | OASIS sec. 2.2.1 Table 2.1; sec. 2.2.2 Table 2.2; sec. 3.3.1 |
| 4 | PUBACK | Both directions | 0x0 | OASIS sec. 2.2.1 Table 2.1; sec. 2.2.2 Table 2.2; sec. 3.4.1 |
| 5 | PUBREC | Both directions | 0x0 | OASIS sec. 2.2.1 Table 2.1; sec. 2.2.2 Table 2.2; sec. 3.5.1 |
| 6 | PUBREL | Both directions | 0x2 | OASIS sec. 2.2.1 Table 2.1; sec. 2.2.2 Table 2.2; sec. 3.6.1 |
| 7 | PUBCOMP | Both directions | 0x0 | OASIS sec. 2.2.1 Table 2.1; sec. 2.2.2 Table 2.2; sec. 3.7.1 |
| 8 | SUBSCRIBE | Client to Server | 0x2 | OASIS sec. 2.2.1 Table 2.1; sec. 2.2.2 Table 2.2; sec. 3.8.1 |
| 9 | SUBACK | Server to Client | 0x0 | OASIS sec. 2.2.1 Table 2.1; sec. 2.2.2 Table 2.2; sec. 3.9.1 |
| 10 | UNSUBSCRIBE | Client to Server | 0x2 | OASIS sec. 2.2.1 Table 2.1; sec. 2.2.2 Table 2.2; sec. 3.10.1 |
| 11 | UNSUBACK | Server to Client | 0x0 | OASIS sec. 2.2.1 Table 2.1; sec. 2.2.2 Table 2.2; sec. 3.11.1 |
| 12 | PINGREQ | Client to Server | 0x0 | OASIS sec. 2.2.1 Table 2.1; sec. 2.2.2 Table 2.2; sec. 3.12.1 |
| 13 | PINGRESP | Server to Client | 0x0 | OASIS sec. 2.2.1 Table 2.1; sec. 2.2.2 Table 2.2; sec. 3.13.1 |
| 14 | DISCONNECT | Client to Server | 0x0 | OASIS sec. 2.2.1 Table 2.1; sec. 2.2.2 Table 2.2; sec. 3.14.1 |
| 15 | Reserved | Forbidden | n/a | OASIS sec. 2.2.1 Table 2.1 |

PUBLISH flag details from OASIS sec. 3.3.1:

- DUP is byte 1 bit 3; it marks possible redelivery of the PUBLISH control
  packet.
- QoS is byte 1 bits 2-1. Values are 0 (at most once), 1 (at least once), and 2
  (exactly once). Value 3, encoded with both QoS bits set, is reserved and must
  not be used.
- RETAIN is byte 1 bit 0.

The Packet Identifier field is a two-byte integer. OASIS sec. 2.3.1 states that
it appears in PUBLISH when QoS is greater than 0, and in PUBACK, PUBREC, PUBREL,
PUBCOMP, SUBSCRIBE, SUBACK, UNSUBSCRIBE, and UNSUBACK. For SUBSCRIBE,
UNSUBSCRIBE, and QoS>0 PUBLISH, the Packet Identifier must be non-zero.

## CONNECT

OASIS sec. 3.1 defines CONNECT as the client request to connect to a server.
OASIS sec. 3.1.1 defines fixed header type 1 with flags 0x0. The Remaining
Length is the length of the 10-byte variable header plus the payload length.

Variable header layout from OASIS sec. 3.1.2:

| Field | Wire shape | Source |
| --- | --- | --- |
| Protocol Name | UTF-8 string `MQTT`, encoded as length 4 followed by `M Q T T`. | OASIS sec. 3.1.2.1 |
| Protocol Level | One unsigned byte; MQTT 3.1.1 uses level 4 (`0x04`). | OASIS sec. 3.1.2.2 |
| Connect Flags | One byte: bit 7 User Name Flag, bit 6 Password Flag, bit 5 Will Retain, bits 4-3 Will QoS, bit 2 Will Flag, bit 1 Clean Session, bit 0 reserved. | OASIS sec. 3.1.2.3 |
| Keep Alive | 16-bit word, seconds. | OASIS sec. 3.1.2.10 |

CONNECT flag constraints from OASIS:

- Reserved bit 0 of Connect Flags must be zero (sec. 3.1.2.3).
- If Will Flag is 1, Will QoS and Will Retain are meaningful and Will Topic and
  Will Message must be present in the payload (sec. 3.1.2.5).
- If Will Flag is 0, Will QoS and Will Retain must be zero, and Will Topic and
  Will Message must not be present (sec. 3.1.2.5 through sec. 3.1.2.7).
- Will QoS values 0, 1, and 2 are valid when Will Flag is 1; value 3 is invalid
  (sec. 3.1.2.6).
- If User Name Flag is 0, User Name must not be present; if it is 1, User Name
  must be present (sec. 3.1.2.8).
- If Password Flag is 0, Password must not be present; if it is 1, Password must
  be present (sec. 3.1.2.9).
- If User Name Flag is 0, Password Flag must be 0 (sec. 3.1.2.9).

Payload layout from OASIS sec. 3.1.3:

| Field | Presence and wire shape | Source |
| --- | --- | --- |
| Client Identifier | Required first field; UTF-8 encoded string. | OASIS sec. 3.1.3.1 |
| Will Topic | Present when Will Flag is 1; UTF-8 encoded string. | OASIS sec. 3.1.3.2 |
| Will Message | Present when Will Flag is 1; two-byte length followed by zero or more bytes. | OASIS sec. 3.1.3.3 |
| User Name | Present when User Name Flag is 1; UTF-8 encoded string. | OASIS sec. 3.1.3.4 |
| Password | Present when Password Flag is 1; two-byte length followed by 0 through 65,535 binary bytes. | OASIS sec. 3.1.3.5 |

OASIS sec. 3.1.3 requires payload fields, if present, to appear in this order:
Client Identifier, Will Topic, Will Message, User Name, Password.

## CONNACK

OASIS sec. 3.2 defines CONNACK as the server response to CONNECT. OASIS sec.
3.2.1 defines fixed header type 2 with flags 0x0 and Remaining Length 2. OASIS
sec. 3.2.2 defines a two-byte variable header:

| Field | Wire shape | Source |
| --- | --- | --- |
| Connect Acknowledge Flags | One byte; bits 7-1 reserved zero, bit 0 Session Present. | OASIS sec. 3.2.2.1 and sec. 3.2.2.2 |
| Connect Return code | One unsigned byte. | OASIS sec. 3.2.2.3 |

CONNACK return codes from OASIS sec. 3.2.2.3 Table 3.1:

| Value | Name |
| --- | --- |
| 0x00 | Connection Accepted |
| 0x01 | Connection Refused, unacceptable protocol version |
| 0x02 | Connection Refused, identifier rejected |
| 0x03 | Connection Refused, Server unavailable |
| 0x04 | Connection Refused, bad user name or password |
| 0x05 | Connection Refused, not authorized |
| 0x06-0xFF | Reserved for future use |

OASIS sec. 3.2.3 states that CONNACK has no payload.

## SUBSCRIBE and SUBACK

OASIS sec. 3.8 defines SUBSCRIBE as the client request to create one or more
subscriptions. OASIS sec. 3.8.1 defines fixed header type 8 with flags 0x2; bits
3,2,1,0 must be `0,0,1,0`. Remaining Length is the two-byte Packet Identifier
variable header plus payload length. OASIS sec. 3.8.2 defines the variable
header as a Packet Identifier. OASIS sec. 3.8.3 defines the payload as at least
one Topic Filter / Requested QoS pair. Each Topic Filter is a UTF-8 encoded
string, followed by one Requested QoS byte. The Requested QoS byte uses bits 1-0
for QoS 0, 1, or 2; bits 7-2 are reserved zero.

OASIS sec. 3.9 defines SUBACK as the server acknowledgement for SUBSCRIBE.
OASIS sec. 3.9.1 defines fixed header type 9 with flags 0x0. OASIS sec. 3.9.2
defines the variable header as the Packet Identifier from the acknowledged
SUBSCRIBE. OASIS sec. 3.9.3 defines the payload as one return code per requested
Topic Filter, in the same order.

SUBACK return codes from OASIS sec. 3.9.3:

| Value | Meaning |
| --- | --- |
| 0x00 | Success - Maximum QoS 0 |
| 0x01 | Success - Maximum QoS 1 |
| 0x02 | Success - Maximum QoS 2 |
| 0x80 | Failure |

OASIS sec. 3.9.3 reserves all SUBACK return codes other than 0x00, 0x01, 0x02,
and 0x80.

## Assigned Ports

IANA's Service Name and Transport Protocol Port Number Registry has the
following MQTT rows:

| Service name | Port | Transport | Description | Registry source |
| --- | --- | --- | --- | --- |
| mqtt | 1883 | tcp | Message Queuing Telemetry Transport Protocol | IANA service registry row for `mqtt` |
| mqtt | 1883 | udp | Message Queuing Telemetry Transport Protocol | IANA service registry row for `mqtt` |
| secure-mqtt | 8883 | tcp | Secure MQTT | IANA service registry row for `secure-mqtt` |
| secure-mqtt | 8883 | udp | Secure MQTT | IANA service registry row for `secure-mqtt` |

The `crafter` cleartext MQTT decode binding is for `mqtt` over TCP port 1883.
The `secure-mqtt` TCP port 8883 is reserved for secure MQTT traffic and is not a
cleartext MQTT decode binding in this baseline.

## Deferred and Out of Scope for Baseline

- MQTT Version 5.0 packet fields and framing differences.
- MQTT Version 5.0 property system, property identifiers, property length
  encoding, duplicate-property rules, and packet-specific property placement.
- MQTT Version 5.0 reason codes for CONNACK, QoS acknowledgements, SUBACK,
  UNSUBACK, DISCONNECT, and AUTH.
- MQTT Version 5.0 AUTH packet and enhanced authentication.
- MQTT Version 5.0 four-byte integer fields and any property-specific integer
  representation not present in MQTT 3.1.1.
- TLS or cleartext decoding on `secure-mqtt` port 8883.
- MQTT over WebSocket IANA identifier and transport binding.
