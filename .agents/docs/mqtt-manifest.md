# MQTT Source Manifest

Source-backed evidence record for the initial `crafter` MQTT layer. Later
constants, builders, decoders, oracle specs, fixtures, and tests must cite this
manifest or the compact authority table in
[`mqtt-codepoints.md`](mqtt-codepoints.md), not model memory.

The baseline sections cover MQTT Version 3.1.1. The MQTT 5.0 extension sections
record the advanced-version facts needed before any MQTT 5.0 implementation.

## Provenance

Evidence was gathered using the repo's `rfc-protocol-bootstrap` and
`rfc-protocol-spec` workflows before adding MQTT code. `rfc-protocol-spec`
discovery for "MQTT" found IETF documents such as RFC 9431 (an ACE/TLS profile
for MQTT) and RFC 9006 (TCP usage guidance), but no IETF RFC defining the MQTT
3.1.1 wire format. The normative core source selected for this baseline is the
OASIS Standard:

- OASIS, "MQTT Version 3.1.1", 29 October 2014, OASIS Standard:
  <https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html>
- OASIS, "MQTT Version 5.0", 7 March 2019, OASIS Standard:
  <https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html>
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

## MQTT 5.0 Protocol Version

OASIS MQTT 5.0 sec. 3.1.2.2 defines the CONNECT Protocol Version byte as a
one-byte unsigned value. MQTT 5.0 uses protocol level `5` (`0x05`).

## MQTT 5.0 Properties

OASIS MQTT 5.0 sec. 2.2.2 defines Properties as a Property Length encoded as a
Variable Byte Integer followed by zero or more property entries. A property entry
is a Variable Byte Integer Property Identifier followed by a value of the
specified type. OASIS sec. 2.2.2.2 states that an identifier not valid for the
packet type, or a value not of the specified data type, is a Malformed Packet;
the receiver uses CONNACK or DISCONNECT with reason code `0x81`.

Property identifiers from OASIS MQTT 5.0 sec. 2.2.2.2 Table 2-4:

| Id | Name | Wire type | Allowed packets / Will Properties |
| --- | --- | --- | --- |
| `0x01` | Payload Format Indicator | Byte | PUBLISH, Will Properties |
| `0x02` | Message Expiry Interval | Four Byte Integer | PUBLISH, Will Properties |
| `0x03` | Content Type | UTF-8 Encoded String | PUBLISH, Will Properties |
| `0x08` | Response Topic | UTF-8 Encoded String | PUBLISH, Will Properties |
| `0x09` | Correlation Data | Binary Data | PUBLISH, Will Properties |
| `0x0B` | Subscription Identifier | Variable Byte Integer | PUBLISH, SUBSCRIBE |
| `0x11` | Session Expiry Interval | Four Byte Integer | CONNECT, CONNACK, DISCONNECT |
| `0x12` | Assigned Client Identifier | UTF-8 Encoded String | CONNACK |
| `0x13` | Server Keep Alive | Two Byte Integer | CONNACK |
| `0x15` | Authentication Method | UTF-8 Encoded String | CONNECT, CONNACK, AUTH |
| `0x16` | Authentication Data | Binary Data | CONNECT, CONNACK, AUTH |
| `0x17` | Request Problem Information | Byte | CONNECT |
| `0x18` | Will Delay Interval | Four Byte Integer | Will Properties |
| `0x19` | Request Response Information | Byte | CONNECT |
| `0x1A` | Response Information | UTF-8 Encoded String | CONNACK |
| `0x1C` | Server Reference | UTF-8 Encoded String | CONNACK, DISCONNECT |
| `0x1F` | Reason String | UTF-8 Encoded String | CONNACK, PUBACK, PUBREC, PUBREL, PUBCOMP, SUBACK, UNSUBACK, DISCONNECT, AUTH |
| `0x21` | Receive Maximum | Two Byte Integer | CONNECT, CONNACK |
| `0x22` | Topic Alias Maximum | Two Byte Integer | CONNECT, CONNACK |
| `0x23` | Topic Alias | Two Byte Integer | PUBLISH |
| `0x24` | Maximum QoS | Byte | CONNACK |
| `0x25` | Retain Available | Byte | CONNACK |
| `0x26` | User Property | UTF-8 String Pair | CONNECT, CONNACK, PUBLISH, Will Properties, PUBACK, PUBREC, PUBREL, PUBCOMP, SUBSCRIBE, SUBACK, UNSUBSCRIBE, UNSUBACK, DISCONNECT, AUTH |
| `0x27` | Maximum Packet Size | Four Byte Integer | CONNECT, CONNACK |
| `0x28` | Wildcard Subscription Available | Byte | CONNACK |
| `0x29` | Subscription Identifier Available | Byte | CONNACK |
| `0x2A` | Shared Subscription Available | Byte | CONNACK |

OASIS sec. 2.2.2.2 notes that although Property Identifier is encoded as a
Variable Byte Integer, every MQTT 5.0 property identifier in Table 2-4 is one
byte long.

## MQTT 5.0 Reason Codes

OASIS MQTT 5.0 sec. 2.4 defines a Reason Code as a one-byte unsigned value.
Values below `0x80` indicate successful completion; values `0x80` and above
indicate failure. CONNACK, PUBACK, PUBREC, PUBREL, PUBCOMP, DISCONNECT, and AUTH
carry a single Reason Code in the variable header. SUBACK and UNSUBACK carry a
list of one or more Reason Codes in the payload. OASIS sec. 2.4 Table 2-6 is the
common reason-code table; the packet sections below provide packet-specific
allowed sets.

| Packet | Allowed reason codes | Source |
| --- | --- | --- |
| CONNACK | `0x00` Success; `0x80` Unspecified error; `0x81` Malformed Packet; `0x82` Protocol Error; `0x83` Implementation specific error; `0x84` Unsupported Protocol Version; `0x85` Client Identifier not valid; `0x86` Bad User Name or Password; `0x87` Not authorized; `0x88` Server unavailable; `0x89` Server busy; `0x8A` Banned; `0x8C` Bad authentication method; `0x90` Topic Name invalid; `0x95` Packet too large; `0x97` Quota exceeded; `0x99` Payload format invalid; `0x9A` Retain not supported; `0x9B` QoS not supported; `0x9C` Use another server; `0x9D` Server moved; `0x9F` Connection rate exceeded. | OASIS MQTT 5.0 sec. 3.2.2.2 Table 3-1 |
| PUBACK | `0x00` Success; `0x10` No matching subscribers; `0x80` Unspecified error; `0x83` Implementation specific error; `0x87` Not authorized; `0x90` Topic Name invalid; `0x91` Packet Identifier in use; `0x97` Quota exceeded; `0x99` Payload format invalid. | OASIS MQTT 5.0 sec. 3.4.2.1 Table 3-4 |
| PUBREC | `0x00` Success; `0x10` No matching subscribers; `0x80` Unspecified error; `0x83` Implementation specific error; `0x87` Not authorized; `0x90` Topic Name invalid; `0x91` Packet Identifier in use; `0x97` Quota exceeded; `0x99` Payload format invalid. | OASIS MQTT 5.0 sec. 3.5.2.1 Table 3-5 |
| PUBREL | `0x00` Success; `0x92` Packet Identifier not found. | OASIS MQTT 5.0 sec. 3.6.2.1 Table 3-6 |
| PUBCOMP | `0x00` Success; `0x92` Packet Identifier not found. | OASIS MQTT 5.0 sec. 3.7.2.1 Table 3-7 |
| SUBACK | `0x00` Granted QoS 0; `0x01` Granted QoS 1; `0x02` Granted QoS 2; `0x80` Unspecified error; `0x83` Implementation specific error; `0x87` Not authorized; `0x8F` Topic Filter invalid; `0x91` Packet Identifier in use; `0x97` Quota exceeded; `0x9E` Shared Subscriptions not supported; `0xA1` Subscription Identifiers not supported; `0xA2` Wildcard Subscriptions not supported. | OASIS MQTT 5.0 sec. 3.9.3 Table 3-9 |
| UNSUBACK | `0x00` Success; `0x11` No subscription existed; `0x80` Unspecified error; `0x83` Implementation specific error; `0x87` Not authorized; `0x8F` Topic Filter invalid; `0x91` Packet Identifier in use. | OASIS MQTT 5.0 sec. 3.11.3 Table 3-10 |
| DISCONNECT | `0x00` Normal disconnection; `0x04` Disconnect with Will Message; `0x80` Unspecified error; `0x81` Malformed Packet; `0x82` Protocol Error; `0x83` Implementation specific error; `0x87` Not authorized; `0x89` Server busy; `0x8B` Server shutting down; `0x8D` Keep Alive timeout; `0x8E` Session taken over; `0x8F` Topic Filter invalid; `0x90` Topic Name invalid; `0x93` Receive Maximum exceeded; `0x94` Topic Alias invalid; `0x95` Packet too large; `0x96` Message rate too high; `0x97` Quota exceeded; `0x98` Administrative action; `0x99` Payload format invalid; `0x9A` Retain not supported; `0x9B` QoS not supported; `0x9C` Use another server; `0x9D` Server moved; `0x9E` Shared Subscriptions not supported; `0x9F` Connection rate exceeded; `0xA0` Maximum connect time; `0xA1` Subscription Identifiers not supported; `0xA2` Wildcard Subscriptions not supported. | OASIS MQTT 5.0 sec. 3.14.2.1 Table 3-12 |
| AUTH | `0x00` Success; `0x18` Continue authentication; `0x19` Re-authenticate. | OASIS MQTT 5.0 sec. 3.15.2.1 Table 3-11 |

## MQTT 5.0 Subscription Options

OASIS MQTT 5.0 sec. 3.8.3.1 defines one Subscription Options byte after each
Topic Filter in a SUBSCRIBE payload:

| Bits | Name | Values |
| --- | --- | --- |
| 0-1 | Maximum QoS | `0`, `1`, or `2`; value `3` is a Protocol Error. |
| 2 | No Local | `1` prevents forwarding messages to a connection with the same ClientID as the publishing connection; setting No Local to `1` on a Shared Subscription is a Protocol Error. |
| 3 | Retain As Published | `1` preserves the PUBLISH RETAIN flag on forwarded Application Messages; `0` clears it on forwarded Application Messages. |
| 4-5 | Retain Handling | `0` send retained messages at subscribe time; `1` send retained messages only if the subscription does not currently exist; `2` do not send retained messages at subscribe time; value `3` is a Protocol Error. |
| 6-7 | Reserved | Must be zero; non-zero reserved bits make the SUBSCRIBE packet malformed. |

## MQTT 5.0 AUTH Packet

OASIS MQTT 5.0 sec. 2.2.1 Table 2-1 and sec. 3.15 define AUTH as control packet
type `15`. OASIS sec. 3.15.1 defines the fixed header first byte as type 15 with
reserved flags `0x0` (`0xF0`); any non-zero flags are malformed.

OASIS sec. 3.15.2 defines the AUTH variable header fields in order:
Authenticate Reason Code, then Properties. OASIS sec. 3.15.2.1 defines the
Authenticate Reason Code as byte 0 of the variable header, with the allowed
values listed in the reason-code table above. The Reason Code and Property
Length may be omitted when the reason code is `0x00` Success and there are no
Properties, yielding Remaining Length 0. OASIS sec. 3.15.2.2 allows AUTH
properties Authentication Method (`0x15`), Authentication Data (`0x16`), Reason
String (`0x1F`), and User Property (`0x26`). OASIS sec. 3.15.3 states that AUTH
has no payload.

## MQTT 5.0 Reference-Backend Notes

Step 77 must confirm reference-backend support for MQTT 5.0 properties, reason
codes, subscription options, and AUTH in `scapy.contrib.mqtt`. Support is
uncertain until checked against the installed Scapy version; unsupported 5.0
features must be recorded as explicit oracle gaps rather than silently skipped.

## Still Deferred and Out of Scope

- TLS or cleartext decoding on `secure-mqtt` port 8883.
- MQTT over WebSocket IANA identifier and transport binding.
