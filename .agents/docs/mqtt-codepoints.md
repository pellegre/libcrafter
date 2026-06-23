# MQTT 3.1.1 Codepoint Authority Table

Compact, code-facing authority for the `crafter` MQTT 3.1.1 layer. This table
is the source of truth for MQTT constants: `constants.rs`, oracle specs, tests,
fixtures, and examples must match it.

Every value here is derived from and must match
[`mqtt-manifest.md`](mqtt-manifest.md). The manifest carries the full OASIS/IANA
evidence. On any disagreement, this table is corrected to the manifest, never
the reverse.

Row format: `NAME = value  # source`.

## Ports

```
MQTT_PORT = 1883  # IANA service registry: mqtt/tcp
MQTT_SECURE_PORT = 8883  # IANA service registry: secure-mqtt/tcp; TLS/opaque, not cleartext decode
```

## Protocol Version

```
MQTT_311_PROTOCOL_NAME = "MQTT"  # OASIS MQTT 3.1.1 sec. 3.1.2.1
MQTT_311_PROTOCOL_LEVEL = 4  # OASIS MQTT 3.1.1 sec. 3.1.2.2
```

## Fixed Header Constants

```
MQTT_FIXED_HEADER_TYPE_SHIFT = 4  # OASIS MQTT 3.1.1 sec. 2.2, sec. 2.2.1
MQTT_FIXED_HEADER_TYPE_MASK = 0xF0  # OASIS MQTT 3.1.1 sec. 2.2
MQTT_FIXED_HEADER_FLAGS_MASK = 0x0F  # OASIS MQTT 3.1.1 sec. 2.2.2
MQTT_REMAINING_LENGTH_MAX = 268435455  # OASIS MQTT 3.1.1 sec. 2.2.3
MQTT_REMAINING_LENGTH_MAX_BYTES = 4  # OASIS MQTT 3.1.1 sec. 2.2.3
```

## Control Packet Types

```
MQTT_TYPE_CONNECT = 1  # OASIS MQTT 3.1.1 sec. 2.2.1 Table 2.1
MQTT_TYPE_CONNACK = 2  # OASIS MQTT 3.1.1 sec. 2.2.1 Table 2.1
MQTT_TYPE_PUBLISH = 3  # OASIS MQTT 3.1.1 sec. 2.2.1 Table 2.1
MQTT_TYPE_PUBACK = 4  # OASIS MQTT 3.1.1 sec. 2.2.1 Table 2.1
MQTT_TYPE_PUBREC = 5  # OASIS MQTT 3.1.1 sec. 2.2.1 Table 2.1
MQTT_TYPE_PUBREL = 6  # OASIS MQTT 3.1.1 sec. 2.2.1 Table 2.1
MQTT_TYPE_PUBCOMP = 7  # OASIS MQTT 3.1.1 sec. 2.2.1 Table 2.1
MQTT_TYPE_SUBSCRIBE = 8  # OASIS MQTT 3.1.1 sec. 2.2.1 Table 2.1
MQTT_TYPE_SUBACK = 9  # OASIS MQTT 3.1.1 sec. 2.2.1 Table 2.1
MQTT_TYPE_UNSUBSCRIBE = 10  # OASIS MQTT 3.1.1 sec. 2.2.1 Table 2.1
MQTT_TYPE_UNSUBACK = 11  # OASIS MQTT 3.1.1 sec. 2.2.1 Table 2.1
MQTT_TYPE_PINGREQ = 12  # OASIS MQTT 3.1.1 sec. 2.2.1 Table 2.1
MQTT_TYPE_PINGRESP = 13  # OASIS MQTT 3.1.1 sec. 2.2.1 Table 2.1
MQTT_TYPE_DISCONNECT = 14  # OASIS MQTT 3.1.1 sec. 2.2.1 Table 2.1
```

Type values `0` and `15` are reserved and forbidden in MQTT 3.1.1 (OASIS sec.
2.2.1 Table 2.1).

## Fixed Header Flag Nibbles

```
MQTT_FLAGS_CONNECT = 0x0  # OASIS MQTT 3.1.1 sec. 2.2.2 Table 2.2
MQTT_FLAGS_CONNACK = 0x0  # OASIS MQTT 3.1.1 sec. 2.2.2 Table 2.2
MQTT_FLAGS_PUBACK = 0x0  # OASIS MQTT 3.1.1 sec. 2.2.2 Table 2.2
MQTT_FLAGS_PUBREC = 0x0  # OASIS MQTT 3.1.1 sec. 2.2.2 Table 2.2
MQTT_FLAGS_PUBREL = 0x2  # OASIS MQTT 3.1.1 sec. 2.2.2 Table 2.2; sec. 3.6.1
MQTT_FLAGS_PUBCOMP = 0x0  # OASIS MQTT 3.1.1 sec. 2.2.2 Table 2.2
MQTT_FLAGS_SUBSCRIBE = 0x2  # OASIS MQTT 3.1.1 sec. 2.2.2 Table 2.2; sec. 3.8.1
MQTT_FLAGS_SUBACK = 0x0  # OASIS MQTT 3.1.1 sec. 2.2.2 Table 2.2
MQTT_FLAGS_UNSUBSCRIBE = 0x2  # OASIS MQTT 3.1.1 sec. 2.2.2 Table 2.2
MQTT_FLAGS_UNSUBACK = 0x0  # OASIS MQTT 3.1.1 sec. 2.2.2 Table 2.2
MQTT_FLAGS_PINGREQ = 0x0  # OASIS MQTT 3.1.1 sec. 2.2.2 Table 2.2
MQTT_FLAGS_PINGRESP = 0x0  # OASIS MQTT 3.1.1 sec. 2.2.2 Table 2.2
MQTT_FLAGS_DISCONNECT = 0x0  # OASIS MQTT 3.1.1 sec. 2.2.2 Table 2.2
```

PUBLISH uses the flags nibble as fields rather than a fixed reserved value
(OASIS sec. 2.2.2 Table 2.2; sec. 3.3.1):

```
MQTT_PUBLISH_FLAG_RETAIN = 0x1  # OASIS MQTT 3.1.1 sec. 3.3.1.3
MQTT_PUBLISH_FLAG_QOS_MASK = 0x6  # OASIS MQTT 3.1.1 sec. 3.3.1.2
MQTT_PUBLISH_FLAG_DUP = 0x8  # OASIS MQTT 3.1.1 sec. 3.3.1.1
MQTT_PUBLISH_QOS_0 = 0  # OASIS MQTT 3.1.1 sec. 3.3.1.2 Table 3.2
MQTT_PUBLISH_QOS_1 = 1  # OASIS MQTT 3.1.1 sec. 3.3.1.2 Table 3.2
MQTT_PUBLISH_QOS_2 = 2  # OASIS MQTT 3.1.1 sec. 3.3.1.2 Table 3.2
MQTT_PUBLISH_QOS_RESERVED = 3  # OASIS MQTT 3.1.1 sec. 3.3.1.2 Table 3.2
```

## Fixed Header First Bytes for Default Encodings

```
MQTT_FIXED_CONNECT = 0x10
MQTT_FIXED_CONNACK = 0x20
MQTT_FIXED_PUBLISH_BASE = 0x30
MQTT_FIXED_PUBACK = 0x40
MQTT_FIXED_PUBREC = 0x50
MQTT_FIXED_PUBREL = 0x62
MQTT_FIXED_PUBCOMP = 0x70
MQTT_FIXED_SUBSCRIBE = 0x82
MQTT_FIXED_SUBACK = 0x90
MQTT_FIXED_UNSUBSCRIBE = 0xA2
MQTT_FIXED_UNSUBACK = 0xB0
MQTT_FIXED_PINGREQ = 0xC0
MQTT_FIXED_PINGRESP = 0xD0
MQTT_FIXED_DISCONNECT = 0xE0
```

The first-byte values are derived from `(type << 4) | flags` using OASIS MQTT
3.1.1 sec. 2.2, sec. 2.2.1 Table 2.1, and sec. 2.2.2 Table 2.2.

## CONNECT Variable Header and Flags

```
MQTT_CONNECT_VARIABLE_HEADER_LEN = 10  # OASIS MQTT 3.1.1 sec. 3.1.1, sec. 3.1.2
MQTT_CONNECT_FLAG_USERNAME = 0x80  # OASIS MQTT 3.1.1 sec. 3.1.2.8
MQTT_CONNECT_FLAG_PASSWORD = 0x40  # OASIS MQTT 3.1.1 sec. 3.1.2.9
MQTT_CONNECT_FLAG_WILL_RETAIN = 0x20  # OASIS MQTT 3.1.1 sec. 3.1.2.7
MQTT_CONNECT_FLAG_WILL_QOS_MASK = 0x18  # OASIS MQTT 3.1.1 sec. 3.1.2.6
MQTT_CONNECT_FLAG_WILL = 0x04  # OASIS MQTT 3.1.1 sec. 3.1.2.5
MQTT_CONNECT_FLAG_CLEAN_SESSION = 0x02  # OASIS MQTT 3.1.1 sec. 3.1.2.4
MQTT_CONNECT_FLAG_RESERVED = 0x01  # OASIS MQTT 3.1.1 sec. 3.1.2.3; must be zero
```

## CONNACK Return Codes

```
MQTT_CONNACK_ACCEPTED = 0x00  # OASIS MQTT 3.1.1 sec. 3.2.2.3 Table 3.1
MQTT_CONNACK_UNACCEPTABLE_PROTOCOL_VERSION = 0x01  # OASIS MQTT 3.1.1 sec. 3.2.2.3 Table 3.1
MQTT_CONNACK_IDENTIFIER_REJECTED = 0x02  # OASIS MQTT 3.1.1 sec. 3.2.2.3 Table 3.1
MQTT_CONNACK_SERVER_UNAVAILABLE = 0x03  # OASIS MQTT 3.1.1 sec. 3.2.2.3 Table 3.1
MQTT_CONNACK_BAD_USERNAME_OR_PASSWORD = 0x04  # OASIS MQTT 3.1.1 sec. 3.2.2.3 Table 3.1
MQTT_CONNACK_NOT_AUTHORIZED = 0x05  # OASIS MQTT 3.1.1 sec. 3.2.2.3 Table 3.1
```

CONNACK return code values `0x06` through `0xFF` are reserved for future use
(OASIS MQTT 3.1.1 sec. 3.2.2.3 Table 3.1).

## SUBACK Return Codes

```
MQTT_SUBACK_MAX_QOS_0 = 0x00  # OASIS MQTT 3.1.1 sec. 3.9.3
MQTT_SUBACK_MAX_QOS_1 = 0x01  # OASIS MQTT 3.1.1 sec. 3.9.3
MQTT_SUBACK_MAX_QOS_2 = 0x02  # OASIS MQTT 3.1.1 sec. 3.9.3
MQTT_SUBACK_FAILURE = 0x80  # OASIS MQTT 3.1.1 sec. 3.9.3
```

SUBACK return code values other than `0x00`, `0x01`, `0x02`, and `0x80` are
reserved and must not be used (OASIS MQTT 3.1.1 sec. 3.9.3).

## Deferred for MQTT 5.0

- Property identifiers and property length handling.
- MQTT 5.0 reason codes.
- AUTH control packet.
- MQTT 5.0-specific CONNECT, CONNACK, PUBLISH, acknowledgement, SUBSCRIBE,
  SUBACK, UNSUBSCRIBE, UNSUBACK, and DISCONNECT fields.
- Four-byte integer fields not defined by MQTT 3.1.1.
