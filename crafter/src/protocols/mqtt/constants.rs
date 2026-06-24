//! MQTT 3.1.1 wire constants.
//!
//! Codepoints copied verbatim where names align from the codepoint authority
//! table, `.agents/docs/mqtt-codepoints.md`, which is itself derived from and
//! kept in sync with `.agents/docs/mqtt-manifest.md` (the full OASIS/IANA
//! evidence record). Each constant cites its defining authority in a line
//! comment. On any disagreement, the authority table -- not this file -- is the
//! source of truth.

// ---------------------------------------------------------------------------
// Fixed protocol constants
// ---------------------------------------------------------------------------

/// MQTT cleartext TCP listen port. IANA service registry `mqtt/tcp`.
pub const MQTT_PORT: u16 = 1883;
/// MQTT-over-TLS TCP listen port; TLS-wrapped and not cleartext MQTT. IANA service registry `secure-mqtt/tcp`.
pub const MQTT_TLS_PORT: u16 = 8883;
/// MQTT 3.1.1 protocol name carried in CONNECT. OASIS MQTT 3.1.1 sec. 3.1.2.1.
pub const MQTT_311_PROTOCOL_NAME: &str = "MQTT";
/// MQTT 3.1.1 protocol level carried in CONNECT. OASIS MQTT 3.1.1 sec. 3.1.2.2.
pub const MQTT_311_PROTOCOL_LEVEL: u8 = 4;

// ---------------------------------------------------------------------------
// Control packet types (OASIS MQTT 3.1.1 sec. 2.2.1 Table 2.1)
// ---------------------------------------------------------------------------

/// CONNECT control packet type. OASIS MQTT 3.1.1 sec. 2.2.1 Table 2.1.
pub const MQTT_TYPE_CONNECT: u8 = 1;
/// CONNACK control packet type. OASIS MQTT 3.1.1 sec. 2.2.1 Table 2.1.
pub const MQTT_TYPE_CONNACK: u8 = 2;
/// PUBLISH control packet type. OASIS MQTT 3.1.1 sec. 2.2.1 Table 2.1.
pub const MQTT_TYPE_PUBLISH: u8 = 3;
/// PUBACK control packet type. OASIS MQTT 3.1.1 sec. 2.2.1 Table 2.1.
pub const MQTT_TYPE_PUBACK: u8 = 4;
/// PUBREC control packet type. OASIS MQTT 3.1.1 sec. 2.2.1 Table 2.1.
pub const MQTT_TYPE_PUBREC: u8 = 5;
/// PUBREL control packet type. OASIS MQTT 3.1.1 sec. 2.2.1 Table 2.1.
pub const MQTT_TYPE_PUBREL: u8 = 6;
/// PUBCOMP control packet type. OASIS MQTT 3.1.1 sec. 2.2.1 Table 2.1.
pub const MQTT_TYPE_PUBCOMP: u8 = 7;
/// SUBSCRIBE control packet type. OASIS MQTT 3.1.1 sec. 2.2.1 Table 2.1.
pub const MQTT_TYPE_SUBSCRIBE: u8 = 8;
/// SUBACK control packet type. OASIS MQTT 3.1.1 sec. 2.2.1 Table 2.1.
pub const MQTT_TYPE_SUBACK: u8 = 9;
/// UNSUBSCRIBE control packet type. OASIS MQTT 3.1.1 sec. 2.2.1 Table 2.1.
pub const MQTT_TYPE_UNSUBSCRIBE: u8 = 10;
/// UNSUBACK control packet type. OASIS MQTT 3.1.1 sec. 2.2.1 Table 2.1.
pub const MQTT_TYPE_UNSUBACK: u8 = 11;
/// PINGREQ control packet type. OASIS MQTT 3.1.1 sec. 2.2.1 Table 2.1.
pub const MQTT_TYPE_PINGREQ: u8 = 12;
/// PINGRESP control packet type. OASIS MQTT 3.1.1 sec. 2.2.1 Table 2.1.
pub const MQTT_TYPE_PINGRESP: u8 = 13;
/// DISCONNECT control packet type. OASIS MQTT 3.1.1 sec. 2.2.1 Table 2.1.
pub const MQTT_TYPE_DISCONNECT: u8 = 14;

// ---------------------------------------------------------------------------
// Fixed header flag nibbles (OASIS MQTT 3.1.1 sec. 2.2.2 Table 2.2)
// ---------------------------------------------------------------------------

/// CONNECT fixed header flags. OASIS MQTT 3.1.1 sec. 2.2.2 Table 2.2.
pub const MQTT_FLAGS_CONNECT: u8 = 0x0;
/// CONNACK fixed header flags. OASIS MQTT 3.1.1 sec. 2.2.2 Table 2.2.
pub const MQTT_FLAGS_CONNACK: u8 = 0x0;
/// PUBACK fixed header flags. OASIS MQTT 3.1.1 sec. 2.2.2 Table 2.2.
pub const MQTT_FLAGS_PUBACK: u8 = 0x0;
/// PUBREC fixed header flags. OASIS MQTT 3.1.1 sec. 2.2.2 Table 2.2.
pub const MQTT_FLAGS_PUBREC: u8 = 0x0;
/// PUBREL fixed header flags. OASIS MQTT 3.1.1 sec. 2.2.2 Table 2.2; sec. 3.6.1.
pub const MQTT_FLAGS_PUBREL: u8 = 0x2;
/// PUBCOMP fixed header flags. OASIS MQTT 3.1.1 sec. 2.2.2 Table 2.2.
pub const MQTT_FLAGS_PUBCOMP: u8 = 0x0;
/// SUBSCRIBE fixed header flags. OASIS MQTT 3.1.1 sec. 2.2.2 Table 2.2; sec. 3.8.1.
pub const MQTT_FLAGS_SUBSCRIBE: u8 = 0x2;
/// SUBACK fixed header flags. OASIS MQTT 3.1.1 sec. 2.2.2 Table 2.2.
pub const MQTT_FLAGS_SUBACK: u8 = 0x0;
/// UNSUBSCRIBE fixed header flags. OASIS MQTT 3.1.1 sec. 2.2.2 Table 2.2.
pub const MQTT_FLAGS_UNSUBSCRIBE: u8 = 0x2;
/// UNSUBACK fixed header flags. OASIS MQTT 3.1.1 sec. 2.2.2 Table 2.2.
pub const MQTT_FLAGS_UNSUBACK: u8 = 0x0;
/// PINGREQ fixed header flags. OASIS MQTT 3.1.1 sec. 2.2.2 Table 2.2.
pub const MQTT_FLAGS_PINGREQ: u8 = 0x0;
/// PINGRESP fixed header flags. OASIS MQTT 3.1.1 sec. 2.2.2 Table 2.2.
pub const MQTT_FLAGS_PINGRESP: u8 = 0x0;
/// DISCONNECT fixed header flags. OASIS MQTT 3.1.1 sec. 2.2.2 Table 2.2.
pub const MQTT_FLAGS_DISCONNECT: u8 = 0x0;

// ---------------------------------------------------------------------------
// CONNECT variable-header flags (OASIS MQTT 3.1.1 sec. 3.1.2.3)
// ---------------------------------------------------------------------------

/// CONNECT Clean Session flag bit. OASIS MQTT 3.1.1 sec. 3.1.2.4.
pub const MQTT_CONNECT_FLAG_CLEAN_SESSION: u8 = 0x02;

// ---------------------------------------------------------------------------
// CONNACK return codes (OASIS MQTT 3.1.1 sec. 3.2.2.3 Table 3.1)
// ---------------------------------------------------------------------------

/// Connection accepted. OASIS MQTT 3.1.1 sec. 3.2.2.3 Table 3.1.
pub const MQTT_CONNACK_ACCEPTED: u8 = 0x00;
/// Connection refused: unacceptable protocol version. OASIS MQTT 3.1.1 sec. 3.2.2.3 Table 3.1.
pub const MQTT_CONNACK_UNACCEPTABLE_PROTOCOL_VERSION: u8 = 0x01;
/// Connection refused: client identifier rejected. OASIS MQTT 3.1.1 sec. 3.2.2.3 Table 3.1.
pub const MQTT_CONNACK_IDENTIFIER_REJECTED: u8 = 0x02;
/// Connection refused: server unavailable. OASIS MQTT 3.1.1 sec. 3.2.2.3 Table 3.1.
pub const MQTT_CONNACK_SERVER_UNAVAILABLE: u8 = 0x03;
/// Connection refused: bad username or password. OASIS MQTT 3.1.1 sec. 3.2.2.3 Table 3.1.
pub const MQTT_CONNACK_BAD_USERNAME_OR_PASSWORD: u8 = 0x04;
/// Connection refused: not authorized. OASIS MQTT 3.1.1 sec. 3.2.2.3 Table 3.1.
pub const MQTT_CONNACK_NOT_AUTHORIZED: u8 = 0x05;

// ---------------------------------------------------------------------------
// SUBACK return codes (OASIS MQTT 3.1.1 sec. 3.9.3)
// ---------------------------------------------------------------------------

/// SUBACK maximum QoS 0 return code. OASIS MQTT 3.1.1 sec. 3.9.3.
pub const MQTT_SUBACK_MAX_QOS_0: u8 = 0x00;
/// SUBACK maximum QoS 1 return code. OASIS MQTT 3.1.1 sec. 3.9.3.
pub const MQTT_SUBACK_MAX_QOS_1: u8 = 0x01;
/// SUBACK maximum QoS 2 return code. OASIS MQTT 3.1.1 sec. 3.9.3.
pub const MQTT_SUBACK_MAX_QOS_2: u8 = 0x02;
/// SUBACK failure return code. OASIS MQTT 3.1.1 sec. 3.9.3.
pub const MQTT_SUBACK_FAILURE: u8 = 0x80;
