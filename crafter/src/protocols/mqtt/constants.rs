//! MQTT wire constants.
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
/// MQTT 5.0 protocol name carried in CONNECT. OASIS MQTT 5.0 sec. 3.1.2.1.
pub const MQTT_5_PROTOCOL_NAME: &str = "MQTT";
/// MQTT 5.0 protocol level carried in CONNECT. OASIS MQTT 5.0 sec. 3.1.2.2.
pub const MQTT_5_PROTOCOL_LEVEL: u8 = 5;

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
/// AUTH control packet type. OASIS MQTT 5.0 sec. 2.2.1 Table 2-1; sec. 3.15.
pub const MQTT_TYPE_AUTH: u8 = 15;

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
/// AUTH fixed header flags. OASIS MQTT 5.0 sec. 3.15.1.
pub const MQTT_FLAGS_AUTH: u8 = 0x0;

// ---------------------------------------------------------------------------
// PUBLISH fixed-header flags (OASIS MQTT 3.1.1 sec. 3.3.1)
// ---------------------------------------------------------------------------

/// PUBLISH RETAIN flag bit. OASIS MQTT 3.1.1 sec. 3.3.1.3.
pub const MQTT_PUBLISH_FLAG_RETAIN: u8 = 0x01;
/// PUBLISH QoS two-bit field mask. OASIS MQTT 3.1.1 sec. 3.3.1.2.
pub const MQTT_PUBLISH_FLAG_QOS_MASK: u8 = 0x06;
/// PUBLISH DUP flag bit. OASIS MQTT 3.1.1 sec. 3.3.1.1.
pub const MQTT_PUBLISH_FLAG_DUP: u8 = 0x08;
/// PUBLISH QoS 0, at most once. OASIS MQTT 3.1.1 sec. 3.3.1.2 Table 3.2.
pub const MQTT_PUBLISH_QOS_0: u8 = 0;
/// PUBLISH QoS 1, at least once. OASIS MQTT 3.1.1 sec. 3.3.1.2 Table 3.2.
pub const MQTT_PUBLISH_QOS_1: u8 = 1;
/// PUBLISH QoS 2, exactly once. OASIS MQTT 3.1.1 sec. 3.3.1.2 Table 3.2.
pub const MQTT_PUBLISH_QOS_2: u8 = 2;
/// Reserved PUBLISH QoS value. OASIS MQTT 3.1.1 sec. 3.3.1.2 Table 3.2.
pub const MQTT_PUBLISH_QOS_RESERVED: u8 = 3;

// ---------------------------------------------------------------------------
// CONNECT variable-header flags (OASIS MQTT 3.1.1 sec. 3.1.2.3)
// ---------------------------------------------------------------------------

/// CONNECT Clean Session flag bit. OASIS MQTT 3.1.1 sec. 3.1.2.4.
pub const MQTT_CONNECT_FLAG_CLEAN_SESSION: u8 = 0x02;
/// CONNECT Will Flag bit. OASIS MQTT 3.1.1 sec. 3.1.2.5.
pub const MQTT_CONNECT_FLAG_WILL: u8 = 0x04;
/// CONNECT Will QoS two-bit field mask. OASIS MQTT 3.1.1 sec. 3.1.2.6.
pub const MQTT_CONNECT_FLAG_WILL_QOS_MASK: u8 = 0x18;
/// CONNECT Will Retain flag bit. OASIS MQTT 3.1.1 sec. 3.1.2.7.
pub const MQTT_CONNECT_FLAG_WILL_RETAIN: u8 = 0x20;
/// CONNECT Password flag bit. OASIS MQTT 3.1.1 sec. 3.1.2.9.
pub const MQTT_CONNECT_FLAG_PASSWORD: u8 = 0x40;
/// CONNECT User Name flag bit. OASIS MQTT 3.1.1 sec. 3.1.2.8.
pub const MQTT_CONNECT_FLAG_USER_NAME: u8 = 0x80;

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

// ---------------------------------------------------------------------------
// MQTT 5.0 property identifiers (OASIS MQTT 5.0 sec. 2.2.2.2 Table 2-4)
// ---------------------------------------------------------------------------

/// Payload Format Indicator, Byte; PUBLISH, Will Properties.
pub const MQTT_PROP_PAYLOAD_FORMAT_INDICATOR: u8 = 0x01;
/// Message Expiry Interval, Four Byte Integer; PUBLISH, Will Properties.
pub const MQTT_PROP_MESSAGE_EXPIRY_INTERVAL: u8 = 0x02;
/// Content Type, UTF-8 Encoded String; PUBLISH, Will Properties.
pub const MQTT_PROP_CONTENT_TYPE: u8 = 0x03;
/// Response Topic, UTF-8 Encoded String; PUBLISH, Will Properties.
pub const MQTT_PROP_RESPONSE_TOPIC: u8 = 0x08;
/// Correlation Data, Binary Data; PUBLISH, Will Properties.
pub const MQTT_PROP_CORRELATION_DATA: u8 = 0x09;
/// Subscription Identifier, Variable Byte Integer; PUBLISH, SUBSCRIBE.
pub const MQTT_PROP_SUBSCRIPTION_IDENTIFIER: u8 = 0x0b;
/// Session Expiry Interval, Four Byte Integer; CONNECT, CONNACK, DISCONNECT.
pub const MQTT_PROP_SESSION_EXPIRY_INTERVAL: u8 = 0x11;
/// Assigned Client Identifier, UTF-8 Encoded String; CONNACK.
pub const MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER: u8 = 0x12;
/// Server Keep Alive, Two Byte Integer; CONNACK.
pub const MQTT_PROP_SERVER_KEEP_ALIVE: u8 = 0x13;
/// Authentication Method, UTF-8 Encoded String; CONNECT, CONNACK, AUTH.
pub const MQTT_PROP_AUTHENTICATION_METHOD: u8 = 0x15;
/// Authentication Data, Binary Data; CONNECT, CONNACK, AUTH.
pub const MQTT_PROP_AUTHENTICATION_DATA: u8 = 0x16;
/// Request Problem Information, Byte; CONNECT.
pub const MQTT_PROP_REQUEST_PROBLEM_INFORMATION: u8 = 0x17;
/// Will Delay Interval, Four Byte Integer; Will Properties.
pub const MQTT_PROP_WILL_DELAY_INTERVAL: u8 = 0x18;
/// Request Response Information, Byte; CONNECT.
pub const MQTT_PROP_REQUEST_RESPONSE_INFORMATION: u8 = 0x19;
/// Response Information, UTF-8 Encoded String; CONNACK.
pub const MQTT_PROP_RESPONSE_INFORMATION: u8 = 0x1a;
/// Server Reference, UTF-8 Encoded String; CONNACK, DISCONNECT.
pub const MQTT_PROP_SERVER_REFERENCE: u8 = 0x1c;
/// Reason String, UTF-8 Encoded String; acknowledgement, DISCONNECT, and AUTH packets.
pub const MQTT_PROP_REASON_STRING: u8 = 0x1f;
/// Receive Maximum, Two Byte Integer; CONNECT, CONNACK.
pub const MQTT_PROP_RECEIVE_MAXIMUM: u8 = 0x21;
/// Topic Alias Maximum, Two Byte Integer; CONNECT, CONNACK.
pub const MQTT_PROP_TOPIC_ALIAS_MAXIMUM: u8 = 0x22;
/// Topic Alias, Two Byte Integer; PUBLISH.
pub const MQTT_PROP_TOPIC_ALIAS: u8 = 0x23;
/// Maximum QoS, Byte; CONNACK.
pub const MQTT_PROP_MAXIMUM_QOS: u8 = 0x24;
/// Retain Available, Byte; CONNACK.
pub const MQTT_PROP_RETAIN_AVAILABLE: u8 = 0x25;
/// User Property, UTF-8 String Pair; many MQTT 5.0 packet/property contexts.
pub const MQTT_PROP_USER_PROPERTY: u8 = 0x26;
/// Maximum Packet Size, Four Byte Integer; CONNECT, CONNACK.
pub const MQTT_PROP_MAXIMUM_PACKET_SIZE: u8 = 0x27;
/// Wildcard Subscription Available, Byte; CONNACK.
pub const MQTT_PROP_WILDCARD_SUBSCRIPTION_AVAILABLE: u8 = 0x28;
/// Subscription Identifier Available, Byte; CONNACK.
pub const MQTT_PROP_SUBSCRIPTION_IDENTIFIER_AVAILABLE: u8 = 0x29;
/// Shared Subscription Available, Byte; CONNACK.
pub const MQTT_PROP_SHARED_SUBSCRIPTION_AVAILABLE: u8 = 0x2a;

// ---------------------------------------------------------------------------
// MQTT 5.0 reason codes (OASIS MQTT 5.0 sec. 2.4 Table 2-6)
// ---------------------------------------------------------------------------

/// Success / normal success-class reason code.
pub const MQTT_REASON_SUCCESS: u8 = 0x00;
/// Normal disconnection. DISCONNECT.
pub const MQTT_REASON_NORMAL_DISCONNECTION: u8 = 0x00;
/// Granted QoS 0. SUBACK.
pub const MQTT_REASON_GRANTED_QOS_0: u8 = 0x00;
/// Granted QoS 1. SUBACK.
pub const MQTT_REASON_GRANTED_QOS_1: u8 = 0x01;
/// Granted QoS 2. SUBACK.
pub const MQTT_REASON_GRANTED_QOS_2: u8 = 0x02;
/// Disconnect with Will Message. DISCONNECT.
pub const MQTT_REASON_DISCONNECT_WITH_WILL_MESSAGE: u8 = 0x04;
/// No matching subscribers. PUBACK, PUBREC.
pub const MQTT_REASON_NO_MATCHING_SUBSCRIBERS: u8 = 0x10;
/// No subscription existed. UNSUBACK.
pub const MQTT_REASON_NO_SUBSCRIPTION_EXISTED: u8 = 0x11;
/// Continue authentication. AUTH.
pub const MQTT_REASON_CONTINUE_AUTHENTICATION: u8 = 0x18;
/// Re-authenticate. AUTH.
pub const MQTT_REASON_RE_AUTHENTICATE: u8 = 0x19;
/// Unspecified error.
pub const MQTT_REASON_UNSPECIFIED_ERROR: u8 = 0x80;
/// Malformed Packet.
pub const MQTT_REASON_MALFORMED_PACKET: u8 = 0x81;
/// Protocol Error.
pub const MQTT_REASON_PROTOCOL_ERROR: u8 = 0x82;
/// Implementation specific error.
pub const MQTT_REASON_IMPLEMENTATION_SPECIFIC_ERROR: u8 = 0x83;
/// Unsupported Protocol Version. CONNACK.
pub const MQTT_REASON_UNSUPPORTED_PROTOCOL_VERSION: u8 = 0x84;
/// Client Identifier not valid. CONNACK.
pub const MQTT_REASON_CLIENT_IDENTIFIER_NOT_VALID: u8 = 0x85;
/// Bad User Name or Password. CONNACK.
pub const MQTT_REASON_BAD_USERNAME_OR_PASSWORD: u8 = 0x86;
/// Not authorized.
pub const MQTT_REASON_NOT_AUTHORIZED: u8 = 0x87;
/// Server unavailable. CONNACK.
pub const MQTT_REASON_SERVER_UNAVAILABLE: u8 = 0x88;
/// Server busy. CONNACK, DISCONNECT.
pub const MQTT_REASON_SERVER_BUSY: u8 = 0x89;
/// Banned. CONNACK.
pub const MQTT_REASON_BANNED: u8 = 0x8a;
/// Server shutting down. DISCONNECT.
pub const MQTT_REASON_SERVER_SHUTTING_DOWN: u8 = 0x8b;
/// Bad authentication method. CONNACK, DISCONNECT.
pub const MQTT_REASON_BAD_AUTHENTICATION_METHOD: u8 = 0x8c;
/// Keep Alive timeout. DISCONNECT.
pub const MQTT_REASON_KEEP_ALIVE_TIMEOUT: u8 = 0x8d;
/// Session taken over. DISCONNECT.
pub const MQTT_REASON_SESSION_TAKEN_OVER: u8 = 0x8e;
/// Topic Filter invalid. SUBACK, UNSUBACK, DISCONNECT.
pub const MQTT_REASON_TOPIC_FILTER_INVALID: u8 = 0x8f;
/// Topic Name invalid. CONNACK, PUBACK, PUBREC, DISCONNECT.
pub const MQTT_REASON_TOPIC_NAME_INVALID: u8 = 0x90;
/// Packet Identifier in use. PUBACK, PUBREC, SUBACK, UNSUBACK.
pub const MQTT_REASON_PACKET_IDENTIFIER_IN_USE: u8 = 0x91;
/// Packet Identifier not found. PUBREL, PUBCOMP.
pub const MQTT_REASON_PACKET_IDENTIFIER_NOT_FOUND: u8 = 0x92;
/// Receive Maximum exceeded. DISCONNECT.
pub const MQTT_REASON_RECEIVE_MAXIMUM_EXCEEDED: u8 = 0x93;
/// Topic Alias invalid. DISCONNECT.
pub const MQTT_REASON_TOPIC_ALIAS_INVALID: u8 = 0x94;
/// Packet too large. CONNACK, DISCONNECT.
pub const MQTT_REASON_PACKET_TOO_LARGE: u8 = 0x95;
/// Message rate too high. DISCONNECT.
pub const MQTT_REASON_MESSAGE_RATE_TOO_HIGH: u8 = 0x96;
/// Quota exceeded.
pub const MQTT_REASON_QUOTA_EXCEEDED: u8 = 0x97;
/// Administrative action. DISCONNECT.
pub const MQTT_REASON_ADMINISTRATIVE_ACTION: u8 = 0x98;
/// Payload format invalid. CONNACK, PUBACK, PUBREC, DISCONNECT.
pub const MQTT_REASON_PAYLOAD_FORMAT_INVALID: u8 = 0x99;
/// Retain not supported. CONNACK, DISCONNECT.
pub const MQTT_REASON_RETAIN_NOT_SUPPORTED: u8 = 0x9a;
/// QoS not supported. CONNACK, DISCONNECT.
pub const MQTT_REASON_QOS_NOT_SUPPORTED: u8 = 0x9b;
/// Use another server. CONNACK, DISCONNECT.
pub const MQTT_REASON_USE_ANOTHER_SERVER: u8 = 0x9c;
/// Server moved. CONNACK, DISCONNECT.
pub const MQTT_REASON_SERVER_MOVED: u8 = 0x9d;
/// Shared Subscriptions not supported. SUBACK, DISCONNECT.
pub const MQTT_REASON_SHARED_SUBSCRIPTIONS_NOT_SUPPORTED: u8 = 0x9e;
/// Connection rate exceeded. CONNACK, DISCONNECT.
pub const MQTT_REASON_CONNECTION_RATE_EXCEEDED: u8 = 0x9f;
/// Maximum connect time. DISCONNECT.
pub const MQTT_REASON_MAXIMUM_CONNECT_TIME: u8 = 0xa0;
/// Subscription Identifiers not supported. SUBACK, DISCONNECT.
pub const MQTT_REASON_SUBSCRIPTION_IDENTIFIERS_NOT_SUPPORTED: u8 = 0xa1;
/// Wildcard Subscriptions not supported. SUBACK, DISCONNECT.
pub const MQTT_REASON_WILDCARD_SUBSCRIPTIONS_NOT_SUPPORTED: u8 = 0xa2;

/// MQTT 5.0 CONNACK reason-code set. OASIS MQTT 5.0 sec. 3.2.2.2 Table 3-1.
pub const MQTT_CONNACK_REASON_CODES: [u8; 22] = [
    MQTT_REASON_SUCCESS,
    MQTT_REASON_UNSPECIFIED_ERROR,
    MQTT_REASON_MALFORMED_PACKET,
    MQTT_REASON_PROTOCOL_ERROR,
    MQTT_REASON_IMPLEMENTATION_SPECIFIC_ERROR,
    MQTT_REASON_UNSUPPORTED_PROTOCOL_VERSION,
    MQTT_REASON_CLIENT_IDENTIFIER_NOT_VALID,
    MQTT_REASON_BAD_USERNAME_OR_PASSWORD,
    MQTT_REASON_NOT_AUTHORIZED,
    MQTT_REASON_SERVER_UNAVAILABLE,
    MQTT_REASON_SERVER_BUSY,
    MQTT_REASON_BANNED,
    MQTT_REASON_BAD_AUTHENTICATION_METHOD,
    MQTT_REASON_TOPIC_NAME_INVALID,
    MQTT_REASON_PACKET_TOO_LARGE,
    MQTT_REASON_QUOTA_EXCEEDED,
    MQTT_REASON_PAYLOAD_FORMAT_INVALID,
    MQTT_REASON_RETAIN_NOT_SUPPORTED,
    MQTT_REASON_QOS_NOT_SUPPORTED,
    MQTT_REASON_USE_ANOTHER_SERVER,
    MQTT_REASON_SERVER_MOVED,
    MQTT_REASON_CONNECTION_RATE_EXCEEDED,
];

/// MQTT 5.0 PUBACK reason-code set. OASIS MQTT 5.0 sec. 3.4.2.1 Table 3-4.
pub const MQTT_PUBACK_REASON_CODES: [u8; 9] = [
    MQTT_REASON_SUCCESS,
    MQTT_REASON_NO_MATCHING_SUBSCRIBERS,
    MQTT_REASON_UNSPECIFIED_ERROR,
    MQTT_REASON_IMPLEMENTATION_SPECIFIC_ERROR,
    MQTT_REASON_NOT_AUTHORIZED,
    MQTT_REASON_TOPIC_NAME_INVALID,
    MQTT_REASON_PACKET_IDENTIFIER_IN_USE,
    MQTT_REASON_QUOTA_EXCEEDED,
    MQTT_REASON_PAYLOAD_FORMAT_INVALID,
];

/// MQTT 5.0 PUBREC reason-code set. OASIS MQTT 5.0 sec. 3.5.2.1 Table 3-5.
pub const MQTT_PUBREC_REASON_CODES: [u8; 9] = MQTT_PUBACK_REASON_CODES;

/// MQTT 5.0 PUBREL reason-code set. OASIS MQTT 5.0 sec. 3.6.2.1 Table 3-6.
pub const MQTT_PUBREL_REASON_CODES: [u8; 2] =
    [MQTT_REASON_SUCCESS, MQTT_REASON_PACKET_IDENTIFIER_NOT_FOUND];

/// MQTT 5.0 PUBCOMP reason-code set. OASIS MQTT 5.0 sec. 3.7.2.1 Table 3-7.
pub const MQTT_PUBCOMP_REASON_CODES: [u8; 2] = MQTT_PUBREL_REASON_CODES;

/// MQTT 5.0 SUBACK reason-code set. OASIS MQTT 5.0 sec. 3.9.3 Table 3-9.
pub const MQTT_SUBACK_REASON_CODES: [u8; 12] = [
    MQTT_REASON_GRANTED_QOS_0,
    MQTT_REASON_GRANTED_QOS_1,
    MQTT_REASON_GRANTED_QOS_2,
    MQTT_REASON_UNSPECIFIED_ERROR,
    MQTT_REASON_IMPLEMENTATION_SPECIFIC_ERROR,
    MQTT_REASON_NOT_AUTHORIZED,
    MQTT_REASON_TOPIC_FILTER_INVALID,
    MQTT_REASON_PACKET_IDENTIFIER_IN_USE,
    MQTT_REASON_QUOTA_EXCEEDED,
    MQTT_REASON_SHARED_SUBSCRIPTIONS_NOT_SUPPORTED,
    MQTT_REASON_SUBSCRIPTION_IDENTIFIERS_NOT_SUPPORTED,
    MQTT_REASON_WILDCARD_SUBSCRIPTIONS_NOT_SUPPORTED,
];

/// MQTT 5.0 UNSUBACK reason-code set. OASIS MQTT 5.0 sec. 3.11.3 Table 3-10.
pub const MQTT_UNSUBACK_REASON_CODES: [u8; 7] = [
    MQTT_REASON_SUCCESS,
    MQTT_REASON_NO_SUBSCRIPTION_EXISTED,
    MQTT_REASON_UNSPECIFIED_ERROR,
    MQTT_REASON_IMPLEMENTATION_SPECIFIC_ERROR,
    MQTT_REASON_NOT_AUTHORIZED,
    MQTT_REASON_TOPIC_FILTER_INVALID,
    MQTT_REASON_PACKET_IDENTIFIER_IN_USE,
];

/// MQTT 5.0 DISCONNECT reason-code set. OASIS MQTT 5.0 sec. 3.14.2.1 Table 3-12.
pub const MQTT_DISCONNECT_REASON_CODES: [u8; 29] = [
    MQTT_REASON_NORMAL_DISCONNECTION,
    MQTT_REASON_DISCONNECT_WITH_WILL_MESSAGE,
    MQTT_REASON_UNSPECIFIED_ERROR,
    MQTT_REASON_MALFORMED_PACKET,
    MQTT_REASON_PROTOCOL_ERROR,
    MQTT_REASON_IMPLEMENTATION_SPECIFIC_ERROR,
    MQTT_REASON_NOT_AUTHORIZED,
    MQTT_REASON_SERVER_BUSY,
    MQTT_REASON_SERVER_SHUTTING_DOWN,
    MQTT_REASON_KEEP_ALIVE_TIMEOUT,
    MQTT_REASON_SESSION_TAKEN_OVER,
    MQTT_REASON_TOPIC_FILTER_INVALID,
    MQTT_REASON_TOPIC_NAME_INVALID,
    MQTT_REASON_RECEIVE_MAXIMUM_EXCEEDED,
    MQTT_REASON_TOPIC_ALIAS_INVALID,
    MQTT_REASON_PACKET_TOO_LARGE,
    MQTT_REASON_MESSAGE_RATE_TOO_HIGH,
    MQTT_REASON_QUOTA_EXCEEDED,
    MQTT_REASON_ADMINISTRATIVE_ACTION,
    MQTT_REASON_PAYLOAD_FORMAT_INVALID,
    MQTT_REASON_RETAIN_NOT_SUPPORTED,
    MQTT_REASON_QOS_NOT_SUPPORTED,
    MQTT_REASON_USE_ANOTHER_SERVER,
    MQTT_REASON_SERVER_MOVED,
    MQTT_REASON_SHARED_SUBSCRIPTIONS_NOT_SUPPORTED,
    MQTT_REASON_CONNECTION_RATE_EXCEEDED,
    MQTT_REASON_MAXIMUM_CONNECT_TIME,
    MQTT_REASON_SUBSCRIPTION_IDENTIFIERS_NOT_SUPPORTED,
    MQTT_REASON_WILDCARD_SUBSCRIPTIONS_NOT_SUPPORTED,
];

/// MQTT 5.0 AUTH reason-code set. OASIS MQTT 5.0 sec. 3.15.2.1 Table 3-11.
pub const MQTT_AUTH_REASON_CODES: [u8; 3] = [
    MQTT_REASON_SUCCESS,
    MQTT_REASON_CONTINUE_AUTHENTICATION,
    MQTT_REASON_RE_AUTHENTICATE,
];

// ---------------------------------------------------------------------------
// MQTT 5.0 subscription options (OASIS MQTT 5.0 sec. 3.8.3.1)
// ---------------------------------------------------------------------------

/// Subscription Options QoS mask, bits 0-1.
pub const MQTT_SUBOPT_QOS_MASK: u8 = 0x03;
/// Subscription Options No Local bit, bit 2.
pub const MQTT_SUBOPT_NO_LOCAL: u8 = 0x04;
/// Subscription Options Retain As Published bit, bit 3.
pub const MQTT_SUBOPT_RETAIN_AS_PUBLISHED: u8 = 0x08;
/// Subscription Options Retain Handling mask, bits 4-5.
pub const MQTT_SUBOPT_RETAIN_HANDLING_MASK: u8 = 0x30;
/// Subscription Options Retain Handling shift.
pub const MQTT_SUBOPT_RETAIN_HANDLING_SHIFT: u8 = 4;
/// Subscription Options reserved mask, bits 6-7, which must be zero.
pub const MQTT_SUBOPT_RESERVED_MASK: u8 = 0xc0;
/// Retain Handling value: send retained messages at subscribe time.
pub const MQTT_SUBOPT_RETAIN_SEND_AT_SUBSCRIBE: u8 = 0;
/// Retain Handling value: send retained messages only if the subscription is new.
pub const MQTT_SUBOPT_RETAIN_SEND_IF_NEW: u8 = 1;
/// Retain Handling value: do not send retained messages at subscribe time.
pub const MQTT_SUBOPT_RETAIN_DO_NOT_SEND: u8 = 2;
/// Reserved Retain Handling value.
pub const MQTT_SUBOPT_RETAIN_RESERVED: u8 = 3;
