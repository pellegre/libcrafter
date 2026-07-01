//! Source-backed TLS constants and registry labels.
//!
//! Codepoints come from `.agents/docs/tls-codepoints.md`, which records the
//! selected IANA TLS registry rows and RFC evidence for this TLS-over-TCP
//! packet-layer bootstrap. Unknown, private-use, reserved, GREASE, and
//! unassigned values stay numeric so later builders and decoders can preserve
//! caller-supplied or observed wire values.

use core::fmt;

// ---------------------------------------------------------------------------
// Shared registry status
// ---------------------------------------------------------------------------

/// Source-backed assignment status for TLS registry codepoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsCodepointStatus {
    /// Registered service or codepoint selected for ordinary packet defaults.
    DefaultEligible,
    /// Registered codepoint selected for labels but not for default builders.
    LabelEligible,
    /// Registered row that is useful to label but deferred to a later grammar step.
    Deferred,
    /// Registered row preserved by value but not selected for TLS-over-TCP typing.
    PreserveOnly,
    /// Compatibility value that remains inspectable but is not a modern default.
    Compatibility,
    /// Obsolete protocol value preserved for explicit construction or decode.
    Obsolete,
    /// DTLS-only or DTLS-oriented row outside the TLS-over-TCP record grammar.
    DtlsOnly,
    /// Reserved codepoint.
    Reserved,
    /// Reserved GREASE value from RFC 8701.
    ReservedGrease,
    /// Reserved for private use.
    PrivateUse,
    /// Reserved for experimental use.
    Experimental,
    /// Registry value in an unassigned range.
    Unassigned,
    /// Value outside the source-backed table for this bootstrap.
    Unknown,
}

impl TlsCodepointStatus {
    /// Stable lowercase status label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::DefaultEligible => "default-eligible",
            Self::LabelEligible => "label-eligible",
            Self::Deferred => "deferred",
            Self::PreserveOnly => "preserve-only",
            Self::Compatibility => "compatibility",
            Self::Obsolete => "obsolete",
            Self::DtlsOnly => "dtls-only",
            Self::Reserved => "reserved",
            Self::ReservedGrease => "reserved-grease",
            Self::PrivateUse => "private-use",
            Self::Experimental => "experimental",
            Self::Unassigned => "unassigned",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for TlsCodepointStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// Common TLS-over-TCP ports
// ---------------------------------------------------------------------------

/// HTTPS TLS-over-TCP port and default generic TLS service port.
pub const TLS_PORT: u16 = 443;
/// HTTPS TLS-over-TCP port.
pub const TLS_PORT_HTTPS: u16 = TLS_PORT;
/// DNS-over-TLS TCP port.
pub const TLS_PORT_DNS_OVER_TLS: u16 = 853;
/// MQTT-over-TLS TCP port.
pub const TLS_PORT_MQTT_OVER_TLS: u16 = 8883;
/// Documentation/testing TLS port used by examples and fixtures.
pub const TLS_PORT_EXAMPLE_TESTING: u16 = 4433;

/// Common TLS-over-TCP ports selected for later conservative dispatch gates.
pub const TLS_COMMON_TCP_PORTS: [u16; 4] = [
    TLS_PORT_HTTPS,
    TLS_PORT_DNS_OVER_TLS,
    TLS_PORT_MQTT_OVER_TLS,
    TLS_PORT_EXAMPLE_TESTING,
];

/// Return the selected service label for a common TLS-over-TCP port.
pub const fn tls_tcp_port_name(port: u16) -> Option<&'static str> {
    match port {
        TLS_PORT_HTTPS => Some("https"),
        TLS_PORT_DNS_OVER_TLS => Some("domain-s"),
        TLS_PORT_MQTT_OVER_TLS => Some("secure-mqtt"),
        TLS_PORT_EXAMPLE_TESTING => Some("tls-example"),
        _ => None,
    }
}

/// Classify a selected TLS-over-TCP port.
pub const fn tls_tcp_port_status(port: u16) -> TlsCodepointStatus {
    match port {
        TLS_PORT_HTTPS | TLS_PORT_DNS_OVER_TLS | TLS_PORT_MQTT_OVER_TLS => {
            TlsCodepointStatus::DefaultEligible
        }
        TLS_PORT_EXAMPLE_TESTING => TlsCodepointStatus::PreserveOnly,
        _ => TlsCodepointStatus::Unknown,
    }
}

/// Stable port label that preserves unknown values numerically.
pub fn tls_tcp_port_label(port: u16) -> String {
    tls_tcp_port_name(port)
        .map(str::to_string)
        .unwrap_or_else(|| format!("tcp-port-{port}"))
}

// ---------------------------------------------------------------------------
// ProtocolVersion
// ---------------------------------------------------------------------------

/// Historical SSL 3.0 version value, preserved by value only.
pub const TLS_VERSION_SSL_3_0: u16 = 0x0300;
/// TLS 1.0 protocol version value.
pub const TLS_VERSION_1_0: u16 = 0x0301;
/// TLS 1.1 protocol version value.
pub const TLS_VERSION_1_1: u16 = 0x0302;
/// TLS 1.2 protocol version value.
pub const TLS_VERSION_1_2: u16 = 0x0303;
/// TLS 1.3 supported_versions protocol version value.
pub const TLS_VERSION_1_3: u16 = 0x0304;
/// TLS 1.3 legacy record and hello version value.
pub const TLS_LEGACY_VERSION: u16 = TLS_VERSION_1_2;
/// TLS 1.3 supported_versions negotiated value.
pub const TLS_CURRENT_VERSION: u16 = TLS_VERSION_1_3;

/// Return true for the sparse two-octet TLS GREASE pattern from RFC 8701.
pub const fn is_tls_grease_u16(value: u16) -> bool {
    let high = (value >> 8) as u8;
    let low = value as u8;
    high == low && (value & 0x0f0f) == 0x0a0a
}

/// Return the source-backed protocol version name.
pub const fn tls_protocol_version_name(version: u16) -> Option<&'static str> {
    match version {
        TLS_VERSION_SSL_3_0 => Some("SSL 3.0"),
        TLS_VERSION_1_0 => Some("TLS 1.0"),
        TLS_VERSION_1_1 => Some("TLS 1.1"),
        TLS_VERSION_1_2 => Some("TLS 1.2"),
        TLS_VERSION_1_3 => Some("TLS 1.3"),
        _ => None,
    }
}

/// Classify a TLS ProtocolVersion value.
pub const fn tls_protocol_version_status(version: u16) -> TlsCodepointStatus {
    match version {
        TLS_VERSION_SSL_3_0 | TLS_VERSION_1_1 => TlsCodepointStatus::Obsolete,
        TLS_VERSION_1_0 => TlsCodepointStatus::Compatibility,
        TLS_VERSION_1_2 | TLS_VERSION_1_3 => TlsCodepointStatus::DefaultEligible,
        _ if is_tls_grease_u16(version) => TlsCodepointStatus::ReservedGrease,
        _ => TlsCodepointStatus::Unknown,
    }
}

/// Human-readable protocol version label preserving unknown values.
pub fn tls_protocol_version_label(version: u16) -> String {
    label_with_known_name(
        tls_protocol_version_name(version),
        tls_protocol_version_status(version),
        "protocol version",
        version as u64,
        4,
    )
}

// ---------------------------------------------------------------------------
// ContentType
// ---------------------------------------------------------------------------

/// TLS record ContentType change_cipher_spec.
pub const TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 20;
/// TLS record ContentType alert.
pub const TLS_CONTENT_TYPE_ALERT: u8 = 21;
/// TLS record ContentType handshake.
pub const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 22;
/// TLS record ContentType application_data.
pub const TLS_CONTENT_TYPE_APPLICATION_DATA: u8 = 23;
/// TLS record ContentType heartbeat, selected for packet-only modeling.
pub const TLS_CONTENT_TYPE_HEARTBEAT: u8 = 24;
/// TLS record ContentType tls12_cid, preserved for explicit values only.
pub const TLS_CONTENT_TYPE_TLS12_CID: u8 = 25;
/// DTLS 1.3 ACK content type, outside TLS-over-TCP.
pub const TLS_CONTENT_TYPE_ACK: u8 = 26;
/// DTLS return_routability_check content type, outside TLS-over-TCP.
pub const TLS_CONTENT_TYPE_RETURN_ROUTABILITY_CHECK: u8 = 27;

/// Return the selected TLS ContentType name.
pub const fn tls_content_type_name(content_type: u8) -> Option<&'static str> {
    match content_type {
        TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC => Some("change_cipher_spec"),
        TLS_CONTENT_TYPE_ALERT => Some("alert"),
        TLS_CONTENT_TYPE_HANDSHAKE => Some("handshake"),
        TLS_CONTENT_TYPE_APPLICATION_DATA => Some("application_data"),
        TLS_CONTENT_TYPE_HEARTBEAT => Some("heartbeat"),
        TLS_CONTENT_TYPE_TLS12_CID => Some("tls12_cid"),
        TLS_CONTENT_TYPE_ACK => Some("ACK"),
        TLS_CONTENT_TYPE_RETURN_ROUTABILITY_CHECK => Some("return_routability_check"),
        _ => None,
    }
}

/// Classify a TLS ContentType value.
pub const fn tls_content_type_status(content_type: u8) -> TlsCodepointStatus {
    match content_type {
        TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC
        | TLS_CONTENT_TYPE_ALERT
        | TLS_CONTENT_TYPE_HANDSHAKE
        | TLS_CONTENT_TYPE_APPLICATION_DATA => TlsCodepointStatus::DefaultEligible,
        TLS_CONTENT_TYPE_HEARTBEAT => TlsCodepointStatus::LabelEligible,
        TLS_CONTENT_TYPE_TLS12_CID => TlsCodepointStatus::PreserveOnly,
        TLS_CONTENT_TYPE_ACK | TLS_CONTENT_TYPE_RETURN_ROUTABILITY_CHECK => {
            TlsCodepointStatus::DtlsOnly
        }
        32..=63 => TlsCodepointStatus::Reserved,
        _ => TlsCodepointStatus::Unassigned,
    }
}

/// Human-readable ContentType label preserving unknown values.
pub fn tls_content_type_label(content_type: u8) -> String {
    label_with_known_name(
        tls_content_type_name(content_type),
        tls_content_type_status(content_type),
        "content type",
        content_type as u64,
        2,
    )
}

// ---------------------------------------------------------------------------
// AlertLevel and AlertDescription
// ---------------------------------------------------------------------------

/// TLS AlertLevel warning.
pub const TLS_ALERT_LEVEL_WARNING: u8 = 1;
/// TLS AlertLevel fatal.
pub const TLS_ALERT_LEVEL_FATAL: u8 = 2;

/// Return the selected TLS AlertLevel name.
pub const fn tls_alert_level_name(level: u8) -> Option<&'static str> {
    match level {
        TLS_ALERT_LEVEL_WARNING => Some("warning"),
        TLS_ALERT_LEVEL_FATAL => Some("fatal"),
        _ => None,
    }
}

/// Classify a TLS AlertLevel value.
pub const fn tls_alert_level_status(level: u8) -> TlsCodepointStatus {
    match level {
        TLS_ALERT_LEVEL_WARNING | TLS_ALERT_LEVEL_FATAL => TlsCodepointStatus::DefaultEligible,
        _ => TlsCodepointStatus::Unassigned,
    }
}

/// Human-readable AlertLevel label preserving unknown values.
pub fn tls_alert_level_label(level: u8) -> String {
    label_with_known_name(
        tls_alert_level_name(level),
        tls_alert_level_status(level),
        "alert level",
        level as u64,
        2,
    )
}

/// TLS AlertDescription close_notify.
pub const TLS_ALERT_DESCRIPTION_CLOSE_NOTIFY: u8 = 0;
/// TLS AlertDescription unexpected_message.
pub const TLS_ALERT_DESCRIPTION_UNEXPECTED_MESSAGE: u8 = 10;
/// TLS AlertDescription bad_record_mac.
pub const TLS_ALERT_DESCRIPTION_BAD_RECORD_MAC: u8 = 20;
/// TLS AlertDescription decryption_failed_RESERVED.
pub const TLS_ALERT_DESCRIPTION_DECRYPTION_FAILED_RESERVED: u8 = 21;
/// TLS AlertDescription record_overflow.
pub const TLS_ALERT_DESCRIPTION_RECORD_OVERFLOW: u8 = 22;
/// TLS AlertDescription decompression_failure_RESERVED.
pub const TLS_ALERT_DESCRIPTION_DECOMPRESSION_FAILURE_RESERVED: u8 = 30;
/// TLS AlertDescription handshake_failure.
pub const TLS_ALERT_DESCRIPTION_HANDSHAKE_FAILURE: u8 = 40;
/// TLS AlertDescription no_certificate_RESERVED.
pub const TLS_ALERT_DESCRIPTION_NO_CERTIFICATE_RESERVED: u8 = 41;
/// TLS AlertDescription bad_certificate.
pub const TLS_ALERT_DESCRIPTION_BAD_CERTIFICATE: u8 = 42;
/// TLS AlertDescription unsupported_certificate.
pub const TLS_ALERT_DESCRIPTION_UNSUPPORTED_CERTIFICATE: u8 = 43;
/// TLS AlertDescription certificate_revoked.
pub const TLS_ALERT_DESCRIPTION_CERTIFICATE_REVOKED: u8 = 44;
/// TLS AlertDescription certificate_expired.
pub const TLS_ALERT_DESCRIPTION_CERTIFICATE_EXPIRED: u8 = 45;
/// TLS AlertDescription certificate_unknown.
pub const TLS_ALERT_DESCRIPTION_CERTIFICATE_UNKNOWN: u8 = 46;
/// TLS AlertDescription illegal_parameter.
pub const TLS_ALERT_DESCRIPTION_ILLEGAL_PARAMETER: u8 = 47;
/// TLS AlertDescription unknown_ca.
pub const TLS_ALERT_DESCRIPTION_UNKNOWN_CA: u8 = 48;
/// TLS AlertDescription access_denied.
pub const TLS_ALERT_DESCRIPTION_ACCESS_DENIED: u8 = 49;
/// TLS AlertDescription decode_error.
pub const TLS_ALERT_DESCRIPTION_DECODE_ERROR: u8 = 50;
/// TLS AlertDescription decrypt_error.
pub const TLS_ALERT_DESCRIPTION_DECRYPT_ERROR: u8 = 51;
/// TLS AlertDescription too_many_cids_requested.
pub const TLS_ALERT_DESCRIPTION_TOO_MANY_CIDS_REQUESTED: u8 = 52;
/// TLS AlertDescription export_restriction_RESERVED.
pub const TLS_ALERT_DESCRIPTION_EXPORT_RESTRICTION_RESERVED: u8 = 60;
/// TLS AlertDescription protocol_version.
pub const TLS_ALERT_DESCRIPTION_PROTOCOL_VERSION: u8 = 70;
/// TLS AlertDescription insufficient_security.
pub const TLS_ALERT_DESCRIPTION_INSUFFICIENT_SECURITY: u8 = 71;
/// TLS AlertDescription internal_error.
pub const TLS_ALERT_DESCRIPTION_INTERNAL_ERROR: u8 = 80;
/// TLS AlertDescription inappropriate_fallback.
pub const TLS_ALERT_DESCRIPTION_INAPPROPRIATE_FALLBACK: u8 = 86;
/// TLS AlertDescription user_canceled.
pub const TLS_ALERT_DESCRIPTION_USER_CANCELED: u8 = 90;
/// TLS AlertDescription no_renegotiation_RESERVED.
pub const TLS_ALERT_DESCRIPTION_NO_RENEGOTIATION_RESERVED: u8 = 100;
/// TLS AlertDescription missing_extension.
pub const TLS_ALERT_DESCRIPTION_MISSING_EXTENSION: u8 = 109;
/// TLS AlertDescription unsupported_extension.
pub const TLS_ALERT_DESCRIPTION_UNSUPPORTED_EXTENSION: u8 = 110;
/// TLS AlertDescription certificate_unobtainable_RESERVED.
pub const TLS_ALERT_DESCRIPTION_CERTIFICATE_UNOBTAINABLE_RESERVED: u8 = 111;
/// TLS AlertDescription unrecognized_name.
pub const TLS_ALERT_DESCRIPTION_UNRECOGNIZED_NAME: u8 = 112;
/// TLS AlertDescription bad_certificate_status_response.
pub const TLS_ALERT_DESCRIPTION_BAD_CERTIFICATE_STATUS_RESPONSE: u8 = 113;
/// TLS AlertDescription bad_certificate_hash_value_RESERVED.
pub const TLS_ALERT_DESCRIPTION_BAD_CERTIFICATE_HASH_VALUE_RESERVED: u8 = 114;
/// TLS AlertDescription unknown_psk_identity.
pub const TLS_ALERT_DESCRIPTION_UNKNOWN_PSK_IDENTITY: u8 = 115;
/// TLS AlertDescription certificate_required.
pub const TLS_ALERT_DESCRIPTION_CERTIFICATE_REQUIRED: u8 = 116;
/// TLS AlertDescription general_error.
pub const TLS_ALERT_DESCRIPTION_GENERAL_ERROR: u8 = 117;
/// TLS AlertDescription no_application_protocol.
pub const TLS_ALERT_DESCRIPTION_NO_APPLICATION_PROTOCOL: u8 = 120;
/// TLS AlertDescription ech_required.
pub const TLS_ALERT_DESCRIPTION_ECH_REQUIRED: u8 = 121;

/// Return the selected TLS AlertDescription name.
pub const fn tls_alert_description_name(description: u8) -> Option<&'static str> {
    match description {
        TLS_ALERT_DESCRIPTION_CLOSE_NOTIFY => Some("close_notify"),
        TLS_ALERT_DESCRIPTION_UNEXPECTED_MESSAGE => Some("unexpected_message"),
        TLS_ALERT_DESCRIPTION_BAD_RECORD_MAC => Some("bad_record_mac"),
        TLS_ALERT_DESCRIPTION_DECRYPTION_FAILED_RESERVED => Some("decryption_failed_RESERVED"),
        TLS_ALERT_DESCRIPTION_RECORD_OVERFLOW => Some("record_overflow"),
        TLS_ALERT_DESCRIPTION_DECOMPRESSION_FAILURE_RESERVED => {
            Some("decompression_failure_RESERVED")
        }
        TLS_ALERT_DESCRIPTION_HANDSHAKE_FAILURE => Some("handshake_failure"),
        TLS_ALERT_DESCRIPTION_NO_CERTIFICATE_RESERVED => Some("no_certificate_RESERVED"),
        TLS_ALERT_DESCRIPTION_BAD_CERTIFICATE => Some("bad_certificate"),
        TLS_ALERT_DESCRIPTION_UNSUPPORTED_CERTIFICATE => Some("unsupported_certificate"),
        TLS_ALERT_DESCRIPTION_CERTIFICATE_REVOKED => Some("certificate_revoked"),
        TLS_ALERT_DESCRIPTION_CERTIFICATE_EXPIRED => Some("certificate_expired"),
        TLS_ALERT_DESCRIPTION_CERTIFICATE_UNKNOWN => Some("certificate_unknown"),
        TLS_ALERT_DESCRIPTION_ILLEGAL_PARAMETER => Some("illegal_parameter"),
        TLS_ALERT_DESCRIPTION_UNKNOWN_CA => Some("unknown_ca"),
        TLS_ALERT_DESCRIPTION_ACCESS_DENIED => Some("access_denied"),
        TLS_ALERT_DESCRIPTION_DECODE_ERROR => Some("decode_error"),
        TLS_ALERT_DESCRIPTION_DECRYPT_ERROR => Some("decrypt_error"),
        TLS_ALERT_DESCRIPTION_TOO_MANY_CIDS_REQUESTED => Some("too_many_cids_requested"),
        TLS_ALERT_DESCRIPTION_EXPORT_RESTRICTION_RESERVED => Some("export_restriction_RESERVED"),
        TLS_ALERT_DESCRIPTION_PROTOCOL_VERSION => Some("protocol_version"),
        TLS_ALERT_DESCRIPTION_INSUFFICIENT_SECURITY => Some("insufficient_security"),
        TLS_ALERT_DESCRIPTION_INTERNAL_ERROR => Some("internal_error"),
        TLS_ALERT_DESCRIPTION_INAPPROPRIATE_FALLBACK => Some("inappropriate_fallback"),
        TLS_ALERT_DESCRIPTION_USER_CANCELED => Some("user_canceled"),
        TLS_ALERT_DESCRIPTION_NO_RENEGOTIATION_RESERVED => Some("no_renegotiation_RESERVED"),
        TLS_ALERT_DESCRIPTION_MISSING_EXTENSION => Some("missing_extension"),
        TLS_ALERT_DESCRIPTION_UNSUPPORTED_EXTENSION => Some("unsupported_extension"),
        TLS_ALERT_DESCRIPTION_CERTIFICATE_UNOBTAINABLE_RESERVED => {
            Some("certificate_unobtainable_RESERVED")
        }
        TLS_ALERT_DESCRIPTION_UNRECOGNIZED_NAME => Some("unrecognized_name"),
        TLS_ALERT_DESCRIPTION_BAD_CERTIFICATE_STATUS_RESPONSE => {
            Some("bad_certificate_status_response")
        }
        TLS_ALERT_DESCRIPTION_BAD_CERTIFICATE_HASH_VALUE_RESERVED => {
            Some("bad_certificate_hash_value_RESERVED")
        }
        TLS_ALERT_DESCRIPTION_UNKNOWN_PSK_IDENTITY => Some("unknown_psk_identity"),
        TLS_ALERT_DESCRIPTION_CERTIFICATE_REQUIRED => Some("certificate_required"),
        TLS_ALERT_DESCRIPTION_GENERAL_ERROR => Some("general_error"),
        TLS_ALERT_DESCRIPTION_NO_APPLICATION_PROTOCOL => Some("no_application_protocol"),
        TLS_ALERT_DESCRIPTION_ECH_REQUIRED => Some("ech_required"),
        _ => None,
    }
}

/// Classify a TLS AlertDescription value.
pub const fn tls_alert_description_status(description: u8) -> TlsCodepointStatus {
    match description {
        TLS_ALERT_DESCRIPTION_DECRYPTION_FAILED_RESERVED
        | TLS_ALERT_DESCRIPTION_DECOMPRESSION_FAILURE_RESERVED
        | TLS_ALERT_DESCRIPTION_NO_CERTIFICATE_RESERVED
        | TLS_ALERT_DESCRIPTION_EXPORT_RESTRICTION_RESERVED
        | TLS_ALERT_DESCRIPTION_NO_RENEGOTIATION_RESERVED
        | TLS_ALERT_DESCRIPTION_CERTIFICATE_UNOBTAINABLE_RESERVED
        | TLS_ALERT_DESCRIPTION_BAD_CERTIFICATE_HASH_VALUE_RESERVED => {
            TlsCodepointStatus::PreserveOnly
        }
        TLS_ALERT_DESCRIPTION_TOO_MANY_CIDS_REQUESTED => TlsCodepointStatus::DtlsOnly,
        TLS_ALERT_DESCRIPTION_ECH_REQUIRED => TlsCodepointStatus::PreserveOnly,
        _ if tls_alert_description_name(description).is_some() => TlsCodepointStatus::LabelEligible,
        _ => TlsCodepointStatus::Unassigned,
    }
}

/// Human-readable AlertDescription label preserving unknown values.
pub fn tls_alert_description_label(description: u8) -> String {
    label_with_known_name(
        tls_alert_description_name(description),
        tls_alert_description_status(description),
        "alert description",
        description as u64,
        2,
    )
}

// ---------------------------------------------------------------------------
// HandshakeType
// ---------------------------------------------------------------------------

/// TLS HandshakeType hello_request_RESERVED.
pub const TLS_HANDSHAKE_TYPE_HELLO_REQUEST_RESERVED: u8 = 0;
/// TLS HandshakeType client_hello.
pub const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;
/// TLS HandshakeType server_hello.
pub const TLS_HANDSHAKE_TYPE_SERVER_HELLO: u8 = 2;
/// TLS HandshakeType hello_verify_request_RESERVED.
pub const TLS_HANDSHAKE_TYPE_HELLO_VERIFY_REQUEST_RESERVED: u8 = 3;
/// TLS HandshakeType new_session_ticket.
pub const TLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET: u8 = 4;
/// TLS HandshakeType end_of_early_data.
pub const TLS_HANDSHAKE_TYPE_END_OF_EARLY_DATA: u8 = 5;
/// TLS HandshakeType hello_retry_request_RESERVED.
pub const TLS_HANDSHAKE_TYPE_HELLO_RETRY_REQUEST_RESERVED: u8 = 6;
/// TLS HandshakeType encrypted_extensions.
pub const TLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: u8 = 8;
/// DTLS HandshakeType request_connection_id.
pub const TLS_HANDSHAKE_TYPE_REQUEST_CONNECTION_ID: u8 = 9;
/// DTLS HandshakeType new_connection_id.
pub const TLS_HANDSHAKE_TYPE_NEW_CONNECTION_ID: u8 = 10;
/// TLS HandshakeType certificate.
pub const TLS_HANDSHAKE_TYPE_CERTIFICATE: u8 = 11;
/// TLS HandshakeType server_key_exchange_RESERVED.
pub const TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE_RESERVED: u8 = 12;
/// TLS HandshakeType certificate_request.
pub const TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST: u8 = 13;
/// TLS HandshakeType server_hello_done_RESERVED.
pub const TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE_RESERVED: u8 = 14;
/// TLS HandshakeType certificate_verify.
pub const TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY: u8 = 15;
/// TLS HandshakeType client_key_exchange_RESERVED.
pub const TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE_RESERVED: u8 = 16;
/// TLS HandshakeType client_certificate_request.
pub const TLS_HANDSHAKE_TYPE_CLIENT_CERTIFICATE_REQUEST: u8 = 17;
/// TLS HandshakeType finished.
pub const TLS_HANDSHAKE_TYPE_FINISHED: u8 = 20;
/// TLS HandshakeType certificate_url_RESERVED.
pub const TLS_HANDSHAKE_TYPE_CERTIFICATE_URL_RESERVED: u8 = 21;
/// TLS HandshakeType certificate_status_RESERVED.
pub const TLS_HANDSHAKE_TYPE_CERTIFICATE_STATUS_RESERVED: u8 = 22;
/// TLS HandshakeType supplemental_data_RESERVED.
pub const TLS_HANDSHAKE_TYPE_SUPPLEMENTAL_DATA_RESERVED: u8 = 23;
/// TLS HandshakeType key_update.
pub const TLS_HANDSHAKE_TYPE_KEY_UPDATE: u8 = 24;
/// TLS HandshakeType compressed_certificate.
pub const TLS_HANDSHAKE_TYPE_COMPRESSED_CERTIFICATE: u8 = 25;
/// DTLS HandshakeType ekt_key.
pub const TLS_HANDSHAKE_TYPE_EKT_KEY: u8 = 26;
/// TLS HandshakeType message_hash.
pub const TLS_HANDSHAKE_TYPE_MESSAGE_HASH: u8 = 254;

/// Return the selected TLS HandshakeType name.
pub const fn tls_handshake_type_name(handshake_type: u8) -> Option<&'static str> {
    match handshake_type {
        TLS_HANDSHAKE_TYPE_HELLO_REQUEST_RESERVED => Some("hello_request_RESERVED"),
        TLS_HANDSHAKE_TYPE_CLIENT_HELLO => Some("client_hello"),
        TLS_HANDSHAKE_TYPE_SERVER_HELLO => Some("server_hello"),
        TLS_HANDSHAKE_TYPE_HELLO_VERIFY_REQUEST_RESERVED => Some("hello_verify_request_RESERVED"),
        TLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET => Some("new_session_ticket"),
        TLS_HANDSHAKE_TYPE_END_OF_EARLY_DATA => Some("end_of_early_data"),
        TLS_HANDSHAKE_TYPE_HELLO_RETRY_REQUEST_RESERVED => Some("hello_retry_request_RESERVED"),
        TLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS => Some("encrypted_extensions"),
        TLS_HANDSHAKE_TYPE_REQUEST_CONNECTION_ID => Some("request_connection_id"),
        TLS_HANDSHAKE_TYPE_NEW_CONNECTION_ID => Some("new_connection_id"),
        TLS_HANDSHAKE_TYPE_CERTIFICATE => Some("certificate"),
        TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE_RESERVED => Some("server_key_exchange_RESERVED"),
        TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST => Some("certificate_request"),
        TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE_RESERVED => Some("server_hello_done_RESERVED"),
        TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY => Some("certificate_verify"),
        TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE_RESERVED => Some("client_key_exchange_RESERVED"),
        TLS_HANDSHAKE_TYPE_CLIENT_CERTIFICATE_REQUEST => Some("client_certificate_request"),
        TLS_HANDSHAKE_TYPE_FINISHED => Some("finished"),
        TLS_HANDSHAKE_TYPE_CERTIFICATE_URL_RESERVED => Some("certificate_url_RESERVED"),
        TLS_HANDSHAKE_TYPE_CERTIFICATE_STATUS_RESERVED => Some("certificate_status_RESERVED"),
        TLS_HANDSHAKE_TYPE_SUPPLEMENTAL_DATA_RESERVED => Some("supplemental_data_RESERVED"),
        TLS_HANDSHAKE_TYPE_KEY_UPDATE => Some("key_update"),
        TLS_HANDSHAKE_TYPE_COMPRESSED_CERTIFICATE => Some("compressed_certificate"),
        TLS_HANDSHAKE_TYPE_EKT_KEY => Some("ekt_key"),
        TLS_HANDSHAKE_TYPE_MESSAGE_HASH => Some("message_hash"),
        _ => None,
    }
}

/// Classify a TLS HandshakeType value.
pub const fn tls_handshake_type_status(handshake_type: u8) -> TlsCodepointStatus {
    match handshake_type {
        TLS_HANDSHAKE_TYPE_CLIENT_HELLO
        | TLS_HANDSHAKE_TYPE_SERVER_HELLO
        | TLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET
        | TLS_HANDSHAKE_TYPE_END_OF_EARLY_DATA
        | TLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS
        | TLS_HANDSHAKE_TYPE_CERTIFICATE
        | TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST
        | TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY
        | TLS_HANDSHAKE_TYPE_FINISHED
        | TLS_HANDSHAKE_TYPE_KEY_UPDATE => TlsCodepointStatus::DefaultEligible,
        TLS_HANDSHAKE_TYPE_COMPRESSED_CERTIFICATE => TlsCodepointStatus::Deferred,
        TLS_HANDSHAKE_TYPE_REQUEST_CONNECTION_ID
        | TLS_HANDSHAKE_TYPE_NEW_CONNECTION_ID
        | TLS_HANDSHAKE_TYPE_EKT_KEY => TlsCodepointStatus::DtlsOnly,
        TLS_HANDSHAKE_TYPE_HELLO_REQUEST_RESERVED
        | TLS_HANDSHAKE_TYPE_HELLO_VERIFY_REQUEST_RESERVED
        | TLS_HANDSHAKE_TYPE_HELLO_RETRY_REQUEST_RESERVED
        | TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE_RESERVED
        | TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE_RESERVED
        | TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE_RESERVED
        | TLS_HANDSHAKE_TYPE_CLIENT_CERTIFICATE_REQUEST
        | TLS_HANDSHAKE_TYPE_CERTIFICATE_URL_RESERVED
        | TLS_HANDSHAKE_TYPE_CERTIFICATE_STATUS_RESERVED
        | TLS_HANDSHAKE_TYPE_SUPPLEMENTAL_DATA_RESERVED
        | TLS_HANDSHAKE_TYPE_MESSAGE_HASH => TlsCodepointStatus::PreserveOnly,
        _ => TlsCodepointStatus::Unassigned,
    }
}

/// Human-readable HandshakeType label preserving unknown values.
pub fn tls_handshake_type_label(handshake_type: u8) -> String {
    label_with_known_name(
        tls_handshake_type_name(handshake_type),
        tls_handshake_type_status(handshake_type),
        "handshake type",
        handshake_type as u64,
        2,
    )
}

// ---------------------------------------------------------------------------
// CipherSuite
// ---------------------------------------------------------------------------

/// TLS 1.3 cipher suite TLS_AES_128_GCM_SHA256.
pub const TLS_CIPHER_SUITE_AES_128_GCM_SHA256: u16 = 0x1301;
/// TLS 1.3 cipher suite TLS_AES_256_GCM_SHA384.
pub const TLS_CIPHER_SUITE_AES_256_GCM_SHA384: u16 = 0x1302;
/// TLS 1.3 cipher suite TLS_CHACHA20_POLY1305_SHA256.
pub const TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
/// TLS 1.3 cipher suite TLS_AES_128_CCM_SHA256.
pub const TLS_CIPHER_SUITE_AES_128_CCM_SHA256: u16 = 0x1304;
/// TLS 1.3 cipher suite TLS_AES_128_CCM_8_SHA256.
pub const TLS_CIPHER_SUITE_AES_128_CCM_8_SHA256: u16 = 0x1305;
/// TLS 1.2 cipher suite TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.
pub const TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02b;
/// TLS 1.2 cipher suite TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.
pub const TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: u16 = 0xc02c;
/// TLS 1.2 cipher suite TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.
pub const TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02f;
/// TLS 1.2 cipher suite TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.
pub const TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384: u16 = 0xc030;
/// TLS 1.2 cipher suite TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.
pub const TLS_CIPHER_SUITE_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xcca8;
/// TLS 1.2 cipher suite TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.
pub const TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xcca9;
/// TLS 1.2 cipher suite TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256.
pub const TLS_CIPHER_SUITE_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xccac;
/// TLS 1.2 cipher suite TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256.
pub const TLS_CIPHER_SUITE_ECDHE_PSK_WITH_AES_128_GCM_SHA256: u16 = 0xd001;
/// TLS 1.2 cipher suite TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384.
pub const TLS_CIPHER_SUITE_ECDHE_PSK_WITH_AES_256_GCM_SHA384: u16 = 0xd002;
/// TLS 1.2 cipher suite TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256.
pub const TLS_CIPHER_SUITE_ECDHE_PSK_WITH_AES_128_CCM_SHA256: u16 = 0xd005;
/// TLS signaling cipher suite value TLS_EMPTY_RENEGOTIATION_INFO_SCSV.
pub const TLS_CIPHER_SUITE_EMPTY_RENEGOTIATION_INFO_SCSV: u16 = 0x00ff;
/// TLS signaling cipher suite value TLS_FALLBACK_SCSV.
pub const TLS_CIPHER_SUITE_FALLBACK_SCSV: u16 = 0x5600;

/// Return the selected TLS CipherSuite name.
pub const fn tls_cipher_suite_name(cipher_suite: u16) -> Option<&'static str> {
    match cipher_suite {
        TLS_CIPHER_SUITE_AES_128_GCM_SHA256 => Some("TLS_AES_128_GCM_SHA256"),
        TLS_CIPHER_SUITE_AES_256_GCM_SHA384 => Some("TLS_AES_256_GCM_SHA384"),
        TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256 => Some("TLS_CHACHA20_POLY1305_SHA256"),
        TLS_CIPHER_SUITE_AES_128_CCM_SHA256 => Some("TLS_AES_128_CCM_SHA256"),
        TLS_CIPHER_SUITE_AES_128_CCM_8_SHA256 => Some("TLS_AES_128_CCM_8_SHA256"),
        TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => {
            Some("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")
        }
        TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => {
            Some("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384")
        }
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => {
            Some("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
        }
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => {
            Some("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
        }
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => {
            Some("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256")
        }
        TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => {
            Some("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256")
        }
        TLS_CIPHER_SUITE_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 => {
            Some("TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256")
        }
        TLS_CIPHER_SUITE_ECDHE_PSK_WITH_AES_128_GCM_SHA256 => {
            Some("TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256")
        }
        TLS_CIPHER_SUITE_ECDHE_PSK_WITH_AES_256_GCM_SHA384 => {
            Some("TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384")
        }
        TLS_CIPHER_SUITE_ECDHE_PSK_WITH_AES_128_CCM_SHA256 => {
            Some("TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256")
        }
        TLS_CIPHER_SUITE_EMPTY_RENEGOTIATION_INFO_SCSV => Some("TLS_EMPTY_RENEGOTIATION_INFO_SCSV"),
        TLS_CIPHER_SUITE_FALLBACK_SCSV => Some("TLS_FALLBACK_SCSV"),
        _ => None,
    }
}

/// Classify a TLS CipherSuite value.
pub const fn tls_cipher_suite_status(cipher_suite: u16) -> TlsCodepointStatus {
    match cipher_suite {
        TLS_CIPHER_SUITE_AES_128_GCM_SHA256
        | TLS_CIPHER_SUITE_AES_256_GCM_SHA384
        | TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256
        | TLS_CIPHER_SUITE_AES_128_CCM_SHA256 => TlsCodepointStatus::DefaultEligible,
        TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        | TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        | TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        | TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        | TLS_CIPHER_SUITE_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        | TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        | TLS_CIPHER_SUITE_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256
        | TLS_CIPHER_SUITE_ECDHE_PSK_WITH_AES_128_GCM_SHA256
        | TLS_CIPHER_SUITE_ECDHE_PSK_WITH_AES_256_GCM_SHA384
        | TLS_CIPHER_SUITE_ECDHE_PSK_WITH_AES_128_CCM_SHA256 => TlsCodepointStatus::LabelEligible,
        TLS_CIPHER_SUITE_AES_128_CCM_8_SHA256
        | TLS_CIPHER_SUITE_EMPTY_RENEGOTIATION_INFO_SCSV
        | TLS_CIPHER_SUITE_FALLBACK_SCSV => TlsCodepointStatus::PreserveOnly,
        _ if is_tls_grease_u16(cipher_suite) => TlsCodepointStatus::ReservedGrease,
        0xff00..=0xffff => TlsCodepointStatus::PrivateUse,
        _ => TlsCodepointStatus::Unknown,
    }
}

/// Human-readable CipherSuite label preserving unknown values.
pub fn tls_cipher_suite_label(cipher_suite: u16) -> String {
    label_with_known_name(
        tls_cipher_suite_name(cipher_suite),
        tls_cipher_suite_status(cipher_suite),
        "cipher suite",
        cipher_suite as u64,
        4,
    )
}

// ---------------------------------------------------------------------------
// ExtensionType
// ---------------------------------------------------------------------------

/// TLS ExtensionType server_name.
pub const TLS_EXTENSION_SERVER_NAME: u16 = 0;
/// TLS ExtensionType max_fragment_length.
pub const TLS_EXTENSION_MAX_FRAGMENT_LENGTH: u16 = 1;
/// TLS ExtensionType status_request.
pub const TLS_EXTENSION_STATUS_REQUEST: u16 = 5;
/// TLS ExtensionType supported_groups.
pub const TLS_EXTENSION_SUPPORTED_GROUPS: u16 = 10;
/// TLS ExtensionType ec_point_formats.
pub const TLS_EXTENSION_EC_POINT_FORMATS: u16 = 11;
/// TLS ExtensionType signature_algorithms.
pub const TLS_EXTENSION_SIGNATURE_ALGORITHMS: u16 = 13;
/// TLS ExtensionType heartbeat.
pub const TLS_EXTENSION_HEARTBEAT: u16 = 15;
/// TLS ExtensionType application_layer_protocol_negotiation.
pub const TLS_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION: u16 = 16;
/// TLS ExtensionType status_request_v2.
pub const TLS_EXTENSION_STATUS_REQUEST_V2: u16 = 17;
/// TLS ExtensionType padding.
pub const TLS_EXTENSION_PADDING: u16 = 21;
/// TLS ExtensionType compress_certificate.
pub const TLS_EXTENSION_COMPRESS_CERTIFICATE: u16 = 27;
/// TLS ExtensionType record_size_limit.
pub const TLS_EXTENSION_RECORD_SIZE_LIMIT: u16 = 28;
/// Reserved TLS ExtensionType 40.
pub const TLS_EXTENSION_RESERVED_40: u16 = 40;
/// TLS ExtensionType pre_shared_key.
pub const TLS_EXTENSION_PRE_SHARED_KEY: u16 = 41;
/// TLS ExtensionType early_data.
pub const TLS_EXTENSION_EARLY_DATA: u16 = 42;
/// TLS ExtensionType supported_versions.
pub const TLS_EXTENSION_SUPPORTED_VERSIONS: u16 = 43;
/// TLS ExtensionType cookie.
pub const TLS_EXTENSION_COOKIE: u16 = 44;
/// TLS ExtensionType psk_key_exchange_modes.
pub const TLS_EXTENSION_PSK_KEY_EXCHANGE_MODES: u16 = 45;
/// Reserved TLS ExtensionType 46.
pub const TLS_EXTENSION_RESERVED_46: u16 = 46;
/// TLS ExtensionType certificate_authorities.
pub const TLS_EXTENSION_CERTIFICATE_AUTHORITIES: u16 = 47;
/// TLS ExtensionType oid_filters.
pub const TLS_EXTENSION_OID_FILTERS: u16 = 48;
/// TLS ExtensionType post_handshake_auth.
pub const TLS_EXTENSION_POST_HANDSHAKE_AUTH: u16 = 49;
/// TLS ExtensionType signature_algorithms_cert.
pub const TLS_EXTENSION_SIGNATURE_ALGORITHMS_CERT: u16 = 50;
/// TLS ExtensionType key_share.
pub const TLS_EXTENSION_KEY_SHARE: u16 = 51;
/// TLS ExtensionType quic_transport_parameters, preserved outside TLS-over-TCP.
pub const TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS: u16 = 57;
/// TLS ExtensionType ech_outer_extensions, ECH deferred.
pub const TLS_EXTENSION_ECH_OUTER_EXTENSIONS: u16 = 0xfd00;
/// TLS ExtensionType encrypted_client_hello, ECH deferred.
pub const TLS_EXTENSION_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
/// TLS ExtensionType renegotiation_info.
pub const TLS_EXTENSION_RENEGOTIATION_INFO: u16 = 0xff01;

/// Return the selected TLS ExtensionType name.
pub const fn tls_extension_name(extension: u16) -> Option<&'static str> {
    match extension {
        TLS_EXTENSION_SERVER_NAME => Some("server_name"),
        TLS_EXTENSION_MAX_FRAGMENT_LENGTH => Some("max_fragment_length"),
        TLS_EXTENSION_STATUS_REQUEST => Some("status_request"),
        TLS_EXTENSION_SUPPORTED_GROUPS => Some("supported_groups"),
        TLS_EXTENSION_EC_POINT_FORMATS => Some("ec_point_formats"),
        TLS_EXTENSION_SIGNATURE_ALGORITHMS => Some("signature_algorithms"),
        TLS_EXTENSION_HEARTBEAT => Some("heartbeat"),
        TLS_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION => {
            Some("application_layer_protocol_negotiation")
        }
        TLS_EXTENSION_STATUS_REQUEST_V2 => Some("status_request_v2"),
        TLS_EXTENSION_PADDING => Some("padding"),
        TLS_EXTENSION_COMPRESS_CERTIFICATE => Some("compress_certificate"),
        TLS_EXTENSION_RECORD_SIZE_LIMIT => Some("record_size_limit"),
        TLS_EXTENSION_RESERVED_40 => Some("Reserved"),
        TLS_EXTENSION_PRE_SHARED_KEY => Some("pre_shared_key"),
        TLS_EXTENSION_EARLY_DATA => Some("early_data"),
        TLS_EXTENSION_SUPPORTED_VERSIONS => Some("supported_versions"),
        TLS_EXTENSION_COOKIE => Some("cookie"),
        TLS_EXTENSION_PSK_KEY_EXCHANGE_MODES => Some("psk_key_exchange_modes"),
        TLS_EXTENSION_RESERVED_46 => Some("Reserved"),
        TLS_EXTENSION_CERTIFICATE_AUTHORITIES => Some("certificate_authorities"),
        TLS_EXTENSION_OID_FILTERS => Some("oid_filters"),
        TLS_EXTENSION_POST_HANDSHAKE_AUTH => Some("post_handshake_auth"),
        TLS_EXTENSION_SIGNATURE_ALGORITHMS_CERT => Some("signature_algorithms_cert"),
        TLS_EXTENSION_KEY_SHARE => Some("key_share"),
        TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS => Some("quic_transport_parameters"),
        TLS_EXTENSION_ECH_OUTER_EXTENSIONS => Some("ech_outer_extensions"),
        TLS_EXTENSION_ENCRYPTED_CLIENT_HELLO => Some("encrypted_client_hello"),
        TLS_EXTENSION_RENEGOTIATION_INFO => Some("renegotiation_info"),
        _ => None,
    }
}

/// Classify a TLS ExtensionType value.
pub const fn tls_extension_status(extension: u16) -> TlsCodepointStatus {
    match extension {
        TLS_EXTENSION_SERVER_NAME
        | TLS_EXTENSION_STATUS_REQUEST
        | TLS_EXTENSION_SUPPORTED_GROUPS
        | TLS_EXTENSION_SIGNATURE_ALGORITHMS
        | TLS_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION
        | TLS_EXTENSION_PADDING
        | TLS_EXTENSION_RECORD_SIZE_LIMIT
        | TLS_EXTENSION_PRE_SHARED_KEY
        | TLS_EXTENSION_EARLY_DATA
        | TLS_EXTENSION_SUPPORTED_VERSIONS
        | TLS_EXTENSION_COOKIE
        | TLS_EXTENSION_PSK_KEY_EXCHANGE_MODES
        | TLS_EXTENSION_CERTIFICATE_AUTHORITIES
        | TLS_EXTENSION_OID_FILTERS
        | TLS_EXTENSION_POST_HANDSHAKE_AUTH
        | TLS_EXTENSION_SIGNATURE_ALGORITHMS_CERT
        | TLS_EXTENSION_KEY_SHARE => TlsCodepointStatus::DefaultEligible,
        TLS_EXTENSION_EC_POINT_FORMATS | TLS_EXTENSION_STATUS_REQUEST_V2 => {
            TlsCodepointStatus::LabelEligible
        }
        TLS_EXTENSION_HEARTBEAT | TLS_EXTENSION_COMPRESS_CERTIFICATE => {
            TlsCodepointStatus::Deferred
        }
        TLS_EXTENSION_RESERVED_40 | TLS_EXTENSION_RESERVED_46 => TlsCodepointStatus::Reserved,
        TLS_EXTENSION_MAX_FRAGMENT_LENGTH
        | TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS
        | TLS_EXTENSION_ECH_OUTER_EXTENSIONS
        | TLS_EXTENSION_ENCRYPTED_CLIENT_HELLO
        | TLS_EXTENSION_RENEGOTIATION_INFO => TlsCodepointStatus::PreserveOnly,
        _ if is_tls_grease_u16(extension) => TlsCodepointStatus::ReservedGrease,
        0xff00..=0xffff => TlsCodepointStatus::PrivateUse,
        _ => TlsCodepointStatus::Unknown,
    }
}

/// Human-readable ExtensionType label preserving unknown values.
pub fn tls_extension_label(extension: u16) -> String {
    label_with_known_name(
        tls_extension_name(extension),
        tls_extension_status(extension),
        "extension",
        extension as u64,
        4,
    )
}

// ---------------------------------------------------------------------------
// CertificateStatusType
// ---------------------------------------------------------------------------

/// Reserved CertificateStatusType zero value.
pub const TLS_CERTIFICATE_STATUS_TYPE_RESERVED: u8 = 0;
/// CertificateStatusType ocsp.
pub const TLS_CERTIFICATE_STATUS_TYPE_OCSP: u8 = 1;
/// CertificateStatusType ocsp_multi, now reserved by the current IANA row.
pub const TLS_CERTIFICATE_STATUS_TYPE_OCSP_MULTI_RESERVED: u8 = 2;

/// Return the selected TLS CertificateStatusType name.
pub const fn tls_certificate_status_type_name(status_type: u8) -> Option<&'static str> {
    match status_type {
        TLS_CERTIFICATE_STATUS_TYPE_RESERVED => Some("Reserved"),
        TLS_CERTIFICATE_STATUS_TYPE_OCSP => Some("ocsp"),
        TLS_CERTIFICATE_STATUS_TYPE_OCSP_MULTI_RESERVED => Some("ocsp_multi_RESERVED"),
        _ => None,
    }
}

/// Classify a TLS CertificateStatusType value.
pub const fn tls_certificate_status_type_status(status_type: u8) -> TlsCodepointStatus {
    match status_type {
        TLS_CERTIFICATE_STATUS_TYPE_RESERVED => TlsCodepointStatus::Reserved,
        TLS_CERTIFICATE_STATUS_TYPE_OCSP => TlsCodepointStatus::DefaultEligible,
        TLS_CERTIFICATE_STATUS_TYPE_OCSP_MULTI_RESERVED => TlsCodepointStatus::PreserveOnly,
        _ => TlsCodepointStatus::Unassigned,
    }
}

/// Human-readable CertificateStatusType label preserving unknown values.
pub fn tls_certificate_status_type_label(status_type: u8) -> String {
    label_with_known_name(
        tls_certificate_status_type_name(status_type),
        tls_certificate_status_type_status(status_type),
        "certificate status type",
        status_type as u64,
        2,
    )
}

// ---------------------------------------------------------------------------
// Supported Groups / NamedGroup
// ---------------------------------------------------------------------------

/// Reserved NamedGroup zero value.
pub const TLS_NAMED_GROUP_RESERVED: u16 = 0;
/// TLS NamedGroup secp256r1.
pub const TLS_NAMED_GROUP_SECP256R1: u16 = 23;
/// TLS NamedGroup secp384r1.
pub const TLS_NAMED_GROUP_SECP384R1: u16 = 24;
/// TLS NamedGroup secp521r1.
pub const TLS_NAMED_GROUP_SECP521R1: u16 = 25;
/// TLS NamedGroup x25519.
pub const TLS_NAMED_GROUP_X25519: u16 = 29;
/// TLS NamedGroup x448.
pub const TLS_NAMED_GROUP_X448: u16 = 30;
/// TLS NamedGroup ffdhe2048.
pub const TLS_NAMED_GROUP_FFDHE2048: u16 = 256;
/// TLS NamedGroup ffdhe3072.
pub const TLS_NAMED_GROUP_FFDHE3072: u16 = 257;
/// TLS NamedGroup ffdhe4096.
pub const TLS_NAMED_GROUP_FFDHE4096: u16 = 258;
/// TLS NamedGroup ffdhe6144.
pub const TLS_NAMED_GROUP_FFDHE6144: u16 = 259;
/// TLS NamedGroup ffdhe8192.
pub const TLS_NAMED_GROUP_FFDHE8192: u16 = 260;
/// Draft-backed NamedGroup X25519MLKEM768, preserve-only in this bootstrap.
pub const TLS_NAMED_GROUP_X25519MLKEM768: u16 = 0x11ec;
/// Legacy explicit-prime curve indicator.
pub const TLS_NAMED_GROUP_ARBITRARY_EXPLICIT_PRIME_CURVES: u16 = 0xff01;
/// Legacy explicit-char2 curve indicator.
pub const TLS_NAMED_GROUP_ARBITRARY_EXPLICIT_CHAR2_CURVES: u16 = 0xff02;

/// Return the selected TLS NamedGroup name.
pub const fn tls_named_group_name(group: u16) -> Option<&'static str> {
    match group {
        TLS_NAMED_GROUP_RESERVED => Some("Reserved"),
        TLS_NAMED_GROUP_SECP256R1 => Some("secp256r1"),
        TLS_NAMED_GROUP_SECP384R1 => Some("secp384r1"),
        TLS_NAMED_GROUP_SECP521R1 => Some("secp521r1"),
        TLS_NAMED_GROUP_X25519 => Some("x25519"),
        TLS_NAMED_GROUP_X448 => Some("x448"),
        TLS_NAMED_GROUP_FFDHE2048 => Some("ffdhe2048"),
        TLS_NAMED_GROUP_FFDHE3072 => Some("ffdhe3072"),
        TLS_NAMED_GROUP_FFDHE4096 => Some("ffdhe4096"),
        TLS_NAMED_GROUP_FFDHE6144 => Some("ffdhe6144"),
        TLS_NAMED_GROUP_FFDHE8192 => Some("ffdhe8192"),
        TLS_NAMED_GROUP_X25519MLKEM768 => Some("X25519MLKEM768"),
        TLS_NAMED_GROUP_ARBITRARY_EXPLICIT_PRIME_CURVES => Some("arbitrary_explicit_prime_curves"),
        TLS_NAMED_GROUP_ARBITRARY_EXPLICIT_CHAR2_CURVES => Some("arbitrary_explicit_char2_curves"),
        _ => None,
    }
}

/// Classify a TLS NamedGroup value.
pub const fn tls_named_group_status(group: u16) -> TlsCodepointStatus {
    match group {
        TLS_NAMED_GROUP_SECP256R1
        | TLS_NAMED_GROUP_SECP384R1
        | TLS_NAMED_GROUP_X25519
        | TLS_NAMED_GROUP_X448 => TlsCodepointStatus::DefaultEligible,
        TLS_NAMED_GROUP_RESERVED => TlsCodepointStatus::Reserved,
        TLS_NAMED_GROUP_SECP521R1
        | TLS_NAMED_GROUP_FFDHE2048
        | TLS_NAMED_GROUP_FFDHE3072
        | TLS_NAMED_GROUP_FFDHE4096
        | TLS_NAMED_GROUP_FFDHE6144
        | TLS_NAMED_GROUP_FFDHE8192
        | TLS_NAMED_GROUP_X25519MLKEM768
        | TLS_NAMED_GROUP_ARBITRARY_EXPLICIT_PRIME_CURVES
        | TLS_NAMED_GROUP_ARBITRARY_EXPLICIT_CHAR2_CURVES => TlsCodepointStatus::PreserveOnly,
        _ if is_tls_grease_u16(group) => TlsCodepointStatus::ReservedGrease,
        0xfe00..=0xfeff => TlsCodepointStatus::PrivateUse,
        _ => TlsCodepointStatus::Unknown,
    }
}

/// Human-readable NamedGroup label preserving unknown values.
pub fn tls_named_group_label(group: u16) -> String {
    label_with_known_name(
        tls_named_group_name(group),
        tls_named_group_status(group),
        "named group",
        group as u64,
        4,
    )
}

// ---------------------------------------------------------------------------
// SignatureScheme
// ---------------------------------------------------------------------------

/// TLS SignatureScheme rsa_pkcs1_sha1.
pub const TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA1: u16 = 0x0201;
/// TLS SignatureScheme ecdsa_sha1.
pub const TLS_SIGNATURE_SCHEME_ECDSA_SHA1: u16 = 0x0203;
/// TLS SignatureScheme rsa_pkcs1_sha256.
pub const TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA256: u16 = 0x0401;
/// TLS SignatureScheme ecdsa_secp256r1_sha256.
pub const TLS_SIGNATURE_SCHEME_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
/// TLS SignatureScheme rsa_pkcs1_sha384.
pub const TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA384: u16 = 0x0501;
/// TLS SignatureScheme ecdsa_secp384r1_sha384.
pub const TLS_SIGNATURE_SCHEME_ECDSA_SECP384R1_SHA384: u16 = 0x0503;
/// TLS SignatureScheme rsa_pkcs1_sha512.
pub const TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA512: u16 = 0x0601;
/// TLS SignatureScheme ecdsa_secp521r1_sha512.
pub const TLS_SIGNATURE_SCHEME_ECDSA_SECP521R1_SHA512: u16 = 0x0603;
/// TLS SignatureScheme rsa_pss_rsae_sha256.
pub const TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA256: u16 = 0x0804;
/// TLS SignatureScheme rsa_pss_rsae_sha384.
pub const TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA384: u16 = 0x0805;
/// TLS SignatureScheme rsa_pss_rsae_sha512.
pub const TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA512: u16 = 0x0806;
/// TLS SignatureScheme ed25519.
pub const TLS_SIGNATURE_SCHEME_ED25519: u16 = 0x0807;
/// TLS SignatureScheme ed448.
pub const TLS_SIGNATURE_SCHEME_ED448: u16 = 0x0808;
/// TLS SignatureScheme rsa_pss_pss_sha256.
pub const TLS_SIGNATURE_SCHEME_RSA_PSS_PSS_SHA256: u16 = 0x0809;
/// TLS SignatureScheme rsa_pss_pss_sha384.
pub const TLS_SIGNATURE_SCHEME_RSA_PSS_PSS_SHA384: u16 = 0x080a;
/// TLS SignatureScheme rsa_pss_pss_sha512.
pub const TLS_SIGNATURE_SCHEME_RSA_PSS_PSS_SHA512: u16 = 0x080b;

/// Return the selected TLS SignatureScheme name.
pub const fn tls_signature_scheme_name(scheme: u16) -> Option<&'static str> {
    match scheme {
        TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA1 => Some("rsa_pkcs1_sha1"),
        TLS_SIGNATURE_SCHEME_ECDSA_SHA1 => Some("ecdsa_sha1"),
        TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA256 => Some("rsa_pkcs1_sha256"),
        TLS_SIGNATURE_SCHEME_ECDSA_SECP256R1_SHA256 => Some("ecdsa_secp256r1_sha256"),
        TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA384 => Some("rsa_pkcs1_sha384"),
        TLS_SIGNATURE_SCHEME_ECDSA_SECP384R1_SHA384 => Some("ecdsa_secp384r1_sha384"),
        TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA512 => Some("rsa_pkcs1_sha512"),
        TLS_SIGNATURE_SCHEME_ECDSA_SECP521R1_SHA512 => Some("ecdsa_secp521r1_sha512"),
        TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA256 => Some("rsa_pss_rsae_sha256"),
        TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA384 => Some("rsa_pss_rsae_sha384"),
        TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA512 => Some("rsa_pss_rsae_sha512"),
        TLS_SIGNATURE_SCHEME_ED25519 => Some("ed25519"),
        TLS_SIGNATURE_SCHEME_ED448 => Some("ed448"),
        TLS_SIGNATURE_SCHEME_RSA_PSS_PSS_SHA256 => Some("rsa_pss_pss_sha256"),
        TLS_SIGNATURE_SCHEME_RSA_PSS_PSS_SHA384 => Some("rsa_pss_pss_sha384"),
        TLS_SIGNATURE_SCHEME_RSA_PSS_PSS_SHA512 => Some("rsa_pss_pss_sha512"),
        _ => None,
    }
}

/// Classify a TLS SignatureScheme value.
pub const fn tls_signature_scheme_status(scheme: u16) -> TlsCodepointStatus {
    match scheme {
        TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA256
        | TLS_SIGNATURE_SCHEME_ECDSA_SECP256R1_SHA256
        | TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA384
        | TLS_SIGNATURE_SCHEME_ECDSA_SECP384R1_SHA384
        | TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA512
        | TLS_SIGNATURE_SCHEME_ECDSA_SECP521R1_SHA512
        | TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA256
        | TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA384
        | TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA512
        | TLS_SIGNATURE_SCHEME_ED25519
        | TLS_SIGNATURE_SCHEME_ED448
        | TLS_SIGNATURE_SCHEME_RSA_PSS_PSS_SHA256
        | TLS_SIGNATURE_SCHEME_RSA_PSS_PSS_SHA384
        | TLS_SIGNATURE_SCHEME_RSA_PSS_PSS_SHA512 => TlsCodepointStatus::DefaultEligible,
        TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA1 | TLS_SIGNATURE_SCHEME_ECDSA_SHA1 => {
            TlsCodepointStatus::PreserveOnly
        }
        _ if is_tls_grease_u16(scheme) => TlsCodepointStatus::ReservedGrease,
        0xfe00..=0xffff => TlsCodepointStatus::PrivateUse,
        _ => TlsCodepointStatus::Unknown,
    }
}

/// Human-readable SignatureScheme label preserving unknown values.
pub fn tls_signature_scheme_label(scheme: u16) -> String {
    label_with_known_name(
        tls_signature_scheme_name(scheme),
        tls_signature_scheme_status(scheme),
        "signature scheme",
        scheme as u64,
        4,
    )
}

// ---------------------------------------------------------------------------
// PskKeyExchangeMode
// ---------------------------------------------------------------------------

/// TLS PskKeyExchangeMode psk_ke.
pub const TLS_PSK_MODE_PSK_KE: u8 = 0;
/// TLS PskKeyExchangeMode psk_dhe_ke.
pub const TLS_PSK_MODE_PSK_DHE_KE: u8 = 1;

/// Return true for the one-octet PSK-mode GREASE values from RFC 8701.
pub const fn is_tls_psk_mode_grease(mode: u8) -> bool {
    matches!(mode, 0x0b | 0x2a | 0x49 | 0x68 | 0x87 | 0xa6 | 0xc5 | 0xe4)
}

/// Return the selected TLS PskKeyExchangeMode name.
pub const fn tls_psk_mode_name(mode: u8) -> Option<&'static str> {
    match mode {
        TLS_PSK_MODE_PSK_KE => Some("psk_ke"),
        TLS_PSK_MODE_PSK_DHE_KE => Some("psk_dhe_ke"),
        _ => None,
    }
}

/// Classify a TLS PskKeyExchangeMode value.
pub const fn tls_psk_mode_status(mode: u8) -> TlsCodepointStatus {
    match mode {
        TLS_PSK_MODE_PSK_KE | TLS_PSK_MODE_PSK_DHE_KE => TlsCodepointStatus::DefaultEligible,
        _ if is_tls_psk_mode_grease(mode) => TlsCodepointStatus::ReservedGrease,
        0xfe..=0xff => TlsCodepointStatus::PrivateUse,
        _ => TlsCodepointStatus::Unassigned,
    }
}

/// Human-readable PskKeyExchangeMode label preserving unknown values.
pub fn tls_psk_mode_label(mode: u8) -> String {
    label_with_known_name(
        tls_psk_mode_name(mode),
        tls_psk_mode_status(mode),
        "psk mode",
        mode as u64,
        2,
    )
}

// ---------------------------------------------------------------------------
// Certificate Compression Algorithm IDs
// ---------------------------------------------------------------------------

/// Reserved certificate-compression algorithm ID.
pub const TLS_CERT_COMPRESSION_ALGORITHM_RESERVED: u16 = 0;
/// TLS certificate-compression algorithm zlib.
pub const TLS_CERT_COMPRESSION_ALGORITHM_ZLIB: u16 = 1;
/// TLS certificate-compression algorithm brotli.
pub const TLS_CERT_COMPRESSION_ALGORITHM_BROTLI: u16 = 2;
/// TLS certificate-compression algorithm zstd.
pub const TLS_CERT_COMPRESSION_ALGORITHM_ZSTD: u16 = 3;

/// Return the selected TLS certificate-compression algorithm name.
pub const fn tls_cert_compression_algorithm_name(algorithm: u16) -> Option<&'static str> {
    match algorithm {
        TLS_CERT_COMPRESSION_ALGORITHM_RESERVED => Some("Reserved"),
        TLS_CERT_COMPRESSION_ALGORITHM_ZLIB => Some("zlib"),
        TLS_CERT_COMPRESSION_ALGORITHM_BROTLI => Some("brotli"),
        TLS_CERT_COMPRESSION_ALGORITHM_ZSTD => Some("zstd"),
        _ => None,
    }
}

/// Classify a TLS certificate-compression algorithm ID.
pub const fn tls_cert_compression_algorithm_status(algorithm: u16) -> TlsCodepointStatus {
    match algorithm {
        TLS_CERT_COMPRESSION_ALGORITHM_RESERVED => TlsCodepointStatus::Reserved,
        TLS_CERT_COMPRESSION_ALGORITHM_ZLIB
        | TLS_CERT_COMPRESSION_ALGORITHM_BROTLI
        | TLS_CERT_COMPRESSION_ALGORITHM_ZSTD => TlsCodepointStatus::Deferred,
        4..=16_383 => TlsCodepointStatus::Unassigned,
        16_384..=65_535 => TlsCodepointStatus::Experimental,
    }
}

/// Human-readable certificate-compression algorithm label preserving unknown values.
pub fn tls_cert_compression_algorithm_label(algorithm: u16) -> String {
    label_with_known_name(
        tls_cert_compression_algorithm_name(algorithm),
        tls_cert_compression_algorithm_status(algorithm),
        "certificate compression algorithm",
        algorithm as u64,
        4,
    )
}

fn label_with_known_name(
    name: Option<&'static str>,
    status: TlsCodepointStatus,
    kind: &str,
    value: u64,
    hex_digits: usize,
) -> String {
    if let Some(name) = name {
        return name.to_string();
    }

    numeric_status_label(status, kind, value, hex_digits)
}

fn numeric_status_label(
    status: TlsCodepointStatus,
    kind: &str,
    value: u64,
    hex_digits: usize,
) -> String {
    let prefix = match status {
        TlsCodepointStatus::DefaultEligible
        | TlsCodepointStatus::LabelEligible
        | TlsCodepointStatus::Deferred
        | TlsCodepointStatus::PreserveOnly
        | TlsCodepointStatus::Compatibility
        | TlsCodepointStatus::Obsolete
        | TlsCodepointStatus::DtlsOnly
        | TlsCodepointStatus::Unknown => "unknown",
        TlsCodepointStatus::Reserved => "reserved",
        TlsCodepointStatus::ReservedGrease => "reserved grease",
        TlsCodepointStatus::PrivateUse => "private-use",
        TlsCodepointStatus::Experimental => "experimental",
        TlsCodepointStatus::Unassigned => "unassigned",
    };

    match hex_digits {
        2 => format!("{prefix} {kind} 0x{value:02x}"),
        4 => format!("{prefix} {kind} 0x{value:04x}"),
        _ => format!("{prefix} {kind} 0x{value:x}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_constants_ports_and_versions_label_known_and_unknown() {
        assert_eq!(TLS_PORT, 443);
        assert_eq!(tls_tcp_port_name(TLS_PORT_HTTPS), Some("https"));
        assert_eq!(
            tls_tcp_port_status(TLS_PORT_DNS_OVER_TLS),
            TlsCodepointStatus::DefaultEligible
        );
        assert_eq!(tls_tcp_port_label(65000), "tcp-port-65000");

        assert_eq!(tls_protocol_version_name(TLS_VERSION_1_2), Some("TLS 1.2"));
        assert_eq!(
            tls_protocol_version_status(TLS_VERSION_1_3),
            TlsCodepointStatus::DefaultEligible
        );
        assert_eq!(
            tls_protocol_version_status(TLS_VERSION_1_0),
            TlsCodepointStatus::Compatibility
        );
        assert_eq!(
            tls_protocol_version_status(0x0a0a),
            TlsCodepointStatus::ReservedGrease
        );
        assert_eq!(
            tls_protocol_version_label(0x7a7a),
            "reserved grease protocol version 0x7a7a"
        );
        assert_eq!(
            tls_protocol_version_label(0x4242),
            "unknown protocol version 0x4242"
        );
    }

    #[test]
    fn tls_constants_content_handshake_and_alert_helpers_preserve_values() {
        assert_eq!(
            tls_content_type_status(TLS_CONTENT_TYPE_HANDSHAKE),
            TlsCodepointStatus::DefaultEligible
        );
        assert_eq!(
            tls_content_type_status(TLS_CONTENT_TYPE_HEARTBEAT),
            TlsCodepointStatus::LabelEligible
        );
        assert_eq!(tls_content_type_label(0x30), "reserved content type 0x30");

        assert_eq!(
            tls_handshake_type_name(TLS_HANDSHAKE_TYPE_CLIENT_HELLO),
            Some("client_hello")
        );
        assert_eq!(
            tls_handshake_type_status(TLS_HANDSHAKE_TYPE_COMPRESSED_CERTIFICATE),
            TlsCodepointStatus::Deferred
        );
        assert_eq!(
            tls_handshake_type_status(TLS_HANDSHAKE_TYPE_MESSAGE_HASH),
            TlsCodepointStatus::PreserveOnly
        );
        assert_eq!(
            tls_handshake_type_label(0x12),
            "unassigned handshake type 0x12"
        );

        assert_eq!(tls_alert_level_name(TLS_ALERT_LEVEL_FATAL), Some("fatal"));
        assert_eq!(
            tls_alert_description_name(TLS_ALERT_DESCRIPTION_DECODE_ERROR),
            Some("decode_error")
        );
        assert_eq!(
            tls_alert_description_status(TLS_ALERT_DESCRIPTION_DECRYPTION_FAILED_RESERVED),
            TlsCodepointStatus::PreserveOnly
        );
        assert_eq!(
            tls_alert_description_label(0x07),
            "unassigned alert description 0x07"
        );
    }

    #[test]
    fn tls_constants_extensions_and_cipher_suites_classify_registry_rows() {
        assert_eq!(
            tls_extension_status(TLS_EXTENSION_SERVER_NAME),
            TlsCodepointStatus::DefaultEligible
        );
        assert_eq!(
            tls_extension_status(TLS_EXTENSION_HEARTBEAT),
            TlsCodepointStatus::Deferred
        );
        assert_eq!(
            tls_extension_status(TLS_EXTENSION_STATUS_REQUEST_V2),
            TlsCodepointStatus::LabelEligible
        );
        assert_eq!(
            tls_extension_status(TLS_EXTENSION_ENCRYPTED_CLIENT_HELLO),
            TlsCodepointStatus::PreserveOnly
        );
        assert_eq!(
            tls_extension_status(0x1a1a),
            TlsCodepointStatus::ReservedGrease
        );
        assert_eq!(tls_extension_label(0xfe0e), "unknown extension 0xfe0e");
        assert_eq!(tls_extension_label(0xff10), "private-use extension 0xff10");
        assert_eq!(
            tls_certificate_status_type_status(TLS_CERTIFICATE_STATUS_TYPE_OCSP),
            TlsCodepointStatus::DefaultEligible
        );
        assert_eq!(
            tls_certificate_status_type_status(TLS_CERTIFICATE_STATUS_TYPE_OCSP_MULTI_RESERVED),
            TlsCodepointStatus::PreserveOnly
        );
        assert_eq!(
            tls_certificate_status_type_label(0x7a),
            "unassigned certificate status type 0x7a"
        );

        assert_eq!(
            tls_cipher_suite_name(TLS_CIPHER_SUITE_AES_128_GCM_SHA256),
            Some("TLS_AES_128_GCM_SHA256")
        );
        assert_eq!(
            tls_cipher_suite_status(TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
            TlsCodepointStatus::LabelEligible
        );
        assert_eq!(
            tls_cipher_suite_status(TLS_CIPHER_SUITE_FALLBACK_SCSV),
            TlsCodepointStatus::PreserveOnly
        );
        assert_eq!(
            tls_cipher_suite_label(0x0a0a),
            "reserved grease cipher suite 0x0a0a"
        );
    }

    #[test]
    fn tls_constants_groups_signatures_psk_and_compression_classify_rows() {
        assert_eq!(
            tls_named_group_status(TLS_NAMED_GROUP_X25519),
            TlsCodepointStatus::DefaultEligible
        );
        assert_eq!(
            tls_named_group_status(TLS_NAMED_GROUP_FFDHE2048),
            TlsCodepointStatus::PreserveOnly
        );
        assert_eq!(
            tls_named_group_label(0xfe00),
            "private-use named group 0xfe00"
        );

        assert_eq!(
            tls_signature_scheme_status(TLS_SIGNATURE_SCHEME_ED25519),
            TlsCodepointStatus::DefaultEligible
        );
        assert_eq!(
            tls_signature_scheme_status(TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA1),
            TlsCodepointStatus::PreserveOnly
        );
        assert_eq!(
            tls_signature_scheme_label(0x2a2a),
            "reserved grease signature scheme 0x2a2a"
        );

        assert_eq!(
            tls_psk_mode_status(TLS_PSK_MODE_PSK_DHE_KE),
            TlsCodepointStatus::DefaultEligible
        );
        assert_eq!(
            tls_psk_mode_status(0x2a),
            TlsCodepointStatus::ReservedGrease
        );
        assert_eq!(tls_psk_mode_label(0x02), "unassigned psk mode 0x02");

        assert_eq!(
            tls_cert_compression_algorithm_status(TLS_CERT_COMPRESSION_ALGORITHM_ZSTD),
            TlsCodepointStatus::Deferred
        );
        assert_eq!(
            tls_cert_compression_algorithm_status(16_384),
            TlsCodepointStatus::Experimental
        );
        assert_eq!(
            tls_cert_compression_algorithm_label(4),
            "unassigned certificate compression algorithm 0x0004"
        );
    }
}
