//! TLS handshake message helpers.
//!
//! A TLS handshake message starts with a one-octet `HandshakeType` followed by
//! a three-octet big-endian body length. Unknown, unsupported, or intentionally
//! raw message bodies stay opaque so callers can preserve bytes.

use core::fmt;

use super::cipher_suite::{TlsCipherSuite, TlsCipherSuiteList, TLS_CIPHER_SUITE_LEN};
use super::constants::{self, TlsCodepointStatus};
use super::extension::{
    TlsCertificateAuthorities, TlsExtensionListContext, TlsExtensions, TlsRawExtension,
    TlsSignatureAlgorithms,
};
use super::signature_scheme::{TlsSignatureScheme, TLS_SIGNATURE_SCHEME_LEN};
use super::version::TlsVersion;
use crate::field::{Field, FieldState};
use crate::protocols::transport::common::hex_bytes;
use crate::{CrafterError, Result};

/// TLS handshake type field width in bytes.
pub const TLS_HANDSHAKE_TYPE_LEN: usize = 1;
/// TLS handshake message body length field width in bytes.
pub const TLS_HANDSHAKE_LENGTH_LEN: usize = 3;
/// TLS handshake header width in bytes.
pub const TLS_HANDSHAKE_HEADER_LEN: usize = TLS_HANDSHAKE_TYPE_LEN + TLS_HANDSHAKE_LENGTH_LEN;
/// Maximum body length representable by the TLS handshake three-octet length.
pub const TLS_HANDSHAKE_MAX_LENGTH: u32 = 0x00ff_ffff;
/// TLS ClientHello legacy-version field width in bytes.
pub const TLS_CLIENT_HELLO_LEGACY_VERSION_LEN: usize = 2;
/// TLS ClientHello random field width in bytes.
pub const TLS_CLIENT_HELLO_RANDOM_LEN: usize = 32;
/// TLS ClientHello fixed field width before vectors.
pub const TLS_CLIENT_HELLO_FIXED_LEN: usize =
    TLS_CLIENT_HELLO_LEGACY_VERSION_LEN + TLS_CLIENT_HELLO_RANDOM_LEN;
/// TLS ServerHello legacy-version field width in bytes.
pub const TLS_SERVER_HELLO_LEGACY_VERSION_LEN: usize = 2;
/// TLS ServerHello random field width in bytes.
pub const TLS_SERVER_HELLO_RANDOM_LEN: usize = 32;
/// RFC 8446 HelloRetryRequest random marker inside a ServerHello body.
pub const TLS_HELLO_RETRY_REQUEST_RANDOM: [u8; TLS_SERVER_HELLO_RANDOM_LEN] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];
/// TLS ServerHello fixed field width before vectors.
pub const TLS_SERVER_HELLO_FIXED_LEN: usize =
    TLS_SERVER_HELLO_LEGACY_VERSION_LEN + TLS_SERVER_HELLO_RANDOM_LEN;
/// TLS legacy null compression method byte.
pub const TLS_COMPRESSION_METHOD_NULL: u8 = 0x00;
/// TLS 1.2 CertificateRequest ClientCertificateType vector length field width in bytes.
pub const TLS_CERTIFICATE_REQUEST_TYPES_LENGTH_LEN: usize = 1;
/// TLS Certificate request-context length field width in bytes.
pub const TLS_CERTIFICATE_REQUEST_CONTEXT_LENGTH_LEN: usize = 1;
/// TLS Certificate certificate-list length field width in bytes.
pub const TLS_CERTIFICATE_LIST_LENGTH_LEN: usize = 3;
/// TLS CertificateEntry certificate-data length field width in bytes.
pub const TLS_CERTIFICATE_ENTRY_LENGTH_LEN: usize = 3;
/// TLS CertificateVerify signature length field width in bytes.
pub const TLS_CERTIFICATE_VERIFY_SIGNATURE_LENGTH_LEN: usize = 2;
/// TLS NewSessionTicket lifetime field width in bytes.
pub const TLS_NEW_SESSION_TICKET_LIFETIME_LEN: usize = 4;
/// TLS 1.3 NewSessionTicket ticket_age_add field width in bytes.
pub const TLS_NEW_SESSION_TICKET_AGE_ADD_LEN: usize = 4;
/// TLS 1.3 NewSessionTicket ticket_nonce length field width in bytes.
pub const TLS_NEW_SESSION_TICKET_NONCE_LENGTH_LEN: usize = 1;
/// TLS NewSessionTicket ticket length field width in bytes.
pub const TLS_NEW_SESSION_TICKET_TICKET_LENGTH_LEN: usize = 2;
/// TLS KeyUpdate request_update field width in bytes.
pub const TLS_KEY_UPDATE_REQUEST_LEN: usize = 1;
/// TLS KeyUpdateRequest `update_not_requested`.
pub const TLS_KEY_UPDATE_REQUEST_UPDATE_NOT_REQUESTED: u8 = 0;
/// TLS KeyUpdateRequest `update_requested`.
pub const TLS_KEY_UPDATE_REQUEST_UPDATE_REQUESTED: u8 = 1;
/// TLS ClientCertificateType `rsa_sign`.
pub const TLS_CLIENT_CERTIFICATE_TYPE_RSA_SIGN: u8 = 1;
/// TLS ClientCertificateType `dss_sign`.
pub const TLS_CLIENT_CERTIFICATE_TYPE_DSS_SIGN: u8 = 2;
/// TLS ClientCertificateType `rsa_fixed_dh`.
pub const TLS_CLIENT_CERTIFICATE_TYPE_RSA_FIXED_DH: u8 = 3;
/// TLS ClientCertificateType `dss_fixed_dh`.
pub const TLS_CLIENT_CERTIFICATE_TYPE_DSS_FIXED_DH: u8 = 4;
/// TLS ClientCertificateType `rsa_ephemeral_dh_RESERVED`.
pub const TLS_CLIENT_CERTIFICATE_TYPE_RSA_EPHEMERAL_DH_RESERVED: u8 = 5;
/// TLS ClientCertificateType `dss_ephemeral_dh_RESERVED`.
pub const TLS_CLIENT_CERTIFICATE_TYPE_DSS_EPHEMERAL_DH_RESERVED: u8 = 6;
/// TLS ClientCertificateType `fortezza_dms_RESERVED`.
pub const TLS_CLIENT_CERTIFICATE_TYPE_FORTEZZA_DMS_RESERVED: u8 = 20;
/// TLS ClientCertificateType `ecdsa_sign`.
pub const TLS_CLIENT_CERTIFICATE_TYPE_ECDSA_SIGN: u8 = 64;
/// TLS ClientCertificateType `rsa_fixed_ecdh`.
pub const TLS_CLIENT_CERTIFICATE_TYPE_RSA_FIXED_ECDH: u8 = 65;
/// TLS ClientCertificateType `ecdsa_fixed_ecdh`.
pub const TLS_CLIENT_CERTIFICATE_TYPE_ECDSA_FIXED_ECDH: u8 = 66;

/// A raw-preserving TLS `HandshakeType` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TlsHandshakeType {
    raw: u8,
}

impl TlsHandshakeType {
    /// TLS HandshakeType `hello_request_RESERVED`.
    pub const HELLO_REQUEST_RESERVED: Self =
        Self::new(constants::TLS_HANDSHAKE_TYPE_HELLO_REQUEST_RESERVED);
    /// TLS HandshakeType `client_hello`.
    pub const CLIENT_HELLO: Self = Self::new(constants::TLS_HANDSHAKE_TYPE_CLIENT_HELLO);
    /// TLS HandshakeType `server_hello`.
    pub const SERVER_HELLO: Self = Self::new(constants::TLS_HANDSHAKE_TYPE_SERVER_HELLO);
    /// TLS HandshakeType `hello_verify_request_RESERVED`.
    pub const HELLO_VERIFY_REQUEST_RESERVED: Self =
        Self::new(constants::TLS_HANDSHAKE_TYPE_HELLO_VERIFY_REQUEST_RESERVED);
    /// TLS HandshakeType `new_session_ticket`.
    pub const NEW_SESSION_TICKET: Self =
        Self::new(constants::TLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET);
    /// TLS HandshakeType `end_of_early_data`.
    pub const END_OF_EARLY_DATA: Self = Self::new(constants::TLS_HANDSHAKE_TYPE_END_OF_EARLY_DATA);
    /// TLS HandshakeType `hello_retry_request_RESERVED`.
    pub const HELLO_RETRY_REQUEST_RESERVED: Self =
        Self::new(constants::TLS_HANDSHAKE_TYPE_HELLO_RETRY_REQUEST_RESERVED);
    /// TLS HandshakeType `encrypted_extensions`.
    pub const ENCRYPTED_EXTENSIONS: Self =
        Self::new(constants::TLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS);
    /// DTLS HandshakeType `request_connection_id`, preserved by value.
    pub const REQUEST_CONNECTION_ID: Self =
        Self::new(constants::TLS_HANDSHAKE_TYPE_REQUEST_CONNECTION_ID);
    /// DTLS HandshakeType `new_connection_id`, preserved by value.
    pub const NEW_CONNECTION_ID: Self = Self::new(constants::TLS_HANDSHAKE_TYPE_NEW_CONNECTION_ID);
    /// TLS HandshakeType `certificate`.
    pub const CERTIFICATE: Self = Self::new(constants::TLS_HANDSHAKE_TYPE_CERTIFICATE);
    /// TLS HandshakeType `server_key_exchange_RESERVED`.
    pub const SERVER_KEY_EXCHANGE_RESERVED: Self =
        Self::new(constants::TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE_RESERVED);
    /// TLS HandshakeType `certificate_request`.
    pub const CERTIFICATE_REQUEST: Self =
        Self::new(constants::TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST);
    /// TLS HandshakeType `server_hello_done_RESERVED`.
    pub const SERVER_HELLO_DONE_RESERVED: Self =
        Self::new(constants::TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE_RESERVED);
    /// TLS HandshakeType `certificate_verify`.
    pub const CERTIFICATE_VERIFY: Self =
        Self::new(constants::TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY);
    /// TLS HandshakeType `client_key_exchange_RESERVED`.
    pub const CLIENT_KEY_EXCHANGE_RESERVED: Self =
        Self::new(constants::TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE_RESERVED);
    /// TLS HandshakeType `client_certificate_request`.
    pub const CLIENT_CERTIFICATE_REQUEST: Self =
        Self::new(constants::TLS_HANDSHAKE_TYPE_CLIENT_CERTIFICATE_REQUEST);
    /// TLS HandshakeType `finished`.
    pub const FINISHED: Self = Self::new(constants::TLS_HANDSHAKE_TYPE_FINISHED);
    /// TLS HandshakeType `certificate_url_RESERVED`.
    pub const CERTIFICATE_URL_RESERVED: Self =
        Self::new(constants::TLS_HANDSHAKE_TYPE_CERTIFICATE_URL_RESERVED);
    /// TLS HandshakeType `certificate_status_RESERVED`.
    pub const CERTIFICATE_STATUS_RESERVED: Self =
        Self::new(constants::TLS_HANDSHAKE_TYPE_CERTIFICATE_STATUS_RESERVED);
    /// TLS HandshakeType `supplemental_data_RESERVED`.
    pub const SUPPLEMENTAL_DATA_RESERVED: Self =
        Self::new(constants::TLS_HANDSHAKE_TYPE_SUPPLEMENTAL_DATA_RESERVED);
    /// TLS HandshakeType `key_update`.
    pub const KEY_UPDATE: Self = Self::new(constants::TLS_HANDSHAKE_TYPE_KEY_UPDATE);
    /// TLS HandshakeType `compressed_certificate`.
    pub const COMPRESSED_CERTIFICATE: Self =
        Self::new(constants::TLS_HANDSHAKE_TYPE_COMPRESSED_CERTIFICATE);
    /// DTLS HandshakeType `ekt_key`, preserved by value.
    pub const EKT_KEY: Self = Self::new(constants::TLS_HANDSHAKE_TYPE_EKT_KEY);
    /// TLS HandshakeType `message_hash`, preserved by value.
    pub const MESSAGE_HASH: Self = Self::new(constants::TLS_HANDSHAKE_TYPE_MESSAGE_HASH);

    /// Preserve a caller-supplied raw one-octet handshake type.
    pub const fn new(raw: u8) -> Self {
        Self { raw }
    }

    /// Preserve a caller-supplied raw one-octet handshake type.
    pub const fn from_u8(raw: u8) -> Self {
        Self::new(raw)
    }

    /// Preserve a caller-supplied raw one-octet handshake type.
    pub const fn from_byte(raw: u8) -> Self {
        Self::new(raw)
    }

    /// TLS HandshakeType `client_hello` constructor.
    pub const fn client_hello() -> Self {
        Self::CLIENT_HELLO
    }

    /// TLS HandshakeType `server_hello` constructor.
    pub const fn server_hello() -> Self {
        Self::SERVER_HELLO
    }

    /// TLS HandshakeType `new_session_ticket` constructor.
    pub const fn new_session_ticket() -> Self {
        Self::NEW_SESSION_TICKET
    }

    /// TLS HandshakeType `end_of_early_data` constructor.
    pub const fn end_of_early_data() -> Self {
        Self::END_OF_EARLY_DATA
    }

    /// TLS HandshakeType `encrypted_extensions` constructor.
    pub const fn encrypted_extensions() -> Self {
        Self::ENCRYPTED_EXTENSIONS
    }

    /// TLS HandshakeType `certificate` constructor.
    pub const fn certificate() -> Self {
        Self::CERTIFICATE
    }

    /// TLS HandshakeType `certificate_request` constructor.
    pub const fn certificate_request() -> Self {
        Self::CERTIFICATE_REQUEST
    }

    /// TLS HandshakeType `certificate_verify` constructor.
    pub const fn certificate_verify() -> Self {
        Self::CERTIFICATE_VERIFY
    }

    /// TLS HandshakeType `finished` constructor.
    pub const fn finished() -> Self {
        Self::FINISHED
    }

    /// TLS HandshakeType `key_update` constructor.
    pub const fn key_update() -> Self {
        Self::KEY_UPDATE
    }

    /// TLS HandshakeType `compressed_certificate` constructor.
    pub const fn compressed_certificate() -> Self {
        Self::COMPRESSED_CERTIFICATE
    }

    /// Return the preserved raw one-octet wire value.
    pub const fn raw(self) -> u8 {
        self.raw
    }

    /// Return the preserved raw one-octet wire value.
    pub const fn as_u8(self) -> u8 {
        self.raw
    }

    /// Return the one-byte wire encoding.
    pub const fn to_byte(self) -> u8 {
        self.raw
    }

    /// Append the one-byte wire encoding to `out`.
    pub fn encode(self, out: &mut Vec<u8>) {
        out.push(self.to_byte());
    }

    /// Return the one-byte wire encoding as a vector.
    pub fn encode_to_vec(self) -> Vec<u8> {
        vec![self.to_byte()]
    }

    /// Decode a TLS handshake type from the first byte of `bytes`.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (handshake_type, _) = Self::decode_prefix(bytes.as_ref())?;
        Ok(handshake_type)
    }

    /// Decode a TLS handshake type from the front of `bytes`, returning the tail.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_HANDSHAKE_TYPE_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.handshake.type",
                TLS_HANDSHAKE_TYPE_LEN,
                bytes.len(),
            ));
        }

        Ok((Self::from_byte(bytes[0]), &bytes[TLS_HANDSHAKE_TYPE_LEN..]))
    }

    /// Return the source-backed handshake type name, when selected.
    pub const fn name(self) -> Option<&'static str> {
        constants::tls_handshake_type_name(self.raw)
    }

    /// Return the source-backed assignment status.
    pub const fn status(self) -> TlsCodepointStatus {
        constants::tls_handshake_type_status(self.raw)
    }

    /// Return true when this handshake type has a selected source-backed name.
    pub const fn is_known(self) -> bool {
        self.name().is_some()
    }

    /// Return true for handshake types selected for default TLS-over-TCP behavior.
    pub const fn is_default_eligible(self) -> bool {
        matches!(self.status(), TlsCodepointStatus::DefaultEligible)
    }

    /// Return true for DTLS-oriented handshake types outside TLS-over-TCP.
    pub const fn is_dtls_only(self) -> bool {
        matches!(self.status(), TlsCodepointStatus::DtlsOnly)
    }

    /// Human-readable label preserving unknown values numerically.
    pub fn label(self) -> String {
        constants::tls_handshake_type_label(self.raw)
    }

    /// Stable one-line summary with raw value and source-backed status.
    pub fn summary(self) -> String {
        format!(
            "{} raw=0x{:02x} status={}",
            self.label(),
            self.raw,
            self.status().label()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(self) -> Vec<(&'static str, String)> {
        vec![
            ("handshake_type", self.label()),
            ("raw", format!("0x{:02x}", self.raw)),
            ("status", self.status().label().to_string()),
            ("dtls_only", self.is_dtls_only().to_string()),
        ]
    }
}

impl From<u8> for TlsHandshakeType {
    fn from(value: u8) -> Self {
        Self::new(value)
    }
}

impl From<TlsHandshakeType> for u8 {
    fn from(value: TlsHandshakeType) -> Self {
        value.raw()
    }
}

impl fmt::Display for TlsHandshakeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// Fixed TLS handshake message header.
///
/// The `length` field is stored as a [`Field<u32>`] because the wire encoding
/// is a TLS `uint24`. Unset lengths are filled from a body byte count during
/// header encoding. Decoded or caller-pinned lengths are preserved verbatim
/// when they fit in the three-octet TLS handshake length field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsHandshakeHeader {
    handshake_type: TlsHandshakeType,
    declared_length: Field<u32>,
}

impl TlsHandshakeHeader {
    /// Construct a TLS handshake header with an unset body length.
    pub fn new(handshake_type: impl Into<TlsHandshakeType>) -> Self {
        Self {
            handshake_type: handshake_type.into(),
            declared_length: Field::unset(),
        }
    }

    /// Construct a TLS handshake header from all non-derived header fields.
    pub fn from_fields(handshake_type: impl Into<TlsHandshakeType>) -> Self {
        Self::new(handshake_type)
    }

    /// Construct a decoded TLS handshake header, preserving the wire length field.
    pub fn from_decoded_parts(
        handshake_type: impl Into<TlsHandshakeType>,
        declared_length: u32,
    ) -> Self {
        Self::from_fields(handshake_type).with_declared_length(declared_length)
    }

    /// Construct a `client_hello` handshake header.
    pub fn client_hello() -> Self {
        Self::new(TlsHandshakeType::CLIENT_HELLO)
    }

    /// Construct a `server_hello` handshake header.
    pub fn server_hello() -> Self {
        Self::new(TlsHandshakeType::SERVER_HELLO)
    }

    /// Construct a `new_session_ticket` handshake header.
    pub fn new_session_ticket() -> Self {
        Self::new(TlsHandshakeType::NEW_SESSION_TICKET)
    }

    /// Construct an `end_of_early_data` handshake header.
    pub fn end_of_early_data() -> Self {
        Self::new(TlsHandshakeType::END_OF_EARLY_DATA)
    }

    /// Construct an `encrypted_extensions` handshake header.
    pub fn encrypted_extensions() -> Self {
        Self::new(TlsHandshakeType::ENCRYPTED_EXTENSIONS)
    }

    /// Construct a `certificate` handshake header.
    pub fn certificate() -> Self {
        Self::new(TlsHandshakeType::CERTIFICATE)
    }

    /// Construct a `certificate_request` handshake header.
    pub fn certificate_request() -> Self {
        Self::new(TlsHandshakeType::CERTIFICATE_REQUEST)
    }

    /// Construct a `certificate_verify` handshake header.
    pub fn certificate_verify() -> Self {
        Self::new(TlsHandshakeType::CERTIFICATE_VERIFY)
    }

    /// Construct a `finished` handshake header.
    pub fn finished() -> Self {
        Self::new(TlsHandshakeType::FINISHED)
    }

    /// Construct a `key_update` handshake header.
    pub fn key_update() -> Self {
        Self::new(TlsHandshakeType::KEY_UPDATE)
    }

    /// Construct a `compressed_certificate` handshake header.
    pub fn compressed_certificate() -> Self {
        Self::new(TlsHandshakeType::COMPRESSED_CERTIFICATE)
    }

    /// Replace the handshake type.
    pub fn with_handshake_type(mut self, handshake_type: impl Into<TlsHandshakeType>) -> Self {
        self.handshake_type = handshake_type.into();
        self
    }

    /// Replace the handshake type from a raw one-octet value.
    pub fn with_raw_handshake_type(self, handshake_type: u8) -> Self {
        self.with_handshake_type(TlsHandshakeType::from_u8(handshake_type))
    }

    /// Pin the declared handshake message body length.
    pub fn with_declared_length(mut self, declared_length: u32) -> Self {
        self.declared_length.set_user(declared_length);
        self
    }

    /// Compatibility alias for pinning the declared handshake message body length.
    pub fn with_length(self, declared_length: u32) -> Self {
        self.with_declared_length(declared_length)
    }

    /// Return the handshake type.
    pub const fn handshake_type(&self) -> TlsHandshakeType {
        self.handshake_type
    }

    /// Return the raw handshake type value.
    pub const fn raw_handshake_type(&self) -> u8 {
        self.handshake_type.raw()
    }

    /// Caller-pinned or decoded declared body length, if present.
    pub fn declared_length(&self) -> Option<u32> {
        self.declared_length.value().copied()
    }

    /// Compatibility alias for the declared body length.
    pub fn declared_len(&self) -> Option<u32> {
        self.declared_length()
    }

    /// Compatibility alias for a caller-pinned declared body length.
    pub fn length_override(&self) -> Option<u32> {
        self.declared_length()
    }

    /// Assignment state for the declared body length field.
    pub const fn declared_length_state(&self) -> FieldState {
        self.declared_length.state()
    }

    /// Compatibility alias for the declared body length field state.
    pub const fn length_state(&self) -> FieldState {
        self.declared_length_state()
    }

    /// Declared body length to emit for a given actual body byte count.
    ///
    /// A caller-pinned or decoded length wins. Otherwise the supplied body
    /// length is converted to the three-octet TLS handshake length field.
    pub fn effective_length(&self, actual_body_len: usize) -> Result<u32> {
        match self.declared_length.value() {
            Some(&declared_length) => validate_u24_length(declared_length),
            None => usize_to_u24_length(actual_body_len),
        }
    }

    /// Compatibility alias for the declared body length to emit.
    pub fn declared_length_value(&self, actual_body_len: usize) -> Result<u32> {
        self.effective_length(actual_body_len)
    }

    /// Compatibility alias for the declared body length to emit.
    pub fn length_value(&self, actual_body_len: usize) -> Result<u32> {
        self.effective_length(actual_body_len)
    }

    /// Number of bytes in a TLS handshake header.
    pub const fn header_len(&self) -> usize {
        TLS_HANDSHAKE_HEADER_LEN
    }

    /// Number of bytes emitted by this header.
    pub const fn encoded_len(&self) -> usize {
        TLS_HANDSHAKE_HEADER_LEN
    }

    /// Actual serialized handshake message byte count with `actual_body_len` bytes.
    pub fn actual_message_len(&self, actual_body_len: usize) -> Result<usize> {
        TLS_HANDSHAKE_HEADER_LEN
            .checked_add(actual_body_len)
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.handshake.length", "length overflow")
            })
    }

    /// Declared handshake message byte count from the header length field.
    pub fn declared_message_len(&self, actual_body_len: usize) -> Result<usize> {
        TLS_HANDSHAKE_HEADER_LEN
            .checked_add(self.effective_length(actual_body_len)? as usize)
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.handshake.length", "length overflow")
            })
    }

    /// Append the four-octet handshake header, treating an unset length as zero.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_with_body_len(0, out)
    }

    /// Append the four-octet handshake header, filling unset length from body bytes.
    pub fn encode_with_body_len(&self, actual_body_len: usize, out: &mut Vec<u8>) -> Result<()> {
        self.handshake_type.encode(out);
        out.extend_from_slice(&u24_to_be_bytes(self.effective_length(actual_body_len)?)?);
        Ok(())
    }

    /// Return the four-octet handshake header, treating an unset length as zero.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        self.encode_to_vec_with_body_len(0)
    }

    /// Return the four-octet handshake header, filling unset length from body bytes.
    pub fn encode_to_vec_with_body_len(&self, actual_body_len: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(TLS_HANDSHAKE_HEADER_LEN);
        self.encode_with_body_len(actual_body_len, &mut out)?;
        Ok(out)
    }

    /// Compatibility alias for returning the encoded header.
    pub fn compile(&self) -> Result<Vec<u8>> {
        self.encode_to_vec()
    }

    /// Decode a TLS handshake header from the first four bytes of `bytes`.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (header, _) = Self::decode_prefix(bytes.as_ref())?;
        Ok(header)
    }

    /// Decode a TLS handshake header from the front of `bytes`, returning the tail.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_HANDSHAKE_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.handshake.header",
                TLS_HANDSHAKE_HEADER_LEN,
                bytes.len(),
            ));
        }

        let handshake_type = TlsHandshakeType::from_byte(bytes[0]);
        let declared_length = u24_from_be_bytes([bytes[1], bytes[2], bytes[3]]);

        Ok((
            Self::from_decoded_parts(handshake_type, declared_length),
            &bytes[TLS_HANDSHAKE_HEADER_LEN..],
        ))
    }

    /// Stable one-line summary preserving codepoints and declared length state.
    pub fn summary(&self) -> String {
        format!(
            "handshake_header handshake_type={} declared_length={}",
            self.handshake_type.label(),
            self.length_label()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("handshake_type", self.handshake_type.label()),
            (
                "handshake_type_raw",
                format!("0x{:02x}", self.handshake_type.raw()),
            ),
            (
                "handshake_type_status",
                self.handshake_type.status().label().to_string(),
            ),
            ("declared_length", self.length_label()),
            (
                "declared_length_state",
                field_state_label(self.declared_length.state()).to_string(),
            ),
            ("header_bytes", TLS_HANDSHAKE_HEADER_LEN.to_string()),
        ]
    }

    fn length_label(&self) -> String {
        self.declared_length()
            .map(|length| length.to_string())
            .unwrap_or_else(|| "auto".to_string())
    }
}

/// TLS handshake body hook.
///
/// Specific handshake body grammars are intentionally deferred. Known TLS
/// handshake types get named variants so later source-backed steps can replace
/// the opaque bytes with typed structures without changing the generic
/// container shape. Unknown, unsupported, or intentionally raw bodies use
/// [`TlsHandshakeBody::Opaque`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsHandshakeBody {
    /// `client_hello` body bytes plus a typed view when available.
    ClientHello(TlsClientHelloBody),
    /// `server_hello` body bytes plus a typed view when available.
    ServerHello(TlsServerHelloBody),
    /// `new_session_ticket` body bytes plus a typed view when available.
    NewSessionTicket(TlsNewSessionTicketBody),
    /// `end_of_early_data` body bytes plus a typed view when available.
    EndOfEarlyData(TlsEndOfEarlyDataBody),
    /// `encrypted_extensions` body bytes plus a typed view when available.
    EncryptedExtensions(TlsEncryptedExtensionsBody),
    /// `certificate` body bytes plus a typed view when available.
    Certificate(TlsCertificateBody),
    /// `certificate_request` body bytes plus a typed view when available.
    CertificateRequest(TlsCertificateRequestBody),
    /// `certificate_verify` body bytes plus a typed view when available.
    CertificateVerify(TlsCertificateVerifyBody),
    /// `finished` body bytes plus a typed view when available.
    Finished(TlsFinishedBody),
    /// `key_update` body bytes plus a typed view when available.
    KeyUpdate(TlsKeyUpdateBody),
    /// Opaque `compressed_certificate` body bytes.
    CompressedCertificate(Vec<u8>),
    /// Unknown, unsupported, or intentionally raw handshake body bytes.
    Opaque(Vec<u8>),
}

impl TlsHandshakeBody {
    /// Create an opaque body for a known `client_hello` hook.
    pub fn client_hello(body: impl Into<Vec<u8>>) -> Self {
        Self::ClientHello(TlsClientHelloBody::raw(body))
    }

    /// Create a typed body for a known `client_hello` hook.
    pub fn from_client_hello(client_hello: TlsClientHello) -> Result<Self> {
        Ok(Self::ClientHello(TlsClientHelloBody::from_client_hello(
            client_hello,
        )?))
    }

    /// Create an opaque body for a known `server_hello` hook.
    pub fn server_hello(body: impl Into<Vec<u8>>) -> Self {
        Self::ServerHello(TlsServerHelloBody::raw(body))
    }

    /// Create a typed body for a known `server_hello` hook.
    pub fn from_server_hello(server_hello: TlsServerHello) -> Result<Self> {
        Ok(Self::ServerHello(TlsServerHelloBody::from_server_hello(
            server_hello,
        )?))
    }

    /// Create an opaque body for a known `new_session_ticket` hook.
    pub fn new_session_ticket(body: impl Into<Vec<u8>>) -> Self {
        Self::NewSessionTicket(TlsNewSessionTicketBody::raw(body))
    }

    /// Create a typed body for a known `new_session_ticket` hook.
    pub fn from_new_session_ticket(new_session_ticket: TlsNewSessionTicket) -> Result<Self> {
        Ok(Self::NewSessionTicket(
            TlsNewSessionTicketBody::from_new_session_ticket(new_session_ticket)?,
        ))
    }

    /// Create an opaque body for a known `end_of_early_data` hook.
    pub fn end_of_early_data(body: impl Into<Vec<u8>>) -> Self {
        Self::EndOfEarlyData(TlsEndOfEarlyDataBody::raw(body))
    }

    /// Create a typed body for a known `end_of_early_data` hook.
    pub fn from_end_of_early_data(end_of_early_data: TlsEndOfEarlyData) -> Result<Self> {
        Ok(Self::EndOfEarlyData(
            TlsEndOfEarlyDataBody::from_end_of_early_data(end_of_early_data)?,
        ))
    }

    /// Create an opaque body for a known `encrypted_extensions` hook.
    pub fn encrypted_extensions(body: impl Into<Vec<u8>>) -> Self {
        Self::EncryptedExtensions(TlsEncryptedExtensionsBody::raw(body))
    }

    /// Create a typed body for a known `encrypted_extensions` hook.
    pub fn from_encrypted_extensions(encrypted_extensions: TlsEncryptedExtensions) -> Result<Self> {
        Ok(Self::EncryptedExtensions(
            TlsEncryptedExtensionsBody::from_encrypted_extensions(encrypted_extensions)?,
        ))
    }

    /// Create an opaque body for a known `certificate` hook.
    pub fn certificate(body: impl Into<Vec<u8>>) -> Self {
        Self::Certificate(TlsCertificateBody::raw(body))
    }

    /// Create a typed body for a known `certificate` hook.
    pub fn from_certificate(certificate: TlsCertificate) -> Result<Self> {
        Ok(Self::Certificate(TlsCertificateBody::from_certificate(
            certificate,
        )?))
    }

    /// Create an opaque body for a known `certificate_request` hook.
    pub fn certificate_request(body: impl Into<Vec<u8>>) -> Self {
        Self::CertificateRequest(TlsCertificateRequestBody::raw(body))
    }

    /// Create a typed body for a known `certificate_request` hook.
    pub fn from_certificate_request(certificate_request: TlsCertificateRequest) -> Result<Self> {
        Ok(Self::CertificateRequest(
            TlsCertificateRequestBody::from_certificate_request(certificate_request)?,
        ))
    }

    /// Create an opaque body for a known `certificate_verify` hook.
    pub fn certificate_verify(body: impl Into<Vec<u8>>) -> Self {
        Self::CertificateVerify(TlsCertificateVerifyBody::raw(body))
    }

    /// Create a typed body for a known `certificate_verify` hook.
    pub fn from_certificate_verify(certificate_verify: TlsCertificateVerify) -> Result<Self> {
        Ok(Self::CertificateVerify(
            TlsCertificateVerifyBody::from_certificate_verify(certificate_verify)?,
        ))
    }

    /// Create an opaque body for a known `finished` hook.
    pub fn finished(body: impl Into<Vec<u8>>) -> Self {
        Self::Finished(TlsFinishedBody::raw(body))
    }

    /// Create a typed body for a known `finished` hook.
    pub fn from_finished(finished: TlsFinished) -> Result<Self> {
        Ok(Self::Finished(TlsFinishedBody::from_finished(finished)?))
    }

    /// Create an opaque body for a known `key_update` hook.
    pub fn key_update(body: impl Into<Vec<u8>>) -> Self {
        Self::KeyUpdate(TlsKeyUpdateBody::raw(body))
    }

    /// Create a typed body for a known `key_update` hook.
    pub fn from_key_update(key_update: TlsKeyUpdate) -> Result<Self> {
        Ok(Self::KeyUpdate(TlsKeyUpdateBody::from_key_update(
            key_update,
        )?))
    }

    /// Create an opaque body for a known `compressed_certificate` hook.
    pub fn compressed_certificate(body: impl Into<Vec<u8>>) -> Self {
        Self::CompressedCertificate(body.into())
    }

    /// Preserve body bytes without assigning typed semantics.
    pub fn opaque(body: impl Into<Vec<u8>>) -> Self {
        Self::Opaque(body.into())
    }

    /// Select the current typed hook for `handshake_type`, preserving body bytes.
    pub fn opaque_for_type(
        handshake_type: impl Into<TlsHandshakeType>,
        body: impl Into<Vec<u8>>,
    ) -> Self {
        let body = body.into();
        match handshake_type.into() {
            TlsHandshakeType::CLIENT_HELLO => Self::ClientHello(TlsClientHelloBody::raw(body)),
            TlsHandshakeType::SERVER_HELLO => Self::ServerHello(TlsServerHelloBody::raw(body)),
            TlsHandshakeType::NEW_SESSION_TICKET => {
                Self::NewSessionTicket(TlsNewSessionTicketBody::raw(body))
            }
            TlsHandshakeType::END_OF_EARLY_DATA => {
                Self::EndOfEarlyData(TlsEndOfEarlyDataBody::raw(body))
            }
            TlsHandshakeType::ENCRYPTED_EXTENSIONS => {
                Self::EncryptedExtensions(TlsEncryptedExtensionsBody::raw(body))
            }
            TlsHandshakeType::CERTIFICATE => Self::Certificate(TlsCertificateBody::raw(body)),
            TlsHandshakeType::CERTIFICATE_REQUEST => {
                Self::CertificateRequest(TlsCertificateRequestBody::raw(body))
            }
            TlsHandshakeType::CERTIFICATE_VERIFY => {
                Self::CertificateVerify(TlsCertificateVerifyBody::raw(body))
            }
            TlsHandshakeType::FINISHED => Self::Finished(TlsFinishedBody::raw(body)),
            TlsHandshakeType::KEY_UPDATE => Self::KeyUpdate(TlsKeyUpdateBody::raw(body)),
            TlsHandshakeType::COMPRESSED_CERTIFICATE => Self::CompressedCertificate(body),
            _ => Self::Opaque(body),
        }
    }

    /// Select the current typed hook for `handshake_type`, decoding known bodies.
    fn decoded_for_type(
        handshake_type: impl Into<TlsHandshakeType>,
        body: impl Into<Vec<u8>>,
    ) -> Result<Self> {
        let body = body.into();
        match handshake_type.into() {
            TlsHandshakeType::CLIENT_HELLO => Ok(Self::ClientHello(
                TlsClientHelloBody::from_decoded_body(body)?,
            )),
            TlsHandshakeType::SERVER_HELLO => Ok(Self::ServerHello(
                TlsServerHelloBody::from_decoded_body(body)?,
            )),
            TlsHandshakeType::NEW_SESSION_TICKET => Ok(Self::NewSessionTicket(
                TlsNewSessionTicketBody::from_decoded_body(body)?,
            )),
            TlsHandshakeType::END_OF_EARLY_DATA => Ok(Self::EndOfEarlyData(
                TlsEndOfEarlyDataBody::from_decoded_body(body)?,
            )),
            TlsHandshakeType::ENCRYPTED_EXTENSIONS => Ok(Self::EncryptedExtensions(
                TlsEncryptedExtensionsBody::from_decoded_body(body)?,
            )),
            TlsHandshakeType::CERTIFICATE => Ok(Self::Certificate(
                TlsCertificateBody::from_decoded_body(body)?,
            )),
            TlsHandshakeType::CERTIFICATE_REQUEST => Ok(Self::CertificateRequest(
                TlsCertificateRequestBody::from_decoded_body(body)?,
            )),
            TlsHandshakeType::CERTIFICATE_VERIFY => Ok(Self::CertificateVerify(
                TlsCertificateVerifyBody::from_decoded_body(body)?,
            )),
            TlsHandshakeType::FINISHED => {
                Ok(Self::Finished(TlsFinishedBody::from_decoded_body(body)?))
            }
            TlsHandshakeType::KEY_UPDATE => {
                Ok(Self::KeyUpdate(TlsKeyUpdateBody::from_decoded_body(body)?))
            }
            TlsHandshakeType::COMPRESSED_CERTIFICATE => Ok(Self::CompressedCertificate(body)),
            _ => Ok(Self::Opaque(body)),
        }
    }

    /// Return the handshake type implied by a known body hook, if any.
    pub const fn handshake_type_hint(&self) -> Option<TlsHandshakeType> {
        match self {
            Self::ClientHello(_) => Some(TlsHandshakeType::CLIENT_HELLO),
            Self::ServerHello(_) => Some(TlsHandshakeType::SERVER_HELLO),
            Self::NewSessionTicket(_) => Some(TlsHandshakeType::NEW_SESSION_TICKET),
            Self::EndOfEarlyData(_) => Some(TlsHandshakeType::END_OF_EARLY_DATA),
            Self::EncryptedExtensions(_) => Some(TlsHandshakeType::ENCRYPTED_EXTENSIONS),
            Self::Certificate(_) => Some(TlsHandshakeType::CERTIFICATE),
            Self::CertificateRequest(_) => Some(TlsHandshakeType::CERTIFICATE_REQUEST),
            Self::CertificateVerify(_) => Some(TlsHandshakeType::CERTIFICATE_VERIFY),
            Self::Finished(_) => Some(TlsHandshakeType::FINISHED),
            Self::KeyUpdate(_) => Some(TlsHandshakeType::KEY_UPDATE),
            Self::CompressedCertificate(_) => Some(TlsHandshakeType::COMPRESSED_CERTIFICATE),
            Self::Opaque(_) => None,
        }
    }

    /// Borrow the bytes that will be emitted after the handshake header.
    pub fn body(&self) -> &[u8] {
        match self {
            Self::ClientHello(body) => body.body(),
            Self::ServerHello(body) => body.body(),
            Self::EncryptedExtensions(body) => body.body(),
            Self::Certificate(body) => body.body(),
            Self::CertificateRequest(body) => body.body(),
            Self::CertificateVerify(body) => body.body(),
            Self::Finished(body) => body.body(),
            Self::NewSessionTicket(body) => body.body(),
            Self::EndOfEarlyData(body) => body.body(),
            Self::KeyUpdate(body) => body.body(),
            Self::CompressedCertificate(body) | Self::Opaque(body) => body,
        }
    }

    /// Consume the body hook and return the preserved bytes.
    pub fn into_body(self) -> Vec<u8> {
        match self {
            Self::ClientHello(body) => body.into_body(),
            Self::ServerHello(body) => body.into_body(),
            Self::EncryptedExtensions(body) => body.into_body(),
            Self::Certificate(body) => body.into_body(),
            Self::CertificateRequest(body) => body.into_body(),
            Self::CertificateVerify(body) => body.into_body(),
            Self::Finished(body) => body.into_body(),
            Self::NewSessionTicket(body) => body.into_body(),
            Self::EndOfEarlyData(body) => body.into_body(),
            Self::KeyUpdate(body) => body.into_body(),
            Self::CompressedCertificate(body) | Self::Opaque(body) => body,
        }
    }

    /// Number of preserved body bytes.
    pub fn body_len(&self) -> usize {
        self.body().len()
    }

    /// Return true when this is the generic unknown/raw/opaque body variant.
    pub const fn is_opaque(&self) -> bool {
        matches!(self, Self::Opaque(_))
    }

    /// Return true when this is one of the named known-body hooks.
    pub const fn is_known_hook(&self) -> bool {
        !self.is_opaque()
    }

    /// Borrow the decoded ClientHello fields when this body carries them.
    pub const fn as_client_hello(&self) -> Option<&TlsClientHello> {
        match self {
            Self::ClientHello(body) => body.client_hello(),
            _ => None,
        }
    }

    /// Borrow the decoded ServerHello fields when this body carries them.
    pub const fn as_server_hello(&self) -> Option<&TlsServerHello> {
        match self {
            Self::ServerHello(body) => body.server_hello(),
            _ => None,
        }
    }

    /// Borrow the decoded EncryptedExtensions fields when this body carries them.
    pub const fn as_encrypted_extensions(&self) -> Option<&TlsEncryptedExtensions> {
        match self {
            Self::EncryptedExtensions(body) => body.encrypted_extensions(),
            _ => None,
        }
    }

    /// Borrow the decoded Certificate fields when this body carries them.
    pub const fn as_certificate(&self) -> Option<&TlsCertificate> {
        match self {
            Self::Certificate(body) => body.certificate(),
            _ => None,
        }
    }

    /// Borrow the decoded CertificateRequest fields when this body carries them.
    pub const fn as_certificate_request(&self) -> Option<&TlsCertificateRequest> {
        match self {
            Self::CertificateRequest(body) => body.certificate_request(),
            _ => None,
        }
    }

    /// Borrow the decoded CertificateVerify fields when this body carries them.
    pub const fn as_certificate_verify(&self) -> Option<&TlsCertificateVerify> {
        match self {
            Self::CertificateVerify(body) => body.certificate_verify(),
            _ => None,
        }
    }

    /// Borrow the decoded Finished fields when this body carries them.
    pub const fn as_finished(&self) -> Option<&TlsFinished> {
        match self {
            Self::Finished(body) => body.finished(),
            _ => None,
        }
    }

    /// Borrow the decoded NewSessionTicket fields when this body carries them.
    pub const fn as_new_session_ticket(&self) -> Option<&TlsNewSessionTicket> {
        match self {
            Self::NewSessionTicket(body) => body.new_session_ticket(),
            _ => None,
        }
    }

    /// Borrow the decoded EndOfEarlyData fields when this body carries them.
    pub const fn as_end_of_early_data(&self) -> Option<&TlsEndOfEarlyData> {
        match self {
            Self::EndOfEarlyData(body) => body.end_of_early_data(),
            _ => None,
        }
    }

    /// Borrow the decoded KeyUpdate fields when this body carries them.
    pub const fn as_key_update(&self) -> Option<&TlsKeyUpdate> {
        match self {
            Self::KeyUpdate(body) => body.key_update(),
            _ => None,
        }
    }

    /// Return true when this body is a decoded or typed ClientHello.
    pub const fn is_typed_client_hello(&self) -> bool {
        match self {
            Self::ClientHello(body) => body.is_typed(),
            _ => false,
        }
    }

    /// Return true when this body is a decoded or typed ServerHello.
    pub const fn is_typed_server_hello(&self) -> bool {
        match self {
            Self::ServerHello(body) => body.is_typed(),
            _ => false,
        }
    }

    /// Return true when this body is a decoded or typed EncryptedExtensions.
    pub const fn is_typed_encrypted_extensions(&self) -> bool {
        match self {
            Self::EncryptedExtensions(body) => body.is_typed(),
            _ => false,
        }
    }

    /// Return true when this body is a decoded or typed Certificate.
    pub const fn is_typed_certificate(&self) -> bool {
        match self {
            Self::Certificate(body) => body.is_typed(),
            _ => false,
        }
    }

    /// Return true when this body is a decoded or typed CertificateRequest.
    pub const fn is_typed_certificate_request(&self) -> bool {
        match self {
            Self::CertificateRequest(body) => body.is_typed(),
            _ => false,
        }
    }

    /// Return true when this body is a decoded or typed CertificateVerify.
    pub const fn is_typed_certificate_verify(&self) -> bool {
        match self {
            Self::CertificateVerify(body) => body.is_typed(),
            _ => false,
        }
    }

    /// Return true when this body is a decoded or typed Finished.
    pub const fn is_typed_finished(&self) -> bool {
        match self {
            Self::Finished(body) => body.is_typed(),
            _ => false,
        }
    }

    /// Return true when this body is a decoded or typed NewSessionTicket.
    pub const fn is_typed_new_session_ticket(&self) -> bool {
        match self {
            Self::NewSessionTicket(body) => body.is_typed(),
            _ => false,
        }
    }

    /// Return true when this body is a decoded or typed EndOfEarlyData.
    pub const fn is_typed_end_of_early_data(&self) -> bool {
        match self {
            Self::EndOfEarlyData(body) => body.is_typed(),
            _ => false,
        }
    }

    /// Return true when this body is a decoded or typed KeyUpdate.
    pub const fn is_typed_key_update(&self) -> bool {
        match self {
            Self::KeyUpdate(body) => body.is_typed(),
            _ => false,
        }
    }

    /// Append the preserved body bytes to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.body());
    }

    /// Return the preserved body bytes as a new vector.
    pub fn encode_to_vec(&self) -> Vec<u8> {
        self.body().to_vec()
    }

    /// Stable one-line summary for the selected handshake body hook.
    pub fn summary(&self) -> String {
        match self {
            Self::ClientHello(body) => body
                .client_hello()
                .map(TlsClientHello::summary)
                .unwrap_or_else(|| format!("client_hello raw_body_bytes={}", body.body_len())),
            Self::ServerHello(body) => body
                .server_hello()
                .map(TlsServerHello::summary)
                .unwrap_or_else(|| format!("server_hello raw_body_bytes={}", body.body_len())),
            Self::NewSessionTicket(body) => body
                .new_session_ticket()
                .map(TlsNewSessionTicket::summary)
                .unwrap_or_else(|| {
                    format!("new_session_ticket raw_body_bytes={}", body.body_len())
                }),
            Self::EndOfEarlyData(body) => body
                .end_of_early_data()
                .map(TlsEndOfEarlyData::summary)
                .unwrap_or_else(|| format!("end_of_early_data raw_body_bytes={}", body.body_len())),
            Self::EncryptedExtensions(body) => body
                .encrypted_extensions()
                .map(TlsEncryptedExtensions::summary)
                .unwrap_or_else(|| {
                    format!("encrypted_extensions raw_body_bytes={}", body.body_len())
                }),
            Self::Certificate(body) => body
                .certificate()
                .map(TlsCertificate::summary)
                .unwrap_or_else(|| format!("certificate raw_body_bytes={}", body.body_len())),
            Self::CertificateRequest(body) => body
                .certificate_request()
                .map(TlsCertificateRequest::summary)
                .unwrap_or_else(|| {
                    format!("certificate_request raw_body_bytes={}", body.body_len())
                }),
            Self::CertificateVerify(body) => body
                .certificate_verify()
                .map(TlsCertificateVerify::summary)
                .unwrap_or_else(|| {
                    format!("certificate_verify raw_body_bytes={}", body.body_len())
                }),
            Self::Finished(body) => body
                .finished()
                .map(TlsFinished::summary)
                .unwrap_or_else(|| format!("finished raw_body_bytes={}", body.body_len())),
            Self::KeyUpdate(body) => body
                .key_update()
                .map(TlsKeyUpdate::summary)
                .unwrap_or_else(|| format!("key_update raw_body_bytes={}", body.body_len())),
            Self::CompressedCertificate(body) => {
                format!("compressed_certificate raw_body_bytes={}", body.len())
            }
            Self::Opaque(body) => format!("opaque raw_body_bytes={}", body.len()),
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::ClientHello(_) => "client_hello",
            Self::ServerHello(_) => "server_hello",
            Self::NewSessionTicket(_) => "new_session_ticket",
            Self::EndOfEarlyData(_) => "end_of_early_data",
            Self::EncryptedExtensions(_) => "encrypted_extensions",
            Self::Certificate(_) => "certificate",
            Self::CertificateRequest(_) => "certificate_request",
            Self::CertificateVerify(_) => "certificate_verify",
            Self::Finished(_) => "finished",
            Self::KeyUpdate(_) => "key_update",
            Self::CompressedCertificate(_) => "compressed_certificate",
            Self::Opaque(_) => "opaque",
        }
    }
}

impl From<Vec<u8>> for TlsHandshakeBody {
    fn from(body: Vec<u8>) -> Self {
        Self::opaque(body)
    }
}

/// A complete generic TLS handshake message.
///
/// The header length field is auto-filled from the body byte count during
/// encoding unless the caller pinned a declared length on the header. Decoded
/// messages preserve the on-wire declared length and the exact body bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsHandshake {
    header: TlsHandshakeHeader,
    body: TlsHandshakeBody,
}

impl TlsHandshake {
    /// Construct an empty TLS handshake message for `handshake_type`.
    pub fn new(handshake_type: impl Into<TlsHandshakeType>) -> Self {
        let handshake_type = handshake_type.into();
        Self {
            header: TlsHandshakeHeader::new(handshake_type),
            body: TlsHandshakeBody::opaque_for_type(handshake_type, Vec::new()),
        }
    }

    /// Construct a TLS handshake message from a type and opaque body bytes.
    pub fn from_body(
        handshake_type: impl Into<TlsHandshakeType>,
        body: impl Into<Vec<u8>>,
    ) -> Self {
        let handshake_type = handshake_type.into();
        Self {
            header: TlsHandshakeHeader::new(handshake_type),
            body: TlsHandshakeBody::opaque_for_type(handshake_type, body),
        }
    }

    /// Construct a TLS handshake message from a complete header and body hook.
    pub fn from_header_and_body(
        header: TlsHandshakeHeader,
        body: impl Into<TlsHandshakeBody>,
    ) -> Self {
        Self {
            header,
            body: body.into(),
        }
    }

    /// Construct a decoded TLS handshake message, preserving header fields.
    pub fn from_decoded_parts(header: TlsHandshakeHeader, body: impl Into<Vec<u8>>) -> Self {
        let body = TlsHandshakeBody::opaque_for_type(header.handshake_type(), body);
        Self::from_header_and_body(header, body)
    }

    /// Construct a `client_hello` handshake message with opaque body bytes.
    pub fn client_hello(body: impl Into<Vec<u8>>) -> Self {
        Self::from_header_and_body(
            TlsHandshakeHeader::client_hello(),
            TlsHandshakeBody::client_hello(body),
        )
    }

    /// Construct a `client_hello` handshake message from typed ClientHello fields.
    pub fn from_client_hello(client_hello: TlsClientHello) -> Result<Self> {
        Ok(Self::from_header_and_body(
            TlsHandshakeHeader::client_hello(),
            TlsHandshakeBody::from_client_hello(client_hello)?,
        ))
    }

    /// Construct a `server_hello` handshake message with opaque body bytes.
    pub fn server_hello(body: impl Into<Vec<u8>>) -> Self {
        Self::from_header_and_body(
            TlsHandshakeHeader::server_hello(),
            TlsHandshakeBody::server_hello(body),
        )
    }

    /// Construct a `server_hello` handshake message from typed ServerHello fields.
    pub fn from_server_hello(server_hello: TlsServerHello) -> Result<Self> {
        Ok(Self::from_header_and_body(
            TlsHandshakeHeader::server_hello(),
            TlsHandshakeBody::from_server_hello(server_hello)?,
        ))
    }

    /// Construct a `new_session_ticket` handshake message with opaque body bytes.
    pub fn new_session_ticket(body: impl Into<Vec<u8>>) -> Self {
        Self::from_header_and_body(
            TlsHandshakeHeader::new_session_ticket(),
            TlsHandshakeBody::new_session_ticket(body),
        )
    }

    /// Construct a `new_session_ticket` handshake message from typed fields.
    pub fn from_new_session_ticket(new_session_ticket: TlsNewSessionTicket) -> Result<Self> {
        Ok(Self::from_header_and_body(
            TlsHandshakeHeader::new_session_ticket(),
            TlsHandshakeBody::from_new_session_ticket(new_session_ticket)?,
        ))
    }

    /// Construct an `end_of_early_data` handshake message with opaque body bytes.
    pub fn end_of_early_data(body: impl Into<Vec<u8>>) -> Self {
        Self::from_header_and_body(
            TlsHandshakeHeader::end_of_early_data(),
            TlsHandshakeBody::end_of_early_data(body),
        )
    }

    /// Construct an `end_of_early_data` handshake message from typed fields.
    pub fn from_end_of_early_data(end_of_early_data: TlsEndOfEarlyData) -> Result<Self> {
        Ok(Self::from_header_and_body(
            TlsHandshakeHeader::end_of_early_data(),
            TlsHandshakeBody::from_end_of_early_data(end_of_early_data)?,
        ))
    }

    /// Construct an `encrypted_extensions` handshake message with opaque body bytes.
    pub fn encrypted_extensions(body: impl Into<Vec<u8>>) -> Self {
        Self::from_header_and_body(
            TlsHandshakeHeader::encrypted_extensions(),
            TlsHandshakeBody::encrypted_extensions(body),
        )
    }

    /// Construct an `encrypted_extensions` handshake message from typed fields.
    pub fn from_encrypted_extensions(encrypted_extensions: TlsEncryptedExtensions) -> Result<Self> {
        Ok(Self::from_header_and_body(
            TlsHandshakeHeader::encrypted_extensions(),
            TlsHandshakeBody::from_encrypted_extensions(encrypted_extensions)?,
        ))
    }

    /// Construct a `certificate` handshake message with opaque body bytes.
    pub fn certificate(body: impl Into<Vec<u8>>) -> Self {
        Self::from_header_and_body(
            TlsHandshakeHeader::certificate(),
            TlsHandshakeBody::certificate(body),
        )
    }

    /// Construct a `certificate` handshake message from typed fields.
    pub fn from_certificate(certificate: TlsCertificate) -> Result<Self> {
        Ok(Self::from_header_and_body(
            TlsHandshakeHeader::certificate(),
            TlsHandshakeBody::from_certificate(certificate)?,
        ))
    }

    /// Construct a `certificate_request` handshake message with opaque body bytes.
    pub fn certificate_request(body: impl Into<Vec<u8>>) -> Self {
        Self::from_header_and_body(
            TlsHandshakeHeader::certificate_request(),
            TlsHandshakeBody::certificate_request(body),
        )
    }

    /// Construct a `certificate_request` handshake message from typed fields.
    pub fn from_certificate_request(certificate_request: TlsCertificateRequest) -> Result<Self> {
        Ok(Self::from_header_and_body(
            TlsHandshakeHeader::certificate_request(),
            TlsHandshakeBody::from_certificate_request(certificate_request)?,
        ))
    }

    /// Construct a `certificate_verify` handshake message with opaque body bytes.
    pub fn certificate_verify(body: impl Into<Vec<u8>>) -> Self {
        Self::from_header_and_body(
            TlsHandshakeHeader::certificate_verify(),
            TlsHandshakeBody::certificate_verify(body),
        )
    }

    /// Construct a `certificate_verify` handshake message from typed fields.
    pub fn from_certificate_verify(certificate_verify: TlsCertificateVerify) -> Result<Self> {
        Ok(Self::from_header_and_body(
            TlsHandshakeHeader::certificate_verify(),
            TlsHandshakeBody::from_certificate_verify(certificate_verify)?,
        ))
    }

    /// Construct a `finished` handshake message with opaque body bytes.
    pub fn finished(body: impl Into<Vec<u8>>) -> Self {
        Self::from_header_and_body(
            TlsHandshakeHeader::finished(),
            TlsHandshakeBody::finished(body),
        )
    }

    /// Construct a `finished` handshake message from typed fields.
    pub fn from_finished(finished: TlsFinished) -> Result<Self> {
        Ok(Self::from_header_and_body(
            TlsHandshakeHeader::finished(),
            TlsHandshakeBody::from_finished(finished)?,
        ))
    }

    /// Construct a `key_update` handshake message with opaque body bytes.
    pub fn key_update(body: impl Into<Vec<u8>>) -> Self {
        Self::from_header_and_body(
            TlsHandshakeHeader::key_update(),
            TlsHandshakeBody::key_update(body),
        )
    }

    /// Construct a `key_update` handshake message from typed fields.
    pub fn from_key_update(key_update: TlsKeyUpdate) -> Result<Self> {
        Ok(Self::from_header_and_body(
            TlsHandshakeHeader::key_update(),
            TlsHandshakeBody::from_key_update(key_update)?,
        ))
    }

    /// Construct a `compressed_certificate` handshake message with opaque body bytes.
    pub fn compressed_certificate(body: impl Into<Vec<u8>>) -> Self {
        Self::from_header_and_body(
            TlsHandshakeHeader::compressed_certificate(),
            TlsHandshakeBody::compressed_certificate(body),
        )
    }

    /// Replace the complete handshake header.
    pub fn with_header(mut self, header: TlsHandshakeHeader) -> Self {
        self.header = header;
        self
    }

    /// Replace the handshake type without rewriting the body hook.
    pub fn with_handshake_type(mut self, handshake_type: impl Into<TlsHandshakeType>) -> Self {
        self.header = self.header.with_handshake_type(handshake_type);
        self
    }

    /// Replace the handshake type from a raw one-octet value.
    pub fn with_raw_handshake_type(self, handshake_type: u8) -> Self {
        self.with_handshake_type(TlsHandshakeType::from_u8(handshake_type))
    }

    /// Pin the declared handshake message body length.
    pub fn with_declared_length(mut self, declared_length: u32) -> Self {
        self.header = self.header.with_declared_length(declared_length);
        self
    }

    /// Compatibility alias for pinning the declared handshake message body length.
    pub fn with_length(self, declared_length: u32) -> Self {
        self.with_declared_length(declared_length)
    }

    /// Replace the handshake body hook without rewriting the header type.
    pub fn with_body(mut self, body: impl Into<TlsHandshakeBody>) -> Self {
        self.body = body.into();
        self
    }

    /// Replace the body with intentionally opaque bytes.
    pub fn with_opaque_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = TlsHandshakeBody::opaque(body);
        self
    }

    /// Borrow the preserved handshake header.
    pub const fn header(&self) -> &TlsHandshakeHeader {
        &self.header
    }

    /// Borrow the preserved handshake body hook.
    pub const fn body(&self) -> &TlsHandshakeBody {
        &self.body
    }

    /// Borrow the preserved body bytes.
    pub fn body_bytes(&self) -> &[u8] {
        self.body.body()
    }

    /// Borrow decoded ClientHello fields when this message carries them.
    pub fn client_hello_body(&self) -> Option<&TlsClientHello> {
        self.body.as_client_hello()
    }

    /// Borrow decoded ServerHello fields when this message carries them.
    pub fn server_hello_body(&self) -> Option<&TlsServerHello> {
        self.body.as_server_hello()
    }

    /// Borrow decoded EncryptedExtensions fields when this message carries them.
    pub fn encrypted_extensions_body(&self) -> Option<&TlsEncryptedExtensions> {
        self.body.as_encrypted_extensions()
    }

    /// Borrow decoded Certificate fields when this message carries them.
    pub fn certificate_body(&self) -> Option<&TlsCertificate> {
        self.body.as_certificate()
    }

    /// Borrow decoded CertificateRequest fields when this message carries them.
    pub fn certificate_request_body(&self) -> Option<&TlsCertificateRequest> {
        self.body.as_certificate_request()
    }

    /// Borrow decoded CertificateVerify fields when this message carries them.
    pub fn certificate_verify_body(&self) -> Option<&TlsCertificateVerify> {
        self.body.as_certificate_verify()
    }

    /// Borrow decoded Finished fields when this message carries them.
    pub fn finished_body(&self) -> Option<&TlsFinished> {
        self.body.as_finished()
    }

    /// Borrow decoded NewSessionTicket fields when this message carries them.
    pub fn new_session_ticket_body(&self) -> Option<&TlsNewSessionTicket> {
        self.body.as_new_session_ticket()
    }

    /// Borrow decoded EndOfEarlyData fields when this message carries them.
    pub fn end_of_early_data_body(&self) -> Option<&TlsEndOfEarlyData> {
        self.body.as_end_of_early_data()
    }

    /// Borrow decoded KeyUpdate fields when this message carries them.
    pub fn key_update_body(&self) -> Option<&TlsKeyUpdate> {
        self.body.as_key_update()
    }

    /// Consume the message and return its header plus body hook.
    pub fn into_header_and_body(self) -> (TlsHandshakeHeader, TlsHandshakeBody) {
        (self.header, self.body)
    }

    /// Consume the message and return its header plus preserved body bytes.
    pub fn into_header_and_body_bytes(self) -> (TlsHandshakeHeader, Vec<u8>) {
        (self.header, self.body.into_body())
    }

    /// Return the handshake type.
    pub const fn handshake_type(&self) -> TlsHandshakeType {
        self.header.handshake_type()
    }

    /// Return the raw handshake type value.
    pub const fn raw_handshake_type(&self) -> u8 {
        self.header.raw_handshake_type()
    }

    /// Caller-pinned or decoded declared body length, if present.
    pub fn declared_length(&self) -> Option<u32> {
        self.header.declared_length()
    }

    /// Compatibility alias for the declared body length.
    pub fn declared_len(&self) -> Option<u32> {
        self.header.declared_len()
    }

    /// Assignment state for the declared body length field.
    pub const fn declared_length_state(&self) -> FieldState {
        self.header.declared_length_state()
    }

    /// Number of bytes in the handshake body.
    pub fn body_len(&self) -> usize {
        self.body.body_len()
    }

    /// Declared body length to emit for this message.
    pub fn effective_length(&self) -> Result<u32> {
        self.header.effective_length(self.body_len())
    }

    /// Actual serialized handshake message byte count.
    pub fn actual_message_len(&self) -> Result<usize> {
        self.header.actual_message_len(self.body_len())
    }

    /// Declared handshake message byte count from the header length field.
    pub fn declared_message_len(&self) -> Result<usize> {
        self.header.declared_message_len(self.body_len())
    }

    /// Number of bytes emitted by this message.
    pub fn encoded_len(&self) -> Result<usize> {
        self.actual_message_len()
    }

    /// Append the complete handshake message, auto-filling an unset length.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.effective_length()?;
        self.header.encode_with_body_len(self.body_len(), out)?;
        self.body.encode(out);
        Ok(())
    }

    /// Return the complete encoded handshake message.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        self.effective_length()?;
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Compatibility alias for returning the complete encoded handshake message.
    pub fn compile(&self) -> Result<Vec<u8>> {
        self.encode_to_vec()
    }

    /// Decode one complete TLS handshake message from `bytes`.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (message, _) = Self::decode_prefix(bytes.as_ref())?;
        Ok(message)
    }

    /// Decode one complete TLS handshake message from the front of `bytes`.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (header, tail) = TlsHandshakeHeader::decode_prefix(bytes)?;
        let body_len = header
            .declared_length()
            .expect("decoded TLS handshake headers always carry length")
            as usize;
        let required = TLS_HANDSHAKE_HEADER_LEN
            .checked_add(body_len)
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.handshake.length", "length overflow")
            })?;

        if bytes.len() < required {
            return Err(CrafterError::buffer_too_short(
                "tls.handshake.body",
                required,
                bytes.len(),
            ));
        }

        let body = tail[..body_len].to_vec();
        let body = TlsHandshakeBody::decoded_for_type(header.handshake_type(), body)?;
        Ok((Self::from_header_and_body(header, body), &tail[body_len..]))
    }

    /// Decode one complete TLS handshake message, returning consumed bytes.
    pub fn decode_with_consumed(bytes: &[u8]) -> Result<(Self, usize)> {
        let (message, tail) = Self::decode_prefix(bytes)?;
        Ok((message, bytes.len() - tail.len()))
    }

    /// Stable one-line summary preserving codepoints and body length.
    pub fn summary(&self) -> String {
        format!(
            "handshake handshake_type={} declared_length={} body_bytes={} body={}",
            self.handshake_type().label(),
            self.header.length_label(),
            self.body_len(),
            self.body.summary()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = self.header.inspection_fields();
        fields.push(("body", self.body.label().to_string()));
        fields.push(("body_summary", self.body.summary()));
        fields.push(("body_bytes", self.body_len().to_string()));
        fields.push((
            "message_bytes",
            self.actual_message_len()
                .map(|len| len.to_string())
                .unwrap_or_else(|_| "overflow".to_string()),
        ));
        fields
    }
}

fn usize_to_u24_length(len: usize) -> Result<u32> {
    if len > TLS_HANDSHAKE_MAX_LENGTH as usize {
        return Err(CrafterError::invalid_field_value(
            "tls.handshake.length",
            "body length must fit in three bytes",
        ));
    }

    Ok(len as u32)
}

fn validate_u24_length(len: u32) -> Result<u32> {
    if len > TLS_HANDSHAKE_MAX_LENGTH {
        return Err(CrafterError::invalid_field_value(
            "tls.handshake.length",
            "length must fit in three bytes",
        ));
    }

    Ok(len)
}

fn u24_to_be_bytes(len: u32) -> Result<[u8; TLS_HANDSHAKE_LENGTH_LEN]> {
    let len = validate_u24_length(len)?;

    Ok([
        ((len >> 16) & 0xff) as u8,
        ((len >> 8) & 0xff) as u8,
        (len & 0xff) as u8,
    ])
}

const fn u24_from_be_bytes(bytes: [u8; TLS_HANDSHAKE_LENGTH_LEN]) -> u32 {
    ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | bytes[2] as u32
}

fn field_state_label(state: FieldState) -> &'static str {
    match state {
        FieldState::Unset => "unset",
        FieldState::Defaulted => "defaulted",
        FieldState::User => "user",
    }
}

/// TLS ClientHello body fields.
///
/// RFC 8446 section 4.1.2 defines the base ClientHello layout as
/// `legacy_version`, 32 random bytes, a one-octet length-prefixed legacy
/// session ID, a two-octet length-prefixed cipher suite vector, a one-octet
/// length-prefixed compression-method vector, and an optional extensions
/// vector. This type models those core fields while leaving extension bodies
/// raw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsClientHello {
    legacy_version: TlsVersion,
    random: [u8; TLS_CLIENT_HELLO_RANDOM_LEN],
    session_id: Vec<u8>,
    cipher_suites: TlsCipherSuiteList,
    compression_methods: Vec<u8>,
    extensions: Vec<TlsRawExtension>,
    extensions_present: bool,
}

impl TlsClientHello {
    /// Construct a ClientHello with compatibility defaults and empty vectors.
    pub fn new() -> Self {
        Self {
            legacy_version: TlsVersion::legacy_hello(),
            random: [0; TLS_CLIENT_HELLO_RANDOM_LEN],
            session_id: Vec::new(),
            cipher_suites: TlsCipherSuiteList::empty(),
            compression_methods: vec![0],
            extensions: Vec::new(),
            extensions_present: true,
        }
    }

    /// Construct a ClientHello with a caller-supplied fixed 32-byte random field.
    pub fn fixed_random(random: [u8; TLS_CLIENT_HELLO_RANDOM_LEN]) -> Self {
        Self::new().with_random(random)
    }

    /// Construct a ClientHello from all decoded or caller-supplied fields.
    pub fn from_fields(
        legacy_version: impl Into<TlsVersion>,
        random: [u8; TLS_CLIENT_HELLO_RANDOM_LEN],
        session_id: impl Into<Vec<u8>>,
        cipher_suites: impl Into<TlsCipherSuiteList>,
        compression_methods: impl Into<Vec<u8>>,
        extensions: impl Into<Vec<TlsRawExtension>>,
    ) -> Self {
        Self {
            legacy_version: legacy_version.into(),
            random,
            session_id: session_id.into(),
            cipher_suites: cipher_suites.into(),
            compression_methods: compression_methods.into(),
            extensions: extensions.into(),
            extensions_present: true,
        }
    }

    /// Replace the legacy ClientHello version field.
    pub fn with_legacy_version(mut self, legacy_version: impl Into<TlsVersion>) -> Self {
        self.legacy_version = legacy_version.into();
        self
    }

    /// Replace the legacy ClientHello version field from a raw `u16`.
    pub fn with_raw_legacy_version(self, legacy_version: u16) -> Self {
        self.with_legacy_version(TlsVersion::from_u16(legacy_version))
    }

    /// Replace the 32-byte ClientHello random field.
    pub fn with_random(mut self, random: [u8; TLS_CLIENT_HELLO_RANDOM_LEN]) -> Self {
        self.random = random;
        self
    }

    /// Replace the 32-byte ClientHello random field with fixed bytes.
    pub fn with_fixed_random(self, random: [u8; TLS_CLIENT_HELLO_RANDOM_LEN]) -> Self {
        self.with_random(random)
    }

    /// Replace the legacy session ID vector body bytes.
    pub fn with_session_id(mut self, session_id: impl Into<Vec<u8>>) -> Self {
        self.session_id = session_id.into();
        self
    }

    /// Encode an empty legacy session ID vector.
    pub fn with_empty_session_id(self) -> Self {
        self.with_session_id(Vec::new())
    }

    /// Replace the legacy session ID vector with explicit caller-supplied bytes.
    pub fn with_explicit_session_id(self, session_id: impl Into<Vec<u8>>) -> Self {
        self.with_session_id(session_id)
    }

    /// Replace the ordered cipher suite vector.
    pub fn with_cipher_suites(mut self, cipher_suites: impl Into<TlsCipherSuiteList>) -> Self {
        self.cipher_suites = cipher_suites.into();
        self
    }

    /// Replace the ordered cipher suite vector from raw two-octet values.
    pub fn with_raw_cipher_suites<I>(self, cipher_suites: I) -> Self
    where
        I: IntoIterator<Item = u16>,
    {
        self.with_cipher_suites(TlsCipherSuiteList::from_raws(cipher_suites))
    }

    /// Append one cipher suite to the ordered vector.
    pub fn with_cipher_suite(mut self, cipher_suite: impl Into<TlsCipherSuite>) -> Self {
        self.cipher_suites.push(cipher_suite.into());
        self
    }

    /// Replace the legacy compression-method vector body bytes.
    pub fn with_compression_methods(mut self, compression_methods: impl Into<Vec<u8>>) -> Self {
        self.compression_methods = compression_methods.into();
        self
    }

    /// Replace the legacy compression-method vector with the null method.
    pub fn with_null_compression(self) -> Self {
        self.with_compression_methods([TLS_COMPRESSION_METHOD_NULL])
    }

    /// Replace the legacy compression-method vector with raw method bytes.
    pub fn with_raw_compression_methods(self, compression_methods: impl Into<Vec<u8>>) -> Self {
        self.with_compression_methods(compression_methods)
    }

    /// Append one legacy compression method byte.
    pub fn with_compression_method(mut self, compression_method: u8) -> Self {
        self.compression_methods.push(compression_method);
        self
    }

    /// Append one raw legacy compression method byte.
    pub fn with_raw_compression_method(self, compression_method: u8) -> Self {
        self.with_compression_method(compression_method)
    }

    /// Replace the raw extension list and mark the extensions vector present.
    pub fn with_extensions(mut self, extensions: impl Into<Vec<TlsRawExtension>>) -> Self {
        self.extensions = extensions.into();
        self.extensions_present = true;
        self
    }

    /// Append one raw extension and mark the extensions vector present.
    pub fn with_extension(mut self, extension: TlsRawExtension) -> Self {
        self.extensions.push(extension);
        self.extensions_present = true;
        self
    }

    /// Omit the optional ClientHello extensions vector when encoding.
    pub fn without_extensions(mut self) -> Self {
        self.extensions.clear();
        self.extensions_present = false;
        self
    }

    /// Return the preserved legacy version field.
    pub const fn legacy_version(&self) -> TlsVersion {
        self.legacy_version
    }

    /// Return the preserved raw legacy version field.
    pub const fn raw_legacy_version(&self) -> u16 {
        self.legacy_version.raw()
    }

    /// Borrow the preserved 32-byte random field.
    pub const fn random(&self) -> &[u8; TLS_CLIENT_HELLO_RANDOM_LEN] {
        &self.random
    }

    /// Borrow the preserved legacy session ID bytes.
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }

    /// Borrow the ordered cipher suite list.
    pub const fn cipher_suites(&self) -> &TlsCipherSuiteList {
        &self.cipher_suites
    }

    /// Borrow the preserved compression-method vector body bytes.
    pub fn compression_methods(&self) -> &[u8] {
        &self.compression_methods
    }

    /// Borrow the raw extension list.
    pub fn extensions(&self) -> &[TlsRawExtension] {
        &self.extensions
    }

    /// Return true when the optional extensions vector is encoded.
    pub const fn extensions_present(&self) -> bool {
        self.extensions_present
    }

    /// Number of bytes occupied by the ClientHello body.
    pub fn encoded_len(&self) -> Result<usize> {
        validate_u8_vector_len(self.session_id.len(), "tls.client_hello.session_id.length")?;
        validate_u8_vector_len(
            self.compression_methods.len(),
            "tls.client_hello.compression_methods.length",
        )?;

        let mut len = TLS_CLIENT_HELLO_FIXED_LEN;
        len = checked_add_len(len, 1, "tls.client_hello.length")?;
        len = checked_add_len(len, self.session_id.len(), "tls.client_hello.length")?;
        len = checked_add_len(
            len,
            self.cipher_suites.encoded_len()?,
            "tls.client_hello.length",
        )?;
        len = checked_add_len(len, 1, "tls.client_hello.length")?;
        len = checked_add_len(
            len,
            self.compression_methods.len(),
            "tls.client_hello.length",
        )?;

        if self.extensions_present {
            len = checked_add_len(len, 2, "tls.client_hello.length")?;
            len = checked_add_len(len, self.extensions_body_len()?, "tls.client_hello.length")?;
        }

        Ok(len)
    }

    /// Append the ClientHello body bytes.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encoded_len()?;

        out.extend_from_slice(&self.legacy_version.to_be_bytes());
        out.extend_from_slice(&self.random);
        encode_u8_vector(&self.session_id, "tls.client_hello.session_id.length", out)?;
        self.cipher_suites.encode(out)?;
        encode_u8_vector(
            &self.compression_methods,
            "tls.client_hello.compression_methods.length",
            out,
        )?;

        if self.extensions_present {
            TlsExtensions::new(self.extensions.clone())
                .encode_with_context(TlsExtensionListContext::client_hello(), out)?;
        }

        Ok(())
    }

    /// Return the encoded ClientHello body bytes.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Compatibility alias for returning the encoded ClientHello body bytes.
    pub fn compile(&self) -> Result<Vec<u8>> {
        self.encode_to_vec()
    }

    /// Decode one complete ClientHello body.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (client_hello, tail) = Self::decode_prefix(bytes.as_ref())?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.client_hello.length",
                "trailing bytes after extensions",
            ));
        }

        Ok(client_hello)
    }

    /// Decode one ClientHello body from the front of `bytes`.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let mut cursor = 0;

        let legacy_version = {
            let version = take_bytes(
                bytes,
                &mut cursor,
                TLS_CLIENT_HELLO_LEGACY_VERSION_LEN,
                "tls.client_hello.legacy_version",
            )?;
            TlsVersion::from_be_bytes([version[0], version[1]])
        };

        let random = {
            let random = take_bytes(
                bytes,
                &mut cursor,
                TLS_CLIENT_HELLO_RANDOM_LEN,
                "tls.client_hello.random",
            )?;
            let mut out = [0u8; TLS_CLIENT_HELLO_RANDOM_LEN];
            out.copy_from_slice(random);
            out
        };

        let session_id = decode_u8_vector(
            bytes,
            &mut cursor,
            "tls.client_hello.session_id",
            "tls.client_hello.session_id.length",
        )?;
        let cipher_suites = decode_cipher_suite_list(bytes, &mut cursor)?;
        let compression_methods = decode_u8_vector(
            bytes,
            &mut cursor,
            "tls.client_hello.compression_methods",
            "tls.client_hello.compression_methods.length",
        )?;

        let (extensions, extensions_present) = if cursor == bytes.len() {
            (Vec::new(), false)
        } else {
            (
                decode_extension_list(bytes, &mut cursor, TlsExtensionListContext::client_hello())?,
                true,
            )
        };

        Ok((
            Self {
                legacy_version,
                random,
                session_id,
                cipher_suites,
                compression_methods,
                extensions,
                extensions_present,
            },
            &bytes[cursor..],
        ))
    }

    /// Stable one-line summary preserving vector sizes.
    pub fn summary(&self) -> String {
        format!(
            "client_hello legacy_version={} session_id_bytes={} cipher_suites={} compression_methods={} extensions={} extensions_present={}",
            self.legacy_version.label(),
            self.session_id.len(),
            self.cipher_suites.len(),
            self.compression_methods.len(),
            self.extensions.len(),
            self.extensions_present
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("legacy_version", self.legacy_version.label()),
            (
                "legacy_version_raw",
                format!("0x{:04x}", self.legacy_version.raw()),
            ),
            ("random", hex_bytes(&self.random)),
            ("random_bytes", self.random.len().to_string()),
            ("session_id", hex_bytes(&self.session_id)),
            ("session_id_bytes", self.session_id.len().to_string()),
            ("cipher_suites_count", self.cipher_suites.len().to_string()),
            ("compression_methods", hex_bytes(&self.compression_methods)),
            (
                "compression_methods_count",
                self.compression_methods.len().to_string(),
            ),
            ("extensions_count", self.extensions.len().to_string()),
            ("extensions_present", self.extensions_present.to_string()),
        ]
    }

    fn extensions_body_len(&self) -> Result<usize> {
        TlsExtensions::new(self.extensions.clone())
            .byte_len_with_context(TlsExtensionListContext::client_hello())
    }
}

impl Default for TlsClientHello {
    fn default() -> Self {
        Self::new()
    }
}

/// TLS ServerHello body fields.
///
/// RFC 8446 section 4.1.3 defines the TLS 1.3 ServerHello layout as
/// `legacy_version`, 32 random bytes, a one-octet length-prefixed legacy
/// session ID echo, one selected cipher suite, a legacy compression-method
/// byte, and an extensions vector. This type models those core fields while
/// leaving extension bodies raw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsServerHello {
    legacy_version: TlsVersion,
    random: [u8; TLS_SERVER_HELLO_RANDOM_LEN],
    session_id_echo: Vec<u8>,
    cipher_suite: TlsCipherSuite,
    compression_method: u8,
    extensions: Vec<TlsRawExtension>,
}

impl TlsServerHello {
    /// Construct a ServerHello with compatibility defaults and no extensions.
    pub fn new() -> Self {
        Self {
            legacy_version: TlsVersion::legacy_hello(),
            random: [0; TLS_SERVER_HELLO_RANDOM_LEN],
            session_id_echo: Vec::new(),
            cipher_suite: TlsCipherSuite::AES_128_GCM_SHA256,
            compression_method: 0,
            extensions: Vec::new(),
        }
    }

    /// Construct a ServerHello with a caller-supplied fixed 32-byte random field.
    pub fn fixed_random(random: [u8; TLS_SERVER_HELLO_RANDOM_LEN]) -> Self {
        Self::new().with_random(random)
    }

    /// Construct a TLS 1.3 HelloRetryRequest encoded in the ServerHello shape.
    pub fn hello_retry_request() -> Self {
        Self::new().with_hello_retry_request_random()
    }

    /// Construct a ServerHello from all decoded or caller-supplied fields.
    pub fn from_fields(
        legacy_version: impl Into<TlsVersion>,
        random: [u8; TLS_SERVER_HELLO_RANDOM_LEN],
        session_id_echo: impl Into<Vec<u8>>,
        cipher_suite: impl Into<TlsCipherSuite>,
        compression_method: u8,
        extensions: impl Into<Vec<TlsRawExtension>>,
    ) -> Self {
        Self {
            legacy_version: legacy_version.into(),
            random,
            session_id_echo: session_id_echo.into(),
            cipher_suite: cipher_suite.into(),
            compression_method,
            extensions: extensions.into(),
        }
    }

    /// Replace the legacy ServerHello version field.
    pub fn with_legacy_version(mut self, legacy_version: impl Into<TlsVersion>) -> Self {
        self.legacy_version = legacy_version.into();
        self
    }

    /// Replace the legacy ServerHello version field from a raw `u16`.
    pub fn with_raw_legacy_version(self, legacy_version: u16) -> Self {
        self.with_legacy_version(TlsVersion::from_u16(legacy_version))
    }

    /// Replace the 32-byte ServerHello random field.
    pub fn with_random(mut self, random: [u8; TLS_SERVER_HELLO_RANDOM_LEN]) -> Self {
        self.random = random;
        self
    }

    /// Replace the 32-byte ServerHello random field with fixed bytes.
    pub fn with_fixed_random(self, random: [u8; TLS_SERVER_HELLO_RANDOM_LEN]) -> Self {
        self.with_random(random)
    }

    /// Replace the random field with the RFC 8446 HelloRetryRequest marker.
    pub fn with_hello_retry_request_random(self) -> Self {
        self.with_random(TLS_HELLO_RETRY_REQUEST_RANDOM)
    }

    /// Replace the legacy session ID echo vector body bytes.
    pub fn with_session_id_echo(mut self, session_id_echo: impl Into<Vec<u8>>) -> Self {
        self.session_id_echo = session_id_echo.into();
        self
    }

    /// Encode an empty legacy session ID echo vector.
    pub fn with_empty_session_id_echo(self) -> Self {
        self.with_session_id_echo(Vec::new())
    }

    /// Replace the legacy session ID echo with explicit caller-supplied bytes.
    pub fn with_explicit_session_id_echo(self, session_id_echo: impl Into<Vec<u8>>) -> Self {
        self.with_session_id_echo(session_id_echo)
    }

    /// Echo the session ID bytes from a ClientHello.
    pub fn with_session_id_echo_from_client(self, client_hello: &TlsClientHello) -> Self {
        self.with_session_id_echo(client_hello.session_id())
    }

    /// Compatibility alias for replacing the legacy session ID echo bytes.
    pub fn with_session_id(self, session_id_echo: impl Into<Vec<u8>>) -> Self {
        self.with_session_id_echo(session_id_echo)
    }

    /// Replace the selected cipher suite.
    pub fn with_cipher_suite(mut self, cipher_suite: impl Into<TlsCipherSuite>) -> Self {
        self.cipher_suite = cipher_suite.into();
        self
    }

    /// Replace the selected cipher suite from a raw two-octet value.
    pub fn with_raw_cipher_suite(self, cipher_suite: u16) -> Self {
        self.with_cipher_suite(TlsCipherSuite::from_u16(cipher_suite))
    }

    /// Replace the legacy compression method byte.
    pub fn with_compression_method(mut self, compression_method: u8) -> Self {
        self.compression_method = compression_method;
        self
    }

    /// Replace the legacy compression method with the null method.
    pub fn with_null_compression(self) -> Self {
        self.with_compression_method(TLS_COMPRESSION_METHOD_NULL)
    }

    /// Replace the legacy compression method with a raw method byte.
    pub fn with_raw_compression_method(self, compression_method: u8) -> Self {
        self.with_compression_method(compression_method)
    }

    /// Replace the raw extension list.
    pub fn with_extensions(mut self, extensions: impl Into<Vec<TlsRawExtension>>) -> Self {
        self.extensions = extensions.into();
        self
    }

    /// Append one raw extension.
    pub fn with_extension(mut self, extension: TlsRawExtension) -> Self {
        self.extensions.push(extension);
        self
    }

    /// Return the preserved legacy version field.
    pub const fn legacy_version(&self) -> TlsVersion {
        self.legacy_version
    }

    /// Return the preserved raw legacy version field.
    pub const fn raw_legacy_version(&self) -> u16 {
        self.legacy_version.raw()
    }

    /// Borrow the preserved 32-byte random field.
    pub const fn random(&self) -> &[u8; TLS_SERVER_HELLO_RANDOM_LEN] {
        &self.random
    }

    /// Return true when this ServerHello carries the RFC 8446 HelloRetryRequest marker.
    pub fn is_hello_retry_request(&self) -> bool {
        self.random == TLS_HELLO_RETRY_REQUEST_RANDOM
    }

    /// Stable form label for summary and inspection output.
    pub fn form_label(&self) -> &'static str {
        if self.is_hello_retry_request() {
            "hello_retry_request"
        } else {
            "server_hello"
        }
    }

    /// Borrow the preserved legacy session ID echo bytes.
    pub fn session_id_echo(&self) -> &[u8] {
        &self.session_id_echo
    }

    /// Compatibility alias for borrowing the legacy session ID echo bytes.
    pub fn session_id(&self) -> &[u8] {
        self.session_id_echo()
    }

    /// Return the selected cipher suite.
    pub const fn cipher_suite(&self) -> TlsCipherSuite {
        self.cipher_suite
    }

    /// Return the preserved raw selected cipher suite value.
    pub const fn raw_cipher_suite(&self) -> u16 {
        self.cipher_suite.raw()
    }

    /// Return the preserved legacy compression method byte.
    pub const fn compression_method(&self) -> u8 {
        self.compression_method
    }

    /// Borrow the raw extension list.
    pub fn extensions(&self) -> &[TlsRawExtension] {
        &self.extensions
    }

    /// Number of bytes occupied by the ServerHello body.
    pub fn encoded_len(&self) -> Result<usize> {
        validate_u8_vector_len(
            self.session_id_echo.len(),
            "tls.server_hello.session_id_echo.length",
        )?;

        let mut len = TLS_SERVER_HELLO_FIXED_LEN;
        len = checked_add_len(len, 1, "tls.server_hello.length")?;
        len = checked_add_len(len, self.session_id_echo.len(), "tls.server_hello.length")?;
        len = checked_add_len(len, TLS_CIPHER_SUITE_LEN, "tls.server_hello.length")?;
        len = checked_add_len(len, 1, "tls.server_hello.length")?;
        len = checked_add_len(len, 2, "tls.server_hello.length")?;
        len = checked_add_len(len, self.extensions_body_len()?, "tls.server_hello.length")?;

        Ok(len)
    }

    /// Append the ServerHello body bytes.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encoded_len()?;

        out.extend_from_slice(&self.legacy_version.to_be_bytes());
        out.extend_from_slice(&self.random);
        encode_u8_vector(
            &self.session_id_echo,
            "tls.server_hello.session_id_echo.length",
            out,
        )?;
        self.cipher_suite.encode(out);
        out.push(self.compression_method);

        TlsExtensions::new(self.extensions.clone())
            .encode_with_context(TlsExtensionListContext::server_hello(), out)?;

        Ok(())
    }

    /// Return the encoded ServerHello body bytes.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Compatibility alias for returning the encoded ServerHello body bytes.
    pub fn compile(&self) -> Result<Vec<u8>> {
        self.encode_to_vec()
    }

    /// Decode one complete ServerHello body.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (server_hello, tail) = Self::decode_prefix(bytes.as_ref())?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.server_hello.length",
                "trailing bytes after extensions",
            ));
        }

        Ok(server_hello)
    }

    /// Decode one ServerHello body from the front of `bytes`.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let mut cursor = 0;

        let legacy_version = {
            let version = take_bytes(
                bytes,
                &mut cursor,
                TLS_SERVER_HELLO_LEGACY_VERSION_LEN,
                "tls.server_hello.legacy_version",
            )?;
            TlsVersion::from_be_bytes([version[0], version[1]])
        };

        let random = {
            let random = take_bytes(
                bytes,
                &mut cursor,
                TLS_SERVER_HELLO_RANDOM_LEN,
                "tls.server_hello.random",
            )?;
            let mut out = [0u8; TLS_SERVER_HELLO_RANDOM_LEN];
            out.copy_from_slice(random);
            out
        };

        let session_id_echo = decode_u8_vector(
            bytes,
            &mut cursor,
            "tls.server_hello.session_id_echo",
            "tls.server_hello.session_id_echo.length",
        )?;

        let cipher_suite = {
            let suite = take_bytes(
                bytes,
                &mut cursor,
                TLS_CIPHER_SUITE_LEN,
                "tls.server_hello.cipher_suite",
            )?;
            TlsCipherSuite::from_be_bytes([suite[0], suite[1]])
        };

        let compression_method =
            take_bytes(bytes, &mut cursor, 1, "tls.server_hello.compression_method")?[0];
        let extensions =
            decode_extension_list(bytes, &mut cursor, TlsExtensionListContext::server_hello())?;

        Ok((
            Self {
                legacy_version,
                random,
                session_id_echo,
                cipher_suite,
                compression_method,
                extensions,
            },
            &bytes[cursor..],
        ))
    }

    /// Stable one-line summary preserving vector sizes.
    pub fn summary(&self) -> String {
        format!(
            "server_hello form={} legacy_version={} session_id_echo_bytes={} cipher_suite={} compression_method=0x{:02x} extensions={}",
            self.form_label(),
            self.legacy_version.label(),
            self.session_id_echo.len(),
            self.cipher_suite.label(),
            self.compression_method,
            self.extensions.len()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("form", self.form_label().to_string()),
            (
                "hello_retry_request",
                self.is_hello_retry_request().to_string(),
            ),
            ("legacy_version", self.legacy_version.label()),
            (
                "legacy_version_raw",
                format!("0x{:04x}", self.legacy_version.raw()),
            ),
            ("random", hex_bytes(&self.random)),
            ("random_bytes", self.random.len().to_string()),
            ("session_id_echo", hex_bytes(&self.session_id_echo)),
            (
                "session_id_echo_bytes",
                self.session_id_echo.len().to_string(),
            ),
            ("cipher_suite", self.cipher_suite.label()),
            (
                "cipher_suite_raw",
                format!("0x{:04x}", self.cipher_suite.raw()),
            ),
            (
                "compression_method",
                format!("0x{:02x}", self.compression_method),
            ),
            ("extensions_count", self.extensions.len().to_string()),
        ]
    }

    fn extensions_body_len(&self) -> Result<usize> {
        TlsExtensions::new(self.extensions.clone())
            .byte_len_with_context(TlsExtensionListContext::server_hello())
    }
}

impl Default for TlsServerHello {
    fn default() -> Self {
        Self::new()
    }
}

/// TLS 1.3 EncryptedExtensions body fields.
///
/// RFC 8446 section 4.3.1 defines EncryptedExtensions as a single
/// uint16-length-prefixed extension list. The extensions stay raw so unknown
/// and future extension bodies remain byte-exact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsEncryptedExtensions {
    extensions: TlsExtensions,
}

impl TlsEncryptedExtensions {
    /// Construct an empty EncryptedExtensions body.
    pub fn new() -> Self {
        Self::empty()
    }

    /// Construct an empty EncryptedExtensions body.
    pub fn empty() -> Self {
        Self {
            extensions: TlsExtensions::empty(),
        }
    }

    /// Construct EncryptedExtensions from an ordered extension list.
    pub fn from_extensions(extensions: impl Into<TlsExtensions>) -> Self {
        Self {
            extensions: extensions.into(),
        }
    }

    /// Construct EncryptedExtensions from ordered raw extension entries.
    pub fn from_raw_extensions(extensions: impl Into<Vec<TlsRawExtension>>) -> Self {
        Self {
            extensions: TlsExtensions::new(extensions),
        }
    }

    /// Replace the ordered extension list.
    pub fn with_extensions(mut self, extensions: impl Into<TlsExtensions>) -> Self {
        self.extensions = extensions.into();
        self
    }

    /// Append one raw extension.
    pub fn with_extension(mut self, extension: TlsRawExtension) -> Self {
        self.extensions.push(extension);
        self
    }

    /// Append one raw extension from an extension type and body bytes.
    pub fn with_raw_extension(self, extension_type: u16, body: impl Into<Vec<u8>>) -> Self {
        self.with_extension(TlsRawExtension::from_raw(extension_type, body))
    }

    /// Borrow the ordered extension list.
    pub const fn extensions(&self) -> &TlsExtensions {
        &self.extensions
    }

    /// Borrow the ordered raw extension entries.
    pub fn raw_extensions(&self) -> &[TlsRawExtension] {
        self.extensions.extensions()
    }

    /// Number of extension entries.
    pub fn len(&self) -> usize {
        self.extensions.len()
    }

    /// Return true when the body carries no extension entries.
    pub fn is_empty(&self) -> bool {
        self.extensions.is_empty()
    }

    /// Number of bytes occupied by the EncryptedExtensions body.
    pub fn encoded_len(&self) -> Result<usize> {
        self.extensions
            .encoded_len_with_context(TlsExtensionListContext::encrypted_extensions())
    }

    /// Append the EncryptedExtensions body bytes.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.extensions
            .encode_with_context(TlsExtensionListContext::encrypted_extensions(), out)
    }

    /// Return the encoded EncryptedExtensions body bytes.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        self.extensions
            .encode_to_vec_with_context(TlsExtensionListContext::encrypted_extensions())
    }

    /// Compile the EncryptedExtensions body bytes.
    pub fn compile(&self) -> Result<Vec<u8>> {
        self.encode_to_vec()
    }

    /// Decode one complete EncryptedExtensions body.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (encrypted_extensions, tail) = Self::decode_prefix(bytes.as_ref())?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.encrypted_extensions.length",
                "trailing bytes after extensions",
            ));
        }

        Ok(encrypted_extensions)
    }

    /// Decode one EncryptedExtensions body from the front of `bytes`.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (extensions, tail) = TlsExtensions::decode_prefix_with_context(
            TlsExtensionListContext::encrypted_extensions(),
            bytes,
        )?;
        Ok((Self { extensions }, tail))
    }

    /// Stable one-line summary preserving extension order and count.
    pub fn summary(&self) -> String {
        format!(
            "encrypted_extensions extensions={} extension_bytes={} values={}",
            self.extensions.len(),
            self.extensions
                .byte_len_with_context(TlsExtensionListContext::encrypted_extensions())
                .unwrap_or(0),
            self.extensions.labels().join(",")
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("extensions_count", self.extensions.len().to_string()),
            (
                "extensions_bytes",
                self.extensions
                    .byte_len_with_context(TlsExtensionListContext::encrypted_extensions())
                    .unwrap_or(0)
                    .to_string(),
            ),
            ("extensions", self.extensions.labels().join(",")),
        ]
    }
}

impl Default for TlsEncryptedExtensions {
    fn default() -> Self {
        Self::new()
    }
}

impl From<TlsExtensions> for TlsEncryptedExtensions {
    fn from(extensions: TlsExtensions) -> Self {
        Self::from_extensions(extensions)
    }
}

impl From<Vec<TlsRawExtension>> for TlsEncryptedExtensions {
    fn from(extensions: Vec<TlsRawExtension>) -> Self {
        Self::from_raw_extensions(extensions)
    }
}

impl<const N: usize> From<[TlsRawExtension; N]> for TlsEncryptedExtensions {
    fn from(extensions: [TlsRawExtension; N]) -> Self {
        Self::from_raw_extensions(Vec::from(extensions))
    }
}

/// TLS Certificate message wire form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsCertificateForm {
    /// TLS 1.2 and earlier certificate list without request context or entry extensions.
    Tls12,
    /// TLS 1.3 certificate message with request context and per-entry extensions.
    Tls13,
}

impl TlsCertificateForm {
    /// Stable lowercase label for summaries and inspection output.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Tls12 => "tls12",
            Self::Tls13 => "tls13",
        }
    }
}

/// One opaque certificate entry.
///
/// Certificate bytes stay opaque; this type does not parse or validate X.509,
/// RawPublicKey, or ASN.1. TLS 1.3 entry extensions are preserved as raw
/// extension entries and are ignored when encoding the TLS 1.2 form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsCertificateEntry {
    certificate: Vec<u8>,
    extensions: Vec<TlsRawExtension>,
}

impl TlsCertificateEntry {
    /// Construct an entry from opaque certificate bytes.
    pub fn new(certificate: impl Into<Vec<u8>>) -> Self {
        Self {
            certificate: certificate.into(),
            extensions: Vec::new(),
        }
    }

    /// Replace the opaque certificate bytes.
    pub fn with_certificate(mut self, certificate: impl Into<Vec<u8>>) -> Self {
        self.certificate = certificate.into();
        self
    }

    /// Replace the TLS 1.3 per-entry extension list.
    pub fn with_extensions(mut self, extensions: impl Into<Vec<TlsRawExtension>>) -> Self {
        self.extensions = extensions.into();
        self
    }

    /// Append one TLS 1.3 per-entry extension.
    pub fn with_extension(mut self, extension: TlsRawExtension) -> Self {
        self.extensions.push(extension);
        self
    }

    /// Append one TLS 1.3 per-entry extension from a raw type and body.
    pub fn with_raw_extension(self, extension_type: u16, body: impl Into<Vec<u8>>) -> Self {
        self.with_extension(TlsRawExtension::from_raw(extension_type, body))
    }

    /// Borrow the opaque certificate bytes.
    pub fn certificate_data(&self) -> &[u8] {
        &self.certificate
    }

    /// Borrow the TLS 1.3 per-entry extensions.
    pub fn extensions(&self) -> &[TlsRawExtension] {
        &self.extensions
    }

    /// Number of opaque certificate bytes.
    pub fn certificate_len(&self) -> usize {
        self.certificate.len()
    }

    /// Return true when the certificate byte vector is empty.
    pub fn is_empty_certificate(&self) -> bool {
        self.certificate.is_empty()
    }

    /// Number of bytes this entry occupies inside a TLS 1.2 certificate list.
    pub fn encoded_len_tls12(&self) -> Result<usize> {
        validate_u24_vector_len(self.certificate.len(), "tls.certificate.certificate.length")?;
        checked_add_len(
            TLS_CERTIFICATE_ENTRY_LENGTH_LEN,
            self.certificate.len(),
            "tls.certificate.entry.length",
        )
    }

    /// Number of bytes this entry occupies inside a TLS 1.3 certificate list.
    pub fn encoded_len_tls13(&self) -> Result<usize> {
        let mut len = self.encoded_len_tls12()?;
        len = checked_add_len(
            len,
            TlsExtensions::new(self.extensions.clone())
                .encoded_len_with_context(TlsExtensionListContext::certificate_entry())?,
            "tls.certificate.entry.length",
        )?;
        Ok(len)
    }

    /// Stable one-line summary preserving byte and extension counts.
    pub fn summary(&self) -> String {
        format!(
            "certificate_entry certificate_bytes={} extensions={}",
            self.certificate.len(),
            self.extensions.len()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("certificate", hex_bytes(&self.certificate)),
            ("certificate_bytes", self.certificate.len().to_string()),
            ("extensions_count", self.extensions.len().to_string()),
        ]
    }

    fn encode_tls12(&self, out: &mut Vec<u8>) -> Result<()> {
        encode_u24_vector(&self.certificate, "tls.certificate.certificate.length", out)
    }

    fn encode_tls13(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_tls12(out)?;
        TlsExtensions::new(self.extensions.clone())
            .encode_with_context(TlsExtensionListContext::certificate_entry(), out)
    }

    fn decode_tls12_from(bytes: &[u8], cursor: &mut usize) -> Result<Self> {
        let certificate = decode_u24_vector(
            bytes,
            cursor,
            "tls.certificate.certificate",
            "tls.certificate.certificate.length",
        )?;
        Ok(Self {
            certificate,
            extensions: Vec::new(),
        })
    }

    fn decode_tls13_from(bytes: &[u8], cursor: &mut usize) -> Result<Self> {
        let certificate = decode_u24_vector(
            bytes,
            cursor,
            "tls.certificate.certificate",
            "tls.certificate.certificate.length",
        )?;
        let extensions =
            decode_extension_list(bytes, cursor, TlsExtensionListContext::certificate_entry())?;
        Ok(Self {
            certificate,
            extensions,
        })
    }
}

impl From<Vec<u8>> for TlsCertificateEntry {
    fn from(certificate: Vec<u8>) -> Self {
        Self::new(certificate)
    }
}

impl<const N: usize> From<[u8; N]> for TlsCertificateEntry {
    fn from(certificate: [u8; N]) -> Self {
        Self::new(certificate)
    }
}

/// TLS Certificate handshake body fields.
///
/// The TLS 1.2 form encodes only a three-octet length-prefixed certificate
/// list. The TLS 1.3 form additionally encodes a one-octet length-prefixed
/// request context and a per-entry extension list. Certificate bytes stay
/// opaque in both forms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsCertificate {
    form: TlsCertificateForm,
    request_context: Vec<u8>,
    certificate_list: Vec<TlsCertificateEntry>,
}

impl TlsCertificate {
    /// Construct an empty TLS 1.3 Certificate body.
    pub fn new() -> Self {
        Self::tls13(Vec::new(), Vec::new())
    }

    /// Construct a TLS 1.2 Certificate body.
    pub fn tls12(certificate_list: impl Into<Vec<TlsCertificateEntry>>) -> Self {
        Self {
            form: TlsCertificateForm::Tls12,
            request_context: Vec::new(),
            certificate_list: certificate_list.into(),
        }
    }

    /// Construct a TLS 1.3 Certificate body.
    pub fn tls13(
        request_context: impl Into<Vec<u8>>,
        certificate_list: impl Into<Vec<TlsCertificateEntry>>,
    ) -> Self {
        Self {
            form: TlsCertificateForm::Tls13,
            request_context: request_context.into(),
            certificate_list: certificate_list.into(),
        }
    }

    /// Replace the message with TLS 1.2 wire form.
    pub fn with_tls12_form(mut self) -> Self {
        self.form = TlsCertificateForm::Tls12;
        self.request_context.clear();
        self
    }

    /// Replace the message with TLS 1.3 wire form.
    pub fn with_tls13_form(mut self) -> Self {
        self.form = TlsCertificateForm::Tls13;
        self
    }

    /// Replace the TLS 1.3 request context and select TLS 1.3 wire form.
    pub fn with_request_context(mut self, request_context: impl Into<Vec<u8>>) -> Self {
        self.form = TlsCertificateForm::Tls13;
        self.request_context = request_context.into();
        self
    }

    /// Replace the ordered certificate list.
    pub fn with_certificate_list(
        mut self,
        certificate_list: impl Into<Vec<TlsCertificateEntry>>,
    ) -> Self {
        self.certificate_list = certificate_list.into();
        self
    }

    /// Append one certificate entry.
    pub fn with_entry(mut self, entry: impl Into<TlsCertificateEntry>) -> Self {
        self.certificate_list.push(entry.into());
        self
    }

    /// Return the selected TLS Certificate wire form.
    pub const fn form(&self) -> TlsCertificateForm {
        self.form
    }

    /// Return true when this body uses the TLS 1.2 certificate-list form.
    pub const fn is_tls12(&self) -> bool {
        matches!(self.form, TlsCertificateForm::Tls12)
    }

    /// Return true when this body uses the TLS 1.3 request-context form.
    pub const fn is_tls13(&self) -> bool {
        matches!(self.form, TlsCertificateForm::Tls13)
    }

    /// Borrow the TLS 1.3 certificate_request_context bytes.
    pub fn request_context(&self) -> &[u8] {
        &self.request_context
    }

    /// Borrow the ordered certificate list.
    pub fn certificate_list(&self) -> &[TlsCertificateEntry] {
        &self.certificate_list
    }

    /// Number of certificate entries.
    pub fn len(&self) -> usize {
        self.certificate_list.len()
    }

    /// Return true when the certificate list is empty.
    pub fn is_empty(&self) -> bool {
        self.certificate_list.is_empty()
    }

    /// Total opaque certificate bytes across all entries.
    pub fn certificate_bytes(&self) -> usize {
        self.certificate_list
            .iter()
            .map(TlsCertificateEntry::certificate_len)
            .sum()
    }

    /// Total TLS 1.3 per-entry extension count across all entries.
    pub fn entry_extensions_len(&self) -> usize {
        self.certificate_list
            .iter()
            .map(|entry| entry.extensions().len())
            .sum()
    }

    /// Number of bytes occupied by the Certificate body.
    pub fn encoded_len(&self) -> Result<usize> {
        match self.form {
            TlsCertificateForm::Tls12 => checked_add_len(
                TLS_CERTIFICATE_LIST_LENGTH_LEN,
                self.certificate_list_body_len_tls12()?,
                "tls.certificate.length",
            ),
            TlsCertificateForm::Tls13 => {
                validate_u8_vector_len(
                    self.request_context.len(),
                    "tls.certificate.request_context.length",
                )?;
                let mut len = TLS_CERTIFICATE_REQUEST_CONTEXT_LENGTH_LEN;
                len = checked_add_len(len, self.request_context.len(), "tls.certificate.length")?;
                len = checked_add_len(
                    len,
                    TLS_CERTIFICATE_LIST_LENGTH_LEN,
                    "tls.certificate.length",
                )?;
                len = checked_add_len(
                    len,
                    self.certificate_list_body_len_tls13()?,
                    "tls.certificate.length",
                )?;
                Ok(len)
            }
        }
    }

    /// Append the Certificate body bytes.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encoded_len()?;
        match self.form {
            TlsCertificateForm::Tls12 => {
                let mut list = Vec::with_capacity(self.certificate_list_body_len_tls12()?);
                for entry in &self.certificate_list {
                    entry.encode_tls12(&mut list)?;
                }
                encode_u24_vector(&list, "tls.certificate.certificate_list.length", out)?;
            }
            TlsCertificateForm::Tls13 => {
                encode_u8_vector(
                    &self.request_context,
                    "tls.certificate.request_context.length",
                    out,
                )?;
                let mut list = Vec::with_capacity(self.certificate_list_body_len_tls13()?);
                for entry in &self.certificate_list {
                    entry.encode_tls13(&mut list)?;
                }
                encode_u24_vector(&list, "tls.certificate.certificate_list.length", out)?;
            }
        }
        Ok(())
    }

    /// Return the encoded Certificate body bytes.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Compile the Certificate body bytes.
    pub fn compile(&self) -> Result<Vec<u8>> {
        self.encode_to_vec()
    }

    /// Decode one complete Certificate body, trying TLS 1.3 and then TLS 1.2.
    ///
    /// Use the version-specific decoders when session context already identifies
    /// the negotiated TLS version.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        match Self::decode_tls13(bytes) {
            Ok(certificate) => Ok(certificate),
            Err(tls13_error) => match Self::decode_tls12(bytes) {
                Ok(certificate) => Ok(certificate),
                Err(_) => Err(tls13_error),
            },
        }
    }

    /// Decode one complete TLS 1.2 Certificate body.
    pub fn decode_tls12(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (certificate, tail) = Self::decode_prefix_tls12(bytes.as_ref())?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.certificate.certificate_list.length",
                "trailing bytes after certificate list",
            ));
        }
        Ok(certificate)
    }

    /// Decode one complete TLS 1.3 Certificate body.
    pub fn decode_tls13(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (certificate, tail) = Self::decode_prefix_tls13(bytes.as_ref())?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.certificate.certificate_list.length",
                "trailing bytes after certificate list",
            ));
        }
        Ok(certificate)
    }

    /// Decode one Certificate body from the front of `bytes`.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        match Self::decode_prefix_tls13(bytes) {
            Ok(result) => Ok(result),
            Err(tls13_error) => match Self::decode_prefix_tls12(bytes) {
                Ok(result) => Ok(result),
                Err(_) => Err(tls13_error),
            },
        }
    }

    /// Decode one TLS 1.2 Certificate body from the front of `bytes`.
    pub fn decode_prefix_tls12(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let mut cursor = 0;
        let list_body = decode_u24_vector(
            bytes,
            &mut cursor,
            "tls.certificate.certificate_list",
            "tls.certificate.certificate_list.length",
        )?;
        let mut list_cursor = 0;
        let mut certificate_list = Vec::new();
        while list_cursor < list_body.len() {
            certificate_list.push(TlsCertificateEntry::decode_tls12_from(
                &list_body,
                &mut list_cursor,
            )?);
        }
        Ok((Self::tls12(certificate_list), &bytes[cursor..]))
    }

    /// Decode one TLS 1.3 Certificate body from the front of `bytes`.
    pub fn decode_prefix_tls13(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let mut cursor = 0;
        let request_context = decode_u8_vector(
            bytes,
            &mut cursor,
            "tls.certificate.request_context",
            "tls.certificate.request_context.length",
        )?;
        let list_body = decode_u24_vector(
            bytes,
            &mut cursor,
            "tls.certificate.certificate_list",
            "tls.certificate.certificate_list.length",
        )?;
        let mut list_cursor = 0;
        let mut certificate_list = Vec::new();
        while list_cursor < list_body.len() {
            certificate_list.push(TlsCertificateEntry::decode_tls13_from(
                &list_body,
                &mut list_cursor,
            )?);
        }
        Ok((
            Self::tls13(request_context, certificate_list),
            &bytes[cursor..],
        ))
    }

    /// Stable one-line summary preserving form, vector sizes, and counts.
    pub fn summary(&self) -> String {
        format!(
            "certificate form={} request_context_bytes={} certificate_list={} certificate_bytes={} entry_extensions={}",
            self.form.label(),
            self.request_context.len(),
            self.certificate_list.len(),
            self.certificate_bytes(),
            self.entry_extensions_len()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("form", self.form.label().to_string()),
            ("request_context", hex_bytes(&self.request_context)),
            (
                "request_context_bytes",
                self.request_context.len().to_string(),
            ),
            (
                "certificate_list_count",
                self.certificate_list.len().to_string(),
            ),
            ("certificate_bytes", self.certificate_bytes().to_string()),
            (
                "entry_extensions_count",
                self.entry_extensions_len().to_string(),
            ),
        ]
    }

    fn certificate_list_body_len_tls12(&self) -> Result<usize> {
        let mut len = 0usize;
        for entry in &self.certificate_list {
            len = checked_add_len(
                len,
                entry.encoded_len_tls12()?,
                "tls.certificate.certificate_list.length",
            )?;
        }
        validate_u24_vector_len(len, "tls.certificate.certificate_list.length")
    }

    fn certificate_list_body_len_tls13(&self) -> Result<usize> {
        let mut len = 0usize;
        for entry in &self.certificate_list {
            len = checked_add_len(
                len,
                entry.encoded_len_tls13()?,
                "tls.certificate.certificate_list.length",
            )?;
        }
        validate_u24_vector_len(len, "tls.certificate.certificate_list.length")
    }
}

impl Default for TlsCertificate {
    fn default() -> Self {
        Self::new()
    }
}

/// A raw-preserving TLS 1.2 `ClientCertificateType` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TlsClientCertificateType {
    raw: u8,
}

impl TlsClientCertificateType {
    /// TLS ClientCertificateType `rsa_sign`.
    pub const RSA_SIGN: Self = Self::new(TLS_CLIENT_CERTIFICATE_TYPE_RSA_SIGN);
    /// TLS ClientCertificateType `dss_sign`.
    pub const DSS_SIGN: Self = Self::new(TLS_CLIENT_CERTIFICATE_TYPE_DSS_SIGN);
    /// TLS ClientCertificateType `rsa_fixed_dh`.
    pub const RSA_FIXED_DH: Self = Self::new(TLS_CLIENT_CERTIFICATE_TYPE_RSA_FIXED_DH);
    /// TLS ClientCertificateType `dss_fixed_dh`.
    pub const DSS_FIXED_DH: Self = Self::new(TLS_CLIENT_CERTIFICATE_TYPE_DSS_FIXED_DH);
    /// TLS ClientCertificateType `rsa_ephemeral_dh_RESERVED`.
    pub const RSA_EPHEMERAL_DH_RESERVED: Self =
        Self::new(TLS_CLIENT_CERTIFICATE_TYPE_RSA_EPHEMERAL_DH_RESERVED);
    /// TLS ClientCertificateType `dss_ephemeral_dh_RESERVED`.
    pub const DSS_EPHEMERAL_DH_RESERVED: Self =
        Self::new(TLS_CLIENT_CERTIFICATE_TYPE_DSS_EPHEMERAL_DH_RESERVED);
    /// TLS ClientCertificateType `fortezza_dms_RESERVED`.
    pub const FORTEZZA_DMS_RESERVED: Self =
        Self::new(TLS_CLIENT_CERTIFICATE_TYPE_FORTEZZA_DMS_RESERVED);
    /// TLS ClientCertificateType `ecdsa_sign`.
    pub const ECDSA_SIGN: Self = Self::new(TLS_CLIENT_CERTIFICATE_TYPE_ECDSA_SIGN);
    /// TLS ClientCertificateType `rsa_fixed_ecdh`.
    pub const RSA_FIXED_ECDH: Self = Self::new(TLS_CLIENT_CERTIFICATE_TYPE_RSA_FIXED_ECDH);
    /// TLS ClientCertificateType `ecdsa_fixed_ecdh`.
    pub const ECDSA_FIXED_ECDH: Self = Self::new(TLS_CLIENT_CERTIFICATE_TYPE_ECDSA_FIXED_ECDH);

    /// Preserve a caller-supplied raw one-octet client certificate type.
    pub const fn new(raw: u8) -> Self {
        Self { raw }
    }

    /// Preserve a caller-supplied raw one-octet client certificate type.
    pub const fn from_u8(raw: u8) -> Self {
        Self::new(raw)
    }

    /// TLS ClientCertificateType `rsa_sign` constructor.
    pub const fn rsa_sign() -> Self {
        Self::RSA_SIGN
    }

    /// TLS ClientCertificateType `ecdsa_sign` constructor.
    pub const fn ecdsa_sign() -> Self {
        Self::ECDSA_SIGN
    }

    /// Return the preserved raw one-octet value.
    pub const fn raw(self) -> u8 {
        self.raw
    }

    /// Return the source-backed label, preserving unknown values numerically.
    pub fn label(self) -> String {
        match self.raw {
            TLS_CLIENT_CERTIFICATE_TYPE_RSA_SIGN => "rsa_sign".to_string(),
            TLS_CLIENT_CERTIFICATE_TYPE_DSS_SIGN => "dss_sign".to_string(),
            TLS_CLIENT_CERTIFICATE_TYPE_RSA_FIXED_DH => "rsa_fixed_dh".to_string(),
            TLS_CLIENT_CERTIFICATE_TYPE_DSS_FIXED_DH => "dss_fixed_dh".to_string(),
            TLS_CLIENT_CERTIFICATE_TYPE_RSA_EPHEMERAL_DH_RESERVED => {
                "rsa_ephemeral_dh_RESERVED".to_string()
            }
            TLS_CLIENT_CERTIFICATE_TYPE_DSS_EPHEMERAL_DH_RESERVED => {
                "dss_ephemeral_dh_RESERVED".to_string()
            }
            TLS_CLIENT_CERTIFICATE_TYPE_FORTEZZA_DMS_RESERVED => {
                "fortezza_dms_RESERVED".to_string()
            }
            TLS_CLIENT_CERTIFICATE_TYPE_ECDSA_SIGN => "ecdsa_sign".to_string(),
            TLS_CLIENT_CERTIFICATE_TYPE_RSA_FIXED_ECDH => "rsa_fixed_ecdh".to_string(),
            TLS_CLIENT_CERTIFICATE_TYPE_ECDSA_FIXED_ECDH => "ecdsa_fixed_ecdh".to_string(),
            raw => format!("unknown client certificate type 0x{raw:02x}"),
        }
    }
}

impl From<u8> for TlsClientCertificateType {
    fn from(value: u8) -> Self {
        Self::new(value)
    }
}

impl From<TlsClientCertificateType> for u8 {
    fn from(value: TlsClientCertificateType) -> Self {
        value.raw()
    }
}

impl fmt::Display for TlsClientCertificateType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// TLS CertificateRequest message wire form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsCertificateRequestForm {
    /// TLS 1.2 form with certificate types, signature schemes, and authorities.
    Tls12,
    /// TLS 1.3 form with request context and extensions.
    Tls13,
}

impl TlsCertificateRequestForm {
    /// Stable lowercase label for summaries and inspection output.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Tls12 => "tls12",
            Self::Tls13 => "tls13",
        }
    }
}

/// TLS CertificateRequest handshake body fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsCertificateRequest {
    form: TlsCertificateRequestForm,
    certificate_types: Vec<TlsClientCertificateType>,
    signature_algorithms: TlsSignatureAlgorithms,
    certificate_authorities: TlsCertificateAuthorities,
    request_context: Vec<u8>,
    extensions: Vec<TlsRawExtension>,
}

impl TlsCertificateRequest {
    /// Construct an empty TLS 1.3 CertificateRequest body.
    pub fn new() -> Self {
        Self::tls13(Vec::new(), Vec::new())
    }

    /// Construct a TLS 1.2 CertificateRequest body.
    pub fn tls12(
        certificate_types: impl Into<Vec<TlsClientCertificateType>>,
        signature_algorithms: impl Into<TlsSignatureAlgorithms>,
        certificate_authorities: impl Into<TlsCertificateAuthorities>,
    ) -> Self {
        Self {
            form: TlsCertificateRequestForm::Tls12,
            certificate_types: certificate_types.into(),
            signature_algorithms: signature_algorithms.into(),
            certificate_authorities: certificate_authorities.into(),
            request_context: Vec::new(),
            extensions: Vec::new(),
        }
    }

    /// Construct a TLS 1.3 CertificateRequest body.
    pub fn tls13(
        request_context: impl Into<Vec<u8>>,
        extensions: impl Into<Vec<TlsRawExtension>>,
    ) -> Self {
        Self {
            form: TlsCertificateRequestForm::Tls13,
            certificate_types: Vec::new(),
            signature_algorithms: TlsSignatureAlgorithms::default(),
            certificate_authorities: TlsCertificateAuthorities::default(),
            request_context: request_context.into(),
            extensions: extensions.into(),
        }
    }

    /// Replace the message with TLS 1.2 wire form.
    pub fn with_tls12_form(mut self) -> Self {
        self.form = TlsCertificateRequestForm::Tls12;
        self.request_context.clear();
        self.extensions.clear();
        self
    }

    /// Replace the message with TLS 1.3 wire form.
    pub fn with_tls13_form(mut self) -> Self {
        self.form = TlsCertificateRequestForm::Tls13;
        self
    }

    /// Replace the TLS 1.2 certificate type vector.
    pub fn with_certificate_types(
        mut self,
        certificate_types: impl Into<Vec<TlsClientCertificateType>>,
    ) -> Self {
        self.form = TlsCertificateRequestForm::Tls12;
        self.certificate_types = certificate_types.into();
        self
    }

    /// Append one TLS 1.2 certificate type.
    pub fn with_certificate_type(
        mut self,
        certificate_type: impl Into<TlsClientCertificateType>,
    ) -> Self {
        self.form = TlsCertificateRequestForm::Tls12;
        self.certificate_types.push(certificate_type.into());
        self
    }

    /// Append one raw TLS 1.2 certificate type.
    pub fn with_raw_certificate_type(self, certificate_type: u8) -> Self {
        self.with_certificate_type(TlsClientCertificateType::from_u8(certificate_type))
    }

    /// Replace the TLS 1.2 supported signature schemes.
    pub fn with_signature_algorithms(
        mut self,
        signature_algorithms: impl Into<TlsSignatureAlgorithms>,
    ) -> Self {
        self.form = TlsCertificateRequestForm::Tls12;
        self.signature_algorithms = signature_algorithms.into();
        self
    }

    /// Replace the TLS 1.2 supported signature schemes from raw values.
    pub fn with_raw_signature_algorithms(self, raws: impl IntoIterator<Item = u16>) -> Self {
        self.with_signature_algorithms(TlsSignatureAlgorithms::from_raws(raws))
    }

    /// Replace the TLS 1.2 certificate authorities.
    pub fn with_certificate_authorities(
        mut self,
        certificate_authorities: impl Into<TlsCertificateAuthorities>,
    ) -> Self {
        self.form = TlsCertificateRequestForm::Tls12;
        self.certificate_authorities = certificate_authorities.into();
        self
    }

    /// Replace the TLS 1.3 certificate_request_context and select TLS 1.3 form.
    pub fn with_request_context(mut self, request_context: impl Into<Vec<u8>>) -> Self {
        self.form = TlsCertificateRequestForm::Tls13;
        self.request_context = request_context.into();
        self
    }

    /// Replace the TLS 1.3 extension list and select TLS 1.3 form.
    pub fn with_extensions(mut self, extensions: impl Into<Vec<TlsRawExtension>>) -> Self {
        self.form = TlsCertificateRequestForm::Tls13;
        self.extensions = extensions.into();
        self
    }

    /// Append one TLS 1.3 extension and select TLS 1.3 form.
    pub fn with_extension(mut self, extension: TlsRawExtension) -> Self {
        self.form = TlsCertificateRequestForm::Tls13;
        self.extensions.push(extension);
        self
    }

    /// Append one raw TLS 1.3 extension and select TLS 1.3 form.
    pub fn with_raw_extension(self, extension_type: u16, body: impl Into<Vec<u8>>) -> Self {
        self.with_extension(TlsRawExtension::from_raw(extension_type, body))
    }

    /// Append a typed TLS 1.3 `signature_algorithms` extension.
    pub fn with_tls13_signature_algorithms(
        self,
        signature_algorithms: impl Into<TlsSignatureAlgorithms>,
    ) -> Result<Self> {
        Ok(self.with_extension(TlsRawExtension::signature_algorithms(
            signature_algorithms.into(),
        )?))
    }

    /// Append a typed TLS 1.3 `certificate_authorities` extension.
    pub fn with_tls13_certificate_authorities(
        self,
        certificate_authorities: impl Into<TlsCertificateAuthorities>,
    ) -> Result<Self> {
        Ok(
            self.with_extension(TlsRawExtension::certificate_authorities(
                certificate_authorities.into(),
            )?),
        )
    }

    /// Return the selected CertificateRequest wire form.
    pub const fn form(&self) -> TlsCertificateRequestForm {
        self.form
    }

    /// Return true when this body uses the TLS 1.2 form.
    pub const fn is_tls12(&self) -> bool {
        matches!(self.form, TlsCertificateRequestForm::Tls12)
    }

    /// Return true when this body uses the TLS 1.3 form.
    pub const fn is_tls13(&self) -> bool {
        matches!(self.form, TlsCertificateRequestForm::Tls13)
    }

    /// Borrow the TLS 1.2 certificate type vector.
    pub fn certificate_types(&self) -> &[TlsClientCertificateType] {
        &self.certificate_types
    }

    /// Return the TLS 1.2 certificate type labels in wire order.
    pub fn certificate_type_labels(&self) -> Vec<String> {
        self.certificate_types
            .iter()
            .map(|certificate_type| certificate_type.label())
            .collect()
    }

    /// Borrow the TLS 1.2 supported signature schemes.
    pub const fn signature_algorithms(&self) -> &TlsSignatureAlgorithms {
        &self.signature_algorithms
    }

    /// Borrow the TLS 1.2 certificate authorities.
    pub const fn certificate_authorities(&self) -> &TlsCertificateAuthorities {
        &self.certificate_authorities
    }

    /// Borrow the TLS 1.3 certificate_request_context bytes.
    pub fn request_context(&self) -> &[u8] {
        &self.request_context
    }

    /// Borrow the TLS 1.3 extension list.
    pub fn extensions(&self) -> &[TlsRawExtension] {
        &self.extensions
    }

    /// Number of bytes occupied by the CertificateRequest body.
    pub fn encoded_len(&self) -> Result<usize> {
        match self.form {
            TlsCertificateRequestForm::Tls12 => {
                let mut len = TLS_CERTIFICATE_REQUEST_TYPES_LENGTH_LEN;
                len = checked_add_len(
                    len,
                    validate_u8_vector_len(
                        self.certificate_types.len(),
                        "tls.certificate_request.certificate_types.length",
                    )?,
                    "tls.certificate_request.length",
                )?;
                len = checked_add_len(
                    len,
                    self.signature_algorithms.encoded_len()?,
                    "tls.certificate_request.length",
                )?;
                len = checked_add_len(
                    len,
                    self.certificate_authorities.encoded_len()?,
                    "tls.certificate_request.length",
                )?;
                Ok(len)
            }
            TlsCertificateRequestForm::Tls13 => {
                validate_u8_vector_len(
                    self.request_context.len(),
                    "tls.certificate_request.request_context.length",
                )?;
                let mut len = TLS_CERTIFICATE_REQUEST_CONTEXT_LENGTH_LEN;
                len = checked_add_len(
                    len,
                    self.request_context.len(),
                    "tls.certificate_request.length",
                )?;
                len = checked_add_len(
                    len,
                    TlsExtensions::new(self.extensions.clone())
                        .encoded_len_with_context(TlsExtensionListContext::certificate_request())?,
                    "tls.certificate_request.length",
                )?;
                Ok(len)
            }
        }
    }

    /// Append the CertificateRequest body bytes.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encoded_len()?;
        match self.form {
            TlsCertificateRequestForm::Tls12 => {
                out.push(self.certificate_types.len() as u8);
                for certificate_type in &self.certificate_types {
                    out.push(certificate_type.raw());
                }
                self.signature_algorithms.encode(out)?;
                self.certificate_authorities.encode(out)?;
            }
            TlsCertificateRequestForm::Tls13 => {
                encode_u8_vector(
                    &self.request_context,
                    "tls.certificate_request.request_context.length",
                    out,
                )?;
                TlsExtensions::new(self.extensions.clone())
                    .encode_with_context(TlsExtensionListContext::certificate_request(), out)?;
            }
        }
        Ok(())
    }

    /// Return the encoded CertificateRequest body bytes.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Compile the CertificateRequest body bytes.
    pub fn compile(&self) -> Result<Vec<u8>> {
        self.encode_to_vec()
    }

    /// Decode one complete CertificateRequest body, trying TLS 1.3 and then TLS 1.2.
    ///
    /// Use the version-specific decoders when session context already identifies
    /// the negotiated TLS version.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        match Self::decode_tls13(bytes) {
            Ok(request) => Ok(request),
            Err(tls13_error) => match Self::decode_tls12(bytes) {
                Ok(request) => Ok(request),
                Err(_) => Err(tls13_error),
            },
        }
    }

    /// Decode one complete TLS 1.2 CertificateRequest body.
    pub fn decode_tls12(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (request, tail) = Self::decode_prefix_tls12(bytes.as_ref())?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.certificate_request.length",
                "trailing bytes after certificate authorities",
            ));
        }
        Ok(request)
    }

    /// Decode one complete TLS 1.3 CertificateRequest body.
    pub fn decode_tls13(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (request, tail) = Self::decode_prefix_tls13(bytes.as_ref())?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.certificate_request.length",
                "trailing bytes after extensions",
            ));
        }
        Ok(request)
    }

    /// Decode one CertificateRequest body from the front of `bytes`.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        match Self::decode_prefix_tls13(bytes) {
            Ok(result) => Ok(result),
            Err(tls13_error) => match Self::decode_prefix_tls12(bytes) {
                Ok(result) => Ok(result),
                Err(_) => Err(tls13_error),
            },
        }
    }

    /// Decode one TLS 1.2 CertificateRequest body from the front of `bytes`.
    pub fn decode_prefix_tls12(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let mut cursor = 0;
        let certificate_type_len = take_bytes(
            bytes,
            &mut cursor,
            TLS_CERTIFICATE_REQUEST_TYPES_LENGTH_LEN,
            "tls.certificate_request.certificate_types.length",
        )?[0] as usize;
        let certificate_type_bytes = take_bytes(
            bytes,
            &mut cursor,
            certificate_type_len,
            "tls.certificate_request.certificate_types",
        )?;
        let certificate_types = certificate_type_bytes
            .iter()
            .copied()
            .map(TlsClientCertificateType::from_u8)
            .collect::<Vec<_>>();

        let (signature_algorithms, tail) = TlsSignatureAlgorithms::decode_prefix(&bytes[cursor..])?;
        cursor = bytes.len() - tail.len();
        let (certificate_authorities, tail) =
            TlsCertificateAuthorities::decode_prefix(&bytes[cursor..])?;
        cursor = bytes.len() - tail.len();

        Ok((
            Self::tls12(
                certificate_types,
                signature_algorithms,
                certificate_authorities,
            ),
            &bytes[cursor..],
        ))
    }

    /// Decode one TLS 1.3 CertificateRequest body from the front of `bytes`.
    pub fn decode_prefix_tls13(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let mut cursor = 0;
        let request_context = decode_u8_vector(
            bytes,
            &mut cursor,
            "tls.certificate_request.request_context",
            "tls.certificate_request.request_context.length",
        )?;
        let extensions = decode_extension_list(
            bytes,
            &mut cursor,
            TlsExtensionListContext::certificate_request(),
        )?;
        Ok((Self::tls13(request_context, extensions), &bytes[cursor..]))
    }

    /// Stable one-line summary preserving form, vector sizes, and counts.
    pub fn summary(&self) -> String {
        format!(
            "certificate_request form={} certificate_types={} signature_algorithms={} certificate_authorities={} request_context_bytes={} extensions={}",
            self.form.label(),
            self.certificate_types.len(),
            self.signature_algorithms.len(),
            self.certificate_authorities.len(),
            self.request_context.len(),
            self.extensions.len()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("form", self.form.label().to_string()),
            (
                "certificate_types_count",
                self.certificate_types.len().to_string(),
            ),
            (
                "certificate_types",
                self.certificate_type_labels().join(","),
            ),
            (
                "signature_algorithms_count",
                self.signature_algorithms.len().to_string(),
            ),
            (
                "certificate_authorities_count",
                self.certificate_authorities.len().to_string(),
            ),
            ("request_context", hex_bytes(&self.request_context)),
            (
                "request_context_bytes",
                self.request_context.len().to_string(),
            ),
            ("extensions_count", self.extensions.len().to_string()),
        ]
    }
}

impl Default for TlsCertificateRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// TLS CertificateVerify handshake body fields.
///
/// The signature bytes stay opaque; this type models packet framing only and
/// does not verify signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsCertificateVerify {
    signature_scheme: TlsSignatureScheme,
    signature: Vec<u8>,
}

impl TlsCertificateVerify {
    /// Construct a CertificateVerify body from a signature scheme and opaque signature bytes.
    pub fn new(
        signature_scheme: impl Into<TlsSignatureScheme>,
        signature: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            signature_scheme: signature_scheme.into(),
            signature: signature.into(),
        }
    }

    /// Construct a CertificateVerify body from a raw signature scheme value.
    pub fn from_raw_signature_scheme(
        raw_signature_scheme: u16,
        signature: impl Into<Vec<u8>>,
    ) -> Self {
        Self::new(
            TlsSignatureScheme::from_u16(raw_signature_scheme),
            signature,
        )
    }

    /// Replace the signature scheme.
    pub fn with_signature_scheme(
        mut self,
        signature_scheme: impl Into<TlsSignatureScheme>,
    ) -> Self {
        self.signature_scheme = signature_scheme.into();
        self
    }

    /// Replace the signature scheme from a raw two-octet value.
    pub fn with_raw_signature_scheme(self, signature_scheme: u16) -> Self {
        self.with_signature_scheme(TlsSignatureScheme::from_u16(signature_scheme))
    }

    /// Replace the opaque signature bytes.
    pub fn with_signature(mut self, signature: impl Into<Vec<u8>>) -> Self {
        self.signature = signature.into();
        self
    }

    /// Return the preserved signature scheme.
    pub const fn signature_scheme(&self) -> TlsSignatureScheme {
        self.signature_scheme
    }

    /// Borrow the opaque signature bytes.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Number of opaque signature bytes.
    pub fn signature_len(&self) -> usize {
        self.signature.len()
    }

    /// Number of bytes occupied by the CertificateVerify body.
    pub fn encoded_len(&self) -> Result<usize> {
        let mut len = TLS_SIGNATURE_SCHEME_LEN;
        len = checked_add_len(
            len,
            TLS_CERTIFICATE_VERIFY_SIGNATURE_LENGTH_LEN,
            "tls.certificate_verify.length",
        )?;
        len = checked_add_len(
            len,
            validate_u16_vector_len(
                self.signature.len(),
                "tls.certificate_verify.signature.length",
            )?,
            "tls.certificate_verify.length",
        )?;
        Ok(len)
    }

    /// Append the CertificateVerify body bytes.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encoded_len()?;
        self.signature_scheme.encode(out);
        encode_u16_vector(
            &self.signature,
            "tls.certificate_verify.signature.length",
            out,
        )
    }

    /// Return the encoded CertificateVerify body bytes.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Compile the CertificateVerify body bytes.
    pub fn compile(&self) -> Result<Vec<u8>> {
        self.encode_to_vec()
    }

    /// Decode one complete CertificateVerify body.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (certificate_verify, tail) = Self::decode_prefix(bytes.as_ref())?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.certificate_verify.length",
                "trailing bytes after signature",
            ));
        }
        Ok(certificate_verify)
    }

    /// Decode one CertificateVerify body from the front of `bytes`.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let mut cursor = 0;
        let scheme = take_bytes(
            bytes,
            &mut cursor,
            TLS_SIGNATURE_SCHEME_LEN,
            "tls.certificate_verify.signature_scheme",
        )?;
        let signature_scheme = TlsSignatureScheme::from_be_bytes([scheme[0], scheme[1]]);
        let signature = decode_u16_vector(
            bytes,
            &mut cursor,
            "tls.certificate_verify.signature",
            "tls.certificate_verify.signature.length",
        )?;
        Ok((
            Self {
                signature_scheme,
                signature,
            },
            &bytes[cursor..],
        ))
    }

    /// Stable one-line summary preserving the signature scheme and opaque size.
    pub fn summary(&self) -> String {
        format!(
            "certificate_verify signature_scheme={} signature_bytes={}",
            self.signature_scheme.label(),
            self.signature.len()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("signature_scheme", self.signature_scheme.label()),
            (
                "signature_scheme_raw",
                format!("0x{:04x}", self.signature_scheme.raw()),
            ),
            ("signature", hex_bytes(&self.signature)),
            ("signature_bytes", self.signature.len().to_string()),
        ]
    }
}

/// TLS Finished handshake body fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsFinished {
    verify_data: Vec<u8>,
}

impl TlsFinished {
    /// Construct a Finished body from opaque verify_data bytes.
    pub fn new(verify_data: impl Into<Vec<u8>>) -> Self {
        Self {
            verify_data: verify_data.into(),
        }
    }

    /// Construct an empty Finished body.
    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    /// Replace the opaque verify_data bytes.
    pub fn with_verify_data(mut self, verify_data: impl Into<Vec<u8>>) -> Self {
        self.verify_data = verify_data.into();
        self
    }

    /// Borrow the opaque verify_data bytes.
    pub fn verify_data(&self) -> &[u8] {
        &self.verify_data
    }

    /// Number of opaque verify_data bytes.
    pub fn len(&self) -> usize {
        self.verify_data.len()
    }

    /// Return true when verify_data is empty.
    pub fn is_empty(&self) -> bool {
        self.verify_data.is_empty()
    }

    /// Number of bytes occupied by the Finished body.
    pub fn encoded_len(&self) -> Result<usize> {
        Ok(self.verify_data.len())
    }

    /// Append the Finished body bytes.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.verify_data);
        Ok(())
    }

    /// Return the encoded Finished body bytes.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Compile the Finished body bytes.
    pub fn compile(&self) -> Result<Vec<u8>> {
        self.encode_to_vec()
    }

    /// Decode one complete Finished body.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        Ok(Self::new(bytes.as_ref().to_vec()))
    }

    /// Stable one-line summary preserving opaque verify_data size.
    pub fn summary(&self) -> String {
        format!("finished verify_data_bytes={}", self.verify_data.len())
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("verify_data", hex_bytes(&self.verify_data)),
            ("verify_data_bytes", self.verify_data.len().to_string()),
        ]
    }
}

impl Default for TlsFinished {
    fn default() -> Self {
        Self::empty()
    }
}

/// TLS NewSessionTicket message wire form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsNewSessionTicketForm {
    /// TLS 1.2 form with lifetime hint and opaque ticket.
    Tls12,
    /// TLS 1.3 form with age_add, nonce, opaque ticket, and extensions.
    Tls13,
}

impl TlsNewSessionTicketForm {
    /// Stable lowercase label for summaries and inspection output.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Tls12 => "tls12",
            Self::Tls13 => "tls13",
        }
    }
}

/// TLS NewSessionTicket handshake body fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsNewSessionTicket {
    form: TlsNewSessionTicketForm,
    ticket_lifetime: u32,
    ticket_age_add: u32,
    ticket_nonce: Vec<u8>,
    ticket: Vec<u8>,
    extensions: Vec<TlsRawExtension>,
}

impl TlsNewSessionTicket {
    /// Construct an empty TLS 1.3 NewSessionTicket body.
    pub fn new() -> Self {
        Self::tls13(0, 0, Vec::new(), Vec::new(), Vec::new())
    }

    /// Construct a TLS 1.2 NewSessionTicket body.
    pub fn tls12(ticket_lifetime_hint: u32, ticket: impl Into<Vec<u8>>) -> Self {
        Self {
            form: TlsNewSessionTicketForm::Tls12,
            ticket_lifetime: ticket_lifetime_hint,
            ticket_age_add: 0,
            ticket_nonce: Vec::new(),
            ticket: ticket.into(),
            extensions: Vec::new(),
        }
    }

    /// Construct a TLS 1.3 NewSessionTicket body.
    pub fn tls13(
        ticket_lifetime: u32,
        ticket_age_add: u32,
        ticket_nonce: impl Into<Vec<u8>>,
        ticket: impl Into<Vec<u8>>,
        extensions: impl Into<Vec<TlsRawExtension>>,
    ) -> Self {
        Self {
            form: TlsNewSessionTicketForm::Tls13,
            ticket_lifetime,
            ticket_age_add,
            ticket_nonce: ticket_nonce.into(),
            ticket: ticket.into(),
            extensions: extensions.into(),
        }
    }

    /// Replace the message with TLS 1.2 wire form.
    pub fn with_tls12_form(mut self) -> Self {
        self.form = TlsNewSessionTicketForm::Tls12;
        self.ticket_age_add = 0;
        self.ticket_nonce.clear();
        self.extensions.clear();
        self
    }

    /// Replace the message with TLS 1.3 wire form.
    pub fn with_tls13_form(mut self) -> Self {
        self.form = TlsNewSessionTicketForm::Tls13;
        self
    }

    /// Replace the ticket lifetime or TLS 1.2 lifetime hint.
    pub fn with_ticket_lifetime(mut self, ticket_lifetime: u32) -> Self {
        self.ticket_lifetime = ticket_lifetime;
        self
    }

    /// Replace the TLS 1.3 ticket_age_add and select TLS 1.3 form.
    pub fn with_ticket_age_add(mut self, ticket_age_add: u32) -> Self {
        self.form = TlsNewSessionTicketForm::Tls13;
        self.ticket_age_add = ticket_age_add;
        self
    }

    /// Replace the TLS 1.3 ticket_nonce and select TLS 1.3 form.
    pub fn with_ticket_nonce(mut self, ticket_nonce: impl Into<Vec<u8>>) -> Self {
        self.form = TlsNewSessionTicketForm::Tls13;
        self.ticket_nonce = ticket_nonce.into();
        self
    }

    /// Replace the opaque ticket bytes.
    pub fn with_ticket(mut self, ticket: impl Into<Vec<u8>>) -> Self {
        self.ticket = ticket.into();
        self
    }

    /// Replace the TLS 1.3 extension list and select TLS 1.3 form.
    pub fn with_extensions(mut self, extensions: impl Into<Vec<TlsRawExtension>>) -> Self {
        self.form = TlsNewSessionTicketForm::Tls13;
        self.extensions = extensions.into();
        self
    }

    /// Append one TLS 1.3 extension and select TLS 1.3 form.
    pub fn with_extension(mut self, extension: TlsRawExtension) -> Self {
        self.form = TlsNewSessionTicketForm::Tls13;
        self.extensions.push(extension);
        self
    }

    /// Append one raw TLS 1.3 extension and select TLS 1.3 form.
    pub fn with_raw_extension(self, extension_type: u16, body: impl Into<Vec<u8>>) -> Self {
        self.with_extension(TlsRawExtension::from_raw(extension_type, body))
    }

    /// Return the selected NewSessionTicket wire form.
    pub const fn form(&self) -> TlsNewSessionTicketForm {
        self.form
    }

    /// Return true when this body uses the TLS 1.2 form.
    pub const fn is_tls12(&self) -> bool {
        matches!(self.form, TlsNewSessionTicketForm::Tls12)
    }

    /// Return true when this body uses the TLS 1.3 form.
    pub const fn is_tls13(&self) -> bool {
        matches!(self.form, TlsNewSessionTicketForm::Tls13)
    }

    /// Return ticket_lifetime in TLS 1.3 or ticket_lifetime_hint in TLS 1.2.
    pub const fn ticket_lifetime(&self) -> u32 {
        self.ticket_lifetime
    }

    /// Return the TLS 1.3 ticket_age_add value.
    pub const fn ticket_age_add(&self) -> u32 {
        self.ticket_age_add
    }

    /// Borrow the TLS 1.3 ticket_nonce bytes.
    pub fn ticket_nonce(&self) -> &[u8] {
        &self.ticket_nonce
    }

    /// Borrow the opaque ticket bytes.
    pub fn ticket(&self) -> &[u8] {
        &self.ticket
    }

    /// Borrow the TLS 1.3 extension list.
    pub fn extensions(&self) -> &[TlsRawExtension] {
        &self.extensions
    }

    /// Number of bytes occupied by the NewSessionTicket body.
    pub fn encoded_len(&self) -> Result<usize> {
        let mut len = TLS_NEW_SESSION_TICKET_LIFETIME_LEN;
        match self.form {
            TlsNewSessionTicketForm::Tls12 => {
                len = checked_add_len(
                    len,
                    TLS_NEW_SESSION_TICKET_TICKET_LENGTH_LEN,
                    "tls.new_session_ticket.length",
                )?;
                len = checked_add_len(
                    len,
                    validate_u16_vector_len(
                        self.ticket.len(),
                        "tls.new_session_ticket.ticket.length",
                    )?,
                    "tls.new_session_ticket.length",
                )?;
                Ok(len)
            }
            TlsNewSessionTicketForm::Tls13 => {
                validate_u8_vector_len(
                    self.ticket_nonce.len(),
                    "tls.new_session_ticket.ticket_nonce.length",
                )?;
                len = checked_add_len(
                    len,
                    TLS_NEW_SESSION_TICKET_AGE_ADD_LEN,
                    "tls.new_session_ticket.length",
                )?;
                len = checked_add_len(
                    len,
                    TLS_NEW_SESSION_TICKET_NONCE_LENGTH_LEN,
                    "tls.new_session_ticket.length",
                )?;
                len = checked_add_len(
                    len,
                    self.ticket_nonce.len(),
                    "tls.new_session_ticket.length",
                )?;
                len = checked_add_len(
                    len,
                    TLS_NEW_SESSION_TICKET_TICKET_LENGTH_LEN,
                    "tls.new_session_ticket.length",
                )?;
                len = checked_add_len(
                    len,
                    validate_u16_vector_len(
                        self.ticket.len(),
                        "tls.new_session_ticket.ticket.length",
                    )?,
                    "tls.new_session_ticket.length",
                )?;
                len = checked_add_len(
                    len,
                    TlsExtensions::new(self.extensions.clone())
                        .encoded_len_with_context(TlsExtensionListContext::new_session_ticket())?,
                    "tls.new_session_ticket.length",
                )?;
                Ok(len)
            }
        }
    }

    /// Append the NewSessionTicket body bytes.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encoded_len()?;
        out.extend_from_slice(&self.ticket_lifetime.to_be_bytes());
        match self.form {
            TlsNewSessionTicketForm::Tls12 => {
                encode_u16_vector(&self.ticket, "tls.new_session_ticket.ticket.length", out)?;
            }
            TlsNewSessionTicketForm::Tls13 => {
                out.extend_from_slice(&self.ticket_age_add.to_be_bytes());
                encode_u8_vector(
                    &self.ticket_nonce,
                    "tls.new_session_ticket.ticket_nonce.length",
                    out,
                )?;
                encode_u16_vector(&self.ticket, "tls.new_session_ticket.ticket.length", out)?;
                TlsExtensions::new(self.extensions.clone())
                    .encode_with_context(TlsExtensionListContext::new_session_ticket(), out)?;
            }
        }
        Ok(())
    }

    /// Return the encoded NewSessionTicket body bytes.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Compile the NewSessionTicket body bytes.
    pub fn compile(&self) -> Result<Vec<u8>> {
        self.encode_to_vec()
    }

    /// Decode one complete NewSessionTicket body, trying TLS 1.3 and then TLS 1.2.
    ///
    /// Use the version-specific decoders when session context already identifies
    /// the negotiated TLS version.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        match Self::decode_tls13(bytes) {
            Ok(ticket) => Ok(ticket),
            Err(tls13_error) => match Self::decode_tls12(bytes) {
                Ok(ticket) => Ok(ticket),
                Err(_) => Err(tls13_error),
            },
        }
    }

    /// Decode one complete TLS 1.2 NewSessionTicket body.
    pub fn decode_tls12(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (ticket, tail) = Self::decode_prefix_tls12(bytes.as_ref())?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.new_session_ticket.length",
                "trailing bytes after ticket",
            ));
        }
        Ok(ticket)
    }

    /// Decode one complete TLS 1.3 NewSessionTicket body.
    pub fn decode_tls13(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (ticket, tail) = Self::decode_prefix_tls13(bytes.as_ref())?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.new_session_ticket.length",
                "trailing bytes after extensions",
            ));
        }
        Ok(ticket)
    }

    /// Decode one NewSessionTicket body from the front of `bytes`.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        match Self::decode_prefix_tls13(bytes) {
            Ok(result) => Ok(result),
            Err(tls13_error) => match Self::decode_prefix_tls12(bytes) {
                Ok(result) => Ok(result),
                Err(_) => Err(tls13_error),
            },
        }
    }

    /// Decode one TLS 1.2 NewSessionTicket body from the front of `bytes`.
    pub fn decode_prefix_tls12(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let mut cursor = 0;
        let lifetime = take_bytes(
            bytes,
            &mut cursor,
            TLS_NEW_SESSION_TICKET_LIFETIME_LEN,
            "tls.new_session_ticket.ticket_lifetime_hint",
        )?;
        let ticket_lifetime_hint =
            u32::from_be_bytes([lifetime[0], lifetime[1], lifetime[2], lifetime[3]]);
        let ticket = decode_u16_vector(
            bytes,
            &mut cursor,
            "tls.new_session_ticket.ticket",
            "tls.new_session_ticket.ticket.length",
        )?;
        Ok((Self::tls12(ticket_lifetime_hint, ticket), &bytes[cursor..]))
    }

    /// Decode one TLS 1.3 NewSessionTicket body from the front of `bytes`.
    pub fn decode_prefix_tls13(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let mut cursor = 0;
        let lifetime = take_bytes(
            bytes,
            &mut cursor,
            TLS_NEW_SESSION_TICKET_LIFETIME_LEN,
            "tls.new_session_ticket.ticket_lifetime",
        )?;
        let ticket_lifetime =
            u32::from_be_bytes([lifetime[0], lifetime[1], lifetime[2], lifetime[3]]);
        let age_add = take_bytes(
            bytes,
            &mut cursor,
            TLS_NEW_SESSION_TICKET_AGE_ADD_LEN,
            "tls.new_session_ticket.ticket_age_add",
        )?;
        let ticket_age_add = u32::from_be_bytes([age_add[0], age_add[1], age_add[2], age_add[3]]);
        let ticket_nonce = decode_u8_vector(
            bytes,
            &mut cursor,
            "tls.new_session_ticket.ticket_nonce",
            "tls.new_session_ticket.ticket_nonce.length",
        )?;
        let ticket = decode_u16_vector(
            bytes,
            &mut cursor,
            "tls.new_session_ticket.ticket",
            "tls.new_session_ticket.ticket.length",
        )?;
        let extensions = decode_extension_list(
            bytes,
            &mut cursor,
            TlsExtensionListContext::new_session_ticket(),
        )?;
        Ok((
            Self::tls13(
                ticket_lifetime,
                ticket_age_add,
                ticket_nonce,
                ticket,
                extensions,
            ),
            &bytes[cursor..],
        ))
    }

    /// Stable one-line summary preserving form, ticket sizes, and extension count.
    pub fn summary(&self) -> String {
        format!(
            "new_session_ticket form={} lifetime={} age_add={} nonce_bytes={} ticket_bytes={} extensions={}",
            self.form.label(),
            self.ticket_lifetime,
            self.ticket_age_add,
            self.ticket_nonce.len(),
            self.ticket.len(),
            self.extensions.len()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("form", self.form.label().to_string()),
            ("ticket_lifetime", self.ticket_lifetime.to_string()),
            ("ticket_age_add", self.ticket_age_add.to_string()),
            ("ticket_nonce", hex_bytes(&self.ticket_nonce)),
            ("ticket_nonce_bytes", self.ticket_nonce.len().to_string()),
            ("ticket", hex_bytes(&self.ticket)),
            ("ticket_bytes", self.ticket.len().to_string()),
            ("extensions_count", self.extensions.len().to_string()),
        ]
    }
}

impl Default for TlsNewSessionTicket {
    fn default() -> Self {
        Self::new()
    }
}

/// A raw-preserving TLS `KeyUpdateRequest` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TlsKeyUpdateRequest {
    raw: u8,
}

impl TlsKeyUpdateRequest {
    /// TLS KeyUpdateRequest `update_not_requested`.
    pub const UPDATE_NOT_REQUESTED: Self = Self::new(TLS_KEY_UPDATE_REQUEST_UPDATE_NOT_REQUESTED);
    /// TLS KeyUpdateRequest `update_requested`.
    pub const UPDATE_REQUESTED: Self = Self::new(TLS_KEY_UPDATE_REQUEST_UPDATE_REQUESTED);

    /// Preserve a caller-supplied raw one-octet KeyUpdateRequest value.
    pub const fn new(raw: u8) -> Self {
        Self { raw }
    }

    /// Preserve a caller-supplied raw one-octet KeyUpdateRequest value.
    pub const fn from_u8(raw: u8) -> Self {
        Self::new(raw)
    }

    /// TLS KeyUpdateRequest `update_not_requested` constructor.
    pub const fn update_not_requested() -> Self {
        Self::UPDATE_NOT_REQUESTED
    }

    /// TLS KeyUpdateRequest `update_requested` constructor.
    pub const fn update_requested() -> Self {
        Self::UPDATE_REQUESTED
    }

    /// Return the preserved raw one-octet value.
    pub const fn raw(self) -> u8 {
        self.raw
    }

    /// Return the source-backed label, preserving unknown values numerically.
    pub fn label(self) -> String {
        match self.raw {
            TLS_KEY_UPDATE_REQUEST_UPDATE_NOT_REQUESTED => "update_not_requested".to_string(),
            TLS_KEY_UPDATE_REQUEST_UPDATE_REQUESTED => "update_requested".to_string(),
            raw => format!("unknown key update request 0x{raw:02x}"),
        }
    }
}

impl From<u8> for TlsKeyUpdateRequest {
    fn from(value: u8) -> Self {
        Self::new(value)
    }
}

impl From<TlsKeyUpdateRequest> for u8 {
    fn from(value: TlsKeyUpdateRequest) -> Self {
        value.raw()
    }
}

impl fmt::Display for TlsKeyUpdateRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// TLS KeyUpdate handshake body fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsKeyUpdate {
    request_update: TlsKeyUpdateRequest,
}

impl TlsKeyUpdate {
    /// Construct a KeyUpdate body.
    pub fn new(request_update: impl Into<TlsKeyUpdateRequest>) -> Self {
        Self {
            request_update: request_update.into(),
        }
    }

    /// Construct a KeyUpdate body from a raw request_update value.
    pub fn from_raw_request_update(request_update: u8) -> Self {
        Self::new(TlsKeyUpdateRequest::from_u8(request_update))
    }

    /// Replace the request_update value.
    pub fn with_request_update(mut self, request_update: impl Into<TlsKeyUpdateRequest>) -> Self {
        self.request_update = request_update.into();
        self
    }

    /// Return the preserved request_update value.
    pub const fn request_update(&self) -> TlsKeyUpdateRequest {
        self.request_update
    }

    /// Number of bytes occupied by the KeyUpdate body.
    pub const fn encoded_len(&self) -> usize {
        TLS_KEY_UPDATE_REQUEST_LEN
    }

    /// Append the KeyUpdate body bytes.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.request_update.raw());
    }

    /// Return the encoded KeyUpdate body bytes.
    pub fn encode_to_vec(&self) -> Vec<u8> {
        vec![self.request_update.raw()]
    }

    /// Compile the KeyUpdate body bytes.
    pub fn compile(&self) -> Vec<u8> {
        self.encode_to_vec()
    }

    /// Decode one complete KeyUpdate body.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (key_update, tail) = Self::decode_prefix(bytes.as_ref())?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.key_update.length",
                "trailing bytes after request_update",
            ));
        }
        Ok(key_update)
    }

    /// Decode one KeyUpdate body from the front of `bytes`.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let mut cursor = 0;
        let request_update = take_bytes(
            bytes,
            &mut cursor,
            TLS_KEY_UPDATE_REQUEST_LEN,
            "tls.key_update.request_update",
        )?[0];
        Ok((
            Self::from_raw_request_update(request_update),
            &bytes[cursor..],
        ))
    }

    /// Stable one-line summary preserving the request_update value.
    pub fn summary(&self) -> String {
        format!("key_update request_update={}", self.request_update.label())
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("request_update", self.request_update.label()),
            (
                "request_update_raw",
                format!("0x{:02x}", self.request_update.raw()),
            ),
        ]
    }
}

impl Default for TlsKeyUpdate {
    fn default() -> Self {
        Self::new(TlsKeyUpdateRequest::update_not_requested())
    }
}

/// TLS EndOfEarlyData handshake body fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TlsEndOfEarlyData;

impl TlsEndOfEarlyData {
    /// Construct an EndOfEarlyData body.
    pub const fn new() -> Self {
        Self
    }

    /// Number of bytes occupied by the EndOfEarlyData body.
    pub const fn encoded_len(&self) -> usize {
        0
    }

    /// Append the EndOfEarlyData body bytes.
    pub fn encode(&self, _out: &mut Vec<u8>) {}

    /// Return the encoded EndOfEarlyData body bytes.
    pub fn encode_to_vec(&self) -> Vec<u8> {
        Vec::new()
    }

    /// Compile the EndOfEarlyData body bytes.
    pub fn compile(&self) -> Vec<u8> {
        self.encode_to_vec()
    }

    /// Decode one complete EndOfEarlyData body.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        if !bytes.as_ref().is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.end_of_early_data.length",
                "body must be empty",
            ));
        }
        Ok(Self)
    }

    /// Stable one-line summary preserving the empty-body contract.
    pub fn summary(&self) -> String {
        "end_of_early_data body_bytes=0".to_string()
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![("body_bytes", "0".to_string())]
    }
}

/// ServerHello handshake body bytes plus an optional decoded view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsServerHelloBody {
    body: Vec<u8>,
    server_hello: Option<TlsServerHello>,
}

impl TlsServerHelloBody {
    /// Preserve ServerHello body bytes without parsing them.
    pub fn raw(body: impl Into<Vec<u8>>) -> Self {
        Self {
            body: body.into(),
            server_hello: None,
        }
    }

    /// Build ServerHello body bytes from typed fields.
    pub fn from_server_hello(server_hello: TlsServerHello) -> Result<Self> {
        let body = server_hello.encode_to_vec()?;
        Ok(Self {
            body,
            server_hello: Some(server_hello),
        })
    }

    /// Decode and preserve exact ServerHello body bytes.
    pub fn from_decoded_body(body: impl Into<Vec<u8>>) -> Result<Self> {
        let body = body.into();
        let server_hello = TlsServerHello::decode(&body)?;
        Ok(Self {
            body,
            server_hello: Some(server_hello),
        })
    }

    /// Borrow the preserved body bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Consume the wrapper and return the preserved body bytes.
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }

    /// Borrow the decoded ServerHello fields when available.
    pub const fn server_hello(&self) -> Option<&TlsServerHello> {
        self.server_hello.as_ref()
    }

    /// Return true when the body carries decoded ServerHello fields.
    pub const fn is_typed(&self) -> bool {
        self.server_hello.is_some()
    }

    /// Number of preserved body bytes.
    pub fn body_len(&self) -> usize {
        self.body.len()
    }
}

/// EncryptedExtensions handshake body bytes plus an optional decoded view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsEncryptedExtensionsBody {
    body: Vec<u8>,
    encrypted_extensions: Option<TlsEncryptedExtensions>,
}

impl TlsEncryptedExtensionsBody {
    /// Preserve EncryptedExtensions body bytes without parsing them.
    pub fn raw(body: impl Into<Vec<u8>>) -> Self {
        Self {
            body: body.into(),
            encrypted_extensions: None,
        }
    }

    /// Build EncryptedExtensions body bytes from typed fields.
    pub fn from_encrypted_extensions(encrypted_extensions: TlsEncryptedExtensions) -> Result<Self> {
        let body = encrypted_extensions.encode_to_vec()?;
        Ok(Self {
            body,
            encrypted_extensions: Some(encrypted_extensions),
        })
    }

    /// Decode and preserve exact EncryptedExtensions body bytes.
    pub fn from_decoded_body(body: impl Into<Vec<u8>>) -> Result<Self> {
        let body = body.into();
        let encrypted_extensions = TlsEncryptedExtensions::decode(&body)?;
        Ok(Self {
            body,
            encrypted_extensions: Some(encrypted_extensions),
        })
    }

    /// Borrow the preserved body bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Consume the wrapper and return the preserved body bytes.
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }

    /// Borrow the decoded EncryptedExtensions fields when available.
    pub const fn encrypted_extensions(&self) -> Option<&TlsEncryptedExtensions> {
        self.encrypted_extensions.as_ref()
    }

    /// Return true when the body carries decoded EncryptedExtensions fields.
    pub const fn is_typed(&self) -> bool {
        self.encrypted_extensions.is_some()
    }

    /// Number of preserved body bytes.
    pub fn body_len(&self) -> usize {
        self.body.len()
    }
}

/// Certificate handshake body bytes plus an optional decoded view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsCertificateBody {
    body: Vec<u8>,
    certificate: Option<TlsCertificate>,
}

impl TlsCertificateBody {
    /// Preserve Certificate body bytes without parsing them.
    pub fn raw(body: impl Into<Vec<u8>>) -> Self {
        Self {
            body: body.into(),
            certificate: None,
        }
    }

    /// Build Certificate body bytes from typed fields.
    pub fn from_certificate(certificate: TlsCertificate) -> Result<Self> {
        let body = certificate.encode_to_vec()?;
        Ok(Self {
            body,
            certificate: Some(certificate),
        })
    }

    /// Decode and preserve exact Certificate body bytes.
    pub fn from_decoded_body(body: impl Into<Vec<u8>>) -> Result<Self> {
        let body = body.into();
        let certificate = TlsCertificate::decode(&body)?;
        Ok(Self {
            body,
            certificate: Some(certificate),
        })
    }

    /// Borrow the preserved body bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Consume the wrapper and return the preserved body bytes.
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }

    /// Borrow the decoded Certificate fields when available.
    pub const fn certificate(&self) -> Option<&TlsCertificate> {
        self.certificate.as_ref()
    }

    /// Return true when the body carries decoded Certificate fields.
    pub const fn is_typed(&self) -> bool {
        self.certificate.is_some()
    }

    /// Number of preserved body bytes.
    pub fn body_len(&self) -> usize {
        self.body.len()
    }
}

/// CertificateRequest handshake body bytes plus an optional decoded view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsCertificateRequestBody {
    body: Vec<u8>,
    certificate_request: Option<TlsCertificateRequest>,
}

impl TlsCertificateRequestBody {
    /// Preserve CertificateRequest body bytes without parsing them.
    pub fn raw(body: impl Into<Vec<u8>>) -> Self {
        Self {
            body: body.into(),
            certificate_request: None,
        }
    }

    /// Build CertificateRequest body bytes from typed fields.
    pub fn from_certificate_request(certificate_request: TlsCertificateRequest) -> Result<Self> {
        let body = certificate_request.encode_to_vec()?;
        Ok(Self {
            body,
            certificate_request: Some(certificate_request),
        })
    }

    /// Decode and preserve exact CertificateRequest body bytes.
    pub fn from_decoded_body(body: impl Into<Vec<u8>>) -> Result<Self> {
        let body = body.into();
        let certificate_request = TlsCertificateRequest::decode(&body)?;
        Ok(Self {
            body,
            certificate_request: Some(certificate_request),
        })
    }

    /// Borrow the preserved body bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Consume the wrapper and return the preserved body bytes.
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }

    /// Borrow the decoded CertificateRequest fields when available.
    pub const fn certificate_request(&self) -> Option<&TlsCertificateRequest> {
        self.certificate_request.as_ref()
    }

    /// Return true when the body carries decoded CertificateRequest fields.
    pub const fn is_typed(&self) -> bool {
        self.certificate_request.is_some()
    }

    /// Number of preserved body bytes.
    pub fn body_len(&self) -> usize {
        self.body.len()
    }
}

/// CertificateVerify handshake body bytes plus an optional decoded view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsCertificateVerifyBody {
    body: Vec<u8>,
    certificate_verify: Option<TlsCertificateVerify>,
}

impl TlsCertificateVerifyBody {
    /// Preserve CertificateVerify body bytes without parsing them.
    pub fn raw(body: impl Into<Vec<u8>>) -> Self {
        Self {
            body: body.into(),
            certificate_verify: None,
        }
    }

    /// Build CertificateVerify body bytes from typed fields.
    pub fn from_certificate_verify(certificate_verify: TlsCertificateVerify) -> Result<Self> {
        let body = certificate_verify.encode_to_vec()?;
        Ok(Self {
            body,
            certificate_verify: Some(certificate_verify),
        })
    }

    /// Decode and preserve exact CertificateVerify body bytes.
    pub fn from_decoded_body(body: impl Into<Vec<u8>>) -> Result<Self> {
        let body = body.into();
        let certificate_verify = TlsCertificateVerify::decode(&body)?;
        Ok(Self {
            body,
            certificate_verify: Some(certificate_verify),
        })
    }

    /// Borrow the preserved body bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Consume the wrapper and return the preserved body bytes.
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }

    /// Borrow the decoded CertificateVerify fields when available.
    pub const fn certificate_verify(&self) -> Option<&TlsCertificateVerify> {
        self.certificate_verify.as_ref()
    }

    /// Return true when the body carries decoded CertificateVerify fields.
    pub const fn is_typed(&self) -> bool {
        self.certificate_verify.is_some()
    }

    /// Number of preserved body bytes.
    pub fn body_len(&self) -> usize {
        self.body.len()
    }
}

/// Finished handshake body bytes plus an optional decoded view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsFinishedBody {
    body: Vec<u8>,
    finished: Option<TlsFinished>,
}

impl TlsFinishedBody {
    /// Preserve Finished body bytes without parsing them.
    pub fn raw(body: impl Into<Vec<u8>>) -> Self {
        Self {
            body: body.into(),
            finished: None,
        }
    }

    /// Build Finished body bytes from typed fields.
    pub fn from_finished(finished: TlsFinished) -> Result<Self> {
        let body = finished.encode_to_vec()?;
        Ok(Self {
            body,
            finished: Some(finished),
        })
    }

    /// Decode and preserve exact Finished body bytes.
    pub fn from_decoded_body(body: impl Into<Vec<u8>>) -> Result<Self> {
        let body = body.into();
        let finished = TlsFinished::decode(&body)?;
        Ok(Self {
            body,
            finished: Some(finished),
        })
    }

    /// Borrow the preserved body bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Consume the wrapper and return the preserved body bytes.
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }

    /// Borrow the decoded Finished fields when available.
    pub const fn finished(&self) -> Option<&TlsFinished> {
        self.finished.as_ref()
    }

    /// Return true when the body carries decoded Finished fields.
    pub const fn is_typed(&self) -> bool {
        self.finished.is_some()
    }

    /// Number of preserved body bytes.
    pub fn body_len(&self) -> usize {
        self.body.len()
    }
}

/// NewSessionTicket handshake body bytes plus an optional decoded view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsNewSessionTicketBody {
    body: Vec<u8>,
    new_session_ticket: Option<TlsNewSessionTicket>,
}

impl TlsNewSessionTicketBody {
    /// Preserve NewSessionTicket body bytes without parsing them.
    pub fn raw(body: impl Into<Vec<u8>>) -> Self {
        Self {
            body: body.into(),
            new_session_ticket: None,
        }
    }

    /// Build NewSessionTicket body bytes from typed fields.
    pub fn from_new_session_ticket(new_session_ticket: TlsNewSessionTicket) -> Result<Self> {
        let body = new_session_ticket.encode_to_vec()?;
        Ok(Self {
            body,
            new_session_ticket: Some(new_session_ticket),
        })
    }

    /// Decode and preserve exact NewSessionTicket body bytes.
    pub fn from_decoded_body(body: impl Into<Vec<u8>>) -> Result<Self> {
        let body = body.into();
        let new_session_ticket = TlsNewSessionTicket::decode(&body)?;
        Ok(Self {
            body,
            new_session_ticket: Some(new_session_ticket),
        })
    }

    /// Borrow the preserved body bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Consume the wrapper and return the preserved body bytes.
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }

    /// Borrow the decoded NewSessionTicket fields when available.
    pub const fn new_session_ticket(&self) -> Option<&TlsNewSessionTicket> {
        self.new_session_ticket.as_ref()
    }

    /// Return true when the body carries decoded NewSessionTicket fields.
    pub const fn is_typed(&self) -> bool {
        self.new_session_ticket.is_some()
    }

    /// Number of preserved body bytes.
    pub fn body_len(&self) -> usize {
        self.body.len()
    }
}

/// EndOfEarlyData handshake body bytes plus an optional decoded view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsEndOfEarlyDataBody {
    body: Vec<u8>,
    end_of_early_data: Option<TlsEndOfEarlyData>,
}

impl TlsEndOfEarlyDataBody {
    /// Preserve EndOfEarlyData body bytes without parsing them.
    pub fn raw(body: impl Into<Vec<u8>>) -> Self {
        Self {
            body: body.into(),
            end_of_early_data: None,
        }
    }

    /// Build EndOfEarlyData body bytes from typed fields.
    pub fn from_end_of_early_data(end_of_early_data: TlsEndOfEarlyData) -> Result<Self> {
        let body = end_of_early_data.encode_to_vec();
        Ok(Self {
            body,
            end_of_early_data: Some(end_of_early_data),
        })
    }

    /// Decode and preserve exact EndOfEarlyData body bytes.
    pub fn from_decoded_body(body: impl Into<Vec<u8>>) -> Result<Self> {
        let body = body.into();
        let end_of_early_data = TlsEndOfEarlyData::decode(&body)?;
        Ok(Self {
            body,
            end_of_early_data: Some(end_of_early_data),
        })
    }

    /// Borrow the preserved body bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Consume the wrapper and return the preserved body bytes.
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }

    /// Borrow the decoded EndOfEarlyData fields when available.
    pub const fn end_of_early_data(&self) -> Option<&TlsEndOfEarlyData> {
        self.end_of_early_data.as_ref()
    }

    /// Return true when the body carries decoded EndOfEarlyData fields.
    pub const fn is_typed(&self) -> bool {
        self.end_of_early_data.is_some()
    }

    /// Number of preserved body bytes.
    pub fn body_len(&self) -> usize {
        self.body.len()
    }
}

/// KeyUpdate handshake body bytes plus an optional decoded view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsKeyUpdateBody {
    body: Vec<u8>,
    key_update: Option<TlsKeyUpdate>,
}

impl TlsKeyUpdateBody {
    /// Preserve KeyUpdate body bytes without parsing them.
    pub fn raw(body: impl Into<Vec<u8>>) -> Self {
        Self {
            body: body.into(),
            key_update: None,
        }
    }

    /// Build KeyUpdate body bytes from typed fields.
    pub fn from_key_update(key_update: TlsKeyUpdate) -> Result<Self> {
        let body = key_update.encode_to_vec();
        Ok(Self {
            body,
            key_update: Some(key_update),
        })
    }

    /// Decode and preserve exact KeyUpdate body bytes.
    pub fn from_decoded_body(body: impl Into<Vec<u8>>) -> Result<Self> {
        let body = body.into();
        let key_update = TlsKeyUpdate::decode(&body)?;
        Ok(Self {
            body,
            key_update: Some(key_update),
        })
    }

    /// Borrow the preserved body bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Consume the wrapper and return the preserved body bytes.
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }

    /// Borrow the decoded KeyUpdate fields when available.
    pub const fn key_update(&self) -> Option<&TlsKeyUpdate> {
        self.key_update.as_ref()
    }

    /// Return true when the body carries decoded KeyUpdate fields.
    pub const fn is_typed(&self) -> bool {
        self.key_update.is_some()
    }

    /// Number of preserved body bytes.
    pub fn body_len(&self) -> usize {
        self.body.len()
    }
}

/// ClientHello handshake body bytes plus an optional decoded view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsClientHelloBody {
    body: Vec<u8>,
    client_hello: Option<TlsClientHello>,
}

impl TlsClientHelloBody {
    /// Preserve ClientHello body bytes without parsing them.
    pub fn raw(body: impl Into<Vec<u8>>) -> Self {
        Self {
            body: body.into(),
            client_hello: None,
        }
    }

    /// Build ClientHello body bytes from typed fields.
    pub fn from_client_hello(client_hello: TlsClientHello) -> Result<Self> {
        let body = client_hello.encode_to_vec()?;
        Ok(Self {
            body,
            client_hello: Some(client_hello),
        })
    }

    /// Decode and preserve exact ClientHello body bytes.
    pub fn from_decoded_body(body: impl Into<Vec<u8>>) -> Result<Self> {
        let body = body.into();
        let client_hello = TlsClientHello::decode(&body)?;
        Ok(Self {
            body,
            client_hello: Some(client_hello),
        })
    }

    /// Borrow the preserved body bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Consume the wrapper and return the preserved body bytes.
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }

    /// Borrow the decoded ClientHello fields when available.
    pub const fn client_hello(&self) -> Option<&TlsClientHello> {
        self.client_hello.as_ref()
    }

    /// Return true when the body carries decoded ClientHello fields.
    pub const fn is_typed(&self) -> bool {
        self.client_hello.is_some()
    }

    /// Number of preserved body bytes.
    pub fn body_len(&self) -> usize {
        self.body.len()
    }
}

fn checked_add_len(lhs: usize, rhs: usize, field: &'static str) -> Result<usize> {
    lhs.checked_add(rhs)
        .ok_or_else(|| CrafterError::invalid_field_value(field, "length overflow"))
}

fn validate_u8_vector_len(len: usize, field: &'static str) -> Result<usize> {
    if len > u8::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            field,
            "length must fit in one byte",
        ));
    }

    Ok(len)
}

fn validate_u16_vector_len(len: usize, field: &'static str) -> Result<usize> {
    if len > u16::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            field,
            "length must fit in two bytes",
        ));
    }

    Ok(len)
}

fn validate_u24_vector_len(len: usize, field: &'static str) -> Result<usize> {
    if len > TLS_HANDSHAKE_MAX_LENGTH as usize {
        return Err(CrafterError::invalid_field_value(
            field,
            "length must fit in three bytes",
        ));
    }

    Ok(len)
}

fn encode_u8_vector(body: &[u8], length_context: &'static str, out: &mut Vec<u8>) -> Result<()> {
    let len = validate_u8_vector_len(body.len(), length_context)?;
    out.push(len as u8);
    out.extend_from_slice(body);
    Ok(())
}

fn encode_u16_vector(body: &[u8], length_context: &'static str, out: &mut Vec<u8>) -> Result<()> {
    let len = validate_u16_vector_len(body.len(), length_context)? as u16;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    Ok(())
}

fn encode_u24_vector(body: &[u8], length_context: &'static str, out: &mut Vec<u8>) -> Result<()> {
    let len = validate_u24_vector_len(body.len(), length_context)? as u32;
    out.extend_from_slice(&u24_to_be_bytes(len)?);
    out.extend_from_slice(body);
    Ok(())
}

fn checked_end(bytes: &[u8], cursor: usize, width: usize, context: &'static str) -> Result<usize> {
    let end = cursor
        .checked_add(width)
        .ok_or_else(|| CrafterError::invalid_field_value(context, "cursor overflow"))?;
    if bytes.len() < end {
        return Err(CrafterError::buffer_too_short(context, end, bytes.len()));
    }

    Ok(end)
}

fn take_bytes<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    width: usize,
    context: &'static str,
) -> Result<&'a [u8]> {
    let start = *cursor;
    let end = checked_end(bytes, start, width, context)?;
    *cursor = end;
    Ok(&bytes[start..end])
}

fn decode_u8_vector(
    bytes: &[u8],
    cursor: &mut usize,
    vector_context: &'static str,
    length_context: &'static str,
) -> Result<Vec<u8>> {
    let declared_len = take_bytes(bytes, cursor, 1, length_context)?[0] as usize;
    Ok(take_bytes(bytes, cursor, declared_len, vector_context)?.to_vec())
}

fn decode_u16_vector(
    bytes: &[u8],
    cursor: &mut usize,
    vector_context: &'static str,
    length_context: &'static str,
) -> Result<Vec<u8>> {
    let length = take_bytes(bytes, cursor, 2, length_context)?;
    let declared_len = u16::from_be_bytes([length[0], length[1]]) as usize;
    Ok(take_bytes(bytes, cursor, declared_len, vector_context)?.to_vec())
}

fn decode_u24_vector(
    bytes: &[u8],
    cursor: &mut usize,
    vector_context: &'static str,
    length_context: &'static str,
) -> Result<Vec<u8>> {
    let length = take_bytes(
        bytes,
        cursor,
        TLS_CERTIFICATE_LIST_LENGTH_LEN,
        length_context,
    )?;
    let declared_len = u24_from_be_bytes([length[0], length[1], length[2]]) as usize;
    Ok(take_bytes(bytes, cursor, declared_len, vector_context)?.to_vec())
}

fn decode_cipher_suite_list(bytes: &[u8], cursor: &mut usize) -> Result<TlsCipherSuiteList> {
    let length = take_bytes(bytes, cursor, 2, "tls.client_hello.cipher_suites.length")?;
    let byte_len = u16::from_be_bytes([length[0], length[1]]) as usize;
    let body = take_bytes(bytes, cursor, byte_len, "tls.client_hello.cipher_suites")?;

    if byte_len % TLS_CIPHER_SUITE_LEN != 0 {
        return Err(CrafterError::invalid_field_value(
            "tls.client_hello.cipher_suites.length",
            "cipher suite vector length must be even",
        ));
    }

    let suites = body
        .chunks_exact(TLS_CIPHER_SUITE_LEN)
        .map(|chunk| TlsCipherSuite::from_be_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();

    Ok(TlsCipherSuiteList::new(suites))
}

fn decode_extension_list(
    bytes: &[u8],
    cursor: &mut usize,
    context: TlsExtensionListContext,
) -> Result<Vec<TlsRawExtension>> {
    let start = *cursor;
    let remaining = bytes
        .get(start..)
        .ok_or_else(|| CrafterError::buffer_too_short(context.list(), start, bytes.len()))?;
    let (extensions, _) = TlsExtensions::decode_prefix_with_context(context, remaining)?;
    *cursor = start
        .checked_add(extensions.encoded_len_with_context(context)?)
        .ok_or_else(|| {
            CrafterError::invalid_field_value(context.list_length(), "cursor overflow")
        })?;
    Ok(extensions.into_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FieldState;

    fn tls_client_hello_test_body() -> Vec<u8> {
        TlsClientHello::new()
            .with_random([0x11; TLS_CLIENT_HELLO_RANDOM_LEN])
            .with_session_id([0x01, 0x02])
            .with_raw_cipher_suites([0x1301, 0x0a0a])
            .with_compression_methods([0x00])
            .with_extension(TlsRawExtension::from_raw(0xbeef, [0xde, 0xad]))
            .encode_to_vec()
            .unwrap()
    }

    fn tls_server_hello_test_body() -> Vec<u8> {
        TlsServerHello::new()
            .with_random([0x22; TLS_SERVER_HELLO_RANDOM_LEN])
            .with_session_id_echo([0x01, 0x02])
            .with_raw_cipher_suite(0x0a0a)
            .with_compression_method(0xff)
            .with_extension(TlsRawExtension::from_raw(0xbeef, [0xde, 0xad]))
            .encode_to_vec()
            .unwrap()
    }

    fn tls_handshake_fixture(handshake_type: u8, body: &[u8]) -> Vec<u8> {
        let len = body.len() as u32;
        let mut out = vec![
            handshake_type,
            ((len >> 16) & 0xff) as u8,
            ((len >> 8) & 0xff) as u8,
            (len & 0xff) as u8,
        ];
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn tls_handshake_message_unknown_type_preserves_opaque_body_and_tail() -> Result<()> {
        let bytes = [0x12, 0x00, 0x00, 0x03, 0xde, 0xad, 0xbe, 0xaa];

        let (message, tail) = TlsHandshake::decode_prefix(&bytes)?;
        let (message_with_consumed, consumed) = TlsHandshake::decode_with_consumed(&bytes)?;

        assert_eq!(tail, &[0xaa]);
        assert_eq!(consumed, TLS_HANDSHAKE_HEADER_LEN + 3);
        assert_eq!(message_with_consumed, message);
        assert_eq!(message.handshake_type(), TlsHandshakeType::from_u8(0x12));
        assert_eq!(message.raw_handshake_type(), 0x12);
        assert_eq!(message.declared_length(), Some(3));
        assert_eq!(message.declared_length_state(), FieldState::User);
        assert_eq!(message.body_bytes(), &[0xde, 0xad, 0xbe]);
        assert!(message.body().is_opaque());
        assert_eq!(
            message.encode_to_vec()?,
            vec![0x12, 0x00, 0x00, 0x03, 0xde, 0xad, 0xbe]
        );
        assert_eq!(
            message.summary(),
            "handshake handshake_type=unassigned handshake type 0x12 declared_length=3 body_bytes=3 body=opaque raw_body_bytes=3"
        );

        let fields = message.inspection_fields();
        assert!(fields.contains(&(
            "handshake_type",
            "unassigned handshake type 0x12".to_string()
        )));
        assert!(fields.contains(&("handshake_type_raw", "0x12".to_string())));
        assert!(fields.contains(&("body", "opaque".to_string())));
        assert!(fields.contains(&("body_bytes", "3".to_string())));
        assert!(fields.contains(&("message_bytes", "7".to_string())));

        Ok(())
    }

    #[test]
    fn tls_handshake_message_known_type_uses_client_hello_body_hook() -> Result<()> {
        let body = tls_client_hello_test_body();
        let bytes = tls_handshake_fixture(0x01, &body);
        let message = TlsHandshake::decode(&bytes)?;

        assert_eq!(message.handshake_type(), TlsHandshakeType::CLIENT_HELLO);
        assert_eq!(
            message.body().handshake_type_hint(),
            Some(TlsHandshakeType::CLIENT_HELLO)
        );
        assert!(message.body().is_known_hook());
        assert!(message.body().is_typed_client_hello());
        assert!(matches!(message.body(), TlsHandshakeBody::ClientHello(_)));
        assert_eq!(message.body_bytes(), body.as_slice());
        assert_eq!(message.client_hello_body().unwrap().session_id(), &[1, 2]);
        assert_eq!(message.encode_to_vec()?, bytes);

        let built = TlsHandshake::client_hello([0xca, 0xfe]);
        assert_eq!(built.declared_length(), None);
        assert_eq!(built.effective_length()?, 2);
        assert_eq!(
            built.encode_to_vec()?,
            vec![0x01, 0x00, 0x00, 0x02, 0xca, 0xfe]
        );
        assert_eq!(
            built.summary(),
            "handshake handshake_type=client_hello declared_length=auto body_bytes=2 body=client_hello raw_body_bytes=2"
        );

        Ok(())
    }

    #[test]
    fn tls_client_hello_builds_and_encodes_core_fields() -> Result<()> {
        let random = [0x42; TLS_CLIENT_HELLO_RANDOM_LEN];
        let hello = TlsClientHello::new()
            .with_raw_legacy_version(0x7a7a)
            .with_random(random)
            .with_session_id([0x01, 0x02, 0x03])
            .with_raw_cipher_suites([0x1301, 0x0a0a])
            .with_compression_methods([0x00, 0xff])
            .with_extension(TlsRawExtension::from_raw(0xbeef, [0xde, 0xad, 0xfa, 0xce]));

        let encoded = hello.encode_to_vec()?;
        let mut expected = vec![0x7a, 0x7a];
        expected.extend_from_slice(&random);
        expected.extend_from_slice(&[
            0x03, 0x01, 0x02, 0x03, 0x00, 0x04, 0x13, 0x01, 0x0a, 0x0a, 0x02, 0x00, 0xff, 0x00,
            0x08, 0xbe, 0xef, 0x00, 0x04, 0xde, 0xad, 0xfa, 0xce,
        ]);

        assert_eq!(encoded, expected);
        assert_eq!(hello.encoded_len()?, encoded.len());
        assert_eq!(
            hello.summary(),
            "client_hello legacy_version=reserved grease protocol version 0x7a7a session_id_bytes=3 cipher_suites=2 compression_methods=2 extensions=1 extensions_present=true"
        );

        let handshake = TlsHandshake::from_client_hello(hello.clone())?;
        assert_eq!(handshake.client_hello_body(), Some(&hello));
        assert_eq!(handshake.body_bytes(), encoded.as_slice());
        assert_eq!(handshake.effective_length()?, encoded.len() as u32);
        assert_eq!(
            handshake.encode_to_vec()?,
            tls_handshake_fixture(TlsHandshakeType::CLIENT_HELLO.raw(), &encoded)
        );

        Ok(())
    }

    #[test]
    fn tls_client_hello_decodes_core_fields_and_unknown_extensions() -> Result<()> {
        let body = tls_client_hello_test_body();
        let with_tail = [body.as_slice(), &[0xaa, 0xbb][..]].concat();
        let (decoded, tail) = TlsClientHello::decode_prefix(&with_tail)?;

        assert_eq!(tail, &[0xaa, 0xbb]);
        assert_eq!(decoded.legacy_version(), TlsVersion::legacy_hello());
        assert_eq!(decoded.random(), &[0x11; TLS_CLIENT_HELLO_RANDOM_LEN]);
        assert_eq!(decoded.session_id(), &[0x01, 0x02]);
        assert_eq!(decoded.cipher_suites().raw_values(), vec![0x1301, 0x0a0a]);
        assert_eq!(decoded.compression_methods(), &[0x00]);
        assert!(decoded.extensions_present());
        assert_eq!(decoded.extensions().len(), 1);
        assert_eq!(decoded.extensions()[0].raw_type(), 0xbeef);
        assert_eq!(decoded.extensions()[0].body(), &[0xde, 0xad]);
        assert_eq!(decoded.encode_to_vec()?, body);

        Ok(())
    }

    #[test]
    fn tls_client_hello_byte_exact_round_trips_through_handshake() -> Result<()> {
        let body = tls_client_hello_test_body();
        let bytes = tls_handshake_fixture(0x01, &body);

        let message = TlsHandshake::decode(&bytes)?;

        assert!(message.client_hello_body().is_some());
        assert_eq!(message.body_bytes(), body.as_slice());
        assert_eq!(message.encode_to_vec()?, bytes);
        assert_eq!(message.compile()?, bytes);

        Ok(())
    }

    #[test]
    fn tls_client_hello_preserves_absent_extension_list() -> Result<()> {
        let hello = TlsClientHello::new()
            .with_random([0x55; TLS_CLIENT_HELLO_RANDOM_LEN])
            .with_raw_cipher_suites([0x1301])
            .with_compression_methods([0x00])
            .without_extensions();
        let encoded = hello.encode_to_vec()?;

        assert_eq!(
            &encoded[TLS_CLIENT_HELLO_FIXED_LEN..],
            &[0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00][..]
        );

        let decoded = TlsClientHello::decode(&encoded)?;
        assert!(!decoded.extensions_present());
        assert!(decoded.extensions().is_empty());
        assert_eq!(decoded.encode_to_vec()?, encoded);

        Ok(())
    }

    #[test]
    fn tls_hello_fields_client_random_session_and_compression_helpers() -> Result<()> {
        let random = [0xab; TLS_CLIENT_HELLO_RANDOM_LEN];
        let hello = TlsClientHello::fixed_random(random)
            .with_empty_session_id()
            .with_raw_cipher_suites([0x1301])
            .with_null_compression()
            .without_extensions();

        assert_eq!(hello.random(), &random);
        assert_eq!(hello.random().len(), TLS_CLIENT_HELLO_RANDOM_LEN);
        assert!(hello.session_id().is_empty());
        assert_eq!(hello.compression_methods(), &[TLS_COMPRESSION_METHOD_NULL]);
        assert_eq!(
            hello.summary(),
            "client_hello legacy_version=TLS 1.2 session_id_bytes=0 cipher_suites=1 compression_methods=1 extensions=0 extensions_present=false"
        );

        let fields = hello.inspection_fields();
        assert!(fields.contains(&("random", hex_bytes(&random))));
        assert!(fields.contains(&("random_bytes", "32".to_string())));
        assert!(fields.contains(&("session_id", String::new())));
        assert!(fields.contains(&("session_id_bytes", "0".to_string())));
        assert!(fields.contains(&("compression_methods", "00".to_string())));
        assert!(fields.contains(&("compression_methods_count", "1".to_string())));

        let encoded = hello.encode_to_vec()?;
        assert_eq!(&encoded[2..TLS_CLIENT_HELLO_FIXED_LEN], random.as_slice());
        assert_eq!(
            &encoded[TLS_CLIENT_HELLO_FIXED_LEN..],
            &[0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00][..]
        );

        let explicit = TlsClientHello::new()
            .with_fixed_random(random)
            .with_explicit_session_id([0x01, 0x02, 0x03])
            .with_raw_cipher_suites([0x1301])
            .with_raw_compression_methods([0x00, 0xff]);
        assert_eq!(explicit.random(), &random);
        assert_eq!(explicit.session_id(), &[0x01, 0x02, 0x03]);
        assert_eq!(explicit.compression_methods(), &[0x00, 0xff]);

        let appended = TlsClientHello::new()
            .with_null_compression()
            .with_raw_compression_method(0xff);
        assert_eq!(appended.compression_methods(), &[0x00, 0xff]);

        Ok(())
    }

    #[test]
    fn tls_hello_fields_server_random_session_echo_and_compression_helpers() -> Result<()> {
        let client = TlsClientHello::new().with_explicit_session_id([0xaa, 0xbb]);
        let random = [0xcd; TLS_SERVER_HELLO_RANDOM_LEN];
        let hello = TlsServerHello::fixed_random(random)
            .with_session_id_echo_from_client(&client)
            .with_raw_cipher_suite(0x1301)
            .with_null_compression();

        assert_eq!(hello.random(), &random);
        assert_eq!(hello.random().len(), TLS_SERVER_HELLO_RANDOM_LEN);
        assert_eq!(hello.session_id_echo(), &[0xaa, 0xbb]);
        assert_eq!(hello.session_id(), &[0xaa, 0xbb]);
        assert_eq!(hello.compression_method(), TLS_COMPRESSION_METHOD_NULL);
        assert_eq!(
            hello.summary(),
            "server_hello form=server_hello legacy_version=TLS 1.2 session_id_echo_bytes=2 cipher_suite=TLS_AES_128_GCM_SHA256 compression_method=0x00 extensions=0"
        );

        let fields = hello.inspection_fields();
        assert!(fields.contains(&("form", "server_hello".to_string())));
        assert!(fields.contains(&("hello_retry_request", "false".to_string())));
        assert!(fields.contains(&("random", hex_bytes(&random))));
        assert!(fields.contains(&("random_bytes", "32".to_string())));
        assert!(fields.contains(&("session_id_echo", "aa bb".to_string())));
        assert!(fields.contains(&("session_id_echo_bytes", "2".to_string())));
        assert!(fields.contains(&("compression_method", "0x00".to_string())));

        let explicit = TlsServerHello::new()
            .with_fixed_random(random)
            .with_empty_session_id_echo()
            .with_explicit_session_id_echo([0x01, 0x02, 0x03])
            .with_raw_compression_method(0xff);
        assert_eq!(explicit.random(), &random);
        assert_eq!(explicit.session_id_echo(), &[0x01, 0x02, 0x03]);
        assert_eq!(explicit.compression_method(), 0xff);

        Ok(())
    }

    #[test]
    fn tls_hello_fields_oversized_u8_vectors_are_rejected_late() {
        let oversized = vec![0xaa; u8::MAX as usize + 1];

        assert_eq!(
            TlsClientHello::new()
                .with_explicit_session_id(oversized.clone())
                .encoded_len()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.client_hello.session_id.length",
                "length must fit in one byte",
            )
        );
        assert_eq!(
            TlsClientHello::new()
                .with_raw_compression_methods(oversized.clone())
                .encoded_len()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.client_hello.compression_methods.length",
                "length must fit in one byte",
            )
        );
        assert_eq!(
            TlsServerHello::new()
                .with_explicit_session_id_echo(oversized)
                .encoded_len()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.server_hello.session_id_echo.length",
                "length must fit in one byte",
            )
        );
    }

    #[test]
    fn tls_client_hello_decode_reports_structured_errors() {
        assert_eq!(
            TlsClientHello::decode([]).unwrap_err(),
            CrafterError::buffer_too_short("tls.client_hello.legacy_version", 2, 0)
        );
        assert_eq!(
            TlsClientHello::decode([0x03]).unwrap_err(),
            CrafterError::buffer_too_short("tls.client_hello.legacy_version", 2, 1)
        );

        let mut missing_session_len = vec![0x03, 0x03];
        missing_session_len.extend_from_slice(&[0; TLS_CLIENT_HELLO_RANDOM_LEN]);
        assert_eq!(
            TlsClientHello::decode(&missing_session_len).unwrap_err(),
            CrafterError::buffer_too_short("tls.client_hello.session_id.length", 35, 34)
        );

        let mut truncated_session_id = missing_session_len.clone();
        truncated_session_id.extend_from_slice(&[0x02, 0xaa]);
        assert_eq!(
            TlsClientHello::decode(&truncated_session_id).unwrap_err(),
            CrafterError::buffer_too_short("tls.client_hello.session_id", 37, 36)
        );

        let mut odd_cipher_suites = missing_session_len.clone();
        odd_cipher_suites.extend_from_slice(&[0x00, 0x00, 0x03, 0x13, 0x01, 0xaa]);
        assert_eq!(
            TlsClientHello::decode(&odd_cipher_suites).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.client_hello.cipher_suites.length",
                "cipher suite vector length must be even"
            )
        );

        let mut truncated_extensions_len = missing_session_len;
        truncated_extensions_len.extend_from_slice(&[
            0x00, // session_id
            0x00, 0x00, // cipher_suites
            0x01, 0x00, // compression_methods
            0x00,
        ]);
        assert_eq!(
            TlsClientHello::decode(&truncated_extensions_len).unwrap_err(),
            CrafterError::buffer_too_short("tls.client_hello.extensions.length", 2, 1)
        );
    }

    #[test]
    fn tls_server_hello_builds_and_encodes_core_fields() -> Result<()> {
        let random = [0x42; TLS_SERVER_HELLO_RANDOM_LEN];
        let hello = TlsServerHello::new()
            .with_raw_legacy_version(0x7a7a)
            .with_random(random)
            .with_session_id_echo([0x01, 0x02, 0x03])
            .with_raw_cipher_suite(0x0a0a)
            .with_compression_method(0xff)
            .with_extension(TlsRawExtension::from_raw(0xbeef, [0xde, 0xad, 0xfa, 0xce]));

        let encoded = hello.encode_to_vec()?;
        let mut expected = vec![0x7a, 0x7a];
        expected.extend_from_slice(&random);
        expected.extend_from_slice(&[
            0x03, 0x01, 0x02, 0x03, 0x0a, 0x0a, 0xff, 0x00, 0x08, 0xbe, 0xef, 0x00, 0x04, 0xde,
            0xad, 0xfa, 0xce,
        ]);

        assert_eq!(encoded, expected);
        assert_eq!(hello.encoded_len()?, encoded.len());
        assert_eq!(hello.session_id(), &[0x01, 0x02, 0x03]);
        assert_eq!(hello.session_id_echo(), &[0x01, 0x02, 0x03]);
        assert_eq!(hello.raw_cipher_suite(), 0x0a0a);
        assert_eq!(
            hello.summary(),
            "server_hello form=server_hello legacy_version=reserved grease protocol version 0x7a7a session_id_echo_bytes=3 cipher_suite=reserved grease cipher suite 0x0a0a compression_method=0xff extensions=1"
        );

        let handshake = TlsHandshake::from_server_hello(hello.clone())?;
        assert_eq!(handshake.server_hello_body(), Some(&hello));
        assert_eq!(handshake.body_bytes(), encoded.as_slice());
        assert_eq!(handshake.effective_length()?, encoded.len() as u32);
        assert_eq!(
            handshake.encode_to_vec()?,
            tls_handshake_fixture(TlsHandshakeType::SERVER_HELLO.raw(), &encoded)
        );

        Ok(())
    }

    #[test]
    fn tls_hello_retry_request_detects_and_round_trips_as_server_hello() -> Result<()> {
        let hello = TlsServerHello::hello_retry_request()
            .with_session_id_echo([0xaa, 0xbb])
            .with_raw_cipher_suite(0x1301)
            .with_null_compression()
            .with_extension(TlsRawExtension::from_raw(0x0033, [0x00, 0x1d]));
        let encoded = hello.encode_to_vec()?;

        assert!(hello.is_hello_retry_request());
        assert_eq!(hello.form_label(), "hello_retry_request");
        assert_eq!(hello.random(), &TLS_HELLO_RETRY_REQUEST_RANDOM);
        assert_eq!(
            hello.summary(),
            "server_hello form=hello_retry_request legacy_version=TLS 1.2 session_id_echo_bytes=2 cipher_suite=TLS_AES_128_GCM_SHA256 compression_method=0x00 extensions=1"
        );
        assert!(hello
            .inspection_fields()
            .contains(&("hello_retry_request", "true".to_string())));
        assert_eq!(
            &encoded[2..TLS_SERVER_HELLO_FIXED_LEN],
            TLS_HELLO_RETRY_REQUEST_RANDOM.as_slice()
        );

        let decoded = TlsServerHello::decode(&encoded)?;
        assert!(decoded.is_hello_retry_request());
        assert_eq!(decoded, hello);
        assert_eq!(decoded.encode_to_vec()?, encoded);

        let handshake = TlsHandshake::from_server_hello(hello.clone())?;
        let handshake_bytes = tls_handshake_fixture(TlsHandshakeType::SERVER_HELLO.raw(), &encoded);
        assert_eq!(handshake.server_hello_body(), Some(&hello));
        assert_eq!(handshake.encode_to_vec()?, handshake_bytes);

        let decoded_handshake = TlsHandshake::decode(&handshake_bytes)?;
        assert_eq!(decoded_handshake.server_hello_body(), Some(&hello));
        assert_eq!(decoded_handshake.encode_to_vec()?, handshake_bytes);

        Ok(())
    }

    #[test]
    fn tls_hello_retry_request_allows_explicit_random_override() -> Result<()> {
        let random = [0x55; TLS_SERVER_HELLO_RANDOM_LEN];
        let hello = TlsServerHello::hello_retry_request().with_fixed_random(random);
        let encoded = hello.encode_to_vec()?;

        assert!(!hello.is_hello_retry_request());
        assert_eq!(hello.form_label(), "server_hello");
        assert_eq!(hello.random(), &random);
        assert_eq!(&encoded[2..TLS_SERVER_HELLO_FIXED_LEN], random.as_slice());

        let decoded = TlsServerHello::decode(&encoded)?;
        assert!(!decoded.is_hello_retry_request());
        assert_eq!(decoded.random(), &random);

        Ok(())
    }

    #[test]
    fn tls_server_hello_decodes_core_fields_and_unknown_extensions() -> Result<()> {
        let body = tls_server_hello_test_body();
        let with_tail = [body.as_slice(), &[0xaa, 0xbb][..]].concat();
        let (decoded, tail) = TlsServerHello::decode_prefix(&with_tail)?;

        assert_eq!(tail, &[0xaa, 0xbb]);
        assert_eq!(decoded.legacy_version(), TlsVersion::legacy_hello());
        assert_eq!(decoded.random(), &[0x22; TLS_SERVER_HELLO_RANDOM_LEN]);
        assert_eq!(decoded.session_id_echo(), &[0x01, 0x02]);
        assert_eq!(decoded.cipher_suite(), TlsCipherSuite::from_u16(0x0a0a));
        assert_eq!(decoded.compression_method(), 0xff);
        assert_eq!(decoded.extensions().len(), 1);
        assert_eq!(decoded.extensions()[0].raw_type(), 0xbeef);
        assert_eq!(decoded.extensions()[0].body(), &[0xde, 0xad]);
        assert_eq!(decoded.encode_to_vec()?, body);

        Ok(())
    }

    #[test]
    fn tls_server_hello_byte_exact_round_trips_through_handshake() -> Result<()> {
        let body = tls_server_hello_test_body();
        let bytes = tls_handshake_fixture(0x02, &body);

        let message = TlsHandshake::decode(&bytes)?;

        assert!(message.server_hello_body().is_some());
        assert!(message.body().is_typed_server_hello());
        assert_eq!(message.body_bytes(), body.as_slice());
        assert_eq!(message.encode_to_vec()?, bytes);
        assert_eq!(message.compile()?, bytes);

        let raw = TlsHandshake::server_hello([0xca, 0xfe]);
        assert_eq!(raw.body_bytes(), &[0xca, 0xfe]);
        assert!(matches!(raw.body(), TlsHandshakeBody::ServerHello(_)));
        assert!(raw.server_hello_body().is_none());
        assert!(!raw.body().is_typed_server_hello());
        assert_eq!(
            raw.encode_to_vec()?,
            vec![0x02, 0x00, 0x00, 0x02, 0xca, 0xfe]
        );

        Ok(())
    }

    #[test]
    fn tls_encrypted_extensions_empty_list_encodes_decodes_through_handshake() -> Result<()> {
        let encrypted_extensions = TlsEncryptedExtensions::new();
        let encoded = encrypted_extensions.encode_to_vec()?;

        assert!(encrypted_extensions.is_empty());
        assert_eq!(encrypted_extensions.len(), 0);
        assert_eq!(encoded, vec![0x00, 0x00]);
        assert_eq!(encrypted_extensions.encoded_len()?, 2);
        assert_eq!(
            encrypted_extensions.summary(),
            "encrypted_extensions extensions=0 extension_bytes=0 values="
        );

        let fields = encrypted_extensions.inspection_fields();
        assert!(fields.contains(&("extensions_count", "0".to_string())));
        assert!(fields.contains(&("extensions_bytes", "0".to_string())));
        assert!(fields.contains(&("extensions", String::new())));

        let handshake = TlsHandshake::from_encrypted_extensions(encrypted_extensions.clone())?;
        let bytes = tls_handshake_fixture(TlsHandshakeType::ENCRYPTED_EXTENSIONS.raw(), &encoded);

        assert_eq!(handshake.body_bytes(), encoded.as_slice());
        assert_eq!(handshake.effective_length()?, encoded.len() as u32);
        assert_eq!(
            handshake.body().handshake_type_hint(),
            Some(TlsHandshakeType::ENCRYPTED_EXTENSIONS)
        );
        assert!(handshake.body().is_typed_encrypted_extensions());
        assert_eq!(
            handshake.encrypted_extensions_body(),
            Some(&encrypted_extensions)
        );
        assert_eq!(handshake.encode_to_vec()?, bytes);

        let decoded = TlsHandshake::decode(&bytes)?;
        assert!(matches!(
            decoded.body(),
            TlsHandshakeBody::EncryptedExtensions(_)
        ));
        assert!(decoded.body().is_typed_encrypted_extensions());
        assert_eq!(
            decoded.encrypted_extensions_body(),
            Some(&encrypted_extensions)
        );
        assert_eq!(decoded.encode_to_vec()?, bytes);

        Ok(())
    }

    #[test]
    fn tls_encrypted_extensions_populated_list_preserves_unknown_extensions() -> Result<()> {
        let encrypted_extensions = TlsEncryptedExtensions::new()
            .with_raw_extension(0x0010, [0x00, 0x03, 0x02, b'h', b'2'])
            .with_extension(TlsRawExtension::from_raw(0xbeef, [0xde, 0xad]));
        let encoded = encrypted_extensions.encode_to_vec()?;

        assert_eq!(
            encoded,
            vec![
                0x00, 0x0f, // extension list length
                0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, b'h', b'2', 0xbe, 0xef, 0x00, 0x02, 0xde,
                0xad,
            ]
        );
        assert_eq!(encrypted_extensions.len(), 2);
        assert_eq!(encrypted_extensions.raw_extensions()[0].raw_type(), 0x0010);
        assert_eq!(
            encrypted_extensions.raw_extensions()[0].body(),
            &[0x00, 0x03, 0x02, b'h', b'2']
        );
        assert_eq!(encrypted_extensions.raw_extensions()[1].raw_type(), 0xbeef);
        assert_eq!(
            encrypted_extensions.raw_extensions()[1].body(),
            &[0xde, 0xad]
        );
        assert_eq!(
            encrypted_extensions.summary(),
            "encrypted_extensions extensions=2 extension_bytes=15 values=application_layer_protocol_negotiation,unknown extension 0xbeef"
        );

        let decoded = TlsEncryptedExtensions::decode(&encoded)?;
        assert_eq!(decoded, encrypted_extensions);
        assert_eq!(decoded.raw_extensions()[1].raw_type(), 0xbeef);
        assert_eq!(decoded.raw_extensions()[1].body(), &[0xde, 0xad]);
        assert_eq!(decoded.encode_to_vec()?, encoded);
        assert_eq!(decoded.compile()?, encoded);

        let with_tail = [encoded.as_slice(), &[0xaa, 0xbb][..]].concat();
        let (decoded_prefix, tail) = TlsEncryptedExtensions::decode_prefix(&with_tail)?;
        assert_eq!(decoded_prefix, encrypted_extensions);
        assert_eq!(tail, &[0xaa, 0xbb]);

        let handshake = TlsHandshake::from_encrypted_extensions(encrypted_extensions.clone())?;
        let handshake_bytes =
            tls_handshake_fixture(TlsHandshakeType::ENCRYPTED_EXTENSIONS.raw(), &encoded);
        let decoded_handshake = TlsHandshake::decode(&handshake_bytes)?;
        assert_eq!(
            decoded_handshake.encrypted_extensions_body(),
            Some(&encrypted_extensions)
        );
        assert_eq!(handshake.encode_to_vec()?, handshake_bytes);

        Ok(())
    }

    #[test]
    fn tls_encrypted_extensions_raw_body_remains_available() -> Result<()> {
        let raw = TlsHandshake::encrypted_extensions([0xca, 0xfe]);

        assert_eq!(raw.body_bytes(), &[0xca, 0xfe]);
        assert!(matches!(
            raw.body(),
            TlsHandshakeBody::EncryptedExtensions(_)
        ));
        assert!(raw.encrypted_extensions_body().is_none());
        assert!(!raw.body().is_typed_encrypted_extensions());
        assert_eq!(
            raw.encode_to_vec()?,
            vec![0x08, 0x00, 0x00, 0x02, 0xca, 0xfe]
        );
        assert_eq!(
            TlsEncryptedExtensions::decode([0x00]).unwrap_err(),
            CrafterError::buffer_too_short("tls.encrypted_extensions.extensions.length", 2, 1)
        );

        Ok(())
    }

    #[test]
    fn tls_certificate_message_tls12_list_encodes_decodes_through_handshake() -> Result<()> {
        let certificate = TlsCertificate::tls12(vec![
            TlsCertificateEntry::new([0x30, 0x03, 0x01]),
            TlsCertificateEntry::new([0x30, 0x01]),
        ]);
        let encoded = certificate.encode_to_vec()?;

        assert_eq!(
            encoded,
            vec![
                0x00, 0x00, 0x0b, // certificate_list length
                0x00, 0x00, 0x03, 0x30, 0x03, 0x01, // first opaque certificate
                0x00, 0x00, 0x02, 0x30, 0x01, // second opaque certificate
            ]
        );
        assert!(certificate.is_tls12());
        assert!(!certificate.is_tls13());
        assert_eq!(certificate.form(), TlsCertificateForm::Tls12);
        assert_eq!(certificate.request_context(), &[]);
        assert_eq!(certificate.certificate_list().len(), 2);
        assert_eq!(certificate.certificate_bytes(), 5);
        assert_eq!(certificate.entry_extensions_len(), 0);
        assert_eq!(
            certificate.summary(),
            "certificate form=tls12 request_context_bytes=0 certificate_list=2 certificate_bytes=5 entry_extensions=0"
        );

        let decoded = TlsCertificate::decode_tls12(&encoded)?;
        assert_eq!(decoded, certificate);
        assert_eq!(TlsCertificate::decode(&encoded)?, certificate);

        let handshake = TlsHandshake::from_certificate(certificate.clone())?;
        let handshake_bytes = tls_handshake_fixture(TlsHandshakeType::CERTIFICATE.raw(), &encoded);
        assert_eq!(handshake.body_bytes(), encoded.as_slice());
        assert!(handshake.body().is_typed_certificate());
        assert_eq!(handshake.certificate_body(), Some(&certificate));
        assert_eq!(handshake.encode_to_vec()?, handshake_bytes);

        let decoded_handshake = TlsHandshake::decode(&handshake_bytes)?;
        assert_eq!(decoded_handshake.certificate_body(), Some(&certificate));
        assert_eq!(decoded_handshake.encode_to_vec()?, handshake_bytes);

        Ok(())
    }

    #[test]
    fn tls_certificate_message_tls13_preserves_request_context_and_entry_extensions() -> Result<()>
    {
        let certificate = TlsCertificate::tls13(
            [0x01, 0x02],
            vec![
                TlsCertificateEntry::new([0x30, 0x82]).with_raw_extension(0xbeef, [0xaa]),
                TlsCertificateEntry::new([0x04]),
            ],
        );
        let encoded = certificate.encode_to_vec()?;

        assert_eq!(
            encoded,
            vec![
                0x02, 0x01, 0x02, // certificate_request_context
                0x00, 0x00, 0x12, // certificate_list length
                0x00, 0x00, 0x02, 0x30, 0x82, // first opaque certificate
                0x00, 0x05, 0xbe, 0xef, 0x00, 0x01, 0xaa, // first entry extensions
                0x00, 0x00, 0x01, 0x04, // second opaque certificate
                0x00, 0x00, // second entry extensions
            ]
        );
        assert!(certificate.is_tls13());
        assert_eq!(certificate.form(), TlsCertificateForm::Tls13);
        assert_eq!(certificate.request_context(), &[0x01, 0x02]);
        assert_eq!(
            certificate.certificate_list()[0].certificate_data(),
            &[0x30, 0x82]
        );
        assert_eq!(
            certificate.certificate_list()[0].extensions()[0].raw_type(),
            0xbeef
        );
        assert_eq!(
            certificate.certificate_list()[0].extensions()[0].body(),
            &[0xaa]
        );
        assert_eq!(certificate.entry_extensions_len(), 1);
        assert_eq!(
            certificate.inspection_fields(),
            vec![
                ("form", "tls13".to_string()),
                ("request_context", "01 02".to_string()),
                ("request_context_bytes", "2".to_string()),
                ("certificate_list_count", "2".to_string()),
                ("certificate_bytes", "3".to_string()),
                ("entry_extensions_count", "1".to_string()),
            ]
        );

        let decoded = TlsCertificate::decode_tls13(&encoded)?;
        assert_eq!(decoded, certificate);
        assert_eq!(decoded.encode_to_vec()?, encoded);
        assert_eq!(decoded.compile()?, encoded);

        let entry_fields = certificate.certificate_list()[0].inspection_fields();
        assert!(entry_fields.contains(&("certificate", "30 82".to_string())));
        assert!(entry_fields.contains(&("certificate_bytes", "2".to_string())));
        assert_eq!(
            certificate.certificate_list()[0].summary(),
            "certificate_entry certificate_bytes=2 extensions=1"
        );

        Ok(())
    }

    #[test]
    fn tls_certificate_message_raw_body_remains_available() -> Result<()> {
        let raw = TlsHandshake::certificate([0xca, 0xfe]);

        assert_eq!(raw.body_bytes(), &[0xca, 0xfe]);
        assert!(matches!(raw.body(), TlsHandshakeBody::Certificate(_)));
        assert!(raw.certificate_body().is_none());
        assert!(!raw.body().is_typed_certificate());
        assert_eq!(
            raw.encode_to_vec()?,
            vec![0x0b, 0x00, 0x00, 0x02, 0xca, 0xfe]
        );

        Ok(())
    }

    #[test]
    fn tls_certificate_message_decode_reports_structured_vector_errors() {
        assert_eq!(
            TlsCertificate::decode_tls12([0x00, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short("tls.certificate.certificate_list.length", 3, 2)
        );

        let truncated_tls12_entry = [
            0x00, 0x00, 0x04, // certificate_list length
            0x00, 0x00, 0x02, 0xaa, // certificate length says two bytes, body has one
        ];
        assert_eq!(
            TlsCertificate::decode_tls12(truncated_tls12_entry).unwrap_err(),
            CrafterError::buffer_too_short("tls.certificate.certificate", 5, 4)
        );

        let truncated_tls13_entry_extensions = [
            0x00, // empty certificate_request_context
            0x00, 0x00, 0x04, // certificate_list length
            0x00, 0x00, 0x01, 0xaa, // certificate entry without extensions vector
        ];
        assert_eq!(
            TlsCertificate::decode_tls13(truncated_tls13_entry_extensions).unwrap_err(),
            CrafterError::buffer_too_short("tls.certificate_entry.extensions.length", 2, 0)
        );
    }

    #[test]
    fn tls_certificate_request_tls12_vectors_encode_decode_through_handshake() -> Result<()> {
        let authorities =
            TlsCertificateAuthorities::from_raws([&[0x30, 0x03, 0x31][..], &[0xaa][..]]);
        let request = TlsCertificateRequest::tls12(
            vec![
                TlsClientCertificateType::rsa_sign(),
                TlsClientCertificateType::ecdsa_sign(),
                TlsClientCertificateType::from_u8(0xfe),
            ],
            TlsSignatureAlgorithms::from_raws([0x0401, 0x0807]),
            authorities.clone(),
        );
        let encoded = request.encode_to_vec()?;

        assert_eq!(
            encoded,
            vec![
                0x03, 0x01, 0x40, 0xfe, // certificate_types
                0x00, 0x04, 0x04, 0x01, 0x08, 0x07, // signature_algorithms
                0x00, 0x08, 0x00, 0x03, 0x30, 0x03, 0x31, 0x00, 0x01,
                0xaa, // certificate_authorities
            ]
        );
        assert!(request.is_tls12());
        assert_eq!(request.form(), TlsCertificateRequestForm::Tls12);
        assert_eq!(
            request.certificate_type_labels(),
            vec![
                "rsa_sign".to_string(),
                "ecdsa_sign".to_string(),
                "unknown client certificate type 0xfe".to_string(),
            ]
        );
        assert_eq!(
            request.signature_algorithms().raw_values(),
            vec![0x0401, 0x0807]
        );
        assert_eq!(request.certificate_authorities(), &authorities);
        assert_eq!(
            request.summary(),
            "certificate_request form=tls12 certificate_types=3 signature_algorithms=2 certificate_authorities=2 request_context_bytes=0 extensions=0"
        );

        let decoded = TlsCertificateRequest::decode_tls12(&encoded)?;
        assert_eq!(decoded, request);
        assert_eq!(TlsCertificateRequest::decode(&encoded)?, request);

        let handshake = TlsHandshake::from_certificate_request(request.clone())?;
        let handshake_bytes =
            tls_handshake_fixture(TlsHandshakeType::CERTIFICATE_REQUEST.raw(), &encoded);
        assert_eq!(handshake.body_bytes(), encoded.as_slice());
        assert!(handshake.body().is_typed_certificate_request());
        assert_eq!(handshake.certificate_request_body(), Some(&request));
        assert_eq!(handshake.encode_to_vec()?, handshake_bytes);

        let decoded_handshake = TlsHandshake::decode(&handshake_bytes)?;
        assert_eq!(decoded_handshake.certificate_request_body(), Some(&request));
        assert_eq!(decoded_handshake.encode_to_vec()?, handshake_bytes);

        Ok(())
    }

    #[test]
    fn tls_certificate_request_tls13_extensions_preserve_typed_helpers() -> Result<()> {
        let authorities = TlsCertificateAuthorities::from_raws([&[0xde, 0xad][..]]);
        let request = TlsCertificateRequest::new()
            .with_request_context([0x10])
            .with_tls13_signature_algorithms(TlsSignatureAlgorithms::from_raws([0x0807]))?
            .with_tls13_certificate_authorities(authorities.clone())?
            .with_raw_extension(0xbeef, [0xca, 0xfe]);
        let encoded = request.encode_to_vec()?;

        assert_eq!(
            encoded,
            vec![
                0x01, 0x10, // certificate_request_context
                0x00, 0x18, // extensions length
                0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x08, 0x07, // signature_algorithms
                0x00, 0x2f, 0x00, 0x06, 0x00, 0x04, 0x00, 0x02, 0xde,
                0xad, // certificate_authorities
                0xbe, 0xef, 0x00, 0x02, 0xca, 0xfe, // unknown extension
            ]
        );
        assert!(request.is_tls13());
        assert_eq!(request.request_context(), &[0x10]);
        assert_eq!(request.extensions().len(), 3);
        assert_eq!(
            request.extensions()[0].as_signature_algorithms()?,
            TlsSignatureAlgorithms::from_raws([0x0807])
        );
        assert_eq!(
            request.extensions()[1].as_certificate_authorities()?,
            authorities
        );
        assert_eq!(request.extensions()[2].raw_type(), 0xbeef);
        assert_eq!(
            request.inspection_fields(),
            vec![
                ("form", "tls13".to_string()),
                ("certificate_types_count", "0".to_string()),
                ("certificate_types", String::new()),
                ("signature_algorithms_count", "0".to_string()),
                ("certificate_authorities_count", "0".to_string()),
                ("request_context", "10".to_string()),
                ("request_context_bytes", "1".to_string()),
                ("extensions_count", "3".to_string()),
            ]
        );

        let decoded = TlsCertificateRequest::decode_tls13(&encoded)?;
        assert_eq!(decoded, request);
        assert_eq!(decoded.encode_to_vec()?, encoded);
        assert_eq!(decoded.compile()?, encoded);

        Ok(())
    }

    #[test]
    fn tls_certificate_request_raw_body_remains_available() -> Result<()> {
        let raw = TlsHandshake::certificate_request([0xca, 0xfe]);

        assert_eq!(raw.body_bytes(), &[0xca, 0xfe]);
        assert!(matches!(
            raw.body(),
            TlsHandshakeBody::CertificateRequest(_)
        ));
        assert!(raw.certificate_request_body().is_none());
        assert!(!raw.body().is_typed_certificate_request());
        assert_eq!(
            raw.encode_to_vec()?,
            vec![0x0d, 0x00, 0x00, 0x02, 0xca, 0xfe]
        );

        Ok(())
    }

    #[test]
    fn tls_certificate_request_decode_reports_structured_vector_errors() {
        assert_eq!(
            TlsCertificateRequest::decode_tls12([]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.certificate_request.certificate_types.length",
                1,
                0
            )
        );

        assert_eq!(
            TlsCertificateRequest::decode_tls12([0x01, 0x01, 0x00, 0x01, 0x04]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.signature_algorithms.length",
                "length must be at least two bytes"
            )
        );

        let truncated_tls13_extension = [
            0x00, // empty certificate_request_context
            0x00, 0x05, // extensions length
            0xbe, 0xef, // extension type
            0x00, 0x02, // extension body length
            0xaa, // truncated extension body
        ];
        assert_eq!(
            TlsCertificateRequest::decode_tls13(truncated_tls13_extension).unwrap_err(),
            CrafterError::buffer_too_short("tls.certificate_request.extension.body", 6, 5)
        );
    }

    #[test]
    fn tls_certificate_verify_unknown_scheme_encodes_decodes_through_handshake() -> Result<()> {
        let certificate_verify =
            TlsCertificateVerify::from_raw_signature_scheme(0xbeef, [0xde, 0xad, 0xfa]);
        let encoded = certificate_verify.encode_to_vec()?;

        assert_eq!(encoded, vec![0xbe, 0xef, 0x00, 0x03, 0xde, 0xad, 0xfa]);
        assert_eq!(
            certificate_verify.signature_scheme(),
            TlsSignatureScheme::from_u16(0xbeef)
        );
        assert_eq!(certificate_verify.signature(), &[0xde, 0xad, 0xfa]);
        assert_eq!(certificate_verify.signature_len(), 3);
        assert_eq!(
            certificate_verify.summary(),
            "certificate_verify signature_scheme=unknown signature scheme 0xbeef signature_bytes=3"
        );
        assert_eq!(
            certificate_verify.inspection_fields(),
            vec![
                (
                    "signature_scheme",
                    "unknown signature scheme 0xbeef".to_string()
                ),
                ("signature_scheme_raw", "0xbeef".to_string()),
                ("signature", "de ad fa".to_string()),
                ("signature_bytes", "3".to_string()),
            ]
        );

        let decoded = TlsCertificateVerify::decode(&encoded)?;
        assert_eq!(decoded, certificate_verify);
        assert_eq!(decoded.encode_to_vec()?, encoded);
        assert_eq!(decoded.compile()?, encoded);

        let with_tail = [encoded.as_slice(), &[0xaa, 0xbb][..]].concat();
        let (decoded_prefix, tail) = TlsCertificateVerify::decode_prefix(&with_tail)?;
        assert_eq!(decoded_prefix, certificate_verify);
        assert_eq!(tail, &[0xaa, 0xbb]);

        let handshake = TlsHandshake::from_certificate_verify(certificate_verify.clone())?;
        let handshake_bytes =
            tls_handshake_fixture(TlsHandshakeType::CERTIFICATE_VERIFY.raw(), &encoded);
        assert_eq!(handshake.body_bytes(), encoded.as_slice());
        assert!(handshake.body().is_typed_certificate_verify());
        assert_eq!(
            handshake.certificate_verify_body(),
            Some(&certificate_verify)
        );
        assert_eq!(handshake.encode_to_vec()?, handshake_bytes);

        let decoded_handshake = TlsHandshake::decode(&handshake_bytes)?;
        assert_eq!(
            decoded_handshake.certificate_verify_body(),
            Some(&certificate_verify)
        );
        assert_eq!(decoded_handshake.encode_to_vec()?, handshake_bytes);

        Ok(())
    }

    #[test]
    fn tls_certificate_verify_raw_body_remains_available() -> Result<()> {
        let raw = TlsHandshake::certificate_verify([0xca, 0xfe]);

        assert_eq!(raw.body_bytes(), &[0xca, 0xfe]);
        assert!(matches!(raw.body(), TlsHandshakeBody::CertificateVerify(_)));
        assert!(raw.certificate_verify_body().is_none());
        assert!(!raw.body().is_typed_certificate_verify());
        assert_eq!(
            raw.encode_to_vec()?,
            vec![0x0f, 0x00, 0x00, 0x02, 0xca, 0xfe]
        );

        Ok(())
    }

    #[test]
    fn tls_certificate_verify_decode_reports_structured_signature_errors() {
        assert_eq!(
            TlsCertificateVerify::decode([]).unwrap_err(),
            CrafterError::buffer_too_short("tls.certificate_verify.signature_scheme", 2, 0)
        );
        assert_eq!(
            TlsCertificateVerify::decode([0x08, 0x07, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short("tls.certificate_verify.signature.length", 4, 3)
        );
        assert_eq!(
            TlsCertificateVerify::decode([0x08, 0x07, 0x00, 0x02, 0xaa]).unwrap_err(),
            CrafterError::buffer_too_short("tls.certificate_verify.signature", 6, 5)
        );
    }

    #[test]
    fn tls_finished_empty_verify_data_encodes_decodes() -> Result<()> {
        let finished = TlsFinished::empty();
        let encoded = finished.encode_to_vec()?;

        assert!(finished.is_empty());
        assert_eq!(finished.len(), 0);
        assert_eq!(finished.verify_data(), &[]);
        assert_eq!(finished.encoded_len()?, 0);
        assert_eq!(encoded, Vec::<u8>::new());
        assert_eq!(finished.summary(), "finished verify_data_bytes=0");
        assert_eq!(
            finished.inspection_fields(),
            vec![
                ("verify_data", String::new()),
                ("verify_data_bytes", "0".to_string()),
            ]
        );
        assert_eq!(TlsFinished::decode(&encoded)?, finished);

        let handshake = TlsHandshake::from_finished(finished.clone())?;
        let handshake_bytes = tls_handshake_fixture(TlsHandshakeType::FINISHED.raw(), &encoded);
        assert!(handshake.body().is_typed_finished());
        assert_eq!(handshake.finished_body(), Some(&finished));
        assert_eq!(handshake.encode_to_vec()?, handshake_bytes);

        Ok(())
    }

    #[test]
    fn tls_finished_non_empty_verify_data_round_trips_through_handshake() -> Result<()> {
        let finished = TlsFinished::new([0xde, 0xad, 0xbe, 0xef]);
        let encoded = finished.encode_to_vec()?;

        assert_eq!(encoded, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(finished.compile()?, encoded);

        let decoded = TlsFinished::decode(&encoded)?;
        assert_eq!(decoded, finished);

        let handshake = TlsHandshake::from_finished(finished.clone())?;
        let handshake_bytes = tls_handshake_fixture(TlsHandshakeType::FINISHED.raw(), &encoded);
        assert_eq!(handshake.body_bytes(), encoded.as_slice());
        assert_eq!(handshake.finished_body(), Some(&finished));
        assert_eq!(handshake.encode_to_vec()?, handshake_bytes);

        let decoded_handshake = TlsHandshake::decode(&handshake_bytes)?;
        assert_eq!(decoded_handshake.finished_body(), Some(&finished));
        assert_eq!(decoded_handshake.encode_to_vec()?, handshake_bytes);

        Ok(())
    }

    #[test]
    fn tls_finished_raw_body_remains_available() -> Result<()> {
        let raw = TlsHandshake::finished([0xca, 0xfe]);

        assert_eq!(raw.body_bytes(), &[0xca, 0xfe]);
        assert!(matches!(raw.body(), TlsHandshakeBody::Finished(_)));
        assert!(raw.finished_body().is_none());
        assert!(!raw.body().is_typed_finished());
        assert_eq!(
            raw.encode_to_vec()?,
            vec![0x14, 0x00, 0x00, 0x02, 0xca, 0xfe]
        );

        Ok(())
    }

    #[test]
    fn tls_new_session_ticket_tls12_ticket_encodes_decodes_through_handshake() -> Result<()> {
        let ticket = TlsNewSessionTicket::tls12(0x0102_0304, [0xaa, 0xbb]);
        let encoded = ticket.encode_to_vec()?;

        assert_eq!(
            encoded,
            vec![
                0x01, 0x02, 0x03, 0x04, // ticket_lifetime_hint
                0x00, 0x02, 0xaa, 0xbb, // ticket
            ]
        );
        assert!(ticket.is_tls12());
        assert_eq!(ticket.form(), TlsNewSessionTicketForm::Tls12);
        assert_eq!(ticket.ticket_lifetime(), 0x0102_0304);
        assert_eq!(ticket.ticket_age_add(), 0);
        assert_eq!(ticket.ticket_nonce(), &[]);
        assert_eq!(ticket.ticket(), &[0xaa, 0xbb]);
        assert!(ticket.extensions().is_empty());
        assert_eq!(
            ticket.summary(),
            "new_session_ticket form=tls12 lifetime=16909060 age_add=0 nonce_bytes=0 ticket_bytes=2 extensions=0"
        );

        let decoded = TlsNewSessionTicket::decode_tls12(&encoded)?;
        assert_eq!(decoded, ticket);
        assert_eq!(TlsNewSessionTicket::decode(&encoded)?, ticket);

        let handshake = TlsHandshake::from_new_session_ticket(ticket.clone())?;
        let handshake_bytes =
            tls_handshake_fixture(TlsHandshakeType::NEW_SESSION_TICKET.raw(), &encoded);
        assert_eq!(handshake.body_bytes(), encoded.as_slice());
        assert!(handshake.body().is_typed_new_session_ticket());
        assert_eq!(handshake.new_session_ticket_body(), Some(&ticket));
        assert_eq!(handshake.encode_to_vec()?, handshake_bytes);

        let decoded_handshake = TlsHandshake::decode(&handshake_bytes)?;
        assert_eq!(decoded_handshake.new_session_ticket_body(), Some(&ticket));
        assert_eq!(decoded_handshake.encode_to_vec()?, handshake_bytes);

        Ok(())
    }

    #[test]
    fn tls_new_session_ticket_tls13_nonce_ticket_and_unknown_extensions_round_trip() -> Result<()> {
        let ticket = TlsNewSessionTicket::tls13(
            7,
            0x0102_0304,
            [0x09],
            [0xaa, 0xbb, 0xcc],
            vec![TlsRawExtension::from_raw(0xbeef, [0xde])],
        );
        let encoded = ticket.encode_to_vec()?;

        assert_eq!(
            encoded,
            vec![
                0x00, 0x00, 0x00, 0x07, // ticket_lifetime
                0x01, 0x02, 0x03, 0x04, // ticket_age_add
                0x01, 0x09, // ticket_nonce
                0x00, 0x03, 0xaa, 0xbb, 0xcc, // ticket
                0x00, 0x05, 0xbe, 0xef, 0x00, 0x01, 0xde, // extensions
            ]
        );
        assert!(ticket.is_tls13());
        assert_eq!(ticket.form(), TlsNewSessionTicketForm::Tls13);
        assert_eq!(ticket.ticket_lifetime(), 7);
        assert_eq!(ticket.ticket_age_add(), 0x0102_0304);
        assert_eq!(ticket.ticket_nonce(), &[0x09]);
        assert_eq!(ticket.ticket(), &[0xaa, 0xbb, 0xcc]);
        assert_eq!(ticket.extensions()[0].raw_type(), 0xbeef);
        assert_eq!(ticket.extensions()[0].body(), &[0xde]);
        assert_eq!(
            ticket.inspection_fields(),
            vec![
                ("form", "tls13".to_string()),
                ("ticket_lifetime", "7".to_string()),
                ("ticket_age_add", "16909060".to_string()),
                ("ticket_nonce", "09".to_string()),
                ("ticket_nonce_bytes", "1".to_string()),
                ("ticket", "aa bb cc".to_string()),
                ("ticket_bytes", "3".to_string()),
                ("extensions_count", "1".to_string()),
            ]
        );

        let decoded = TlsNewSessionTicket::decode_tls13(&encoded)?;
        assert_eq!(decoded, ticket);
        assert_eq!(decoded.encode_to_vec()?, encoded);
        assert_eq!(decoded.compile()?, encoded);

        Ok(())
    }

    #[test]
    fn tls_new_session_ticket_raw_body_remains_available() -> Result<()> {
        let raw = TlsHandshake::new_session_ticket([0xca, 0xfe]);

        assert_eq!(raw.body_bytes(), &[0xca, 0xfe]);
        assert!(matches!(raw.body(), TlsHandshakeBody::NewSessionTicket(_)));
        assert!(raw.new_session_ticket_body().is_none());
        assert!(!raw.body().is_typed_new_session_ticket());
        assert_eq!(
            raw.encode_to_vec()?,
            vec![0x04, 0x00, 0x00, 0x02, 0xca, 0xfe]
        );

        Ok(())
    }

    #[test]
    fn tls_new_session_ticket_decode_reports_structured_vector_errors() {
        assert_eq!(
            TlsNewSessionTicket::decode_tls13([0x00, 0x00, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short("tls.new_session_ticket.ticket_lifetime", 4, 3)
        );
        assert_eq!(
            TlsNewSessionTicket::decode_tls12([0x00, 0x00, 0x00, 0x01, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short("tls.new_session_ticket.ticket.length", 6, 5)
        );
        assert_eq!(
            TlsNewSessionTicket::decode_tls13([
                0x00, 0x00, 0x00, 0x01, // ticket_lifetime
                0x00, 0x00, 0x00, 0x02, // ticket_age_add
                0x00, // empty nonce
                0x00, 0x02, 0xaa, // truncated ticket
            ])
            .unwrap_err(),
            CrafterError::buffer_too_short("tls.new_session_ticket.ticket", 13, 12)
        );
    }

    #[test]
    fn tls_key_update_end_early_data_key_update_preserves_unknown_request_values() -> Result<()> {
        assert_eq!(TlsKeyUpdateRequest::update_not_requested().raw(), 0);
        assert_eq!(
            TlsKeyUpdateRequest::update_requested().label(),
            "update_requested"
        );

        let key_update = TlsKeyUpdate::from_raw_request_update(0x7a);
        let encoded = key_update.encode_to_vec();

        assert_eq!(encoded, vec![0x7a]);
        assert_eq!(key_update.encoded_len(), TLS_KEY_UPDATE_REQUEST_LEN);
        assert_eq!(
            key_update.request_update(),
            TlsKeyUpdateRequest::from_u8(0x7a)
        );
        assert_eq!(
            key_update.summary(),
            "key_update request_update=unknown key update request 0x7a"
        );
        assert_eq!(
            key_update.inspection_fields(),
            vec![
                (
                    "request_update",
                    "unknown key update request 0x7a".to_string()
                ),
                ("request_update_raw", "0x7a".to_string()),
            ]
        );
        assert_eq!(TlsKeyUpdate::decode(&encoded)?, key_update);
        assert_eq!(key_update.compile(), encoded);

        let with_tail = [encoded.as_slice(), &[0xaa][..]].concat();
        let (decoded_prefix, tail) = TlsKeyUpdate::decode_prefix(&with_tail)?;
        assert_eq!(decoded_prefix, key_update);
        assert_eq!(tail, &[0xaa]);

        let handshake = TlsHandshake::from_key_update(key_update)?;
        let handshake_bytes = tls_handshake_fixture(TlsHandshakeType::KEY_UPDATE.raw(), &encoded);
        assert_eq!(handshake.body_bytes(), encoded.as_slice());
        assert!(handshake.body().is_typed_key_update());
        assert_eq!(handshake.key_update_body(), Some(&key_update));
        assert_eq!(handshake.encode_to_vec()?, handshake_bytes);

        let decoded_handshake = TlsHandshake::decode(&handshake_bytes)?;
        assert_eq!(decoded_handshake.key_update_body(), Some(&key_update));
        assert_eq!(decoded_handshake.encode_to_vec()?, handshake_bytes);

        Ok(())
    }

    #[test]
    fn tls_key_update_end_early_data_empty_body_round_trips_through_handshake() -> Result<()> {
        let end_of_early_data = TlsEndOfEarlyData::new();
        let encoded = end_of_early_data.encode_to_vec();

        assert_eq!(end_of_early_data.encoded_len(), 0);
        assert_eq!(encoded, Vec::<u8>::new());
        assert_eq!(end_of_early_data.compile(), encoded);
        assert_eq!(
            end_of_early_data.summary(),
            "end_of_early_data body_bytes=0"
        );
        assert_eq!(
            end_of_early_data.inspection_fields(),
            vec![("body_bytes", "0".to_string())]
        );
        assert_eq!(TlsEndOfEarlyData::decode(&encoded)?, end_of_early_data);

        let handshake = TlsHandshake::from_end_of_early_data(end_of_early_data)?;
        let handshake_bytes =
            tls_handshake_fixture(TlsHandshakeType::END_OF_EARLY_DATA.raw(), &encoded);
        assert_eq!(handshake.body_bytes(), encoded.as_slice());
        assert!(handshake.body().is_typed_end_of_early_data());
        assert_eq!(handshake.end_of_early_data_body(), Some(&end_of_early_data));
        assert_eq!(handshake.encode_to_vec()?, handshake_bytes);

        let decoded_handshake = TlsHandshake::decode(&handshake_bytes)?;
        assert_eq!(
            decoded_handshake.end_of_early_data_body(),
            Some(&end_of_early_data)
        );
        assert_eq!(decoded_handshake.encode_to_vec()?, handshake_bytes);

        Ok(())
    }

    #[test]
    fn tls_key_update_end_early_data_raw_bodies_remain_available() -> Result<()> {
        let raw_key_update = TlsHandshake::key_update([0xca, 0xfe]);
        assert_eq!(raw_key_update.body_bytes(), &[0xca, 0xfe]);
        assert!(matches!(
            raw_key_update.body(),
            TlsHandshakeBody::KeyUpdate(_)
        ));
        assert!(raw_key_update.key_update_body().is_none());
        assert!(!raw_key_update.body().is_typed_key_update());
        assert_eq!(
            raw_key_update.encode_to_vec()?,
            tls_handshake_fixture(TlsHandshakeType::KEY_UPDATE.raw(), &[0xca, 0xfe])
        );

        let raw_end = TlsHandshake::end_of_early_data([0xca]);
        assert_eq!(raw_end.body_bytes(), &[0xca]);
        assert!(matches!(
            raw_end.body(),
            TlsHandshakeBody::EndOfEarlyData(_)
        ));
        assert!(raw_end.end_of_early_data_body().is_none());
        assert!(!raw_end.body().is_typed_end_of_early_data());
        assert_eq!(
            raw_end.encode_to_vec()?,
            tls_handshake_fixture(TlsHandshakeType::END_OF_EARLY_DATA.raw(), &[0xca])
        );

        Ok(())
    }

    #[test]
    fn tls_key_update_end_early_data_decode_reports_structured_length_errors() {
        assert_eq!(
            TlsKeyUpdate::decode([]).unwrap_err(),
            CrafterError::buffer_too_short("tls.key_update.request_update", 1, 0)
        );
        assert_eq!(
            TlsKeyUpdate::decode([0x00, 0x01]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.key_update.length",
                "trailing bytes after request_update"
            )
        );
        assert_eq!(
            TlsEndOfEarlyData::decode([0x00]).unwrap_err(),
            CrafterError::invalid_field_value("tls.end_of_early_data.length", "body must be empty")
        );
    }

    #[test]
    fn tls_server_hello_decode_reports_structured_errors() {
        assert_eq!(
            TlsServerHello::decode([]).unwrap_err(),
            CrafterError::buffer_too_short("tls.server_hello.legacy_version", 2, 0)
        );
        assert_eq!(
            TlsServerHello::decode([0x03]).unwrap_err(),
            CrafterError::buffer_too_short("tls.server_hello.legacy_version", 2, 1)
        );

        let mut missing_session_len = vec![0x03, 0x03];
        missing_session_len.extend_from_slice(&[0; TLS_SERVER_HELLO_RANDOM_LEN]);
        assert_eq!(
            TlsServerHello::decode(&missing_session_len).unwrap_err(),
            CrafterError::buffer_too_short("tls.server_hello.session_id_echo.length", 35, 34)
        );

        let mut truncated_session_id = missing_session_len.clone();
        truncated_session_id.extend_from_slice(&[0x02, 0xaa]);
        assert_eq!(
            TlsServerHello::decode(&truncated_session_id).unwrap_err(),
            CrafterError::buffer_too_short("tls.server_hello.session_id_echo", 37, 36)
        );

        let mut missing_extensions_len = missing_session_len.clone();
        missing_extensions_len.extend_from_slice(&[
            0x00, // session_id_echo
            0x13, 0x01, // cipher_suite
            0x00, // compression_method
        ]);
        assert_eq!(
            TlsServerHello::decode(&missing_extensions_len).unwrap_err(),
            CrafterError::buffer_too_short("tls.server_hello.extensions.length", 2, 0)
        );

        let mut truncated_extension = missing_extensions_len;
        truncated_extension.extend_from_slice(&[
            0x00, 0x05, // extensions length
            0xbe, 0xef, // extension type
            0x00, 0x02, // extension body length
            0xaa, // truncated extension body
        ]);
        assert_eq!(
            TlsServerHello::decode(&truncated_extension).unwrap_err(),
            CrafterError::buffer_too_short("tls.server_hello.extension.body", 6, 5)
        );
    }

    #[test]
    fn tls_extensions_client_and_server_hello_decode_use_reusable_raw_list_codec() -> Result<()> {
        let client = TlsClientHello::new()
            .with_random([0x31; TLS_CLIENT_HELLO_RANDOM_LEN])
            .with_raw_cipher_suites([0x1301])
            .with_null_compression()
            .with_extensions(vec![
                TlsRawExtension::from_raw(0xbeef, [0xde, 0xad]),
                TlsRawExtension::from_raw(0xbeef, [0xfa, 0xce]),
            ]);
        let client_encoded = client.encode_to_vec()?;
        let client_decoded = TlsClientHello::decode(&client_encoded)?;

        assert!(client_decoded.extensions_present());
        assert_eq!(client_decoded.extensions().len(), 2);
        assert_eq!(client_decoded.extensions()[0].raw_type(), 0xbeef);
        assert_eq!(client_decoded.extensions()[0].body(), &[0xde, 0xad]);
        assert_eq!(client_decoded.extensions()[1].raw_type(), 0xbeef);
        assert_eq!(client_decoded.extensions()[1].body(), &[0xfa, 0xce]);
        assert_eq!(client_decoded.encode_to_vec()?, client_encoded);

        let server = TlsServerHello::new()
            .with_random([0x41; TLS_SERVER_HELLO_RANDOM_LEN])
            .with_raw_cipher_suite(0x1301)
            .with_null_compression()
            .with_extensions(vec![
                TlsRawExtension::from_raw(0x002b, [0x03, 0x04]),
                TlsRawExtension::from_raw(0xbeef, [0xaa]),
            ]);
        let server_encoded = server.encode_to_vec()?;
        let server_decoded = TlsServerHello::decode(&server_encoded)?;

        assert_eq!(server_decoded.extensions().len(), 2);
        assert_eq!(server_decoded.extensions()[0].raw_type(), 0x002b);
        assert_eq!(server_decoded.extensions()[0].body(), &[0x03, 0x04]);
        assert_eq!(server_decoded.extensions()[1].raw_type(), 0xbeef);
        assert_eq!(server_decoded.extensions()[1].body(), &[0xaa]);
        assert_eq!(server_decoded.encode_to_vec()?, server_encoded);

        Ok(())
    }

    #[test]
    fn tls_handshake_message_explicit_length_override_is_preserved() -> Result<()> {
        let message = TlsHandshake::client_hello([0xaa, 0xbb, 0xcc]).with_length(1);

        assert_eq!(message.declared_length(), Some(1));
        assert_eq!(message.declared_len(), Some(1));
        assert_eq!(message.effective_length()?, 1);
        assert_eq!(
            message.declared_message_len()?,
            TLS_HANDSHAKE_HEADER_LEN + 1
        );
        assert_eq!(message.actual_message_len()?, TLS_HANDSHAKE_HEADER_LEN + 3);
        assert_eq!(message.encoded_len()?, TLS_HANDSHAKE_HEADER_LEN + 3);
        assert_eq!(
            message.encode_to_vec()?,
            vec![0x01, 0x00, 0x00, 0x01, 0xaa, 0xbb, 0xcc]
        );

        let mismatched = message.clone().with_raw_handshake_type(0x14);
        assert_eq!(mismatched.handshake_type(), TlsHandshakeType::FINISHED);
        assert!(matches!(
            mismatched.body(),
            TlsHandshakeBody::ClientHello(_)
        ));
        assert_eq!(
            mismatched.encode_to_vec()?,
            vec![0x14, 0x00, 0x00, 0x01, 0xaa, 0xbb, 0xcc]
        );

        Ok(())
    }

    #[test]
    fn tls_handshake_message_byte_exact_round_trips() -> Result<()> {
        let client_hello = tls_handshake_fixture(0x01, &tls_client_hello_test_body());
        let server_hello = tls_handshake_fixture(0x02, &tls_server_hello_test_body());
        let fixtures = [
            client_hello,
            server_hello,
            vec![0x14, 0x00, 0x00, 0x01, 0x00],
            vec![0x1b, 0x00, 0x00, 0x02, 0xab, 0xcd],
            vec![0x12, 0x00, 0x00, 0x03, 0xde, 0xad, 0xbe],
        ];

        for fixture in fixtures {
            let message = TlsHandshake::decode(&fixture)?;
            assert_eq!(message.encode_to_vec()?, fixture);
            assert_eq!(message.compile()?, fixture);
        }

        Ok(())
    }

    #[test]
    fn tls_handshake_message_short_buffers_are_structured_errors() {
        for available in 0..TLS_HANDSHAKE_HEADER_LEN {
            let bytes = vec![0u8; available];

            assert_eq!(
                TlsHandshake::decode(&bytes).unwrap_err(),
                CrafterError::buffer_too_short(
                    "tls.handshake.header",
                    TLS_HANDSHAKE_HEADER_LEN,
                    available
                )
            );
        }

        assert_eq!(
            TlsHandshake::decode([0x01, 0x00, 0x00, 0x04, 0xaa]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.handshake.body",
                TLS_HANDSHAKE_HEADER_LEN + 4,
                TLS_HANDSHAKE_HEADER_LEN + 1
            )
        );
    }

    #[test]
    fn tls_handshake_header_type_known_helpers_reuse_constants() -> Result<()> {
        let client_hello = TlsHandshakeType::client_hello();

        assert_eq!(
            client_hello.raw(),
            constants::TLS_HANDSHAKE_TYPE_CLIENT_HELLO
        );
        assert_eq!(client_hello.as_u8(), 0x01);
        assert_eq!(client_hello.to_byte(), 0x01);
        assert_eq!(client_hello.name(), Some("client_hello"));
        assert_eq!(client_hello.status(), TlsCodepointStatus::DefaultEligible);
        assert_eq!(client_hello.label(), "client_hello");
        assert_eq!(client_hello.to_string(), "client_hello");
        assert!(client_hello.is_known());
        assert!(client_hello.is_default_eligible());
        assert!(!client_hello.is_dtls_only());
        assert_eq!(client_hello.encode_to_vec(), vec![0x01]);

        let mut encoded = Vec::new();
        TlsHandshakeType::server_hello().encode(&mut encoded);
        assert_eq!(encoded, [0x02]);
        assert_eq!(
            TlsHandshakeType::decode_prefix(&[0x02, 0xaa])?,
            (TlsHandshakeType::SERVER_HELLO, &[0xaa][..])
        );
        assert_eq!(
            TlsHandshakeType::decode([0x14])?,
            TlsHandshakeType::FINISHED
        );
        assert_eq!(u8::from(client_hello), 0x01);
        assert_eq!(TlsHandshakeType::from(0x18), TlsHandshakeType::KEY_UPDATE);

        assert_eq!(
            TlsHandshakeType::COMPRESSED_CERTIFICATE.status(),
            TlsCodepointStatus::Deferred
        );
        assert_eq!(
            TlsHandshakeType::REQUEST_CONNECTION_ID.status(),
            TlsCodepointStatus::DtlsOnly
        );
        assert!(TlsHandshakeType::REQUEST_CONNECTION_ID.is_dtls_only());
        assert_eq!(
            TlsHandshakeType::MESSAGE_HASH.status(),
            TlsCodepointStatus::PreserveOnly
        );

        Ok(())
    }

    #[test]
    fn tls_handshake_header_type_unknown_values_are_preserved() {
        let unknown = TlsHandshakeType::from_u8(0x12);

        assert_eq!(unknown.raw(), 0x12);
        assert_eq!(unknown.name(), None);
        assert_eq!(unknown.status(), TlsCodepointStatus::Unassigned);
        assert_eq!(unknown.label(), "unassigned handshake type 0x12");
        assert_eq!(
            unknown.summary(),
            "unassigned handshake type 0x12 raw=0x12 status=unassigned"
        );
        assert!(!unknown.is_known());
        assert!(!unknown.is_default_eligible());
        assert_eq!(
            unknown.inspection_fields(),
            vec![
                (
                    "handshake_type",
                    "unassigned handshake type 0x12".to_string()
                ),
                ("raw", "0x12".to_string()),
                ("status", "unassigned".to_string()),
                ("dtls_only", "false".to_string()),
            ]
        );
    }

    #[test]
    fn tls_handshake_header_encodes_u24_auto_length_and_preserves_override() -> Result<()> {
        let header = TlsHandshakeHeader::client_hello();

        assert_eq!(header.handshake_type(), TlsHandshakeType::CLIENT_HELLO);
        assert_eq!(header.raw_handshake_type(), 0x01);
        assert_eq!(header.declared_length(), None);
        assert_eq!(header.declared_len(), None);
        assert_eq!(header.length_override(), None);
        assert_eq!(header.declared_length_state(), FieldState::Unset);
        assert_eq!(header.length_state(), FieldState::Unset);
        assert_eq!(header.effective_length(0x010203)?, 0x010203);
        assert_eq!(header.declared_length_value(7)?, 7);
        assert_eq!(header.length_value(7)?, 7);
        assert_eq!(header.header_len(), TLS_HANDSHAKE_HEADER_LEN);
        assert_eq!(header.encoded_len(), TLS_HANDSHAKE_HEADER_LEN);
        assert_eq!(
            header.actual_message_len(0x010203)?,
            TLS_HANDSHAKE_HEADER_LEN + 0x010203
        );
        assert_eq!(
            header.declared_message_len(0x010203)?,
            TLS_HANDSHAKE_HEADER_LEN + 0x010203
        );
        assert_eq!(
            header.encode_to_vec_with_body_len(0x010203)?,
            vec![0x01, 0x01, 0x02, 0x03]
        );
        assert_eq!(header.encode_to_vec()?, vec![0x01, 0x00, 0x00, 0x00]);
        assert_eq!(header.compile()?, header.encode_to_vec()?);

        let overridden = header.clone().with_length(1);
        assert_eq!(overridden.declared_length(), Some(1));
        assert_eq!(overridden.effective_length(0x010203)?, 1);
        assert_eq!(
            overridden.declared_message_len(0x010203)?,
            TLS_HANDSHAKE_HEADER_LEN + 1
        );
        assert_eq!(
            overridden.actual_message_len(0x010203)?,
            TLS_HANDSHAKE_HEADER_LEN + 0x010203
        );
        assert_eq!(
            overridden.encode_to_vec_with_body_len(0x010203)?,
            vec![0x01, 0x00, 0x00, 0x01]
        );

        let max = header
            .clone()
            .with_declared_length(TLS_HANDSHAKE_MAX_LENGTH);
        assert_eq!(
            max.encode_to_vec_with_body_len(0)?,
            vec![0x01, 0xff, 0xff, 0xff]
        );

        Ok(())
    }

    #[test]
    fn tls_handshake_header_decode_preserves_u24_length_and_tail() -> Result<()> {
        let bytes = [0x02, 0x01, 0x02, 0x03, 0xaa, 0xbb];
        let (header, tail) = TlsHandshakeHeader::decode_prefix(&bytes)?;

        assert_eq!(tail, &[0xaa, 0xbb]);
        assert_eq!(header.handshake_type(), TlsHandshakeType::SERVER_HELLO);
        assert_eq!(header.raw_handshake_type(), 0x02);
        assert_eq!(header.declared_length(), Some(0x010203));
        assert_eq!(header.declared_length_state(), FieldState::User);
        assert_eq!(header.effective_length(99)?, 0x010203);
        assert_eq!(
            header.encode_to_vec_with_body_len(99)?,
            vec![0x02, 0x01, 0x02, 0x03]
        );
        assert_eq!(
            TlsHandshakeHeader::decode(bytes)?.declared_length(),
            Some(0x010203)
        );

        Ok(())
    }

    #[test]
    fn tls_handshake_header_supports_unknown_type_and_inspection() -> Result<()> {
        let header =
            TlsHandshakeHeader::new(TlsHandshakeType::from_u8(0x12)).with_declared_length(0x000004);

        assert_eq!(
            header.handshake_type().label(),
            "unassigned handshake type 0x12"
        );
        assert_eq!(
            header.summary(),
            "handshake_header handshake_type=unassigned handshake type 0x12 declared_length=4"
        );

        let fields = header.inspection_fields();
        assert!(fields.contains(&(
            "handshake_type",
            "unassigned handshake type 0x12".to_string(),
        )));
        assert!(fields.contains(&("handshake_type_raw", "0x12".to_string())));
        assert!(fields.contains(&("handshake_type_status", "unassigned".to_string())));
        assert!(fields.contains(&("declared_length", "4".to_string())));
        assert!(fields.contains(&("declared_length_state", "user".to_string())));
        assert!(fields.contains(&("header_bytes", "4".to_string())));
        assert_eq!(
            header.with_raw_handshake_type(0x14).handshake_type(),
            TlsHandshakeType::FINISHED
        );

        Ok(())
    }

    #[test]
    fn tls_handshake_header_decode_reports_structured_short_buffers() {
        assert_eq!(
            TlsHandshakeType::decode([]).unwrap_err(),
            CrafterError::buffer_too_short("tls.handshake.type", TLS_HANDSHAKE_TYPE_LEN, 0)
        );

        for available in 0..TLS_HANDSHAKE_HEADER_LEN {
            let bytes = vec![0u8; available];
            assert_eq!(
                TlsHandshakeHeader::decode(&bytes).unwrap_err(),
                CrafterError::buffer_too_short(
                    "tls.handshake.header",
                    TLS_HANDSHAKE_HEADER_LEN,
                    available
                )
            );
        }
    }

    #[test]
    fn tls_handshake_header_encode_rejects_oversized_auto_length_but_preserves_override() {
        let header = TlsHandshakeHeader::finished();

        assert_eq!(
            header
                .encode_to_vec_with_body_len(TLS_HANDSHAKE_MAX_LENGTH as usize + 1)
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.handshake.length",
                "body length must fit in three bytes"
            )
        );

        let overridden = header.with_length(0);
        assert_eq!(
            overridden
                .encode_to_vec_with_body_len(TLS_HANDSHAKE_MAX_LENGTH as usize + 1)
                .unwrap(),
            vec![0x14, 0x00, 0x00, 0x00]
        );

        assert_eq!(
            TlsHandshakeHeader::finished()
                .with_length(TLS_HANDSHAKE_MAX_LENGTH + 1)
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.handshake.length",
                "length must fit in three bytes"
            )
        );
    }
}
