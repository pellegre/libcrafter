//! TLS handshake message header helpers.
//!
//! A TLS handshake message starts with a one-octet `HandshakeType` followed by
//! a three-octet big-endian body length. Message bodies are intentionally left
//! opaque for later source-backed grammar steps.

use core::fmt;

use super::constants::{self, TlsCodepointStatus};
use crate::field::{Field, FieldState};
use crate::{CrafterError, Result};

/// TLS handshake type field width in bytes.
pub const TLS_HANDSHAKE_TYPE_LEN: usize = 1;
/// TLS handshake message body length field width in bytes.
pub const TLS_HANDSHAKE_LENGTH_LEN: usize = 3;
/// TLS handshake header width in bytes.
pub const TLS_HANDSHAKE_HEADER_LEN: usize = TLS_HANDSHAKE_TYPE_LEN + TLS_HANDSHAKE_LENGTH_LEN;
/// Maximum body length representable by the TLS handshake three-octet length.
pub const TLS_HANDSHAKE_MAX_LENGTH: u32 = 0x00ff_ffff;

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
    /// Opaque `client_hello` body bytes.
    ClientHello(Vec<u8>),
    /// Opaque `server_hello` body bytes.
    ServerHello(Vec<u8>),
    /// Opaque `new_session_ticket` body bytes.
    NewSessionTicket(Vec<u8>),
    /// Opaque `end_of_early_data` body bytes.
    EndOfEarlyData(Vec<u8>),
    /// Opaque `encrypted_extensions` body bytes.
    EncryptedExtensions(Vec<u8>),
    /// Opaque `certificate` body bytes.
    Certificate(Vec<u8>),
    /// Opaque `certificate_request` body bytes.
    CertificateRequest(Vec<u8>),
    /// Opaque `certificate_verify` body bytes.
    CertificateVerify(Vec<u8>),
    /// Opaque `finished` body bytes.
    Finished(Vec<u8>),
    /// Opaque `key_update` body bytes.
    KeyUpdate(Vec<u8>),
    /// Opaque `compressed_certificate` body bytes.
    CompressedCertificate(Vec<u8>),
    /// Unknown, unsupported, or intentionally raw handshake body bytes.
    Opaque(Vec<u8>),
}

impl TlsHandshakeBody {
    /// Create an opaque body for a known `client_hello` hook.
    pub fn client_hello(body: impl Into<Vec<u8>>) -> Self {
        Self::ClientHello(body.into())
    }

    /// Create an opaque body for a known `server_hello` hook.
    pub fn server_hello(body: impl Into<Vec<u8>>) -> Self {
        Self::ServerHello(body.into())
    }

    /// Create an opaque body for a known `new_session_ticket` hook.
    pub fn new_session_ticket(body: impl Into<Vec<u8>>) -> Self {
        Self::NewSessionTicket(body.into())
    }

    /// Create an opaque body for a known `end_of_early_data` hook.
    pub fn end_of_early_data(body: impl Into<Vec<u8>>) -> Self {
        Self::EndOfEarlyData(body.into())
    }

    /// Create an opaque body for a known `encrypted_extensions` hook.
    pub fn encrypted_extensions(body: impl Into<Vec<u8>>) -> Self {
        Self::EncryptedExtensions(body.into())
    }

    /// Create an opaque body for a known `certificate` hook.
    pub fn certificate(body: impl Into<Vec<u8>>) -> Self {
        Self::Certificate(body.into())
    }

    /// Create an opaque body for a known `certificate_request` hook.
    pub fn certificate_request(body: impl Into<Vec<u8>>) -> Self {
        Self::CertificateRequest(body.into())
    }

    /// Create an opaque body for a known `certificate_verify` hook.
    pub fn certificate_verify(body: impl Into<Vec<u8>>) -> Self {
        Self::CertificateVerify(body.into())
    }

    /// Create an opaque body for a known `finished` hook.
    pub fn finished(body: impl Into<Vec<u8>>) -> Self {
        Self::Finished(body.into())
    }

    /// Create an opaque body for a known `key_update` hook.
    pub fn key_update(body: impl Into<Vec<u8>>) -> Self {
        Self::KeyUpdate(body.into())
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
            TlsHandshakeType::CLIENT_HELLO => Self::ClientHello(body),
            TlsHandshakeType::SERVER_HELLO => Self::ServerHello(body),
            TlsHandshakeType::NEW_SESSION_TICKET => Self::NewSessionTicket(body),
            TlsHandshakeType::END_OF_EARLY_DATA => Self::EndOfEarlyData(body),
            TlsHandshakeType::ENCRYPTED_EXTENSIONS => Self::EncryptedExtensions(body),
            TlsHandshakeType::CERTIFICATE => Self::Certificate(body),
            TlsHandshakeType::CERTIFICATE_REQUEST => Self::CertificateRequest(body),
            TlsHandshakeType::CERTIFICATE_VERIFY => Self::CertificateVerify(body),
            TlsHandshakeType::FINISHED => Self::Finished(body),
            TlsHandshakeType::KEY_UPDATE => Self::KeyUpdate(body),
            TlsHandshakeType::COMPRESSED_CERTIFICATE => Self::CompressedCertificate(body),
            _ => Self::Opaque(body),
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
            Self::ClientHello(body)
            | Self::ServerHello(body)
            | Self::NewSessionTicket(body)
            | Self::EndOfEarlyData(body)
            | Self::EncryptedExtensions(body)
            | Self::Certificate(body)
            | Self::CertificateRequest(body)
            | Self::CertificateVerify(body)
            | Self::Finished(body)
            | Self::KeyUpdate(body)
            | Self::CompressedCertificate(body)
            | Self::Opaque(body) => body,
        }
    }

    /// Consume the body hook and return the preserved bytes.
    pub fn into_body(self) -> Vec<u8> {
        match self {
            Self::ClientHello(body)
            | Self::ServerHello(body)
            | Self::NewSessionTicket(body)
            | Self::EndOfEarlyData(body)
            | Self::EncryptedExtensions(body)
            | Self::Certificate(body)
            | Self::CertificateRequest(body)
            | Self::CertificateVerify(body)
            | Self::Finished(body)
            | Self::KeyUpdate(body)
            | Self::CompressedCertificate(body)
            | Self::Opaque(body) => body,
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

    /// Append the preserved body bytes to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.body());
    }

    /// Return the preserved body bytes as a new vector.
    pub fn encode_to_vec(&self) -> Vec<u8> {
        self.body().to_vec()
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

    /// Construct a `server_hello` handshake message with opaque body bytes.
    pub fn server_hello(body: impl Into<Vec<u8>>) -> Self {
        Self::from_header_and_body(
            TlsHandshakeHeader::server_hello(),
            TlsHandshakeBody::server_hello(body),
        )
    }

    /// Construct a `new_session_ticket` handshake message with opaque body bytes.
    pub fn new_session_ticket(body: impl Into<Vec<u8>>) -> Self {
        Self::from_header_and_body(
            TlsHandshakeHeader::new_session_ticket(),
            TlsHandshakeBody::new_session_ticket(body),
        )
    }

    /// Construct an `end_of_early_data` handshake message with opaque body bytes.
    pub fn end_of_early_data(body: impl Into<Vec<u8>>) -> Self {
        Self::from_header_and_body(
            TlsHandshakeHeader::end_of_early_data(),
            TlsHandshakeBody::end_of_early_data(body),
        )
    }

    /// Construct an `encrypted_extensions` handshake message with opaque body bytes.
    pub fn encrypted_extensions(body: impl Into<Vec<u8>>) -> Self {
        Self::from_header_and_body(
            TlsHandshakeHeader::encrypted_extensions(),
            TlsHandshakeBody::encrypted_extensions(body),
        )
    }

    /// Construct a `certificate` handshake message with opaque body bytes.
    pub fn certificate(body: impl Into<Vec<u8>>) -> Self {
        Self::from_header_and_body(
            TlsHandshakeHeader::certificate(),
            TlsHandshakeBody::certificate(body),
        )
    }

    /// Construct a `certificate_request` handshake message with opaque body bytes.
    pub fn certificate_request(body: impl Into<Vec<u8>>) -> Self {
        Self::from_header_and_body(
            TlsHandshakeHeader::certificate_request(),
            TlsHandshakeBody::certificate_request(body),
        )
    }

    /// Construct a `certificate_verify` handshake message with opaque body bytes.
    pub fn certificate_verify(body: impl Into<Vec<u8>>) -> Self {
        Self::from_header_and_body(
            TlsHandshakeHeader::certificate_verify(),
            TlsHandshakeBody::certificate_verify(body),
        )
    }

    /// Construct a `finished` handshake message with opaque body bytes.
    pub fn finished(body: impl Into<Vec<u8>>) -> Self {
        Self::from_header_and_body(
            TlsHandshakeHeader::finished(),
            TlsHandshakeBody::finished(body),
        )
    }

    /// Construct a `key_update` handshake message with opaque body bytes.
    pub fn key_update(body: impl Into<Vec<u8>>) -> Self {
        Self::from_header_and_body(
            TlsHandshakeHeader::key_update(),
            TlsHandshakeBody::key_update(body),
        )
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
        Ok((Self::from_decoded_parts(header, body), &tail[body_len..]))
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
            self.body.label()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = self.header.inspection_fields();
        fields.push(("body", self.body.label().to_string()));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FieldState;

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
            "handshake handshake_type=unassigned handshake type 0x12 declared_length=3 body_bytes=3 body=opaque"
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
    fn tls_handshake_message_known_type_uses_opaque_body_hook() -> Result<()> {
        let bytes = [0x01, 0x00, 0x00, 0x02, 0xca, 0xfe];
        let message = TlsHandshake::decode(bytes)?;

        assert_eq!(message.handshake_type(), TlsHandshakeType::CLIENT_HELLO);
        assert_eq!(
            message.body().handshake_type_hint(),
            Some(TlsHandshakeType::CLIENT_HELLO)
        );
        assert!(message.body().is_known_hook());
        assert!(matches!(message.body(), TlsHandshakeBody::ClientHello(_)));
        assert_eq!(message.body_bytes(), &[0xca, 0xfe]);
        assert_eq!(
            message.encode_to_vec()?,
            vec![0x01, 0x00, 0x00, 0x02, 0xca, 0xfe]
        );

        let built = TlsHandshake::client_hello([0xca, 0xfe]);
        assert_eq!(built.declared_length(), None);
        assert_eq!(built.effective_length()?, 2);
        assert_eq!(
            built.encode_to_vec()?,
            vec![0x01, 0x00, 0x00, 0x02, 0xca, 0xfe]
        );
        assert_eq!(
            built.summary(),
            "handshake handshake_type=client_hello declared_length=auto body_bytes=2 body=client_hello"
        );

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
        let fixtures = [
            vec![0x01, 0x00, 0x00, 0x02, 0xca, 0xfe],
            vec![0x02, 0x00, 0x00, 0x00],
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
