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
