//! TLS heartbeat packet grammar.
//!
//! This module models RFC 6520 heartbeat record payload bytes only. It does
//! not implement keepalive scheduling, PMTU probing, peer policy, retransmit
//! behavior, or live endpoint probing.

use super::constants::TlsCodepointStatus;
use crate::field::{Field, FieldState};
use crate::protocols::transport::common::hex_bytes;
use crate::{CrafterError, Result};

/// TLS HeartbeatMessage `type` field width in bytes.
pub const TLS_HEARTBEAT_MESSAGE_TYPE_LEN: usize = 1;
/// TLS HeartbeatMessage `payload_length` field width in bytes.
pub const TLS_HEARTBEAT_PAYLOAD_LENGTH_LEN: usize = 2;
/// TLS HeartbeatMessage fixed header width in bytes.
pub const TLS_HEARTBEAT_HEADER_LEN: usize =
    TLS_HEARTBEAT_MESSAGE_TYPE_LEN + TLS_HEARTBEAT_PAYLOAD_LENGTH_LEN;
/// RFC 6520 HeartbeatRequest message type.
pub const TLS_HEARTBEAT_MESSAGE_TYPE_REQUEST: u8 = 1;
/// RFC 6520 HeartbeatResponse message type.
pub const TLS_HEARTBEAT_MESSAGE_TYPE_RESPONSE: u8 = 2;
/// RFC 6520 sender-side minimum heartbeat padding length.
pub const TLS_HEARTBEAT_MIN_PADDING_LEN: usize = 16;

/// Raw-preserving TLS heartbeat message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TlsHeartbeatMessageType {
    raw: u8,
}

impl TlsHeartbeatMessageType {
    /// RFC 6520 `heartbeat_request`.
    pub const REQUEST: Self = Self::new(TLS_HEARTBEAT_MESSAGE_TYPE_REQUEST);
    /// RFC 6520 `heartbeat_response`.
    pub const RESPONSE: Self = Self::new(TLS_HEARTBEAT_MESSAGE_TYPE_RESPONSE);

    /// Preserve a caller-supplied heartbeat message type value.
    pub const fn new(raw: u8) -> Self {
        Self { raw }
    }

    /// Preserve a caller-supplied heartbeat message type value.
    pub const fn from_u8(raw: u8) -> Self {
        Self::new(raw)
    }

    /// `heartbeat_request` constructor.
    pub const fn request() -> Self {
        Self::REQUEST
    }

    /// `heartbeat_response` constructor.
    pub const fn response() -> Self {
        Self::RESPONSE
    }

    /// Return the preserved raw message type.
    pub const fn raw(self) -> u8 {
        self.raw
    }

    /// Return the preserved raw message type.
    pub const fn as_u8(self) -> u8 {
        self.raw
    }

    /// Return the one-byte wire encoding.
    pub const fn to_byte(self) -> u8 {
        self.raw
    }

    /// Return the selected source-backed name, if any.
    pub const fn name(self) -> Option<&'static str> {
        match self.raw {
            TLS_HEARTBEAT_MESSAGE_TYPE_REQUEST => Some("heartbeat_request"),
            TLS_HEARTBEAT_MESSAGE_TYPE_RESPONSE => Some("heartbeat_response"),
            _ => None,
        }
    }

    /// Return the source-backed assignment status.
    pub const fn status(self) -> TlsCodepointStatus {
        match self.raw {
            TLS_HEARTBEAT_MESSAGE_TYPE_REQUEST | TLS_HEARTBEAT_MESSAGE_TYPE_RESPONSE => {
                TlsCodepointStatus::DefaultEligible
            }
            0 | 255 => TlsCodepointStatus::Reserved,
            _ => TlsCodepointStatus::Unassigned,
        }
    }

    /// Return true for request messages.
    pub const fn is_request(self) -> bool {
        self.raw == TLS_HEARTBEAT_MESSAGE_TYPE_REQUEST
    }

    /// Return true for response messages.
    pub const fn is_response(self) -> bool {
        self.raw == TLS_HEARTBEAT_MESSAGE_TYPE_RESPONSE
    }

    /// Human-readable label preserving unknown values numerically.
    pub fn label(self) -> String {
        match self.name() {
            Some(name) => name.to_string(),
            None => format!("unknown heartbeat message type 0x{:02x}", self.raw),
        }
    }
}

impl From<u8> for TlsHeartbeatMessageType {
    fn from(value: u8) -> Self {
        Self::new(value)
    }
}

impl From<TlsHeartbeatMessageType> for u8 {
    fn from(value: TlsHeartbeatMessageType) -> Self {
        value.raw()
    }
}

/// TLS HeartbeatMessage body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsHeartbeat {
    message_type: TlsHeartbeatMessageType,
    payload_length: Field<u16>,
    payload: Vec<u8>,
    padding: Vec<u8>,
}

impl TlsHeartbeat {
    /// Construct a heartbeat message with empty payload and padding.
    pub fn new(message_type: impl Into<TlsHeartbeatMessageType>) -> Self {
        Self {
            message_type: message_type.into(),
            payload_length: Field::unset(),
            payload: Vec::new(),
            padding: Vec::new(),
        }
    }

    /// Construct a heartbeat request from explicit payload and padding bytes.
    pub fn request(payload: impl Into<Vec<u8>>, padding: impl Into<Vec<u8>>) -> Self {
        Self::new(TlsHeartbeatMessageType::request())
            .with_payload(payload)
            .with_padding(padding)
    }

    /// Construct a heartbeat response from explicit payload and padding bytes.
    pub fn response(payload: impl Into<Vec<u8>>, padding: impl Into<Vec<u8>>) -> Self {
        Self::new(TlsHeartbeatMessageType::response())
            .with_payload(payload)
            .with_padding(padding)
    }

    /// Construct a heartbeat message from a raw message type value.
    pub fn from_raw_type(
        message_type: u8,
        payload: impl Into<Vec<u8>>,
        padding: impl Into<Vec<u8>>,
    ) -> Self {
        Self::new(TlsHeartbeatMessageType::from_u8(message_type))
            .with_payload(payload)
            .with_padding(padding)
    }

    /// Replace the message type.
    pub fn with_message_type(mut self, message_type: impl Into<TlsHeartbeatMessageType>) -> Self {
        self.message_type = message_type.into();
        self
    }

    /// Replace the message type from a raw value.
    pub fn with_raw_message_type(self, message_type: u8) -> Self {
        self.with_message_type(TlsHeartbeatMessageType::from_u8(message_type))
    }

    /// Replace the opaque payload bytes.
    pub fn with_payload(mut self, payload: impl Into<Vec<u8>>) -> Self {
        self.payload = payload.into();
        self
    }

    /// Replace the opaque padding bytes.
    pub fn with_padding(mut self, padding: impl Into<Vec<u8>>) -> Self {
        self.padding = padding.into();
        self
    }

    /// Pin the declared payload_length field.
    pub fn with_payload_length(mut self, payload_length: u16) -> Self {
        self.payload_length.set_user(payload_length);
        self
    }

    /// Compatibility alias for pinning the declared payload_length field.
    pub fn with_declared_payload_length(self, payload_length: u16) -> Self {
        self.with_payload_length(payload_length)
    }

    /// Return the message type.
    pub const fn message_type(&self) -> TlsHeartbeatMessageType {
        self.message_type
    }

    /// Return the raw message type.
    pub const fn raw_message_type(&self) -> u8 {
        self.message_type.raw()
    }

    /// Borrow the opaque payload bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Borrow the padding bytes.
    pub fn padding(&self) -> &[u8] {
        &self.padding
    }

    /// Actual payload byte count.
    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }

    /// Padding byte count.
    pub fn padding_len(&self) -> usize {
        self.padding.len()
    }

    /// Caller-pinned or decoded payload length, if present.
    pub fn declared_payload_length(&self) -> Option<u16> {
        self.payload_length.value().copied()
    }

    /// Assignment state of the payload_length field.
    pub const fn payload_length_state(&self) -> FieldState {
        self.payload_length.state()
    }

    /// Declared payload length to emit.
    pub fn effective_payload_length(&self) -> Result<u16> {
        match self.payload_length.value() {
            Some(&payload_length) => Ok(payload_length),
            None => u16::try_from(self.payload.len()).map_err(|_| {
                CrafterError::invalid_field_value(
                    "tls.heartbeat.payload_length",
                    "payload length must fit in two bytes",
                )
            }),
        }
    }

    /// Number of bytes occupied by the heartbeat message.
    pub fn encoded_len(&self) -> Result<usize> {
        self.effective_payload_length()?;
        TLS_HEARTBEAT_HEADER_LEN
            .checked_add(self.payload.len())
            .and_then(|len| len.checked_add(self.padding.len()))
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.heartbeat.length", "length overflow")
            })
    }

    /// Append the heartbeat message bytes.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encoded_len()?;
        out.push(self.message_type.to_byte());
        out.extend_from_slice(&self.effective_payload_length()?.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out.extend_from_slice(&self.padding);
        Ok(())
    }

    /// Return the heartbeat message bytes.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Compatibility alias for returning the heartbeat message bytes.
    pub fn compile(&self) -> Result<Vec<u8>> {
        self.encode_to_vec()
    }

    /// Decode one complete heartbeat message from record fragment bytes.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        if bytes.len() < TLS_HEARTBEAT_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.heartbeat.header",
                TLS_HEARTBEAT_HEADER_LEN,
                bytes.len(),
            ));
        }

        let message_type = TlsHeartbeatMessageType::from_u8(bytes[0]);
        let payload_length = u16::from_be_bytes([bytes[1], bytes[2]]);
        let payload_end = TLS_HEARTBEAT_HEADER_LEN
            .checked_add(usize::from(payload_length))
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.heartbeat.length", "length overflow")
            })?;

        if bytes.len() < payload_end {
            return Err(CrafterError::buffer_too_short(
                "tls.heartbeat.payload",
                payload_end,
                bytes.len(),
            ));
        }

        Ok(Self {
            message_type,
            payload_length: Field::user(payload_length),
            payload: bytes[TLS_HEARTBEAT_HEADER_LEN..payload_end].to_vec(),
            padding: bytes[payload_end..].to_vec(),
        })
    }

    /// Stable one-line summary preserving declared and actual lengths.
    pub fn summary(&self) -> String {
        format!(
            "heartbeat type={} declared_payload_length={} payload_bytes={} padding_bytes={}",
            self.message_type.label(),
            self.payload_length_label(),
            self.payload.len(),
            self.padding.len()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("message_type", self.message_type.label()),
            (
                "message_type_raw",
                format!("0x{:02x}", self.message_type.raw()),
            ),
            (
                "message_type_status",
                self.message_type.status().label().to_string(),
            ),
            ("declared_payload_length", self.payload_length_label()),
            (
                "payload_length_state",
                field_state_label(self.payload_length.state()).to_string(),
            ),
            ("payload", hex_bytes(&self.payload)),
            ("payload_bytes", self.payload.len().to_string()),
            ("padding", hex_bytes(&self.padding)),
            ("padding_bytes", self.padding.len().to_string()),
            (
                "sender_min_padding_met",
                (self.padding.len() >= TLS_HEARTBEAT_MIN_PADDING_LEN).to_string(),
            ),
        ]
    }

    fn payload_length_label(&self) -> String {
        self.declared_payload_length()
            .map(|length| length.to_string())
            .unwrap_or_else(|| "auto".to_string())
    }
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

    #[test]
    fn tls_heartbeat_request_and_response_round_trip() -> Result<()> {
        let request = TlsHeartbeat::request([0xde, 0xad], [0x55; TLS_HEARTBEAT_MIN_PADDING_LEN]);
        let encoded = request.encode_to_vec()?;

        assert_eq!(
            encoded,
            vec![
                0x01, 0x00, 0x02, 0xde, 0xad, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
                0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
            ]
        );
        assert_eq!(request.message_type(), TlsHeartbeatMessageType::REQUEST);
        assert_eq!(request.payload(), &[0xde, 0xad]);
        assert_eq!(request.padding_len(), TLS_HEARTBEAT_MIN_PADDING_LEN);
        assert_eq!(request.effective_payload_length()?, 2);
        assert_eq!(
            request.summary(),
            "heartbeat type=heartbeat_request declared_payload_length=auto payload_bytes=2 padding_bytes=16"
        );

        let decoded = TlsHeartbeat::decode(&encoded)?;
        assert_eq!(decoded.message_type(), TlsHeartbeatMessageType::REQUEST);
        assert_eq!(decoded.declared_payload_length(), Some(2));
        assert_eq!(decoded.payload_length_state(), FieldState::User);
        assert_eq!(decoded.payload(), &[0xde, 0xad]);
        assert_eq!(decoded.padding(), &[0x55; TLS_HEARTBEAT_MIN_PADDING_LEN]);
        assert_eq!(decoded.encode_to_vec()?, encoded);

        let response = TlsHeartbeat::response(decoded.payload().to_vec(), decoded.padding());
        assert_eq!(response.message_type(), TlsHeartbeatMessageType::RESPONSE);
        assert!(response.message_type().is_response());
        assert_eq!(
            response.encode_to_vec()?[0],
            TLS_HEARTBEAT_MESSAGE_TYPE_RESPONSE
        );

        Ok(())
    }

    #[test]
    fn tls_heartbeat_unknown_type_and_payload_length_override_are_preserved() -> Result<()> {
        let heartbeat =
            TlsHeartbeat::from_raw_type(0x7f, [0xaa, 0xbb, 0xcc], [0x00]).with_payload_length(1);
        let encoded = heartbeat.encode_to_vec()?;

        assert_eq!(encoded, vec![0x7f, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0x00]);
        assert_eq!(
            heartbeat.message_type().label(),
            "unknown heartbeat message type 0x7f"
        );
        assert_eq!(heartbeat.effective_payload_length()?, 1);
        assert_eq!(heartbeat.declared_payload_length(), Some(1));
        assert_eq!(
            heartbeat.summary(),
            "heartbeat type=unknown heartbeat message type 0x7f declared_payload_length=1 payload_bytes=3 padding_bytes=1"
        );

        let decoded = TlsHeartbeat::decode(&encoded)?;
        assert_eq!(
            decoded.message_type(),
            TlsHeartbeatMessageType::from_u8(0x7f)
        );
        assert_eq!(decoded.payload(), &[0xaa]);
        assert_eq!(decoded.padding(), &[0xbb, 0xcc, 0x00]);

        Ok(())
    }

    #[test]
    fn tls_heartbeat_decode_reports_malformed_lengths() {
        assert_eq!(
            TlsHeartbeat::decode([0x01, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short("tls.heartbeat.header", TLS_HEARTBEAT_HEADER_LEN, 2)
        );
        assert_eq!(
            TlsHeartbeat::decode([0x01, 0x00, 0x04, 0xaa]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.heartbeat.payload",
                TLS_HEARTBEAT_HEADER_LEN + 4,
                TLS_HEARTBEAT_HEADER_LEN + 1
            )
        );
    }
}
