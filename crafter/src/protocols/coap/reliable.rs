//! Reliable-transport CoAP framing primitives.
//!
//! RFC 8323 Section 3.2 supplies the reliable message-length grammar. RFC
//! 8974 updates the TKL grammar shared by datagram and reliable messages. The
//! decoder below identifies exactly one complete frame; it never buffers or
//! searches a transport stream.

use std::sync::OnceLock;

use crate::error::{CrafterError, Result};
use crate::field::{Field, FieldState};
use crate::packet::{Layer, LayerContext};
use crate::protocols::transport::common::{impl_layer_div, impl_layer_object};

use super::constants::COAP_PAYLOAD_MARKER;
use super::decode::{decode_token_boundary, DecodedTokenBoundary, TokenDecodeContext};
use super::message::{CoapCode, CoapPayloadMarker, CoapToken, CoapTokenLength};
use super::option::{encode_option_sequence, CoapOption, CoapOptions};

const RELIABLE_DIRECT_MAX_BODY_LEN: usize = 12;
const RELIABLE_EXTENDED8_MIN_BODY_LEN: usize = 13;
const RELIABLE_EXTENDED8_MAX_BODY_LEN: usize = 268;
const RELIABLE_EXTENDED16_MIN_BODY_LEN: usize = 269;
const RELIABLE_EXTENDED16_MAX_BODY_LEN: usize = 65_804;
const RELIABLE_EXTENDED32_MIN_BODY_LEN: usize = 65_805;

/// Lossless RFC 8323 reliable-message body-length metadata.
///
/// The discriminator, extension bytes, and declared body length remain
/// independent so the typed layer can preserve caller-supplied malformed
/// overrides without repairing them during compilation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CoapReliableLength {
    nibble: u8,
    extension_bytes: Vec<u8>,
    declared_body_len: usize,
}

impl CoapReliableLength {
    /// Build the shortest RFC 8323 representation for `body_len`.
    pub fn canonical_for_body_len(body_len: usize) -> Result<Self> {
        match body_len {
            0..=RELIABLE_DIRECT_MAX_BODY_LEN => {
                Ok(Self::explicit(body_len as u8, Vec::new(), body_len))
            }
            RELIABLE_EXTENDED8_MIN_BODY_LEN..=RELIABLE_EXTENDED8_MAX_BODY_LEN => {
                Ok(Self::explicit(
                    13,
                    vec![(body_len - RELIABLE_EXTENDED8_MIN_BODY_LEN) as u8],
                    body_len,
                ))
            }
            RELIABLE_EXTENDED16_MIN_BODY_LEN..=RELIABLE_EXTENDED16_MAX_BODY_LEN => {
                Ok(Self::explicit(
                    14,
                    ((body_len - RELIABLE_EXTENDED16_MIN_BODY_LEN) as u16)
                        .to_be_bytes()
                        .to_vec(),
                    body_len,
                ))
            }
            _ => {
                let extension = body_len
                    .checked_sub(RELIABLE_EXTENDED32_MIN_BODY_LEN)
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or_else(reliable_length_range_error)?;
                Ok(Self::explicit(
                    15,
                    extension.to_be_bytes().to_vec(),
                    body_len,
                ))
            }
        }
    }

    /// Preserve explicit length metadata without requiring its parts to agree.
    pub fn explicit(
        nibble: u8,
        extension_bytes: impl Into<Vec<u8>>,
        declared_body_len: usize,
    ) -> Self {
        Self {
            nibble,
            extension_bytes: extension_bytes.into(),
            declared_body_len,
        }
    }

    /// Return the preserved four-bit Len discriminator without masking.
    pub const fn nibble(&self) -> u8 {
        self.nibble
    }

    /// Borrow the exact preserved Len extension bytes.
    pub fn extension_bytes(&self) -> &[u8] {
        &self.extension_bytes
    }

    /// Return the preserved logical body length.
    pub const fn declared_body_len(&self) -> usize {
        self.declared_body_len
    }

    /// Decode a body length from the preserved wire representation.
    pub(super) fn wire_body_len(&self) -> Result<usize> {
        match (self.nibble, self.extension_bytes.as_slice()) {
            (nibble @ 0..=12, []) => Ok(usize::from(nibble)),
            (13, [extension]) => RELIABLE_EXTENDED8_MIN_BODY_LEN
                .checked_add(usize::from(*extension))
                .ok_or_else(reliable_length_overflow_error),
            (14, [high, low]) => RELIABLE_EXTENDED16_MIN_BODY_LEN
                .checked_add(usize::from(u16::from_be_bytes([*high, *low])))
                .ok_or_else(reliable_length_overflow_error),
            (15, [first, second, third, fourth]) => {
                let extension = u32::from_be_bytes([*first, *second, *third, *fourth]);
                let extension =
                    usize::try_from(extension).map_err(|_| reliable_length_overflow_error())?;
                RELIABLE_EXTENDED32_MIN_BODY_LEN
                    .checked_add(extension)
                    .ok_or_else(reliable_length_overflow_error)
            }
            (0..=12, _) => Err(CrafterError::invalid_field_value(
                "coap.reliable.length",
                "direct Len encoding must not contain extension bytes",
            )),
            (13, _) => Err(CrafterError::invalid_field_value(
                "coap.reliable.length",
                "Len 13 encoding requires exactly one extension byte",
            )),
            (14, _) => Err(CrafterError::invalid_field_value(
                "coap.reliable.length",
                "Len 14 encoding requires exactly two extension bytes",
            )),
            (15, _) => Err(CrafterError::invalid_field_value(
                "coap.reliable.length",
                "Len 15 encoding requires exactly four extension bytes",
            )),
            (_, _) => Err(CrafterError::invalid_field_value(
                "coap.reliable.length",
                "Len discriminator exceeds four bits",
            )),
        }
    }

    pub(super) fn declared_frame_len(&self, token_length: &CoapTokenLength) -> Result<usize> {
        checked_reliable_frame_len(
            self.extension_bytes.len(),
            token_length.extension_bytes().len(),
            token_length.declared_len(),
            self.declared_body_len,
        )
    }

    fn encode_extension(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.extension_bytes);
    }
}

impl Default for CoapReliableLength {
    fn default() -> Self {
        Self::explicit(0, Vec::new(), 0)
    }
}

static EMPTY_RELIABLE_TOKEN: OnceLock<CoapToken> = OnceLock::new();

/// One owned RFC 8323 message supplied at a complete-frame boundary.
///
/// Reliable CoAP omits the datagram Version, Type, and Message ID fields.
/// Length metadata, token-length metadata, code, token, options, payload
/// marker, and payload remain independent so explicit malformed values can be
/// inspected and preserved without introducing TCP stream state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoapReliable {
    length: Field<CoapReliableLength>,
    token_length: Field<CoapTokenLength>,
    code: Field<CoapCode>,
    token: Field<CoapToken>,
    options: Vec<CoapOption>,
    payload_marker: Field<CoapPayloadMarker>,
    payload: Vec<u8>,
}

impl CoapReliable {
    fn unset() -> Self {
        Self {
            length: Field::unset(),
            token_length: Field::unset(),
            code: Field::unset(),
            token: Field::unset(),
            options: Vec::new(),
            payload_marker: Field::unset(),
            payload: Vec::new(),
        }
    }

    /// Create a reliable CoAP message with an explicit Code.
    pub fn new(code: impl Into<CoapCode>) -> Self {
        Self::unset().code(code)
    }

    /// Build an ordinary reliable-transport request with an explicit Code.
    ///
    /// The code is retained without semantic restriction so unknown, future,
    /// and deliberately role-inappropriate values remain constructible.
    pub fn request(code: CoapCode) -> Self {
        Self::new(code)
    }

    /// Build an ordinary reliable-transport response with an explicit Code.
    pub fn response(code: CoapCode) -> Self {
        Self::new(code)
    }

    /// Build a Capabilities and Settings Message (`7.01`).
    pub fn csm() -> Self {
        Self::new(CoapCode::csm())
    }

    /// Build a Ping signaling message (`7.02`).
    pub fn ping() -> Self {
        Self::new(CoapCode::ping())
    }

    /// Build a Pong signaling message (`7.03`).
    pub fn pong() -> Self {
        Self::new(CoapCode::pong())
    }

    /// Build a Release signaling message (`7.04`).
    pub fn release() -> Self {
        Self::new(CoapCode::release())
    }

    /// Build an Abort signaling message (`7.05`).
    pub fn abort() -> Self {
        Self::new(CoapCode::abort())
    }

    /// Set explicit Len metadata independently from the owned frame body.
    pub fn length(mut self, value: CoapReliableLength) -> Self {
        self.length.set_user(value);
        self
    }

    /// Set explicit token-length metadata independently from the token bytes.
    pub fn token_length(mut self, value: CoapTokenLength) -> Self {
        self.token_length.set_user(value);
        self
    }

    /// Set the exact one-octet Code value.
    pub fn code(mut self, value: impl Into<CoapCode>) -> Self {
        self.code.set_user(value.into());
        self
    }

    /// Set owned token bytes independently from token-length metadata.
    pub fn token(mut self, value: impl Into<CoapToken>) -> Self {
        self.token.set_user(value.into());
        self
    }

    /// Append one option while retaining occurrence order.
    pub fn option(mut self, value: impl Into<CoapOption>) -> Self {
        self.options.push(value.into());
        self
    }

    /// Replace the ordered option sequence.
    pub fn options(mut self, values: impl IntoIterator<Item = CoapOption>) -> Self {
        self.options = values.into_iter().collect();
        self
    }

    /// Set an explicit payload-marker choice independently from payload bytes.
    pub fn payload_marker(mut self, value: CoapPayloadMarker) -> Self {
        self.payload_marker.set_user(value);
        self
    }

    /// Set the exact owned binary payload.
    pub fn payload(mut self, value: impl Into<Vec<u8>>) -> Self {
        self.payload = value.into();
        self
    }

    /// Return the reliable Len metadata field state.
    pub const fn length_state(&self) -> FieldState {
        self.length.state()
    }

    /// Return explicit Len metadata or derive it from the encoded frame body.
    pub fn length_value(&self) -> Result<CoapReliableLength> {
        match self.length.value() {
            Some(value) => Ok(value.clone()),
            None => CoapReliableLength::canonical_for_body_len(self.encoded_body_len()?),
        }
    }

    /// Return the token-length metadata field state.
    pub const fn token_length_state(&self) -> FieldState {
        self.token_length.state()
    }

    /// Return explicit token-length metadata or derive it from owned bytes.
    pub fn token_length_value(&self) -> Result<CoapTokenLength> {
        match self.token_length.value() {
            Some(value) => Ok(value.clone()),
            None => CoapTokenLength::canonical_for_len(self.token_value().len()),
        }
    }

    /// Return the Code field state.
    pub const fn code_state(&self) -> FieldState {
        self.code.state()
    }

    /// Return the explicit Code or the Empty compile-time default.
    pub fn code_value(&self) -> CoapCode {
        self.code.value().copied().unwrap_or_default()
    }

    /// Return the token field state.
    pub const fn token_state(&self) -> FieldState {
        self.token.state()
    }

    /// Borrow explicit token bytes or the effective empty token.
    pub fn token_value(&self) -> &CoapToken {
        self.token
            .value()
            .unwrap_or_else(|| EMPTY_RELIABLE_TOKEN.get_or_init(CoapToken::default))
    }

    /// Borrow option occurrences in their retained order.
    pub fn options_value(&self) -> &[CoapOption] {
        &self.options
    }

    /// Return the payload-marker field state.
    pub const fn payload_marker_state(&self) -> FieldState {
        self.payload_marker.state()
    }

    /// Return the explicit marker choice or derive it from payload presence.
    pub fn payload_marker_value(&self) -> CoapPayloadMarker {
        self.payload_marker.value().copied().unwrap_or_else(|| {
            if self.payload.is_empty() {
                CoapPayloadMarker::Absent
            } else {
                CoapPayloadMarker::Present
            }
        })
    }

    /// Borrow the exact owned payload bytes.
    pub fn payload_value(&self) -> &[u8] {
        &self.payload
    }

    fn encoded_options(&self) -> Result<Vec<u8>> {
        let mut options = CoapOptions::from_options(self.options.iter().cloned());
        options.sort_canonical();

        let mut encoded = Vec::new();
        encode_option_sequence(&options, &mut encoded)?;
        Ok(encoded)
    }

    fn encoded_body_len(&self) -> Result<usize> {
        self.encoded_options()?
            .len()
            .checked_add(usize::from(self.payload_marker_value().is_present()))
            .and_then(|value| value.checked_add(self.payload.len()))
            .ok_or_else(reliable_length_overflow_error)
    }

    fn length_inspection_label(&self) -> String {
        self.length_value()
            .map(|length| length.declared_body_len().to_string())
            .unwrap_or_else(|_| "invalid".to_string())
    }

    fn code_inspection_label(&self) -> String {
        let code = self.code_value();
        format!("{}({})", code.label(), code.registry_meta().label)
    }

    fn token_length_inspection_label(&self) -> String {
        let actual_len = self.token_value().len();
        let Ok(token_length) = self.token_length_value() else {
            return format!("{actual_len} [unset-invalid]");
        };

        if self.token_length_state() == FieldState::User
            && token_length.declared_len() != actual_len
        {
            format!(
                "{} [explicit-mismatch:nibble={},actual={actual_len}]",
                token_length.declared_len(),
                token_length.nibble()
            )
        } else {
            token_length.declared_len().to_string()
        }
    }

    fn payload_marker_inspection_label(&self) -> String {
        let marker = self.payload_marker_value();
        let label = if marker.is_present() {
            "present"
        } else {
            "absent"
        };
        let mismatch = self.payload_marker_state() == FieldState::User
            && marker.is_present() != !self.payload.is_empty();

        if mismatch {
            format!("{label} [explicit-mismatch]")
        } else {
            label.to_string()
        }
    }
}

impl Default for CoapReliable {
    fn default() -> Self {
        Self::unset()
    }
}

impl Layer for CoapReliable {
    fn name(&self) -> &'static str {
        "CoapReliable"
    }

    fn summary(&self) -> String {
        format!(
            "CoapReliable(length={}, code={}, token_len={}, options={}, marker={}, payload={} bytes)",
            self.length_inspection_label(),
            self.code_inspection_label(),
            self.token_length_inspection_label(),
            self.options.len(),
            self.payload_marker_inspection_label(),
            self.payload.len()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("length", self.length_inspection_label()),
            ("token_length", self.token_length_inspection_label()),
            ("code", self.code_inspection_label()),
            (
                "token",
                format!(
                    "len={} hex={}",
                    self.token_value().len(),
                    self.token_value()
                ),
            ),
            ("options", self.options.len().to_string()),
            ("payload_marker", self.payload_marker_inspection_label()),
            ("payload_length", self.payload.len().to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        let Ok(options) = self.encoded_options() else {
            return 0;
        };
        let Ok(length) = self.length_value() else {
            return 0;
        };
        let Ok(token_length) = self.token_length_value() else {
            return 0;
        };
        let Some(body_len) = options
            .len()
            .checked_add(usize::from(self.payload_marker_value().is_present()))
            .and_then(|value| value.checked_add(self.payload.len()))
        else {
            return 0;
        };

        checked_reliable_frame_len(
            length.extension_bytes().len(),
            token_length.extension_bytes().len(),
            self.token_value().len(),
            body_len,
        )
        .unwrap_or_default()
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        let options = self.encoded_options()?;
        let token_length = self.token_length_value()?;
        let body_len = options
            .len()
            .checked_add(usize::from(self.payload_marker_value().is_present()))
            .and_then(|value| value.checked_add(self.payload.len()))
            .ok_or_else(reliable_length_overflow_error)?;
        let length = match self.length.value() {
            Some(length) => length.clone(),
            None => CoapReliableLength::canonical_for_body_len(body_len)?,
        };
        let encoded_len = checked_reliable_frame_len(
            length.extension_bytes().len(),
            token_length.extension_bytes().len(),
            self.token_value().len(),
            body_len,
        )?;
        let mut encoded = Vec::with_capacity(encoded_len);

        encode_reliable_header(
            &length,
            &token_length,
            self.code_value(),
            self.token_value(),
            &mut encoded,
        )?;
        encoded.extend_from_slice(&options);
        if self.payload_marker_value().is_present() {
            encoded.push(COAP_PAYLOAD_MARKER);
        }
        encoded.extend_from_slice(&self.payload);
        out.extend_from_slice(&encoded);
        Ok(())
    }

    impl_layer_object!(CoapReliable);
}

impl_layer_div!(CoapReliable);

/// The checked byte boundaries of one complete reliable CoAP frame.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DecodedReliableFrameBoundary<'a> {
    pub(super) length: CoapReliableLength,
    pub(super) token_length: CoapTokenLength,
    pub(super) code: CoapCode,
    pub(super) token: &'a [u8],
    pub(super) body: &'a [u8],
    /// Bytes through the Len/TKL octet and optional Len extension.
    pub(super) length_header_len: usize,
    /// Bytes through Code, optional TKL extension, and Token.
    pub(super) header_len: usize,
    /// Exact boundary immediately after this frame's declared body.
    pub(super) frame_len: usize,
}

/// Encode the complete framing header through the Token boundary.
///
/// Exact Len and TKL extension bytes are copied without normalization. The
/// returned length is the number of bytes appended before the body.
#[allow(dead_code)]
pub(super) fn encode_reliable_header(
    length: &CoapReliableLength,
    token_length: &CoapTokenLength,
    code: CoapCode,
    token: &CoapToken,
    out: &mut Vec<u8>,
) -> Result<usize> {
    let header_len = checked_reliable_frame_len(
        length.extension_bytes().len(),
        token_length.extension_bytes().len(),
        token.len(),
        0,
    )?;
    let mut encoded = Vec::with_capacity(header_len);
    encoded.push(((length.nibble() & 0x0f) << 4) | (token_length.nibble() & 0x0f));
    length.encode_extension(&mut encoded);
    encoded.push(code.wire_value());
    encode_reliable_token(token_length, token, &mut encoded)?;
    out.extend_from_slice(&encoded);
    Ok(header_len)
}

/// Decode the boundaries and borrowed fields of exactly one reliable frame.
///
/// Bytes after `frame_len` belong to a following frame or to caller-owned
/// trailing data and are never included in `body`.
#[allow(dead_code)]
pub(super) fn decode_reliable_frame_boundary(
    bytes: &[u8],
) -> Result<DecodedReliableFrameBoundary<'_>> {
    let first = *bytes
        .first()
        .ok_or_else(|| CrafterError::buffer_too_short("coap.reliable.header", 1, bytes.len()))?;
    let length_nibble = first >> 4;
    let token_length_nibble = first & 0x0f;
    let after_first = bytes.get(1..).unwrap_or_default();
    let (length, length_extension_len) = decode_reliable_length(length_nibble, after_first)?;
    let length_header_len = 1usize
        .checked_add(length_extension_len)
        .ok_or_else(reliable_length_overflow_error)?;
    let after_length = bytes.get(length_header_len..).unwrap_or_default();
    let code = *after_length.first().ok_or_else(|| {
        CrafterError::buffer_too_short("coap.reliable.code", 1, after_length.len())
    })?;
    let after_code = after_length.get(1..).unwrap_or_default();
    let decoded_token = decode_reliable_token(token_length_nibble, after_code)?;
    let header_len = length_header_len
        .checked_add(1)
        .and_then(|value| value.checked_add(decoded_token.consumed))
        .ok_or_else(reliable_length_overflow_error)?;
    let body_len = length.declared_body_len();
    let after_header = bytes.get(header_len..).unwrap_or_default();
    let body = after_header.get(..body_len).ok_or_else(|| {
        CrafterError::buffer_too_short("coap.reliable.body", body_len, after_header.len())
    })?;
    let frame_len = header_len
        .checked_add(body_len)
        .ok_or_else(reliable_length_overflow_error)?;

    Ok(DecodedReliableFrameBoundary {
        length,
        token_length: decoded_token.token_length,
        code: CoapCode::from_wire(code),
        token: decoded_token.token,
        body,
        length_header_len,
        header_len,
        frame_len,
    })
}

fn decode_reliable_length(
    nibble: u8,
    bytes_after_first: &[u8],
) -> Result<(CoapReliableLength, usize)> {
    let (extension_bytes, extension_len) = match nibble {
        0..=12 => (Vec::new(), 0),
        13 => {
            let extension = bytes_after_first.first().ok_or_else(|| {
                CrafterError::buffer_too_short(
                    "coap.reliable.length.extended8",
                    1,
                    bytes_after_first.len(),
                )
            })?;
            (vec![*extension], 1)
        }
        14 => {
            let extension = bytes_after_first.get(..2).ok_or_else(|| {
                CrafterError::buffer_too_short(
                    "coap.reliable.length.extended16",
                    2,
                    bytes_after_first.len(),
                )
            })?;
            (extension.to_vec(), 2)
        }
        15 => {
            let extension = bytes_after_first.get(..4).ok_or_else(|| {
                CrafterError::buffer_too_short(
                    "coap.reliable.length.extended32",
                    4,
                    bytes_after_first.len(),
                )
            })?;
            (extension.to_vec(), 4)
        }
        _ => {
            return Err(CrafterError::invalid_field_value(
                "coap.reliable.length",
                "Len discriminator exceeds four bits",
            ))
        }
    };
    let length = CoapReliableLength::explicit(nibble, extension_bytes, 0);
    let declared_body_len = length.wire_body_len()?;

    Ok((
        CoapReliableLength::explicit(nibble, length.extension_bytes().to_vec(), declared_body_len),
        extension_len,
    ))
}

fn checked_reliable_frame_len(
    length_extension_len: usize,
    token_extension_len: usize,
    token_len: usize,
    body_len: usize,
) -> Result<usize> {
    1usize
        .checked_add(length_extension_len)
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(token_extension_len))
        .and_then(|value| value.checked_add(token_len))
        .and_then(|value| value.checked_add(body_len))
        .ok_or_else(reliable_length_overflow_error)
}

fn reliable_length_overflow_error() -> CrafterError {
    CrafterError::invalid_field_value("coap.reliable.length", "reliable frame length overflow")
}

fn reliable_length_range_error() -> CrafterError {
    CrafterError::invalid_field_value(
        "coap.reliable.length",
        "body length exceeds the RFC 8323 encoding range",
    )
}

/// Encode the exact TKL extension followed by all owned Token bytes.
///
/// Canonical metadata supplies the shortest RFC 8974 extension. Explicit
/// metadata is copied without repair even when its discriminator, extension,
/// declared length, and owned token disagree.
#[allow(dead_code)]
pub(super) fn encode_reliable_token(
    token_length: &CoapTokenLength,
    token: &CoapToken,
    out: &mut Vec<u8>,
) -> Result<usize> {
    let consumed = token_length
        .extension_bytes()
        .len()
        .checked_add(token.len())
        .ok_or_else(|| {
            CrafterError::invalid_field_value(
                "coap.reliable.token-length",
                "encoded token boundary overflow",
            )
        })?;

    token_length.encode_extension(out);
    out.extend_from_slice(token.as_bytes());
    Ok(consumed)
}

/// Decode the TKL extension and complete Token at a reliable-frame boundary.
#[allow(dead_code)]
pub(super) fn decode_reliable_token(
    nibble: u8,
    bytes_after_code: &[u8],
) -> Result<DecodedTokenBoundary<'_>> {
    decode_token_boundary(nibble, bytes_after_code, TokenDecodeContext::RELIABLE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Packet;
    use crate::protocols::transport::Tcp;

    #[test]
    fn reliable_default_keeps_override_aware_fields_unset() {
        let message = CoapReliable::default();

        assert_eq!(message.length_state(), FieldState::Unset);
        assert_eq!(
            message.length_value().unwrap(),
            CoapReliableLength::default()
        );
        assert_eq!(message.token_length_state(), FieldState::Unset);
        assert_eq!(
            message.token_length_value().unwrap(),
            CoapTokenLength::default()
        );
        assert_eq!(message.code_state(), FieldState::Unset);
        assert_eq!(message.code_value(), CoapCode::empty());
        assert_eq!(message.token_state(), FieldState::Unset);
        assert!(message.token_value().is_empty());
        assert!(message.options_value().is_empty());
        assert_eq!(message.payload_marker_state(), FieldState::Unset);
        assert_eq!(message.payload_marker_value(), CoapPayloadMarker::Absent);
        assert!(message.payload_value().is_empty());
    }

    #[test]
    fn reliable_constructors_pin_only_the_supplied_code() {
        let cases = [
            (CoapReliable::request(CoapCode::get()), CoapCode::get()),
            (
                CoapReliable::response(CoapCode::content()),
                CoapCode::content(),
            ),
            (CoapReliable::csm(), CoapCode::csm()),
            (CoapReliable::ping(), CoapCode::ping()),
            (CoapReliable::pong(), CoapCode::pong()),
            (CoapReliable::release(), CoapCode::release()),
            (CoapReliable::abort(), CoapCode::abort()),
            (
                CoapReliable::new(CoapCode::from_wire(0xff)),
                CoapCode::from_wire(0xff),
            ),
        ];

        for (message, expected_code) in cases {
            assert_eq!(message.code_state(), FieldState::User);
            assert_eq!(message.code_value(), expected_code);
            assert_eq!(message.length_state(), FieldState::Unset);
            assert_eq!(message.token_length_state(), FieldState::Unset);
            assert_eq!(message.token_state(), FieldState::Unset);
            assert_eq!(message.payload_marker_state(), FieldState::Unset);
        }
    }

    #[test]
    fn reliable_builders_preserve_independent_explicit_state_and_order() {
        let length = CoapReliableLength::explicit(0xfe, vec![0xaa, 0xbb], usize::MAX);
        let token_length = CoapTokenLength::explicit(0xfd, vec![0xcc], 999);
        let first = CoapOption::new(15u16, b"a=1".to_vec());
        let second = CoapOption::new(11u16, b"status".to_vec());
        let message = CoapReliable::request(CoapCode::get())
            .length(length.clone())
            .token_length(token_length.clone())
            .code(0xffu8)
            .token(CoapToken::from_bytes([1, 2, 3]))
            .option(CoapOption::new(12u16, vec![0]))
            .options([first.clone(), second.clone()])
            .payload_marker(CoapPayloadMarker::Absent)
            .payload([0xff, 0x00]);

        assert_eq!(message.length_state(), FieldState::User);
        assert_eq!(message.length_value().unwrap(), length);
        assert_eq!(message.token_length_state(), FieldState::User);
        assert_eq!(message.token_length_value().unwrap(), token_length);
        assert_eq!(message.code_state(), FieldState::User);
        assert_eq!(message.code_value(), CoapCode::from_wire(0xff));
        assert_eq!(message.token_state(), FieldState::User);
        assert_eq!(message.token_value().as_bytes(), &[1, 2, 3]);
        assert_eq!(message.options_value(), &[first, second]);
        assert_eq!(message.payload_marker_state(), FieldState::User);
        assert_eq!(message.payload_marker_value(), CoapPayloadMarker::Absent);
        assert_eq!(message.payload_value(), &[0xff, 0x00]);
    }

    #[test]
    fn reliable_layer_downcasts_and_composes_after_tcp() {
        let message = CoapReliable::ping().token(CoapToken::from_bytes([0xaa, 0xbb]));
        let packet = Tcp::new() / message.clone();

        assert_eq!(packet.len(), 2);
        assert!(packet.layer::<Tcp>().is_some());
        assert_eq!(packet.layer::<CoapReliable>(), Some(&message));
        assert_eq!(
            packet.get(1).expect("reliable CoAP layer").name(),
            "CoapReliable"
        );
        assert_eq!(packet.clone().layer::<CoapReliable>(), Some(&message));
    }

    #[test]
    fn reliable_layer_uses_the_frozen_inspection_shape() {
        let message = CoapReliable::csm();

        assert_eq!(
            message.summary(),
            "CoapReliable(length=0, code=7.01(CSM), token_len=0, options=0, marker=absent, payload=0 bytes)"
        );
        assert_eq!(
            message
                .inspection_fields()
                .into_iter()
                .map(|(name, _)| name)
                .collect::<Vec<_>>(),
            [
                "length",
                "token_length",
                "code",
                "token",
                "options",
                "payload_marker",
                "payload_length",
            ]
        );
    }

    #[test]
    fn reliable_compile_emits_short_frame_with_canonical_options() {
        let message = CoapReliable::request(CoapCode::get())
            .option(CoapOption::new(15u16, b"a=1".to_vec()))
            .option(CoapOption::new(11u16, b"status".to_vec()));
        let packet = Packet::from_layer(message.clone());
        let expected = [
            0xb0, 0x01, 0xb6, b's', b't', b'a', b't', b'u', b's', 0x43, b'a', b'=', b'1',
        ];

        assert_eq!(message.length_value().unwrap().declared_body_len(), 11);
        assert_eq!(packet.encoded_len(), expected.len());
        assert_eq!(packet.compile().unwrap().as_bytes(), expected);
    }

    #[test]
    fn reliable_compile_selects_each_extended_length_form_exactly() {
        let cases = [
            (12usize, vec![0xd0, 0x00, 0x45]),
            (268usize, vec![0xe0, 0x00, 0x00, 0x45]),
            (65_804usize, vec![0xf0, 0x00, 0x00, 0x00, 0x00, 0x45]),
        ];

        for (payload_len, mut expected) in cases {
            let message =
                CoapReliable::response(CoapCode::content()).payload(vec![0xa5; payload_len]);
            expected.push(COAP_PAYLOAD_MARKER);
            expected.extend(std::iter::repeat(0xa5).take(payload_len));
            let packet = Packet::from_layer(message.clone());

            assert_eq!(
                message.length_value().unwrap().declared_body_len(),
                payload_len + 1
            );
            assert_eq!(packet.encoded_len(), expected.len());
            assert_eq!(packet.compile().unwrap().as_bytes(), expected);
        }
    }

    #[test]
    fn reliable_compile_encodes_long_token_outside_len_body() {
        let message =
            CoapReliable::request(CoapCode::get()).token(CoapToken::from_bytes(vec![0xa5; 13]));
        let mut expected = vec![0x0d, 0x01, 0x00];
        expected.extend(std::iter::repeat(0xa5).take(13));
        let packet = Packet::from_layer(message.clone());

        assert_eq!(message.length_value().unwrap().declared_body_len(), 0);
        assert_eq!(message.token_length_value().unwrap().nibble(), 13);
        assert_eq!(packet.encoded_len(), expected.len());
        assert_eq!(packet.compile().unwrap().as_bytes(), expected);
    }

    #[test]
    fn reliable_compile_preserves_explicit_mismatches_and_raw_extensions() {
        let message = CoapReliable::response(CoapCode::content())
            .length(CoapReliableLength::explicit(0xfe, vec![0xaa], usize::MAX))
            .token_length(CoapTokenLength::explicit(0xfd, vec![0xca, 0xfe], 999))
            .token(CoapToken::from_bytes([1, 2, 3]))
            .option(CoapOption::new(15u16, b"a".to_vec()))
            .option(CoapOption::new(11u16, b"x".to_vec()))
            .payload_marker(CoapPayloadMarker::Absent)
            .payload([0xff, 0x00]);
        let packet = Packet::from_layer(message.clone());
        let expected = [
            0xed, 0xaa, 0x45, 0xca, 0xfe, 0x01, 0x02, 0x03, 0xb1, b'x', 0x41, b'a', 0xff, 0x00,
        ];

        assert_eq!(message.length_value().unwrap().nibble(), 0xfe);
        assert_eq!(message.token_length_value().unwrap().nibble(), 0xfd);
        assert_eq!(packet.encoded_len(), expected.len());
        assert_eq!(packet.compile().unwrap().as_bytes(), expected);
    }

    fn encode_complete_frame(body_len: usize, token_len: usize) -> Vec<u8> {
        let length = CoapReliableLength::canonical_for_body_len(body_len).unwrap();
        let token_length = CoapTokenLength::canonical_for_len(token_len).unwrap();
        let token = CoapToken::from_bytes(vec![0xa5; token_len]);
        let mut bytes = Vec::new();
        encode_reliable_header(&length, &token_length, CoapCode::get(), &token, &mut bytes)
            .unwrap();
        bytes.extend(std::iter::repeat(0xb0).take(body_len));
        bytes
    }

    #[test]
    fn reliable_length_transitions_encode_and_decode_exact_boundaries() {
        let cases: &[(usize, u8, &[u8])] = &[
            (0, 0, &[]),
            (12, 12, &[]),
            (13, 13, &[0x00]),
            (268, 13, &[0xff]),
            (269, 14, &[0x00, 0x00]),
            (65_804, 14, &[0xff, 0xff]),
            (65_805, 15, &[0x00, 0x00, 0x00, 0x00]),
        ];

        for &(body_len, nibble, extension) in cases {
            let bytes = encode_complete_frame(body_len, 0);
            let decoded = decode_reliable_frame_boundary(&bytes).unwrap();

            assert_eq!(decoded.length.nibble(), nibble);
            assert_eq!(decoded.length.extension_bytes(), extension);
            assert_eq!(decoded.length.declared_body_len(), body_len);
            assert_eq!(decoded.length.wire_body_len().unwrap(), body_len);
            assert_eq!(decoded.length_header_len, 1 + extension.len());
            assert_eq!(decoded.header_len, 2 + extension.len());
            assert_eq!(decoded.frame_len, bytes.len());
            assert_eq!(decoded.body.len(), body_len);
            assert_eq!(decoded.code, CoapCode::get());
        }
    }

    #[test]
    fn extended32_length_covers_its_full_wire_range_without_allocation() {
        let maximum = u64::from(u32::MAX) + RELIABLE_EXTENDED32_MIN_BODY_LEN as u64;
        let maximum = usize::try_from(maximum).expect("64-bit test target");
        let length = CoapReliableLength::canonical_for_body_len(maximum).unwrap();

        assert_eq!(length.nibble(), 15);
        assert_eq!(length.extension_bytes(), &[0xff; 4]);
        assert_eq!(length.wire_body_len().unwrap(), maximum);
        assert_eq!(length.declared_body_len(), maximum);
        assert!(CoapReliableLength::canonical_for_body_len(maximum + 1).is_err());
    }

    #[test]
    fn reliable_token_boundaries_stop_before_body_at_every_transition() {
        let cases: &[(usize, u8, &[u8])] = &[
            (0, 0, &[]),
            (8, 8, &[]),
            (12, 12, &[]),
            (13, 13, &[0x00]),
            (268, 13, &[0xff]),
            (269, 14, &[0x00, 0x00]),
            (CoapTokenLength::MAX_LEN, 14, &[0xff, 0xff]),
        ];

        for &(token_len, nibble, extension) in cases {
            let mut bytes = encode_complete_frame(1, token_len);
            bytes.extend_from_slice(&[0xcc, 0xdd]);
            let decoded = decode_reliable_frame_boundary(&bytes).unwrap();

            assert_eq!(decoded.token_length.nibble(), nibble);
            assert_eq!(decoded.token_length.extension_bytes(), extension);
            assert_eq!(decoded.token_length.declared_len(), token_len);
            assert_eq!(decoded.token, vec![0xa5; token_len]);
            assert_eq!(decoded.body, &[0xb0]);
            assert_eq!(decoded.header_len, 2 + extension.len() + token_len);
            assert_eq!(&bytes[decoded.frame_len..], &[0xcc, 0xdd]);
        }
    }

    #[test]
    fn reliable_decoder_leaves_complete_following_frames_unconsumed() {
        let first = encode_complete_frame(2, 1);
        let second = encode_complete_frame(0, 0);
        let mut stream_slice = first.clone();
        stream_slice.extend_from_slice(&second);

        let decoded = decode_reliable_frame_boundary(&stream_slice).unwrap();

        assert_eq!(decoded.frame_len, first.len());
        assert_eq!(decoded.body, &[0xb0, 0xb0]);
        assert_eq!(&stream_slice[decoded.frame_len..], second);
    }

    #[test]
    fn reliable_header_encoding_preserves_explicit_extensions_exactly() {
        let length = CoapReliableLength::explicit(13, vec![0xfe, 0xed], usize::MAX);
        let token_length = CoapTokenLength::explicit(13, vec![0xca, 0xfe], usize::MAX);
        let token = CoapToken::from_bytes([0xaa, 0xbb]);
        let mut encoded = Vec::new();

        assert_eq!(
            encode_reliable_header(
                &length,
                &token_length,
                CoapCode::from_wire(0xe1),
                &token,
                &mut encoded,
            )
            .unwrap(),
            8,
        );
        assert_eq!(encoded, [0xdd, 0xfe, 0xed, 0xe1, 0xca, 0xfe, 0xaa, 0xbb]);
    }

    #[test]
    fn reliable_truncation_reports_each_stable_boundary() {
        let cases = [
            (
                Vec::new(),
                CrafterError::buffer_too_short("coap.reliable.header", 1, 0),
            ),
            (
                vec![0xd0],
                CrafterError::buffer_too_short("coap.reliable.length.extended8", 1, 0),
            ),
            (
                vec![0xe0, 0x00],
                CrafterError::buffer_too_short("coap.reliable.length.extended16", 2, 1),
            ),
            (
                vec![0xf0, 0x00, 0x00, 0x00],
                CrafterError::buffer_too_short("coap.reliable.length.extended32", 4, 3),
            ),
            (
                vec![0x00],
                CrafterError::buffer_too_short("coap.reliable.code", 1, 0),
            ),
            (
                vec![0x0d, 0x01],
                CrafterError::buffer_too_short("coap.reliable.token-length.extended8", 1, 0),
            ),
            (
                vec![0x0e, 0x01, 0x00],
                CrafterError::buffer_too_short("coap.reliable.token-length.extended16", 2, 1),
            ),
            (
                vec![0x02, 0x01, 0xaa],
                CrafterError::buffer_too_short("coap.reliable.token", 2, 1),
            ),
            (
                vec![0x30, 0x01, 0xaa, 0xbb],
                CrafterError::buffer_too_short("coap.reliable.body", 3, 2),
            ),
        ];

        for (bytes, expected) in cases {
            assert_eq!(decode_reliable_frame_boundary(&bytes), Err(expected));
        }
    }

    #[test]
    fn reliable_length_arithmetic_reports_overflow() {
        assert_eq!(
            checked_reliable_frame_len(usize::MAX, 0, 0, 0),
            Err(reliable_length_overflow_error())
        );
        assert_eq!(
            CoapReliableLength::explicit(0, Vec::new(), usize::MAX)
                .declared_frame_len(&CoapTokenLength::default()),
            Err(reliable_length_overflow_error())
        );
        assert_eq!(
            CoapReliableLength::explicit(0, Vec::new(), 0)
                .declared_frame_len(&CoapTokenLength::explicit(0, Vec::new(), usize::MAX),),
            Err(reliable_length_overflow_error())
        );
    }

    #[test]
    fn reliable_token_failures_use_stable_reliable_contexts() {
        assert_eq!(
            decode_reliable_token(13, &[]),
            Err(CrafterError::buffer_too_short(
                "coap.reliable.token-length.extended8",
                1,
                0,
            ))
        );
        assert_eq!(
            decode_reliable_token(14, &[0x00]),
            Err(CrafterError::buffer_too_short(
                "coap.reliable.token-length.extended16",
                2,
                1,
            ))
        );
        assert_eq!(
            decode_reliable_token(12, &[0xa5; 11]),
            Err(CrafterError::buffer_too_short(
                "coap.reliable.token",
                12,
                11,
            ))
        );
        assert_eq!(
            decode_reliable_token(15, &[]),
            Err(CrafterError::invalid_field_value(
                "coap.reliable.token-length",
                "reserved TKL encoding 15",
            ))
        );
    }
}
