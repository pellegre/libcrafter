//! TLS record-layer helpers.
//!
//! A TLS record is the fixed five-octet record header followed by the declared
//! fragment bytes: `ContentType | legacy_record_version | length | fragment`.
//! Handshake records can expose generic typed handshake messages while other
//! content types remain opaque so unsupported, encrypted, or future payloads
//! round-trip unchanged.

use super::content_type::TlsContentType;
use super::handshake::TlsHandshake;
use super::heartbeat::TlsHeartbeat;
use super::version::{TlsVersion, TlsVersionField};
use crate::field::{Field, FieldState};
use crate::protocols::transport::common::hex_bytes;
use crate::{CrafterError, Result};

/// TLS record content type field width in bytes.
pub const TLS_RECORD_CONTENT_TYPE_LEN: usize = 1;
/// TLS record legacy version field width in bytes.
pub const TLS_RECORD_VERSION_LEN: usize = 2;
/// TLS record fragment length field width in bytes.
pub const TLS_RECORD_LENGTH_LEN: usize = 2;
/// TLS record header width in bytes.
pub const TLS_RECORD_HEADER_LEN: usize =
    TLS_RECORD_CONTENT_TYPE_LEN + TLS_RECORD_VERSION_LEN + TLS_RECORD_LENGTH_LEN;
/// TLS ChangeCipherSpec fragment length in bytes.
pub const TLS_CHANGE_CIPHER_SPEC_LEN: usize = 1;
/// TLS ChangeCipherSpec standard wire value.
pub const TLS_CHANGE_CIPHER_SPEC_VALUE: u8 = 1;

/// TLS `change_cipher_spec` record fragment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TlsChangeCipherSpec {
    value: u8,
}

impl TlsChangeCipherSpec {
    /// TLS standard ChangeCipherSpec value.
    pub const STANDARD: Self = Self::new(TLS_CHANGE_CIPHER_SPEC_VALUE);

    /// Preserve a caller-supplied one-octet ChangeCipherSpec value.
    pub const fn new(value: u8) -> Self {
        Self { value }
    }

    /// Construct the standard ChangeCipherSpec value.
    pub const fn standard() -> Self {
        Self::STANDARD
    }

    /// Preserve a caller-supplied one-octet ChangeCipherSpec value.
    pub const fn from_raw_value(value: u8) -> Self {
        Self::new(value)
    }

    /// Return the preserved one-octet value.
    pub const fn value(self) -> u8 {
        self.value
    }

    /// Return the preserved one-octet value.
    pub const fn raw_value(self) -> u8 {
        self.value
    }

    /// Return true when this is the standard ChangeCipherSpec value.
    pub const fn is_standard(self) -> bool {
        self.value == TLS_CHANGE_CIPHER_SPEC_VALUE
    }

    /// Human-readable value label preserving unknown values numerically.
    pub fn value_label(self) -> String {
        if self.is_standard() {
            "change_cipher_spec".to_string()
        } else {
            format!("unknown change_cipher_spec 0x{:02x}", self.value)
        }
    }

    /// Number of bytes occupied by the fragment.
    pub const fn encoded_len(self) -> usize {
        TLS_CHANGE_CIPHER_SPEC_LEN
    }

    /// Return the one-byte wire encoding.
    pub const fn to_byte(self) -> u8 {
        self.value
    }

    /// Append the ChangeCipherSpec fragment bytes.
    pub fn encode(self, out: &mut Vec<u8>) {
        out.push(self.to_byte());
    }

    /// Return the ChangeCipherSpec fragment bytes.
    pub fn encode_to_vec(self) -> Vec<u8> {
        vec![self.to_byte()]
    }

    /// Compatibility alias for returning the ChangeCipherSpec fragment bytes.
    pub fn compile(self) -> Vec<u8> {
        self.encode_to_vec()
    }

    /// Decode one complete ChangeCipherSpec fragment.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (change_cipher_spec, tail) = Self::decode_prefix(bytes.as_ref())?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.change_cipher_spec.length",
                "trailing bytes after value",
            ));
        }
        Ok(change_cipher_spec)
    }

    /// Decode one ChangeCipherSpec value from the front of `bytes`.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_CHANGE_CIPHER_SPEC_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.change_cipher_spec",
                TLS_CHANGE_CIPHER_SPEC_LEN,
                bytes.len(),
            ));
        }
        Ok((Self::new(bytes[0]), &bytes[TLS_CHANGE_CIPHER_SPEC_LEN..]))
    }

    /// Stable one-line summary preserving unknown values.
    pub fn summary(self) -> String {
        format!(
            "change_cipher_spec value={} raw=0x{:02x}",
            self.value_label(),
            self.value
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(self) -> Vec<(&'static str, String)> {
        vec![
            ("value", self.value_label()),
            ("value_raw", format!("0x{:02x}", self.value)),
            ("standard", self.is_standard().to_string()),
        ]
    }
}

impl Default for TlsChangeCipherSpec {
    fn default() -> Self {
        Self::standard()
    }
}

impl From<u8> for TlsChangeCipherSpec {
    fn from(value: u8) -> Self {
        Self::new(value)
    }
}

impl From<TlsChangeCipherSpec> for u8 {
    fn from(value: TlsChangeCipherSpec) -> Self {
        value.raw_value()
    }
}

/// Parsed body for a TLS record with content type `handshake`.
///
/// TLS-over-TCP can split handshake messages across records. This helper keeps
/// cross-record reassembly out of scope by decoding only complete messages
/// available in this record fragment and preserving any trailing partial
/// message bytes as a raw tail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsHandshakeRecordBody {
    messages: Vec<TlsHandshake>,
    raw_tail: Vec<u8>,
    fragment: Vec<u8>,
}

impl TlsHandshakeRecordBody {
    /// Construct a handshake record body from complete messages and no raw tail.
    pub fn from_messages<I, M>(messages: I) -> Result<Self>
    where
        I: IntoIterator<Item = M>,
        M: Into<TlsHandshake>,
    {
        Self::from_messages_and_raw_tail(messages, Vec::new())
    }

    /// Construct a handshake record body from complete messages plus raw tail bytes.
    pub fn from_messages_and_raw_tail<I, M>(
        messages: I,
        raw_tail: impl Into<Vec<u8>>,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = M>,
        M: Into<TlsHandshake>,
    {
        let messages = messages.into_iter().map(Into::into).collect::<Vec<_>>();
        let raw_tail = raw_tail.into();
        let mut fragment = Vec::new();

        for message in &messages {
            message.encode(&mut fragment)?;
        }
        fragment.extend_from_slice(&raw_tail);

        Ok(Self {
            messages,
            raw_tail,
            fragment,
        })
    }

    fn from_decoded_parts(
        messages: Vec<TlsHandshake>,
        raw_tail: Vec<u8>,
        fragment: Vec<u8>,
    ) -> Self {
        Self {
            messages,
            raw_tail,
            fragment,
        }
    }

    /// Borrow the ordered complete handshake messages decoded from this record.
    pub fn messages(&self) -> &[TlsHandshake] {
        &self.messages
    }

    /// Borrow the raw trailing fragment bytes that did not form a complete message.
    pub fn raw_tail(&self) -> &[u8] {
        &self.raw_tail
    }

    /// Return true when this record body has trailing raw bytes.
    pub fn has_raw_tail(&self) -> bool {
        !self.raw_tail.is_empty()
    }

    /// Borrow the exact fragment bytes emitted after the record header.
    pub fn fragment(&self) -> &[u8] {
        &self.fragment
    }

    /// Consume the body and return its ordered complete messages plus raw tail.
    pub fn into_messages_and_raw_tail(self) -> (Vec<TlsHandshake>, Vec<u8>) {
        (self.messages, self.raw_tail)
    }

    /// Consume the body and return the exact fragment bytes.
    pub fn into_fragment(self) -> Vec<u8> {
        self.fragment
    }

    /// Number of exact fragment bytes.
    pub fn fragment_len(&self) -> usize {
        self.fragment.len()
    }

    /// Append the exact fragment bytes to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.fragment);
    }

    /// Stable one-line summary of complete messages and any trailing partial bytes.
    pub fn summary(&self) -> String {
        let types = self
            .messages
            .iter()
            .map(|message| message.handshake_type().label())
            .collect::<Vec<_>>()
            .join(", ");
        let message_summaries = self
            .messages
            .iter()
            .map(TlsHandshake::summary)
            .collect::<Vec<_>>()
            .join("; ");

        format!(
            "handshake messages={} raw_tail_bytes={} fragment_bytes={} types=[{}] details=[{}]",
            self.messages.len(),
            self.raw_tail.len(),
            self.fragment.len(),
            types,
            message_summaries
        )
    }
}

/// ChangeCipherSpec record body bytes plus an optional decoded view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsChangeCipherSpecRecordBody {
    fragment: Vec<u8>,
    change_cipher_spec: Option<TlsChangeCipherSpec>,
}

impl TlsChangeCipherSpecRecordBody {
    /// Preserve ChangeCipherSpec fragment bytes without parsing them.
    pub fn raw(fragment: impl Into<Vec<u8>>) -> Self {
        Self {
            fragment: fragment.into(),
            change_cipher_spec: None,
        }
    }

    /// Build ChangeCipherSpec fragment bytes from a typed value.
    pub fn from_change_cipher_spec(change_cipher_spec: TlsChangeCipherSpec) -> Self {
        Self {
            fragment: change_cipher_spec.encode_to_vec(),
            change_cipher_spec: Some(change_cipher_spec),
        }
    }

    /// Decode and preserve exact ChangeCipherSpec fragment bytes.
    pub fn from_decoded_fragment(fragment: impl Into<Vec<u8>>) -> Result<Self> {
        let fragment = fragment.into();
        let change_cipher_spec = TlsChangeCipherSpec::decode(&fragment)?;
        Ok(Self {
            fragment,
            change_cipher_spec: Some(change_cipher_spec),
        })
    }

    /// Borrow the exact fragment bytes.
    pub fn fragment(&self) -> &[u8] {
        &self.fragment
    }

    /// Consume the body and return exact fragment bytes.
    pub fn into_fragment(self) -> Vec<u8> {
        self.fragment
    }

    /// Borrow the decoded ChangeCipherSpec value when available.
    pub const fn change_cipher_spec(&self) -> Option<&TlsChangeCipherSpec> {
        self.change_cipher_spec.as_ref()
    }

    /// Return true when this body carries decoded typed fields.
    pub const fn is_typed(&self) -> bool {
        self.change_cipher_spec.is_some()
    }

    /// Number of exact fragment bytes.
    pub fn fragment_len(&self) -> usize {
        self.fragment.len()
    }

    /// Append the exact fragment bytes.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.fragment);
    }

    /// Stable one-line summary of the ChangeCipherSpec body.
    pub fn summary(&self) -> String {
        self.change_cipher_spec
            .map(TlsChangeCipherSpec::summary)
            .unwrap_or_else(|| format!("change_cipher_spec raw_bytes={}", self.fragment.len()))
    }
}

/// TLS `application_data` record fragment bytes.
///
/// Application data is encrypted or application-defined. This type preserves
/// the bytes for packet construction and inspection without interpreting HTTP,
/// MQTT, DNS-over-TLS, or any other application protocol inside the fragment.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TlsApplicationData {
    bytes: Vec<u8>,
}

impl TlsApplicationData {
    /// Preserve caller-supplied application data bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    /// Preserve caller-supplied application data bytes.
    pub fn opaque(bytes: impl Into<Vec<u8>>) -> Self {
        Self::new(bytes)
    }

    /// Preserve caller-supplied application data bytes.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self::new(bytes)
    }

    /// Decode application data by preserving all fragment bytes.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        Ok(Self::new(bytes.as_ref().to_vec()))
    }

    /// Borrow the preserved bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrow the preserved bytes.
    pub fn fragment(&self) -> &[u8] {
        self.bytes()
    }

    /// Borrow the preserved bytes.
    pub fn data(&self) -> &[u8] {
        self.bytes()
    }

    /// Consume and return the preserved bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Number of preserved bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return true when no bytes are carried.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Number of bytes occupied by the fragment.
    pub fn encoded_len(&self) -> usize {
        self.bytes.len()
    }

    /// Append the preserved bytes.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.bytes);
    }

    /// Return the preserved bytes.
    pub fn encode_to_vec(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Compatibility alias for returning the preserved bytes.
    pub fn compile(&self) -> Vec<u8> {
        self.encode_to_vec()
    }

    /// Stable one-line summary preserving only byte count.
    pub fn summary(&self) -> String {
        format!("application_data bytes={}", self.bytes.len())
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("bytes", self.bytes.len().to_string()),
            ("data", hex_bytes(&self.bytes)),
        ]
    }
}

/// Heartbeat record body bytes plus an optional decoded view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsHeartbeatRecordBody {
    fragment: Vec<u8>,
    heartbeat: Option<TlsHeartbeat>,
}

impl TlsHeartbeatRecordBody {
    /// Preserve heartbeat fragment bytes without parsing them.
    pub fn raw(fragment: impl Into<Vec<u8>>) -> Self {
        Self {
            fragment: fragment.into(),
            heartbeat: None,
        }
    }

    /// Build heartbeat fragment bytes from typed fields.
    pub fn from_heartbeat(heartbeat: TlsHeartbeat) -> Result<Self> {
        let fragment = heartbeat.encode_to_vec()?;
        Ok(Self {
            fragment,
            heartbeat: Some(heartbeat),
        })
    }

    /// Decode and preserve exact heartbeat fragment bytes.
    pub fn from_decoded_fragment(fragment: impl Into<Vec<u8>>) -> Result<Self> {
        let fragment = fragment.into();
        let heartbeat = TlsHeartbeat::decode(&fragment)?;
        Ok(Self {
            fragment,
            heartbeat: Some(heartbeat),
        })
    }

    /// Borrow the exact fragment bytes.
    pub fn fragment(&self) -> &[u8] {
        &self.fragment
    }

    /// Consume the body and return exact fragment bytes.
    pub fn into_fragment(self) -> Vec<u8> {
        self.fragment
    }

    /// Borrow the decoded heartbeat when available.
    pub const fn heartbeat(&self) -> Option<&TlsHeartbeat> {
        self.heartbeat.as_ref()
    }

    /// Return true when this body carries decoded typed fields.
    pub const fn is_typed(&self) -> bool {
        self.heartbeat.is_some()
    }

    /// Number of exact fragment bytes.
    pub fn fragment_len(&self) -> usize {
        self.fragment.len()
    }

    /// Append the exact fragment bytes.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.fragment);
    }

    /// Stable one-line summary of the heartbeat body.
    pub fn summary(&self) -> String {
        self.heartbeat
            .as_ref()
            .map(TlsHeartbeat::summary)
            .unwrap_or_else(|| format!("heartbeat raw_bytes={}", self.fragment.len()))
    }
}

/// TLS record body hook.
///
/// Handshake records carry ordered generic handshake messages when the fragment
/// starts with at least one complete message. Non-handshake records, encrypted
/// records, and unsupported content types stay opaque.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsRecordBody {
    /// Typed ChangeCipherSpec fragment plus exact bytes.
    ChangeCipherSpec(TlsChangeCipherSpecRecordBody),
    /// Opaque application data bytes with no inner protocol decoding.
    ApplicationData(TlsApplicationData),
    /// Heartbeat message bytes plus a typed view when available.
    Heartbeat(TlsHeartbeatRecordBody),
    /// Generic typed handshake messages plus any trailing raw fragment bytes.
    Handshake(TlsHandshakeRecordBody),
    /// Opaque TLS record fragment bytes.
    Opaque(Vec<u8>),
}

impl TlsRecordBody {
    /// Construct a raw-preserving ChangeCipherSpec body.
    pub fn change_cipher_spec(fragment: impl Into<Vec<u8>>) -> Self {
        Self::ChangeCipherSpec(TlsChangeCipherSpecRecordBody::raw(fragment))
    }

    /// Construct a typed ChangeCipherSpec body.
    pub fn from_change_cipher_spec(change_cipher_spec: TlsChangeCipherSpec) -> Self {
        Self::ChangeCipherSpec(TlsChangeCipherSpecRecordBody::from_change_cipher_spec(
            change_cipher_spec,
        ))
    }

    /// Construct an opaque typed application_data body.
    pub fn application_data(fragment: impl Into<Vec<u8>>) -> Self {
        Self::ApplicationData(TlsApplicationData::new(fragment))
    }

    /// Construct an application_data body from a typed byte wrapper.
    pub fn from_application_data(application_data: TlsApplicationData) -> Self {
        Self::ApplicationData(application_data)
    }

    /// Construct a raw-preserving heartbeat body.
    pub fn heartbeat(fragment: impl Into<Vec<u8>>) -> Self {
        Self::Heartbeat(TlsHeartbeatRecordBody::raw(fragment))
    }

    /// Construct a typed heartbeat body.
    pub fn from_heartbeat(heartbeat: TlsHeartbeat) -> Result<Self> {
        Ok(Self::Heartbeat(TlsHeartbeatRecordBody::from_heartbeat(
            heartbeat,
        )?))
    }

    /// Construct a typed handshake body from complete messages and no raw tail.
    pub fn handshake<I, M>(messages: I) -> Result<Self>
    where
        I: IntoIterator<Item = M>,
        M: Into<TlsHandshake>,
    {
        Ok(Self::Handshake(TlsHandshakeRecordBody::from_messages(
            messages,
        )?))
    }

    /// Construct a typed handshake body from complete messages plus raw tail bytes.
    pub fn handshake_with_raw_tail<I, M>(messages: I, raw_tail: impl Into<Vec<u8>>) -> Result<Self>
    where
        I: IntoIterator<Item = M>,
        M: Into<TlsHandshake>,
    {
        Ok(Self::Handshake(
            TlsHandshakeRecordBody::from_messages_and_raw_tail(messages, raw_tail)?,
        ))
    }

    /// Preserve fragment bytes without inner parsing.
    pub fn opaque(fragment: impl Into<Vec<u8>>) -> Self {
        Self::Opaque(fragment.into())
    }

    fn decode_for_content_type(
        content_type: TlsContentType,
        fragment: impl Into<Vec<u8>>,
    ) -> Result<Self> {
        let fragment = fragment.into();
        match content_type {
            TlsContentType::CHANGE_CIPHER_SPEC => Ok(Self::ChangeCipherSpec(
                TlsChangeCipherSpecRecordBody::from_decoded_fragment(fragment)?,
            )),
            TlsContentType::APPLICATION_DATA => {
                Ok(Self::ApplicationData(TlsApplicationData::decode(fragment)?))
            }
            TlsContentType::HEARTBEAT => Ok(Self::Heartbeat(
                TlsHeartbeatRecordBody::from_decoded_fragment(fragment)?,
            )),
            TlsContentType::HANDSHAKE => Self::decode_handshake_fragment(fragment),
            _ => Ok(Self::opaque(fragment)),
        }
    }

    fn decode_handshake_fragment(fragment: Vec<u8>) -> Result<Self> {
        if fragment.is_empty() {
            return Ok(Self::Handshake(TlsHandshakeRecordBody::from_decoded_parts(
                Vec::new(),
                Vec::new(),
                fragment,
            )));
        }

        let mut remaining = fragment.as_slice();
        let mut messages = Vec::new();

        while !remaining.is_empty() {
            match TlsHandshake::decode_with_consumed(remaining) {
                Ok((message, consumed)) if consumed > 0 => {
                    messages.push(message);
                    remaining = &remaining[consumed..];
                }
                Ok((_message, _consumed)) => {
                    return Err(CrafterError::invalid_field_value(
                        "tls.handshake.length",
                        "decoded handshake consumed no bytes",
                    ));
                }
                Err(_err) if !messages.is_empty() => {
                    let raw_tail = remaining.to_vec();
                    return Ok(Self::Handshake(TlsHandshakeRecordBody::from_decoded_parts(
                        messages, raw_tail, fragment,
                    )));
                }
                Err(_err) => {
                    return Ok(Self::Handshake(TlsHandshakeRecordBody::from_decoded_parts(
                        Vec::new(),
                        fragment.clone(),
                        fragment,
                    )));
                }
            }
        }

        Ok(Self::Handshake(TlsHandshakeRecordBody::from_decoded_parts(
            messages,
            Vec::new(),
            fragment,
        )))
    }

    /// Borrow the bytes that will be emitted after the record header.
    pub fn fragment(&self) -> &[u8] {
        match self {
            Self::ChangeCipherSpec(change_cipher_spec) => change_cipher_spec.fragment(),
            Self::ApplicationData(application_data) => application_data.bytes(),
            Self::Heartbeat(heartbeat) => heartbeat.fragment(),
            Self::Handshake(handshake) => handshake.fragment(),
            Self::Opaque(fragment) => fragment,
        }
    }

    /// Consume the body hook and return the preserved fragment bytes.
    pub fn into_fragment(self) -> Vec<u8> {
        match self {
            Self::ChangeCipherSpec(change_cipher_spec) => change_cipher_spec.into_fragment(),
            Self::ApplicationData(application_data) => application_data.into_bytes(),
            Self::Heartbeat(heartbeat) => heartbeat.into_fragment(),
            Self::Handshake(handshake) => handshake.into_fragment(),
            Self::Opaque(fragment) => fragment,
        }
    }

    /// Number of preserved fragment bytes.
    pub fn fragment_len(&self) -> usize {
        self.fragment().len()
    }

    /// Return true when the body is carried as an opaque fragment.
    pub const fn is_opaque(&self) -> bool {
        matches!(self, Self::Opaque(_))
    }

    /// Return true when the body carries decoded ChangeCipherSpec fields.
    pub const fn is_change_cipher_spec(&self) -> bool {
        matches!(self, Self::ChangeCipherSpec(_))
    }

    /// Return true when the body carries application data bytes.
    pub const fn is_application_data(&self) -> bool {
        matches!(self, Self::ApplicationData(_))
    }

    /// Return true when the body carries a heartbeat message hook.
    pub const fn is_heartbeat(&self) -> bool {
        matches!(self, Self::Heartbeat(_))
    }

    /// Return true when the body carries decoded generic handshake messages.
    pub const fn is_handshake(&self) -> bool {
        matches!(self, Self::Handshake(_))
    }

    /// Borrow the typed ChangeCipherSpec record body when present.
    pub const fn change_cipher_spec_record_body(&self) -> Option<&TlsChangeCipherSpecRecordBody> {
        match self {
            Self::ChangeCipherSpec(change_cipher_spec) => Some(change_cipher_spec),
            _ => None,
        }
    }

    /// Borrow the decoded ChangeCipherSpec value when present.
    pub const fn change_cipher_spec_body(&self) -> Option<&TlsChangeCipherSpec> {
        match self {
            Self::ChangeCipherSpec(change_cipher_spec) => change_cipher_spec.change_cipher_spec(),
            _ => None,
        }
    }

    /// Borrow the application data bytes when present.
    pub const fn application_data_body(&self) -> Option<&TlsApplicationData> {
        match self {
            Self::ApplicationData(application_data) => Some(application_data),
            _ => None,
        }
    }

    /// Borrow the typed heartbeat record body when present.
    pub const fn heartbeat_record_body(&self) -> Option<&TlsHeartbeatRecordBody> {
        match self {
            Self::Heartbeat(heartbeat) => Some(heartbeat),
            _ => None,
        }
    }

    /// Borrow decoded heartbeat fields when present.
    pub const fn heartbeat_body(&self) -> Option<&TlsHeartbeat> {
        match self {
            Self::Heartbeat(heartbeat) => heartbeat.heartbeat(),
            _ => None,
        }
    }

    /// Borrow the typed handshake record body when present.
    pub const fn handshake_body(&self) -> Option<&TlsHandshakeRecordBody> {
        match self {
            Self::ChangeCipherSpec(_) => None,
            Self::ApplicationData(_) => None,
            Self::Heartbeat(_) => None,
            Self::Handshake(handshake) => Some(handshake),
            Self::Opaque(_) => None,
        }
    }

    /// Borrow decoded complete handshake messages when this is a handshake body.
    pub fn handshake_messages(&self) -> Option<&[TlsHandshake]> {
        self.handshake_body().map(TlsHandshakeRecordBody::messages)
    }

    /// Borrow the raw trailing handshake fragment bytes when this is a handshake body.
    pub fn handshake_raw_tail(&self) -> Option<&[u8]> {
        self.handshake_body().map(TlsHandshakeRecordBody::raw_tail)
    }

    /// Append the body fragment bytes to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::ChangeCipherSpec(change_cipher_spec) => change_cipher_spec.encode(out),
            Self::ApplicationData(application_data) => application_data.encode(out),
            Self::Heartbeat(heartbeat) => heartbeat.encode(out),
            Self::Handshake(handshake) => handshake.encode(out),
            Self::Opaque(fragment) => out.extend_from_slice(fragment),
        }
    }

    /// Return the preserved fragment bytes as a new vector.
    pub fn encode_to_vec(&self) -> Vec<u8> {
        self.fragment().to_vec()
    }

    /// Stable one-line summary of the selected record body.
    pub fn summary(&self) -> String {
        match self {
            Self::ChangeCipherSpec(change_cipher_spec) => change_cipher_spec.summary(),
            Self::ApplicationData(application_data) => application_data.summary(),
            Self::Heartbeat(heartbeat) => heartbeat.summary(),
            Self::Handshake(handshake) => handshake.summary(),
            Self::Opaque(fragment) => format!("opaque bytes={}", fragment.len()),
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::ChangeCipherSpec(_) => "change_cipher_spec",
            Self::ApplicationData(_) => "application_data",
            Self::Heartbeat(_) => "heartbeat",
            Self::Handshake(_) => "handshake",
            Self::Opaque(_) => "opaque",
        }
    }
}

impl From<TlsHandshakeRecordBody> for TlsRecordBody {
    fn from(body: TlsHandshakeRecordBody) -> Self {
        Self::Handshake(body)
    }
}

impl From<TlsChangeCipherSpecRecordBody> for TlsRecordBody {
    fn from(body: TlsChangeCipherSpecRecordBody) -> Self {
        Self::ChangeCipherSpec(body)
    }
}

impl From<TlsChangeCipherSpec> for TlsRecordBody {
    fn from(change_cipher_spec: TlsChangeCipherSpec) -> Self {
        Self::from_change_cipher_spec(change_cipher_spec)
    }
}

impl From<TlsApplicationData> for TlsRecordBody {
    fn from(application_data: TlsApplicationData) -> Self {
        Self::from_application_data(application_data)
    }
}

impl From<TlsHeartbeatRecordBody> for TlsRecordBody {
    fn from(body: TlsHeartbeatRecordBody) -> Self {
        Self::Heartbeat(body)
    }
}

impl From<Vec<u8>> for TlsRecordBody {
    fn from(fragment: Vec<u8>) -> Self {
        Self::opaque(fragment)
    }
}

/// A complete TLS record with raw-preserving fragment bytes.
///
/// The header length field is auto-filled from the fragment length during
/// encoding unless the caller pinned a declared length on the header. Decoded
/// records preserve the on-wire declared length and the exact fragment bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsRecord {
    header: TlsRecordHeader,
    body: TlsRecordBody,
}

impl TlsRecord {
    /// Construct an empty TLS record for `content_type`.
    pub fn new(content_type: impl Into<TlsContentType>) -> Self {
        Self {
            header: TlsRecordHeader::new(content_type),
            body: TlsRecordBody::opaque(Vec::new()),
        }
    }

    /// Construct a TLS record with opaque fragment bytes.
    pub fn from_fragment(
        content_type: impl Into<TlsContentType>,
        fragment: impl Into<Vec<u8>>,
    ) -> Self {
        Self::new(content_type).with_fragment(fragment)
    }

    /// Construct a TLS record from a header and opaque fragment bytes.
    pub fn from_header_and_fragment(header: TlsRecordHeader, fragment: impl Into<Vec<u8>>) -> Self {
        Self::from_header_and_body(header, TlsRecordBody::opaque(fragment))
    }

    /// Construct a TLS record from a header and body hook.
    pub fn from_header_and_body(header: TlsRecordHeader, body: impl Into<TlsRecordBody>) -> Self {
        Self {
            header,
            body: body.into(),
        }
    }

    /// Construct a `change_cipher_spec` TLS record.
    pub fn change_cipher_spec(fragment: impl Into<Vec<u8>>) -> Self {
        Self::from_header_and_fragment(TlsRecordHeader::change_cipher_spec(), fragment)
    }

    /// Construct a `change_cipher_spec` TLS record from a typed body.
    pub fn from_change_cipher_spec(change_cipher_spec: TlsChangeCipherSpec) -> Self {
        Self::from_header_and_body(
            TlsRecordHeader::change_cipher_spec(),
            TlsRecordBody::from_change_cipher_spec(change_cipher_spec),
        )
    }

    /// Construct a standard `change_cipher_spec` TLS record.
    pub fn standard_change_cipher_spec() -> Self {
        Self::from_change_cipher_spec(TlsChangeCipherSpec::standard())
    }

    /// Construct an `alert` TLS record.
    pub fn alert(fragment: impl Into<Vec<u8>>) -> Self {
        Self::from_header_and_fragment(TlsRecordHeader::alert(), fragment)
    }

    /// Construct a `handshake` TLS record.
    pub fn handshake(fragment: impl Into<Vec<u8>>) -> Self {
        Self::from_header_and_fragment(TlsRecordHeader::handshake(), fragment)
    }

    /// Construct a `handshake` TLS record from complete generic messages.
    pub fn handshake_messages<I, M>(messages: I) -> Result<Self>
    where
        I: IntoIterator<Item = M>,
        M: Into<TlsHandshake>,
    {
        Ok(Self::from_header_and_body(
            TlsRecordHeader::handshake(),
            TlsRecordBody::handshake(messages)?,
        ))
    }

    /// Construct a `handshake` TLS record from complete generic messages plus raw tail bytes.
    pub fn handshake_messages_with_raw_tail<I, M>(
        messages: I,
        raw_tail: impl Into<Vec<u8>>,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = M>,
        M: Into<TlsHandshake>,
    {
        Ok(Self::from_header_and_body(
            TlsRecordHeader::handshake(),
            TlsRecordBody::handshake_with_raw_tail(messages, raw_tail)?,
        ))
    }

    /// Construct an `application_data` TLS record.
    pub fn application_data(fragment: impl Into<Vec<u8>>) -> Self {
        Self::from_header_and_body(
            TlsRecordHeader::application_data(),
            TlsRecordBody::application_data(fragment),
        )
    }

    /// Construct an `application_data` TLS record from a typed opaque body.
    pub fn from_application_data(application_data: TlsApplicationData) -> Self {
        Self::from_header_and_body(
            TlsRecordHeader::application_data(),
            TlsRecordBody::from_application_data(application_data),
        )
    }

    /// Construct a `heartbeat` TLS record with raw fragment bytes.
    pub fn heartbeat(fragment: impl Into<Vec<u8>>) -> Self {
        Self::from_header_and_fragment(TlsRecordHeader::heartbeat(), fragment)
    }

    /// Construct a `heartbeat` TLS record from a typed body.
    pub fn from_heartbeat(heartbeat: TlsHeartbeat) -> Result<Self> {
        Ok(Self::from_header_and_body(
            TlsRecordHeader::heartbeat(),
            TlsRecordBody::from_heartbeat(heartbeat)?,
        ))
    }

    /// Replace the complete record header.
    pub fn with_header(mut self, header: TlsRecordHeader) -> Self {
        self.header = header;
        self
    }

    /// Replace the record content type.
    pub fn with_content_type(mut self, content_type: impl Into<TlsContentType>) -> Self {
        self.header = self.header.with_content_type(content_type);
        self
    }

    /// Replace the record content type from a raw one-octet value.
    pub fn with_raw_content_type(self, content_type: u8) -> Self {
        self.with_content_type(TlsContentType::from_u8(content_type))
    }

    /// Replace the record legacy version field.
    pub fn with_legacy_record_version(
        mut self,
        legacy_record_version: impl Into<TlsVersion>,
    ) -> Self {
        self.header = self
            .header
            .with_legacy_record_version(legacy_record_version);
        self
    }

    /// Compatibility alias for replacing the record legacy version field.
    pub fn with_version(self, legacy_record_version: impl Into<TlsVersion>) -> Self {
        self.with_legacy_record_version(legacy_record_version)
    }

    /// Replace the record legacy version field from a raw two-octet value.
    pub fn with_raw_legacy_record_version(self, legacy_record_version: u16) -> Self {
        self.with_legacy_record_version(TlsVersion::from_u16(legacy_record_version))
    }

    /// Compatibility alias for replacing the record legacy version field.
    pub fn with_raw_version(self, legacy_record_version: u16) -> Self {
        self.with_raw_legacy_record_version(legacy_record_version)
    }

    /// Pin the declared record fragment length.
    pub fn with_declared_length(mut self, declared_length: u16) -> Self {
        self.header = self.header.with_declared_length(declared_length);
        self
    }

    /// Compatibility alias for pinning the declared record fragment length.
    pub fn with_length(self, declared_length: u16) -> Self {
        self.with_declared_length(declared_length)
    }

    /// Replace the opaque fragment bytes.
    pub fn with_fragment(mut self, fragment: impl Into<Vec<u8>>) -> Self {
        self.body = TlsRecordBody::opaque(fragment);
        self
    }

    /// Replace the record body hook.
    pub fn with_body(mut self, body: impl Into<TlsRecordBody>) -> Self {
        self.body = body.into();
        self
    }

    /// Borrow the preserved record header.
    pub const fn header(&self) -> &TlsRecordHeader {
        &self.header
    }

    /// Borrow the preserved record body hook.
    pub const fn body(&self) -> &TlsRecordBody {
        &self.body
    }

    /// Borrow decoded ChangeCipherSpec fields when this record carries them.
    pub const fn change_cipher_spec_body(&self) -> Option<&TlsChangeCipherSpec> {
        self.body.change_cipher_spec_body()
    }

    /// Borrow application data bytes when this record carries them.
    pub const fn application_data_body(&self) -> Option<&TlsApplicationData> {
        self.body.application_data_body()
    }

    /// Borrow decoded heartbeat fields when this record carries them.
    pub const fn heartbeat_body(&self) -> Option<&TlsHeartbeat> {
        self.body.heartbeat_body()
    }

    /// Borrow the opaque fragment bytes.
    pub fn fragment(&self) -> &[u8] {
        self.body.fragment()
    }

    /// Consume the record and return the header plus preserved fragment bytes.
    pub fn into_header_and_fragment(self) -> (TlsRecordHeader, Vec<u8>) {
        (self.header, self.body.into_fragment())
    }

    /// Return the record content type.
    pub const fn content_type(&self) -> TlsContentType {
        self.header.content_type()
    }

    /// Return the raw record content type value.
    pub const fn raw_content_type(&self) -> u8 {
        self.header.raw_content_type()
    }

    /// Return the record legacy version field.
    pub const fn legacy_record_version(&self) -> TlsVersion {
        self.header.legacy_record_version()
    }

    /// Compatibility alias for the record legacy version field.
    pub const fn version(&self) -> TlsVersion {
        self.header.version()
    }

    /// Return the raw record legacy version value.
    pub const fn raw_legacy_record_version(&self) -> u16 {
        self.header.raw_legacy_record_version()
    }

    /// Compatibility alias for the raw record legacy version value.
    pub const fn raw_version(&self) -> u16 {
        self.header.raw_version()
    }

    /// Caller-pinned or decoded declared fragment length, if present.
    pub fn declared_length(&self) -> Option<u16> {
        self.header.declared_length()
    }

    /// Compatibility alias for the declared fragment length.
    pub fn declared_len(&self) -> Option<u16> {
        self.header.declared_len()
    }

    /// Assignment state for the declared fragment length field.
    pub const fn declared_length_state(&self) -> FieldState {
        self.header.declared_length_state()
    }

    /// Number of bytes in the record fragment.
    pub fn fragment_len(&self) -> usize {
        self.body.fragment_len()
    }

    /// Declared fragment length to emit for this record.
    pub fn effective_length(&self) -> Result<u16> {
        self.header.effective_length(self.fragment_len())
    }

    /// Actual serialized record byte count.
    pub fn actual_record_len(&self) -> Result<usize> {
        self.header.actual_record_len(self.fragment_len())
    }

    /// Declared record byte count from the header length field.
    pub fn declared_record_len(&self) -> Result<usize> {
        self.header.declared_record_len(self.fragment_len())
    }

    /// Number of bytes emitted by this record.
    pub fn encoded_len(&self) -> Result<usize> {
        self.actual_record_len()
    }

    /// Append the complete record, auto-filling an unset length from the fragment.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.effective_length()?;
        self.header
            .encode_with_fragment_len(self.fragment_len(), out)?;
        self.body.encode(out);
        Ok(())
    }

    /// Return the complete encoded record.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        self.effective_length()?;
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Compatibility alias for returning the complete encoded record.
    pub fn compile(&self) -> Result<Vec<u8>> {
        self.encode_to_vec()
    }

    /// Decode one complete TLS record from `bytes`.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (record, _) = Self::decode_prefix(bytes.as_ref())?;
        Ok(record)
    }

    /// Decode one complete TLS record from the front of `bytes`, returning the tail.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (header, tail) = TlsRecordHeader::decode_prefix(bytes)?;
        let fragment_len = usize::from(
            header
                .declared_length()
                .expect("decoded TLS record headers always carry length"),
        );
        let required = TLS_RECORD_HEADER_LEN
            .checked_add(fragment_len)
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.record.length", "length overflow")
            })?;

        if bytes.len() < required {
            return Err(CrafterError::buffer_too_short(
                "tls.record.fragment",
                required,
                bytes.len(),
            ));
        }

        let fragment = tail[..fragment_len].to_vec();
        let body = TlsRecordBody::decode_for_content_type(header.content_type(), fragment)?;
        Ok((
            Self::from_header_and_body(header, body),
            &tail[fragment_len..],
        ))
    }

    /// Decode one complete TLS record, returning the number of consumed bytes.
    pub fn decode_with_consumed(bytes: &[u8]) -> Result<(Self, usize)> {
        let (record, tail) = Self::decode_prefix(bytes)?;
        Ok((record, bytes.len() - tail.len()))
    }

    /// Stable one-line summary preserving codepoints and fragment length.
    pub fn summary(&self) -> String {
        format!(
            "record content_type={} legacy_record_version={} declared_length={} fragment_bytes={} body={}",
            self.content_type().label(),
            self.legacy_record_version().label(),
            self.header.length_label(),
            self.fragment_len(),
            self.body.summary()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = self.header.inspection_fields();
        fields.push(("body", self.body.label().to_string()));
        fields.push(("body_summary", self.body.summary()));
        fields.push(("fragment_bytes", self.fragment_len().to_string()));
        fields.push((
            "record_bytes",
            self.actual_record_len()
                .map(|len| len.to_string())
                .unwrap_or_else(|_| "overflow".to_string()),
        ));
        fields
    }
}

/// Fixed TLS record header.
///
/// The `length` field is intentionally stored as a [`Field<u16>`]. Unset
/// lengths can be filled from a fragment byte count by later record compile
/// code, while decoded or caller-pinned lengths are preserved verbatim even
/// when they disagree with the actual fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsRecordHeader {
    content_type: TlsContentType,
    legacy_record_version: TlsVersion,
    declared_length: Field<u16>,
}

impl TlsRecordHeader {
    /// Construct a TLS record header with the common legacy record version.
    pub fn new(content_type: impl Into<TlsContentType>) -> Self {
        Self {
            content_type: content_type.into(),
            legacy_record_version: TlsVersion::legacy_record(),
            declared_length: Field::unset(),
        }
    }

    /// Construct a TLS record header from all header fields.
    pub fn from_fields(
        content_type: impl Into<TlsContentType>,
        legacy_record_version: impl Into<TlsVersion>,
    ) -> Self {
        Self::new(content_type).with_legacy_record_version(legacy_record_version)
    }

    /// Construct a decoded TLS record header, preserving the wire length field.
    pub fn from_decoded_parts(
        content_type: impl Into<TlsContentType>,
        legacy_record_version: impl Into<TlsVersion>,
        declared_length: u16,
    ) -> Self {
        Self::from_fields(content_type, legacy_record_version).with_declared_length(declared_length)
    }

    /// Construct a `change_cipher_spec` record header.
    pub fn change_cipher_spec() -> Self {
        Self::new(TlsContentType::change_cipher_spec())
    }

    /// Construct an `alert` record header.
    pub fn alert() -> Self {
        Self::new(TlsContentType::alert())
    }

    /// Construct a `handshake` record header.
    pub fn handshake() -> Self {
        Self::new(TlsContentType::handshake())
    }

    /// Construct an `application_data` record header.
    pub fn application_data() -> Self {
        Self::new(TlsContentType::application_data())
    }

    /// Construct a `heartbeat` record header.
    pub fn heartbeat() -> Self {
        Self::new(TlsContentType::heartbeat())
    }

    /// Replace the record content type.
    pub fn with_content_type(mut self, content_type: impl Into<TlsContentType>) -> Self {
        self.content_type = content_type.into();
        self
    }

    /// Replace the record content type from a raw one-octet value.
    pub fn with_raw_content_type(self, content_type: u8) -> Self {
        self.with_content_type(TlsContentType::from_u8(content_type))
    }

    /// Replace the record legacy version field.
    pub fn with_legacy_record_version(
        mut self,
        legacy_record_version: impl Into<TlsVersion>,
    ) -> Self {
        self.legacy_record_version = legacy_record_version.into();
        self
    }

    /// Compatibility alias for replacing the record legacy version field.
    pub fn with_version(self, legacy_record_version: impl Into<TlsVersion>) -> Self {
        self.with_legacy_record_version(legacy_record_version)
    }

    /// Replace the record legacy version field from a raw two-octet value.
    pub fn with_raw_legacy_record_version(self, legacy_record_version: u16) -> Self {
        self.with_legacy_record_version(TlsVersion::from_u16(legacy_record_version))
    }

    /// Compatibility alias for replacing the record legacy version field.
    pub fn with_raw_version(self, legacy_record_version: u16) -> Self {
        self.with_raw_legacy_record_version(legacy_record_version)
    }

    /// Pin the declared record fragment length.
    pub fn with_declared_length(mut self, declared_length: u16) -> Self {
        self.declared_length.set_user(declared_length);
        self
    }

    /// Compatibility alias for pinning the declared record fragment length.
    pub fn with_length(self, declared_length: u16) -> Self {
        self.with_declared_length(declared_length)
    }

    /// Return the record content type.
    pub const fn content_type(&self) -> TlsContentType {
        self.content_type
    }

    /// Return the raw record content type value.
    pub const fn raw_content_type(&self) -> u8 {
        self.content_type.raw()
    }

    /// Return the record legacy version field.
    pub const fn legacy_record_version(&self) -> TlsVersion {
        self.legacy_record_version
    }

    /// Compatibility alias for the record legacy version field.
    pub const fn version(&self) -> TlsVersion {
        self.legacy_record_version()
    }

    /// Return the raw record legacy version value.
    pub const fn raw_legacy_record_version(&self) -> u16 {
        self.legacy_record_version.raw()
    }

    /// Compatibility alias for the raw record legacy version value.
    pub const fn raw_version(&self) -> u16 {
        self.raw_legacy_record_version()
    }

    /// Return true when the legacy record version is the TLS 1.3 compatibility value.
    pub const fn uses_legacy_record_version(&self) -> bool {
        self.legacy_record_version.is_legacy_compatibility_value()
    }

    /// Caller-pinned or decoded declared fragment length, if present.
    pub fn declared_length(&self) -> Option<u16> {
        self.declared_length.value().copied()
    }

    /// Compatibility alias for the declared fragment length.
    pub fn declared_len(&self) -> Option<u16> {
        self.declared_length()
    }

    /// Compatibility alias for a caller-pinned declared fragment length.
    pub fn length_override(&self) -> Option<u16> {
        self.declared_length()
    }

    /// Assignment state for the declared fragment length field.
    pub const fn declared_length_state(&self) -> FieldState {
        self.declared_length.state()
    }

    /// Compatibility alias for the declared fragment length field state.
    pub const fn length_state(&self) -> FieldState {
        self.declared_length_state()
    }

    /// Declared fragment length to emit for a given actual fragment byte count.
    ///
    /// A caller-pinned or decoded length wins. Otherwise the supplied actual
    /// fragment length is converted to the two-octet TLS record length field.
    pub fn effective_length(&self, actual_fragment_len: usize) -> Result<u16> {
        match self.declared_length.value() {
            Some(&declared_length) => Ok(declared_length),
            None => u16::try_from(actual_fragment_len).map_err(|_| {
                CrafterError::invalid_field_value(
                    "tls.record.length",
                    "fragment length must fit in two bytes",
                )
            }),
        }
    }

    /// Compatibility alias for the declared fragment length to emit.
    pub fn declared_length_value(&self, actual_fragment_len: usize) -> Result<u16> {
        self.effective_length(actual_fragment_len)
    }

    /// Compatibility alias for the declared fragment length to emit.
    pub fn length_value(&self, actual_fragment_len: usize) -> Result<u16> {
        self.effective_length(actual_fragment_len)
    }

    /// Number of bytes in a TLS record header.
    pub const fn header_len(&self) -> usize {
        TLS_RECORD_HEADER_LEN
    }

    /// Number of bytes emitted by this header.
    pub const fn encoded_len(&self) -> usize {
        TLS_RECORD_HEADER_LEN
    }

    /// Actual serialized record byte count when followed by `actual_fragment_len` bytes.
    pub fn actual_record_len(&self, actual_fragment_len: usize) -> Result<usize> {
        TLS_RECORD_HEADER_LEN
            .checked_add(actual_fragment_len)
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.record.length", "length overflow")
            })
    }

    /// Declared record byte count from the header length field.
    pub fn declared_record_len(&self, actual_fragment_len: usize) -> Result<usize> {
        TLS_RECORD_HEADER_LEN
            .checked_add(usize::from(self.effective_length(actual_fragment_len)?))
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.record.length", "length overflow")
            })
    }

    /// Append the five-octet record header, treating an unset length as zero.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_with_fragment_len(0, out)
    }

    /// Append the five-octet record header, filling unset length from fragment bytes.
    pub fn encode_with_fragment_len(
        &self,
        actual_fragment_len: usize,
        out: &mut Vec<u8>,
    ) -> Result<()> {
        out.push(self.content_type.to_byte());
        out.extend_from_slice(&self.legacy_record_version.to_be_bytes());
        out.extend_from_slice(&self.effective_length(actual_fragment_len)?.to_be_bytes());
        Ok(())
    }

    /// Return the five-octet record header, treating an unset length as zero.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        self.encode_to_vec_with_fragment_len(0)
    }

    /// Return the five-octet record header, filling unset length from fragment bytes.
    pub fn encode_to_vec_with_fragment_len(&self, actual_fragment_len: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(TLS_RECORD_HEADER_LEN);
        self.encode_with_fragment_len(actual_fragment_len, &mut out)?;
        Ok(out)
    }

    /// Decode a TLS record header from the first five bytes of `bytes`.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (header, _) = Self::decode_prefix(bytes.as_ref())?;
        Ok(header)
    }

    /// Decode a TLS record header from the front of `bytes`, returning the tail.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_RECORD_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.record.header",
                TLS_RECORD_HEADER_LEN,
                bytes.len(),
            ));
        }

        let content_type = TlsContentType::from_u8(bytes[0]);
        let legacy_record_version = TlsVersion::from_be_bytes([bytes[1], bytes[2]]);
        let declared_length = u16::from_be_bytes([bytes[3], bytes[4]]);

        Ok((
            Self::from_decoded_parts(content_type, legacy_record_version, declared_length),
            &bytes[TLS_RECORD_HEADER_LEN..],
        ))
    }

    /// Stable one-line summary preserving codepoints and declared length state.
    pub fn summary(&self) -> String {
        format!(
            "record_header content_type={} legacy_record_version={} declared_length={}",
            self.content_type.label(),
            self.legacy_record_version.label(),
            self.length_label()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("content_type", self.content_type.label()),
            (
                "content_type_raw",
                format!("0x{:02x}", self.content_type.raw()),
            ),
            (
                "content_type_status",
                self.content_type.status().label().to_string(),
            ),
            ("legacy_record_version", self.legacy_record_version.label()),
            (
                "legacy_record_version_raw",
                format!("0x{:04x}", self.legacy_record_version.raw()),
            ),
            (
                "legacy_record_version_status",
                self.legacy_record_version.status().label().to_string(),
            ),
            (
                "legacy_record_version_role",
                TlsVersionField::LegacyRecordVersion.role().to_string(),
            ),
            ("declared_length", self.length_label()),
            (
                "declared_length_state",
                field_state_label(self.declared_length.state()).to_string(),
            ),
            ("header_bytes", TLS_RECORD_HEADER_LEN.to_string()),
        ]
    }

    fn length_label(&self) -> String {
        self.declared_length()
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
    use crate::protocols::tls::heartbeat::TlsHeartbeatMessageType;
    use crate::protocols::tls::{
        TlsClientHello, TlsHandshakeType, TlsRawExtension, TLS_CLIENT_HELLO_RANDOM_LEN,
        TLS_HANDSHAKE_HEADER_LEN, TLS_HEARTBEAT_HEADER_LEN, TLS_HEARTBEAT_MIN_PADDING_LEN,
    };
    use crate::FieldState;

    fn record_test_client_hello_message() -> (Vec<u8>, Vec<u8>) {
        let body = TlsClientHello::new()
            .with_random([0x11; TLS_CLIENT_HELLO_RANDOM_LEN])
            .with_raw_cipher_suites([0x1301])
            .with_compression_methods([0x00])
            .with_extension(TlsRawExtension::from_raw(0xbeef, [0xde, 0xad]))
            .encode_to_vec()
            .unwrap();
        let len = body.len() as u32;
        let mut message = vec![
            TlsHandshakeType::CLIENT_HELLO.raw(),
            ((len >> 16) & 0xff) as u8,
            ((len >> 8) & 0xff) as u8,
            (len & 0xff) as u8,
        ];
        message.extend_from_slice(&body);
        (message, body)
    }

    #[test]
    fn tls_record_encodes_auto_length_and_preserves_override() -> Result<()> {
        let record = TlsRecord::handshake([0xaa, 0xbb, 0xcc]);

        assert_eq!(record.content_type(), TlsContentType::HANDSHAKE);
        assert_eq!(record.legacy_record_version(), TlsVersion::legacy_record());
        assert_eq!(record.declared_length(), None);
        assert_eq!(record.fragment(), &[0xaa, 0xbb, 0xcc]);
        assert_eq!(record.fragment_len(), 3);
        assert_eq!(record.effective_length()?, 3);
        assert_eq!(record.encoded_len()?, TLS_RECORD_HEADER_LEN + 3);
        assert_eq!(
            record.encode_to_vec()?,
            vec![0x16, 0x03, 0x03, 0x00, 0x03, 0xaa, 0xbb, 0xcc]
        );
        assert_eq!(record.compile()?, record.encode_to_vec()?);

        let overridden = record.clone().with_length(1);
        assert_eq!(overridden.declared_length(), Some(1));
        assert_eq!(overridden.effective_length()?, 1);
        assert_eq!(overridden.declared_record_len()?, TLS_RECORD_HEADER_LEN + 1);
        assert_eq!(overridden.actual_record_len()?, TLS_RECORD_HEADER_LEN + 3);
        assert_eq!(
            overridden.encode_to_vec()?,
            vec![0x16, 0x03, 0x03, 0x00, 0x01, 0xaa, 0xbb, 0xcc]
        );
        Ok(())
    }

    #[test]
    fn tls_record_decode_consumes_one_complete_record_and_preserves_tail() -> Result<()> {
        let bytes = [0x15, 0x03, 0x01, 0x00, 0x02, 0x01, 0x00, 0xaa];

        let (record, tail) = TlsRecord::decode_prefix(&bytes)?;
        let (record_with_consumed, consumed) = TlsRecord::decode_with_consumed(&bytes)?;

        assert_eq!(tail, &[0xaa]);
        assert_eq!(consumed, TLS_RECORD_HEADER_LEN + 2);
        assert_eq!(record_with_consumed, record);
        assert_eq!(record.content_type(), TlsContentType::alert());
        assert_eq!(record.legacy_record_version(), TlsVersion::tls_1_0());
        assert_eq!(record.declared_length(), Some(2));
        assert_eq!(record.declared_length_state(), FieldState::User);
        assert_eq!(record.fragment(), &[0x01, 0x00]);
        assert!(record.body().is_opaque());
        assert_eq!(
            record.encode_to_vec()?,
            vec![0x15, 0x03, 0x01, 0x00, 0x02, 0x01, 0x00]
        );
        assert_eq!(TlsRecord::decode(bytes)?.fragment(), &[0x01, 0x00]);
        Ok(())
    }

    #[test]
    fn tls_change_cipher_spec_standard_value_round_trips_as_typed_record() -> Result<()> {
        let change_cipher_spec = TlsChangeCipherSpec::standard();

        assert_eq!(change_cipher_spec.value(), TLS_CHANGE_CIPHER_SPEC_VALUE);
        assert_eq!(change_cipher_spec.raw_value(), 1);
        assert!(change_cipher_spec.is_standard());
        assert_eq!(change_cipher_spec.encoded_len(), TLS_CHANGE_CIPHER_SPEC_LEN);
        assert_eq!(change_cipher_spec.encode_to_vec(), vec![0x01]);
        assert_eq!(change_cipher_spec.compile(), vec![0x01]);
        assert_eq!(
            change_cipher_spec.summary(),
            "change_cipher_spec value=change_cipher_spec raw=0x01"
        );
        assert_eq!(
            change_cipher_spec.inspection_fields(),
            vec![
                ("value", "change_cipher_spec".to_string()),
                ("value_raw", "0x01".to_string()),
                ("standard", "true".to_string()),
            ]
        );

        let record = TlsRecord::from_change_cipher_spec(change_cipher_spec);
        let encoded = vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
        assert_eq!(record.content_type(), TlsContentType::CHANGE_CIPHER_SPEC);
        assert_eq!(record.fragment(), &[0x01]);
        assert!(record.body().is_change_cipher_spec());
        assert_eq!(record.change_cipher_spec_body(), Some(&change_cipher_spec));
        assert_eq!(record.encode_to_vec()?, encoded);
        assert_eq!(
            record.summary(),
            "record content_type=change_cipher_spec legacy_record_version=TLS 1.2 declared_length=auto fragment_bytes=1 body=change_cipher_spec value=change_cipher_spec raw=0x01"
        );

        let decoded = TlsRecord::decode(&encoded)?;
        assert!(decoded.body().is_change_cipher_spec());
        assert_eq!(decoded.change_cipher_spec_body(), Some(&change_cipher_spec));
        assert_eq!(decoded.fragment(), &[0x01]);
        assert_eq!(decoded.encode_to_vec()?, encoded);

        Ok(())
    }

    #[test]
    fn tls_change_cipher_spec_unknown_one_byte_value_is_preserved() -> Result<()> {
        let change_cipher_spec = TlsChangeCipherSpec::from_raw_value(0x7f);
        let encoded = vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x7f];

        assert!(!change_cipher_spec.is_standard());
        assert_eq!(
            change_cipher_spec.value_label(),
            "unknown change_cipher_spec 0x7f"
        );
        assert_eq!(
            change_cipher_spec.summary(),
            "change_cipher_spec value=unknown change_cipher_spec 0x7f raw=0x7f"
        );
        assert_eq!(TlsChangeCipherSpec::decode([0x7f])?, change_cipher_spec);

        let decoded = TlsRecord::decode(&encoded)?;
        assert_eq!(decoded.change_cipher_spec_body(), Some(&change_cipher_spec));
        assert_eq!(decoded.fragment(), &[0x7f]);
        assert_eq!(decoded.encode_to_vec()?, encoded);

        Ok(())
    }

    #[test]
    fn tls_change_cipher_spec_raw_builders_preserve_empty_and_oversized_fragments() -> Result<()> {
        let empty = TlsRecord::change_cipher_spec([]);
        assert_eq!(empty.content_type(), TlsContentType::CHANGE_CIPHER_SPEC);
        assert!(empty.body().is_opaque());
        assert_eq!(empty.change_cipher_spec_body(), None);
        assert_eq!(empty.fragment(), &[]);
        assert_eq!(empty.encode_to_vec()?, vec![0x14, 0x03, 0x03, 0x00, 0x00]);

        let oversized = TlsRecord::change_cipher_spec([0x01, 0x02]);
        assert!(oversized.body().is_opaque());
        assert_eq!(oversized.change_cipher_spec_body(), None);
        assert_eq!(oversized.fragment(), &[0x01, 0x02]);
        assert_eq!(
            oversized.encode_to_vec()?,
            vec![0x14, 0x03, 0x03, 0x00, 0x02, 0x01, 0x02]
        );

        Ok(())
    }

    #[test]
    fn tls_change_cipher_spec_decode_reports_empty_and_oversized_fragments() {
        assert_eq!(
            TlsChangeCipherSpec::decode([]).unwrap_err(),
            CrafterError::buffer_too_short("tls.change_cipher_spec", TLS_CHANGE_CIPHER_SPEC_LEN, 0)
        );
        assert_eq!(
            TlsChangeCipherSpec::decode([0x01, 0x02]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.change_cipher_spec.length",
                "trailing bytes after value"
            )
        );
        assert_eq!(
            TlsRecord::decode([0x14, 0x03, 0x03, 0x00, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short("tls.change_cipher_spec", TLS_CHANGE_CIPHER_SPEC_LEN, 0)
        );
        assert_eq!(
            TlsRecord::decode([0x14, 0x03, 0x03, 0x00, 0x02, 0x01, 0x02]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.change_cipher_spec.length",
                "trailing bytes after value"
            )
        );
    }

    #[test]
    fn tls_application_data_preserves_opaque_bytes_without_inner_decoding() -> Result<()> {
        let payload = b"GET / HTTP/1.1\r\nhost: example.test\r\n\r\n".to_vec();
        let application_data = TlsApplicationData::new(payload.clone());

        assert_eq!(application_data.bytes(), payload.as_slice());
        assert_eq!(application_data.fragment(), payload.as_slice());
        assert_eq!(application_data.data(), payload.as_slice());
        assert_eq!(application_data.len(), payload.len());
        assert!(!application_data.is_empty());
        assert_eq!(application_data.encoded_len(), payload.len());
        assert_eq!(application_data.encode_to_vec(), payload);
        assert_eq!(application_data.compile(), payload);
        assert_eq!(
            application_data.summary(),
            format!("application_data bytes={}", payload.len())
        );
        assert_eq!(
            application_data.inspection_fields(),
            vec![
                ("bytes", payload.len().to_string()),
                ("data", hex_bytes(&payload)),
            ]
        );

        let record = TlsRecord::application_data(payload.clone());
        let mut encoded = vec![
            0x17,
            0x03,
            0x03,
            ((payload.len() >> 8) & 0xff) as u8,
            (payload.len() & 0xff) as u8,
        ];
        encoded.extend_from_slice(&payload);

        assert_eq!(record.content_type(), TlsContentType::APPLICATION_DATA);
        assert!(record.body().is_application_data());
        assert!(!record.body().is_opaque());
        assert_eq!(record.application_data_body(), Some(&application_data));
        assert_eq!(record.fragment(), payload.as_slice());
        assert_eq!(record.encode_to_vec()?, encoded);
        assert_eq!(
            record.summary(),
            format!(
                "record content_type=application_data legacy_record_version=TLS 1.2 declared_length=auto fragment_bytes={} body=application_data bytes={}",
                payload.len(),
                payload.len()
            )
        );

        let decoded = TlsRecord::decode(&encoded)?;
        assert!(decoded.body().is_application_data());
        assert_eq!(decoded.application_data_body(), Some(&application_data));
        assert_eq!(decoded.encode_to_vec()?, encoded);

        Ok(())
    }

    #[test]
    fn tls_application_data_empty_and_arbitrary_bytes_round_trip() -> Result<()> {
        let empty_body = TlsApplicationData::default();
        let empty = TlsRecord::from_application_data(empty_body.clone());
        let empty_encoded = vec![0x17, 0x03, 0x03, 0x00, 0x00];
        assert_eq!(empty.application_data_body(), Some(&empty_body));
        assert_eq!(empty.encode_to_vec()?, empty_encoded);

        let decoded_empty = TlsRecord::decode(&empty_encoded)?;
        let decoded_empty_body = decoded_empty
            .application_data_body()
            .expect("application_data body");
        assert!(decoded_empty_body.is_empty());
        assert_eq!(decoded_empty.encode_to_vec()?, empty_encoded);

        let arbitrary = TlsApplicationData::from_bytes([0x00, 0xff, 0x16, 0x03, 0x03]);
        let record = TlsRecord::from_application_data(arbitrary.clone());
        assert_eq!(record.application_data_body(), Some(&arbitrary));
        assert_eq!(
            record.encode_to_vec()?,
            vec![0x17, 0x03, 0x03, 0x00, 0x05, 0x00, 0xff, 0x16, 0x03, 0x03]
        );

        Ok(())
    }

    #[test]
    fn tls_heartbeat_record_builds_decodes_and_preserves_full_fragment() -> Result<()> {
        let heartbeat = TlsHeartbeat::request([0xde, 0xad], [0x77; TLS_HEARTBEAT_MIN_PADDING_LEN]);
        let fragment = heartbeat.encode_to_vec()?;
        let record = TlsRecord::from_heartbeat(heartbeat.clone())?;
        let mut encoded = vec![
            0x18,
            0x03,
            0x03,
            ((fragment.len() >> 8) & 0xff) as u8,
            (fragment.len() & 0xff) as u8,
        ];
        encoded.extend_from_slice(&fragment);

        assert_eq!(record.content_type(), TlsContentType::HEARTBEAT);
        assert!(record.body().is_heartbeat());
        assert_eq!(record.heartbeat_body(), Some(&heartbeat));
        assert_eq!(record.fragment(), fragment.as_slice());
        assert_eq!(record.encode_to_vec()?, encoded);
        assert_eq!(
            record.summary(),
            format!(
                "record content_type=heartbeat legacy_record_version=TLS 1.2 declared_length=auto fragment_bytes={} body=heartbeat type=heartbeat_request declared_payload_length=auto payload_bytes=2 padding_bytes={}",
                fragment.len(),
                TLS_HEARTBEAT_MIN_PADDING_LEN
            )
        );

        let decoded = TlsRecord::decode(&encoded)?;
        let decoded_heartbeat = decoded.heartbeat_body().expect("heartbeat body");
        assert_eq!(decoded.content_type(), TlsContentType::HEARTBEAT);
        assert!(decoded.body().is_heartbeat());
        assert_eq!(
            decoded_heartbeat.message_type(),
            TlsHeartbeatMessageType::REQUEST
        );
        assert_eq!(decoded_heartbeat.declared_payload_length(), Some(2));
        assert_eq!(decoded_heartbeat.payload(), &[0xde, 0xad]);
        assert_eq!(
            decoded_heartbeat.padding(),
            &[0x77; TLS_HEARTBEAT_MIN_PADDING_LEN]
        );
        assert_eq!(decoded.fragment(), fragment.as_slice());
        assert_eq!(decoded.encode_to_vec()?, encoded);

        Ok(())
    }

    #[test]
    fn tls_heartbeat_record_raw_builder_preserves_malformed_fragments() -> Result<()> {
        let raw = TlsRecord::heartbeat([0x01, 0x00, 0x04, 0xaa]);

        assert_eq!(raw.content_type(), TlsContentType::HEARTBEAT);
        assert!(raw.body().is_opaque());
        assert_eq!(raw.heartbeat_body(), None);
        assert_eq!(raw.fragment(), &[0x01, 0x00, 0x04, 0xaa]);
        assert_eq!(
            raw.encode_to_vec()?,
            vec![0x18, 0x03, 0x03, 0x00, 0x04, 0x01, 0x00, 0x04, 0xaa]
        );

        assert_eq!(
            TlsRecord::decode([0x18, 0x03, 0x03, 0x00, 0x04, 0x01, 0x00, 0x04, 0xaa]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.heartbeat.payload",
                7,
                TLS_HEARTBEAT_HEADER_LEN + 1
            )
        );

        Ok(())
    }

    #[test]
    fn tls_handshake_record_decode_parses_messages_and_preserves_partial_tail() -> Result<()> {
        let (first, first_body) = record_test_client_hello_message();
        let second = [0x14, 0x00, 0x00, 0x01, 0x00];
        let partial = [0x02, 0x00, 0x00, 0x02, 0xaa];
        let expected_fragment = [&first[..], &second[..], &partial[..]].concat();
        let mut bytes = vec![
            0x16,
            0x03,
            0x03,
            ((expected_fragment.len() >> 8) & 0xff) as u8,
            (expected_fragment.len() & 0xff) as u8,
        ];
        bytes.extend_from_slice(&expected_fragment);

        let record = TlsRecord::decode(&bytes)?;
        let body = record
            .body()
            .handshake_body()
            .expect("handshake record body");

        assert_eq!(record.content_type(), TlsContentType::HANDSHAKE);
        assert!(record.body().is_handshake());
        assert_eq!(body.messages().len(), 2);
        assert_eq!(
            body.messages()[0].handshake_type(),
            TlsHandshakeType::CLIENT_HELLO
        );
        assert_eq!(body.messages()[0].body_bytes(), first_body.as_slice());
        assert_eq!(
            body.messages()[1].handshake_type(),
            TlsHandshakeType::FINISHED
        );
        assert_eq!(body.messages()[1].body_bytes(), &[0x00]);
        assert_eq!(body.raw_tail(), &partial);
        assert!(body.has_raw_tail());
        assert_eq!(record.fragment(), expected_fragment.as_slice());
        assert_eq!(record.encode_to_vec()?, bytes);

        Ok(())
    }

    #[test]
    fn tls_fragmented_handshake_preserves_first_partial_message_as_raw_tail() -> Result<()> {
        let short_header = [0x16, 0x03, 0x03, 0x00, 0x01, 0x01];
        let record = TlsRecord::decode(short_header)?;
        let body = record
            .body()
            .handshake_body()
            .expect("partial handshake body");
        assert!(record.body().is_handshake());
        assert_eq!(body.messages(), &[]);
        assert_eq!(body.raw_tail(), &[0x01]);
        assert_eq!(record.fragment(), &[0x01]);
        assert_eq!(record.encode_to_vec()?, short_header);

        let partial_body = [0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x04, 0xaa];
        let record = TlsRecord::decode(partial_body)?;
        let body = record
            .body()
            .handshake_body()
            .expect("partial handshake body");
        assert_eq!(body.messages(), &[]);
        assert_eq!(body.raw_tail(), &[0x01, 0x00, 0x00, 0x04, 0xaa]);
        assert!(body.has_raw_tail());
        assert_eq!(record.fragment(), &[0x01, 0x00, 0x00, 0x04, 0xaa]);
        assert_eq!(record.encode_to_vec()?, partial_body);

        Ok(())
    }

    #[test]
    fn tls_fragmented_handshake_empty_record_fragment_is_preserved() -> Result<()> {
        let record = TlsRecord::decode([0x16, 0x03, 0x03, 0x00, 0x00])?;
        let body = record
            .body()
            .handshake_body()
            .expect("empty handshake body");

        assert_eq!(body.messages(), &[]);
        assert_eq!(body.raw_tail(), &[]);
        assert!(!body.has_raw_tail());
        assert_eq!(record.fragment(), &[]);
        assert_eq!(
            record.summary(),
            "record content_type=handshake legacy_record_version=TLS 1.2 declared_length=0 fragment_bytes=0 body=handshake messages=0 raw_tail_bytes=0 fragment_bytes=0 types=[] details=[]"
        );

        Ok(())
    }

    #[test]
    fn tls_handshake_record_encode_round_trips_typed_body_and_raw_tail() -> Result<()> {
        let message = TlsHandshake::client_hello([0xaa, 0xbb, 0xcc]).with_length(1);
        let record = TlsRecord::handshake_messages_with_raw_tail([message], [0xde])?.with_length(2);

        assert_eq!(record.declared_length(), Some(2));
        assert_eq!(record.effective_length()?, 2);
        assert_eq!(record.fragment_len(), TLS_HANDSHAKE_HEADER_LEN + 4);
        assert_eq!(
            record.encode_to_vec()?,
            vec![0x16, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xde,]
        );

        let body = record.body().handshake_body().expect("typed body");
        assert_eq!(body.messages().len(), 1);
        assert_eq!(body.raw_tail(), &[0xde]);
        assert_eq!(
            record.fragment(),
            &[0x01, 0x00, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xde]
        );

        Ok(())
    }

    #[test]
    fn tls_handshake_record_non_handshake_records_remain_opaque() -> Result<()> {
        let bytes = [0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00];
        let record = TlsRecord::decode(bytes)?;

        assert_eq!(record.content_type(), TlsContentType::alert());
        assert!(record.body().is_opaque());
        assert_eq!(record.fragment(), &[0x01, 0x00]);
        assert_eq!(record.encode_to_vec()?, bytes);

        Ok(())
    }

    #[test]
    fn tls_record_preserves_unknown_content_type_as_opaque_fragment() -> Result<()> {
        let record = TlsRecord::decode([0xfe, 0x42, 0x42, 0x00, 0x02, 0xde, 0xad])?;

        assert_eq!(record.content_type(), TlsContentType::from_u8(0xfe));
        assert_eq!(record.raw_content_type(), 0xfe);
        assert_eq!(record.legacy_record_version(), TlsVersion::from_u16(0x4242));
        assert_eq!(record.fragment(), &[0xde, 0xad]);
        assert!(record.body().is_opaque());
        assert_eq!(
            record.encode_to_vec()?,
            vec![0xfe, 0x42, 0x42, 0x00, 0x02, 0xde, 0xad]
        );
        assert_eq!(
            record.summary(),
            "record content_type=unassigned content type 0xfe legacy_record_version=unknown protocol version 0x4242 declared_length=2 fragment_bytes=2 body=opaque bytes=2"
        );

        let fields = record.inspection_fields();
        assert!(fields.contains(&("content_type", "unassigned content type 0xfe".to_string())));
        assert!(fields.contains(&("fragment_bytes", "2".to_string())));
        assert!(fields.contains(&("body", "opaque".to_string())));
        Ok(())
    }

    #[test]
    fn tls_record_short_input_is_structured_error() {
        assert_eq!(
            TlsRecord::decode([0x16, 0x03, 0x03, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short("tls.record.header", TLS_RECORD_HEADER_LEN, 4)
        );
        assert_eq!(
            TlsRecord::decode([0x16, 0x03, 0x03, 0x00, 0x04, 0xaa]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.record.fragment",
                TLS_RECORD_HEADER_LEN + 4,
                TLS_RECORD_HEADER_LEN + 1
            )
        );
    }

    #[test]
    fn tls_record_encode_rejects_oversized_auto_length_but_allows_override() {
        let oversized = TlsRecord::application_data(vec![0; usize::from(u16::MAX) + 1]);

        assert_eq!(
            oversized.encode_to_vec().unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.record.length",
                "fragment length must fit in two bytes"
            )
        );

        let overridden = oversized.with_length(0);
        assert_eq!(overridden.effective_length().unwrap(), 0);
    }

    #[test]
    fn tls_record_header_builders_default_legacy_version_and_unset_length() -> Result<()> {
        let header = TlsRecordHeader::handshake();

        assert_eq!(header.content_type(), TlsContentType::HANDSHAKE);
        assert_eq!(header.raw_content_type(), 0x16);
        assert_eq!(header.legacy_record_version(), TlsVersion::legacy_record());
        assert_eq!(header.version(), TlsVersion::legacy_record());
        assert!(header.uses_legacy_record_version());
        assert_eq!(header.declared_length(), None);
        assert_eq!(header.length_override(), None);
        assert_eq!(header.declared_length_state(), FieldState::Unset);
        assert_eq!(header.effective_length(3)?, 3);
        assert_eq!(header.declared_record_len(3)?, TLS_RECORD_HEADER_LEN + 3);
        assert_eq!(header.actual_record_len(9)?, TLS_RECORD_HEADER_LEN + 9);

        let raw = TlsRecordHeader::new(0xff)
            .with_raw_version(0x7a7a)
            .with_declared_length(0x1234);
        assert_eq!(raw.content_type(), TlsContentType::from_u8(0xff));
        assert_eq!(raw.raw_version(), 0x7a7a);
        assert_eq!(raw.declared_len(), Some(0x1234));
        assert_eq!(raw.length_state(), FieldState::User);
        Ok(())
    }

    #[test]
    fn tls_record_header_encode_fills_unset_length_and_preserves_override() -> Result<()> {
        let header = TlsRecordHeader::handshake();
        assert_eq!(
            header.encode_to_vec_with_fragment_len(3)?,
            vec![0x16, 0x03, 0x03, 0x00, 0x03]
        );
        assert_eq!(header.encode_to_vec()?, vec![0x16, 0x03, 0x03, 0x00, 0x00]);

        let overridden = header.with_length(1);
        assert_eq!(
            overridden.encode_to_vec_with_fragment_len(3)?,
            vec![0x16, 0x03, 0x03, 0x00, 0x01]
        );
        assert_eq!(overridden.effective_length(usize::from(u16::MAX) + 1)?, 1);

        let oversized = TlsRecordHeader::application_data()
            .effective_length(usize::from(u16::MAX) + 1)
            .unwrap_err();
        assert_eq!(
            oversized,
            CrafterError::invalid_field_value(
                "tls.record.length",
                "fragment length must fit in two bytes"
            )
        );
        Ok(())
    }

    #[test]
    fn tls_record_header_decode_preserves_declared_length_and_tail() -> Result<()> {
        let bytes = [0x15, 0x03, 0x01, 0x00, 0x02, 0xaa, 0xbb, 0xcc];

        let (header, tail) = TlsRecordHeader::decode_prefix(&bytes)?;

        assert_eq!(header.content_type(), TlsContentType::alert());
        assert_eq!(header.legacy_record_version(), TlsVersion::tls_1_0());
        assert_eq!(header.declared_length(), Some(2));
        assert_eq!(header.length_state(), FieldState::User);
        assert_eq!(header.effective_length(99)?, 2);
        assert_eq!(tail, &[0xaa, 0xbb, 0xcc]);
        assert_eq!(TlsRecordHeader::decode(bytes)?.declared_length(), Some(2));
        assert_eq!(
            header.encode_to_vec_with_fragment_len(99)?,
            vec![0x15, 0x03, 0x01, 0x00, 0x02]
        );
        Ok(())
    }

    #[test]
    fn tls_record_header_short_input_is_structured_error() {
        for available in 0..TLS_RECORD_HEADER_LEN {
            let bytes = vec![0u8; available];

            assert_eq!(
                TlsRecordHeader::decode_prefix(&bytes).unwrap_err(),
                CrafterError::buffer_too_short(
                    "tls.record.header",
                    TLS_RECORD_HEADER_LEN,
                    available
                )
            );
        }
    }

    #[test]
    fn tls_record_header_summary_and_inspection_show_legacy_context() {
        let header = TlsRecordHeader::handshake().with_length(4);

        assert_eq!(
            header.summary(),
            "record_header content_type=handshake legacy_record_version=TLS 1.2 declared_length=4"
        );

        let fields = header.inspection_fields();
        assert!(fields.contains(&("content_type", "handshake".to_string())));
        assert!(fields.contains(&("content_type_raw", "0x16".to_string())));
        assert!(fields.contains(&("legacy_record_version", "TLS 1.2".to_string())));
        assert!(fields.contains(&("legacy_record_version_raw", "0x0303".to_string())));
        assert!(fields.contains(&(
            "legacy_record_version_role",
            "record compatibility field".to_string()
        )));
        assert!(fields.contains(&("declared_length", "4".to_string())));
        assert!(fields.contains(&("declared_length_state", "user".to_string())));
        assert!(fields.contains(&("header_bytes", "5".to_string())));
    }
}
