//! TLS record-layer helpers.
//!
//! A TLS record is the fixed five-octet record header followed by the declared
//! fragment bytes: `ContentType | legacy_record_version | length | fragment`.
//! Inner message parsing is intentionally deferred; record bodies are preserved
//! as opaque fragments so unsupported, encrypted, or future content types
//! round-trip unchanged.

use super::content_type::TlsContentType;
use super::version::{TlsVersion, TlsVersionField};
use crate::field::{Field, FieldState};
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

/// TLS record body hook.
///
/// The record layer currently keeps every fragment opaque. The enum exists as
/// the local typed-body seam for later source-backed handshake, alert,
/// change_cipher_spec, application_data, and heartbeat modeling without
/// changing the record container shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsRecordBody {
    /// Opaque TLS record fragment bytes.
    Opaque(Vec<u8>),
}

impl TlsRecordBody {
    /// Preserve fragment bytes without inner parsing.
    pub fn opaque(fragment: impl Into<Vec<u8>>) -> Self {
        Self::Opaque(fragment.into())
    }

    /// Borrow the bytes that will be emitted after the record header.
    pub fn fragment(&self) -> &[u8] {
        match self {
            Self::Opaque(fragment) => fragment,
        }
    }

    /// Consume the body hook and return the preserved fragment bytes.
    pub fn into_fragment(self) -> Vec<u8> {
        match self {
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

    /// Append the body fragment bytes to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.fragment());
    }

    /// Return the preserved fragment bytes as a new vector.
    pub fn encode_to_vec(&self) -> Vec<u8> {
        self.fragment().to_vec()
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Opaque(_) => "opaque",
        }
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

    /// Construct an `alert` TLS record.
    pub fn alert(fragment: impl Into<Vec<u8>>) -> Self {
        Self::from_header_and_fragment(TlsRecordHeader::alert(), fragment)
    }

    /// Construct a `handshake` TLS record.
    pub fn handshake(fragment: impl Into<Vec<u8>>) -> Self {
        Self::from_header_and_fragment(TlsRecordHeader::handshake(), fragment)
    }

    /// Construct an `application_data` TLS record.
    pub fn application_data(fragment: impl Into<Vec<u8>>) -> Self {
        Self::from_header_and_fragment(TlsRecordHeader::application_data(), fragment)
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
        Ok((
            Self::from_header_and_fragment(header, fragment),
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
            self.body.label()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = self.header.inspection_fields();
        fields.push(("body", self.body.label().to_string()));
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
    use crate::FieldState;

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
            "record content_type=unassigned content type 0xfe legacy_record_version=unknown protocol version 0x4242 declared_length=2 fragment_bytes=2 body=opaque"
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
