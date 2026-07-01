//! TLS record-layer header helpers.
//!
//! Full TLS record bodies are modeled in later source-backed steps. This module
//! currently owns only the fixed five-octet record header:
//! `ContentType | legacy_record_version | length`.

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
