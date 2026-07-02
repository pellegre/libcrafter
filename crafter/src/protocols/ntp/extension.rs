//! Raw-preserving NTP extension field model.

use super::constants::{
    NTP_EXTENSION_FIELD_HEADER_LEN, NTP_EXTENSION_FIELD_MIN_LAST_WITHOUT_MAC_LEN,
    NTP_EXTENSION_FIELD_MIN_LEN, NTP_LEGACY_MAC_KEY_ID_LEN,
};
use super::registry::{
    ntp_extension_type, NtpExtensionFieldType, NtpExtensionFieldTypeCategory, NtpRegistryMeta,
};
use crate::error::{CrafterError, Result};
use crate::field::Field;

pub(super) const NTP_EXTENSION_CONTEXT: &str = "ntp.extension";
pub(super) const NTP_EXTENSION_LENGTH_CONTEXT: &str = "ntp.extension.length";
pub(super) const NTP_MAC_CONTEXT: &str = "ntp.mac";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NtpExtensionDecodeAll {
    pub(super) fields: Vec<NtpExtensionField>,
    pub(super) legacy_mac: Option<Vec<u8>>,
}

/// UDP Checksum Complement NTP extension body.
///
/// RFC 7821 defines this packet-data extension, and RFC 9748 keeps the current
/// registry assignment at field type `0x2005`. This model only carries the NTP
/// extension bytes; UDP checksum calculation remains the UDP layer's job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtpChecksumComplementExtension {
    body: Vec<u8>,
}

impl NtpChecksumComplementExtension {
    /// NTP Extension Field Type for UDP Checksum Complement.
    pub const FIELD_TYPE: u16 = 0x2005;

    /// Build a UDP Checksum Complement body from raw bytes.
    pub fn new(body: impl Into<Vec<u8>>) -> Self {
        Self { body: body.into() }
    }

    /// Build a UDP Checksum Complement body from the two-octet complement.
    pub fn from_complement(complement: u16) -> Self {
        Self::new(complement.to_be_bytes())
    }

    /// NTP Extension Field Type encoded for this body.
    pub const fn field_type(&self) -> u16 {
        Self::FIELD_TYPE
    }

    /// Raw extension body bytes, excluding the four-octet extension envelope.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Return the first two body octets as a checksum complement, when present.
    pub fn complement_value(&self) -> Option<u16> {
        let bytes = self.body.get(..2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    /// Convert to the generic raw-preserving NTP extension field envelope.
    pub fn into_extension_field(self) -> NtpExtensionField {
        self.into()
    }

    /// Decode a generic extension field as UDP Checksum Complement when typed.
    pub fn from_extension_field(field: &NtpExtensionField) -> Option<Self> {
        if field.is_udp_checksum_complement() {
            Some(Self::new(field.value().to_vec()))
        } else {
            None
        }
    }
}

impl From<NtpChecksumComplementExtension> for NtpExtensionField {
    fn from(extension: NtpChecksumComplementExtension) -> Self {
        Self::new(NtpChecksumComplementExtension::FIELD_TYPE, extension.body)
    }
}

/// Raw-preserving NTP extension field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtpExtensionField {
    field_type: Field<u16>,
    length: Field<u16>,
    value: Vec<u8>,
    padding: Option<Vec<u8>>,
}

impl NtpExtensionField {
    /// Build an extension field with an auto-filled length.
    pub fn new(field_type: u16, value: impl Into<Vec<u8>>) -> Self {
        Self {
            field_type: Field::user(field_type),
            length: Field::unset(),
            value: value.into(),
            padding: None,
        }
    }

    /// Build an Unknown or currently unassigned extension field.
    pub fn unknown(field_type: u16, value: impl Into<Vec<u8>>) -> Self {
        Self::new(field_type, value)
    }

    /// Build an NTS Unique Identifier extension field.
    pub fn nts_unique_identifier(value: impl Into<Vec<u8>>) -> Self {
        Self::new(0x0104, value)
    }

    /// Build an NTS Cookie extension field.
    pub fn nts_cookie(value: impl Into<Vec<u8>>) -> Self {
        Self::new(0x0204, value)
    }

    /// Build an NTS Cookie Placeholder extension field.
    pub fn nts_cookie_placeholder(value: impl Into<Vec<u8>>) -> Self {
        Self::new(0x0304, value)
    }

    /// Build an NTS Authenticator and Encrypted Extension Fields wrapper.
    pub fn nts_authenticator_encrypted(value: impl Into<Vec<u8>>) -> Self {
        Self::new(0x0404, value)
    }

    /// Build a UDP Checksum Complement extension field.
    pub fn udp_checksum_complement(value: impl Into<Vec<u8>>) -> Self {
        NtpChecksumComplementExtension::new(value).into_extension_field()
    }

    /// Build an Autokey-related raw extension field by type.
    pub fn autokey_raw(field_type: u16, value: impl Into<Vec<u8>>) -> Self {
        Self::new(field_type, value)
    }

    /// Set an explicit declared extension length.
    pub fn declared_length(mut self, length: u16) -> Self {
        self.length.set_user(length);
        self
    }

    /// Set explicit padding bytes to serialize after the value bytes.
    pub fn padding(mut self, padding: impl Into<Vec<u8>>) -> Self {
        self.padding = Some(padding.into());
        self
    }

    /// Raw extension field type.
    pub fn field_type(&self) -> u16 {
        self.field_type.value().copied().unwrap_or(0)
    }

    /// Source-backed extension field type metadata.
    pub fn extension_type(&self) -> NtpExtensionFieldType {
        ntp_extension_type(self.field_type())
    }

    /// Stable extension field type label for summary and inspection output.
    pub fn label(&self) -> String {
        self.extension_type().label().to_string()
    }

    /// Stable extension field type summary label without exposing body bytes.
    pub fn summary_label(&self) -> String {
        self.label()
    }

    /// Declared length when caller-set or decoded.
    pub fn declared_length_value(&self) -> Option<u16> {
        self.length.value().copied()
    }

    /// Borrow the extension value bytes excluding the four-octet envelope.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Borrow explicit padding bytes, when caller-provided.
    pub fn padding_value(&self) -> Option<&[u8]> {
        self.padding.as_deref()
    }

    /// Source-backed metadata for the extension field type.
    pub fn registry_meta(&self) -> NtpRegistryMeta {
        self.extension_type().registry_meta()
    }

    /// Return true when the field type is unknown or currently unassigned.
    pub fn is_unknown_or_unassigned(&self) -> bool {
        matches!(
            self.extension_type().category(),
            NtpExtensionFieldTypeCategory::UnknownOrUnassigned
        )
    }

    /// Return true when the field type is assigned by the NTS extension registry.
    pub fn is_nts_extension(&self) -> bool {
        matches!(self.field_type(), 0x0104 | 0x0204 | 0x0304 | 0x0404)
    }

    /// Return true when the field type is the UDP Checksum Complement extension.
    pub fn is_udp_checksum_complement(&self) -> bool {
        self.field_type() == NtpChecksumComplementExtension::FIELD_TYPE
    }

    /// Borrow this field body through the typed UDP Checksum Complement helper.
    pub fn as_udp_checksum_complement(&self) -> Option<NtpChecksumComplementExtension> {
        NtpChecksumComplementExtension::from_extension_field(self)
    }

    pub(super) fn from_decoded(field_type: u16, declared_length: u16, value: Vec<u8>) -> Self {
        Self {
            field_type: Field::user(field_type),
            length: Field::user(declared_length),
            value,
            padding: None,
        }
    }

    pub(super) fn encoded_len(&self, last_without_mac: bool) -> usize {
        if let Some(length) = self.length.value().copied() {
            return usize::from(length).max(NTP_EXTENSION_FIELD_HEADER_LEN);
        }

        let minimum = if last_without_mac {
            NTP_EXTENSION_FIELD_MIN_LAST_WITHOUT_MAC_LEN
        } else {
            NTP_EXTENSION_FIELD_MIN_LEN
        };
        align_4((NTP_EXTENSION_FIELD_HEADER_LEN + self.body_len()).max(minimum))
    }

    pub(super) fn compile(&self, last_without_mac: bool, out: &mut Vec<u8>) -> Result<()> {
        let encoded_len = self.encoded_len(last_without_mac);
        let declared_len = self.length.value().copied().unwrap_or(encoded_len as u16);

        out.extend_from_slice(&self.field_type().to_be_bytes());
        out.extend_from_slice(&declared_len.to_be_bytes());

        let body_len = encoded_len.saturating_sub(NTP_EXTENSION_FIELD_HEADER_LEN);
        let copy_value_len = body_len.min(self.value.len());
        out.extend_from_slice(&self.value[..copy_value_len]);

        let remaining_body_len = body_len - copy_value_len;
        if remaining_body_len == 0 {
            return Ok(());
        }

        let copy_padding_len = if let Some(padding) = self.padding.as_deref() {
            let copy_padding_len = remaining_body_len.min(padding.len());
            out.extend_from_slice(&padding[..copy_padding_len]);
            copy_padding_len
        } else {
            0
        };
        out.resize(out.len() + (remaining_body_len - copy_padding_len), 0);
        Ok(())
    }

    fn body_len(&self) -> usize {
        self.value.len() + self.padding.as_ref().map(Vec::len).unwrap_or(0)
    }
}

pub(super) fn encoded_all_len(fields: &[NtpExtensionField], has_legacy_mac: bool) -> usize {
    fields
        .iter()
        .enumerate()
        .map(|(index, field)| {
            let last_without_mac = index + 1 == fields.len() && !has_legacy_mac;
            field.encoded_len(last_without_mac)
        })
        .sum()
}

pub(super) fn encode_all(
    fields: &[NtpExtensionField],
    has_legacy_mac: bool,
    out: &mut Vec<u8>,
) -> Result<()> {
    for (index, field) in fields.iter().enumerate() {
        let last_without_mac = index + 1 == fields.len() && !has_legacy_mac;
        field.compile(last_without_mac, out)?;
    }
    Ok(())
}

pub(super) fn decode_all(tail: &[u8]) -> Result<NtpExtensionDecodeAll> {
    let mut fields = Vec::new();
    let mut offset = 0;

    while offset < tail.len() {
        let remaining = &tail[offset..];
        if !fields.is_empty() && is_plausible_legacy_mac_len(remaining.len()) {
            return Ok(NtpExtensionDecodeAll {
                fields,
                legacy_mac: Some(remaining.to_vec()),
            });
        }
        if remaining.len() < NTP_EXTENSION_FIELD_HEADER_LEN {
            let context = if fields.is_empty() {
                NTP_EXTENSION_CONTEXT
            } else {
                NTP_MAC_CONTEXT
            };
            let required = if fields.is_empty() {
                NTP_EXTENSION_FIELD_HEADER_LEN
            } else {
                NTP_LEGACY_MAC_KEY_ID_LEN
            };
            return Err(CrafterError::buffer_too_short(
                context,
                required,
                remaining.len(),
            ));
        }

        let field_type = u16::from_be_bytes([remaining[0], remaining[1]]);
        let declared_len = u16::from_be_bytes([remaining[2], remaining[3]]) as usize;

        if let Err(err) = validate_extension_length(declared_len, remaining.len()) {
            return if can_partition_as_legacy_mac(fields.is_empty(), remaining.len()) {
                Ok(NtpExtensionDecodeAll {
                    fields,
                    legacy_mac: Some(remaining.to_vec()),
                })
            } else {
                Err(err)
            };
        }

        let final_without_mac = offset + declared_len == tail.len();
        if final_without_mac {
            if let Err(err) = validate_final_extension_without_mac_length(declared_len) {
                return if can_partition_as_legacy_mac(fields.is_empty(), remaining.len()) {
                    Ok(NtpExtensionDecodeAll {
                        fields,
                        legacy_mac: Some(remaining.to_vec()),
                    })
                } else {
                    Err(err)
                };
            }
        }

        let value = remaining[NTP_EXTENSION_FIELD_HEADER_LEN..declared_len].to_vec();
        fields.push(NtpExtensionField::from_decoded(
            field_type,
            declared_len as u16,
            value,
        ));
        offset += declared_len;
    }

    Ok(NtpExtensionDecodeAll {
        fields,
        legacy_mac: None,
    })
}

pub(super) fn tail_shape_is_plausible(tail: &[u8]) -> bool {
    if tail.is_empty() {
        return true;
    }
    if is_plausible_legacy_mac_len(tail.len()) {
        return true;
    }

    let mut offset = 0;
    while offset < tail.len() {
        let remaining = &tail[offset..];
        if offset > 0 && is_plausible_legacy_mac_len(remaining.len()) {
            return true;
        }
        if remaining.len() < NTP_EXTENSION_FIELD_HEADER_LEN {
            return false;
        }
        let declared_len = u16::from_be_bytes([remaining[2], remaining[3]]) as usize;
        if !is_valid_extension_length(declared_len, remaining.len()) {
            return false;
        }
        if offset + declared_len == tail.len()
            && !is_valid_final_extension_without_mac_length(declared_len)
        {
            return false;
        }
        offset += declared_len;
    }
    true
}

fn is_plausible_legacy_mac_len(len: usize) -> bool {
    matches!(len, 4 | 20 | 24)
}

fn can_partition_as_legacy_mac(no_extensions_seen: bool, len: usize) -> bool {
    if no_extensions_seen {
        matches!(len, 20 | 24)
    } else {
        is_plausible_legacy_mac_len(len)
    }
}

fn align_4(value: usize) -> usize {
    (value + 3) & !3
}

pub(super) fn validate_extension_length(declared_len: usize, available: usize) -> Result<()> {
    if declared_len < NTP_EXTENSION_FIELD_MIN_LEN {
        return Err(CrafterError::invalid_field_value(
            NTP_EXTENSION_LENGTH_CONTEXT,
            "extension length must be at least 16 bytes",
        ));
    }
    if declared_len % 4 != 0 {
        return Err(CrafterError::invalid_field_value(
            NTP_EXTENSION_LENGTH_CONTEXT,
            "extension length must be a multiple of 4 bytes",
        ));
    }
    if declared_len > available {
        return Err(CrafterError::buffer_too_short(
            NTP_EXTENSION_CONTEXT,
            declared_len,
            available,
        ));
    }
    Ok(())
}

pub(super) fn is_valid_extension_length(declared_len: usize, available: usize) -> bool {
    validate_extension_length(declared_len, available).is_ok()
}

pub(super) fn validate_final_extension_without_mac_length(declared_len: usize) -> Result<()> {
    if declared_len < NTP_EXTENSION_FIELD_MIN_LAST_WITHOUT_MAC_LEN {
        return Err(CrafterError::invalid_field_value(
            NTP_EXTENSION_LENGTH_CONTEXT,
            "final extension without MAC must be at least 28 bytes",
        ));
    }
    Ok(())
}

pub(super) fn is_valid_final_extension_without_mac_length(declared_len: usize) -> bool {
    validate_final_extension_without_mac_length(declared_len).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CrafterError;
    use crate::protocols::ntp::registry::NtpExtensionFieldTypeCategory;
    use crate::protocols::ntp::NtpRegistryStatus;
    use crate::{Ipv4, Ntp, Udp};
    use std::net::Ipv4Addr;

    #[test]
    fn ntp_extension_model_preserves_unknown_type_value_and_declared_length() {
        let value = vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03];
        let field = NtpExtensionField::from_decoded(0xdead, 28, value.clone());

        assert_eq!(field.field_type(), 0xdead);
        assert_eq!(field.declared_length_value(), Some(28));
        assert_eq!(field.value(), value.as_slice());
        assert_eq!(field.padding_value(), None);
        assert_eq!(field.registry_meta().status, NtpRegistryStatus::Unassigned);
    }

    #[test]
    fn ntp_extension_registry_field_exposes_extension_type_metadata() {
        let field = NtpExtensionField::from_decoded(0xdead, 28, vec![0xaa; 24]);
        let extension_type = field.extension_type();

        assert_eq!(extension_type.value(), 0xdead);
        assert_eq!(extension_type.label(), "extension-field-0xDEAD");
        assert_eq!(
            extension_type.category(),
            NtpExtensionFieldTypeCategory::UnknownOrUnassigned
        );
        assert_eq!(extension_type.status(), NtpRegistryStatus::Unassigned);
        assert_eq!(field.registry_meta(), extension_type.registry_meta());
    }

    #[test]
    fn ntp_unknown_extensions_constructor_exposes_fallback_label_and_category() {
        let field = NtpExtensionField::unknown(0x2222, [0xde, 0xad, 0xbe, 0xef]);

        assert_eq!(field.field_type(), 0x2222);
        assert_eq!(field.value(), &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(field.label(), "extension-field-0x2222");
        assert_eq!(field.summary_label(), "extension-field-0x2222");
        assert!(field.is_unknown_or_unassigned());
        assert_eq!(field.registry_meta().status, NtpRegistryStatus::Unassigned);
        assert_eq!(
            field.extension_type().category(),
            NtpExtensionFieldTypeCategory::UnknownOrUnassigned
        );
    }

    #[test]
    fn ntp_extension_model_serializes_explicit_padding_after_value() -> Result<()> {
        let field = NtpExtensionField::udp_checksum_complement([0xaa, 0xbb])
            .padding([0xcc, 0xdd])
            .declared_length(16);
        let mut out = Vec::new();

        field.compile(false, &mut out)?;

        assert_eq!(
            out,
            vec![
                0x20, 0x05, 0x00, 0x10, 0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00
            ]
        );
        Ok(())
    }

    #[test]
    fn ntp_checksum_complement_extension_helper_encodes_type_and_body() -> Result<()> {
        let checksum = NtpChecksumComplementExtension::from_complement(0x1234);
        let field = checksum.clone().into_extension_field().declared_length(16);
        let mut out = Vec::new();

        field.compile(false, &mut out)?;

        assert_eq!(checksum.field_type(), 0x2005);
        assert_eq!(checksum.body(), &[0x12, 0x34]);
        assert_eq!(checksum.complement_value(), Some(0x1234));
        assert_eq!(
            &out[..NTP_EXTENSION_FIELD_HEADER_LEN],
            &[0x20, 0x05, 0x00, 0x10]
        );
        assert_eq!(&out[NTP_EXTENSION_FIELD_HEADER_LEN..6], &[0x12, 0x34]);
        assert!(out[6..].iter().all(|byte| *byte == 0));
        assert!(field.is_udp_checksum_complement());
        assert_eq!(field.label(), "UDP Checksum Complement");
        assert_eq!(field.registry_meta().status, NtpRegistryStatus::Assigned);
        Ok(())
    }

    #[test]
    fn ntp_checksum_complement_extension_decode_preserves_raw_body_bytes() -> Result<()> {
        let body = (0u8..24).map(|offset| 0xa0 + offset).collect::<Vec<_>>();
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&NtpChecksumComplementExtension::FIELD_TYPE.to_be_bytes());
        encoded.extend_from_slice(
            &(NTP_EXTENSION_FIELD_MIN_LAST_WITHOUT_MAC_LEN as u16).to_be_bytes(),
        );
        encoded.extend_from_slice(&body);

        let decoded = decode_all(&encoded)?;

        assert_eq!(decoded.legacy_mac, None);
        assert_eq!(decoded.fields.len(), 1);
        let field = &decoded.fields[0];
        let checksum = field
            .as_udp_checksum_complement()
            .expect("0x2005 decodes through checksum complement helper");
        assert_eq!(field.declared_length_value(), Some(28));
        assert_eq!(field.value(), body.as_slice());
        assert_eq!(field.padding_value(), None);
        assert_eq!(checksum.body(), body.as_slice());
        assert_eq!(checksum.complement_value(), Some(0xa0a1));
        Ok(())
    }

    #[test]
    fn ntp_checksum_complement_extension_does_not_mutate_udp_checksum() -> Result<()> {
        let packet = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            / Udp::ntp().checksum(0x1234)
            / Ntp::client()
                .extension_field(NtpExtensionField::udp_checksum_complement([0xaa, 0xbb]));

        let compiled = packet.compile()?;
        let bytes = compiled.as_bytes();

        assert_eq!(u16::from_be_bytes([bytes[26], bytes[27]]), 0x1234);
        Ok(())
    }

    #[test]
    fn ntp_extension_lengths_reject_declared_length_below_minimum() {
        assert_eq!(
            validate_extension_length(NTP_EXTENSION_FIELD_MIN_LEN - 4, 64).unwrap_err(),
            CrafterError::invalid_field_value(
                NTP_EXTENSION_LENGTH_CONTEXT,
                "extension length must be at least 16 bytes",
            )
        );
    }

    #[test]
    fn ntp_extension_lengths_reject_unaligned_declared_length() {
        assert_eq!(
            validate_extension_length(NTP_EXTENSION_FIELD_MIN_LEN + 2, 64).unwrap_err(),
            CrafterError::invalid_field_value(
                NTP_EXTENSION_LENGTH_CONTEXT,
                "extension length must be a multiple of 4 bytes",
            )
        );
    }

    #[test]
    fn ntp_extension_lengths_report_required_and_available_bytes() {
        assert_eq!(
            validate_extension_length(20, 16).unwrap_err(),
            CrafterError::buffer_too_short(NTP_EXTENSION_CONTEXT, 20, 16)
        );
    }

    #[test]
    fn ntp_extension_lengths_reject_short_final_extension_without_mac() {
        assert_eq!(
            validate_final_extension_without_mac_length(NTP_EXTENSION_FIELD_MIN_LEN).unwrap_err(),
            CrafterError::invalid_field_value(
                NTP_EXTENSION_LENGTH_CONTEXT,
                "final extension without MAC must be at least 28 bytes",
            )
        );
        assert!(validate_final_extension_without_mac_length(
            NTP_EXTENSION_FIELD_MIN_LAST_WITHOUT_MAC_LEN
        )
        .is_ok());
    }

    #[test]
    fn ntp_extension_lengths_accept_unknown_structurally_valid_type() -> Result<()> {
        let field = NtpExtensionField::new(0xdead, [0xaa, 0xbb, 0xcc, 0xdd])
            .declared_length(NTP_EXTENSION_FIELD_MIN_LEN as u16);
        let mut out = Vec::new();

        validate_extension_length(
            field.declared_length_value().unwrap() as usize,
            NTP_EXTENSION_FIELD_MIN_LEN,
        )?;
        field.compile(false, &mut out)?;

        assert_eq!(field.registry_meta().status, NtpRegistryStatus::Unassigned);
        assert_eq!(
            &out[..NTP_EXTENSION_FIELD_HEADER_LEN],
            &[0xde, 0xad, 0x00, 0x10]
        );
        assert_eq!(out.len(), NTP_EXTENSION_FIELD_MIN_LEN);
        Ok(())
    }

    #[test]
    fn ntp_extension_lengths_compile_preserves_malformed_declared_length_override() -> Result<()> {
        let field = NtpExtensionField::nts_cookie([0xaa, 0xbb, 0xcc]).declared_length(12);
        let mut out = Vec::new();

        field.compile(false, &mut out)?;

        assert_eq!(
            &out[..NTP_EXTENSION_FIELD_HEADER_LEN],
            &[0x02, 0x04, 0x00, 0x0c]
        );
        assert_eq!(out.len(), 12);
        assert!(validate_extension_length(12, out.len()).is_err());
        Ok(())
    }

    #[test]
    fn ntp_extension_registry_labels_do_not_gate_legacy_mac_partition() -> Result<()> {
        let mut tail = Vec::new();
        tail.extend_from_slice(&0x0204u16.to_be_bytes());
        tail.extend_from_slice(&12u16.to_be_bytes());
        tail.extend_from_slice(&[0xcc; 16]);

        let decoded = decode_all(&tail)?;

        assert_eq!(decoded.fields, Vec::new());
        assert_eq!(decoded.legacy_mac.as_deref(), Some(tail.as_slice()));
        Ok(())
    }

    #[test]
    fn ntp_extension_roundtrip_sequence_preserves_body_padding_and_unknown_types() -> Result<()> {
        let fields = vec![
            NtpExtensionField::new(0xdead, [0xaa, 0xbb])
                .padding([0xcc, 0xdd])
                .declared_length(NTP_EXTENSION_FIELD_MIN_LEN as u16),
            NtpExtensionField::udp_checksum_complement([0x11, 0x22, 0x33, 0x44])
                .declared_length(NTP_EXTENSION_FIELD_MIN_LAST_WITHOUT_MAC_LEN as u16),
        ];
        let mut encoded = Vec::new();

        encode_all(&fields, false, &mut encoded)?;
        let decoded = decode_all(&encoded)?;

        assert_eq!(decoded.legacy_mac, None);
        assert_eq!(decoded.fields.len(), 2);
        assert_eq!(decoded.fields[0].field_type(), 0xdead);
        assert_eq!(
            decoded.fields[0].value(),
            &[0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(decoded.fields[0].padding_value(), None);
        assert_eq!(
            decoded.fields[1].declared_length_value(),
            Some(NTP_EXTENSION_FIELD_MIN_LAST_WITHOUT_MAC_LEN as u16)
        );

        let mut reencoded = Vec::new();
        encode_all(&decoded.fields, false, &mut reencoded)?;
        assert_eq!(reencoded, encoded);
        Ok(())
    }

    #[test]
    fn ntp_extension_roundtrip_decode_all_splits_legacy_mac_tail() -> Result<()> {
        let fields = vec![NtpExtensionField::nts_cookie([0x01, 0x02, 0x03])];
        let legacy_mac = vec![0x01, 0x02, 0x03, 0x04, 0xcc, 0xcc, 0xcc, 0xcc];
        let mut legacy_mac = legacy_mac.into_iter().chain([0xcc; 12]).collect::<Vec<_>>();
        let mut encoded = Vec::new();

        encode_all(&fields, true, &mut encoded)?;
        encoded.append(&mut legacy_mac);
        let decoded = decode_all(&encoded)?;

        assert_eq!(decoded.fields.len(), 1);
        assert_eq!(decoded.fields[0].field_type(), 0x0204);
        assert_eq!(
            decoded.fields[0].declared_length_value(),
            Some(NTP_EXTENSION_FIELD_MIN_LEN as u16)
        );
        assert_eq!(
            decoded.legacy_mac.as_deref(),
            Some(&encoded[NTP_EXTENSION_FIELD_MIN_LEN..])
        );
        Ok(())
    }
}
