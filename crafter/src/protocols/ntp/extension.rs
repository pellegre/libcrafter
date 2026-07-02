//! Raw-preserving NTP extension field model.

use super::constants::{
    NTP_EXTENSION_FIELD_HEADER_LEN, NTP_EXTENSION_FIELD_MIN_LAST_WITHOUT_MAC_LEN,
    NTP_EXTENSION_FIELD_MIN_LEN,
};
use super::registry::{ntp_extension_field_type_meta, NtpRegistryMeta};
use crate::error::{CrafterError, Result};
use crate::field::Field;

pub(super) const NTP_EXTENSION_CONTEXT: &str = "ntp.extension";
pub(super) const NTP_EXTENSION_LENGTH_CONTEXT: &str = "ntp.extension.length";

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
        Self::new(0x2005, value)
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
        ntp_extension_field_type_meta(self.field_type())
    }

    /// Return true when the field type is assigned by the NTS extension registry.
    pub fn is_nts_extension(&self) -> bool {
        matches!(self.field_type(), 0x0104 | 0x0204 | 0x0304 | 0x0404)
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
    use crate::protocols::ntp::NtpRegistryStatus;

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
}
