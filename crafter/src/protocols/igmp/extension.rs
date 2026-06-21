//! Generic IGMP/MLD extension TLV model.
//!
//! RFC 9279 defines the IGMP extension area as byte-contiguous TLVs: 16-bit
//! Extension Type, 16-bit Extension Length in octets, and raw Extension Value
//! bytes. The E flag that gates this area lives in the query/report layer; each
//! TLV here preserves only its type, declared value length, and value bytes.

use core::any::Any;
use core::ops::Div;

use crate::error::{CrafterError, Result};
use crate::field::{Field, FieldState};
use crate::packet::{IntoPacket, Layer, LayerContext, Packet};

use super::constants::{IGMP_DEFAULT_EXTENSION_LENGTH, IGMP_EXTENSION_HEADER_LEN};
use super::registry::{IgmpExtensionType, IgmpExtensionTypeMeta};

/// Raw value bytes for one IGMP/MLD extension TLV.
///
/// RFC 9279 currently assigns only the No-op extension type. Until a future
/// source review justifies semantic extension bodies, all extension values are
/// preserved as uninterpreted bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct IgmpExtensionValue {
    bytes: Vec<u8>,
}

impl IgmpExtensionValue {
    /// Create an empty extension value.
    pub const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Create a raw extension value by copying bytes.
    pub fn raw(bytes: impl AsRef<[u8]>) -> Self {
        Self {
            bytes: bytes.as_ref().to_vec(),
        }
    }

    /// Borrow the raw extension value bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Mutably borrow the raw extension value bytes.
    pub fn as_bytes_mut(&mut self) -> &mut Vec<u8> {
        &mut self.bytes
    }

    /// Consume the value and return its raw bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Raw value length in octets.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return true when the value has no bytes.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl From<Vec<u8>> for IgmpExtensionValue {
    fn from(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl From<&[u8]> for IgmpExtensionValue {
    fn from(bytes: &[u8]) -> Self {
        Self::raw(bytes)
    }
}

impl<const N: usize> From<[u8; N]> for IgmpExtensionValue {
    fn from(bytes: [u8; N]) -> Self {
        Self::raw(bytes)
    }
}

impl<const N: usize> From<&[u8; N]> for IgmpExtensionValue {
    fn from(bytes: &[u8; N]) -> Self {
        Self::raw(bytes)
    }
}

/// One generic IGMP/MLD extension TLV.
///
/// The Extension Length field auto-fills from the raw value length unless the
/// caller pins it explicitly. Explicit shorter lengths are emitted as declared
/// and retain the full caller-supplied value in memory; explicit longer lengths
/// require corresponding value bytes and return a structured error when they
/// cannot be represented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgmpExtension {
    extension_type: IgmpExtensionType,
    extension_length: Field<u16>,
    value: IgmpExtensionValue,
}

impl IgmpExtension {
    /// Create an empty No-op extension TLV.
    pub fn new() -> Self {
        Self::noop()
    }

    /// Create an extension TLV with a source-backed Extension Type.
    pub fn with_type(extension_type: IgmpExtensionType) -> Self {
        Self {
            extension_type,
            extension_length: Field::unset(),
            value: IgmpExtensionValue::new(),
        }
    }

    /// Create an empty No-op extension TLV.
    pub fn noop() -> Self {
        Self::with_type(IgmpExtensionType::Noop)
    }

    /// Create a TLV from a raw Extension Type value and raw value bytes.
    pub fn raw(extension_type: u16, value: impl Into<IgmpExtensionValue>) -> Self {
        Self::with_type(IgmpExtensionType::from_u16(extension_type)).with_value(value)
    }

    /// Set the source-backed Extension Type.
    pub fn with_extension_type(mut self, extension_type: IgmpExtensionType) -> Self {
        self.extension_type = extension_type;
        self
    }

    /// Set the raw Extension Type value, preserving unassigned values.
    pub fn with_raw_extension_type(self, extension_type: u16) -> Self {
        self.with_extension_type(IgmpExtensionType::from_u16(extension_type))
    }

    /// Set the declared Extension Length field in octets.
    pub fn with_extension_length(mut self, length: u16) -> Self {
        self.extension_length.set_user(length);
        self
    }

    /// Compatibility alias for the declared Extension Length field.
    pub fn with_length(self, length: u16) -> Self {
        self.with_extension_length(length)
    }

    /// Replace the raw Extension Value bytes.
    pub fn with_value(mut self, value: impl Into<IgmpExtensionValue>) -> Self {
        self.value = value.into();
        self
    }

    /// Compatibility alias for replacing raw Extension Value bytes.
    pub fn with_raw_value(self, value: impl Into<IgmpExtensionValue>) -> Self {
        self.with_value(value)
    }

    /// Source-backed Extension Type classification.
    pub fn extension_type(&self) -> IgmpExtensionType {
        self.extension_type
    }

    /// Raw Extension Type value.
    pub fn extension_type_value(&self) -> u16 {
        self.extension_type.code()
    }

    /// Raw Extension Type value.
    pub fn raw_extension_type_value(&self) -> u16 {
        self.extension_type_value()
    }

    /// Source-backed Extension Type metadata.
    pub fn extension_type_meta(&self) -> IgmpExtensionTypeMeta {
        self.extension_type.meta()
    }

    /// Declared Extension Length in octets.
    pub fn extension_length_value(&self) -> u16 {
        value_or_copy(
            &self.extension_length,
            extension_length_value(self.value.len()),
        )
    }

    /// Compatibility alias for the declared Extension Length field.
    pub fn length_value(&self) -> u16 {
        self.extension_length_value()
    }

    /// Assignment state for the Extension Length field.
    pub fn extension_length_state(&self) -> FieldState {
        self.extension_length.state()
    }

    /// Compatibility alias for the Extension Length field state.
    pub fn length_state(&self) -> FieldState {
        self.extension_length_state()
    }

    /// Raw Extension Value.
    pub fn value(&self) -> &IgmpExtensionValue {
        &self.value
    }

    /// Raw Extension Value bytes.
    pub fn value_bytes(&self) -> &[u8] {
        self.value.as_bytes()
    }

    /// Compatibility alias for raw Extension Value bytes.
    pub fn raw_value(&self) -> &[u8] {
        self.value_bytes()
    }

    /// Serialize this TLV to wire bytes.
    pub fn compile(&self) -> Result<Vec<u8>> {
        self.try_compile()
    }

    /// Serialize this TLV to wire bytes.
    pub fn try_compile(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        self.try_encode_into(&mut bytes)?;
        Ok(bytes)
    }

    /// Append this TLV's wire bytes to `out`.
    pub fn try_encode_into(&self, out: &mut Vec<u8>) -> Result<()> {
        let value_len = self.wire_value_len()?;

        out.extend_from_slice(&self.extension_type_value().to_be_bytes());
        out.extend_from_slice(&self.extension_length_value().to_be_bytes());
        out.extend_from_slice(&self.value.as_bytes()[..value_len]);
        Ok(())
    }

    fn wire_value_len(&self) -> Result<usize> {
        let value_len = usize::from(self.extension_length_value());
        if self.extension_length.is_user_set() && self.value.len() < value_len {
            return Err(CrafterError::buffer_too_short(
                "igmp.extension.value",
                value_len,
                self.value.len(),
            ));
        }
        if !self.extension_length.is_user_set() && self.value.len() > usize::from(u16::MAX) {
            return Err(CrafterError::invalid_field_value(
                "igmp.extension.length",
                "extension value length exceeds 65535 bytes",
            ));
        }

        Ok(value_len)
    }
}

pub(crate) fn decode_extensions(mut bytes: &[u8]) -> Result<Vec<IgmpExtension>> {
    let mut extensions = Vec::new();

    while !bytes.is_empty() {
        if bytes.len() < IGMP_EXTENSION_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                "igmp.extension.header",
                IGMP_EXTENSION_HEADER_LEN,
                bytes.len(),
            ));
        }

        let extension_type = u16::from_be_bytes([bytes[0], bytes[1]]);
        let extension_length = u16::from_be_bytes([bytes[2], bytes[3]]);
        let value_end = IGMP_EXTENSION_HEADER_LEN + usize::from(extension_length);
        if bytes.len() < value_end {
            return Err(CrafterError::buffer_too_short(
                "igmp.extension.value",
                value_end,
                bytes.len(),
            ));
        }

        let value = &bytes[IGMP_EXTENSION_HEADER_LEN..value_end];
        extensions.push(
            IgmpExtension::raw(extension_type, value).with_extension_length(extension_length),
        );
        bytes = &bytes[value_end..];
    }

    Ok(extensions)
}

impl Default for IgmpExtension {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for IgmpExtension {
    fn name(&self) -> &'static str {
        "IgmpExtension"
    }

    fn summary(&self) -> String {
        format!(
            "IgmpExtension(type=0x{:04x} {}, length={}, value_len={}B)",
            self.extension_type_value(),
            self.extension_type,
            self.extension_length_value(),
            self.value.len()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "extension_type",
                format!(
                    "0x{:04x} ({})",
                    self.extension_type_value(),
                    self.extension_type
                ),
            ),
            (
                "extension_length",
                self.extension_length_value().to_string(),
            ),
            ("value", hex_bytes(self.value.as_bytes())),
        ]
    }

    fn encoded_len(&self) -> usize {
        IGMP_EXTENSION_HEADER_LEN + usize::from(self.extension_length_value())
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        self.try_encode_into(out)
    }

    fn clone_layer(&self) -> Box<dyn Layer> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

impl<R> Div<R> for IgmpExtension
where
    R: IntoPacket,
{
    type Output = Packet;

    fn div(self, rhs: R) -> Self::Output {
        Packet::from_layer(self).concat(rhs)
    }
}

fn extension_length_value(value_len: usize) -> u16 {
    if value_len == 0 {
        return IGMP_DEFAULT_EXTENSION_LENGTH;
    }

    u16::try_from(value_len).unwrap_or(u16::MAX)
}

fn value_or_copy<T: Copy>(field: &Field<T>, default: T) -> T {
    field.value().copied().unwrap_or(default)
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod igmp_extension_model {
    use super::*;
    use crate::checksum::verify_internet_checksum;
    use crate::protocols::igmp::constants::{
        IGMP_EXTENSION_TYPE_EXPERIMENTAL_FIRST, IGMP_FIXED_HEADER_LEN, IGMP_TYPE_MEMBERSHIP_QUERY,
        IGMP_TYPE_V3_MEMBERSHIP_REPORT,
    };
    use crate::protocols::igmp::message::Igmp;
    use crate::protocols::igmp::query::IgmpQuery;
    use crate::protocols::igmp::registry::IgmpExtensionTypeStatus;
    use crate::protocols::igmp::report::IgmpReport;

    #[test]
    fn igmp_extension_model_defaults_to_empty_noop_tlv() -> crate::Result<()> {
        let extension = IgmpExtension::default();

        assert_eq!(extension.extension_type(), IgmpExtensionType::Noop);
        assert_eq!(extension.extension_type_value(), 0);
        assert_eq!(extension.raw_extension_type_value(), 0);
        assert_eq!(
            extension.extension_type_meta().status,
            IgmpExtensionTypeStatus::Assigned
        );
        assert_eq!(extension.extension_length_value(), 0);
        assert_eq!(extension.length_value(), 0);
        assert_eq!(extension.extension_length_state(), FieldState::Unset);
        assert_eq!(extension.length_state(), FieldState::Unset);
        assert!(extension.value().is_empty());
        assert!(extension.value_bytes().is_empty());
        assert_eq!(extension.encoded_len(), IGMP_EXTENSION_HEADER_LEN);
        assert_eq!(extension.compile()?, vec![0, 0, 0, 0]);
        assert_eq!(
            extension.summary(),
            "IgmpExtension(type=0x0000 No-op, length=0, value_len=0B)"
        );
        assert_eq!(
            extension.inspection_fields(),
            vec![
                ("extension_type", "0x0000 (No-op)".to_string()),
                ("extension_length", "0".to_string()),
                ("value", String::new()),
            ]
        );

        Ok(())
    }

    #[test]
    fn igmp_extension_model_auto_fills_length_from_value_bytes() -> crate::Result<()> {
        let extension = IgmpExtension::noop().with_value([0xde, 0xad, 0xbe, 0xef]);

        assert_eq!(extension.extension_type(), IgmpExtensionType::Noop);
        assert_eq!(extension.extension_length_value(), 4);
        assert_eq!(extension.extension_length_state(), FieldState::Unset);
        assert_eq!(extension.value_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(extension.encoded_len(), IGMP_EXTENSION_HEADER_LEN + 4);
        assert_eq!(
            extension.compile()?,
            vec![0x00, 0x00, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef]
        );

        Ok(())
    }

    #[test]
    fn igmp_extension_model_preserves_unassigned_type_and_explicit_length() -> crate::Result<()> {
        let extension = IgmpExtension::raw(0x1234, [1, 2, 3, 4, 5]).with_extension_length(3);

        assert_eq!(
            extension.extension_type(),
            IgmpExtensionType::Unassigned(0x1234)
        );
        assert_eq!(extension.extension_type_value(), 0x1234);
        assert_eq!(
            extension.extension_type_meta().status,
            IgmpExtensionTypeStatus::Unassigned
        );
        assert_eq!(extension.extension_length_value(), 3);
        assert_eq!(extension.extension_length_state(), FieldState::User);
        assert_eq!(extension.value_bytes(), &[1, 2, 3, 4, 5]);
        assert_eq!(extension.encoded_len(), IGMP_EXTENSION_HEADER_LEN + 3);
        assert_eq!(extension.compile()?, vec![0x12, 0x34, 0x00, 0x03, 1, 2, 3]);

        Ok(())
    }

    #[test]
    fn igmp_extension_model_preserves_experimental_type() {
        let extension = IgmpExtension::default()
            .with_raw_extension_type(IGMP_EXTENSION_TYPE_EXPERIMENTAL_FIRST);

        assert_eq!(
            extension.extension_type(),
            IgmpExtensionType::Experimental(IGMP_EXTENSION_TYPE_EXPERIMENTAL_FIRST)
        );
        assert_eq!(
            extension.extension_type_meta().status,
            IgmpExtensionTypeStatus::Experimental
        );
    }

    #[test]
    fn igmp_extension_model_errors_when_explicit_length_requires_missing_bytes() {
        let extension = IgmpExtension::noop()
            .with_value([0xaa, 0xbb])
            .with_length(3);

        assert_eq!(
            extension.try_compile(),
            Err(CrafterError::buffer_too_short("igmp.extension.value", 3, 2,))
        );
    }

    #[test]
    fn igmp_extension_model_composes_after_v3_report_body() -> crate::Result<()> {
        let extension = IgmpExtension::noop().with_value([0xca, 0xfe]);
        let report = IgmpReport::new().with_extension_flag(true);
        let packet = Igmp::v3_membership_report() / report / extension.clone();

        assert_eq!(packet.layer::<IgmpExtension>(), Some(&extension));

        let bytes = packet.compile()?;
        assert_eq!(bytes.as_bytes()[0], IGMP_TYPE_V3_MEMBERSHIP_REPORT);
        assert_eq!(
            &bytes.as_bytes()[IGMP_FIXED_HEADER_LEN..],
            &[0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xca, 0xfe]
        );
        assert!(verify_internet_checksum(bytes.as_bytes()));

        Ok(())
    }

    #[test]
    fn igmp_extension_encode_empty_query_tlv() -> crate::Result<()> {
        let query = IgmpQuery::new().with_extension_flag(true);
        let packet =
            Igmp::v3_membership_query(100, core::net::Ipv4Addr::new(233, 252, 0, 60), query)
                / IgmpExtension::noop();

        let bytes = packet.compile()?;

        assert_eq!(bytes.as_bytes()[0], IGMP_TYPE_MEMBERSHIP_QUERY);
        assert_eq!(
            &bytes.as_bytes()[IGMP_FIXED_HEADER_LEN..],
            &[0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert!(verify_internet_checksum(bytes.as_bytes()));

        Ok(())
    }

    #[test]
    fn igmp_extension_encode_non_empty_report_tlv_autofills_length() -> crate::Result<()> {
        let report = IgmpReport::new().with_extension_flag(true);
        let extension = IgmpExtension::raw(0x1234, [0xde, 0xad, 0xbe, 0xef]);
        let packet = Igmp::v3_membership_report() / report / extension;

        let bytes = packet.compile()?;

        assert_eq!(bytes.as_bytes()[0], IGMP_TYPE_V3_MEMBERSHIP_REPORT);
        assert_eq!(
            &bytes.as_bytes()[IGMP_FIXED_HEADER_LEN..],
            &[0x80, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef,]
        );
        assert!(verify_internet_checksum(bytes.as_bytes()));

        Ok(())
    }

    #[test]
    fn igmp_extension_encode_multiple_tlvs_are_byte_contiguous() -> crate::Result<()> {
        let query = IgmpQuery::new().with_extension_flag(true);
        let first = IgmpExtension::raw(0x0000, [0xaa]);
        let second = IgmpExtension::raw(0xfffe, [0xbb, 0xcc]);
        let packet =
            Igmp::v3_membership_query(100, core::net::Ipv4Addr::new(233, 252, 0, 61), query)
                / first
                / second;

        let bytes = packet.compile()?;

        assert_eq!(
            &bytes.as_bytes()[IGMP_FIXED_HEADER_LEN..],
            &[
                0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xaa, 0xff, 0xfe, 0x00, 0x02, 0xbb,
                0xcc,
            ]
        );
        assert!(verify_internet_checksum(bytes.as_bytes()));

        Ok(())
    }

    #[test]
    fn igmp_extension_encode_preserves_representable_explicit_length() -> crate::Result<()> {
        let extension = IgmpExtension::raw(0x1234, [1, 2, 3, 4]).with_extension_length(2);
        let report = IgmpReport::new().with_extension_flag(true);
        let packet = Igmp::v3_membership_report() / report / extension;

        let bytes = packet.compile()?;

        assert_eq!(
            &bytes.as_bytes()[IGMP_FIXED_HEADER_LEN..],
            &[0x80, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02, 1, 2]
        );
        assert!(verify_internet_checksum(bytes.as_bytes()));

        Ok(())
    }

    #[test]
    fn igmp_extension_encode_malformed_length_missing_value_is_structured_error() {
        let extension = IgmpExtension::noop()
            .with_value([0xaa, 0xbb])
            .with_extension_length(3);
        let report = IgmpReport::new().with_extension_flag(true);
        let packet = Igmp::v3_membership_report() / report / extension;

        assert_eq!(
            packet.compile(),
            Err(CrafterError::buffer_too_short("igmp.extension.value", 3, 2,))
        );
    }
}
