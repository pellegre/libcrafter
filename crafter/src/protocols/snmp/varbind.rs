//! SNMP variable binding support.
//!
//! Source-gated by `.agents/docs/snmp-rfc-manifest.md`; this module models one
//! VarBind as packet bytes only and does not perform MIB lookup.

use super::{ber, oid::SnmpOid, value::SnmpValue};
use crate::error::Result;

/// One SNMP variable binding: an object identifier name plus one SNMP value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnmpVarBind {
    name: SnmpOid,
    value: SnmpValue,
}

/// Ordered SNMP variable binding list.
///
/// A VarBindList is encoded as one BER SEQUENCE containing zero or more
/// VarBind SEQUENCE values. Order and duplicate names are preserved because
/// this type models packet bytes, not MIB semantics.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SnmpVarBindList {
    varbinds: Vec<SnmpVarBind>,
    length: Option<usize>,
}

impl SnmpVarBind {
    pub(super) fn new(name: SnmpOid, value: SnmpValue) -> Self {
        Self { name, value }
    }

    /// Build a request variable binding whose value is BER NULL.
    pub fn null(name: SnmpOid) -> Self {
        Self::new(name, SnmpValue::null())
    }

    /// Compatibility alias for [`SnmpVarBind::null`].
    pub fn request_null(name: SnmpOid) -> Self {
        Self::null(name)
    }

    /// Build an INTEGER-valued variable binding.
    pub fn integer(name: SnmpOid, value: i64) -> Self {
        Self::new(name, SnmpValue::integer(value))
    }

    /// Build an OCTET STRING-valued variable binding.
    pub fn octet_string(name: SnmpOid, bytes: impl Into<Vec<u8>>) -> Self {
        Self::new(name, SnmpValue::octet_string(bytes))
    }

    /// Build an OBJECT IDENTIFIER-valued variable binding.
    pub fn object_identifier(name: SnmpOid, value: SnmpOid) -> Self {
        Self::new(name, SnmpValue::object_identifier(value))
    }

    /// Build an IpAddress-valued variable binding.
    pub fn ip_address(name: SnmpOid, octets: [u8; 4]) -> Self {
        Self::new(name, SnmpValue::ip_address(octets))
    }

    /// Build a Counter32-valued variable binding.
    pub fn counter32(name: SnmpOid, value: u32) -> Self {
        Self::new(name, SnmpValue::counter32(value))
    }

    /// Build a Gauge32-valued variable binding.
    pub fn gauge32(name: SnmpOid, value: u32) -> Self {
        Self::new(name, SnmpValue::gauge32(value))
    }

    /// Build an Unsigned32-valued variable binding.
    pub fn unsigned32(name: SnmpOid, value: u32) -> Self {
        Self::new(name, SnmpValue::unsigned32(value))
    }

    /// Build a TimeTicks-valued variable binding.
    pub fn time_ticks(name: SnmpOid, value: u32) -> Self {
        Self::new(name, SnmpValue::time_ticks(value))
    }

    /// Build an Opaque-valued variable binding.
    pub fn opaque(name: SnmpOid, bytes: impl Into<Vec<u8>>) -> Self {
        Self::new(name, SnmpValue::opaque(bytes))
    }

    /// Build a Counter64-valued variable binding.
    pub fn counter64(name: SnmpOid, value: u64) -> Self {
        Self::new(name, SnmpValue::counter64(value))
    }

    /// Build a noSuchObject exception variable binding.
    pub fn no_such_object(name: SnmpOid) -> Self {
        Self::new(name, SnmpValue::no_such_object())
    }

    /// Build a noSuchInstance exception variable binding.
    pub fn no_such_instance(name: SnmpOid) -> Self {
        Self::new(name, SnmpValue::no_such_instance())
    }

    /// Build an endOfMibView exception variable binding.
    pub fn end_of_mib_view(name: SnmpOid) -> Self {
        Self::new(name, SnmpValue::end_of_mib_view())
    }

    /// Build a variable binding with an application-class raw value.
    pub fn raw_application_value(
        name: SnmpOid,
        tag_number: u8,
        constructed: bool,
        content: impl Into<Vec<u8>>,
    ) -> Self {
        Self::new(
            name,
            SnmpValue::raw_application(tag_number, constructed, content),
        )
    }

    /// Build a variable binding with a byte-exact raw TLV value.
    pub fn raw_value_tlv(name: SnmpOid, bytes: impl Into<Vec<u8>>) -> Self {
        Self::new(name, SnmpValue::raw_tlv(bytes))
    }

    /// Build a variable binding with a raw value TLV and explicit BER length.
    ///
    /// The identifier octet and content bytes are emitted as supplied. The BER
    /// length field is encoded from `length`, even when it deliberately
    /// disagrees with the content bytes.
    pub fn raw_value_tlv_with_length(
        name: SnmpOid,
        identifier_octet: u8,
        length: usize,
        content: impl Into<Vec<u8>>,
    ) -> Result<Self> {
        let content = content.into();
        let mut bytes = Vec::with_capacity(2 + content.len());
        bytes.push(identifier_octet);
        ber::encode_length(length, &mut bytes)?;
        bytes.extend_from_slice(&content);
        Ok(Self::raw_value_tlv(name, bytes))
    }

    /// Compatibility alias for [`SnmpVarBind::raw_value_tlv_with_length`].
    pub fn raw_value_with_length(
        name: SnmpOid,
        identifier_octet: u8,
        length: usize,
        content: impl Into<Vec<u8>>,
    ) -> Result<Self> {
        Self::raw_value_tlv_with_length(name, identifier_octet, length, content)
    }

    /// Compatibility alias for [`SnmpVarBind::raw_value_tlv`].
    pub fn raw_value(name: SnmpOid, bytes: impl Into<Vec<u8>>) -> Self {
        Self::raw_value_tlv(name, bytes)
    }

    /// Decode one variable binding SEQUENCE and return the remaining bytes.
    pub fn decode(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (content, rest) = ber::decode_sequence(bytes)?;
        let (name, content_rest) = SnmpOid::decode(content)?;
        let (value, content_rest) = SnmpValue::decode(content_rest)?;
        ber::require_sequence_exact(content_rest)?;

        Ok((Self::new(name, value), rest))
    }

    /// Encode this variable binding into BER bytes.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let mut content = Vec::new();
        self.name.encode(&mut content)?;
        self.value.encode(&mut content)?;

        ber::encode_sequence(&content, out)
    }

    /// Return this variable binding encoded as BER bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Compile this variable binding into BER bytes.
    pub fn compile(&self) -> Result<Vec<u8>> {
        self.to_bytes()
    }

    /// Object identifier name.
    pub fn name(&self) -> &SnmpOid {
        &self.name
    }

    /// Human-readable value kind, suitable for summaries.
    pub fn value_summary(&self) -> String {
        self.value.summary_label()
    }

    /// Whether this variable binding value is BER NULL.
    pub fn is_null_value(&self) -> bool {
        self.value.is_null()
    }

    /// INTEGER value, if present.
    pub fn as_integer(&self) -> Option<i64> {
        self.value.as_integer()
    }

    /// OCTET STRING bytes, if present.
    pub fn as_octets(&self) -> Option<&[u8]> {
        self.value.as_octets()
    }

    /// OBJECT IDENTIFIER value, if present.
    pub fn as_object_identifier(&self) -> Option<&SnmpOid> {
        self.value.as_object_identifier()
    }

    /// IpAddress value, if present.
    pub fn as_ip_address(&self) -> Option<[u8; 4]> {
        self.value.as_ip_address()
    }

    /// Counter32 value, if present.
    pub fn as_counter32(&self) -> Option<u32> {
        self.value.as_counter32()
    }

    /// Gauge32 or Unsigned32 value, if present.
    pub fn as_gauge32_or_unsigned32(&self) -> Option<u32> {
        self.value.as_gauge32_or_unsigned32()
    }

    /// TimeTicks value, if present.
    pub fn as_time_ticks(&self) -> Option<u32> {
        self.value.as_time_ticks()
    }

    /// Opaque bytes, if present.
    pub fn as_opaque(&self) -> Option<&[u8]> {
        self.value.as_opaque()
    }

    /// Counter64 value, if present.
    pub fn as_counter64(&self) -> Option<u64> {
        self.value.as_counter64()
    }

    /// Whether this variable binding carries the noSuchObject exception value.
    pub fn is_no_such_object(&self) -> bool {
        self.value.is_no_such_object()
    }

    /// Whether this variable binding carries the noSuchInstance exception value.
    pub fn is_no_such_instance(&self) -> bool {
        self.value.is_no_such_instance()
    }

    /// Whether this variable binding carries the endOfMibView exception value.
    pub fn is_end_of_mib_view(&self) -> bool {
        self.value.is_end_of_mib_view()
    }

    /// Byte-exact raw TLV value bytes, if present.
    pub fn raw_value_tlv_bytes(&self) -> Option<&[u8]> {
        self.value.as_raw_tlv().map(|raw| raw.as_bytes())
    }

    /// BER class label for an unsupported value TLV, if present.
    pub fn unknown_value_class(&self) -> Option<&'static str> {
        self.value.unknown_value_class()
    }

    /// Whether an unsupported value TLV used the BER constructed bit.
    pub fn unknown_value_is_constructed(&self) -> Option<bool> {
        self.value.unknown_value_is_constructed()
    }

    /// Low-tag-number value for an unsupported value TLV.
    pub fn unknown_value_tag_number(&self) -> Option<u8> {
        self.value.unknown_value_tag_number()
    }

    /// Raw content octets for an unsupported value TLV.
    pub fn unknown_value_content(&self) -> Option<&[u8]> {
        self.value.unknown_value_content()
    }

    /// Byte-exact unsupported value TLV bytes, if they came from decode.
    pub fn unknown_value_tlv_bytes(&self) -> Option<&[u8]> {
        self.value.unknown_value_tlv_bytes()
    }

    /// A compact summary of this variable binding.
    pub fn summary(&self) -> String {
        format!("{}={}", self.name, self.value.summary_label())
    }

    /// Stable inspection fields for generated tools.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            ("name", self.name.to_string()),
            ("name_type", self.name.summary_label().to_string()),
            ("name_arc_count", self.name.arcs().len().to_string()),
        ];
        fields.extend(self.value.inspection_fields());
        fields
    }
}

impl SnmpVarBindList {
    /// Build a variable binding list from ordered variable bindings.
    pub fn new(varbinds: impl Into<Vec<SnmpVarBind>>) -> Self {
        Self {
            varbinds: varbinds.into(),
            length: None,
        }
    }

    /// Build an empty variable binding list.
    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    /// Decode one VarBindList SEQUENCE and return the remaining bytes.
    pub fn decode(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (mut content, rest) = ber::decode_sequence(bytes)?;
        let mut varbinds = Vec::new();

        while !content.is_empty() {
            let (varbind, remaining) = SnmpVarBind::decode(content)?;
            varbinds.push(varbind);
            content = remaining;
        }

        Ok((Self::new(varbinds), rest))
    }

    /// Encode this variable binding list into BER bytes.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let mut content = Vec::new();
        for varbind in &self.varbinds {
            varbind.encode(&mut content)?;
        }

        encode_varbind_list_sequence(&content, self.length, out)
    }

    /// Return this variable binding list encoded as BER bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Compile this variable binding list into BER bytes.
    pub fn compile(&self) -> Result<Vec<u8>> {
        self.to_bytes()
    }

    /// Pin the VarBindList SEQUENCE length field to an explicit value.
    ///
    /// Unset list lengths are auto-filled from the encoded VarBind bytes. A
    /// pinned value is emitted verbatim, even when it deliberately disagrees
    /// with the VarBind bytes; the VarBind bytes are still emitted unchanged.
    pub fn length(mut self, length: usize) -> Self {
        self.length = Some(length);
        self
    }

    /// Drop any explicit VarBindList length override so encode auto-fills it.
    pub fn clear_length(mut self) -> Self {
        self.length = None;
        self
    }

    /// Explicit VarBindList BER length override, if one is pinned.
    pub const fn explicit_length(&self) -> Option<usize> {
        self.length
    }

    /// Append one variable binding.
    pub fn push(&mut self, varbind: SnmpVarBind) {
        self.varbinds.push(varbind);
    }

    /// Ordered variable bindings.
    pub fn varbinds(&self) -> &[SnmpVarBind] {
        &self.varbinds
    }

    /// Compatibility alias for [`SnmpVarBindList::varbinds`].
    pub fn as_slice(&self) -> &[SnmpVarBind] {
        self.varbinds()
    }

    /// Consume the list and return the ordered variable bindings.
    pub fn into_vec(self) -> Vec<SnmpVarBind> {
        self.varbinds
    }

    /// Iterate over ordered variable bindings.
    pub fn iter(&self) -> core::slice::Iter<'_, SnmpVarBind> {
        self.varbinds.iter()
    }

    /// Number of variable bindings.
    pub fn len(&self) -> usize {
        self.varbinds.len()
    }

    /// Whether the list contains no variable bindings.
    pub fn is_empty(&self) -> bool {
        self.varbinds.is_empty()
    }

    /// A compact summary of this variable binding list.
    pub fn summary(&self) -> String {
        format!("varbinds={}", self.varbinds.len())
    }

    /// Stable inspection fields for generated tools.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![("varbind_count", self.varbinds.len().to_string())];
        for (index, varbind) in self.varbinds.iter().enumerate() {
            fields.push((varbind_field_name(index), varbind.summary()));
        }
        fields
    }
}

fn varbind_field_name(index: usize) -> &'static str {
    const NAMES: [&str; 8] = [
        "varbind[0]",
        "varbind[1]",
        "varbind[2]",
        "varbind[3]",
        "varbind[4]",
        "varbind[5]",
        "varbind[6]",
        "varbind[7]",
    ];
    NAMES.get(index).copied().unwrap_or("varbind[*]")
}

fn encode_varbind_list_sequence(
    content: &[u8],
    explicit_length: Option<usize>,
    out: &mut Vec<u8>,
) -> Result<()> {
    ber::encode_identifier(
        ber::BerTag::new(ber::BerClass::Universal, true, ber::BER_TAG_SEQUENCE),
        out,
    )?;
    ber::encode_length(explicit_length.unwrap_or(content.len()), out)?;
    out.extend_from_slice(content);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CrafterError;

    #[test]
    fn snmp_varbind_request_null_compiles_decodes_and_inspects() -> Result<()> {
        let name = SnmpOid::from_dotted("1.3.6.1.2.1.1.3.0")?;
        let varbind = SnmpVarBind::request_null(name.clone());

        // Source-backed: .agents/docs/snmp-rfc-manifest.md records RFC 1157 Section
        // 4.1.1 and RFC 3416 Section 3 for VarBind as `{ name, value }`, with
        // NULL used by request variable bindings that carry no supplied value.
        let expected = [
            0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x05, 0x00,
        ];
        assert_eq!(varbind.compile()?, expected);
        assert_eq!(varbind.name(), &name);
        assert!(varbind.is_null_value());
        assert_eq!(varbind.value_summary(), "null");
        assert_eq!(varbind.summary(), "1.3.6.1.2.1.1.3.0=null");
        assert_eq!(
            varbind.inspection_fields(),
            [
                ("name", "1.3.6.1.2.1.1.3.0".to_string()),
                ("name_type", "object-identifier".to_string()),
                ("name_arc_count", "9".to_string()),
                ("value_type", "null".to_string()),
            ]
        );

        let mut with_rest = expected.to_vec();
        with_rest.push(0xaa);
        let (decoded, rest) = SnmpVarBind::decode(&with_rest)?;

        assert_eq!(decoded, varbind);
        assert_eq!(decoded.compile()?, expected);
        assert_eq!(rest, &[0xaa]);

        Ok(())
    }

    #[test]
    fn snmp_varbind_response_value_compiles_decodes_and_exposes_accessors() -> Result<()> {
        let name = SnmpOid::from_dotted("1.3.6.1.2.1.1.3.0")?;
        let varbind = SnmpVarBind::time_ticks(name.clone(), 12_345);

        // Source-backed: .agents/docs/snmp-rfc-manifest.md records RFC 2578 Section
        // 7.1.9 and RFC 3416 Section 3 for TimeTicks as an application value
        // that can appear in a response VarBind value choice.
        let expected = [
            0x30, 0x0e, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x43, 0x02,
            0x30, 0x39,
        ];
        assert_eq!(varbind.compile()?, expected);
        assert_eq!(varbind.name(), &name);
        assert_eq!(varbind.as_time_ticks(), Some(12_345));
        assert_eq!(varbind.value_summary(), "time-ticks");

        let (decoded, rest) = SnmpVarBind::decode(&expected)?;
        assert_eq!(decoded, varbind);
        assert!(rest.is_empty());

        Ok(())
    }

    #[test]
    fn snmp_varbind_exception_and_raw_value_escapes_are_byte_exact() -> Result<()> {
        let name = SnmpOid::from_dotted("1.3.6.1.2.1.1.5.0")?;
        let no_such_object = SnmpVarBind::no_such_object(name.clone());
        assert_eq!(
            no_such_object.compile()?,
            [0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00, 0x80, 0x00,]
        );
        assert!(no_such_object.is_no_such_object());

        let raw = SnmpVarBind::raw_value_tlv(name, [0xc3, 0x01, 0xaa]);
        assert_eq!(
            raw.compile()?,
            [
                0x30, 0x0d, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00, 0xc3, 0x01,
                0xaa,
            ]
        );
        assert_eq!(raw.raw_value_tlv_bytes(), Some(&[0xc3, 0x01, 0xaa][..]));

        Ok(())
    }

    #[test]
    fn snmp_unknown_value_metadata_is_exposed_from_varbind_decode() -> Result<()> {
        let bytes = [
            0x30, 0x0f, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00, 0x45, 0x81,
            0x02, 0xde, 0xad,
        ];
        let (decoded, rest) = SnmpVarBind::decode(&bytes)?;

        assert!(rest.is_empty());
        assert_eq!(decoded.unknown_value_class(), Some("application"));
        assert_eq!(decoded.unknown_value_is_constructed(), Some(false));
        assert_eq!(decoded.unknown_value_tag_number(), Some(5));
        assert_eq!(decoded.unknown_value_content(), Some(&[0xde, 0xad][..]));
        assert_eq!(
            decoded.unknown_value_tlv_bytes(),
            Some(&[0x45, 0x81, 0x02, 0xde, 0xad][..])
        );
        assert_eq!(decoded.compile()?, bytes);

        Ok(())
    }

    #[test]
    fn snmp_raw_tlv_varbind_compile_decode_recompile_and_inspection() -> Result<()> {
        let name = SnmpOid::from_dotted("1.3.6.1.2.1.1.5.0")?;
        let raw_tlv = [0xc3, 0x81, 0x02, 0xde, 0xad];
        let varbind = SnmpVarBind::raw_value_tlv(name, raw_tlv);
        let expected = [
            0x30, 0x0f, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00, 0xc3, 0x81,
            0x02, 0xde, 0xad,
        ];

        assert_eq!(varbind.compile()?, expected);
        let (decoded, rest) = SnmpVarBind::decode(&expected)?;

        assert!(rest.is_empty());
        assert_eq!(decoded.compile()?, expected);
        assert_eq!(decoded.value_summary(), "private-3");
        assert_eq!(decoded.raw_value_tlv_bytes(), Some(&raw_tlv[..]));
        assert_eq!(decoded.unknown_value_class(), Some("private"));
        assert_eq!(decoded.unknown_value_is_constructed(), Some(false));
        assert_eq!(decoded.unknown_value_tag_number(), Some(3));
        assert_eq!(decoded.unknown_value_content(), Some(&[0xde, 0xad][..]));
        assert_eq!(decoded.unknown_value_tlv_bytes(), Some(&raw_tlv[..]));
        assert_eq!(
            decoded.inspection_fields(),
            [
                ("name", "1.3.6.1.2.1.1.5.0".to_string()),
                ("name_type", "object-identifier".to_string()),
                ("name_arc_count", "9".to_string()),
                ("value_type", "private-3".to_string()),
                ("value_ber_class", "private".to_string()),
                ("value_ber_class_bits", "0xc0".to_string()),
                ("value_ber_constructed", "false".to_string()),
                ("value_ber_tag_number", "3".to_string()),
                ("value_ber_identifier", "0xc3".to_string()),
                ("value_ber_length", "2".to_string()),
                ("value_content_len", "2".to_string()),
                ("value_tlv_len", "5".to_string()),
                ("value_content_bytes", "de ad".to_string()),
                ("value_tlv_bytes", "c3 81 02 de ad".to_string()),
            ]
        );

        Ok(())
    }

    #[test]
    fn snmp_varbind_list_empty_compiles_and_decodes() -> Result<()> {
        let list = SnmpVarBindList::empty();

        // Source-backed: .agents/docs/snmp-rfc-manifest.md records RFC 1157 Section
        // 4.1.1 and RFC 3416 Section 3 for VarBindList as an ordered
        // SEQUENCE OF VarBind, which may be empty at the BER layer.
        assert_eq!(list.compile()?, [0x30, 0x00]);
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
        assert_eq!(list.as_slice(), &[]);
        assert_eq!(list.summary(), "varbinds=0");
        assert_eq!(
            list.inspection_fields(),
            [("varbind_count", "0".to_string())]
        );

        let mut with_rest = list.compile()?;
        with_rest.push(0xaa);
        let (decoded, rest) = SnmpVarBindList::decode(&with_rest)?;

        assert_eq!(decoded, list);
        assert_eq!(rest, &[0xaa]);

        Ok(())
    }

    #[test]
    fn snmp_varbind_list_single_compiles_and_decodes() -> Result<()> {
        let name = SnmpOid::from_dotted("1.3.6.1.2.1.1.3.0")?;
        let varbind = SnmpVarBind::null(name);
        let list = SnmpVarBindList::new(vec![varbind.clone()]);

        let expected = [
            0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00,
            0x05, 0x00,
        ];
        assert_eq!(list.compile()?, expected);
        assert_eq!(list.len(), 1);
        assert_eq!(list.as_slice(), &[varbind]);
        assert_eq!(list.summary(), "varbinds=1");
        assert_eq!(
            list.inspection_fields(),
            [
                ("varbind_count", "1".to_string()),
                ("varbind[0]", "1.3.6.1.2.1.1.3.0=null".to_string()),
            ]
        );

        let (decoded, rest) = SnmpVarBindList::decode(&expected)?;
        assert_eq!(decoded, list);
        assert!(rest.is_empty());

        Ok(())
    }

    #[test]
    fn snmp_varbind_list_multiple_preserves_order_and_unknown_values() -> Result<()> {
        let uptime = SnmpVarBind::time_ticks(SnmpOid::from_dotted("1.3.6.1.2.1.1.3.0")?, 12_345);
        let raw = SnmpVarBind::raw_value_tlv(
            SnmpOid::from_dotted("1.3.6.1.2.1.1.5.0")?,
            [0xc3, 0x01, 0xaa],
        );
        let list = SnmpVarBindList::new(vec![uptime.clone(), raw.clone()]);

        let expected = [
            0x30, 0x1f, 0x30, 0x0e, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00,
            0x43, 0x02, 0x30, 0x39, 0x30, 0x0d, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01,
            0x05, 0x00, 0xc3, 0x01, 0xaa,
        ];
        assert_eq!(list.compile()?, expected);

        let (decoded, rest) = SnmpVarBindList::decode(&expected)?;
        assert!(rest.is_empty());
        assert_eq!(decoded.as_slice(), &[uptime, raw.clone()]);
        assert_eq!(
            decoded.as_slice()[1].raw_value_tlv_bytes(),
            raw.raw_value_tlv_bytes()
        );

        Ok(())
    }

    #[test]
    fn snmp_varbind_list_duplicate_names_are_preserved() -> Result<()> {
        let name = SnmpOid::from_dotted("1.3.6.1.2.1.1.5.0")?;
        let first = SnmpVarBind::octet_string(name.clone(), b"alpha".to_vec());
        let second = SnmpVarBind::octet_string(name, b"beta".to_vec());
        let list = SnmpVarBindList::new(vec![first.clone(), second.clone()]);

        let decoded = SnmpVarBindList::decode(&list.compile()?)?.0;

        assert_eq!(decoded.as_slice(), &[first, second]);
        assert_eq!(decoded.as_slice()[0].name(), decoded.as_slice()[1].name());
        assert_eq!(decoded.as_slice()[0].as_octets(), Some(&b"alpha"[..]));
        assert_eq!(decoded.as_slice()[1].as_octets(), Some(&b"beta"[..]));

        Ok(())
    }

    #[test]
    fn snmp_varbind_list_truncated_member_returns_structured_error() {
        let bytes = [
            0x30, 0x0d, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00,
            0x05,
        ];

        assert_eq!(
            SnmpVarBindList::decode(&bytes),
            Err(CrafterError::buffer_too_short("snmp.ber.sequence", 14, 13))
        );
    }

    #[test]
    fn snmp_varbind_list_invalid_nested_sequence_returns_structured_error() {
        let bytes = [0x30, 0x03, 0x02, 0x01, 0x00];

        assert_eq!(
            SnmpVarBindList::decode(&bytes),
            Err(CrafterError::invalid_field_value(
                "snmp.ber.sequence",
                "expected universal constructed SEQUENCE"
            ))
        );
    }
}
