//! SNMP variable binding support.
//!
//! Source-gated by `docs/snmp-rfc-manifest.md`; this module models one
//! VarBind as packet bytes only and does not perform MIB lookup.

use super::{ber, oid::SnmpOid, value::SnmpValue};
use crate::error::Result;

/// One SNMP variable binding: an object identifier name plus one SNMP value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnmpVarBind {
    name: SnmpOid,
    value: SnmpValue,
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

    /// A compact summary of this variable binding.
    pub fn summary(&self) -> String {
        format!("{}={}", self.name, self.value.summary_label())
    }

    /// Stable inspection fields for generated tools.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("name", self.name.to_string()),
            ("value_type", self.value.summary_label()),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snmp_varbind_request_null_compiles_decodes_and_inspects() -> Result<()> {
        let name = SnmpOid::from_dotted("1.3.6.1.2.1.1.3.0")?;
        let varbind = SnmpVarBind::request_null(name.clone());

        // Source-backed: docs/snmp-rfc-manifest.md records RFC 1157 Section
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

        // Source-backed: docs/snmp-rfc-manifest.md records RFC 2578 Section
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
}
