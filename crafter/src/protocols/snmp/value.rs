//! SNMP value scaffold.
//!
//! Source-gated by `docs/snmp-rfc-manifest.md`; value types and BER-backed
//! preservation behavior are added in later slices.

#![cfg_attr(not(test), allow(dead_code))]

use super::ber;
use crate::error::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SnmpValue {
    Integer(i64),
    RawTlv(RawTlv),
}

impl SnmpValue {
    pub(super) const fn integer(value: i64) -> Self {
        Self::Integer(value)
    }

    pub(super) fn raw_tlv(bytes: impl Into<Vec<u8>>) -> Self {
        Self::RawTlv(RawTlv::new(bytes))
    }

    pub(super) fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Integer(value) => ber::encode_integer(*value, out),
            Self::RawTlv(raw) => {
                out.extend_from_slice(raw.as_bytes());
                Ok(())
            }
        }
    }

    pub(super) fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.encode(&mut out)?;
        Ok(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RawTlv {
    bytes: Vec<u8>,
}

impl RawTlv {
    pub(super) fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snmp_ber_integer_value_constructor_emits_minimal_integer_tlv() {
        assert_eq!(
            SnmpValue::integer(-129)
                .to_bytes()
                .expect("encode SNMP integer"),
            [0x02, 0x02, 0xff, 0x7f]
        );
        assert_eq!(
            SnmpValue::integer(128)
                .to_bytes()
                .expect("encode SNMP integer"),
            [0x02, 0x02, 0x00, 0x80]
        );
    }

    #[test]
    fn snmp_ber_integer_non_minimal_raw_tlv_is_preserved() {
        let bytes = [0x02, 0x02, 0x00, 0x7f];
        let value = SnmpValue::raw_tlv(bytes.to_vec());

        assert_eq!(value.to_bytes().expect("encode raw TLV"), bytes);
    }

    #[test]
    fn snmp_ber_integer_malformed_raw_tlv_constructor_preserves_bytes() {
        let bytes = [0x02, 0x02, 0x7f];
        let value = SnmpValue::raw_tlv(bytes.to_vec());

        assert_eq!(value.to_bytes().expect("encode raw TLV"), bytes);
    }
}
