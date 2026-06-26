//! BER OBJECT IDENTIFIER support for SNMP packet values.
//!
//! Source-gated by `.agents/docs/snmp-rfc-manifest.md`; this module treats OIDs as
//! ordered packet arcs and does not perform MIB name resolution.

#![cfg_attr(not(test), allow(dead_code))]

use core::fmt;
use core::str::FromStr;

use super::ber;
use crate::error::{CrafterError, Result};

const OID_CONTEXT: &str = "snmp.oid";
const OID_DOTTED_CONTEXT: &str = "snmp.oid.dotted";
const BER_OID_CONTEXT: &str = "snmp.ber.object_identifier";
const BER_OID_BASE128_CONTEXT: &str = "snmp.ber.object_identifier.base128";

const MAX_OID_ARCS: usize = 128;
const MIN_OID_ARCS: usize = 2;
const MAX_ARC: u64 = u32::MAX as u64;
const MAX_FIRST_SUBIDENTIFIER: u64 = MAX_ARC + 80;

/// SNMP OBJECT IDENTIFIER value as ordered numeric arcs.
///
/// `SnmpOid` is a packet-level object identifier. It does not resolve MIB
/// names and it does not imply that the crate implements the referenced MIB
/// object.
///
/// ```rust
/// use crafter::protocols::snmp::SnmpOid;
///
/// # fn main() -> crafter::Result<()> {
/// let oid = SnmpOid::from_arcs([1, 3, 6, 1, 2, 1, 1, 3, 0])?;
/// assert_eq!(oid.to_string(), "1.3.6.1.2.1.1.3.0");
/// assert_eq!(oid.arcs(), &[1, 3, 6, 1, 2, 1, 1, 3, 0]);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SnmpOid {
    arcs: Vec<u32>,
}

impl SnmpOid {
    /// Build an object identifier from ordered numeric arcs.
    pub fn from_arcs(arcs: impl Into<Vec<u32>>) -> Result<Self> {
        let arcs = arcs.into();
        validate_arcs(&arcs)?;
        Ok(Self { arcs })
    }

    /// Build an object identifier from a borrowed arc slice.
    pub fn from_slice(arcs: &[u32]) -> Result<Self> {
        Self::from_arcs(arcs.to_vec())
    }

    /// Parse a dotted-decimal object identifier such as `1.3.6.1.2.1.1.3.0`.
    pub fn from_dotted(input: &str) -> Result<Self> {
        if input.is_empty() {
            return Err(invalid_dotted("dotted object identifier is empty"));
        }

        let mut arcs = Vec::new();
        for part in input.split('.') {
            if part.is_empty() {
                return Err(invalid_dotted(
                    "dotted object identifier contains an empty arc",
                ));
            }

            let arc = part
                .parse::<u32>()
                .map_err(|_| invalid_dotted("dotted object identifier arc is not a decimal u32"))?;
            arcs.push(arc);
            if arcs.len() > MAX_OID_ARCS {
                return Err(invalid_oid("object identifier has more than 128 arcs"));
            }
        }

        Self::from_arcs(arcs)
    }

    /// Decode one BER OBJECT IDENTIFIER TLV and return the remaining bytes.
    pub fn decode(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (tag, rest) = ber::decode_identifier(bytes)?;
        if tag
            != ber::BerTag::new(
                ber::BerClass::Universal,
                false,
                ber::BER_TAG_OBJECT_IDENTIFIER,
            )
        {
            return Err(ber::invalid_ber_field(
                BER_OID_CONTEXT,
                "expected universal primitive OBJECT IDENTIFIER",
            ));
        }

        let (length, rest) = ber::decode_length(rest)?;
        if rest.len() < length {
            let prefix_len = bytes.len() - rest.len();
            let required = prefix_len.checked_add(length).ok_or_else(|| {
                ber::invalid_ber_field(
                    BER_OID_CONTEXT,
                    "object identifier length exceeds supported size",
                )
            })?;
            return Err(ber::truncated_ber(BER_OID_CONTEXT, required, bytes.len()));
        }

        let (content, rest) = rest.split_at(length);
        Ok((Self::decode_content(content)?, rest))
    }

    pub(super) fn decode_content(content: &[u8]) -> Result<Self> {
        if content.is_empty() {
            return Err(ber::invalid_ber_field(
                BER_OID_CONTEXT,
                "object identifier requires at least one content octet",
            ));
        }

        let mut offset = 0;
        let first_subidentifier = decode_base128(content, &mut offset, MAX_FIRST_SUBIDENTIFIER)?;

        let (first, second) = if first_subidentifier < 40 {
            (0, first_subidentifier)
        } else if first_subidentifier < 80 {
            (1, first_subidentifier - 40)
        } else {
            (2, first_subidentifier - 80)
        };
        if second > MAX_ARC {
            return Err(invalid_oid("object identifier arc exceeds u32::MAX"));
        }

        let mut arcs = Vec::with_capacity(MIN_OID_ARCS);
        arcs.push(first);
        arcs.push(second as u32);

        while offset < content.len() {
            if arcs.len() == MAX_OID_ARCS {
                return Err(invalid_oid("object identifier has more than 128 arcs"));
            }
            let arc = decode_base128(content, &mut offset, MAX_ARC)?;
            arcs.push(arc as u32);
        }

        Self::from_arcs(arcs)
    }

    /// Encode this object identifier as a BER OBJECT IDENTIFIER TLV.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let mut content = Vec::new();
        self.encode_content(&mut content)?;

        ber::encode_identifier(
            ber::BerTag::new(
                ber::BerClass::Universal,
                false,
                ber::BER_TAG_OBJECT_IDENTIFIER,
            ),
            out,
        )?;
        ber::encode_length(content.len(), out)?;
        out.extend_from_slice(&content);
        Ok(())
    }

    pub(super) fn encode_content(&self, out: &mut Vec<u8>) -> Result<()> {
        validate_arcs(&self.arcs)?;

        let first_subidentifier = u64::from(self.arcs[0]) * 40 + u64::from(self.arcs[1]);
        encode_base128(first_subidentifier, out);
        for arc in &self.arcs[2..] {
            encode_base128(u64::from(*arc), out);
        }
        Ok(())
    }

    /// Return this object identifier encoded as a BER OBJECT IDENTIFIER TLV.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Ordered numeric arcs.
    pub fn arcs(&self) -> &[u32] {
        &self.arcs
    }

    /// Compatibility alias for [`SnmpOid::arcs`].
    pub fn as_slice(&self) -> &[u32] {
        self.arcs()
    }

    /// Compatibility alias for [`SnmpOid::arcs`].
    pub fn as_arcs(&self) -> &[u32] {
        self.arcs()
    }

    /// Copy the ordered numeric arcs into a vector.
    pub fn to_vec(&self) -> Vec<u32> {
        self.arcs.clone()
    }

    /// Consume the object identifier and return its arc vector.
    pub fn into_vec(self) -> Vec<u32> {
        self.arcs
    }

    /// Stable packet-value label for summaries and inspection output.
    pub const fn summary_label(&self) -> &'static str {
        "object-identifier"
    }

    /// A compact object identifier summary without MIB name resolution.
    pub fn summary(&self) -> String {
        format!("oid={self}")
    }

    /// Stable inspection fields for generated tools.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("type", self.summary_label().to_string()),
            ("oid", self.to_string()),
            ("arc_count", self.arcs.len().to_string()),
        ]
    }
}

impl FromStr for SnmpOid {
    type Err = CrafterError;

    fn from_str(input: &str) -> Result<Self> {
        Self::from_dotted(input)
    }
}

impl fmt::Display for SnmpOid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, arc) in self.arcs.iter().enumerate() {
            if index > 0 {
                f.write_str(".")?;
            }
            write!(f, "{arc}")?;
        }
        Ok(())
    }
}

fn validate_arcs(arcs: &[u32]) -> Result<()> {
    if arcs.len() < MIN_OID_ARCS {
        return Err(invalid_oid("object identifier requires at least two arcs"));
    }
    if arcs.len() > MAX_OID_ARCS {
        return Err(invalid_oid("object identifier has more than 128 arcs"));
    }

    match arcs[0] {
        0 | 1 if arcs[1] <= 39 => Ok(()),
        0 | 1 => Err(invalid_oid(
            "object identifier second arc must be <= 39 when first arc is 0 or 1",
        )),
        2 => Ok(()),
        _ => Err(invalid_oid(
            "object identifier first arc must be 0, 1, or 2",
        )),
    }
}

fn decode_base128(content: &[u8], offset: &mut usize, limit: u64) -> Result<u64> {
    let mut value = 0u64;

    loop {
        let Some(&octet) = content.get(*offset) else {
            let required = content.len().saturating_add(1);
            return Err(ber::truncated_ber(
                BER_OID_BASE128_CONTEXT,
                required,
                content.len(),
            ));
        };
        *offset += 1;

        let chunk = u64::from(octet & 0x7f);
        if value > (limit - chunk) / 128 {
            return Err(invalid_oid("object identifier arc exceeds u32::MAX"));
        }
        value = value * 128 + chunk;

        if octet & 0x80 == 0 {
            return Ok(value);
        }
    }
}

fn encode_base128(value: u64, out: &mut Vec<u8>) {
    let mut encoded = [0u8; 10];
    let mut index = encoded.len();
    let mut value = value;

    index -= 1;
    encoded[index] = (value & 0x7f) as u8;
    value >>= 7;

    while value != 0 {
        index -= 1;
        encoded[index] = ((value & 0x7f) as u8) | 0x80;
        value >>= 7;
    }

    out.extend_from_slice(&encoded[index..]);
}

fn invalid_oid(reason: &'static str) -> CrafterError {
    CrafterError::invalid_field_value(OID_CONTEXT, reason)
}

fn invalid_dotted(reason: &'static str) -> CrafterError {
    CrafterError::invalid_field_value(OID_DOTTED_CONTEXT, reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snmp_oid_common_shape_parses_encodes_and_decodes() {
        let oid = SnmpOid::from_dotted("1.3.6.1.2.1.1.1.0").expect("parse OID");

        assert_eq!(oid.arcs(), &[1, 3, 6, 1, 2, 1, 1, 1, 0]);
        assert_eq!(oid.as_slice(), &[1, 3, 6, 1, 2, 1, 1, 1, 0]);
        assert_eq!(oid.as_arcs(), &[1, 3, 6, 1, 2, 1, 1, 1, 0]);
        assert_eq!(oid.to_vec(), vec![1, 3, 6, 1, 2, 1, 1, 1, 0]);
        assert_eq!(oid.to_string(), "1.3.6.1.2.1.1.1.0");
        assert_eq!(oid.summary_label(), "object-identifier");
        assert_eq!(oid.summary(), "oid=1.3.6.1.2.1.1.1.0");
        assert_eq!(
            oid.inspection_fields(),
            [
                ("type", "object-identifier".to_string()),
                ("oid", "1.3.6.1.2.1.1.1.0".to_string()),
                ("arc_count", "9".to_string()),
            ]
        );

        let encoded = oid.to_bytes().expect("encode OID");
        assert_eq!(
            encoded,
            [0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]
        );

        let mut with_rest = encoded.clone();
        with_rest.push(0xaa);
        let (decoded, rest) = SnmpOid::decode(&with_rest).expect("decode OID");

        assert_eq!(decoded.as_slice(), oid.as_slice());
        assert_eq!(decoded.into_vec(), vec![1, 3, 6, 1, 2, 1, 1, 1, 0]);
        assert_eq!(rest, &[0xaa]);
    }

    #[test]
    fn snmp_oid_root_arc_shapes_roundtrip() {
        let cases: &[&[u32]] = &[&[0, 0], &[0, 39], &[1, 0], &[1, 39], &[2, 0], &[2, 100]];

        for arcs in cases {
            let oid = SnmpOid::from_slice(arcs).expect("valid OID");
            let encoded = oid.to_bytes().expect("encode OID");
            let (decoded, rest) = SnmpOid::decode(&encoded).expect("decode OID");

            assert_eq!(decoded.as_slice(), *arcs, "{arcs:?}");
            assert!(rest.is_empty(), "{arcs:?}");
        }
    }

    #[test]
    fn snmp_oid_boundary_arcs_and_arc_count_roundtrip() {
        let oid = SnmpOid::from_slice(&[2, u32::MAX]).expect("max second arc");
        let encoded = oid.to_bytes().expect("encode OID");
        let (decoded, rest) = SnmpOid::decode(&encoded).expect("decode max second arc");

        assert_eq!(decoded.as_slice(), &[2, u32::MAX]);
        assert!(rest.is_empty());

        let oid = SnmpOid::from_slice(&[1, 3, u32::MAX]).expect("max later arc");
        let encoded = oid.to_bytes().expect("encode OID");
        let (decoded, rest) = SnmpOid::decode(&encoded).expect("decode max later arc");

        assert_eq!(decoded.as_slice(), &[1, 3, u32::MAX]);
        assert!(rest.is_empty());

        let mut arcs = vec![1, 3];
        arcs.extend(0..126);
        let oid = SnmpOid::from_arcs(arcs.clone()).expect("max arc count");
        let encoded = oid.to_bytes().expect("encode max arc count");
        let (decoded, rest) = SnmpOid::decode(&encoded).expect("decode OID");

        assert_eq!(decoded.as_slice(), &arcs);
        assert_eq!(decoded.as_slice().len(), MAX_OID_ARCS);
        assert!(rest.is_empty());
    }

    #[test]
    fn snmp_oid_invalid_arcs_return_structured_errors() {
        assert_eq!(
            SnmpOid::from_slice(&[1]),
            Err(CrafterError::invalid_field_value(
                OID_CONTEXT,
                "object identifier requires at least two arcs"
            ))
        );
        assert_eq!(
            SnmpOid::from_slice(&[3, 0]),
            Err(CrafterError::invalid_field_value(
                OID_CONTEXT,
                "object identifier first arc must be 0, 1, or 2"
            ))
        );
        assert_eq!(
            SnmpOid::from_slice(&[1, 40]),
            Err(CrafterError::invalid_field_value(
                OID_CONTEXT,
                "object identifier second arc must be <= 39 when first arc is 0 or 1"
            ))
        );

        let too_many = vec![2; MAX_OID_ARCS + 1];
        assert_eq!(
            SnmpOid::from_arcs(too_many),
            Err(CrafterError::invalid_field_value(
                OID_CONTEXT,
                "object identifier has more than 128 arcs"
            ))
        );
    }

    #[test]
    fn snmp_oid_invalid_dotted_strings_return_structured_errors() {
        assert_eq!(
            SnmpOid::from_dotted(""),
            Err(CrafterError::invalid_field_value(
                OID_DOTTED_CONTEXT,
                "dotted object identifier is empty"
            ))
        );
        assert_eq!(
            SnmpOid::from_dotted("1..3"),
            Err(CrafterError::invalid_field_value(
                OID_DOTTED_CONTEXT,
                "dotted object identifier contains an empty arc"
            ))
        );
        assert_eq!(
            SnmpOid::from_dotted("1.3.name"),
            Err(CrafterError::invalid_field_value(
                OID_DOTTED_CONTEXT,
                "dotted object identifier arc is not a decimal u32"
            ))
        );
        assert_eq!(
            SnmpOid::from_dotted("1.3.4294967296"),
            Err(CrafterError::invalid_field_value(
                OID_DOTTED_CONTEXT,
                "dotted object identifier arc is not a decimal u32"
            ))
        );
    }

    #[test]
    fn snmp_oid_truncated_base128_continuation_returns_structured_error() {
        assert_eq!(
            SnmpOid::decode(&[0x06, 0x01, 0x80]),
            Err(CrafterError::buffer_too_short(
                BER_OID_BASE128_CONTEXT,
                2,
                1
            ))
        );
        assert_eq!(
            SnmpOid::decode(&[0x06, 0x02, 0x2b, 0x80]),
            Err(CrafterError::buffer_too_short(
                BER_OID_BASE128_CONTEXT,
                3,
                2
            ))
        );
    }

    #[test]
    fn snmp_oid_standard_notification_oid_decode_encode_keeps_arc_vector() {
        let bytes = [
            0x06, 0x0a, 0x2b, 0x06, 0x01, 0x06, 0x03, 0x01, 0x01, 0x04, 0x01, 0x00,
        ];
        let arcs = [1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0];

        let (decoded, rest) = SnmpOid::decode(&bytes).expect("decode snmpTrapOID.0");

        assert_eq!(decoded.as_slice(), &arcs);
        assert!(rest.is_empty());
        assert_eq!(decoded.to_bytes().expect("re-encode OID"), bytes);
    }

    #[test]
    fn snmp_oid_rejects_wrong_tag_and_truncated_content() {
        assert_eq!(
            SnmpOid::decode(&[0x04, 0x00]),
            Err(CrafterError::invalid_field_value(
                BER_OID_CONTEXT,
                "expected universal primitive OBJECT IDENTIFIER"
            ))
        );
        assert_eq!(
            SnmpOid::decode(&[0x06, 0x02, 0x2b]),
            Err(CrafterError::buffer_too_short(BER_OID_CONTEXT, 4, 3))
        );
    }
}
