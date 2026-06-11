//! BGP-4 (RFC 4271) path attribute types.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::field::Field;
use crate::{CrafterError, Result};

use super::constants::{
    ATTR_AGGREGATOR, ATTR_AGGREGATOR_FLAGS, ATTR_AS4_AGGREGATOR, ATTR_AS4_AGGREGATOR_FLAGS,
    ATTR_AS4_PATH, ATTR_AS4_PATH_FLAGS, ATTR_AS_PATH, ATTR_AS_PATH_FLAGS, ATTR_ATOMIC_AGGREGATE,
    ATTR_ATOMIC_AGGREGATE_FLAGS, ATTR_COMMUNITIES, ATTR_COMMUNITIES_FLAGS,
    ATTR_EXTENDED_COMMUNITIES, ATTR_EXTENDED_COMMUNITIES_FLAGS, ATTR_LARGE_COMMUNITY,
    ATTR_LARGE_COMMUNITY_FLAGS, ATTR_LOCAL_PREF, ATTR_LOCAL_PREF_FLAGS, ATTR_MP_REACH_NLRI,
    ATTR_MP_REACH_NLRI_FLAGS, ATTR_MP_UNREACH_NLRI, ATTR_MP_UNREACH_NLRI_FLAGS,
    ATTR_MULTI_EXIT_DISC, ATTR_MULTI_EXIT_DISC_FLAGS, ATTR_NEXT_HOP, ATTR_NEXT_HOP_FLAGS,
    ATTR_ORIGIN, ATTR_ORIGIN_FLAGS, BGP_ATTR_FLAG_EXTENDED_LENGTH, BGP_ATTR_FLAG_OPTIONAL,
    ORIGIN_EGP, ORIGIN_IGP, ORIGIN_INCOMPLETE,
};
use super::decode::take;

/// ORIGIN = IGP. RFC 4271 §5.1.1.
pub const BGP_ORIGIN_IGP: u8 = ORIGIN_IGP;
/// ORIGIN = EGP. RFC 4271 §5.1.1.
pub const BGP_ORIGIN_EGP: u8 = ORIGIN_EGP;
/// ORIGIN = INCOMPLETE. RFC 4271 §5.1.1.
pub const BGP_ORIGIN_INCOMPLETE: u8 = ORIGIN_INCOMPLETE;

/// BGP path-attribute value bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BgpAttrValue {
    /// ORIGIN path attribute (RFC 4271 §5.1.1).
    Origin(u8),
    /// A value whose type-specific structure is not modeled yet.
    Unknown(Vec<u8>),
}

impl BgpAttrValue {
    /// Encoded attribute value length, in octets.
    pub fn encoded_len(&self) -> usize {
        match self {
            Self::Origin(_) => 1,
            Self::Unknown(value) => value.len(),
        }
    }

    /// Append the raw attribute value bytes to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Origin(origin) => out.push(*origin),
            Self::Unknown(value) => out.extend_from_slice(value),
        }
    }
}

/// Generic BGP path attribute frame (RFC 4271 §4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpPathAttribute {
    /// Attribute Flags octet.
    pub flags: Field<u8>,
    /// Attribute Type Code.
    pub type_code: u8,
    /// Attribute Value.
    pub value: BgpAttrValue,
}

impl BgpPathAttribute {
    /// Build an ORIGIN path attribute (RFC 4271 §5.1.1).
    pub fn origin(origin: u8) -> Self {
        Self {
            flags: Field::defaulted(ATTR_ORIGIN_FLAGS),
            type_code: ATTR_ORIGIN,
            value: BgpAttrValue::Origin(origin),
        }
    }

    /// Build a raw path attribute with canonical flags inferred from type code.
    pub fn unknown(type_code: u8, value: impl Into<Vec<u8>>) -> Self {
        Self {
            flags: Field::unset(),
            type_code,
            value: BgpAttrValue::Unknown(value.into()),
        }
    }

    /// Force a specific Attribute Flags octet.
    pub fn with_flags(mut self, flags: u8) -> Self {
        self.flags.set_user(flags);
        self
    }

    /// Encoded path-attribute length, including flags, type, length, and value.
    pub fn encoded_len(&self) -> usize {
        let flags = self.effective_flags();
        let length_len = if flags & BGP_ATTR_FLAG_EXTENDED_LENGTH != 0 {
            2
        } else {
            1
        };
        2 + length_len + self.value.encoded_len()
    }

    /// Append `Flags | Type Code | Length | Value` to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let flags = self.effective_flags();
        let value_len = self.value.encoded_len();

        out.push(flags);
        out.push(self.type_code);
        if flags & BGP_ATTR_FLAG_EXTENDED_LENGTH != 0 {
            out.extend_from_slice(&(value_len as u16).to_be_bytes());
        } else {
            out.push(value_len as u8);
        }
        self.value.encode(out);
    }

    /// Human-readable path-attribute summary.
    pub fn summary(&self) -> String {
        match &self.value {
            BgpAttrValue::Origin(origin) => format!("ORIGIN={}", origin_value_name(*origin)),
            BgpAttrValue::Unknown(value) => format!("attr-{} len={}", self.type_code, value.len()),
        }
    }

    fn effective_flags(&self) -> u8 {
        let mut flags = self
            .flags
            .value()
            .copied()
            .unwrap_or_else(|| well_known_flags(self.type_code));
        if !self.flags.is_user_set() && self.value.encoded_len() > u8::MAX as usize {
            flags |= BGP_ATTR_FLAG_EXTENDED_LENGTH;
        }
        flags
    }
}

/// Canonical default flags for known BGP path-attribute type codes.
pub fn well_known_flags(type_code: u8) -> u8 {
    match type_code {
        ATTR_ORIGIN => ATTR_ORIGIN_FLAGS,
        ATTR_AS_PATH => ATTR_AS_PATH_FLAGS,
        ATTR_NEXT_HOP => ATTR_NEXT_HOP_FLAGS,
        ATTR_MULTI_EXIT_DISC => ATTR_MULTI_EXIT_DISC_FLAGS,
        ATTR_LOCAL_PREF => ATTR_LOCAL_PREF_FLAGS,
        ATTR_ATOMIC_AGGREGATE => ATTR_ATOMIC_AGGREGATE_FLAGS,
        ATTR_AGGREGATOR => ATTR_AGGREGATOR_FLAGS,
        ATTR_COMMUNITIES => ATTR_COMMUNITIES_FLAGS,
        ATTR_MP_REACH_NLRI => ATTR_MP_REACH_NLRI_FLAGS,
        ATTR_MP_UNREACH_NLRI => ATTR_MP_UNREACH_NLRI_FLAGS,
        ATTR_EXTENDED_COMMUNITIES => ATTR_EXTENDED_COMMUNITIES_FLAGS,
        ATTR_AS4_PATH => ATTR_AS4_PATH_FLAGS,
        ATTR_AS4_AGGREGATOR => ATTR_AS4_AGGREGATOR_FLAGS,
        ATTR_LARGE_COMMUNITY => ATTR_LARGE_COMMUNITY_FLAGS,
        _ => BGP_ATTR_FLAG_OPTIONAL,
    }
}

/// Decode one RFC 4271 path attribute from the front of `buf`.
pub fn decode_attribute(buf: &[u8]) -> Result<(BgpPathAttribute, usize)> {
    let (flags, rest) = take(buf, 1, "bgp path attribute flags")?;
    let (type_code, rest) = take(rest, 1, "bgp path attribute type")?;
    let flags = flags[0];
    let type_code = type_code[0];

    let extended = flags & BGP_ATTR_FLAG_EXTENDED_LENGTH != 0;
    let (length, rest, length_len) = if extended {
        let (length, rest) = take(rest, 2, "bgp path attribute length")?;
        (u16::from_be_bytes([length[0], length[1]]) as usize, rest, 2)
    } else {
        let (length, rest) = take(rest, 1, "bgp path attribute length")?;
        (length[0] as usize, rest, 1)
    };
    let (value, _) = take(rest, length, "bgp path attribute value")?;
    let value = match type_code {
        ATTR_ORIGIN => decode_origin_value(value)?,
        _ => BgpAttrValue::Unknown(value.to_vec()),
    };

    Ok((
        BgpPathAttribute {
            flags: Field::user(flags),
            type_code,
            value,
        },
        2 + length_len + length,
    ))
}

fn decode_origin_value(value: &[u8]) -> Result<BgpAttrValue> {
    let (origin, rest) = take(value, 1, "bgp origin attribute value")?;
    if !rest.is_empty() {
        return Err(CrafterError::invalid_field_value(
            "bgp.attribute.origin.length",
            "ORIGIN attribute value must be exactly one octet",
        ));
    }
    Ok(BgpAttrValue::Origin(origin[0]))
}

fn origin_value_name(origin: u8) -> String {
    match origin {
        BGP_ORIGIN_IGP => "IGP".to_string(),
        BGP_ORIGIN_EGP => "EGP".to_string(),
        BGP_ORIGIN_INCOMPLETE => "INCOMPLETE".to_string(),
        other => format!("origin-{other}"),
    }
}

/// A BGP network-layer reachability prefix.
///
/// RFC 4271 encodes both UPDATE NLRI and withdrawn routes as one octet of
/// prefix length in bits followed by `ceil(length / 8)` significant prefix
/// octets. MP-BGP uses the same prefix encoding for IPv6 NLRI inside the
/// address-family-specific attributes, so the maximum accepted length is a
/// decoder parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpPrefix {
    /// Prefix length in bits.
    pub length: u8,
    /// Exactly `ceil(length / 8)` significant prefix octets.
    pub prefix: Vec<u8>,
}

impl BgpPrefix {
    /// Create an IPv4 BGP prefix, accepting lengths from 0 through 32.
    pub fn from_ipv4(address: Ipv4Addr, length: u8) -> Result<Self> {
        Self::from_address_octets(&address.octets(), length, 32)
    }

    /// Create an IPv6 BGP prefix, accepting lengths from 0 through 128.
    pub fn from_ipv6(address: Ipv6Addr, length: u8) -> Result<Self> {
        Self::from_address_octets(&address.octets(), length, 128)
    }

    /// Number of significant prefix octets encoded on the wire.
    pub fn significant_octets(length: u8) -> usize {
        (length as usize).div_ceil(8)
    }

    /// Append this prefix as `Length | Prefix` bytes.
    pub fn encode_prefix(&self, out: &mut Vec<u8>) {
        out.push(self.length);
        out.extend_from_slice(&self.prefix);
    }

    /// Decode an IPv4 BGP prefix, accepting lengths from 0 through 32.
    pub fn decode_prefix(buf: &[u8]) -> Result<(Self, usize)> {
        Self::decode_prefix_with_max(buf, 32)
    }

    /// Decode a BGP prefix with a caller-supplied maximum length.
    pub fn decode_prefix_with_max(buf: &[u8], max_length: u8) -> Result<(Self, usize)> {
        let (length, rest) = take(buf, 1, "bgp prefix length")?;
        let length = length[0];
        Self::validate_length(length, max_length)?;

        let prefix_len = Self::significant_octets(length);
        let (prefix, _) = take(rest, prefix_len, "bgp prefix")?;

        Ok((
            Self {
                length,
                prefix: prefix.to_vec(),
            },
            1 + prefix_len,
        ))
    }

    fn from_address_octets(octets: &[u8], length: u8, max_length: u8) -> Result<Self> {
        Self::validate_length(length, max_length)?;

        let prefix_len = Self::significant_octets(length);
        let mut prefix = octets[..prefix_len].to_vec();
        if let Some(last) = prefix.last_mut() {
            let remainder = length % 8;
            if remainder != 0 {
                *last &= 0xffu8 << (8 - remainder);
            }
        }

        Ok(Self { length, prefix })
    }

    fn validate_length(length: u8, max_length: u8) -> Result<()> {
        if length > max_length {
            return Err(CrafterError::invalid_field_value(
                "bgp.prefix.length",
                "prefix length exceeds address-family maximum",
            ));
        }
        Ok(())
    }
}

/// Decode an IPv4 BGP prefix, accepting lengths from 0 through 32.
pub fn decode_prefix(buf: &[u8]) -> Result<(BgpPrefix, usize)> {
    BgpPrefix::decode_prefix(buf)
}

/// Decode a BGP prefix with a caller-supplied maximum length.
pub fn decode_prefix_with_max(buf: &[u8], max_length: u8) -> Result<(BgpPrefix, usize)> {
    BgpPrefix::decode_prefix_with_max(buf, max_length)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_prefix_encodes_as_length_and_significant_octets() {
        let prefix =
            BgpPrefix::from_ipv4(Ipv4Addr::new(203, 0, 113, 0), 24).expect("valid IPv4 prefix");

        let mut encoded = Vec::new();
        prefix.encode_prefix(&mut encoded);

        assert_eq!(prefix.prefix, [0xcb, 0x00, 0x71]);
        assert_eq!(encoded, [0x18, 0xcb, 0x00, 0x71]);
    }

    #[test]
    fn ipv4_prefix_decodes_and_reports_consumed_bytes() {
        let bytes = [0x18, 0xcb, 0x00, 0x71, 0xaa];
        let (prefix, consumed) = BgpPrefix::decode_prefix(&bytes).expect("prefix decodes");

        assert_eq!(
            prefix,
            BgpPrefix {
                length: 24,
                prefix: vec![0xcb, 0x00, 0x71],
            }
        );
        assert_eq!(consumed, 4);
    }

    #[test]
    fn overlong_ipv4_prefix_length_errors() {
        let err = BgpPrefix::decode_prefix(&[33, 0, 0, 0, 0]).expect_err("IPv4 max is 32 bits");

        assert!(matches!(
            err,
            CrafterError::InvalidFieldValue {
                field: "bgp.prefix.length",
                ..
            }
        ));
    }

    #[test]
    fn ipv6_prefix_constructor_allows_128_bits() {
        let prefix = BgpPrefix::from_ipv6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1), 128)
            .expect("valid IPv6 prefix");

        assert_eq!(prefix.length, 128);
        assert_eq!(prefix.prefix.len(), 16);
    }

    #[test]
    fn origin_attribute_encodes_and_round_trips() {
        let attr = BgpPathAttribute::origin(BGP_ORIGIN_IGP);
        let mut encoded = Vec::new();
        attr.encode(&mut encoded);

        assert_eq!(encoded, [ATTR_ORIGIN_FLAGS, ATTR_ORIGIN, 1, BGP_ORIGIN_IGP]);
        assert_eq!(attr.summary(), "ORIGIN=IGP");

        let (decoded, consumed) = decode_attribute(&encoded).expect("attribute decodes");
        assert_eq!(consumed, encoded.len());
        assert_eq!(
            decoded,
            BgpPathAttribute {
                flags: Field::user(ATTR_ORIGIN_FLAGS),
                type_code: ATTR_ORIGIN,
                value: BgpAttrValue::Origin(BGP_ORIGIN_IGP),
            }
        );
        assert_eq!(decoded.summary(), "ORIGIN=IGP");

        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded);
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn short_unknown_path_attribute_uses_one_octet_length_and_round_trips() {
        let attr = BgpPathAttribute::unknown(99, vec![0xaa]);
        let mut encoded = Vec::new();
        attr.encode(&mut encoded);

        assert_eq!(encoded, [BGP_ATTR_FLAG_OPTIONAL, 99, 1, 0xaa]);

        let (decoded, consumed) = decode_attribute(&encoded).expect("attribute decodes");
        assert_eq!(consumed, encoded.len());
        assert_eq!(
            decoded,
            BgpPathAttribute {
                flags: Field::user(BGP_ATTR_FLAG_OPTIONAL),
                type_code: 99,
                value: BgpAttrValue::Unknown(vec![0xaa]),
            }
        );

        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded);
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn long_path_attribute_auto_uses_extended_length_and_round_trips() {
        let value = (0..300).map(|n| n as u8).collect::<Vec<_>>();
        let attr = BgpPathAttribute::unknown(ATTR_COMMUNITIES, value.clone());
        let mut encoded = Vec::new();
        attr.encode(&mut encoded);

        assert_eq!(
            encoded[0],
            ATTR_COMMUNITIES_FLAGS | BGP_ATTR_FLAG_EXTENDED_LENGTH
        );
        assert_eq!(encoded[1], ATTR_COMMUNITIES);
        assert_eq!(&encoded[2..4], &(300u16).to_be_bytes());
        assert_eq!(&encoded[4..], value.as_slice());

        let (decoded, consumed) = decode_attribute(&encoded).expect("attribute decodes");
        assert_eq!(consumed, encoded.len());
        assert_eq!(
            decoded.flags.value(),
            Some(&(ATTR_COMMUNITIES_FLAGS | BGP_ATTR_FLAG_EXTENDED_LENGTH))
        );
        assert_eq!(decoded.type_code, ATTR_COMMUNITIES);
        assert_eq!(decoded.value, BgpAttrValue::Unknown(value));

        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded);
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn caller_fixed_flags_are_not_extended_automatically() {
        let value = vec![0xaa; 300];
        let attr = BgpPathAttribute::unknown(ATTR_COMMUNITIES, value.clone())
            .with_flags(ATTR_COMMUNITIES_FLAGS);
        let mut encoded = Vec::new();
        attr.encode(&mut encoded);

        assert_eq!(encoded[0], ATTR_COMMUNITIES_FLAGS);
        assert_eq!(encoded[1], ATTR_COMMUNITIES);
        assert_eq!(encoded[2], value.len() as u8);
        assert_eq!(&encoded[3..], value.as_slice());
    }
}
