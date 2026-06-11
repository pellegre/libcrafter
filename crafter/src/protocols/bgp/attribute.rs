//! BGP-4 (RFC 4271) path attribute types.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{CrafterError, Result};

use super::decode::take;

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
}
