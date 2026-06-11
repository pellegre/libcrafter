//! BGP-4 (RFC 4271) capability negotiation types.

use crate::{CrafterError, Result};

use super::constants::{
    AFI_IPV4, AFI_IPV6, CAP_ADD_PATH, CAP_FOUR_OCTET_AS, CAP_GRACEFUL_RESTART,
    CAP_MULTIPROTOCOL, CAP_ROUTE_REFRESH, SAFI_UNICAST,
};
use super::decode::take;

/// OPEN optional-parameter type for RFC 5492 capabilities.
pub const BGP_OPT_PARAM_CAPABILITIES: u8 = 2;

/// RFC 4760 Multiprotocol capability value length.
pub const BGP_CAP_MULTIPROTOCOL_VALUE_LEN: usize = 4;

/// RFC 6793 Four-octet AS Number capability value length.
pub const BGP_CAP_FOUR_OCTET_AS_VALUE_LEN: usize = 4;

/// IPv4 unicast AFI/SAFI pair for the MP-BGP capability.
pub const BGP_MP_IPV4_UNICAST: (u16, u8) = (AFI_IPV4, SAFI_UNICAST);

/// IPv6 unicast AFI/SAFI pair for the MP-BGP capability.
pub const BGP_MP_IPV6_UNICAST: (u16, u8) = (AFI_IPV6, SAFI_UNICAST);

/// BGP capability advertisement (RFC 5492 §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpCapability {
    /// Capability Code.
    pub code: u8,
    /// Capability Value bytes.
    pub value: Vec<u8>,
}

impl BgpCapability {
    /// Create a capability with a raw code and value.
    pub fn raw(code: u8, value: impl Into<Vec<u8>>) -> Self {
        Self {
            code,
            value: value.into(),
        }
    }

    /// Create the RFC 4760 Multiprotocol capability for one AFI/SAFI pair.
    pub fn multiprotocol(afi: u16, safi: u8) -> Self {
        let mut value = Vec::with_capacity(BGP_CAP_MULTIPROTOCOL_VALUE_LEN);
        value.extend_from_slice(&afi.to_be_bytes());
        value.push(0);
        value.push(safi);
        Self::raw(CAP_MULTIPROTOCOL, value)
    }

    /// Create an MP-BGP capability advertising IPv4 unicast.
    pub fn ipv4_unicast() -> Self {
        Self::multiprotocol(AFI_IPV4, SAFI_UNICAST)
    }

    /// Create an MP-BGP capability advertising IPv6 unicast.
    pub fn ipv6_unicast() -> Self {
        Self::multiprotocol(AFI_IPV6, SAFI_UNICAST)
    }

    /// Create the RFC 2918 Route Refresh capability.
    pub fn route_refresh() -> Self {
        Self::raw(CAP_ROUTE_REFRESH, Vec::new())
    }

    /// Create the RFC 6793 Four-octet AS Number capability.
    pub fn four_octet_as(asn: u32) -> Self {
        Self::raw(CAP_FOUR_OCTET_AS, asn.to_be_bytes())
    }

    /// Create the RFC 4724 Graceful Restart capability.
    pub fn graceful_restart(flags_time: u16, tuples: &[(u16, u8, u8)]) -> Self {
        let mut value = Vec::with_capacity(2 + tuples.len() * 4);
        value.extend_from_slice(&flags_time.to_be_bytes());
        for &(afi, safi, flags) in tuples {
            value.extend_from_slice(&afi.to_be_bytes());
            value.push(safi);
            value.push(flags);
        }
        Self::raw(CAP_GRACEFUL_RESTART, value)
    }

    /// Create the RFC 7911 ADD-PATH capability.
    pub fn add_path(entries: &[(u16, u8, u8)]) -> Self {
        let mut value = Vec::with_capacity(entries.len() * 4);
        for &(afi, safi, send_receive) in entries {
            value.extend_from_slice(&afi.to_be_bytes());
            value.push(safi);
            value.push(send_receive);
        }
        Self::raw(CAP_ADD_PATH, value)
    }

    /// Parse this RFC 4760 Multiprotocol capability into its AFI/SAFI pair.
    pub fn multiprotocol_afi_safi(&self) -> Result<(u16, u8)> {
        if self.code != CAP_MULTIPROTOCOL {
            return Err(CrafterError::invalid_field_value(
                "bgp.capability.code",
                "not a multiprotocol capability",
            ));
        }

        let (value, rest) = take(
            &self.value,
            BGP_CAP_MULTIPROTOCOL_VALUE_LEN,
            "bgp multiprotocol capability value",
        )?;
        if !rest.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "bgp.capability.multiprotocol.length",
                "expected 4 octets",
            ));
        }

        let afi = u16::from_be_bytes([value[0], value[1]]);
        let safi = value[3];
        Ok((afi, safi))
    }

    /// Parse this RFC 6793 Four-octet AS Number capability into its AS value.
    pub fn four_octet_asn(&self) -> Result<u32> {
        if self.code != CAP_FOUR_OCTET_AS {
            return Err(CrafterError::invalid_field_value(
                "bgp.capability.code",
                "not a four-octet AS capability",
            ));
        }

        let (value, rest) = take(
            &self.value,
            BGP_CAP_FOUR_OCTET_AS_VALUE_LEN,
            "bgp four-octet AS capability value",
        )?;
        if !rest.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "bgp.capability.four_octet_as.length",
                "expected 4 octets",
            ));
        }

        Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
    }

    /// Append `Code | Length | Value` to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.code);
        out.push(self.value.len() as u8);
        out.extend_from_slice(&self.value);
    }

    /// Decode one capability from the front of `bytes`.
    pub fn decode(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (code, rest) = take(bytes, 1, "bgp capability")?;
        let (length, rest) = take(rest, 1, "bgp capability")?;
        let (value, rest) = take(rest, length[0] as usize, "bgp capability value")?;

        Ok((Self::raw(code[0], value.to_vec()), rest))
    }
}

/// Encode a list of RFC 5492 capabilities into one optional-parameter value.
pub fn encode_capabilities(capabilities: &[BgpCapability]) -> Vec<u8> {
    let encoded_len = capabilities.iter().map(|cap| 2 + cap.value.len()).sum();
    let mut out = Vec::with_capacity(encoded_len);
    for capability in capabilities {
        capability.encode(&mut out);
    }
    out
}

/// Decode all RFC 5492 capabilities from an optional-parameter value.
pub fn decode_capabilities(bytes: &[u8]) -> Result<Vec<BgpCapability>> {
    let mut capabilities = Vec::new();
    let mut rest = bytes;

    while !rest.is_empty() {
        let (capability, remaining) = BgpCapability::decode(rest)?;
        capabilities.push(capability);
        rest = remaining;
    }

    Ok(capabilities)
}

/// BGP OPEN optional parameter (RFC 4271 §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpOptParam {
    /// Optional parameter Type.
    pub param_type: u8,
    /// Optional parameter Value bytes.
    pub value: Vec<u8>,
}

impl BgpOptParam {
    /// Create an optional parameter with a raw type code and value.
    pub fn raw(param_type: u8, value: impl Into<Vec<u8>>) -> Self {
        Self {
            param_type,
            value: value.into(),
        }
    }

    /// Create the RFC 5492 capabilities optional-parameter container.
    pub fn capabilities(value: impl Into<Vec<u8>>) -> Self {
        Self::raw(BGP_OPT_PARAM_CAPABILITIES, value)
    }

    /// Encoded optional-parameter length, including Type and Length.
    pub(crate) fn encoded_len(&self) -> usize {
        2 + self.value.len()
    }

    /// Append `Type | Length | Value` to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.param_type);
        out.push(self.value.len() as u8);
        out.extend_from_slice(&self.value);
    }

    /// Decode one optional parameter from the front of `bytes`.
    pub fn decode(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (param_type, rest) = take(bytes, 1, "bgp optional parameter")?;
        let (param_len, rest) = take(rest, 1, "bgp optional parameter")?;
        let (value, rest) = take(rest, param_len[0] as usize, "bgp optional parameter value")?;

        Ok((Self::raw(param_type[0], value.to_vec()), rest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_optional_parameter_round_trips() {
        let param = BgpOptParam::raw(99, vec![0xaa, 0xbb, 0xcc]);
        let mut encoded = Vec::new();
        param.encode(&mut encoded);

        assert_eq!(encoded, [99, 3, 0xaa, 0xbb, 0xcc]);

        let (decoded, rest) = BgpOptParam::decode(&encoded).expect("parameter decodes");
        assert_eq!(decoded, param);
        assert!(rest.is_empty());
    }

    #[test]
    fn capabilities_round_trip_with_unknown_code() {
        let capabilities = vec![
            BgpCapability::raw(2, Vec::new()),
            BgpCapability::raw(200, vec![0xaa, 0xbb, 0xcc]),
        ];

        let encoded = encode_capabilities(&capabilities);
        assert_eq!(encoded, [2, 0, 200, 3, 0xaa, 0xbb, 0xcc]);

        let decoded = decode_capabilities(&encoded).expect("capabilities decode");
        assert_eq!(decoded, capabilities);
    }

    #[test]
    fn multiprotocol_capability_encodes_and_parses() {
        let capability = BgpCapability::multiprotocol(2, 1);

        let mut encoded = Vec::new();
        capability.encode(&mut encoded);

        assert_eq!(encoded, [1, 4, 0x00, 0x02, 0x00, 0x01]);
        assert_eq!(
            capability
                .multiprotocol_afi_safi()
                .expect("MP-BGP capability parses"),
            (2, 1)
        );
        assert_eq!(
            BgpCapability::ipv4_unicast().multiprotocol_afi_safi(),
            Ok(BGP_MP_IPV4_UNICAST)
        );
        assert_eq!(
            BgpCapability::ipv6_unicast().multiprotocol_afi_safi(),
            Ok(BGP_MP_IPV6_UNICAST)
        );
    }

    #[test]
    fn four_octet_as_capability_encodes_and_parses() {
        let capability = BgpCapability::four_octet_as(4_200_000_000);

        let mut encoded = Vec::new();
        capability.encode(&mut encoded);

        assert_eq!(encoded, [65, 4, 0xfa, 0x56, 0xea, 0x00]);
        assert_eq!(
            capability
                .four_octet_asn()
                .expect("four-octet AS capability parses"),
            4_200_000_000
        );
    }
}
