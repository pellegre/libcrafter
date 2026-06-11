//! BGP-4 (RFC 4271) capability negotiation types.

use crate::Result;

use super::decode::take;

/// OPEN optional-parameter type for RFC 5492 capabilities.
pub const BGP_OPT_PARAM_CAPABILITIES: u8 = 2;

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
}
