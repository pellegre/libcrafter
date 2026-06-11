//! BGP-4 (RFC 4271) capability negotiation types.

use crate::Result;

use super::decode::take;

/// OPEN optional-parameter type for RFC 5492 capabilities.
pub const BGP_OPT_PARAM_CAPABILITIES: u8 = 2;

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
}
