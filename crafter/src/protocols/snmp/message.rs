//! SNMP message scaffold.
//!
//! Source-gated by `docs/snmp-rfc-manifest.md`; top-level message wrappers are
//! added only after the corresponding wire model is implemented.

#![cfg_attr(not(test), allow(dead_code))]

use core::fmt;

use super::ber;
use crate::error::Result;

pub(super) const SNMP_VERSION_VALUE_V1: i64 = 0;
pub(super) const SNMP_VERSION_VALUE_V2C: i64 = 1;

const SNMP_MESSAGE_COMMUNITY_CONTEXT: &str = "snmp.message.community";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SnmpVersion {
    V1,
    V2c,
    Unknown(i64),
}

impl SnmpVersion {
    pub(super) const fn from_integer(value: i64) -> Self {
        match value {
            SNMP_VERSION_VALUE_V1 => Self::V1,
            SNMP_VERSION_VALUE_V2C => Self::V2c,
            value => Self::Unknown(value),
        }
    }

    pub(super) const fn as_integer(self) -> i64 {
        match self {
            Self::V1 => SNMP_VERSION_VALUE_V1,
            Self::V2c => SNMP_VERSION_VALUE_V2C,
            Self::Unknown(value) => value,
        }
    }

    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2c => "v2c",
            Self::Unknown(_) => "unknown",
        }
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (value, rest) = ber::decode_integer(bytes)?;
        Ok((Self::from_integer(value), rest))
    }

    pub(super) fn encode(self, out: &mut Vec<u8>) -> Result<()> {
        ber::encode_integer(self.as_integer(), out)
    }
}

impl fmt::Display for SnmpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(value) => write!(f, "unknown({value})"),
            _ => f.write_str(self.label()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SnmpCommunity {
    bytes: Vec<u8>,
}

impl SnmpCommunity {
    pub(super) fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (content, rest) = decode_community_octet_string(bytes)?;
        Ok((Self::new(content.to_vec()), rest))
    }

    pub(super) fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        encode_community_octet_string(self.as_bytes(), out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SnmpMessageHeader {
    version: SnmpVersion,
    community: SnmpCommunity,
}

impl SnmpMessageHeader {
    pub(super) fn new(version: SnmpVersion, community: impl Into<Vec<u8>>) -> Self {
        Self {
            version,
            community: SnmpCommunity::new(community),
        }
    }

    pub(super) const fn version(&self) -> SnmpVersion {
        self.version
    }

    pub(super) fn community(&self) -> &[u8] {
        self.community.as_bytes()
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (version, rest) = SnmpVersion::decode(bytes)?;
        let (community, rest) = SnmpCommunity::decode(rest)?;

        Ok((Self { version, community }, rest))
    }

    pub(super) fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.version.encode(out)?;
        self.community.encode(out)
    }

    pub(super) fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.encode(&mut out)?;
        Ok(out)
    }
}

fn decode_community_octet_string(bytes: &[u8]) -> Result<(&[u8], &[u8])> {
    let (tag, rest) = ber::decode_identifier(bytes)?;
    if tag
        != ber::BerTag::new(
            ber::BerClass::Universal,
            false,
            ber::BER_TAG_OCTET_STRING,
        )
    {
        return Err(ber::invalid_ber_field(
            SNMP_MESSAGE_COMMUNITY_CONTEXT,
            "expected universal primitive OCTET STRING",
        ));
    }

    let (length, rest) = ber::decode_length(rest)?;
    if rest.len() < length {
        let prefix_len = bytes.len() - rest.len();
        let required = prefix_len.checked_add(length).ok_or_else(|| {
            ber::invalid_ber_field(
                SNMP_MESSAGE_COMMUNITY_CONTEXT,
                "community length exceeds supported size",
            )
        })?;
        return Err(ber::truncated_ber(
            SNMP_MESSAGE_COMMUNITY_CONTEXT,
            required,
            bytes.len(),
        ));
    }

    Ok(rest.split_at(length))
}

fn encode_community_octet_string(bytes: &[u8], out: &mut Vec<u8>) -> Result<()> {
    ber::encode_identifier(
        ber::BerTag::new(
            ber::BerClass::Universal,
            false,
            ber::BER_TAG_OCTET_STRING,
        ),
        out,
    )?;
    ber::encode_length(bytes.len(), out)?;
    out.extend_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snmp_version_labels_source_backed_values() {
        // Source-backed: docs/snmp-rfc-manifest.md records RFC 1157 Section
        // 4.1.2 for SNMPv1 value 0 and RFC 1901 Section 3 for SNMPv2c value 1.
        let cases = [
            (SNMP_VERSION_VALUE_V1, SnmpVersion::V1, "v1"),
            (SNMP_VERSION_VALUE_V2C, SnmpVersion::V2c, "v2c"),
        ];

        for (integer, version, label) in cases {
            assert_eq!(SnmpVersion::from_integer(integer), version);
            assert_eq!(version.as_integer(), integer);
            assert_eq!(version.label(), label);
            assert_eq!(version.to_string(), label);
        }

        let unknown = SnmpVersion::from_integer(3);
        assert_eq!(unknown.label(), "unknown");
        assert_eq!(unknown.to_string(), "unknown(3)");
    }

    #[test]
    fn snmp_version_unknown_version_preservation() -> Result<()> {
        let mut bytes = SnmpMessageHeader::new(SnmpVersion::from_integer(3), b"example".to_vec())
            .to_bytes()?;
        bytes.extend_from_slice(&[0xa0, 0x00]);

        let (decoded, rest) = SnmpMessageHeader::decode(&bytes)?;
        assert_eq!(decoded.version(), SnmpVersion::Unknown(3));
        assert_eq!(decoded.version().as_integer(), 3);
        assert_eq!(decoded.version().label(), "unknown");
        assert_eq!(decoded.community(), b"example");
        assert_eq!(rest, &[0xa0, 0x00]);

        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded)?;
        assert_eq!(reencoded, &bytes[..bytes.len() - rest.len()]);

        let negative = SnmpVersion::from_integer(-1);
        assert_eq!(negative, SnmpVersion::Unknown(-1));
        assert_eq!(negative.as_integer(), -1);

        Ok(())
    }

    #[test]
    fn snmp_version_empty_community_strings() -> Result<()> {
        let header = SnmpMessageHeader::new(SnmpVersion::V1, Vec::<u8>::new());
        let mut bytes = header.to_bytes()?;
        bytes.extend_from_slice(&[0xa0, 0x00]);

        assert_eq!(header.community(), b"");
        assert_eq!(
            &bytes[..bytes.len() - 2],
            &[0x02, 0x01, 0x00, 0x04, 0x00]
        );

        let (decoded, rest) = SnmpMessageHeader::decode(&bytes)?;
        assert_eq!(decoded.version(), SnmpVersion::V1);
        assert_eq!(decoded.community(), b"");
        assert_eq!(rest, &[0xa0, 0x00]);

        Ok(())
    }

    #[test]
    fn snmp_version_non_utf8_community_bytes() -> Result<()> {
        let community = [0x00, 0xff, 0x80, b'a'];
        let header = SnmpMessageHeader::new(SnmpVersion::V2c, community.to_vec());
        let bytes = header.to_bytes()?;

        assert_eq!(
            bytes,
            [0x02, 0x01, 0x01, 0x04, 0x04, 0x00, 0xff, 0x80, b'a']
        );

        let (decoded, rest) = SnmpMessageHeader::decode(&bytes)?;
        assert_eq!(decoded.version(), SnmpVersion::V2c);
        assert_eq!(decoded.community(), &community);
        assert!(rest.is_empty());

        Ok(())
    }
}
