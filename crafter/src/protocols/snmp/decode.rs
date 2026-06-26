//! SNMP decode scaffold.
//!
//! Source-gated by `.agents/docs/snmp-rfc-manifest.md`; UDP dispatch binding is added
//! in a later step.

use super::{ber, Snmp, SnmpVersion};
use crate::error::Result;
use crate::packet::Packet;

/// Append a decoded SNMP message to an existing packet stack.
pub(crate) fn append_snmp_packet(packet: Packet, bytes: &[u8]) -> Result<Packet> {
    Ok(packet.push(Snmp::decode(bytes)?))
}

/// Return true when bytes have enough SNMP wrapper structure for UDP dispatch.
///
/// The check is deliberately conservative so unrelated bytes on UDP/161 or
/// UDP/162 fall through to `Raw`: the payload must be one exact BER SEQUENCE,
/// start with an INTEGER version, and then carry either a community wrapper
/// (`OCTET STRING` plus one complete context-specific constructed PDU TLV) or
/// an SNMPv3 wrapper (`HeaderData`, `msgSecurityParameters`, and complete
/// plaintext/encrypted scoped data).
pub(crate) fn looks_like_snmp_payload(bytes: &[u8]) -> bool {
    let Ok(content) = ber::decode_sequence_exact(bytes) else {
        return false;
    };
    let Ok((version, rest)) = SnmpVersion::decode(content) else {
        return false;
    };

    if version == SnmpVersion::V3 {
        looks_like_v3_wrapper(rest)
    } else {
        looks_like_community_wrapper(rest)
    }
}

fn looks_like_community_wrapper(bytes: &[u8]) -> bool {
    let Some((community_tag, _, rest)) = decode_tlv(bytes) else {
        return false;
    };
    if community_tag != ber::BerTag::new(ber::BerClass::Universal, false, ber::BER_TAG_OCTET_STRING)
    {
        return false;
    }

    let Some((pdu_tag, _, rest)) = decode_tlv(rest) else {
        return false;
    };

    pdu_tag.class() == ber::BerClass::ContextSpecific && pdu_tag.is_constructed() && rest.is_empty()
}

fn looks_like_v3_wrapper(bytes: &[u8]) -> bool {
    let Some((global_tag, global_content, rest)) = decode_tlv(bytes) else {
        return false;
    };
    if global_tag != ber::BerTag::new(ber::BerClass::Universal, true, ber::BER_TAG_SEQUENCE) {
        return false;
    }
    if !looks_like_v3_global_data(global_content) {
        return false;
    }

    let Some((security_tag, _, rest)) = decode_tlv(rest) else {
        return false;
    };
    if security_tag != ber::BerTag::new(ber::BerClass::Universal, false, ber::BER_TAG_OCTET_STRING)
    {
        return false;
    }

    let Some((scoped_tag, _, rest)) = decode_tlv(rest) else {
        return false;
    };
    matches!(
        scoped_tag,
        tag if tag == ber::BerTag::new(ber::BerClass::Universal, true, ber::BER_TAG_SEQUENCE)
            || tag
                == ber::BerTag::new(
                    ber::BerClass::Universal,
                    false,
                    ber::BER_TAG_OCTET_STRING
                )
    ) && rest.is_empty()
}

fn looks_like_v3_global_data(bytes: &[u8]) -> bool {
    let Ok((_, rest)) = ber::decode_integer(bytes) else {
        return false;
    };
    let Ok((_, rest)) = ber::decode_integer(rest) else {
        return false;
    };
    let Some((flags_tag, _, rest)) = decode_tlv(rest) else {
        return false;
    };
    if flags_tag != ber::BerTag::new(ber::BerClass::Universal, false, ber::BER_TAG_OCTET_STRING) {
        return false;
    }
    let Ok((_, rest)) = ber::decode_integer(rest) else {
        return false;
    };

    rest.is_empty()
}

fn decode_tlv(bytes: &[u8]) -> Option<(ber::BerTag, &[u8], &[u8])> {
    let (tag, rest) = ber::decode_identifier(bytes).ok()?;
    let (length, rest) = ber::decode_length(rest).ok()?;
    if rest.len() < length {
        return None;
    }

    let (content, rest) = rest.split_at(length);
    Some((tag, content, rest))
}

#[cfg(test)]
mod tests {
    use super::looks_like_snmp_payload;
    use crate::protocols::snmp::registry;
    use crate::protocols::snmp::{Snmp, SnmpPdu, SnmpScopedPdu, SnmpVarBindList};
    use crate::Result;

    #[test]
    fn snmp_payload_detection_accepts_valid_v1_v2c_and_v3_wrappers() -> Result<()> {
        let v1 = Snmp::v1_get_request(b"public".to_vec(), 1, SnmpVarBindList::empty())?;
        let v2c =
            Snmp::v2c_get_bulk_request(b"public".to_vec(), 2, 0, 10, SnmpVarBindList::empty())?;
        let scoped = SnmpScopedPdu::new(
            Vec::<u8>::new(),
            Vec::<u8>::new(),
            SnmpPdu::get_request(3, SnmpVarBindList::empty())?,
        );
        let v3 = Snmp::v3_plaintext(
            3,
            1500,
            [0x00],
            registry::SNMP_SECURITY_MODEL_USM,
            Vec::<u8>::new(),
            scoped,
        )?;
        let encrypted_v3 = Snmp::v3(
            4,
            1500,
            [registry::SNMP_V3_FLAG_PRIVACY],
            registry::SNMP_SECURITY_MODEL_USM,
            Vec::<u8>::new(),
            [0x04, 0x03, 0xaa, 0xbb, 0xcc],
        );

        // Source-backed: .agents/docs/snmp-rfc-manifest.md records RFC 1157, RFC
        // 1901, and RFC 3412 message wrappers plus RFC 3417 BER restrictions.
        assert!(looks_like_snmp_payload(&v1.compile()?));
        assert!(looks_like_snmp_payload(&v2c.compile()?));
        assert!(looks_like_snmp_payload(&v3.compile()?));
        assert!(looks_like_snmp_payload(&encrypted_v3.compile()?));

        Ok(())
    }

    #[test]
    fn snmp_payload_detection_accepts_unknown_but_valid_wrappers() -> Result<()> {
        let unknown_version_and_pdu = [
            0x30, 0x0b, 0x02, 0x01, 0x04, 0x04, 0x01, b'x', 0xa9, 0x03, 0x02, 0x01, 0x05,
        ];
        let scoped = SnmpScopedPdu::new(
            Vec::<u8>::new(),
            Vec::<u8>::new(),
            SnmpPdu::get_request(5, SnmpVarBindList::empty())?,
        );
        let unknown_security_model_v3 =
            Snmp::v3_plaintext(5, 1500, [0x00], 999, [0xaa, 0xbb], scoped)?;

        assert!(looks_like_snmp_payload(&unknown_version_and_pdu));
        assert!(looks_like_snmp_payload(
            &unknown_security_model_v3.compile()?
        ));

        Ok(())
    }

    #[test]
    fn snmp_payload_detection_rejects_short_or_random_payloads() {
        let invalid_cases: &[&[u8]] = &[
            &[],
            &[0x30],
            &[0x30, 0x03, 0x02, 0x01, 0x00],
            b"not-snmp",
            &[0x30, 0x03, 0x04, 0x01, 0x00],
            &[0x30, 0x07, 0x02, 0x01, 0x00, 0x04, 0x00, 0x04, 0x01, 0x00],
            &[0x30, 0x08, 0x02, 0x01, 0x03, 0x30, 0x03, 0x02, 0x01, 0x01],
        ];

        for bytes in invalid_cases {
            assert!(!looks_like_snmp_payload(bytes), "{bytes:02x?}");
        }
    }

    #[test]
    fn snmp_payload_detection_rejects_otherwise_valid_wrapper_with_trailing_bytes() -> Result<()> {
        let mut bytes =
            Snmp::v1_get_request(b"public".to_vec(), 1, SnmpVarBindList::empty())?.compile()?;
        bytes.push(0xaa);

        assert!(!looks_like_snmp_payload(&bytes));

        Ok(())
    }
}
