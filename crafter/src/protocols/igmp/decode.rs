//! IGMP decode helpers.
//!
//! Later decode steps should type supported messages and preserve unsupported
//! IGMP payload bytes as raw data where possible.

use core::net::Ipv4Addr;

use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{Packet, Raw};

use super::constants::IGMP_FIXED_HEADER_LEN;
use super::message::Igmp;

/// Append a decoded IGMP packet to an existing packet stack.
///
/// This bootstrap decoder always recovers the fixed IGMP header and preserves
/// any remaining bytes as a single [`Raw`] tail. Later typed-body decoders can
/// dispatch on the Type value before falling back to the same raw policy.
pub(crate) fn append_igmp_packet(mut packet: Packet, bytes: &[u8]) -> Result<Packet> {
    let (igmp, payload) = decode_igmp_parts(bytes)?;
    packet = packet.push(igmp);

    if !payload.is_empty() {
        packet = packet.push_raw(Raw::from_bytes(payload));
    }

    Ok(packet)
}

fn decode_igmp_parts(bytes: &[u8]) -> Result<(Igmp, &[u8])> {
    if bytes.len() < IGMP_FIXED_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "igmp header",
            IGMP_FIXED_HEADER_LEN,
            bytes.len(),
        ));
    }

    let igmp = Igmp {
        igmp_type: Field::user(bytes[0]),
        code: Field::user(bytes[1]),
        checksum: Field::user(u16::from_be_bytes([bytes[2], bytes[3]])),
        group_address: Field::user(Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7])),
    };

    Ok((igmp, &bytes[IGMP_FIXED_HEADER_LEN..]))
}

#[cfg(test)]
mod igmp_unknown_raw {
    use super::*;
    use crate::error::CrafterError;
    use crate::field::FieldState;
    use crate::protocols::igmp::constants::{
        IGMP_TYPE_DVMRP, IGMP_TYPE_MEMBERSHIP_QUERY, IGMP_TYPE_UNASSIGNED_FIRST,
    };
    use crate::protocols::igmp::registry::{IgmpType, IgmpTypeStatus};

    #[test]
    fn unsupported_registered_type_preserves_raw_payload() {
        let bytes = [
            IGMP_TYPE_DVMRP,
            0x07,
            0x12,
            0x34,
            224,
            0,
            0,
            251,
            0xde,
            0xad,
            0xbe,
            0xef,
        ];

        let decoded = append_igmp_packet(Packet::new(), &bytes).expect("decode DVMRP as IGMP raw");
        let igmp = decoded.layer::<Igmp>().expect("typed IGMP header");
        let raw = decoded.layer::<Raw>().expect("raw unsupported body");

        assert_eq!(igmp.igmp_type_value(), IGMP_TYPE_DVMRP);
        assert_eq!(igmp.igmp_type(), IgmpType::Dvmrp);
        assert_eq!(igmp.type_meta().status, IgmpTypeStatus::UnsupportedAssigned);
        assert_eq!(igmp.code_value(), 0x07);
        assert_eq!(igmp.checksum_value(), Some(0x1234));
        assert_eq!(igmp.group_address_value(), Ipv4Addr::new(224, 0, 0, 251));
        assert_eq!(igmp.igmp_type_state(), FieldState::User);
        assert_eq!(igmp.code_state(), FieldState::User);
        assert_eq!(igmp.checksum_state(), FieldState::User);
        assert_eq!(igmp.group_address_state(), FieldState::User);
        assert_eq!(raw.as_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(decoded.compile().expect("roundtrip").as_bytes(), &bytes);
    }

    #[test]
    fn unassigned_type_preserves_raw_payload() {
        let bytes = [
            IGMP_TYPE_UNASSIGNED_FIRST,
            0xaa,
            0x00,
            0x00,
            239,
            1,
            2,
            3,
            0x01,
            0x02,
            0x03,
        ];

        let decoded =
            append_igmp_packet(Packet::new(), &bytes).expect("decode unassigned IGMP as raw");
        let igmp = decoded.layer::<Igmp>().expect("typed IGMP header");
        let raw = decoded.layer::<Raw>().expect("raw unsupported body");

        assert_eq!(
            igmp.igmp_type(),
            IgmpType::Unassigned(IGMP_TYPE_UNASSIGNED_FIRST)
        );
        assert_eq!(igmp.type_meta().status, IgmpTypeStatus::Unassigned);
        assert_eq!(raw.as_bytes(), &[0x01, 0x02, 0x03]);
        assert_eq!(decoded.compile().expect("roundtrip").as_bytes(), &bytes);
    }

    #[test]
    fn valid_fixed_header_without_payload_does_not_synthesize_raw() {
        let bytes = [
            IGMP_TYPE_MEMBERSHIP_QUERY,
            0x00,
            0xee,
            0xff,
            0,
            0,
            0,
            0,
        ];

        let decoded = append_igmp_packet(Packet::new(), &bytes).expect("decode fixed header");

        assert!(decoded.layer::<Igmp>().is_some());
        assert!(decoded.layer::<Raw>().is_none());
        assert_eq!(decoded.compile().expect("roundtrip").as_bytes(), &bytes);
    }

    #[test]
    fn short_header_returns_structured_error() {
        let err =
            append_igmp_packet(Packet::new(), &[IGMP_TYPE_MEMBERSHIP_QUERY, 0, 0]).unwrap_err();

        assert_eq!(
            err,
            CrafterError::buffer_too_short("igmp header", IGMP_FIXED_HEADER_LEN, 3)
        );
    }
}
