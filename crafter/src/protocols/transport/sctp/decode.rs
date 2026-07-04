//! SCTP packet splitting and registry-driven decode.

#![allow(dead_code)]

use crate::error::{CrafterError, Result};
use crate::packet::Packet;
use crate::registry::ProtocolRegistry;

use super::checksum::{decoded_sctp_checksum_status, SctpChecksumStatus};
use super::chunk::decode_chunks;
use super::constants::{
    SCTP_CHUNK_HEADER_LEN, SCTP_COMMON_HEADER_LEN, SCTP_UDP_ENCAPSULATION_PORT,
};
use super::packet::Sctp;

/// Append a decoded SCTP packet using an explicit registry.
pub(crate) fn append_sctp_packet_with_registry(
    registry: &ProtocolRegistry,
    packet: Packet,
    bytes: &[u8],
) -> Result<Packet> {
    let decoded = decode_sctp_parts(bytes, registry.validates_checksums())?;
    Ok(packet.push_sctp(decoded.sctp))
}

/// Return true when bytes are structurally decodable as an SCTP packet.
///
/// This helper is intentionally shape-only: it requires the fixed common header
/// plus at least one valid SCTP chunk envelope, but it does not require a valid
/// CRC32c because checksum status is inspectable decode output.
pub fn looks_like_sctp_payload(bytes: &[u8]) -> bool {
    if bytes.len() < SCTP_COMMON_HEADER_LEN + SCTP_CHUNK_HEADER_LEN {
        return false;
    }

    match decode_sctp_parts(bytes, false) {
        Ok(decoded) => !decoded.sctp.is_chunks_empty(),
        Err(_) => false,
    }
}

/// Return true when a UDP datagram is eligible for RFC 6951 SCTP encapsulation.
pub fn looks_like_udp_encapsulated_sctp_payload(
    source_port: u16,
    destination_port: u16,
    bytes: &[u8],
) -> bool {
    (source_port == SCTP_UDP_ENCAPSULATION_PORT || destination_port == SCTP_UDP_ENCAPSULATION_PORT)
        && looks_like_sctp_payload(bytes)
}

/// Compatibility spelling for the RFC 6951 SCTP-over-UDP shape gate.
pub fn looks_like_sctp_udp_encapsulation(
    source_port: u16,
    destination_port: u16,
    bytes: &[u8],
) -> bool {
    looks_like_udp_encapsulated_sctp_payload(source_port, destination_port, bytes)
}

struct DecodedSctpPacket {
    sctp: Sctp,
}

fn decode_sctp_parts(bytes: &[u8], validate_checksum: bool) -> Result<DecodedSctpPacket> {
    if bytes.len() < SCTP_COMMON_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "sctp common header",
            SCTP_COMMON_HEADER_LEN,
            bytes.len(),
        ));
    }

    let source_port = u16::from_be_bytes([bytes[0], bytes[1]]);
    let destination_port = u16::from_be_bytes([bytes[2], bytes[3]]);
    let verification_tag = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let checksum = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let chunks = decode_chunks(&bytes[SCTP_COMMON_HEADER_LEN..])?;
    let checksum_status = if validate_checksum {
        decoded_sctp_checksum_status(bytes)?
    } else {
        SctpChecksumStatus::NotChecked
    };

    Ok(DecodedSctpPacket {
        sctp: Sctp::from_decoded_parts_with_chunks_and_checksum_status(
            source_port,
            destination_port,
            verification_tag,
            checksum,
            chunks,
            checksum_status,
        ),
    })
}

#[cfg(test)]
mod tests {
    use crate::error::CrafterError;
    use crate::packet::Packet;
    use crate::registry::ProtocolRegistry;

    use super::super::checksum::SctpChecksumStatus;
    use super::super::chunk::{SctpChunk, SctpDataChunk};
    use super::super::constants::{
        SCTP_CHECKSUM_LEN, SCTP_CHECKSUM_OFFSET, SCTP_CHUNK_TYPE_DATA,
        SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_4, SCTP_COMMON_HEADER_LEN,
    };
    use super::super::packet::Sctp;
    use super::*;

    fn read_checksum(bytes: &[u8]) -> u32 {
        u32::from_be_bytes([
            bytes[SCTP_CHECKSUM_OFFSET],
            bytes[SCTP_CHECKSUM_OFFSET + 1],
            bytes[SCTP_CHECKSUM_OFFSET + 2],
            bytes[SCTP_CHECKSUM_OFFSET + 3],
        ])
    }

    #[test]
    fn sctp_append_decoder_materializes_common_header_chunks_and_checksum_status() -> Result<()> {
        let compiled = Packet::from_layer(
            Sctp::new()
                .sport(12_000)
                .dport(12_001)
                .vtag(0x1122_3344)
                .chunk(SctpDataChunk::from_data(1, 2, 3, 4, b"payload".to_vec())),
        )
        .compile()?;

        let decoded = append_sctp_packet_with_registry(
            &ProtocolRegistry::new(),
            Packet::new(),
            compiled.as_bytes(),
        )?;
        let sctp = decoded.layer::<Sctp>().expect("decoded SCTP layer");

        assert_eq!(sctp.source_port_value(), 12_000);
        assert_eq!(sctp.destination_port_value(), 12_001);
        assert_eq!(sctp.verification_tag_value(), 0x1122_3344);
        assert_eq!(
            sctp.checksum_value(),
            Some(read_checksum(compiled.as_bytes()))
        );
        assert_eq!(sctp.checksum_status(), SctpChecksumStatus::Valid);
        assert_eq!(sctp.chunk_count(), 1);
        let SctpChunk::Data(data) = &sctp.chunks()[0] else {
            panic!("expected DATA chunk");
        };
        assert_eq!(data.user_data()?, b"payload");
        assert!(decoded.summary().contains("checksum_status=valid"));
        Ok(())
    }

    #[test]
    fn sctp_append_decoder_preserves_valid_unknown_chunks() -> Result<()> {
        let compiled = Packet::from_layer(Sctp::new().chunk(SctpChunk::unknown(
            SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_4,
            0xa0,
            [0xde, 0xad],
        )))
        .compile()?;

        let decoded = append_sctp_packet_with_registry(
            &ProtocolRegistry::new(),
            Packet::new(),
            compiled.as_bytes(),
        )?;
        let sctp = decoded.layer::<Sctp>().expect("decoded SCTP layer");

        assert_eq!(sctp.chunk_count(), 1);
        let SctpChunk::Unknown(unknown) = &sctp.chunks()[0] else {
            panic!("expected UNKNOWN chunk");
        };
        assert_eq!(
            unknown.chunk_type_value(),
            SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_4
        );
        assert_eq!(unknown.flags(), 0xa0);
        assert_eq!(unknown.value(), &[0xde, 0xad]);
        assert_eq!(unknown.padding(), &[0x00, 0x00]);
        Ok(())
    }

    #[test]
    fn sctp_append_decoder_can_skip_checksum_validation() -> Result<()> {
        let compiled = Packet::from_layer(Sctp::new().chunk(SctpDataChunk::from_data(
            1,
            2,
            3,
            4,
            b"payload".to_vec(),
        )))
        .compile()?;
        let registry = ProtocolRegistry::new().checksum_validation(false);

        let decoded =
            append_sctp_packet_with_registry(&registry, Packet::new(), compiled.as_bytes())?;
        let sctp = decoded.layer::<Sctp>().expect("decoded SCTP layer");

        assert_eq!(sctp.checksum_status(), SctpChecksumStatus::NotChecked);
        assert!(!decoded.summary().contains("checksum_status="));
        Ok(())
    }

    #[test]
    fn sctp_append_decoder_reports_invalid_nonzero_checksum_without_dropping_layer() -> Result<()> {
        let compiled = Packet::from_layer(Sctp::new()).compile()?;
        let mut bytes = compiled.as_bytes().to_vec();
        let mut bad_checksum = read_checksum(compiled.as_bytes()) ^ 0xffff_ffff;
        if bad_checksum == 0 {
            bad_checksum = 1;
        }
        bytes[SCTP_CHECKSUM_OFFSET..SCTP_CHECKSUM_OFFSET + SCTP_CHECKSUM_LEN]
            .copy_from_slice(&bad_checksum.to_be_bytes());

        let decoded =
            append_sctp_packet_with_registry(&ProtocolRegistry::new(), Packet::new(), &bytes)?;
        let sctp = decoded.layer::<Sctp>().expect("decoded SCTP layer");

        assert_eq!(sctp.checksum_value(), Some(bad_checksum));
        assert_eq!(sctp.checksum_status(), SctpChecksumStatus::Invalid);
        Ok(())
    }

    #[test]
    fn sctp_append_decoder_rejects_short_common_header() {
        let short = [0u8; SCTP_COMMON_HEADER_LEN - 1];
        let err = append_sctp_packet_with_registry(&ProtocolRegistry::new(), Packet::new(), &short)
            .unwrap_err();

        assert_eq!(
            err,
            CrafterError::BufferTooShort {
                context: "sctp common header",
                required: SCTP_COMMON_HEADER_LEN,
                available: short.len(),
            }
        );
    }

    #[test]
    fn sctp_udp_encap_shape_accepts_only_port_9899_structural_sctp() -> Result<()> {
        let compiled = Packet::from_layer(Sctp::new().chunk(SctpDataChunk::from_data(
            1,
            2,
            3,
            4,
            b"payload".to_vec(),
        )))
        .compile()?;
        let sctp = compiled.as_bytes();

        assert!(looks_like_sctp_payload(sctp));
        assert!(looks_like_udp_encapsulated_sctp_payload(
            SCTP_UDP_ENCAPSULATION_PORT,
            49_152,
            sctp
        ));
        assert!(looks_like_sctp_udp_encapsulation(
            49_152,
            SCTP_UDP_ENCAPSULATION_PORT,
            sctp
        ));
        assert!(!looks_like_udp_encapsulated_sctp_payload(
            49_152, 49_153, sctp
        ));

        let header_only = Packet::from_layer(Sctp::new()).compile()?;
        assert!(!looks_like_sctp_payload(header_only.as_bytes()));
        assert!(!looks_like_udp_encapsulated_sctp_payload(
            SCTP_UDP_ENCAPSULATION_PORT,
            49_152,
            header_only.as_bytes()
        ));

        let unrelated = b"not an sctp packet";
        assert!(!looks_like_udp_encapsulated_sctp_payload(
            SCTP_UDP_ENCAPSULATION_PORT,
            49_152,
            unrelated
        ));

        let mut truncated_chunk = vec![0u8; SCTP_COMMON_HEADER_LEN];
        truncated_chunk.extend_from_slice(&[SCTP_CHUNK_TYPE_DATA, 0x00, 0x00]);
        assert!(!looks_like_udp_encapsulated_sctp_payload(
            SCTP_UDP_ENCAPSULATION_PORT,
            49_152,
            &truncated_chunk
        ));

        Ok(())
    }
}
