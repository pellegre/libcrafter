use std::net::{Ipv4Addr, Ipv6Addr};

use crafter::prelude::*;

const DOC_V4_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 81);
const DOC_V4_DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 81);
const DOC_V6_SRC: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x81, 0, 0, 0, 0, 1);
const DOC_V6_DST: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x81, 0, 0, 0, 0, 2);

fn truncated_sctp_payload(available: usize) -> Vec<u8> {
    (0..available).map(|byte| byte as u8).collect()
}

fn ipv4_sctp_raw(payload: &[u8]) -> crafter::Result<CompiledPacket> {
    (Ipv4::new()
        .src(DOC_V4_SRC)
        .dst(DOC_V4_DST)
        .ipv4_protocol(Ipv4Protocol::Sctp)
        / Raw::from_bytes(payload))
    .compile()
}

fn ipv6_sctp_raw(payload: &[u8]) -> crafter::Result<CompiledPacket> {
    (Ipv6::new().src(DOC_V6_SRC).dst(DOC_V6_DST).nh(IPPROTO_SCTP) / Raw::from_bytes(payload))
        .compile()
}

fn assert_sctp_common_header_error(error: CrafterError, available: usize) {
    assert_eq!(
        error,
        CrafterError::BufferTooShort {
            context: "sctp common header",
            required: SCTP_COMMON_HEADER_LEN,
            available,
        }
    );
}

fn sctp_payload(chunks: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(SCTP_COMMON_HEADER_LEN + chunks.len());
    payload.extend_from_slice(&12_000u16.to_be_bytes());
    payload.extend_from_slice(&12_001u16.to_be_bytes());
    payload.extend_from_slice(&0x1122_3344u32.to_be_bytes());
    payload.extend_from_slice(&0u32.to_be_bytes());
    payload.extend_from_slice(chunks);
    payload
}

#[test]
fn sctp_malformed_common_header_ipv4_errors_are_structured() -> crafter::Result<()> {
    for available in 0..SCTP_COMMON_HEADER_LEN {
        let payload = truncated_sctp_payload(available);
        let bytes = ipv4_sctp_raw(&payload)?;
        let error = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())
            .expect_err("truncated SCTP common header must fail over IPv4");

        assert_sctp_common_header_error(error, available);
    }

    Ok(())
}

#[test]
fn sctp_malformed_common_header_ipv6_errors_are_structured() -> crafter::Result<()> {
    for available in 0..SCTP_COMMON_HEADER_LEN {
        let payload = truncated_sctp_payload(available);
        let bytes = ipv6_sctp_raw(&payload)?;
        let error = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes())
            .expect_err("truncated SCTP common header must fail over IPv6");

        assert_sctp_common_header_error(error, available);
    }

    Ok(())
}

#[test]
fn sctp_malformed_common_header_shape_gate_rejects_truncated_payloads() {
    for available in 0..SCTP_COMMON_HEADER_LEN {
        let payload = truncated_sctp_payload(available);
        assert!(!looks_like_sctp_payload(&payload));
    }
}

#[test]
fn sctp_malformed_chunk_length_below_header_is_structured() -> crafter::Result<()> {
    let payload = sctp_payload(&[SCTP_CHUNK_TYPE_DATA, 0x00, 0x00, 0x03]);
    let bytes = ipv4_sctp_raw(&payload)?;
    let error = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())
        .expect_err("chunk length below header length must fail");

    assert_eq!(
        error,
        CrafterError::InvalidFieldValue {
            field: "sctp.chunk.length",
            reason: "declared length must be at least 4 bytes",
        }
    );

    Ok(())
}

#[test]
fn sctp_malformed_chunk_length_beyond_packet_is_structured() -> crafter::Result<()> {
    let payload = sctp_payload(&[
        SCTP_CHUNK_TYPE_DATA,
        0x00,
        0x00,
        0x0c,
        0xaa,
        0xbb,
        0xcc,
        0xdd,
    ]);
    let bytes = ipv4_sctp_raw(&payload)?;
    let error = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())
        .expect_err("chunk declared length beyond packet must fail");

    assert_eq!(
        error,
        CrafterError::BufferTooShort {
            context: "sctp.chunk",
            required: 12,
            available: 8,
        }
    );

    Ok(())
}

#[test]
fn sctp_malformed_chunk_length_missing_padding_is_structured() -> crafter::Result<()> {
    let payload = sctp_payload(&[SCTP_CHUNK_TYPE_DATA, 0x00, 0x00, 0x05, 0xaa]);
    let bytes = ipv4_sctp_raw(&payload)?;
    let error = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())
        .expect_err("chunk missing required padding must fail");

    assert_eq!(
        error,
        CrafterError::BufferTooShort {
            context: "sctp.chunk",
            required: 8,
            available: 5,
        }
    );

    Ok(())
}

#[test]
fn sctp_malformed_chunk_length_trailing_partial_chunk_is_structured() -> crafter::Result<()> {
    let payload = sctp_payload(&[SCTP_CHUNK_TYPE_COOKIE_ACK, 0x00, 0x00, 0x04, 0xff]);
    let bytes = ipv4_sctp_raw(&payload)?;
    let error = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())
        .expect_err("partial following chunk header must fail");

    assert_eq!(
        error,
        CrafterError::BufferTooShort {
            context: "sctp.chunk.header",
            required: SCTP_CHUNK_HEADER_LEN,
            available: 1,
        }
    );

    Ok(())
}

#[test]
fn sctp_malformed_parameter_length_below_header_is_structured() {
    let error = decode_parameters([0x00, 0x01, 0x00, 0x03])
        .expect_err("parameter length below header length must fail");

    assert_eq!(
        error,
        CrafterError::InvalidFieldValue {
            field: "sctp.parameter.length",
            reason: "declared length must be at least 4 bytes",
        }
    );
}

#[test]
fn sctp_malformed_parameter_length_value_truncation_is_structured() {
    let error = decode_parameters([0x00, 0x01, 0x00, 0x08, 0xaa])
        .expect_err("parameter declared value beyond available bytes must fail");

    assert_eq!(
        error,
        CrafterError::BufferTooShort {
            context: "sctp.parameter",
            required: 8,
            available: 5,
        }
    );
}

#[test]
fn sctp_malformed_parameter_length_trailing_partial_parameter_is_structured() {
    let error = decode_parameters([0x00, 0x01, 0x00, 0x04, 0xff])
        .expect_err("partial following parameter header must fail");

    assert_eq!(
        error,
        CrafterError::BufferTooShort {
            context: "sctp.parameter.header",
            required: SCTP_PARAMETER_HEADER_LEN,
            available: 1,
        }
    );
}

#[test]
fn sctp_malformed_parameter_length_nested_overrun_is_structured() -> crafter::Result<()> {
    let malformed_parameter = [0x00, 0x01, 0x00, 0x08, 0xaa];
    let mut chunk = vec![
        SCTP_CHUNK_TYPE_ASCONF,
        0x00,
        0x00,
        0x0d,
        0x11,
        0x22,
        0x33,
        0x44,
    ];
    chunk.extend_from_slice(&malformed_parameter);
    chunk.extend_from_slice(&[0x00, 0x00, 0x00]);

    let payload = sctp_payload(&chunk);
    let bytes = ipv4_sctp_raw(&payload)?;
    let error = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())
        .expect_err("nested ASCONF parameter overrun must fail");

    assert_eq!(
        error,
        CrafterError::BufferTooShort {
            context: "sctp.parameter",
            required: 8,
            available: 5,
        }
    );

    Ok(())
}
