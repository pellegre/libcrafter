use std::net::Ipv4Addr;

use crafter::prelude::*;

const DOC_V4_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 85);
const DOC_V4_DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 85);

fn value_for_padding_len(expected_padding_len: usize, seed: u8) -> Vec<u8> {
    let value_len = match expected_padding_len {
        0 => 0,
        1 => 3,
        2 => 2,
        3 => 1,
        other => panic!("unexpected SCTP padding length {other}"),
    };
    (0..value_len).map(|offset| seed + offset as u8).collect()
}

#[test]
fn sctp_padding_roundtrip_chunks_cover_all_alignment_classes() -> crafter::Result<()> {
    let expected_padding = [0usize, 1, 2, 3];
    let chunks = expected_padding
        .iter()
        .enumerate()
        .map(|(index, padding_len)| {
            SctpChunk::unknown(
                0x81,
                index as u8,
                value_for_padding_len(*padding_len, 0xa0 + index as u8),
            )
        })
        .collect::<Vec<_>>();
    let packet = Ipv4::new().src(DOC_V4_SRC).dst(DOC_V4_DST)
        / Sctp::new()
            .sport(16_085)
            .dport(16_086)
            .vtag(0x1122_3385)
            .checksum(0)
            .with_chunks(chunks);
    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let sctp = decoded.layer::<Sctp>().expect("SCTP layer");

    assert_eq!(sctp.chunk_count(), expected_padding.len());
    for (chunk, expected_padding_len) in sctp.chunks().iter().zip(expected_padding) {
        let expected_padding_bytes = vec![0; expected_padding_len];
        assert_eq!(chunk.required_padding_len(), expected_padding_len);
        assert_eq!(chunk.encoded_padding_len(), expected_padding_len);
        assert_eq!(chunk.padding(), expected_padding_bytes.as_slice());
        assert_eq!(
            sctp_chunk_padding_len(chunk.declared_length()),
            expected_padding_len
        );
    }
    assert_eq!(decoded.compile()?.as_bytes(), compiled.as_bytes());

    Ok(())
}

#[test]
fn sctp_padding_roundtrip_parameters_cover_all_alignment_classes() -> crafter::Result<()> {
    let expected_padding = [0usize, 1, 2, 3];
    let parameters = expected_padding
        .iter()
        .enumerate()
        .map(|(index, padding_len)| {
            SctpParameter::unknown(
                0xd234 + index as u16,
                value_for_padding_len(*padding_len, 0xb0 + index as u8),
            )
        })
        .collect::<Vec<_>>();
    let mut encoded = Vec::new();
    encode_parameters(&parameters, &mut encoded)?;
    let decoded = decode_parameters(&encoded)?;

    assert_eq!(decoded.len(), expected_padding.len());
    for (parameter, expected_padding_len) in decoded.iter().zip(expected_padding) {
        let expected_padding_bytes = vec![0; expected_padding_len];
        assert_eq!(parameter.required_padding_len(), expected_padding_len);
        assert_eq!(parameter.encoded_padding_len(), expected_padding_len);
        assert_eq!(parameter.padding(), expected_padding_bytes.as_slice());
        assert_eq!(
            sctp_parameter_padding_len(parameter.declared_length()),
            expected_padding_len
        );
    }

    let mut reencoded = Vec::new();
    encode_parameters(&decoded, &mut reencoded)?;
    assert_eq!(reencoded, encoded);

    Ok(())
}

#[test]
fn sctp_padding_roundtrip_causes_cover_all_alignment_classes() -> crafter::Result<()> {
    let expected_padding = [0usize, 1, 2, 3];
    let causes = expected_padding
        .iter()
        .enumerate()
        .map(|(index, padding_len)| {
            SctpErrorCause::unknown(
                0xbe00 + index as u16,
                value_for_padding_len(*padding_len, 0xc0 + index as u8),
            )
        })
        .collect::<Vec<_>>();
    let mut encoded = Vec::new();
    encode_causes(&causes, &mut encoded)?;
    let decoded = decode_causes(&encoded)?;

    assert_eq!(decoded.len(), expected_padding.len());
    for (cause, expected_padding_len) in decoded.iter().zip(expected_padding) {
        let expected_padding_bytes = vec![0; expected_padding_len];
        assert_eq!(cause.required_padding_len(), expected_padding_len);
        assert_eq!(cause.encoded_padding_len(), expected_padding_len);
        assert_eq!(cause.padding(), expected_padding_bytes.as_slice());
        assert_eq!(
            sctp_error_cause_padding_len(cause.declared_length()),
            expected_padding_len
        );
    }

    let mut reencoded = Vec::new();
    encode_causes(&decoded, &mut reencoded)?;
    assert_eq!(reencoded, encoded);

    Ok(())
}
