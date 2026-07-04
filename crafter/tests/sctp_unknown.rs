use std::net::Ipv4Addr;

use crafter::prelude::*;

const DOC_V4_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 84);
const DOC_V4_DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 84);

#[test]
fn sctp_unknown_codepoints_chunks_flags_and_ppids_are_byte_preserving() -> crafter::Result<()> {
    let unknown_chunk_type = 0x81;
    let unknown_flags = 0xe5;
    let data_flags = SCTP_DATA_FLAG_BEGIN | SCTP_DATA_FLAG_END | 0xf0;
    let unassigned_ppid = 26;
    let unknown_chunk = SctpChunk::from_preserved_parts(
        unknown_chunk_type,
        unknown_flags,
        7,
        [0xde, 0xad, 0xbe],
        [0xcc],
    );
    let data_chunk =
        SctpDataChunk::from_data(0x0102_0304, 7, 9, unassigned_ppid, b"unknown-ppid".to_vec())
            .with_flags(data_flags);

    let packet = Ipv4::new().src(DOC_V4_SRC).dst(DOC_V4_DST)
        / Sctp::new()
            .sport(16_084)
            .dport(16_085)
            .vtag(0x1122_3384)
            .checksum(0)
            .chunk(unknown_chunk)
            .chunk(data_chunk);
    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let sctp = decoded.layer::<Sctp>().expect("SCTP layer");

    assert_eq!(sctp.checksum_value(), Some(0));
    assert_eq!(sctp.chunk_count(), 2);
    let SctpChunk::Unknown(unknown) = &sctp.chunks()[0] else {
        panic!("unknown chunk codepoint must remain an unknown chunk");
    };
    assert_eq!(unknown.chunk_type_value(), unknown_chunk_type);
    assert_eq!(unknown.chunk_type_status(), SctpChunkTypeStatus::Unknown);
    assert_eq!(unknown.chunk_type_name(), None);
    assert_eq!(unknown.flags(), unknown_flags);
    assert_eq!(unknown.active_flag_names(), Vec::<&str>::new());
    assert_eq!(unknown.unassigned_flag_bits(), unknown_flags);
    assert_eq!(unknown.explicit_declared_length(), Some(7));
    assert_eq!(unknown.value(), &[0xde, 0xad, 0xbe]);
    assert_eq!(unknown.padding(), &[0xcc]);

    let SctpChunk::Data(data) = &sctp.chunks()[1] else {
        panic!("DATA chunk must stay typed");
    };
    assert_eq!(data.flags(), data_flags);
    assert_eq!(data.unassigned_flag_bits(), 0xf0);
    assert_eq!(data.ppid()?, unassigned_ppid);
    assert_eq!(data.ppid_status()?, SctpPpidStatus::Unassigned);
    assert_eq!(data.ppid_name()?, None);
    assert_eq!(data.user_data()?, b"unknown-ppid");
    assert_eq!(decoded.compile()?.as_bytes(), compiled.as_bytes());

    Ok(())
}

#[test]
fn sctp_unknown_codepoints_parameter_action_bits_are_byte_preserving() -> crafter::Result<()> {
    let parameter_type = SctpParameterType::from_unknown_action_and_value_bits(
        SctpUnknownParameterAction::SkipAndReport,
        0x1234,
    )
    .raw();
    let parameter =
        SctpParameter::from_preserved_parts(parameter_type, 7, [0xaa, 0xbb, 0xcc], [0xdd]);
    let mut encoded = Vec::new();
    encode_parameters(&[parameter], &mut encoded)?;
    let decoded = decode_parameters(&encoded)?;

    assert_eq!(decoded.len(), 1);
    let SctpParameter::Unknown(unknown) = &decoded[0] else {
        panic!("unassigned parameter type must remain unknown");
    };
    assert_eq!(unknown.parameter_type_value(), parameter_type);
    assert_eq!(unknown.unknown_action_bits(), 0b11);
    assert_eq!(
        unknown.unknown_action(),
        SctpUnknownParameterAction::SkipAndReport
    );
    assert!(unknown.unknown_action().skips_parameter());
    assert!(unknown.unknown_action().reports_unrecognized_parameter());
    assert!(!unknown.unknown_action().stops_parameter_processing());
    assert_eq!(unknown.type_value_bits_without_unknown_action(), 0x1234);
    assert_eq!(unknown.explicit_declared_length(), Some(7));
    assert_eq!(unknown.value(), &[0xaa, 0xbb, 0xcc]);
    assert_eq!(unknown.padding(), &[0xdd]);

    let mut reencoded = Vec::new();
    encode_parameters(&decoded, &mut reencoded)?;
    assert_eq!(reencoded, encoded);

    Ok(())
}

#[test]
fn sctp_unknown_codepoints_causes_are_byte_preserving() -> crafter::Result<()> {
    let cause = SctpErrorCause::from_preserved_parts(0xbeef, 7, [0xde, 0xad, 0xbe], [0xcc]);
    let mut encoded = Vec::new();
    encode_causes(&[cause], &mut encoded)?;
    let decoded = decode_causes(&encoded)?;

    assert_eq!(decoded.len(), 1);
    let SctpErrorCause::Unknown(unknown) = &decoded[0] else {
        panic!("future cause codepoint must remain unknown");
    };
    assert_eq!(unknown.cause_code_value(), 0xbeef);
    assert_eq!(unknown.explicit_declared_length(), Some(7));
    assert_eq!(unknown.info(), &[0xde, 0xad, 0xbe]);
    assert_eq!(unknown.value(), &[0xde, 0xad, 0xbe]);
    assert_eq!(unknown.padding(), &[0xcc]);

    let mut reencoded = Vec::new();
    encode_causes(&decoded, &mut reencoded)?;
    assert_eq!(reencoded, encoded);

    Ok(())
}
