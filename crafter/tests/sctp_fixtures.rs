#[macro_use]
mod support;

use std::net::{Ipv4Addr, Ipv6Addr};

use crafter::prelude::*;

const DOC_V4_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 86);
const DOC_V4_DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 86);
const INIT_ACK_DOC_V4_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 87);
const INIT_ACK_DOC_V4_DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 87);
const DATA_DOC_V4_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 88);
const DATA_DOC_V4_DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 88);
const SACK_DOC_V4_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 89);
const SACK_DOC_V4_DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 89);
const CONTROL_DOC_V4_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 90);
const CONTROL_DOC_V4_DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 90);
const DOC_V6_SRC: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x86, 0, 0, 0, 0, 1);
const DOC_V6_DST: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x86, 0, 0, 0, 0, 2);
const INIT_ACK_STATE_COOKIE: [u8; 6] = [0x87, 0x00, 0xca, 0xfe, 0xde, 0xad];

fn decode_hex_fixture(label: &str, text: &str) -> Vec<u8> {
    text.split_whitespace()
        .map(|byte| {
            u8::from_str_radix(byte, 16)
                .unwrap_or_else(|_| panic!("hex fixture {label} has invalid byte {byte:?}"))
        })
        .collect()
}

fn sctp_init_fixture_layer() -> Sctp {
    Sctp::init(0x1122_3386, 65_535, 10, 10, 0x0102_0386)
        .sport(16_086)
        .dport(16_087)
        .vtag(0)
}

fn ipv4_sctp_init_fixture_packet() -> Packet {
    Ipv4::new()
        .src(DOC_V4_SRC)
        .dst(DOC_V4_DST)
        .id(0x5086)
        .ttl(64)
        / sctp_init_fixture_layer()
}

fn ipv6_sctp_init_fixture_packet() -> Packet {
    Ipv6::new().src(DOC_V6_SRC).dst(DOC_V6_DST).hlim(64) / sctp_init_fixture_layer()
}

fn init_ack_parameter_bytes() -> crafter::Result<Vec<u8>> {
    let parameters = vec![
        SctpParameter::from(SctpStateCookieParameter::from_cookie(INIT_ACK_STATE_COOKIE)),
        SctpParameter::from(SctpSupportedExtensionsParameter::from_chunk_type_values([
            SCTP_CHUNK_TYPE_ASCONF,
            SCTP_CHUNK_TYPE_ASCONF_ACK,
            SCTP_CHUNK_TYPE_AUTH,
            SCTP_CHUNK_TYPE_FORWARD_TSN,
        ])),
    ];
    let mut bytes = Vec::new();

    encode_parameters(&parameters, &mut bytes)?;
    Ok(bytes)
}

fn sctp_init_ack_fixture_layer() -> crafter::Result<Sctp> {
    Ok(Sctp::new()
        .sport(17_087)
        .dport(17_088)
        .vtag(0x1122_3387)
        .chunk(SctpInitAckChunk::from_init_ack_with_parameters(
            0x5566_7787,
            0x0002_0000,
            20,
            20,
            0x0102_0387,
            init_ack_parameter_bytes()?,
        )))
}

fn ipv4_sctp_init_ack_fixture_packet() -> crafter::Result<Packet> {
    Ok(Ipv4::new()
        .src(INIT_ACK_DOC_V4_SRC)
        .dst(INIT_ACK_DOC_V4_DST)
        .id(0x5087)
        .ttl(64)
        / sctp_init_ack_fixture_layer()?)
}

fn sctp_data_fixture_layer() -> Sctp {
    let data_flags = SCTP_DATA_FLAG_BEGIN
        | SCTP_DATA_FLAG_END
        | SCTP_DATA_FLAG_UNORDERED
        | SCTP_DATA_FLAG_SACK_IMMEDIATELY;
    let idata_flags =
        SCTP_IDATA_FLAG_BEGIN | SCTP_IDATA_FLAG_END | SCTP_IDATA_FLAG_SACK_IMMEDIATELY;

    Sctp::new()
        .sport(18_088)
        .dport(18_089)
        .vtag(0x1122_3388)
        .chunk(SctpDataChunk::from_data_parts(
            data_flags,
            0x0102_0388,
            0x0012,
            0x0034,
            SCTP_PPID_WEBRTC_STRING,
            b"abc".to_vec(),
        ))
        .chunk(SctpIDataChunk::from_idata_parts(
            idata_flags,
            0x0506_0788,
            0x0044,
            0,
            0x1020_3088,
            SCTP_PPID_WEBRTC_BINARY,
            [],
        ))
}

fn ipv4_sctp_data_fixture_packet() -> Packet {
    Ipv4::new()
        .src(DATA_DOC_V4_SRC)
        .dst(DATA_DOC_V4_DST)
        .id(0x5088)
        .ttl(64)
        / sctp_data_fixture_layer()
}

fn sctp_sack_fixture_layer() -> crafter::Result<Sctp> {
    Ok(Sctp::sack(
        0x1122_3389,
        0x0003_0000,
        [
            SctpSackGapAckBlock::new(1, 3),
            SctpSackGapAckBlock::new(7, 9),
        ],
        [0x0102_0389, 0x0506_0789],
    )?
    .sport(19_089)
    .dport(19_090)
    .vtag(0x1122_3389))
}

fn ipv4_sctp_sack_fixture_packet() -> crafter::Result<Packet> {
    Ok(Ipv4::new()
        .src(SACK_DOC_V4_SRC)
        .dst(SACK_DOC_V4_DST)
        .id(0x5089)
        .ttl(64)
        / sctp_sack_fixture_layer()?)
}

fn sctp_control_fixture_layer() -> crafter::Result<Sctp> {
    let abort_causes = [SctpErrorCause::unknown(0xbeef, [])];
    let error_causes = [SctpErrorCause::unknown(0xbeef, [])];
    let asconf_sender =
        SctpParameter::from(SctpIpv4AddressParameter::from_address(CONTROL_DOC_V4_SRC));
    let asconf_request = SctpParameter::from(
        SctpAddIpAddressParameter::from_correlation_id_and_ipv4_address(
            0x0102_0390,
            CONTROL_DOC_V4_DST,
        ),
    );
    let asconf_response = SctpParameter::from(
        SctpSuccessIndicationParameter::from_response_correlation_id(0x0102_0390),
    );
    let reconfig_response = SctpParameter::from(
        SctpReConfigurationResponseParameter::from_response_sequence_number_and_result_value(
            0x0102_0390,
            1,
        ),
    );

    Ok(Sctp::new()
        .sport(20_090)
        .dport(20_091)
        .vtag(0x1122_3390)
        .chunk(SctpHeartbeatChunk::try_from_heartbeat_info([0x90, 0x01])?)
        .chunk(SctpHeartbeatAckChunk::try_from_heartbeat_info([
            0x90, 0x02, 0x03, 0x04,
        ])?)
        .chunk(SctpAbortChunk::try_from_error_causes(&abort_causes)?.t_bit())
        .chunk(SctpErrorChunk::try_from_error_causes(&error_causes)?)
        .chunk(SctpCookieEchoChunk::from_cookie([0x90, 0xca, 0xfe]))
        .chunk(SctpCookieAckChunk::cookie_ack())
        .chunk(SctpAuthChunk::from_auth(
            SctpSharedKeyIdentifier::from_u16(0x0190),
            SctpHmacIdentifier::Sha256,
            [0xaa, 0xbb, 0xcc],
        ))
        .chunk(SctpAsconfChunk::try_from_asconf(
            0x1122_3390,
            asconf_sender,
            &[asconf_request],
        )?)
        .chunk(SctpAsconfAckChunk::try_from_asconf_ack(
            0x1122_3390,
            &[asconf_response],
        )?)
        .chunk(SctpReConfigChunk::try_from_reconfig(&[reconfig_response])?)
        .chunk(SctpForwardTsnChunk::from_forward_tsn(
            0x0102_0390,
            &[SctpForwardTsnSkippedStreamSequence::new(1, 2)],
        ))
        .chunk(SctpIForwardTsnChunk::from_iforward_tsn(
            0x0102_0391,
            &[SctpIForwardTsnSkippedStream::unordered(3, 0x0102_0392)],
        ))
        .chunk(SctpPadChunk::from_padding_data([0x90, 0x91, 0x92])))
}

fn ipv4_sctp_control_fixture_packet() -> crafter::Result<Packet> {
    Ok(Ipv4::new()
        .src(CONTROL_DOC_V4_SRC)
        .dst(CONTROL_DOC_V4_DST)
        .id(0x5090)
        .ttl(64)
        / sctp_control_fixture_layer()?)
}

fn assert_decoded_sctp_init(decoded: &Packet) -> crafter::Result<()> {
    let sctp = decoded.layer::<Sctp>().expect("SCTP layer");

    assert_eq!(sctp.source_port_value(), 16_086);
    assert_eq!(sctp.destination_port_value(), 16_087);
    assert_eq!(sctp.verification_tag_value(), 0);
    assert_eq!(sctp.checksum_status(), SctpChecksumStatus::Valid);
    assert_eq!(sctp.chunk_count(), 1);

    let SctpChunk::Init(init) = &sctp.chunks()[0] else {
        panic!("expected INIT chunk");
    };

    assert_eq!(init.initiate_tag()?, 0x1122_3386);
    assert_eq!(init.a_rwnd()?, 65_535);
    assert_eq!(init.outbound_streams()?, 10);
    assert_eq!(init.inbound_streams()?, 10);
    assert_eq!(init.initial_tsn()?, 0x0102_0386);
    assert_eq!(init.parameters()?, &[]);

    Ok(())
}

fn assert_decoded_sctp_init_ack(decoded: &Packet) -> crafter::Result<()> {
    let sctp = decoded.layer::<Sctp>().expect("SCTP layer");

    assert_eq!(sctp.source_port_value(), 17_087);
    assert_eq!(sctp.destination_port_value(), 17_088);
    assert_eq!(sctp.verification_tag_value(), 0x1122_3387);
    assert_eq!(sctp.checksum_status(), SctpChecksumStatus::Valid);
    assert_eq!(sctp.chunk_count(), 1);

    let SctpChunk::InitAck(init_ack) = &sctp.chunks()[0] else {
        panic!("expected INIT ACK chunk");
    };

    assert_eq!(init_ack.initiate_tag()?, 0x5566_7787);
    assert_eq!(init_ack.a_rwnd()?, 0x0002_0000);
    assert_eq!(init_ack.outbound_streams()?, 20);
    assert_eq!(init_ack.inbound_streams()?, 20);
    assert_eq!(init_ack.initial_tsn()?, 0x0102_0387);
    assert_eq!(
        init_ack.parameters()?,
        init_ack_parameter_bytes()?.as_slice()
    );

    let parameters = decode_parameters(init_ack.parameters()?)?;
    assert_eq!(parameters.len(), 2);

    let SctpParameter::StateCookie(cookie) = &parameters[0] else {
        panic!("expected State Cookie parameter");
    };
    assert_eq!(cookie.cookie(), INIT_ACK_STATE_COOKIE);
    assert_eq!(cookie.padding(), &[0x00, 0x00]);

    let SctpParameter::SupportedExtensions(extensions) = &parameters[1] else {
        panic!("expected Supported Extensions parameter");
    };
    assert_eq!(
        extensions.chunk_type_values(),
        vec![
            SCTP_CHUNK_TYPE_ASCONF,
            SCTP_CHUNK_TYPE_ASCONF_ACK,
            SCTP_CHUNK_TYPE_AUTH,
            SCTP_CHUNK_TYPE_FORWARD_TSN,
        ]
    );
    assert!(extensions.supports_asconf());
    assert!(extensions.supports_asconf_ack());
    assert!(extensions.supports_auth());
    assert!(extensions.supports_forward_tsn_chunk());
    assert_eq!(extensions.padding(), &[]);

    Ok(())
}

fn assert_decoded_sctp_data(decoded: &Packet) -> crafter::Result<()> {
    let sctp = decoded.layer::<Sctp>().expect("SCTP layer");

    assert_eq!(sctp.source_port_value(), 18_088);
    assert_eq!(sctp.destination_port_value(), 18_089);
    assert_eq!(sctp.verification_tag_value(), 0x1122_3388);
    assert_eq!(sctp.checksum_status(), SctpChecksumStatus::Valid);
    assert_eq!(sctp.chunk_count(), 2);

    let SctpChunk::Data(data) = &sctp.chunks()[0] else {
        panic!("expected DATA chunk");
    };
    assert_eq!(
        data.flags(),
        SCTP_DATA_FLAG_BEGIN
            | SCTP_DATA_FLAG_END
            | SCTP_DATA_FLAG_UNORDERED
            | SCTP_DATA_FLAG_SACK_IMMEDIATELY
    );
    assert_eq!(data.tsn()?, 0x0102_0388);
    assert_eq!(data.stream_id()?, 0x0012);
    assert_eq!(data.stream_sequence_number()?, 0x0034);
    assert_eq!(data.ppid()?, SCTP_PPID_WEBRTC_STRING);
    assert_eq!(data.ppid_status()?, SctpPpidStatus::Assigned);
    assert_eq!(data.ppid_name()?, Some("WebRTC String"));
    assert_eq!(data.user_data()?, b"abc");
    assert_eq!(data.padding(), &[0x00]);

    let SctpChunk::IData(idata) = &sctp.chunks()[1] else {
        panic!("expected I-DATA chunk");
    };
    assert_eq!(
        idata.flags(),
        SCTP_IDATA_FLAG_BEGIN | SCTP_IDATA_FLAG_END | SCTP_IDATA_FLAG_SACK_IMMEDIATELY
    );
    assert!(idata.is_begin());
    assert!(idata.is_end());
    assert!(!idata.is_unordered());
    assert!(idata.is_sack_immediately());
    assert_eq!(idata.tsn()?, 0x0506_0788);
    assert_eq!(idata.stream_id()?, 0x0044);
    assert_eq!(idata.reserved()?, 0);
    assert_eq!(idata.message_id()?, 0x1020_3088);
    assert_eq!(idata.ppid_fsn()?, SCTP_PPID_WEBRTC_BINARY);
    assert_eq!(idata.ppid()?, Some(SCTP_PPID_WEBRTC_BINARY));
    assert_eq!(idata.ppid_status()?, Some(SctpPpidStatus::Assigned));
    assert_eq!(idata.ppid_name()?, Some("WebRTC Binary"));
    assert_eq!(idata.fsn()?, None);
    assert_eq!(idata.user_data()?, &[]);
    assert_eq!(idata.padding(), &[]);

    Ok(())
}

fn assert_decoded_sctp_sack(decoded: &Packet) -> crafter::Result<()> {
    let sctp = decoded.layer::<Sctp>().expect("SCTP layer");

    assert_eq!(sctp.source_port_value(), 19_089);
    assert_eq!(sctp.destination_port_value(), 19_090);
    assert_eq!(sctp.verification_tag_value(), 0x1122_3389);
    assert_eq!(sctp.checksum_status(), SctpChecksumStatus::Valid);
    assert_eq!(sctp.chunk_count(), 1);

    let SctpChunk::Sack(sack) = &sctp.chunks()[0] else {
        panic!("expected SACK chunk");
    };

    assert_eq!(sack.flags(), 0);
    assert_eq!(sack.cumulative_tsn_ack()?, 0x1122_3389);
    assert_eq!(sack.a_rwnd()?, 0x0003_0000);
    assert_eq!(sack.gap_ack_block_count()?, 2);
    assert_eq!(sack.duplicate_tsn_count()?, 2);
    assert_eq!(
        sack.gap_ack_blocks()?,
        [
            SctpSackGapAckBlock::new(1, 3),
            SctpSackGapAckBlock::new(7, 9)
        ]
    );
    assert_eq!(sack.duplicate_tsns()?, [0x0102_0389, 0x0506_0789]);
    assert_eq!(sack.padding(), &[]);

    Ok(())
}

fn assert_decoded_sctp_control(decoded: &Packet) -> crafter::Result<()> {
    let sctp = decoded.layer::<Sctp>().expect("SCTP layer");

    assert_eq!(sctp.source_port_value(), 20_090);
    assert_eq!(sctp.destination_port_value(), 20_091);
    assert_eq!(sctp.verification_tag_value(), 0x1122_3390);
    assert_eq!(sctp.checksum_status(), SctpChecksumStatus::Valid);
    assert_eq!(sctp.chunk_count(), 13);
    let chunks = sctp.chunks();

    let SctpChunk::Heartbeat(heartbeat) = &chunks[0] else {
        panic!("expected HEARTBEAT chunk");
    };
    assert_eq!(heartbeat.heartbeat_info()?, &[0x90, 0x01]);
    assert_eq!(heartbeat.heartbeat_info_parameter()?.padding(), &[0, 0]);

    let SctpChunk::HeartbeatAck(heartbeat_ack) = &chunks[1] else {
        panic!("expected HEARTBEAT ACK chunk");
    };
    assert_eq!(heartbeat_ack.heartbeat_info()?, &[0x90, 0x02, 0x03, 0x04]);

    let SctpChunk::Abort(abort) = &chunks[2] else {
        panic!("expected ABORT chunk");
    };
    assert!(abort.is_t_bit_set());
    assert_eq!(abort.error_cause_bytes(), &[0xbe, 0xef, 0x00, 0x04]);
    assert_eq!(abort.error_causes()?.len(), 1);

    let SctpChunk::Error(error) = &chunks[3] else {
        panic!("expected ERROR chunk");
    };
    assert_eq!(error.error_cause_bytes(), &[0xbe, 0xef, 0x00, 0x04]);
    assert_eq!(error.error_causes()?.len(), 1);

    let SctpChunk::CookieEcho(cookie_echo) = &chunks[4] else {
        panic!("expected COOKIE ECHO chunk");
    };
    assert_eq!(cookie_echo.cookie(), &[0x90, 0xca, 0xfe]);
    assert_eq!(cookie_echo.padding(), &[0x00]);

    let SctpChunk::CookieAck(cookie_ack) = &chunks[5] else {
        panic!("expected COOKIE ACK chunk");
    };
    cookie_ack.validate_empty_value()?;

    let SctpChunk::Auth(auth) = &chunks[6] else {
        panic!("expected AUTH chunk");
    };
    assert_eq!(auth.shared_key_identifier_value()?, 0x0190);
    assert_eq!(auth.hmac_identifier()?, SctpHmacIdentifier::Sha256);
    assert_eq!(auth.hmac_bytes()?, &[0xaa, 0xbb, 0xcc]);
    assert_eq!(auth.padding(), &[0x00]);

    let SctpChunk::Asconf(asconf) = &chunks[7] else {
        panic!("expected ASCONF chunk");
    };
    assert_eq!(asconf.serial_number()?, 0x1122_3390);
    assert_eq!(asconf.parameter_count()?, 2);
    assert!(matches!(
        asconf.address_parameter()?,
        SctpParameter::Ipv4Address(_)
    ));
    let requests = asconf.request_parameters()?;
    assert_eq!(requests.len(), 1);
    let SctpParameter::AddIpAddress(add_ip) = &requests[0] else {
        panic!("expected ASCONF Add IP Address parameter");
    };
    assert_eq!(add_ip.correlation_id()?, 0x0102_0390);
    assert_eq!(add_ip.ipv4_address()?, CONTROL_DOC_V4_DST);

    let SctpChunk::AsconfAck(asconf_ack) = &chunks[8] else {
        panic!("expected ASCONF ACK chunk");
    };
    assert_eq!(asconf_ack.serial_number()?, 0x1122_3390);
    let responses = asconf_ack.response_parameters()?;
    let SctpParameter::SuccessIndication(success) = &responses[0] else {
        panic!("expected ASCONF ACK Success Indication parameter");
    };
    assert_eq!(success.response_correlation_id()?, 0x0102_0390);

    let SctpChunk::ReConfig(reconfig) = &chunks[9] else {
        panic!("expected RE-CONFIG chunk");
    };
    let parameters = reconfig.parameters()?;
    let SctpParameter::ReConfigurationResponse(response) = &parameters[0] else {
        panic!("expected Re-configuration Response parameter");
    };
    assert_eq!(response.response_sequence_number()?, 0x0102_0390);
    assert_eq!(response.result_value()?, 1);

    let SctpChunk::ForwardTsn(forward_tsn) = &chunks[10] else {
        panic!("expected FORWARD TSN chunk");
    };
    assert_eq!(forward_tsn.new_cumulative_tsn()?, 0x0102_0390);
    assert_eq!(
        forward_tsn.skipped_stream_sequences()?,
        [SctpForwardTsnSkippedStreamSequence::new(1, 2)]
    );

    let SctpChunk::IForwardTsn(iforward_tsn) = &chunks[11] else {
        panic!("expected I-FORWARD TSN chunk");
    };
    assert_eq!(iforward_tsn.new_cumulative_tsn()?, 0x0102_0391);
    assert_eq!(
        iforward_tsn.skipped_streams()?,
        [SctpIForwardTsnSkippedStream::unordered(3, 0x0102_0392)]
    );

    let SctpChunk::Pad(pad) = &chunks[12] else {
        panic!("expected PAD chunk");
    };
    assert_eq!(pad.padding_data(), &[0x90, 0x91, 0x92]);
    assert_eq!(pad.padding(), &[0x00]);

    Ok(())
}

#[test]
fn sctp_init_fixture_ipv4_compiles_decodes_and_recompiles() -> crafter::Result<()> {
    let fixture = decode_hex_fixture(
        "bytes/ipv4-sctp-init.hex",
        fixture_str!("bytes/ipv4-sctp-init.hex"),
    );
    let compiled = ipv4_sctp_init_fixture_packet().compile()?;

    assert_eq!(compiled.as_bytes(), fixture.as_slice());

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &fixture)?;
    let ipv4 = decoded.layer::<Ipv4>().expect("IPv4 layer");
    assert_eq!(ipv4.source(), DOC_V4_SRC);
    assert_eq!(ipv4.destination(), DOC_V4_DST);
    assert_eq!(ipv4.identification_value(), 0x5086);
    assert_eq!(ipv4.ttl_value(), 64);
    assert_eq!(ipv4.protocol_value(), IPPROTO_SCTP);
    assert_decoded_sctp_init(&decoded)?;
    assert!(decoded.layer::<Raw>().is_none());
    assert_eq!(decoded.compile()?, compiled);

    Ok(())
}

#[test]
fn sctp_init_ack_fixture_ipv4_compiles_decodes_and_recompiles() -> crafter::Result<()> {
    let fixture = decode_hex_fixture(
        "bytes/ipv4-sctp-init-ack.hex",
        fixture_str!("bytes/ipv4-sctp-init-ack.hex"),
    );
    let compiled = ipv4_sctp_init_ack_fixture_packet()?.compile()?;

    assert_eq!(compiled.as_bytes(), fixture.as_slice());

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &fixture)?;
    let ipv4 = decoded.layer::<Ipv4>().expect("IPv4 layer");
    assert_eq!(ipv4.source(), INIT_ACK_DOC_V4_SRC);
    assert_eq!(ipv4.destination(), INIT_ACK_DOC_V4_DST);
    assert_eq!(ipv4.identification_value(), 0x5087);
    assert_eq!(ipv4.ttl_value(), 64);
    assert_eq!(ipv4.protocol_value(), IPPROTO_SCTP);
    assert_decoded_sctp_init_ack(&decoded)?;
    assert!(decoded.layer::<Raw>().is_none());
    assert_eq!(decoded.compile()?, compiled);

    Ok(())
}

#[test]
fn sctp_data_fixture_ipv4_compiles_decodes_and_recompiles() -> crafter::Result<()> {
    let fixture = decode_hex_fixture(
        "bytes/ipv4-sctp-data.hex",
        fixture_str!("bytes/ipv4-sctp-data.hex"),
    );
    let compiled = ipv4_sctp_data_fixture_packet().compile()?;

    assert_eq!(compiled.as_bytes(), fixture.as_slice());

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &fixture)?;
    let ipv4 = decoded.layer::<Ipv4>().expect("IPv4 layer");
    assert_eq!(ipv4.source(), DATA_DOC_V4_SRC);
    assert_eq!(ipv4.destination(), DATA_DOC_V4_DST);
    assert_eq!(ipv4.identification_value(), 0x5088);
    assert_eq!(ipv4.ttl_value(), 64);
    assert_eq!(ipv4.protocol_value(), IPPROTO_SCTP);
    assert_decoded_sctp_data(&decoded)?;
    assert!(decoded.layer::<Raw>().is_none());
    assert_eq!(decoded.compile()?, compiled);

    Ok(())
}

#[test]
fn sctp_sack_fixture_ipv4_compiles_decodes_and_recompiles() -> crafter::Result<()> {
    let fixture = decode_hex_fixture(
        "bytes/ipv4-sctp-sack.hex",
        fixture_str!("bytes/ipv4-sctp-sack.hex"),
    );
    let compiled = ipv4_sctp_sack_fixture_packet()?.compile()?;

    assert_eq!(compiled.as_bytes(), fixture.as_slice());

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &fixture)?;
    let ipv4 = decoded.layer::<Ipv4>().expect("IPv4 layer");
    assert_eq!(ipv4.source(), SACK_DOC_V4_SRC);
    assert_eq!(ipv4.destination(), SACK_DOC_V4_DST);
    assert_eq!(ipv4.identification_value(), 0x5089);
    assert_eq!(ipv4.ttl_value(), 64);
    assert_eq!(ipv4.protocol_value(), IPPROTO_SCTP);
    assert_decoded_sctp_sack(&decoded)?;
    assert!(decoded.layer::<Raw>().is_none());
    assert_eq!(decoded.compile()?, compiled);

    Ok(())
}

#[test]
fn sctp_control_fixtures_ipv4_compile_decode_and_recompile() -> crafter::Result<()> {
    let fixture = decode_hex_fixture(
        "bytes/ipv4-sctp-control-chunks.hex",
        fixture_str!("bytes/ipv4-sctp-control-chunks.hex"),
    );
    let compiled = ipv4_sctp_control_fixture_packet()?.compile()?;

    assert_eq!(compiled.as_bytes(), fixture.as_slice());

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &fixture)?;
    let ipv4 = decoded.layer::<Ipv4>().expect("IPv4 layer");
    assert_eq!(ipv4.source(), CONTROL_DOC_V4_SRC);
    assert_eq!(ipv4.destination(), CONTROL_DOC_V4_DST);
    assert_eq!(ipv4.identification_value(), 0x5090);
    assert_eq!(ipv4.ttl_value(), 64);
    assert_eq!(ipv4.protocol_value(), IPPROTO_SCTP);
    assert_decoded_sctp_control(&decoded)?;
    assert!(decoded.layer::<Raw>().is_none());
    assert_eq!(decoded.compile()?, compiled);

    Ok(())
}

#[test]
fn sctp_init_fixture_ipv6_compiles_decodes_and_recompiles() -> crafter::Result<()> {
    let fixture = decode_hex_fixture(
        "bytes/ipv6-sctp-init.hex",
        fixture_str!("bytes/ipv6-sctp-init.hex"),
    );
    let compiled = ipv6_sctp_init_fixture_packet().compile()?;

    assert_eq!(compiled.as_bytes(), fixture.as_slice());

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, &fixture)?;
    let ipv6 = decoded.layer::<Ipv6>().expect("IPv6 layer");
    assert_eq!(ipv6.source(), DOC_V6_SRC);
    assert_eq!(ipv6.destination(), DOC_V6_DST);
    assert_eq!(ipv6.hop_limit_value(), 64);
    assert_eq!(ipv6.next_header_value(), IPPROTO_SCTP);
    assert_decoded_sctp_init(&decoded)?;
    assert!(decoded.layer::<Raw>().is_none());
    assert_eq!(decoded.compile()?, compiled);

    Ok(())
}
