//! RFC 8323 reliable-transport CoAP integration coverage through public APIs.
//!
//! Every network envelope is compiled and decoded offline with documentation
//! addresses. The tests provide complete TCP payload boundaries explicitly;
//! they do not add TCP stream reassembly, TLS, WebSocket framing, or live I/O.

use std::net::Ipv4Addr;

use crafter::checksum::ipv4_pseudo_header_checksum;
use crafter::prelude::*;

const IPV4_HEADER_LEN: usize = 20;
const TCP_HEADER_LEN: usize = 20;
const CLIENT_PORT: u16 = 49_152;
const IPV4_CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 85);
const IPV4_SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 85);

fn compile_reliable(message: CoapReliable) -> crafter::Result<Vec<u8>> {
    Ok(Packet::from_layer(message).compile()?.into_bytes())
}

fn reliable_tcp_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    payload: impl IntoPacket,
) -> Packet {
    Ipv4::with_addresses(source, destination)
        / Tcp::new()
            .sport(source_port)
            .dport(destination_port)
            .seq(0x0102_0304)
            .ack(0x0506_0708)
            .ack_segment()
        / payload
}

#[test]
fn request_and_response_frames_cover_every_reliable_length_form() -> crafter::Result<()> {
    // RFC 8323 Section 3.2 uses direct Len values through 12, then one-,
    // two-, and four-octet extensions at 13, 269, and 65,805 respectively.
    let cases: &[(usize, u8, &[u8], CoapCode)] = &[
        (0, 0, &[], CoapCode::get()),
        (12, 12, &[], CoapCode::content()),
        (13, 13, &[0x00], CoapCode::get()),
        (268, 13, &[0xff], CoapCode::content()),
        (269, 14, &[0x00, 0x00], CoapCode::get()),
        (65_804, 14, &[0xff, 0xff], CoapCode::content()),
        (65_805, 15, &[0x00, 0x00, 0x00, 0x00], CoapCode::get()),
    ];

    for &(body_len, length_nibble, extension, code) in cases {
        let message = if code.is_request() {
            CoapReliable::request(code)
        } else {
            CoapReliable::response(code)
        };
        let payload_len = body_len.saturating_sub(1);
        let message = if body_len == 0 {
            message
        } else {
            message.payload(vec![0xa5; payload_len])
        };

        let mut expected = vec![length_nibble << 4];
        expected.extend_from_slice(extension);
        expected.push(code.wire_value());
        if body_len != 0 {
            expected.push(COAP_PAYLOAD_MARKER);
            expected.extend(std::iter::repeat_n(0xa5, payload_len));
        }

        let encoded = compile_reliable(message.clone())?;
        assert_eq!(encoded, expected, "body length {body_len}");
        let length = message.length_value()?;
        assert_eq!(length.nibble(), length_nibble, "body length {body_len}");
        assert_eq!(
            length.extension_bytes(),
            extension,
            "body length {body_len}"
        );
        assert_eq!(
            length.declared_body_len(),
            body_len,
            "body length {body_len}"
        );

        let (decoded, consumed) = decode_coap_reliable(&encoded)?;
        assert_eq!(consumed, encoded.len(), "body length {body_len}");
        assert_eq!(decoded.code_value(), code, "body length {body_len}");
        assert_eq!(decoded.is_request(), code.is_request());
        assert_eq!(decoded.is_response(), code.is_response());
        assert_eq!(decoded.payload_value().len(), payload_len);
        assert_eq!(
            compile_reliable(decoded)?,
            encoded,
            "body length {body_len}"
        );
    }

    Ok(())
}

#[test]
fn signaling_frames_and_contextual_options_are_exact_and_lossless() -> crafter::Result<()> {
    let bare_signals = [
        (CoapReliable::csm(), 0xe1),
        (CoapReliable::ping(), 0xe2),
        (CoapReliable::pong(), 0xe3),
        (CoapReliable::release(), 0xe4),
        (CoapReliable::abort(), 0xe5),
    ];
    for (message, code) in bare_signals {
        let expected = [0x00, code];
        assert_eq!(compile_reliable(message.clone())?, expected);
        let (decoded, consumed) = decode_coap_reliable(&expected)?;
        assert_eq!(consumed, expected.len());
        assert!(decoded.is_signaling());
        assert_eq!(decoded.code_value().wire_value(), code);
    }

    // RFC 8323 Sections 5.3.1 and 5.3.2: CSM option 2 contains uint
    // 1152 (`0x0480`) and option 4 is empty.
    let csm = CoapReliable::csm()
        .option(CoapSignalingOption::max_message_size(1152))
        .option(CoapSignalingOption::block_wise_transfer());
    let csm_expected = [0x40, 0xe1, 0x22, 0x04, 0x80, 0x20];
    assert_eq!(csm.validate_signaling_options(), Ok(()));
    assert_eq!(compile_reliable(csm)?, csm_expected);
    let (decoded_csm, consumed) = decode_coap_reliable(&csm_expected)?;
    assert_eq!(consumed, csm_expected.len());
    assert_eq!(decoded_csm.validate_signaling_options(), Ok(()));
    let csm_options = decoded_csm.signaling_options();
    assert_eq!(csm_options.len(), 2);
    assert_eq!(csm_options[0].registry_meta().label, "Max-Message-Size");
    assert_eq!(csm_options[0].option().as_uint()?, 1152);
    assert_eq!(csm_options[1].registry_meta().label, "Block-Wise-Transfer");
    assert_eq!(csm_options[1].format(), CoapOptionFormat::Empty);
    assert_eq!(compile_reliable(decoded_csm)?, csm_expected);

    let ping = CoapReliable::ping()
        .token(CoapToken::from_bytes([0x42]))
        .option(CoapSignalingOption::custody(CoapCode::ping())?);
    assert_eq!(compile_reliable(ping.clone())?, [0x11, 0xe2, 0x42, 0x20]);
    assert_eq!(ping.validate_signaling_options(), Ok(()));

    let pong =
        CoapReliable::pong_for(&ping).option(CoapSignalingOption::custody(CoapCode::pong())?);
    assert!(pong.matches_ping(&ping));
    assert_eq!(pong.validate_signaling_options(), Ok(()));
    assert_eq!(compile_reliable(pong)?, [0x11, 0xe3, 0x42, 0x20]);

    let release = CoapReliable::release()
        .option(CoapSignalingOption::alternative_address(
            "coap.example:5683",
        ))
        .option(CoapSignalingOption::hold_off(30));
    let mut release_expected = vec![0xd0, 0x08, 0xe4, 0x2d, 0x04];
    release_expected.extend_from_slice(b"coap.example:5683");
    release_expected.extend_from_slice(&[0x21, 0x1e]);
    assert_eq!(release.validate_signaling_options(), Ok(()));
    assert_eq!(compile_reliable(release.clone())?, release_expected);
    let (decoded_release, consumed) = decode_coap_reliable(&release_expected)?;
    assert_eq!(consumed, release_expected.len());
    assert!(decoded_release.is_release());
    assert_eq!(decoded_release.validate_signaling_options(), Ok(()));

    let abort = CoapReliable::abort().option(CoapSignalingOption::bad_csm_option(4));
    assert_eq!(abort.validate_signaling_options(), Ok(()));
    assert_eq!(compile_reliable(abort)?, [0x20, 0xe5, 0x21, 0x04]);

    Ok(())
}

#[test]
fn bert_extended_tokens_and_unknown_values_round_trip() -> crafter::Result<()> {
    let bert = CoapBlock::block2(5, false, CoapBlock::BERT_SZX)?;
    assert!(bert
        .validate(CoapBlockKind::Block2, CoapBlockTransport::Reliable, 1_537,)
        .is_valid());
    let message = CoapReliable::response(CoapCode::content())
        .option(bert.clone().into_option(CoapBlockKind::Block2))
        .payload(vec![0x4d; 1_537]);
    let mut bert_expected = vec![
        0xe0,
        0x04,
        0xf8,
        0x45, // Len 1541, 2.05 Content.
        0xd1,
        0x0a,
        0x57, // Block2 NUM=5, M=0, SZX=7 (BERT).
        COAP_PAYLOAD_MARKER,
    ];
    bert_expected.extend(std::iter::repeat_n(0x4d, 1_537));
    let bert_bytes = compile_reliable(message)?;
    assert_eq!(bert_bytes, bert_expected);
    let (decoded_bert, consumed) = decode_coap_reliable(&bert_bytes)?;
    assert_eq!(consumed, bert_bytes.len());
    let decoded_block = CoapBlock::try_from(&decoded_bert.options_value()[0])?;
    assert!(decoded_block.is_bert());
    assert_eq!(decoded_block.number(), 5);
    assert_eq!(decoded_block.bert_block_count(1_537)?, 2);
    assert_eq!(compile_reliable(decoded_bert)?, bert_bytes);

    let token = (0u8..13).map(|value| 0x80 + value).collect::<Vec<_>>();
    let extended = CoapReliable::request(CoapCode::get())
        .token(CoapToken::from_bytes(&token))
        .option(CoapOption::new(65_000u16, [0xde, 0xad]));
    let mut extended_expected = vec![0x5d, 0x01, 0x00];
    extended_expected.extend_from_slice(&token);
    extended_expected.extend_from_slice(&[0xe2, 0xfc, 0xdb, 0xde, 0xad]);
    let extended_bytes = compile_reliable(extended)?;
    assert_eq!(extended_bytes, extended_expected);
    let (decoded_extended, consumed) = decode_coap_reliable(&extended_bytes)?;
    assert_eq!(consumed, extended_bytes.len());
    assert_eq!(decoded_extended.token_value().as_bytes(), token);
    assert_eq!(decoded_extended.token_length_value()?.nibble(), 13);
    assert_eq!(
        decoded_extended.token_length_value()?.extension_bytes(),
        [0x00]
    );
    assert_eq!(decoded_extended.options_value()[0].number().value(), 65_000);
    assert_eq!(decoded_extended.options_value()[0].value(), [0xde, 0xad]);
    assert_eq!(compile_reliable(decoded_extended)?, extended_bytes);

    let unknown = CoapReliable::new(CoapCode::from_wire(0xff)).option(CoapSignalingOption::new(
        CoapCode::from_wire(0xff),
        CoapOption::new(65_000u16, [0xca, 0xfe]),
    ));
    let unknown_expected = [0x50, 0xff, 0xe2, 0xfc, 0xdb, 0xca, 0xfe];
    assert_eq!(unknown.validate_signaling_options(), Ok(()));
    assert_eq!(compile_reliable(unknown)?, unknown_expected);
    let (decoded_unknown, consumed) = decode_coap_reliable(&unknown_expected)?;
    assert_eq!(consumed, unknown_expected.len());
    assert_eq!(decoded_unknown.code_value().wire_value(), 0xff);
    assert_eq!(decoded_unknown.options_value()[0].value(), [0xca, 0xfe]);
    assert_eq!(compile_reliable(decoded_unknown)?, unknown_expected);

    Ok(())
}

#[test]
fn ipv4_tcp_stacks_autofill_checksums_and_registry_decode_exact_frames() -> crafter::Result<()> {
    let cases = [
        (
            IPV4_CLIENT,
            IPV4_SERVER,
            CLIENT_PORT,
            COAP_PORT,
            CoapReliable::request(CoapCode::get()).token(CoapToken::from_bytes([0xaa, 0xbb])),
            vec![0x02, 0x01, 0xaa, 0xbb],
        ),
        (
            IPV4_SERVER,
            IPV4_CLIENT,
            COAP_PORT,
            CLIENT_PORT,
            CoapReliable::response(CoapCode::content()).token(CoapToken::from_bytes([0xaa, 0xbb])),
            vec![0x02, 0x45, 0xaa, 0xbb],
        ),
    ];

    for (source, destination, source_port, destination_port, message, frame) in cases {
        let packet =
            reliable_tcp_packet(source, destination, source_port, destination_port, message);
        let compiled = packet.compile()?;
        let bytes = compiled.as_bytes();
        assert_eq!(bytes.len(), IPV4_HEADER_LEN + TCP_HEADER_LEN + frame.len());
        assert_eq!(&bytes[IPV4_HEADER_LEN + TCP_HEADER_LEN..], frame);
        assert_eq!(bytes[9], IPPROTO_TCP);
        assert_eq!(
            ipv4_pseudo_header_checksum(
                source,
                destination,
                IPPROTO_TCP,
                &bytes[IPV4_HEADER_LEN..]
            ),
            0,
            "TCP pseudo-header checksum"
        );

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes)?;
        let ipv4 = decoded.layer::<Ipv4>().expect("decoded IPv4 layer");
        let tcp = decoded.layer::<Tcp>().expect("decoded TCP layer");
        let coap = decoded
            .layer::<CoapReliable>()
            .expect("one exact reliable CoAP frame");
        assert_eq!(ipv4.checksum_status(), Ipv4ChecksumStatus::Valid);
        assert_eq!(tcp.source_port_value(), source_port);
        assert_eq!(tcp.destination_port_value(), destination_port);
        assert_eq!(tcp.data_offset_value(), 5);
        assert_ne!(tcp.checksum_value(), Some(0));
        assert_eq!(coap.token_value().as_bytes(), [0xaa, 0xbb]);
        assert!(decoded.layer::<Raw>().is_none());
        assert_eq!(decoded.compile()?.as_bytes(), bytes);
    }

    let inspected = CoapReliable::ping().token(CoapToken::from_bytes([0x42]));
    assert_eq!(
        inspected.summary(),
        "CoapReliable(length=0, code=7.02(Ping), token_len=1, options=0, marker=absent, payload=0 bytes)"
    );
    assert_eq!(
        Packet::from_layer(inspected).show(),
        "Packet(len=3, layers=1)\n  [0] CoapReliable\n      length: 0\n      token_length: 1\n      code: 7.02(Ping)\n      token: len=1 hex=42\n      options: 0\n      payload_marker: absent\n      payload_length: 0"
    );

    Ok(())
}

#[test]
fn direct_decode_consumes_one_frame_while_registry_refuses_stream_assumptions(
) -> crafter::Result<()> {
    let first = compile_reliable(CoapReliable::ping())?;
    let second = compile_reliable(CoapReliable::pong())?;
    let mut concatenated = first.clone();
    concatenated.extend_from_slice(&second);

    let (decoded_first, consumed) = decode_coap_reliable(&concatenated)?;
    assert!(decoded_first.is_ping());
    assert_eq!(consumed, first.len());
    assert_eq!(&concatenated[consumed..], second);

    let concatenated_packet = reliable_tcp_packet(
        IPV4_CLIENT,
        IPV4_SERVER,
        CLIENT_PORT,
        COAP_PORT,
        Raw::from_bytes(&concatenated),
    );
    let concatenated_bytes = concatenated_packet.compile()?;
    let concatenated_decoded =
        Packet::decode_from_l3(NetworkLayer::Ipv4, concatenated_bytes.as_bytes())?;
    assert!(concatenated_decoded.layer::<CoapReliable>().is_none());
    assert_eq!(
        concatenated_decoded
            .layer::<Raw>()
            .expect("concatenated TCP payload remains Raw")
            .as_bytes(),
        concatenated
    );

    let partial = [0x30, 0x01, 0xaa, 0xbb]; // Declares three body bytes, carries two.
    assert_eq!(
        decode_coap_reliable(&partial),
        Err(CrafterError::buffer_too_short("coap.reliable.body", 3, 2,))
    );
    let partial_packet = reliable_tcp_packet(
        IPV4_CLIENT,
        IPV4_SERVER,
        CLIENT_PORT,
        COAP_PORT,
        Raw::from_bytes(partial),
    );
    let partial_bytes = partial_packet.compile()?;
    let partial_decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, partial_bytes.as_bytes())?;
    assert!(partial_decoded.layer::<CoapReliable>().is_none());
    assert_eq!(
        partial_decoded
            .layer::<Raw>()
            .expect("partial TCP payload remains Raw")
            .as_bytes(),
        partial
    );

    let protected_packet = reliable_tcp_packet(
        IPV4_CLIENT,
        IPV4_SERVER,
        CLIENT_PORT,
        COAPS_PORT,
        Raw::from_bytes(&first),
    );
    let protected_bytes = protected_packet.compile()?;
    let protected_decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, protected_bytes.as_bytes())?;
    assert!(protected_decoded.layer::<CoapReliable>().is_none());
    assert_eq!(
        protected_decoded
            .layer::<Raw>()
            .expect("secure-port bytes remain opaque")
            .as_bytes(),
        first
    );

    Ok(())
}
