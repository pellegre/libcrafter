#![cfg(feature = "whad")]

pub use crafter::{CrafterError, Result};

pub mod wire {
    pub use crafter::wire::{Result, WireError};
}

pub(crate) const WHAD_TARGET_PROTOCOL_VERSION: u32 = 3;

pub(crate) mod proto {
    #![allow(dead_code)]
    // The vendored WHAD protobuf schema owns its enum variant names.
    #![allow(clippy::enum_variant_names)]

    include!(concat!(env!("OUT_DIR"), "/whad_proto.rs"));
}

#[path = "../src/wire/backend/whad/framing.rs"]
mod framing;

#[path = "../src/wire/backend/whad/messages.rs"]
mod messages;

#[path = "../src/wire/backend/whad/dot15d4.rs"]
mod dot15d4;

use dot15d4::{
    build_dot15d4_message, build_dot15d4_send, build_dot15d4_send_raw, build_dot15d4_sniff,
    build_dot15d4_start, build_dot15d4_stop, parse_dot15d4_received, WhadDot15d4Rx,
};
use framing::{encode_message, FrameDecoder};
use messages::{build_send_raw_pdu, parse_received_pdu, WhadRxPdu};
use prost::Message as _;

const BLE_ADVERTISING_ACCESS_ADDRESS: u32 = 0x8E89_BED6;
const DOC_BLE_ADV_ADDRESS: [u8; 6] = [0x46, 0x53, 0x00, 0x5e, 0x00, 0x00];
const DOC_BLE_FLAGS_AD: [u8; 3] = [0x02, 0x01, 0x06];

#[test]
fn send_raw_pdu_frames_and_decodes_as_whad_message() {
    let pdu = sample_adv_ind_pdu();
    let message = build_send_raw_pdu(37, BLE_ADVERTISING_ACCESS_ADDRESS, &pdu);
    let frame = encode_message(&message);

    let mut decoder = FrameDecoder::default();
    decoder.push(&frame);
    let payload = decoder.next().expect("framed WHAD payload decodes");
    assert_eq!(decoder.next(), None);

    let decoded = proto::Message::decode(payload.as_slice()).expect("WHAD message decodes");
    match decoded.msg {
        Some(proto::message::Msg::Ble(ble)) => match ble.msg {
            Some(proto::ble::message::Msg::SendRawPdu(command)) => {
                assert_eq!(command.conn_handle, 37);
                assert_eq!(command.access_address, BLE_ADVERTISING_ACCESS_ADDRESS);
                assert_eq!(command.pdu, pdu);
                assert_eq!(command.direction, proto::ble::BleDirection::Unknown as i32);
            }
            other => panic!("expected SendRawPdu, got {other:?}"),
        },
        other => panic!("expected BLE message, got {other:?}"),
    }
}

#[test]
fn received_advertising_pdu_frames_in_chunks_and_parses() {
    let message = proto::Message {
        msg: Some(proto::message::Msg::Ble(proto::ble::Message {
            msg: Some(proto::ble::message::Msg::AdvPdu(
                proto::ble::AdvPduReceived {
                    adv_type: proto::ble::BleAdvType::AdvNonconnInd as i32,
                    rssi: -42,
                    bd_address: DOC_BLE_ADV_ADDRESS.to_vec(),
                    adv_data: DOC_BLE_FLAGS_AD.to_vec(),
                    addr_type: proto::ble::BleAddrType::Public as i32,
                    channel: 37,
                    phy: proto::ble::BlePhy::Le1m as i32,
                },
            )),
        })),
    };
    let frame = encode_message(&message);

    let mut decoder = FrameDecoder::default();
    decoder.push(&frame[..5]);
    assert_eq!(decoder.next(), None);
    decoder.push(&frame[5..]);
    let payload = decoder.next().expect("split WHAD frame decodes");
    assert_eq!(decoder.next(), None);

    let decoded = proto::Message::decode(payload.as_slice()).expect("WHAD message decodes");
    let received = parse_received_pdu(&decoded).expect("received advertising PDU parses");

    assert_eq!(
        received,
        WhadRxPdu {
            channel: 37,
            rssi: -42,
            crc_valid: true,
            access_address: BLE_ADVERTISING_ACCESS_ADDRESS,
            pdu: expected_adv_nonconn_ind_pdu(),
        }
    );
}

fn sample_adv_ind_pdu() -> Vec<u8> {
    let mut pdu = vec![
        0x00,
        (DOC_BLE_ADV_ADDRESS.len() + DOC_BLE_FLAGS_AD.len()) as u8,
    ];
    pdu.extend_from_slice(&DOC_BLE_ADV_ADDRESS);
    pdu.extend_from_slice(&DOC_BLE_FLAGS_AD);
    pdu
}

fn expected_adv_nonconn_ind_pdu() -> Vec<u8> {
    let mut pdu = vec![
        0x02,
        (DOC_BLE_ADV_ADDRESS.len() + DOC_BLE_FLAGS_AD.len()) as u8,
    ];
    pdu.extend_from_slice(&DOC_BLE_ADV_ADDRESS);
    pdu.extend_from_slice(&DOC_BLE_FLAGS_AD);
    pdu
}

// A lab-safe 802.15.4 data frame PDU (FCF + seq + addressing + payload),
// used as the dot15d4 framing-test payload.
const DOC_DOT15D4_PDU: [u8; 9] = [0x41, 0x88, 0x02, 0xAB, 0xCD, 0xEF, 0x01, 0xDE, 0xAD];

/// Round-trip one built dot15d4 `proto::Message` through `encode_message` and a
/// `FrameDecoder`, returning the decoded top-level message so the caller can
/// assert the oneof variant and fields.
fn dot15d4_framing_round_trip(message: &proto::Message) -> proto::Message {
    let frame = encode_message(message);

    let mut decoder = FrameDecoder::default();
    decoder.push(&frame);
    let payload = decoder.next().expect("framed WHAD dot15d4 payload decodes");
    assert_eq!(decoder.next(), None);

    proto::Message::decode(payload.as_slice()).expect("WHAD dot15d4 message decodes")
}

fn dot15d4_payload(message: proto::Message) -> proto::dot15d4::message::Msg {
    match message.msg {
        Some(proto::message::Msg::Dot15d4(dot15d4)) => {
            dot15d4.msg.expect("dot15d4 message carries a payload")
        }
        other => panic!("expected top-level dot15d4 message, got {other:?}"),
    }
}

#[test]
fn dot15d4_framing_command_messages_round_trip() {
    // Sniff
    let sniff = dot15d4_payload(dot15d4_framing_round_trip(&build_dot15d4_sniff(15)));
    match sniff {
        proto::dot15d4::message::Msg::Sniff(command) => assert_eq!(command.channel, 15),
        other => panic!("expected dot15d4 sniff command, got {other:?}"),
    }

    // Send
    let send_pdu = DOC_DOT15D4_PDU.to_vec();
    let send = dot15d4_payload(dot15d4_framing_round_trip(&build_dot15d4_send(
        20,
        send_pdu.clone(),
    )));
    match send {
        proto::dot15d4::message::Msg::Send(command) => {
            assert_eq!(command.channel, 20);
            assert_eq!(command.pdu, send_pdu);
        }
        other => panic!("expected dot15d4 send command, got {other:?}"),
    }

    // SendRaw
    let raw_pdu = DOC_DOT15D4_PDU.to_vec();
    let send_raw = dot15d4_payload(dot15d4_framing_round_trip(&build_dot15d4_send_raw(
        26,
        raw_pdu.clone(),
        0xBEEF,
    )));
    match send_raw {
        proto::dot15d4::message::Msg::SendRaw(command) => {
            assert_eq!(command.channel, 26);
            assert_eq!(command.pdu, raw_pdu);
            assert_eq!(command.fcs, 0xBEEF);
        }
        other => panic!("expected dot15d4 send-raw command, got {other:?}"),
    }

    // Start
    let start = dot15d4_payload(dot15d4_framing_round_trip(&build_dot15d4_start()));
    match start {
        proto::dot15d4::message::Msg::Start(_) => {}
        other => panic!("expected dot15d4 start command, got {other:?}"),
    }

    // Stop
    let stop = dot15d4_payload(dot15d4_framing_round_trip(&build_dot15d4_stop()));
    match stop {
        proto::dot15d4::message::Msg::Stop(_) => {}
        other => panic!("expected dot15d4 stop command, got {other:?}"),
    }
}

#[test]
fn dot15d4_framing_received_pdus_round_trip() {
    // RawPduReceived: carries an explicit FCS and its validity bit.
    let raw_pdu = DOC_DOT15D4_PDU.to_vec();
    let raw_message = build_dot15d4_message(proto::dot15d4::message::Msg::RawPdu(
        proto::dot15d4::RawPduReceived {
            channel: 15,
            rssi: Some(-57),
            timestamp: Some(123),
            fcs_validity: true,
            pdu: raw_pdu.clone(),
            fcs: 0xBEEF,
            lqi: Some(200),
        },
    ));
    let decoded_raw = dot15d4_framing_round_trip(&raw_message);
    let parsed_raw = parse_dot15d4_received(&decoded_raw).expect("framed raw PDU parses");
    assert_eq!(
        parsed_raw,
        WhadDot15d4Rx {
            channel: 15,
            rssi: -57,
            fcs_valid: true,
            lqi: 200,
            pdu: raw_pdu,
        }
    );

    // PduReceived: FCS stripped/validated by firmware -> fcs_valid true.
    let pdu = DOC_DOT15D4_PDU.to_vec();
    let pdu_message = build_dot15d4_message(proto::dot15d4::message::Msg::Pdu(
        proto::dot15d4::PduReceived {
            channel: 20,
            rssi: Some(-70),
            timestamp: Some(456),
            fcs_validity: false,
            pdu: pdu.clone(),
            lqi: Some(120),
        },
    ));
    let decoded_pdu = dot15d4_framing_round_trip(&pdu_message);
    let parsed_pdu = parse_dot15d4_received(&decoded_pdu).expect("framed PDU parses");
    assert_eq!(
        parsed_pdu,
        WhadDot15d4Rx {
            channel: 20,
            rssi: -70,
            fcs_valid: true,
            lqi: 120,
            pdu,
        }
    );
}

#[test]
fn dot15d4_framing_received_pdu_in_chunks_parses() {
    let pdu = DOC_DOT15D4_PDU.to_vec();
    let message = build_dot15d4_message(proto::dot15d4::message::Msg::RawPdu(
        proto::dot15d4::RawPduReceived {
            channel: 26,
            rssi: Some(-42),
            timestamp: Some(789),
            fcs_validity: true,
            pdu: pdu.clone(),
            fcs: 0x1234,
            lqi: Some(180),
        },
    ));
    let frame = encode_message(&message);

    let mut decoder = FrameDecoder::default();
    decoder.push(&frame[..5]);
    assert_eq!(decoder.next(), None);
    decoder.push(&frame[5..]);
    let payload = decoder.next().expect("split WHAD dot15d4 frame decodes");
    assert_eq!(decoder.next(), None);

    let decoded = proto::Message::decode(payload.as_slice()).expect("WHAD dot15d4 message decodes");
    let received = parse_dot15d4_received(&decoded).expect("received dot15d4 PDU parses");
    assert_eq!(
        received,
        WhadDot15d4Rx {
            channel: 26,
            rssi: -42,
            fcs_valid: true,
            lqi: 180,
            pdu,
        }
    );
}

#[test]
fn dot15d4_framing_concatenated_frames_decode_as_two() {
    // Two distinct dot15d4 messages back-to-back: the decoder must resync on
    // the second `0xAC 0xBE` sync word and surface both frames.
    let first = build_dot15d4_sniff(11);
    let second = build_dot15d4_send(26, DOC_DOT15D4_PDU.to_vec());

    let mut bytes = encode_message(&first);
    bytes.extend_from_slice(&encode_message(&second));

    let mut decoder = FrameDecoder::default();
    decoder.push(&bytes);

    let first_payload = decoder.next().expect("first framed dot15d4 message decodes");
    let second_payload = decoder
        .next()
        .expect("second framed dot15d4 message decodes");
    assert_eq!(decoder.next(), None);

    let first_decoded =
        proto::Message::decode(first_payload.as_slice()).expect("first dot15d4 message decodes");
    match dot15d4_payload(first_decoded) {
        proto::dot15d4::message::Msg::Sniff(command) => assert_eq!(command.channel, 11),
        other => panic!("expected dot15d4 sniff command, got {other:?}"),
    }

    let second_decoded =
        proto::Message::decode(second_payload.as_slice()).expect("second dot15d4 message decodes");
    match dot15d4_payload(second_decoded) {
        proto::dot15d4::message::Msg::Send(command) => {
            assert_eq!(command.channel, 26);
            assert_eq!(command.pdu, DOC_DOT15D4_PDU.to_vec());
        }
        other => panic!("expected dot15d4 send command, got {other:?}"),
    }
}
