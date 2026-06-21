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
