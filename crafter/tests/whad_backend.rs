#![cfg(feature = "whad")]

use crafter::prelude::*;
use crafter::wire::packet_wire::WhadMockChannel;
use crafter::wire::{BackendKind, MediumMetadata, PacketOrigin, PacketWire, WireError};
use prost::Message as _;

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

const BLE_ADVERTISING_ACCESS_ADDRESS: u32 = 0x8E89_BED6;
const DOC_ADV_ADDRESS: &str = "02:00:00:00:00:01";
const DOC_ADV_ADDRESS_DISPLAY: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const DOC_ADV_ADDRESS_ON_AIR: [u8; 6] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x02];
const DOC_BLE_FLAGS_AD: [u8; 3] = [0x02, 0x01, 0x06];

#[test]
fn whad_packetwire_dry_run_inject_plans_without_writing_channel_bytes() {
    let channel = WhadMockChannel::new();
    let wire = PacketWire::whad_serial("mock-whad")
        .ble_inject()
        .channel(38)
        .with_mock_channel(channel.clone())
        .open()
        .expect("dry-run WHAD PacketWire should open without serial I/O");
    assert!(wire.has_writer());
    assert!(!wire.has_source());
    assert!(channel.written_bytes().is_empty());

    let mut writer = wire
        .writer()
        .expect("dry-run inject target should expose a writer");
    let report = writer
        .write_record(&PacketRecord::new(sample_advertisement(38)))
        .expect("dry-run write should produce a send plan");

    assert_eq!(report.backend(), &BackendKind::Whad);
    assert_eq!(report.bytes_requested(), expected_adv_ind_pdu().len());
    assert_eq!(report.bytes_written(), 0);
    assert!(report.is_dry_run());
    let details = report
        .target_details()
        .expect("WHAD dry-run report should include an inspectable plan");
    assert!(details.contains("SendRawPdu"));
    assert!(details.contains("channel=38"));
    assert!(details.contains("access_address=0x8e89bed6"));
    assert!(details.contains("pdu_len=11"));
    assert!(channel.written_bytes().is_empty());
}

#[test]
fn whad_packetwire_live_inject_emits_one_send_raw_pdu_after_open() {
    let channel = WhadMockChannel::new();
    queue_ble_discovery(
        &channel,
        command_mask(&[
            proto::ble::BleCommand::CentralMode,
            proto::ble::BleCommand::SendRawPdu,
            proto::ble::BleCommand::Start,
        ]),
    );

    let wire = PacketWire::whad_serial("mock-whad")
        .ble_inject()
        .channel(38)
        .with_mock_channel(channel.clone())
        .live()
        .open()
        .expect("live mock WHAD PacketWire should discover and enter BLE inject mode");
    assert!(wire.has_writer());
    assert!(!wire.has_source());
    let _open_control_frames = channel.take_written_bytes();

    let mut writer = wire
        .writer()
        .expect("live inject target should expose a writer");
    let report = writer
        .write_record(&PacketRecord::new(sample_advertisement(38)))
        .expect("live mock write should frame one WHAD SendRawPdu");

    assert_eq!(report.backend(), &BackendKind::Whad);
    assert_eq!(report.bytes_requested(), expected_adv_ind_pdu().len());
    assert_eq!(report.bytes_written(), expected_adv_ind_pdu().len());
    assert!(!report.is_dry_run());

    let messages = decode_written_messages(channel.take_written_bytes());
    assert_eq!(messages.len(), 1);
    assert_send_raw_pdu(&messages[0], 38, &expected_adv_ind_pdu());
}

#[test]
fn whad_packetwire_sniff_decodes_received_advertising_pdu() {
    let channel = WhadMockChannel::new();
    queue_ble_discovery(
        &channel,
        command_mask(&[
            proto::ble::BleCommand::SniffAdv,
            proto::ble::BleCommand::Start,
        ]),
    );
    queue_message(&channel, &advertising_pdu_received());

    let wire = PacketWire::whad_serial("mock-whad")
        .ble_sniff(37)
        .with_mock_channel(channel)
        .live()
        .open()
        .expect("live mock WHAD PacketWire should discover and enter BLE sniff mode");
    assert!(wire.has_source());
    assert!(!wire.has_writer());

    let mut source = wire.source().expect("sniff target should expose a source");
    let record = source
        .next_record()
        .expect("WHAD source should decode queued PDU")
        .expect("queued PDU should produce one record");

    assert_eq!(record.metadata().origin(), PacketOrigin::Captured);
    assert_eq!(record.metadata().backend(), &BackendKind::Whad);
    match record.metadata().medium() {
        Some(MediumMetadata::Bluetooth(bluetooth)) => {
            assert_eq!(bluetooth.channel(), Some(37));
            assert_eq!(bluetooth.signal_dbm(), Some(-42));
            assert_eq!(bluetooth.protocol(), Some("ble"));
        }
        other => panic!("expected Bluetooth metadata, got {other:?}"),
    }

    let packet = record.packet();
    assert!(packet.layer::<BleRadio>().is_some());
    let adv = packet
        .layer::<BleLlAdv>()
        .expect("sniffed record should decode a BLE advertising PDU");
    assert_eq!(
        adv.adv_a_value().expect("AdvA should decode"),
        MacAddr::new(DOC_ADV_ADDRESS_DISPLAY)
    );
}

#[test]
fn whad_packetwire_open_rejects_device_without_ble_domain() {
    let channel = WhadMockChannel::new();
    queue_message(
        &channel,
        &device_info_response(vec![proto::discovery::Domain::Phy as u32]),
    );
    queue_message(
        &channel,
        &domain_response(proto::discovery::Domain::Phy as u32, 0),
    );

    let err = PacketWire::whad_serial("mock-whad")
        .ble_sniff(37)
        .with_mock_channel(channel)
        .live()
        .open()
        .expect_err("non-BLE WHAD devices should fail during open/enter BLE");

    match err {
        WireError::Backend {
            backend,
            operation,
            reason,
        } => {
            assert_eq!(backend, "whad");
            assert_eq!(operation, "enter BLE");
            assert!(reason.contains("BLE domain"));
        }
        other => panic!("expected WHAD backend error, got {other:?}"),
    }
}

fn sample_advertisement(channel: u8) -> Packet {
    BleRadio::advertising(channel).access_address(BLE_ADVERTISING_ACCESS_ADDRESS)
        / BleLlAdv::adv_ind()
            .tx_add(false)
            .adv_a_str(DOC_ADV_ADDRESS)
            .expect("documentation BLE address should parse")
            .payload(DOC_BLE_FLAGS_AD)
}

fn expected_adv_ind_pdu() -> Vec<u8> {
    let mut pdu = vec![
        0x00,
        (DOC_ADV_ADDRESS_ON_AIR.len() + DOC_BLE_FLAGS_AD.len()) as u8,
    ];
    pdu.extend_from_slice(&DOC_ADV_ADDRESS_ON_AIR);
    pdu.extend_from_slice(&DOC_BLE_FLAGS_AD);
    pdu
}

fn queue_ble_discovery(channel: &WhadMockChannel, supported_commands: u64) {
    queue_message(
        channel,
        &device_info_response(vec![proto::discovery::Domain::BtLe as u32]),
    );
    queue_message(
        channel,
        &domain_response(proto::discovery::Domain::BtLe as u32, supported_commands),
    );
}

fn queue_message(channel: &WhadMockChannel, message: &proto::Message) {
    channel.queue_frame(framing::encode_message(message));
}

fn decode_written_messages(bytes: Vec<u8>) -> Vec<proto::Message> {
    let mut decoder = framing::FrameDecoder::default();
    decoder.push(&bytes);

    let mut messages = Vec::new();
    while let Some(payload) = decoder.next() {
        messages.push(proto::Message::decode(payload.as_slice()).expect("written WHAD message"));
    }
    messages
}

fn device_info_response(supported_domains: Vec<u32>) -> proto::Message {
    proto::Message {
        msg: Some(proto::message::Msg::Discovery(proto::discovery::Message {
            msg: Some(proto::discovery::message::Msg::InfoResp(
                proto::discovery::DeviceInfoResp {
                    r#type: proto::discovery::DeviceType::Butterfly as u32,
                    devid: vec![0x10, 0x20, 0x30, 0x40],
                    proto_min_ver: WHAD_TARGET_PROTOCOL_VERSION,
                    max_speed: 1_000_000,
                    fw_author: b"whad-team".to_vec(),
                    fw_url: b"https://example.invalid/firmware".to_vec(),
                    fw_version_major: 1,
                    fw_version_minor: 2,
                    fw_version_rev: 3,
                    capabilities: supported_domains,
                },
            )),
        })),
    }
}

fn domain_response(domain: u32, supported_commands: u64) -> proto::Message {
    proto::Message {
        msg: Some(proto::message::Msg::Discovery(proto::discovery::Message {
            msg: Some(proto::discovery::message::Msg::DomainResp(
                proto::discovery::DeviceDomainInfoResp {
                    domain,
                    supported_commands,
                },
            )),
        })),
    }
}

fn advertising_pdu_received() -> proto::Message {
    proto::Message {
        msg: Some(proto::message::Msg::Ble(proto::ble::Message {
            msg: Some(proto::ble::message::Msg::AdvPdu(
                proto::ble::AdvPduReceived {
                    adv_type: proto::ble::BleAdvType::AdvInd as i32,
                    rssi: -42,
                    bd_address: DOC_ADV_ADDRESS_ON_AIR.to_vec(),
                    adv_data: DOC_BLE_FLAGS_AD.to_vec(),
                    addr_type: proto::ble::BleAddrType::Public as i32,
                    channel: 37,
                    phy: proto::ble::BlePhy::Le1m as i32,
                },
            )),
        })),
    }
}

fn command_mask(commands: &[proto::ble::BleCommand]) -> u64 {
    commands
        .iter()
        .fold(0, |mask, command| mask | (1u64 << (*command as u32)))
}

fn assert_send_raw_pdu(message: &proto::Message, channel: u32, expected_pdu: &[u8]) {
    match message.msg.as_ref() {
        Some(proto::message::Msg::Ble(ble)) => match ble.msg.as_ref() {
            Some(proto::ble::message::Msg::SendRawPdu(command)) => {
                assert_eq!(command.conn_handle, channel);
                assert_eq!(command.access_address, BLE_ADVERTISING_ACCESS_ADDRESS);
                assert_eq!(command.pdu, expected_pdu);
                assert_eq!(command.direction, proto::ble::BleDirection::Unknown as i32);
            }
            other => panic!("expected BLE SendRawPdu command, got {other:?}"),
        },
        other => panic!("expected top-level BLE message, got {other:?}"),
    }
}
