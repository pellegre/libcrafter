#![cfg(feature = "whad")]

//! WHAD 802.15.4 backend integration tests.
//!
//! Mirrors `crafter/tests/whad_backend.rs` for the BLE backend: a mock
//! `WhadMockChannel` is pre-loaded with a WHAD discovery handshake that
//! advertises the `Dot15d4` domain plus the command bits a mode needs, then
//! the dot15d4 sniff and send paths are exercised through `PacketWire`.
//!
//! This is the committed offline proof of the 802.15.4 backend (no hardware):
//! the mock channel stands in for the serial transport, so the discovery,
//! framing, capability, reader, and writer layers all run without a dongle.
//! The file is `#![cfg(feature = "whad")]`, so the default build skips it.

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

// Lab-safe documentation-style 802.15.4 values: a 2.4 GHz channel and a
// short-addressed data frame between two PAN devices.
const DOT15D4_CHANNEL: u8 = 15;
const DOT15D4_RSSI: i16 = -57;
const DOT15D4_LQI: u8 = 200;

// The committed `crafter/tests/fixtures/dot15d4/mac-data-short.hex` fixture: an
// 802.15.4 Data frame with short addressing and PAN-ID compression. FCF
// `41 88` (Data, PAN-ID compression, short dest/src), sequence `0x2a`, dest PAN
// `0x1234`, dest short `0x0000`, src short `0xABCD`, MAC payload `de ad be ef`,
// trailing CRC-16 FCS `56 1b`. The non-Zigbee payload decodes to a trailing
// `Raw` layer.
const MAC_DATA_SHORT_PDU: [u8; 15] = [
    0x41, 0x88, 0x2a, 0x34, 0x12, 0x00, 0x00, 0xcd, 0xab, 0xde, 0xad, 0xbe, 0xef, 0x56, 0x1b,
];

#[test]
fn dot15d4_packetwire_sniff_decodes_received_raw_pdu() {
    let channel = WhadMockChannel::new();
    queue_dot15d4_discovery(
        &channel,
        dot15d4_command_mask(&[
            proto::dot15d4::Dot15d4Command::Sniff,
            proto::dot15d4::Dot15d4Command::Stop,
            proto::dot15d4::Dot15d4Command::Start,
        ]),
    );
    queue_message(&channel, &raw_pdu_received());

    let wire = PacketWire::whad_serial("mock-whad")
        .dot15d4_sniff(DOT15D4_CHANNEL)
        .with_mock_channel(channel)
        .live()
        .open()
        .expect("live mock WHAD PacketWire should discover and enter 802.15.4 sniff mode");
    assert!(wire.has_source());
    assert!(!wire.has_writer());

    let mut source = wire.source().expect("sniff target should expose a source");
    let record = source
        .next_record()
        .expect("WHAD source should decode queued PDU")
        .expect("queued PDU should produce one record");

    assert_eq!(record.metadata().origin(), PacketOrigin::Captured);
    assert_eq!(record.metadata().backend(), &BackendKind::Whad);
    assert_eq!(
        record.metadata().link_type(),
        Some(LinkType::Ieee802154Tap)
    );
    match record.metadata().medium() {
        Some(MediumMetadata::Dot15d4(dot15d4)) => {
            assert_eq!(dot15d4.channel(), Some(DOT15D4_CHANNEL));
            assert_eq!(dot15d4.signal_dbm(), Some(DOT15D4_RSSI));
            assert_eq!(dot15d4.lqi(), Some(DOT15D4_LQI));
            assert_eq!(dot15d4.fcs_valid(), Some(true));
            assert_eq!(dot15d4.protocol(), Some("dot15d4"));
        }
        other => panic!("expected Dot15d4 metadata, got {other:?}"),
    }

    // The record reads `Dot15d4Radio / Dot15d4 / Raw`: the radio descriptor
    // pseudo-header, the decoded MAC frame, and the non-Zigbee payload preserved
    // as `Raw`.
    let packet = record.packet();
    let radio = packet
        .layer::<Dot15d4Radio>()
        .expect("sniffed record should carry a Dot15d4Radio descriptor");
    let radio_fields = radio.inspection_fields();
    let radio_field = |name: &str| {
        radio_fields
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.as_str())
    };
    assert_eq!(radio_field("channel"), Some(DOT15D4_CHANNEL.to_string().as_str()));
    assert_eq!(radio_field("fcs_valid"), Some("true"));
    let mac = packet
        .layer::<Dot15d4>()
        .expect("sniffed record should decode a Dot15d4 MAC frame");
    // The decoded MAC frame carries the fixture's sequence number (0x2a = 42).
    let seq = mac
        .inspection_fields()
        .into_iter()
        .find(|(name, _)| *name == "seq")
        .map(|(_, value)| value)
        .expect("decoded Dot15d4 should expose a sequence number");
    assert_eq!(seq, "42");
}

#[test]
fn dot15d4_packetwire_dry_run_send_plans_without_writing_channel_bytes() {
    let channel = WhadMockChannel::new();
    let wire = PacketWire::whad_serial("mock-whad")
        .dot15d4_send()
        .channel(DOT15D4_CHANNEL)
        .with_mock_channel(channel.clone())
        .open()
        .expect("dry-run WHAD 802.15.4 PacketWire should open without serial I/O");
    assert!(wire.has_writer());
    assert!(!wire.has_source());
    assert!(channel.written_bytes().is_empty());

    let expected_pdu = sample_dot15d4_mac_pdu();
    let mut writer = wire
        .writer()
        .expect("dry-run 802.15.4 send target should expose a writer");
    let report = writer
        .write_record(&PacketRecord::new(sample_dot15d4_frame()))
        .expect("dry-run write should produce a send plan");

    assert_eq!(report.backend(), &BackendKind::Whad);
    assert_eq!(report.bytes_requested(), expected_pdu.len());
    assert_eq!(report.bytes_written(), 0);
    assert!(report.is_dry_run());
    let details = report
        .target_details()
        .expect("WHAD dry-run report should include an inspectable plan");
    assert!(details.contains("dot15d4 SendCmd"));
    assert!(details.contains(&format!("channel={DOT15D4_CHANNEL}")));
    assert!(details.contains(&format!("pdu_len={}", expected_pdu.len())));
    // The dry-run write transmitted nothing onto the mock channel.
    assert!(channel.written_bytes().is_empty());
}

#[test]
fn dot15d4_packetwire_live_send_emits_one_send_cmd_after_open() {
    let channel = WhadMockChannel::new();
    queue_dot15d4_discovery(
        &channel,
        dot15d4_command_mask(&[
            proto::dot15d4::Dot15d4Command::Send,
            proto::dot15d4::Dot15d4Command::SendRaw,
            proto::dot15d4::Dot15d4Command::Start,
        ]),
    );

    let wire = PacketWire::whad_serial("mock-whad")
        .dot15d4_send()
        .channel(DOT15D4_CHANNEL)
        .with_mock_channel(channel.clone())
        .live()
        .open()
        .expect("live mock WHAD PacketWire should discover and enter 802.15.4 send mode");
    assert!(wire.has_writer());
    assert!(!wire.has_source());
    // Drain the mode-entry control frames so only the crafted send remains.
    let _open_control_frames = channel.take_written_bytes();

    let expected_pdu = sample_dot15d4_mac_pdu();
    let mut writer = wire
        .writer()
        .expect("live send target should expose a writer");
    let report = writer
        .write_record(&PacketRecord::new(sample_dot15d4_frame()))
        .expect("live mock write should frame one WHAD SendCmd");

    assert_eq!(report.backend(), &BackendKind::Whad);
    assert_eq!(report.bytes_requested(), expected_pdu.len());
    assert_eq!(report.bytes_written(), expected_pdu.len());
    assert!(!report.is_dry_run());

    let messages = decode_written_messages(channel.take_written_bytes());
    assert_eq!(messages.len(), 1);
    assert_dot15d4_send_cmd(&messages[0], u32::from(DOT15D4_CHANNEL), &expected_pdu);
}

#[test]
fn dot15d4_packetwire_open_rejects_device_without_dot15d4_domain() {
    let channel = WhadMockChannel::new();
    queue_message(
        &channel,
        &device_info_response(vec![proto::discovery::Domain::BtLe as u32]),
    );
    queue_message(
        &channel,
        &domain_response(proto::discovery::Domain::BtLe as u32, 0),
    );

    let err = PacketWire::whad_serial("mock-whad")
        .dot15d4_sniff(DOT15D4_CHANNEL)
        .with_mock_channel(channel)
        .live()
        .open()
        .expect_err("non-dot15d4 WHAD devices should fail during open/enter Dot15d4");

    match err {
        WireError::Backend {
            backend,
            operation,
            reason,
        } => {
            assert_eq!(backend, "whad");
            assert_eq!(operation, "enter Dot15d4");
            assert!(reason.contains("Dot15d4 domain"));
        }
        other => panic!("expected WHAD backend error, got {other:?}"),
    }
}

fn sample_dot15d4_frame() -> Packet {
    Dot15d4Radio::on_channel(DOT15D4_CHANNEL)
        / Dot15d4::data()
            .seq(0x2A)
            .dest_short(0x1234, 0x0002)
            .src_short(0x1234, 0x0001)
            .payload(&[0xDE, 0xAD, 0xBE, 0xEF])
}

/// The compiled MAC (+FCS) bytes the writer carries as the PDU: the MAC layer
/// stacked after the `Dot15d4Radio` pseudo-header. The radio descriptor is a
/// metadata pseudo-header and does not contribute to the over-the-air PDU, so
/// compiling the MAC layer on its own reproduces the writer's `pdu` exactly.
fn sample_dot15d4_mac_pdu() -> Vec<u8> {
    let mac = Dot15d4::data()
        .seq(0x2A)
        .dest_short(0x1234, 0x0002)
        .src_short(0x1234, 0x0001)
        .payload(&[0xDE, 0xAD, 0xBE, 0xEF]);
    Packet::from_layer(mac)
        .compile()
        .expect("802.15.4 MAC frame should compile")
        .into_bytes()
}

fn raw_pdu_received() -> proto::Message {
    proto::Message {
        msg: Some(proto::message::Msg::Dot15d4(proto::dot15d4::Message {
            msg: Some(proto::dot15d4::message::Msg::RawPdu(
                proto::dot15d4::RawPduReceived {
                    channel: u32::from(DOT15D4_CHANNEL),
                    rssi: Some(i32::from(DOT15D4_RSSI)),
                    timestamp: Some(123),
                    fcs_validity: true,
                    pdu: MAC_DATA_SHORT_PDU.to_vec(),
                    fcs: 0x1b56,
                    lqi: Some(u32::from(DOT15D4_LQI)),
                },
            )),
        })),
    }
}

fn queue_dot15d4_discovery(channel: &WhadMockChannel, supported_commands: u64) {
    queue_message(
        channel,
        &device_info_response(vec![proto::discovery::Domain::Dot15d4 as u32]),
    );
    queue_message(
        channel,
        &domain_response(proto::discovery::Domain::Dot15d4 as u32, supported_commands),
    );
}

fn dot15d4_command_mask(commands: &[proto::dot15d4::Dot15d4Command]) -> u64 {
    commands
        .iter()
        .fold(0, |mask, command| mask | (1u64 << (*command as u32)))
}

fn assert_dot15d4_send_cmd(message: &proto::Message, channel: u32, expected_pdu: &[u8]) {
    match message.msg.as_ref() {
        Some(proto::message::Msg::Dot15d4(dot15d4)) => match dot15d4.msg.as_ref() {
            Some(proto::dot15d4::message::Msg::Send(command)) => {
                assert_eq!(command.channel, channel);
                assert_eq!(command.pdu, expected_pdu);
            }
            other => panic!("expected dot15d4 SendCmd, got {other:?}"),
        },
        other => panic!("expected top-level dot15d4 message, got {other:?}"),
    }
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
