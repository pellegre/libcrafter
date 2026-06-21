#![cfg(feature = "whad")]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::Duration;

pub use crafter::{CrafterError, Result};

pub mod wire {
    pub use crafter::wire::{Result, WireError};
}

pub(crate) const WHAD_TARGET_PROTOCOL_VERSION: u32 = 3;

pub(crate) mod proto {
    #![allow(dead_code)]

    include!(concat!(env!("OUT_DIR"), "/whad_proto.rs"));
}

#[path = "../src/wire/backend/whad/framing.rs"]
mod framing;

#[path = "../src/wire/backend/whad/messages.rs"]
mod messages;

#[path = "../src/wire/backend/whad/transport.rs"]
mod transport;

#[path = "../src/wire/backend/whad/discovery.rs"]
mod discovery;

#[path = "../src/wire/backend/whad/capability.rs"]
mod capability;

use capability::{enter_ble, WhadBleMode};
use discovery::discover;
use messages::{parse_received_pdu, WhadRxPdu};
use prost::Message as _;
use transport::{WhadByteChannel, WhadLink};

const BLE_ADVERTISING_ACCESS_ADDRESS: u32 = 0x8E89_BED6;
const DOC_BLE_ADV_ADDRESS: [u8; 6] = [0x46, 0x53, 0x00, 0x5e, 0x00, 0x00];
const DOC_BLE_FLAGS_AD: [u8; 3] = [0x02, 0x01, 0x06];

#[test]
fn whad_transport_loopback_discovers_enters_ble_and_receives_advertisement() {
    let channel = LoopbackChannel::default();
    channel.queue_message(&device_info_response(vec![
        proto::discovery::Domain::BtLe as u32,
    ]));
    channel.queue_message(&domain_response(
        proto::discovery::Domain::BtLe as u32,
        command_mask(&[
            proto::ble::BleCommand::SniffAdv,
            proto::ble::BleCommand::Start,
        ]),
    ));
    let mut link = WhadLink::new(channel.clone());

    let device = discover(&mut link).expect("WHAD discovery should succeed");
    enter_ble(&mut link, &device, WhadBleMode::SniffAdv { channel: 37 })
        .expect("BLE advertising sniff mode should start");

    channel.queue_message(&advertising_pdu_received());
    let bytes = link
        .recv_message(Duration::from_millis(20))
        .expect("received advertising frame should be readable");
    let decoded = proto::Message::decode(bytes.as_slice()).expect("WHAD frame should decode");
    let received = parse_received_pdu(&decoded).expect("received PDU should parse");

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

    assert_written_messages(channel.written_messages());
}

#[test]
fn whad_transport_loopback_enter_ble_rejects_non_ble_discovery() {
    let channel = LoopbackChannel::default();
    channel.queue_message(&device_info_response(vec![
        proto::discovery::Domain::Phy as u32,
    ]));
    channel.queue_message(&domain_response(proto::discovery::Domain::Phy as u32, 0));
    let mut link = WhadLink::new(channel);

    let device = discover(&mut link).expect("non-BLE WHAD discovery should succeed");
    let err = enter_ble(&mut link, &device, WhadBleMode::SniffAdv { channel: 37 })
        .expect_err("non-BLE device should be rejected");

    match err {
        crafter::wire::WireError::Backend {
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

#[derive(Clone, Default)]
struct LoopbackChannel {
    state: Rc<RefCell<LoopbackState>>,
}

#[derive(Default)]
struct LoopbackState {
    inbound: VecDeque<u8>,
    written: Vec<u8>,
}

impl LoopbackChannel {
    fn queue_message(&self, message: &proto::Message) {
        self.state
            .borrow_mut()
            .inbound
            .extend(framing::encode_message(message));
    }

    fn written_messages(&self) -> Vec<proto::Message> {
        let written = self.state.borrow().written.clone();
        let mut decoder = framing::FrameDecoder::default();
        decoder.push(&written);

        let mut messages = Vec::new();
        while let Some(bytes) = decoder.next() {
            messages.push(proto::Message::decode(bytes.as_slice()).expect("written WHAD message"));
        }
        messages
    }
}

impl WhadByteChannel for LoopbackChannel {
    fn read(&mut self, buf: &mut [u8]) -> wire::Result<usize> {
        let mut state = self.state.borrow_mut();
        let n = buf.len().min(state.inbound.len());
        for slot in &mut buf[..n] {
            *slot = state
                .inbound
                .pop_front()
                .expect("loopback byte disappeared");
        }
        Ok(n)
    }

    fn write_all(&mut self, data: &[u8]) -> wire::Result<()> {
        self.state.borrow_mut().written.extend_from_slice(data);
        Ok(())
    }
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
    }
}

fn command_mask(commands: &[proto::ble::BleCommand]) -> u64 {
    commands
        .iter()
        .fold(0, |mask, command| mask | (1u64 << (*command as u32)))
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

fn assert_written_messages(messages: Vec<proto::Message>) {
    assert_eq!(messages.len(), 5);

    assert_discovery_info_query(&messages[0]);
    assert_domain_query(&messages[1], proto::discovery::Domain::BtLe as u32);
    assert_domain_query(&messages[2], proto::discovery::Domain::BtLe as u32);
    assert_sniff_adv(&messages[3], 37);
    assert_ble_start(&messages[4]);
}

fn assert_discovery_info_query(message: &proto::Message) {
    match message.msg.as_ref() {
        Some(proto::message::Msg::Discovery(discovery)) => match discovery.msg.as_ref() {
            Some(proto::discovery::message::Msg::InfoQuery(query)) => {
                assert_eq!(query.proto_ver, WHAD_TARGET_PROTOCOL_VERSION);
            }
            other => panic!("expected discovery info query, got {other:?}"),
        },
        other => panic!("expected discovery message, got {other:?}"),
    }
}

fn assert_domain_query(message: &proto::Message, domain: u32) {
    match message.msg.as_ref() {
        Some(proto::message::Msg::Discovery(discovery)) => match discovery.msg.as_ref() {
            Some(proto::discovery::message::Msg::DomainQuery(query)) => {
                assert_eq!(query.domain, domain);
            }
            other => panic!("expected discovery domain query, got {other:?}"),
        },
        other => panic!("expected discovery message, got {other:?}"),
    }
}

fn assert_sniff_adv(message: &proto::Message, channel: u32) {
    match message.msg.as_ref() {
        Some(proto::message::Msg::Ble(ble)) => match ble.msg.as_ref() {
            Some(proto::ble::message::Msg::SniffAdv(command)) => {
                assert!(!command.use_extended_adv);
                assert_eq!(command.channel, channel);
                assert!(command.bd_address.is_empty());
            }
            other => panic!("expected BLE advertising sniff command, got {other:?}"),
        },
        other => panic!("expected BLE message, got {other:?}"),
    }
}

fn assert_ble_start(message: &proto::Message) {
    match message.msg.as_ref() {
        Some(proto::message::Msg::Ble(ble)) => match ble.msg.as_ref() {
            Some(proto::ble::message::Msg::Start(_)) => {}
            other => panic!("expected BLE start command, got {other:?}"),
        },
        other => panic!("expected BLE message, got {other:?}"),
    }
}
