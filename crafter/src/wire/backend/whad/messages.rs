//! Typed WHAD message helpers.

#![allow(dead_code)]

use crate::wire::{Result as WireResult, WireError};
use crate::{CrafterError, Result};

use super::proto;
use super::WHAD_TARGET_PROTOCOL_VERSION;

const BLE_ADVERTISING_ACCESS_ADDRESS: u32 = 0x8E89_BED6;
const BLE_ADDRESS_LEN: usize = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WhadFirmwareVersion {
    pub(crate) major: u32,
    pub(crate) minor: u32,
    pub(crate) revision: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WhadDeviceInfo {
    pub(crate) device_type: u32,
    pub(crate) device_id: Vec<u8>,
    pub(crate) protocol_min_version: u32,
    pub(crate) max_speed: u32,
    pub(crate) firmware_author: String,
    pub(crate) firmware_url: String,
    pub(crate) firmware_version: WhadFirmwareVersion,
    pub(crate) supported_domains: Vec<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WhadDomainCommands {
    pub(crate) domain: u32,
    pub(crate) supported_commands: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct WhadDomains {
    pub(crate) supported_domains: Vec<u32>,
    pub(crate) commands: Vec<WhadDomainCommands>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WhadRxPdu {
    pub(crate) channel: u8,
    pub(crate) rssi: i16,
    pub(crate) crc_valid: bool,
    pub(crate) access_address: u32,
    pub(crate) pdu: Vec<u8>,
}

pub(crate) fn build_device_info_query(proto_ver: u32) -> proto::Message {
    build_discovery_message(proto::discovery::message::Msg::InfoQuery(
        proto::discovery::DeviceInfoQuery { proto_ver },
    ))
}

pub(crate) fn build_domain_query(domain: u32) -> proto::Message {
    build_discovery_message(proto::discovery::message::Msg::DomainQuery(
        proto::discovery::DeviceDomainInfoQuery { domain },
    ))
}

pub(crate) fn build_device_reset_query() -> proto::Message {
    build_discovery_message(proto::discovery::message::Msg::ResetQuery(
        proto::discovery::DeviceResetQuery {},
    ))
}

pub(crate) fn build_ble_domain_query() -> proto::Message {
    build_domain_query(proto::discovery::Domain::BtLe as u32)
}

pub(crate) fn build_ble_sniff_adv(
    use_extended_adv: bool,
    channel: u32,
    bd_address: impl Into<Vec<u8>>,
) -> proto::Message {
    build_ble_message(proto::ble::message::Msg::SniffAdv(
        proto::ble::SniffAdvCmd {
            use_extended_adv,
            channel,
            bd_address: bd_address.into(),
        },
    ))
}

pub(crate) fn build_ble_scan_mode(active_scan: bool) -> proto::Message {
    build_ble_message(proto::ble::message::Msg::ScanMode(
        proto::ble::ScanModeCmd { active_scan },
    ))
}

pub(crate) fn build_ble_central_mode() -> proto::Message {
    build_ble_message(proto::ble::message::Msg::CentralMode(
        proto::ble::CentralModeCmd {},
    ))
}

pub(crate) fn build_ble_peripheral_mode(
    scan_data: impl Into<Vec<u8>>,
    scanrsp_data: impl Into<Vec<u8>>,
) -> proto::Message {
    build_ble_message(proto::ble::message::Msg::PeriphMode(
        proto::ble::PeripheralModeCmd {
            scan_data: scan_data.into(),
            scanrsp_data: scanrsp_data.into(),
        },
    ))
}

pub(crate) fn build_ble_start() -> proto::Message {
    build_ble_message(proto::ble::message::Msg::Start(proto::ble::StartCmd {}))
}

pub(crate) fn build_ble_stop() -> proto::Message {
    build_ble_message(proto::ble::message::Msg::Stop(proto::ble::StopCmd {}))
}

pub(crate) fn build_send_raw_pdu(channel: u8, access_address: u32, pdu: &[u8]) -> proto::Message {
    build_ble_message(proto::ble::message::Msg::SendRawPdu(
        proto::ble::SendRawPduCmd {
            direction: proto::ble::BleDirection::Unknown as i32,
            conn_handle: u32::from(channel),
            access_address,
            pdu: pdu.to_vec(),
            crc: 0,
            encrypt: false,
            phy: None,
        },
    ))
}

pub(crate) fn parse_received_pdu(message: &proto::Message) -> Option<WhadRxPdu> {
    let ble = match message.msg.as_ref()? {
        proto::message::Msg::Ble(ble) => ble,
        _ => return None,
    };

    match ble.msg.as_ref()? {
        proto::ble::message::Msg::AdvPdu(received) => parse_adv_pdu_received(received),
        proto::ble::message::Msg::RawPdu(received) => parse_raw_pdu_received(received),
        _ => None,
    }
}

/// WHAD packs the domain in the top byte of each `capabilities` entry and the
/// capability flags (Scan/Sniff/Inject/...) in the low bits. The discovery flow
/// queries domains by ID, so isolate the domain bits. The real firmware ORs in
/// capability flags that the clean-value unit fixtures never exercised, which is
/// why querying the raw entries made the device reject the bogus domain.
const WHAD_DOMAIN_MASK: u32 = 0xFF00_0000;

fn domains_from_capabilities(capabilities: &[u32]) -> Vec<u32> {
    let mut domains = Vec::new();
    for capability in capabilities {
        let domain = capability & WHAD_DOMAIN_MASK;
        if domain != 0 && !domains.contains(&domain) {
            domains.push(domain);
        }
    }
    domains
}

pub(crate) fn parse_device_info_response(message: &proto::Message) -> Result<WhadDeviceInfo> {
    let response = match discovery_payload(message)? {
        proto::discovery::message::Msg::InfoResp(response) => response,
        _ => {
            return Err(CrafterError::invalid_field_value(
                "whad.discovery.message",
                "expected device info response",
            ));
        }
    };

    Ok(WhadDeviceInfo {
        device_type: response.r#type,
        device_id: response.devid.clone(),
        protocol_min_version: response.proto_min_ver,
        max_speed: response.max_speed,
        firmware_author: String::from_utf8_lossy(&response.fw_author).into_owned(),
        firmware_url: String::from_utf8_lossy(&response.fw_url).into_owned(),
        firmware_version: WhadFirmwareVersion {
            major: response.fw_version_major,
            minor: response.fw_version_minor,
            revision: response.fw_version_rev,
        },
        supported_domains: domains_from_capabilities(&response.capabilities),
    })
}

pub(crate) fn negotiate_protocol_version(device_info: &WhadDeviceInfo) -> WireResult<u32> {
    let device_min_version = device_info.protocol_min_version;
    if device_min_version <= WHAD_TARGET_PROTOCOL_VERSION {
        return Ok(device_min_version);
    }

    Err(WireError::backend(
        "whad",
        "protocol version negotiation",
        format!(
            "device requires WHAD protocol version {device_min_version} or newer; libcrafter is pinned to {WHAD_TARGET_PROTOCOL_VERSION}"
        ),
    ))
}

pub(crate) fn parse_domain_response(message: &proto::Message) -> Result<WhadDomainCommands> {
    let response = match discovery_payload(message)? {
        proto::discovery::message::Msg::DomainResp(response) => response,
        _ => {
            return Err(CrafterError::invalid_field_value(
                "whad.discovery.message",
                "expected domain response",
            ));
        }
    };

    Ok(WhadDomainCommands {
        domain: response.domain,
        supported_commands: response.supported_commands,
    })
}

pub(crate) fn parse_domains_response<'a>(
    device_info: &WhadDeviceInfo,
    messages: impl IntoIterator<Item = &'a proto::Message>,
) -> Result<WhadDomains> {
    let mut commands = Vec::new();
    for message in messages {
        commands.push(parse_domain_response(message)?);
    }

    Ok(WhadDomains {
        supported_domains: device_info.supported_domains.clone(),
        commands,
    })
}

fn build_discovery_message(msg: proto::discovery::message::Msg) -> proto::Message {
    proto::Message {
        msg: Some(proto::message::Msg::Discovery(proto::discovery::Message {
            msg: Some(msg),
        })),
    }
}

fn build_ble_message(msg: proto::ble::message::Msg) -> proto::Message {
    proto::Message {
        msg: Some(proto::message::Msg::Ble(proto::ble::Message {
            msg: Some(msg),
        })),
    }
}

fn parse_adv_pdu_received(received: &proto::ble::AdvPduReceived) -> Option<WhadRxPdu> {
    let channel = u8::try_from(received.channel).ok()?;
    let mut pdu = Vec::with_capacity(2 + received.bd_address.len() + received.adv_data.len());
    let payload_len = received
        .bd_address
        .len()
        .checked_add(received.adv_data.len())?;
    let payload_len = u8::try_from(payload_len).ok()?;

    if received.bd_address.len() != BLE_ADDRESS_LEN {
        return None;
    }

    let pdu_type = whad_adv_type_to_pdu_bits(received.adv_type)?;
    let tx_add = whad_addr_type_is_random(received.addr_type)?;

    pdu.push(pdu_type | (u8::from(tx_add) << 6));
    pdu.push(payload_len);
    pdu.extend_from_slice(&received.bd_address);
    pdu.extend_from_slice(&received.adv_data);

    // AdvPduReceived does not carry access-address or CRC-validity fields.
    // WHAD firmware already accepted the advertisement, so the crate maps it
    // to the advertising access address with a valid CRC. The reported PHY is
    // also ignored here; WhadRxPdu is intentionally just radio metadata plus
    // the Link Layer PDU bytes needed by the later backend step.
    Some(WhadRxPdu {
        channel,
        rssi: saturating_i32_to_i16(received.rssi),
        crc_valid: true,
        access_address: BLE_ADVERTISING_ACCESS_ADDRESS,
        pdu,
    })
}

fn parse_raw_pdu_received(received: &proto::ble::RawPduReceived) -> Option<WhadRxPdu> {
    // Direction, timestamps, connection handle, CRC bytes, processed/decrypted
    // status, and PHY are firmware annotations outside this helper's descriptor
    // plus raw-PDU contract.
    Some(WhadRxPdu {
        channel: u8::try_from(received.channel).ok()?,
        rssi: saturating_i32_to_i16(received.rssi.unwrap_or(0)),
        crc_valid: received.crc_validity.unwrap_or(false),
        access_address: received.access_address,
        pdu: received.pdu.clone(),
    })
}

fn whad_adv_type_to_pdu_bits(adv_type: i32) -> Option<u8> {
    match proto::ble::BleAdvType::try_from(adv_type).ok()? {
        proto::ble::BleAdvType::AdvInd => Some(0x0),
        proto::ble::BleAdvType::AdvDirectInd => Some(0x1),
        proto::ble::BleAdvType::AdvNonconnInd => Some(0x2),
        proto::ble::BleAdvType::AdvScanRsp => Some(0x4),
        proto::ble::BleAdvType::AdvScanInd => Some(0x6),
        proto::ble::BleAdvType::AdvUnknown
        | proto::ble::BleAdvType::AdvExtInd
        | proto::ble::BleAdvType::AdvDecisionInd => None,
    }
}

fn whad_addr_type_is_random(addr_type: i32) -> Option<bool> {
    match proto::ble::BleAddrType::try_from(addr_type).ok()? {
        proto::ble::BleAddrType::Public => Some(false),
        proto::ble::BleAddrType::Random | proto::ble::BleAddrType::Rpa => Some(true),
    }
}

fn saturating_i32_to_i16(value: i32) -> i16 {
    value.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16
}

fn discovery_payload(message: &proto::Message) -> Result<&proto::discovery::message::Msg> {
    let discovery = match message.msg.as_ref() {
        Some(proto::message::Msg::Discovery(discovery)) => discovery,
        _ => {
            return Err(CrafterError::invalid_field_value(
                "whad.message",
                "expected discovery message",
            ));
        }
    };

    discovery.msg.as_ref().ok_or_else(|| {
        CrafterError::invalid_field_value("whad.discovery.message", "expected discovery payload")
    })
}

#[cfg(all(test, feature = "whad"))]
mod tests {
    use prost::Message as _;

    use super::*;

    fn decode_top_level(message: &proto::Message) -> proto::Message {
        let encoded = message.encode_to_vec();
        assert!(!encoded.is_empty());
        proto::Message::decode(encoded.as_slice()).expect("WHAD message decodes")
    }

    fn device_info_with_protocol_min_version(protocol_min_version: u32) -> WhadDeviceInfo {
        WhadDeviceInfo {
            device_type: proto::discovery::DeviceType::Butterfly as u32,
            device_id: vec![0x10, 0x20, 0x30, 0x40],
            protocol_min_version,
            max_speed: 1_000_000,
            firmware_author: "whad-team".to_string(),
            firmware_url: "https://example.invalid/firmware".to_string(),
            firmware_version: WhadFirmwareVersion {
                major: 1,
                minor: 2,
                revision: 3,
            },
            supported_domains: vec![proto::discovery::Domain::BtLe as u32],
        }
    }

    #[test]
    fn whad_discovery_device_info_query_round_trips() {
        let decoded = decode_top_level(&build_device_info_query(3));

        match decoded.msg {
            Some(proto::message::Msg::Discovery(discovery)) => match discovery.msg {
                Some(proto::discovery::message::Msg::InfoQuery(query)) => {
                    assert_eq!(query.proto_ver, 3);
                }
                _ => panic!("expected discovery info query"),
            },
            _ => panic!("expected top-level discovery message"),
        }
    }

    #[test]
    fn whad_discovery_domain_query_round_trips() {
        let domain = proto::discovery::Domain::BtLe as u32;
        let decoded = decode_top_level(&build_domain_query(domain));

        match decoded.msg {
            Some(proto::message::Msg::Discovery(discovery)) => match discovery.msg {
                Some(proto::discovery::message::Msg::DomainQuery(query)) => {
                    assert_eq!(query.domain, domain);
                }
                _ => panic!("expected discovery domain query"),
            },
            _ => panic!("expected top-level discovery message"),
        }
    }

    #[test]
    fn whad_discovery_responses_parse_after_encode() {
        let info_message = build_discovery_message(proto::discovery::message::Msg::InfoResp(
            proto::discovery::DeviceInfoResp {
                r#type: proto::discovery::DeviceType::Butterfly as u32,
                devid: vec![0x10, 0x20, 0x30, 0x40],
                proto_min_ver: 2,
                max_speed: 1_000_000,
                fw_author: b"whad-team".to_vec(),
                fw_url: b"https://example.invalid/firmware".to_vec(),
                fw_version_major: 1,
                fw_version_minor: 2,
                fw_version_rev: 3,
                // Real firmware ORs capability flags into the low byte; parse
                // must mask them off to recover the domain IDs (regression).
                capabilities: vec![
                    proto::discovery::Domain::Phy as u32 | 0x01, // | Scan
                    proto::discovery::Domain::BtLe as u32 | 0x06, // | Inject | Sniff
                ],
            },
        ));
        let decoded_info_message = decode_top_level(&info_message);
        let device_info =
            parse_device_info_response(&decoded_info_message).expect("device info response parses");

        assert_eq!(
            device_info.device_type,
            proto::discovery::DeviceType::Butterfly as u32
        );
        assert_eq!(device_info.device_id, vec![0x10, 0x20, 0x30, 0x40]);
        assert_eq!(device_info.protocol_min_version, 2);
        assert_eq!(device_info.max_speed, 1_000_000);
        assert_eq!(device_info.firmware_author, "whad-team");
        assert_eq!(device_info.firmware_url, "https://example.invalid/firmware");
        assert_eq!(
            device_info.firmware_version,
            WhadFirmwareVersion {
                major: 1,
                minor: 2,
                revision: 3,
            }
        );
        assert_eq!(
            device_info.supported_domains,
            vec![
                proto::discovery::Domain::Phy as u32,
                proto::discovery::Domain::BtLe as u32,
            ]
        );

        let domain_message = build_discovery_message(proto::discovery::message::Msg::DomainResp(
            proto::discovery::DeviceDomainInfoResp {
                domain: proto::discovery::Domain::BtLe as u32,
                supported_commands: 0b1011,
            },
        ));
        let decoded_domain_message = decode_top_level(&domain_message);
        let domain =
            parse_domain_response(&decoded_domain_message).expect("domain response parses");

        assert_eq!(domain.domain, proto::discovery::Domain::BtLe as u32);
        assert_eq!(domain.supported_commands, 0b1011);

        let domains = parse_domains_response(&device_info, [&decoded_domain_message])
            .expect("domains response parses");
        assert_eq!(domains.supported_domains, device_info.supported_domains);
        assert_eq!(domains.commands, vec![domain]);
    }

    #[test]
    fn whad_version_compatible_device_minimum_passes() {
        let device_info = device_info_with_protocol_min_version(WHAD_TARGET_PROTOCOL_VERSION - 1);

        assert_eq!(
            negotiate_protocol_version(&device_info).expect("protocol version is compatible"),
            WHAD_TARGET_PROTOCOL_VERSION - 1
        );
    }

    #[test]
    fn whad_version_incompatible_device_minimum_returns_backend_error() {
        let device_info = device_info_with_protocol_min_version(WHAD_TARGET_PROTOCOL_VERSION + 1);
        let err = negotiate_protocol_version(&device_info).expect_err("version mismatch errors");

        match err {
            WireError::Backend {
                backend,
                operation,
                reason,
            } => {
                assert_eq!(backend, "whad");
                assert_eq!(operation, "protocol version negotiation");
                assert!(reason.contains("device requires WHAD protocol version 4 or newer"));
                assert!(reason.contains("libcrafter is pinned to 3"));
            }
            other => panic!("expected WHAD backend error, got {other:?}"),
        }
    }

    #[test]
    fn whad_device_msgs_reset_and_ble_domain_encode() {
        let decoded_reset = decode_top_level(&build_device_reset_query());
        match decoded_reset.msg {
            Some(proto::message::Msg::Discovery(discovery)) => match discovery.msg {
                Some(proto::discovery::message::Msg::ResetQuery(_)) => {}
                _ => panic!("expected discovery reset query"),
            },
            _ => panic!("expected top-level discovery message"),
        }

        let decoded_domain = decode_top_level(&build_ble_domain_query());
        match decoded_domain.msg {
            Some(proto::message::Msg::Discovery(discovery)) => match discovery.msg {
                Some(proto::discovery::message::Msg::DomainQuery(query)) => {
                    assert_eq!(query.domain, proto::discovery::Domain::BtLe as u32);
                }
                _ => panic!("expected discovery BLE domain query"),
            },
            _ => panic!("expected top-level discovery message"),
        }
    }

    #[test]
    fn whad_device_msgs_ble_sniff_and_scan_modes_encode() {
        let decoded_sniff = decode_top_level(&build_ble_sniff_adv(
            false,
            37,
            [0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
        ));
        match decoded_sniff.msg {
            Some(proto::message::Msg::Ble(ble)) => match ble.msg {
                Some(proto::ble::message::Msg::SniffAdv(command)) => {
                    assert!(!command.use_extended_adv);
                    assert_eq!(command.channel, 37);
                    assert_eq!(command.bd_address, vec![0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
                }
                _ => panic!("expected BLE sniff advertising command"),
            },
            _ => panic!("expected top-level BLE message"),
        }

        let decoded_scan = decode_top_level(&build_ble_scan_mode(true));
        match decoded_scan.msg {
            Some(proto::message::Msg::Ble(ble)) => match ble.msg {
                Some(proto::ble::message::Msg::ScanMode(command)) => {
                    assert!(command.active_scan);
                }
                _ => panic!("expected BLE scan mode command"),
            },
            _ => panic!("expected top-level BLE message"),
        }
    }

    #[test]
    fn whad_device_msgs_ble_inject_modes_encode() {
        let decoded_central = decode_top_level(&build_ble_central_mode());
        match decoded_central.msg {
            Some(proto::message::Msg::Ble(ble)) => match ble.msg {
                Some(proto::ble::message::Msg::CentralMode(_)) => {}
                _ => panic!("expected BLE central mode command"),
            },
            _ => panic!("expected top-level BLE message"),
        }

        let decoded_peripheral = decode_top_level(&build_ble_peripheral_mode(
            [0x02, 0x01, 0x06],
            [0x03, 0x09, b'c'],
        ));
        match decoded_peripheral.msg {
            Some(proto::message::Msg::Ble(ble)) => match ble.msg {
                Some(proto::ble::message::Msg::PeriphMode(command)) => {
                    assert_eq!(command.scan_data, vec![0x02, 0x01, 0x06]);
                    assert_eq!(command.scanrsp_data, vec![0x03, 0x09, b'c']);
                }
                _ => panic!("expected BLE peripheral mode command"),
            },
            _ => panic!("expected top-level BLE message"),
        }
    }

    #[test]
    fn whad_device_msgs_ble_start_stop_encode() {
        let decoded_start = decode_top_level(&build_ble_start());
        match decoded_start.msg {
            Some(proto::message::Msg::Ble(ble)) => match ble.msg {
                Some(proto::ble::message::Msg::Start(_)) => {}
                _ => panic!("expected BLE start command"),
            },
            _ => panic!("expected top-level BLE message"),
        }

        let decoded_stop = decode_top_level(&build_ble_stop());
        match decoded_stop.msg {
            Some(proto::message::Msg::Ble(ble)) => match ble.msg {
                Some(proto::ble::message::Msg::Stop(_)) => {}
                _ => panic!("expected BLE stop command"),
            },
            _ => panic!("expected top-level BLE message"),
        }
    }

    #[test]
    fn whad_ble_msgs_send_raw_pdu_round_trips() {
        let pdu = [0x42, 0x03, 0x02, 0x01, 0x06];
        let decoded = decode_top_level(&build_send_raw_pdu(
            38,
            BLE_ADVERTISING_ACCESS_ADDRESS,
            &pdu,
        ));

        match decoded.msg {
            Some(proto::message::Msg::Ble(ble)) => match ble.msg {
                Some(proto::ble::message::Msg::SendRawPdu(command)) => {
                    assert_eq!(command.conn_handle, 38);
                    assert_eq!(command.access_address, BLE_ADVERTISING_ACCESS_ADDRESS);
                    assert_eq!(command.pdu, pdu);
                    assert_eq!(command.direction, proto::ble::BleDirection::Unknown as i32);
                    assert_eq!(command.crc, 0);
                    assert!(!command.encrypt);
                    assert_eq!(command.phy, None);
                }
                _ => panic!("expected BLE send raw PDU command"),
            },
            _ => panic!("expected top-level BLE message"),
        }
    }

    #[test]
    fn whad_ble_msgs_received_adv_pdu_parses() {
        let message = build_ble_message(proto::ble::message::Msg::AdvPdu(
            proto::ble::AdvPduReceived {
                adv_type: proto::ble::BleAdvType::AdvNonconnInd as i32,
                rssi: -42,
                bd_address: vec![0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
                adv_data: vec![0x02, 0x01, 0x06],
                addr_type: proto::ble::BleAddrType::Random as i32,
                channel: 39,
                phy: proto::ble::BlePhy::Le1m as i32,
            },
        ));

        let received = parse_received_pdu(&message).expect("advertising PDU parses");

        assert_eq!(
            received,
            WhadRxPdu {
                channel: 39,
                rssi: -42,
                crc_valid: true,
                access_address: BLE_ADVERTISING_ACCESS_ADDRESS,
                pdu: vec![0x42, 0x09, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x02, 0x01, 0x06],
            }
        );
    }
}
