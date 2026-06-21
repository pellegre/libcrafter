//! Typed WHAD discovery message helpers.

#![allow(dead_code)]

use crate::{CrafterError, Result};

use super::proto;

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
        supported_domains: response.capabilities.clone(),
    })
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
        proto::Message::decode(encoded.as_slice()).expect("WHAD message decodes")
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
                capabilities: vec![
                    proto::discovery::Domain::Phy as u32,
                    proto::discovery::Domain::BtLe as u32,
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
}
