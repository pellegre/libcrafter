//! WHAD discovery handshake.

use std::time::Duration;

use prost::Message as _;

use super::messages::{
    build_device_info_query, build_domain_query, negotiate_protocol_version,
    parse_device_info_response, parse_domains_response, WhadDeviceInfo, WhadDomains,
};
use super::proto;
use super::transport::{WhadByteChannel, WhadLink};
use super::WHAD_TARGET_PROTOCOL_VERSION;
use crate::wire::{Result, WireError};

const DISCOVERY_RESPONSE_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WhadDevice {
    pub(crate) info: WhadDeviceInfo,
    pub(crate) domains: WhadDomains,
}

pub(crate) fn discover<C: WhadByteChannel>(link: &mut WhadLink<C>) -> Result<WhadDevice> {
    link.send_message(&build_device_info_query(WHAD_TARGET_PROTOCOL_VERSION))?;

    let info_message = recv_discovery_message(link, "discover device info response")?;
    let info = parse_device_info_response(&info_message).map_err(|err| {
        WireError::backend("whad", "discover device info response", err.to_string())
    })?;
    negotiate_protocol_version(&info)?;

    let mut domain_messages = Vec::with_capacity(info.supported_domains.len());
    for domain in &info.supported_domains {
        link.send_message(&build_domain_query(*domain))?;
        domain_messages.push(recv_discovery_message(link, "discover domain response")?);
    }

    let domains = parse_domains_response(&info, domain_messages.iter())
        .map_err(|err| WireError::backend("whad", "discover domain response", err.to_string()))?;

    Ok(WhadDevice { info, domains })
}

fn recv_discovery_message<C: WhadByteChannel>(
    link: &mut WhadLink<C>,
    operation: &'static str,
) -> Result<proto::Message> {
    let bytes = link.recv_message(DISCOVERY_RESPONSE_TIMEOUT)?;
    proto::Message::decode(bytes.as_slice()).map_err(|err| {
        WireError::backend(
            "whad",
            operation,
            format!("malformed WHAD protobuf response: {err}"),
        )
    })
}

#[cfg(all(test, feature = "whad"))]
mod tests {
    use super::super::framing::encode_message;
    use super::super::messages::{WhadDomainCommands, WhadFirmwareVersion};
    use super::super::transport::{LoopbackChannel, WhadByteChannel, WhadLink};
    use super::*;

    #[test]
    fn whad_discover_queries_device_info_and_domains() {
        let mut channel = LoopbackChannel::default();
        channel
            .write_all(&encode_message(&device_info_response()))
            .unwrap();
        channel
            .write_all(&encode_message(&domain_response(
                proto::discovery::Domain::Phy as u32,
                0b101,
            )))
            .unwrap();
        channel
            .write_all(&encode_message(&domain_response(
                proto::discovery::Domain::BtLe as u32,
                0b1011,
            )))
            .unwrap();

        let mut link = WhadLink::new(channel);
        let device = discover(&mut link).expect("WHAD discovery succeeds");

        assert_eq!(
            device.info.device_type,
            proto::discovery::DeviceType::Butterfly as u32
        );
        assert_eq!(device.info.device_id, vec![0x10, 0x20, 0x30, 0x40]);
        assert_eq!(
            device.info.protocol_min_version,
            WHAD_TARGET_PROTOCOL_VERSION
        );
        assert_eq!(device.info.max_speed, 1_000_000);
        assert_eq!(device.info.firmware_author, "whad-team");
        assert_eq!(device.info.firmware_url, "https://example.invalid/firmware");
        assert_eq!(
            device.info.firmware_version,
            WhadFirmwareVersion {
                major: 1,
                minor: 2,
                revision: 3,
            }
        );
        assert_eq!(
            device.info.supported_domains,
            vec![
                proto::discovery::Domain::Phy as u32,
                proto::discovery::Domain::BtLe as u32,
            ]
        );
        assert_eq!(
            device.domains.supported_domains,
            device.info.supported_domains
        );
        assert_eq!(
            device.domains.commands,
            vec![
                WhadDomainCommands {
                    domain: proto::discovery::Domain::Phy as u32,
                    supported_commands: 0b101,
                },
                WhadDomainCommands {
                    domain: proto::discovery::Domain::BtLe as u32,
                    supported_commands: 0b1011,
                },
            ]
        );
    }

    fn device_info_response() -> proto::Message {
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
                        capabilities: vec![
                            proto::discovery::Domain::Phy as u32,
                            proto::discovery::Domain::BtLe as u32,
                        ],
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
}
