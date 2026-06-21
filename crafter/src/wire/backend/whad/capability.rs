//! WHAD BLE capability assertion and mode selection.

#[cfg(feature = "whad")]
use super::discovery::WhadDevice;
#[cfg(feature = "whad")]
use super::messages::{
    build_ble_central_mode, build_ble_domain_query, build_ble_sniff_adv, build_ble_start,
};
#[cfg(feature = "whad")]
use super::proto;
#[cfg(feature = "whad")]
use super::transport::{WhadByteChannel, WhadLink};
#[cfg(feature = "whad")]
use crate::wire::{Result, WireError};

/// BLE operating mode requested for a WHAD serial packet wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WhadBleMode {
    /// Capture BLE advertising PDUs on one advertising channel.
    SniffAdv {
        /// BLE advertising channel, usually 37, 38, or 39.
        channel: u8,
    },
    /// Inject BLE raw PDUs through WHAD's central/raw-PDU path.
    Inject,
}

#[cfg(feature = "whad")]
pub(crate) fn enter_ble<C: WhadByteChannel>(
    link: &mut WhadLink<C>,
    device: &WhadDevice,
    mode: WhadBleMode,
) -> Result<()> {
    assert_ble_capability(device, mode)?;

    link.send_message(&build_ble_domain_query())?;
    match mode {
        WhadBleMode::SniffAdv { channel } => {
            link.send_message(&build_ble_sniff_adv(false, u32::from(channel), Vec::new()))?;
        }
        WhadBleMode::Inject => {
            link.send_message(&build_ble_central_mode())?;
        }
    }
    link.send_message(&build_ble_start())
}

#[cfg(feature = "whad")]
fn assert_ble_capability(device: &WhadDevice, mode: WhadBleMode) -> Result<()> {
    let ble_domain = proto::discovery::Domain::BtLe as u32;
    if !device.domains.supported_domains.contains(&ble_domain) {
        return Err(missing_capability("BLE domain"));
    }

    let commands = device
        .domains
        .commands
        .iter()
        .find(|commands| commands.domain == ble_domain)
        .map(|commands| commands.supported_commands)
        .ok_or_else(|| missing_capability("BLE command table"))?;

    match mode {
        WhadBleMode::SniffAdv { .. } => {
            require_command(commands, proto::ble::BleCommand::SniffAdv, "SniffAdv")?;
        }
        WhadBleMode::Inject => {
            require_command(commands, proto::ble::BleCommand::CentralMode, "CentralMode")?;
            require_command(commands, proto::ble::BleCommand::SendRawPdu, "SendRawPdu")?;
        }
    }
    require_command(commands, proto::ble::BleCommand::Start, "Start")
}

#[cfg(feature = "whad")]
fn require_command(
    commands: u64,
    command: proto::ble::BleCommand,
    capability: &'static str,
) -> Result<()> {
    let bit = 1u64 << command as u32;
    if commands & bit == 0 {
        return Err(missing_capability(capability));
    }

    Ok(())
}

#[cfg(feature = "whad")]
fn missing_capability(capability: &'static str) -> WireError {
    WireError::backend(
        "whad",
        "enter BLE",
        format!("missing required capability: {capability}"),
    )
}

#[cfg(all(test, feature = "whad"))]
mod tests {
    use std::time::Duration;

    use prost::Message as _;

    use super::super::discovery::WhadDevice;
    use super::super::messages::{
        WhadDeviceInfo, WhadDomainCommands, WhadDomains, WhadFirmwareVersion,
    };
    use super::super::transport::LoopbackChannel;
    use super::*;

    #[test]
    fn whad_capability_enter_ble_rejects_non_ble_device() {
        let mut link = WhadLink::new(LoopbackChannel::default());
        let err = enter_ble(
            &mut link,
            &device_with_domains(vec![proto::discovery::Domain::Phy as u32], vec![]),
            WhadBleMode::SniffAdv { channel: 37 },
        )
        .expect_err("non-BLE device should be rejected");

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

    #[test]
    fn whad_capability_enter_ble_rejects_missing_inject_command() {
        let mut link = WhadLink::new(LoopbackChannel::default());
        let err = enter_ble(
            &mut link,
            &ble_device_with_commands(command_mask(&[
                proto::ble::BleCommand::CentralMode,
                proto::ble::BleCommand::Start,
            ])),
            WhadBleMode::Inject,
        )
        .expect_err("BLE device without raw inject should be rejected");

        match err {
            WireError::Backend { reason, .. } => {
                assert!(reason.contains("SendRawPdu"));
            }
            other => panic!("expected WHAD backend error, got {other:?}"),
        }
    }

    #[test]
    fn whad_capability_enter_ble_sniff_succeeds_and_emits_control_frames() {
        let mut link = WhadLink::new(LoopbackChannel::default());
        let device = ble_device_with_commands(command_mask(&[
            proto::ble::BleCommand::SniffAdv,
            proto::ble::BleCommand::Start,
        ]));

        enter_ble(&mut link, &device, WhadBleMode::SniffAdv { channel: 39 })
            .expect("BLE advertising sniff mode should start");

        assert_ble_domain_query(recv_control(&mut link));
        assert_sniff_adv(recv_control(&mut link), 39);
        assert_ble_start(recv_control(&mut link));
    }

    #[test]
    fn whad_capability_enter_ble_inject_succeeds_and_emits_control_frames() {
        let mut link = WhadLink::new(LoopbackChannel::default());
        let device = ble_device_with_commands(command_mask(&[
            proto::ble::BleCommand::CentralMode,
            proto::ble::BleCommand::SendRawPdu,
            proto::ble::BleCommand::Start,
        ]));

        enter_ble(&mut link, &device, WhadBleMode::Inject)
            .expect("BLE raw inject mode should start");

        assert_ble_domain_query(recv_control(&mut link));
        assert_central_mode(recv_control(&mut link));
        assert_ble_start(recv_control(&mut link));
    }

    fn ble_device_with_commands(supported_commands: u64) -> WhadDevice {
        let ble_domain = proto::discovery::Domain::BtLe as u32;
        device_with_domains(
            vec![ble_domain],
            vec![WhadDomainCommands {
                domain: ble_domain,
                supported_commands,
            }],
        )
    }

    fn device_with_domains(
        supported_domains: Vec<u32>,
        commands: Vec<WhadDomainCommands>,
    ) -> WhadDevice {
        WhadDevice {
            info: WhadDeviceInfo {
                device_type: proto::discovery::DeviceType::Butterfly as u32,
                device_id: vec![0x10, 0x20, 0x30, 0x40],
                protocol_min_version: super::super::WHAD_TARGET_PROTOCOL_VERSION,
                max_speed: 1_000_000,
                firmware_author: "whad-team".to_string(),
                firmware_url: "https://example.invalid/firmware".to_string(),
                firmware_version: WhadFirmwareVersion {
                    major: 1,
                    minor: 2,
                    revision: 3,
                },
                supported_domains: supported_domains.clone(),
            },
            domains: WhadDomains {
                supported_domains,
                commands,
            },
        }
    }

    fn command_mask(commands: &[proto::ble::BleCommand]) -> u64 {
        commands
            .iter()
            .fold(0, |mask, command| mask | (1u64 << (*command as u32)))
    }

    fn recv_control(link: &mut WhadLink<LoopbackChannel>) -> proto::Message {
        let bytes = link
            .recv_message(Duration::from_millis(20))
            .expect("control frame should be readable");
        proto::Message::decode(bytes.as_slice()).expect("control frame should decode")
    }

    fn assert_ble_domain_query(message: proto::Message) {
        match message.msg {
            Some(proto::message::Msg::Discovery(discovery)) => match discovery.msg {
                Some(proto::discovery::message::Msg::DomainQuery(query)) => {
                    assert_eq!(query.domain, proto::discovery::Domain::BtLe as u32);
                }
                other => panic!("expected BLE domain query, got {other:?}"),
            },
            other => panic!("expected discovery message, got {other:?}"),
        }
    }

    fn assert_sniff_adv(message: proto::Message, channel: u32) {
        match message.msg {
            Some(proto::message::Msg::Ble(ble)) => match ble.msg {
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

    fn assert_central_mode(message: proto::Message) {
        match message.msg {
            Some(proto::message::Msg::Ble(ble)) => match ble.msg {
                Some(proto::ble::message::Msg::CentralMode(_)) => {}
                other => panic!("expected BLE central-mode command, got {other:?}"),
            },
            other => panic!("expected BLE message, got {other:?}"),
        }
    }

    fn assert_ble_start(message: proto::Message) {
        match message.msg {
            Some(proto::message::Msg::Ble(ble)) => match ble.msg {
                Some(proto::ble::message::Msg::Start(_)) => {}
                other => panic!("expected BLE start command, got {other:?}"),
            },
            other => panic!("expected BLE message, got {other:?}"),
        }
    }
}
