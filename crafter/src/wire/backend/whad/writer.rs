//! Packet writer for WHAD BLE raw-PDU transmission.

use crate::wire::record::{BackendKind, PacketRecord};
use crate::wire::writer::{PacketWriter, WriteReport};
use crate::wire::{Result, WireError};
use crate::{BleRadio, Dot15d4, Dot15d4Radio, Packet};

use super::discovery::WhadDevice;
use super::dot15d4::build_dot15d4_send;
use super::framing::encode_frame;
use super::messages::build_send_raw_pdu;
use super::transport::{WhadByteChannel, WhadLink};

use prost::Message as _;

const BLE_ADVERTISING_ACCESS_ADDRESS: u32 = 0x8E89_BED6;

/// IEEE 802.15.4 channel used for a dot15d4 `SendCmd` when the record carries no
/// `Dot15d4Radio` descriptor (the lowest 2.4 GHz channel, channel 11), mirroring
/// the radio descriptor's own default.
const DOT15D4_DEFAULT_CHANNEL: u8 = 11;

/// Inspectable WHAD dry-run write plan.
///
/// Describes the WHAD command a dry-run write planned but did not transmit.
/// `access_address` is carried only for BLE `SendRawPdu` plans; 802.15.4
/// `SendCmd`/`SendRawCmd` plans leave it `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WhadDryRunPlan {
    channel: u8,
    access_address: Option<u32>,
    pdu_len: usize,
    frame: Vec<u8>,
}

impl WhadDryRunPlan {
    /// Channel carried by the planned WHAD command.
    #[cfg(test)]
    pub(crate) const fn channel(&self) -> u8 {
        self.channel
    }

    /// BLE access address carried by the planned `SendRawPdu`, if any.
    ///
    /// 802.15.4 plans have no access address and report `None`.
    #[cfg(test)]
    pub(crate) const fn access_address(&self) -> Option<u32> {
        self.access_address
    }

    /// Raw PDU length carried by the planned WHAD command.
    #[cfg(test)]
    pub(crate) const fn pdu_len(&self) -> usize {
        self.pdu_len
    }

    /// Complete framed WHAD command bytes that dry-run skipped sending.
    #[cfg(test)]
    pub(crate) fn planned_frame(&self) -> &[u8] {
        &self.frame
    }
}

/// WHAD packet writer translating packet records into BLE `SendRawPdu` messages.
pub(crate) struct WhadWriter<C: WhadByteChannel> {
    link: WhadLink<C>,
    dry_run: bool,
    channel: u8,
    last_dry_run_plan: Option<WhadDryRunPlan>,
}

impl<C: WhadByteChannel> WhadWriter<C> {
    /// Create a WHAD writer for a discovered device and default BLE channel.
    pub(crate) fn new(link: WhadLink<C>, _device: WhadDevice, channel: u8) -> Self {
        Self {
            link,
            dry_run: false,
            channel,
            last_dry_run_plan: None,
        }
    }

    /// Create a WHAD writer whose writes are reported without sending.
    pub(crate) fn dry_run(link: WhadLink<C>, device: WhadDevice, channel: u8) -> Self {
        Self::new(link, device, channel).with_dry_run(true)
    }

    /// Set whether writes should avoid live WHAD transport emission.
    pub(crate) const fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// Last dry-run frame this writer planned instead of transmitting.
    #[cfg(test)]
    pub(crate) fn last_dry_run_plan(&self) -> Option<&WhadDryRunPlan> {
        self.last_dry_run_plan.as_ref()
    }

    /// Consume the writer and return the underlying WHAD link.
    #[cfg(test)]
    pub(crate) fn into_link(self) -> WhadLink<C> {
        self.link
    }

    /// Mutably borrow the shared WHAD link.
    #[cfg(test)]
    pub(crate) fn link_mut(&mut self) -> &mut WhadLink<C> {
        &mut self.link
    }

    /// Build a WHAD command message for one packet record.
    ///
    /// An 802.15.4 record (carrying a `Dot15d4Radio` or `Dot15d4` layer) routes
    /// to the dot15d4 `SendCmd` path; every other record is treated as a BLE
    /// raw-PDU transmission, mirroring the existing default.
    fn build_message(&self, record: &PacketRecord) -> Result<WhadSendMessage> {
        let packet = record.packet();
        if is_dot15d4_record(packet) {
            self.build_dot15d4_send_message(packet)
        } else {
            self.build_raw_pdu_message(packet)
        }
    }

    fn build_raw_pdu_message(&self, packet: &Packet) -> Result<WhadSendMessage> {
        let (channel, access_address, pdu) = if let Some((index, radio)) = ble_radio_layer(packet) {
            let mut pdu = Vec::new();
            packet.compile_layers_after_into(index, &mut pdu)?;
            (
                radio.effective_channel_for_backend(),
                radio.effective_access_address_for_backend(),
                pdu,
            )
        } else {
            (
                self.channel,
                BLE_ADVERTISING_ACCESS_ADDRESS,
                packet.compile()?.into_bytes(),
            )
        };

        Ok(WhadSendMessage {
            message: build_send_raw_pdu(channel, access_address, &pdu),
            channel,
            access_address: Some(access_address),
            pdu_len: pdu.len(),
        })
    }

    /// Build a WHAD `dot15d4` `SendCmd` for an 802.15.4 record.
    ///
    /// The channel comes from the `Dot15d4Radio` descriptor (defaulting to
    /// channel 11 when no radio layer is present), and the MAC (+Zigbee) layers
    /// after the radio compile into the PDU bytes. The `Dot15d4Radio` carries no
    /// explicit raw/FCS-control intent, so this emits a `SendCmd` (firmware
    /// appends the FCS) rather than a `SendRawCmd`; a `SendRawCmd` with an
    /// explicit FCS would be used if such intent were added to the descriptor.
    fn build_dot15d4_send_message(&self, packet: &Packet) -> Result<WhadSendMessage> {
        let (channel, pdu) = if let Some((index, radio)) = dot15d4_radio_layer(packet) {
            let mut pdu = Vec::new();
            packet.compile_layers_after_into(index, &mut pdu)?;
            (radio.effective_channel_for_backend(), pdu)
        } else {
            (DOT15D4_DEFAULT_CHANNEL, packet.compile()?.into_bytes())
        };

        let pdu_len = pdu.len();
        Ok(WhadSendMessage {
            message: build_dot15d4_send(u32::from(channel), pdu),
            channel,
            access_address: None,
            pdu_len,
        })
    }
}

impl<C: WhadByteChannel> PacketWriter for WhadWriter<C> {
    fn write_record(&mut self, record: &PacketRecord) -> Result<WriteReport> {
        let send = self.build_message(record)?;
        if self.dry_run {
            let plan = WhadDryRunPlan {
                channel: send.channel,
                access_address: send.access_address,
                pdu_len: send.pdu_len,
                frame: encode_planned_frame(&send.message)?,
            };
            let target_details = dry_run_target_details(&plan);
            self.last_dry_run_plan = Some(plan);

            return Ok(WriteReport::new(BackendKind::Whad, send.pdu_len, 0, true)
                .with_target_details(target_details));
        }

        self.last_dry_run_plan = None;
        self.link.send_message(&send.message)?;
        Ok(WriteReport::new(
            BackendKind::Whad,
            send.pdu_len,
            send.pdu_len,
            false,
        ))
    }
}

struct WhadSendMessage {
    message: super::proto::Message,
    channel: u8,
    access_address: Option<u32>,
    pdu_len: usize,
}

fn encode_planned_frame(message: &super::proto::Message) -> Result<Vec<u8>> {
    let message_bytes = message.encode_to_vec();
    if message_bytes.len() > u16::MAX as usize {
        return Err(WireError::backend(
            "whad writer",
            "dry-run plan",
            "encoded SendRawPdu exceeds WHAD frame length",
        ));
    }

    Ok(encode_frame(&message_bytes))
}

fn dry_run_target_details(plan: &WhadDryRunPlan) -> String {
    match plan.access_address {
        Some(access_address) => format!(
            "whad SendRawPdu dry-run channel={} access_address=0x{:08x} pdu_len={} frame_len={} frame_hex={}",
            plan.channel,
            access_address,
            plan.pdu_len,
            plan.frame.len(),
            hex_bytes(&plan.frame)
        ),
        None => format!(
            "whad dot15d4 SendCmd dry-run channel={} pdu_len={} frame_len={} frame_hex={}",
            plan.channel,
            plan.pdu_len,
            plan.frame.len(),
            hex_bytes(&plan.frame)
        ),
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn ble_radio_layer(packet: &Packet) -> Option<(usize, &BleRadio)> {
    packet.iter().enumerate().find_map(|(index, layer)| {
        layer
            .as_any()
            .downcast_ref::<BleRadio>()
            .map(|radio| (index, radio))
    })
}

/// Find the `Dot15d4Radio` descriptor layer and its index in the packet,
/// mirroring [`ble_radio_layer`] for the 802.15.4 send path.
fn dot15d4_radio_layer(packet: &Packet) -> Option<(usize, &Dot15d4Radio)> {
    packet.iter().enumerate().find_map(|(index, layer)| {
        layer
            .as_any()
            .downcast_ref::<Dot15d4Radio>()
            .map(|radio| (index, radio))
    })
}

/// Whether a packet record is an 802.15.4 record that should route to the
/// dot15d4 `SendCmd` path.
///
/// A record qualifies when it carries either the `Dot15d4Radio` descriptor or
/// the `Dot15d4` MAC layer, mirroring how the BLE path keys off `BleRadio`.
fn is_dot15d4_record(packet: &Packet) -> bool {
    packet.iter().any(|layer| {
        let any = layer.as_any();
        any.is::<Dot15d4Radio>() || any.is::<Dot15d4>()
    })
}

#[cfg(all(test, feature = "whad"))]
mod whad_writer {
    use std::time::Duration;

    use prost::Message as _;

    use super::super::framing::encode_message;
    use super::super::messages::{
        build_send_raw_pdu, WhadDeviceInfo, WhadDomainCommands, WhadDomains, WhadFirmwareVersion,
    };
    use super::super::proto;
    use super::super::transport::{LoopbackChannel, WhadLink};
    use super::*;
    use crate::{BleLlAdv, PacketRecord};

    #[test]
    fn whad_writer_non_dry_run_emits_one_send_raw_pdu() {
        let packet = BleRadio::advertising(39).access_address(0xAABB_CCDD)
            / BleLlAdv::adv_ind()
                .adv_a_str("C0:FF:EE:11:22:33")
                .unwrap()
                .payload([0x02, 0x01, 0x06]);
        let record = PacketRecord::new(packet);
        let expected_pdu = [
            0x40, 0x09, 0x33, 0x22, 0x11, 0xEE, 0xFF, 0xC0, 0x02, 0x01, 0x06,
        ];
        let mut writer =
            WhadWriter::new(WhadLink::new(LoopbackChannel::default()), test_device(), 37);

        let report = writer.write_record(&record).unwrap();

        assert_eq!(report.backend(), &BackendKind::Whad);
        assert_eq!(report.bytes_requested(), expected_pdu.len());
        assert_eq!(report.bytes_written(), expected_pdu.len());
        assert!(!report.is_dry_run());

        let mut link = writer.into_link();
        let message = recv_message(&mut link);
        assert_send_raw_pdu(message, 39, 0xAABB_CCDD, &expected_pdu);
        assert!(link.recv_message(Duration::from_millis(1)).is_err());
    }

    #[test]
    fn whad_dry_run_plan_describes_send_raw_pdu_and_writes_no_loopback_bytes() {
        let packet = BleRadio::advertising(38).access_address(0x1122_3344)
            / BleLlAdv::adv_ind()
                .adv_a_str("C0:FF:EE:11:22:33")
                .unwrap()
                .payload([0x02, 0x01, 0x06]);
        let record = PacketRecord::new(packet);
        let expected_pdu = [
            0x40, 0x09, 0x33, 0x22, 0x11, 0xEE, 0xFF, 0xC0, 0x02, 0x01, 0x06,
        ];
        let expected_message = build_send_raw_pdu(38, 0x1122_3344, &expected_pdu);
        let expected_frame = encode_message(&expected_message);
        let mut writer =
            WhadWriter::dry_run(WhadLink::new(LoopbackChannel::default()), test_device(), 37);

        let report = writer.write_record(&record).unwrap();

        assert_eq!(report.backend(), &BackendKind::Whad);
        assert!(report.is_dry_run());
        assert_eq!(report.bytes_requested(), expected_pdu.len());
        assert_eq!(report.bytes_written(), 0);
        let details = report
            .target_details()
            .expect("dry-run report should describe planned WHAD frame");
        assert!(details.contains("SendRawPdu"));
        assert!(details.contains("channel=38"));
        assert!(details.contains("access_address=0x11223344"));
        assert!(details.contains("pdu_len=11"));
        assert!(details.contains(&format!("frame_hex={}", hex_bytes(&expected_frame))));

        let plan = writer
            .last_dry_run_plan()
            .expect("writer should retain the last dry-run plan");
        assert_eq!(plan.channel(), 38);
        assert_eq!(plan.access_address(), Some(0x1122_3344));
        assert_eq!(plan.pdu_len(), expected_pdu.len());
        assert_eq!(plan.planned_frame(), expected_frame);

        let mut link = writer.into_link();
        assert!(link.recv_message(Duration::from_millis(1)).is_err());
    }

    fn recv_message(link: &mut WhadLink<LoopbackChannel>) -> proto::Message {
        let bytes = link
            .recv_message(Duration::from_millis(20))
            .expect("writer frame should be readable");
        proto::Message::decode(bytes.as_slice()).expect("writer frame should decode")
    }

    fn assert_send_raw_pdu(
        message: proto::Message,
        channel: u8,
        access_address: u32,
        expected_pdu: &[u8],
    ) {
        match message.msg {
            Some(proto::message::Msg::Ble(ble)) => match ble.msg {
                Some(proto::ble::message::Msg::SendRawPdu(command)) => {
                    assert_eq!(command.conn_handle, u32::from(channel));
                    assert_eq!(command.access_address, access_address);
                    assert_eq!(command.pdu, expected_pdu);
                    assert_eq!(command.direction, proto::ble::BleDirection::Unknown as i32);
                    assert_eq!(command.crc, 0);
                    assert!(!command.encrypt);
                    assert_eq!(command.phy, None);
                }
                other => panic!("expected BLE send raw PDU command, got {other:?}"),
            },
            other => panic!("expected top-level BLE message, got {other:?}"),
        }
    }

    fn test_device() -> WhadDevice {
        let ble_domain = proto::discovery::Domain::BtLe as u32;
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
                supported_domains: vec![ble_domain],
            },
            domains: WhadDomains {
                supported_domains: vec![ble_domain],
                commands: vec![WhadDomainCommands {
                    domain: ble_domain,
                    supported_commands: 0,
                }],
            },
        }
    }
}

#[cfg(all(test, feature = "whad"))]
mod dot15d4_writer {
    use std::time::Duration;

    use prost::Message as _;

    use super::super::framing::encode_message;
    use super::super::messages::{
        WhadDeviceInfo, WhadDomainCommands, WhadDomains, WhadFirmwareVersion,
    };
    use super::super::proto;
    use super::super::transport::{LoopbackChannel, WhadLink};
    use super::*;
    use crate::{Dot15d4, Dot15d4Radio, PacketRecord};

    // Lab-safe documentation-style 802.15.4 values: a 2.4 GHz channel and a
    // short-addressed data frame between two PAN devices. The PDU bytes are
    // recomputed by compiling the MAC layer rather than hardcoded so the test
    // tracks the crate's FCS auto-fill.
    const TEST_CHANNEL: u8 = 15;

    fn test_packet() -> Packet {
        Dot15d4Radio::on_channel(TEST_CHANNEL)
            / Dot15d4::data()
                .seq(0x2A)
                .dest_short(0x1234, 0x0002)
                .src_short(0x1234, 0x0001)
                .payload(&[0xDE, 0xAD, 0xBE, 0xEF])
    }

    /// The compiled MAC (+FCS) bytes the writer should carry as the PDU: the
    /// layers after the `Dot15d4Radio` descriptor.
    fn expected_pdu(packet: &Packet) -> Vec<u8> {
        let (index, _radio) =
            dot15d4_radio_layer(packet).expect("test packet carries a Dot15d4Radio layer");
        let mut pdu = Vec::new();
        packet
            .compile_layers_after_into(index, &mut pdu)
            .expect("compile the MAC layers after the radio");
        pdu
    }

    #[test]
    fn dot15d4_writer_non_dry_run_emits_one_send_cmd() {
        let packet = test_packet();
        let expected = expected_pdu(&packet);
        let record = PacketRecord::new(packet);
        let mut writer =
            WhadWriter::new(WhadLink::new(LoopbackChannel::default()), test_device(), 11);

        let report = writer.write_record(&record).unwrap();

        assert_eq!(report.backend(), &BackendKind::Whad);
        assert_eq!(report.bytes_requested(), expected.len());
        assert_eq!(report.bytes_written(), expected.len());
        assert!(!report.is_dry_run());

        let mut link = writer.into_link();
        let message = recv_message(&mut link);
        assert_send_cmd(message, TEST_CHANNEL, &expected);
        // Exactly one frame was emitted.
        assert!(link.recv_message(Duration::from_millis(1)).is_err());
    }

    #[test]
    fn dot15d4_dry_run_plan_describes_send_cmd_and_writes_no_loopback_bytes() {
        let packet = test_packet();
        let expected = expected_pdu(&packet);
        let expected_message = build_dot15d4_send(u32::from(TEST_CHANNEL), expected.clone());
        let expected_frame = encode_message(&expected_message);
        let record = PacketRecord::new(packet);
        let mut writer =
            WhadWriter::dry_run(WhadLink::new(LoopbackChannel::default()), test_device(), 11);

        let report = writer.write_record(&record).unwrap();

        assert_eq!(report.backend(), &BackendKind::Whad);
        assert!(report.is_dry_run());
        assert_eq!(report.bytes_requested(), expected.len());
        assert_eq!(report.bytes_written(), 0);
        let details = report
            .target_details()
            .expect("dry-run report should describe the planned WHAD frame");
        assert!(details.contains("dot15d4 SendCmd"));
        assert!(details.contains(&format!("channel={TEST_CHANNEL}")));
        assert!(details.contains(&format!("pdu_len={}", expected.len())));
        assert!(details.contains(&format!("frame_hex={}", hex_bytes(&expected_frame))));

        let plan = writer
            .last_dry_run_plan()
            .expect("writer should retain the last dry-run plan");
        assert_eq!(plan.channel(), TEST_CHANNEL);
        // 802.15.4 plans carry no BLE access address.
        assert_eq!(plan.access_address(), None);
        assert_eq!(plan.pdu_len(), expected.len());
        assert_eq!(plan.planned_frame(), expected_frame);

        // The dry-run write transmitted nothing onto the loopback channel.
        let mut link = writer.into_link();
        assert!(link.recv_message(Duration::from_millis(1)).is_err());
    }

    fn recv_message(link: &mut WhadLink<LoopbackChannel>) -> proto::Message {
        let bytes = link
            .recv_message(Duration::from_millis(20))
            .expect("writer frame should be readable");
        proto::Message::decode(bytes.as_slice()).expect("writer frame should decode")
    }

    fn assert_send_cmd(message: proto::Message, channel: u8, expected_pdu: &[u8]) {
        match message.msg {
            Some(proto::message::Msg::Dot15d4(dot15d4)) => match dot15d4.msg {
                Some(proto::dot15d4::message::Msg::Send(command)) => {
                    assert_eq!(command.channel, u32::from(channel));
                    assert_eq!(command.pdu, expected_pdu);
                }
                other => panic!("expected dot15d4 SendCmd, got {other:?}"),
            },
            other => panic!("expected top-level dot15d4 message, got {other:?}"),
        }
    }

    fn test_device() -> WhadDevice {
        let dot15d4_domain = proto::discovery::Domain::Dot15d4 as u32;
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
                supported_domains: vec![dot15d4_domain],
            },
            domains: WhadDomains {
                supported_domains: vec![dot15d4_domain],
                commands: vec![WhadDomainCommands {
                    domain: dot15d4_domain,
                    supported_commands: 0,
                }],
            },
        }
    }
}
