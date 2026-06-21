//! Packet writer for WHAD BLE raw-PDU transmission.

use crate::wire::record::{BackendKind, PacketRecord};
use crate::wire::writer::{PacketWriter, WriteReport};
use crate::wire::Result;
use crate::{BleRadio, Packet};

use super::discovery::WhadDevice;
use super::messages::build_send_raw_pdu;
use super::transport::{WhadByteChannel, WhadLink};

const BLE_ADVERTISING_ACCESS_ADDRESS: u32 = 0x8E89_BED6;

/// WHAD packet writer translating packet records into BLE `SendRawPdu` messages.
pub(crate) struct WhadWriter<C: WhadByteChannel> {
    link: WhadLink<C>,
    device: WhadDevice,
    dry_run: bool,
    channel: u8,
}

impl<C: WhadByteChannel> WhadWriter<C> {
    /// Create a WHAD writer for a discovered device and default BLE channel.
    pub(crate) fn new(link: WhadLink<C>, device: WhadDevice, channel: u8) -> Self {
        Self {
            link,
            device,
            dry_run: false,
            channel,
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

    /// Borrow the discovered WHAD device metadata associated with this writer.
    pub(crate) const fn device(&self) -> &WhadDevice {
        &self.device
    }

    /// Configured fallback BLE channel used when a packet has no radio layer.
    pub(crate) const fn channel(&self) -> u8 {
        self.channel
    }

    /// Return true when this writer only reports planned writes.
    pub(crate) const fn is_dry_run(&self) -> bool {
        self.dry_run
    }

    /// Consume the writer and return the underlying WHAD link.
    pub(crate) fn into_link(self) -> WhadLink<C> {
        self.link
    }

    fn build_raw_pdu_message(
        &self,
        record: &PacketRecord,
    ) -> Result<(super::proto::Message, usize)> {
        let packet = record.packet();
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

        let requested = pdu.len();
        Ok((build_send_raw_pdu(channel, access_address, &pdu), requested))
    }
}

impl<C: WhadByteChannel> PacketWriter for WhadWriter<C> {
    fn write_record(&mut self, record: &PacketRecord) -> Result<WriteReport> {
        let (message, requested) = self.build_raw_pdu_message(record)?;
        if !self.dry_run {
            self.link.send_message(&message)?;
        }

        let written = if self.dry_run { 0 } else { requested };
        Ok(WriteReport::new(
            BackendKind::Whad,
            requested,
            written,
            self.dry_run,
        ))
    }
}

fn ble_radio_layer(packet: &Packet) -> Option<(usize, &BleRadio)> {
    packet.iter().enumerate().find_map(|(index, layer)| {
        layer
            .as_any()
            .downcast_ref::<BleRadio>()
            .map(|radio| (index, radio))
    })
}

#[cfg(all(test, feature = "whad"))]
mod whad_writer {
    use std::time::Duration;

    use prost::Message as _;

    use super::super::messages::{
        WhadDeviceInfo, WhadDomainCommands, WhadDomains, WhadFirmwareVersion,
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
    fn whad_writer_dry_run_emits_nothing_and_reports_dry_run() {
        let packet = BleRadio::advertising(38)
            / BleLlAdv::adv_nonconn_ind()
                .adv_a_str("C0:FF:EE:11:22:33")
                .unwrap();
        let record = PacketRecord::new(packet);
        let mut writer =
            WhadWriter::dry_run(WhadLink::new(LoopbackChannel::default()), test_device(), 37);

        let report = writer.write_record(&record).unwrap();

        assert_eq!(report.backend(), &BackendKind::Whad);
        assert!(report.is_dry_run());
        assert_eq!(report.bytes_written(), 0);

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
