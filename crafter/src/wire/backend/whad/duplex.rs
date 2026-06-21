//! Shared-link send/receive support for WHAD BLE traffic.

use std::time::{Duration, Instant};

use crate::packet::IntoPacket;
use crate::wire::record::PacketRecord;
use crate::wire::writer::PacketWriter;
use crate::wire::Result;

use super::discovery::WhadDevice;
use super::reader::read_record_from_link_until;
use super::transport::{WhadByteChannel, WhadLink};
use super::writer::WhadWriter;

/// WHAD BLE inject-then-capture handle over one framed link.
///
/// WHAD dongles are half-duplex from the host's perspective: firmware and the
/// serial link arbitrate radio TX/RX, and the host cannot transmit and receive
/// simultaneously. This handle keeps one shared [`WhadLink`] behind the writer
/// and reads replies from the same link after injection.
pub(crate) struct WhadDuplex<C: WhadByteChannel> {
    writer: WhadWriter<C>,
}

impl<C: WhadByteChannel> WhadDuplex<C> {
    /// Create a WHAD duplex handle for a discovered device and fallback BLE channel.
    pub(crate) fn new(link: WhadLink<C>, device: WhadDevice, channel: u8) -> Self {
        Self {
            writer: WhadWriter::new(link, device, channel),
        }
    }

    /// Inject a packet, then return the first captured record accepted by `match_fn`.
    pub(crate) fn send_recv<P, F>(
        &mut self,
        packet: P,
        mut match_fn: F,
        timeout: Duration,
    ) -> Result<Option<PacketRecord>>
    where
        P: IntoPacket,
        F: FnMut(&PacketRecord) -> bool,
    {
        let record = PacketRecord::new(packet);
        self.writer.write_record(&record)?;

        let start = Instant::now();
        let deadline = start.checked_add(timeout).unwrap_or(start);
        loop {
            let Some(record) = read_record_from_link_until(self.writer.link_mut(), deadline)?
            else {
                return Ok(None);
            };

            if match_fn(&record) {
                return Ok(Some(record));
            }
        }
    }
}

#[cfg(all(test, feature = "whad"))]
mod whad_send_recv {
    use std::collections::VecDeque;

    use super::super::framing::encode_message;
    use super::super::messages::{
        WhadDeviceInfo, WhadDomainCommands, WhadDomains, WhadFirmwareVersion,
    };
    use super::super::proto;
    use super::super::transport::LoopbackChannel;
    use super::*;
    use crate::{BleLlAdv, BleRadio, MacAddr};

    const BLE_ADVERTISING_ACCESS_ADDRESS: u32 = 0x8E89_BED6;
    const SCANNER_ADDRESS: &str = "02:00:00:00:00:01";
    const ADVERTISER_ADDRESS: &str = "C0:FF:EE:11:22:33";
    const ADVERTISER_ADDRESS_DISPLAY: [u8; 6] = [0xC0, 0xFF, 0xEE, 0x11, 0x22, 0x33];
    const ADVERTISER_ADDRESS_ON_AIR: [u8; 6] = [0x33, 0x22, 0x11, 0xEE, 0xFF, 0xC0];

    #[test]
    fn whad_send_recv_scan_req_returns_matching_scan_rsp() {
        let scan_req = BleRadio::advertising(37)
            / BleLlAdv::scan_req()
                .adv_a_str(SCANNER_ADDRESS)
                .unwrap()
                .target_a_str(ADVERTISER_ADDRESS)
                .unwrap();
        let channel = ScriptedLoopbackChannel::respond_after_write(scan_rsp_received());
        let mut duplex = WhadDuplex::new(WhadLink::new(channel), test_device(), 37);

        let record = duplex
            .send_recv(
                scan_req,
                |record| record.packet().summary().contains("SCAN_RSP"),
                Duration::from_millis(50),
            )
            .expect("WHAD send/receive should succeed")
            .expect("scripted scan response should match");

        let adv = record
            .packet()
            .layer::<BleLlAdv>()
            .expect("response should decode to BLE advertising PDU");
        assert_eq!(
            adv.adv_a_value().unwrap(),
            MacAddr::new(ADVERTISER_ADDRESS_DISPLAY)
        );
        assert_eq!(
            record
                .packet()
                .layer::<BleRadio>()
                .expect("response should include radio metadata")
                .effective_access_address_for_backend(),
            BLE_ADVERTISING_ACCESS_ADDRESS
        );
    }

    #[derive(Default)]
    struct ScriptedLoopbackChannel {
        inner: LoopbackChannel,
        write_responses: VecDeque<Vec<u8>>,
    }

    impl ScriptedLoopbackChannel {
        fn respond_after_write(response: proto::Message) -> Self {
            Self {
                inner: LoopbackChannel::default(),
                write_responses: VecDeque::from([encode_message(&response)]),
            }
        }
    }

    impl WhadByteChannel for ScriptedLoopbackChannel {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            self.inner.read(buf)
        }

        fn write_all(&mut self, data: &[u8]) -> Result<()> {
            self.inner.write_all(data)?;
            if let Some(response) = self.write_responses.pop_front() {
                self.inner.write_all(&response)?;
            }
            Ok(())
        }
    }

    fn scan_rsp_received() -> proto::Message {
        proto::Message {
            msg: Some(proto::message::Msg::Ble(proto::ble::Message {
                msg: Some(proto::ble::message::Msg::AdvPdu(
                    proto::ble::AdvPduReceived {
                        adv_type: proto::ble::BleAdvType::AdvScanRsp as i32,
                        rssi: -32,
                        bd_address: ADVERTISER_ADDRESS_ON_AIR.to_vec(),
                        adv_data: vec![0x02, 0x01, 0x06],
                        addr_type: proto::ble::BleAddrType::Public as i32,
                        channel: 37,
                        phy: proto::ble::BlePhy::Le1m as i32,
                    },
                )),
            })),
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
