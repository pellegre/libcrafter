//! Packet source for WHAD BLE receive messages.

use std::time::Duration;

use prost::Message as _;

use crate::protocols::link::decode_ble_adv;
use crate::wire::record::{
    BackendKind, BluetoothMetadata, MediumMetadata, PacketOrigin, PacketRecord,
};
use crate::wire::source::PacketSource;
use crate::wire::{Result, WireError};
use crate::{BleRadio, LinkType, Raw};

use super::messages::parse_received_pdu;
use super::proto;
use super::transport::{WhadByteChannel, WhadLink};

const WHAD_READER_RECV_TIMEOUT: Duration = Duration::from_millis(100);
const WHAD_TIMEOUT_REASON: &str = "timeout waiting for WHAD frame";

/// WHAD BLE receive adapter that yields packet-shaped capture records.
pub(crate) struct WhadReader<C: WhadByteChannel> {
    link: WhadLink<C>,
    recv_timeout: Duration,
}

impl<C: WhadByteChannel> WhadReader<C> {
    /// Create a WHAD reader from a configured WHAD link.
    pub(crate) fn new(link: WhadLink<C>) -> Self {
        Self {
            link,
            recv_timeout: WHAD_READER_RECV_TIMEOUT,
        }
    }

    /// Set the bounded receive timeout used for one WHAD frame poll.
    pub(crate) const fn with_recv_timeout(mut self, recv_timeout: Duration) -> Self {
        self.recv_timeout = recv_timeout;
        self
    }

    /// Consume the reader and return the underlying WHAD link.
    pub(crate) fn into_link(self) -> WhadLink<C> {
        self.link
    }
}

impl<C: WhadByteChannel> PacketSource for WhadReader<C> {
    fn next_record(&mut self) -> Result<Option<PacketRecord>> {
        loop {
            let message_bytes = match self.link.recv_message(self.recv_timeout) {
                Ok(message_bytes) => message_bytes,
                Err(err) if is_whad_timeout(&err) => return Ok(None),
                Err(err) => return Err(err),
            };

            let message = proto::Message::decode(message_bytes.as_slice())
                .map_err(|err| WireError::backend("whad", "receive PDU", err.to_string()))?;
            let Some(rx) = parse_received_pdu(&message) else {
                continue;
            };

            let (adv, tail) = decode_ble_adv(&rx.pdu)?;
            let radio = BleRadio::advertising(rx.channel)
                .access_address(rx.access_address)
                .rssi(rx.rssi)
                .crc_valid(rx.crc_valid);
            let mut packet = radio / adv;
            if !tail.is_empty() {
                packet = packet.push(Raw::from_bytes(tail));
            }

            let bluetooth =
                BluetoothMetadata::from_whad_rx_descriptor(rx.channel, rx.rssi, rx.access_address);
            let record = PacketRecord::new(packet)
                .with_origin(PacketOrigin::Captured)
                .with_backend(BackendKind::Whad)
                .with_link_type(LinkType::BluetoothLeLl)
                .with_medium(MediumMetadata::Bluetooth(bluetooth));

            return Ok(Some(record));
        }
    }
}

fn is_whad_timeout(err: &WireError) -> bool {
    matches!(
        err,
        WireError::Backend { reason, .. } if reason.contains(WHAD_TIMEOUT_REASON)
    )
}

#[cfg(all(test, feature = "whad"))]
mod whad_reader {
    use super::super::transport::LoopbackChannel;
    use super::*;
    use crate::{BleLlAdv, MacAddr};

    const BLE_ADVERTISING_ACCESS_ADDRESS: u32 = 0x8E89_BED6;
    const DOC_BLE_ADV_ADDRESS: [u8; 6] = [0x46, 0x53, 0x00, 0x5e, 0x00, 0x00];
    const DOC_BLE_FLAGS_AD: [u8; 3] = [0x02, 0x01, 0x06];

    #[test]
    fn whad_reader_received_adv_pdu_yields_ble_packet_record() {
        let mut link = WhadLink::new(LoopbackChannel::default());
        link.send_message(&advertising_pdu_received())
            .expect("queue WHAD advertising PDU");
        let mut reader = WhadReader::new(link);

        let record = reader
            .next_record()
            .expect("read WHAD packet record")
            .expect("record should be available");

        let packet = record.packet();
        assert_eq!(packet.iter().count(), 2);
        assert!(packet.get(0).unwrap().as_any().is::<BleRadio>());
        assert!(packet.get(1).unwrap().as_any().is::<BleLlAdv>());

        let radio = packet.layer::<BleRadio>().expect("BleRadio layer");
        assert_eq!(radio.effective_channel_for_backend(), 37);
        assert_eq!(
            radio.effective_access_address_for_backend(),
            BLE_ADVERTISING_ACCESS_ADDRESS
        );

        let adv = packet.layer::<BleLlAdv>().expect("BleLlAdv layer");
        assert_eq!(
            adv.adv_a_value().unwrap(),
            MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x46])
        );

        let metadata = record.metadata();
        assert_eq!(metadata.origin(), PacketOrigin::Captured);
        assert_eq!(metadata.backend(), &BackendKind::Whad);
        assert_eq!(metadata.link_type(), Some(LinkType::BluetoothLeLl));
        match metadata.medium() {
            Some(MediumMetadata::Bluetooth(bluetooth)) => {
                assert_eq!(bluetooth.channel(), Some(37));
                assert_eq!(bluetooth.signal_dbm(), Some(-42));
                assert_eq!(bluetooth.address(), Some("0x8e89bed6"));
                assert_eq!(bluetooth.protocol(), Some("ble"));
            }
            other => panic!("expected Bluetooth metadata, got {other:?}"),
        }
    }

    #[test]
    fn whad_reader_timeout_without_frame_returns_none() {
        let mut reader = WhadReader::new(WhadLink::new(LoopbackChannel::default()))
            .with_recv_timeout(Duration::from_millis(1));

        assert!(reader
            .next_record()
            .expect("timeout is not a source error")
            .is_none());
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
}
