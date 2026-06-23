//! Packet source for WHAD BLE receive messages.

use std::time::{Duration, Instant};

use prost::Message as _;

use crate::protocols::link::{decode_ble_adv, decode_dot15d4_with_registry};
use crate::wire::record::{
    BackendKind, BluetoothMetadata, Dot15d4Metadata, MediumMetadata, PacketOrigin, PacketRecord,
};
use crate::wire::source::PacketSource;
use crate::wire::{Result, WireError};
use crate::{BleRadio, Dot15d4Radio, LinkType, Packet, ProtocolRegistry, Raw};

use super::dot15d4::{parse_dot15d4_received, WhadDot15d4Rx};
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
    #[cfg(test)]
    pub(crate) const fn with_recv_timeout(mut self, recv_timeout: Duration) -> Self {
        self.recv_timeout = recv_timeout;
        self
    }
}

impl<C: WhadByteChannel> PacketSource for WhadReader<C> {
    fn next_record(&mut self) -> Result<Option<PacketRecord>> {
        read_record_from_link(&mut self.link, self.recv_timeout)
    }
}

pub(crate) fn read_record_from_link<C: WhadByteChannel>(
    link: &mut WhadLink<C>,
    recv_timeout: Duration,
) -> Result<Option<PacketRecord>> {
    let start = Instant::now();
    let deadline = start.checked_add(recv_timeout).unwrap_or(start);
    read_record_from_link_until(link, deadline)
}

pub(crate) fn read_record_from_link_until<C: WhadByteChannel>(
    link: &mut WhadLink<C>,
    deadline: Instant,
) -> Result<Option<PacketRecord>> {
    loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Ok(None);
        };
        if remaining == Duration::ZERO {
            return Ok(None);
        }

        let message_bytes = match link.recv_message(remaining) {
            Ok(message_bytes) => message_bytes,
            Err(err) if is_whad_timeout(&err) => return Ok(None),
            Err(err) => return Err(err),
        };

        let message = proto::Message::decode(message_bytes.as_slice())
            .map_err(|err| WireError::backend("whad", "receive PDU", err.to_string()))?;

        // A WHAD receive notification belongs to exactly one domain: try the
        // 802.15.4 parser and the BLE parser and route by whichever matches.
        // Both parsers return `None` for messages outside their domain and for
        // non-PDU control/command frames, so a non-PDU frame falls through and
        // the loop polls the next message. The 802.15.4 parser accepts BOTH
        // `raw_pdu` and `pdu` notifications (the BLE live sniff bug lesson).
        if let Some(rx) = parse_dot15d4_received(&message) {
            return Ok(Some(record_from_dot15d4_rx(rx)?));
        }
        let Some(rx) = parse_received_pdu(&message) else {
            continue;
        };

        return Ok(Some(record_from_rx(rx)?));
    }
}

fn record_from_rx(rx: super::messages::WhadRxPdu) -> Result<PacketRecord> {
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
    Ok(PacketRecord::new(packet)
        .with_origin(PacketOrigin::Captured)
        .with_backend(BackendKind::Whad)
        .with_link_type(LinkType::BluetoothLeLl)
        .with_medium(MediumMetadata::Bluetooth(bluetooth)))
}

/// Translate a WHAD 802.15.4 received-PDU descriptor into a captured packet
/// record, mirroring the BLE [`record_from_rx`].
///
/// The WHAD notification carries the bare MAC frame (no TAP pseudo-header); the
/// radio metadata lives in the descriptor. So the descriptor is rebuilt into a
/// [`Dot15d4Radio`] layer and the MAC PDU is decoded with
/// [`decode_dot15d4_with_registry`] (`tap = false`), reusing the SAME
/// Zigbee-recognition logic as the `LinkType::Ieee802154` decode entrypoint:
/// the decoded `Dot15d4` MAC layer is followed by `ZigbeeNwk`/`ZigbeeAps` when
/// the payload is recognized Zigbee, else the payload is preserved as `Raw`.
/// The radio descriptor is then prepended so the record reads
/// `Dot15d4Radio / Dot15d4 [/ ZigbeeNwk / ZigbeeAps | / Raw]`.
///
/// The record is tagged `LinkType::Ieee802154Tap` because it carries radio
/// metadata, mirroring how the BLE path tags `LinkType::BluetoothLeLl` for its
/// radio-prefixed records.
fn record_from_dot15d4_rx(rx: WhadDot15d4Rx) -> Result<PacketRecord> {
    let radio = Dot15d4Radio::on_channel(rx.channel)
        .rssi(rx.rssi)
        .fcs_valid(rx.fcs_valid)
        .lqi(rx.lqi);

    // The WHAD PDU is the bare MAC frame, so decode with `tap = false`; this
    // yields a `Dot15d4` MAC layer plus the recognized Zigbee NWK/APS layers or
    // a `Raw` payload. A structured decode error propagates rather than panics.
    let decoded = decode_dot15d4_with_registry(ProtocolRegistry::builtin(), &rx.pdu, false)?;
    let packet = Packet::from_layer(radio).concat(decoded);

    let dot15d4 =
        Dot15d4Metadata::from_whad_rx_descriptor(rx.channel, rx.rssi, rx.fcs_valid, rx.lqi);
    Ok(PacketRecord::new(packet)
        .with_origin(PacketOrigin::Captured)
        .with_backend(BackendKind::Whad)
        .with_link_type(LinkType::Ieee802154Tap)
        .with_medium(MediumMetadata::Dot15d4(dot15d4)))
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

#[cfg(all(test, feature = "whad"))]
mod dot15d4_reader {
    use super::super::dot15d4::build_dot15d4_message;
    use super::super::transport::LoopbackChannel;
    use super::*;
    use crate::Dot15d4;

    // The bytes of the committed `crafter/tests/fixtures/dot15d4/mac-data-short.hex`
    // fixture: an 802.15.4 Data frame with short addressing and PAN-ID
    // compression. FCF `41 88` (Data, PAN-ID compression, short dest/src),
    // sequence `0x2a`, dest PAN `0x1234`, dest short `0x0000`, src short
    // `0xABCD`, MAC payload `de ad be ef`, trailing CRC-16 FCS `56 1b`.
    const MAC_DATA_SHORT_PDU: [u8; 15] = [
        0x41, 0x88, 0x2a, 0x34, 0x12, 0x00, 0x00, 0xcd, 0xab, 0xde, 0xad, 0xbe, 0xef, 0x56, 0x1b,
    ];
    const DOT15D4_SNIFF_CHANNEL: u8 = 15;
    const DOT15D4_SNIFF_RSSI: i16 = -57;
    const DOT15D4_SNIFF_LQI: u8 = 200;

    #[test]
    fn dot15d4_reader_received_raw_pdu_yields_dot15d4_packet_record() {
        let mut link = WhadLink::new(LoopbackChannel::default());
        link.send_message(&raw_pdu_received())
            .expect("queue WHAD 802.15.4 raw PDU");
        let mut reader = WhadReader::new(link);

        let record = reader
            .next_record()
            .expect("read WHAD packet record")
            .expect("record should be available");

        // The record reads `Dot15d4Radio / Dot15d4 / Raw`: the non-Zigbee MAC
        // payload `de ad be ef` is preserved as a `Raw` layer.
        let packet = record.packet();
        assert_eq!(packet.iter().count(), 3);
        assert!(packet.get(0).unwrap().as_any().is::<Dot15d4Radio>());
        assert!(packet.get(1).unwrap().as_any().is::<Dot15d4>());
        assert!(packet.get(2).unwrap().as_any().is::<Raw>());

        let radio = packet.layer::<Dot15d4Radio>().expect("Dot15d4Radio layer");
        assert_eq!(radio.effective_channel_for_backend(), DOT15D4_SNIFF_CHANNEL);
        assert!(radio.effective_fcs_valid_for_backend());

        let metadata = record.metadata();
        assert_eq!(metadata.origin(), PacketOrigin::Captured);
        assert_eq!(metadata.backend(), &BackendKind::Whad);
        assert_eq!(metadata.link_type(), Some(LinkType::Ieee802154Tap));
        match metadata.medium() {
            Some(MediumMetadata::Dot15d4(dot15d4)) => {
                assert_eq!(dot15d4.channel(), Some(DOT15D4_SNIFF_CHANNEL));
                assert_eq!(dot15d4.signal_dbm(), Some(DOT15D4_SNIFF_RSSI));
                assert_eq!(dot15d4.lqi(), Some(DOT15D4_SNIFF_LQI));
                assert_eq!(dot15d4.fcs_valid(), Some(true));
                assert_eq!(dot15d4.protocol(), Some("dot15d4"));
            }
            other => panic!("expected Dot15d4 metadata, got {other:?}"),
        }
    }

    #[test]
    fn dot15d4_reader_accepts_pdu_notification() {
        // The reader must accept BOTH `raw_pdu` and `pdu` notifications (the BLE
        // live sniff bug lesson). A `PduReceived` frame (FCS already stripped by
        // firmware) must still yield a `Dot15d4Radio / Dot15d4` record.
        let mut link = WhadLink::new(LoopbackChannel::default());
        link.send_message(&pdu_received())
            .expect("queue WHAD 802.15.4 PDU");
        let mut reader = WhadReader::new(link);

        let record = reader
            .next_record()
            .expect("read WHAD packet record")
            .expect("record should be available");

        let packet = record.packet();
        assert!(packet.layer::<Dot15d4Radio>().is_some());
        assert!(packet.layer::<Dot15d4>().is_some());

        let radio = packet.layer::<Dot15d4Radio>().expect("Dot15d4Radio layer");
        assert_eq!(radio.effective_channel_for_backend(), DOT15D4_SNIFF_CHANNEL);

        assert_eq!(record.metadata().link_type(), Some(LinkType::Ieee802154Tap));
    }

    fn raw_pdu_received() -> proto::Message {
        build_dot15d4_message(proto::dot15d4::message::Msg::RawPdu(
            proto::dot15d4::RawPduReceived {
                channel: u32::from(DOT15D4_SNIFF_CHANNEL),
                rssi: Some(i32::from(DOT15D4_SNIFF_RSSI)),
                timestamp: Some(123),
                fcs_validity: true,
                pdu: MAC_DATA_SHORT_PDU.to_vec(),
                fcs: 0x1b56,
                lqi: Some(u32::from(DOT15D4_SNIFF_LQI)),
            },
        ))
    }

    fn pdu_received() -> proto::Message {
        build_dot15d4_message(proto::dot15d4::message::Msg::Pdu(
            proto::dot15d4::PduReceived {
                channel: u32::from(DOT15D4_SNIFF_CHANNEL),
                rssi: Some(i32::from(DOT15D4_SNIFF_RSSI)),
                timestamp: Some(456),
                fcs_validity: false,
                pdu: MAC_DATA_SHORT_PDU.to_vec(),
                lqi: Some(u32::from(DOT15D4_SNIFF_LQI)),
            },
        ))
    }
}
