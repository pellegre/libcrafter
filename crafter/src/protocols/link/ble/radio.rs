//! BLE radio pseudo-header metadata.

use core::any::Any;

use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet};

use super::consts::{ADVERTISING_ACCESS_ADDRESS, ADV_CHANNEL_37, ADV_CRC_INIT};

const BLE_RADIO_PSEUDO_HEADER_LEN: usize = 10;

const BLE_RADIO_FLAG_DEWHITENED: u16 = 0x0001;
const BLE_RADIO_FLAG_SIGNAL_POWER_VALID: u16 = 0x0002;
const BLE_RADIO_FLAG_REFERENCE_ACCESS_ADDRESS_VALID: u16 = 0x0010;
const BLE_RADIO_FLAG_CRC_CHECKED: u16 = 0x0400;
const BLE_RADIO_FLAG_CRC_VALID: u16 = 0x0800;
const BLE_RADIO_FLAG_PHY_SHIFT: u16 = 14;

/// BLE physical-layer modulation used for the advertising PDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlePhy {
    /// Bluetooth LE 1M PHY.
    Le1M,
    /// Bluetooth LE 2M PHY.
    Le2M,
    /// Bluetooth LE Coded PHY.
    LeCoded,
}

impl Default for BlePhy {
    fn default() -> Self {
        Self::Le1M
    }
}

impl BlePhy {
    fn label(self) -> &'static str {
        match self {
            Self::Le1M => "1M",
            Self::Le2M => "2M",
            Self::LeCoded => "Coded",
        }
    }
}

/// BLE Link Layer radio descriptor preceding an advertising PDU.
#[derive(Debug)]
pub struct BleRadio {
    /// BLE physical channel index.
    ///
    /// This descriptor field maps to both the pcap BLE pseudo-header and the
    /// WHAD radio descriptor fields.
    channel: Field<u8>,
    /// Access address carried before the Link Layer PDU.
    ///
    /// This descriptor field maps to both the pcap BLE pseudo-header and the
    /// WHAD radio descriptor fields.
    access_address: Field<u32>,
    /// BLE PHY used to send or receive the PDU.
    ///
    /// This descriptor field maps to both the pcap BLE pseudo-header and the
    /// WHAD radio descriptor fields.
    phy: Field<BlePhy>,
    /// Whether BLE data whitening is enabled for the PDU.
    ///
    /// This descriptor field maps to both the pcap BLE pseudo-header and the
    /// WHAD radio descriptor fields.
    whitening: Field<bool>,
    /// CRC initializer used for the Link Layer PDU.
    ///
    /// This descriptor field maps to both the pcap BLE pseudo-header and the
    /// WHAD radio descriptor fields.
    crc_init: Field<u32>,
    /// Receive-only RSSI metadata, in dBm, when a backend reports it.
    rssi: Field<i16>,
    /// Receive-only CRC validity metadata when a backend reports it.
    crc_valid: Field<bool>,
}

impl Clone for BleRadio {
    fn clone(&self) -> Self {
        Self {
            channel: self.channel.clone(),
            access_address: self.access_address.clone(),
            phy: self.phy.clone(),
            whitening: self.whitening.clone(),
            crc_init: self.crc_init.clone(),
            rssi: self.rssi.clone(),
            crc_valid: self.crc_valid.clone(),
        }
    }
}

impl BleRadio {
    /// Create a BLE radio descriptor with advertising-channel defaults.
    pub fn new() -> Self {
        Self {
            channel: Field::unset(),
            access_address: Field::defaulted(ADVERTISING_ACCESS_ADDRESS),
            phy: Field::defaulted(BlePhy::Le1M),
            whitening: Field::defaulted(true),
            crc_init: Field::defaulted(ADV_CRC_INIT),
            rssi: Field::unset(),
            crc_valid: Field::unset(),
        }
    }

    /// Create an advertising-channel BLE radio descriptor.
    pub fn advertising(channel: u8) -> Self {
        Self::new().channel(channel)
    }

    /// Set the BLE physical channel index.
    pub fn channel(mut self, channel: u8) -> Self {
        self.channel.set_user(channel);
        self
    }

    /// Set the Link Layer access address.
    pub fn access_address(mut self, access_address: u32) -> Self {
        self.access_address.set_user(access_address);
        self
    }

    /// Set the BLE PHY.
    pub fn phy(mut self, phy: BlePhy) -> Self {
        self.phy.set_user(phy);
        self
    }

    /// Set whether data whitening is enabled.
    pub fn whitening(mut self, whitening: bool) -> Self {
        self.whitening.set_user(whitening);
        self
    }

    /// Set the Link Layer CRC initializer.
    pub fn crc_init(mut self, crc_init: u32) -> Self {
        self.crc_init.set_user(crc_init);
        self
    }

    /// Set receive-only RSSI metadata.
    pub fn rssi(mut self, rssi: i16) -> Self {
        self.rssi.set_user(rssi);
        self
    }

    /// Set receive-only CRC validity metadata.
    pub fn crc_valid(mut self, crc_valid: bool) -> Self {
        self.crc_valid.set_user(crc_valid);
        self
    }

    /// Return the fixed BLE LE Link-Layer pcap pseudo-header length.
    pub(crate) fn encoded_len(&self) -> usize {
        BLE_RADIO_PSEUDO_HEADER_LEN
    }

    /// Encode the BLE LE Link-Layer pcap pseudo-header.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        let channel = self.effective_channel();
        let signal_power = self.rssi.value().copied().unwrap_or(0) as u8;
        let access_address = self.effective_access_address();

        out.push(channel);
        out.push(signal_power);
        out.push(0);
        out.push(0);
        out.extend_from_slice(&access_address.to_le_bytes());
        out.extend_from_slice(&self.flags().to_le_bytes());
    }

    fn flags(&self) -> u16 {
        let mut flags = 0;

        // Bit assignments follow the LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR
        // pseudo-header cited from .agents/docs/ble-manifest.md:
        // bit 0 de-whitened, bit 1 signal power valid, bit 4 reference
        // access address valid, bits 10/11 CRC checked/valid, bits 14/15 PHY.
        if self.whitening.value().copied().unwrap_or(true) {
            flags |= BLE_RADIO_FLAG_DEWHITENED;
        }
        if self.rssi.value().is_some() {
            flags |= BLE_RADIO_FLAG_SIGNAL_POWER_VALID;
        }
        if self.access_address.value().is_some() {
            flags |= BLE_RADIO_FLAG_REFERENCE_ACCESS_ADDRESS_VALID;
        }
        if self.crc_valid.value().is_some() || self.crc_init.value().is_some() {
            flags |= BLE_RADIO_FLAG_CRC_CHECKED;
        }
        if self.crc_valid.value().copied().unwrap_or(false) {
            flags |= BLE_RADIO_FLAG_CRC_VALID;
        }

        flags
            | (Self::phy_bits(self.effective_phy()) << BLE_RADIO_FLAG_PHY_SHIFT)
    }

    fn effective_channel(&self) -> u8 {
        self.channel.value().copied().unwrap_or(ADV_CHANNEL_37)
    }

    fn effective_access_address(&self) -> u32 {
        self.access_address
            .value()
            .copied()
            .unwrap_or(ADVERTISING_ACCESS_ADDRESS)
    }

    fn effective_phy(&self) -> BlePhy {
        self.phy.value().copied().unwrap_or_default()
    }

    fn effective_whitening(&self) -> bool {
        self.whitening.value().copied().unwrap_or(true)
    }

    fn phy_bits(phy: BlePhy) -> u16 {
        match phy {
            BlePhy::Le1M => 0,
            BlePhy::Le2M => 1,
            BlePhy::LeCoded => 2,
        }
    }

    fn phy_from_bits(bits: u16) -> BlePhy {
        match bits & 0x0003 {
            0 => BlePhy::Le1M,
            1 => BlePhy::Le2M,
            2 => BlePhy::LeCoded,
            _ => BlePhy::Le1M,
        }
    }
}

impl Default for BleRadio {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn decode_ble_radio(bytes: &[u8]) -> Result<(BleRadio, &[u8])> {
    if bytes.len() < BLE_RADIO_PSEUDO_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "ble.radio.pseudo_header",
            BLE_RADIO_PSEUDO_HEADER_LEN,
            bytes.len(),
        ));
    }

    let access_address = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let flags = u16::from_le_bytes([bytes[8], bytes[9]]);
    let phy = BleRadio::phy_from_bits(flags >> BLE_RADIO_FLAG_PHY_SHIFT);

    let radio = BleRadio {
        channel: Field::user(bytes[0]),
        access_address: Field::user(access_address),
        phy: Field::user(phy),
        whitening: Field::user(flags & BLE_RADIO_FLAG_DEWHITENED != 0),
        crc_init: Field::defaulted(ADV_CRC_INIT),
        rssi: Field::user(i16::from(bytes[1] as i8)),
        crc_valid: Field::user(flags & BLE_RADIO_FLAG_CRC_VALID != 0),
    };

    Ok((radio, &bytes[BLE_RADIO_PSEUDO_HEADER_LEN..]))
}

impl Layer for BleRadio {
    fn name(&self) -> &'static str {
        "BleRadio"
    }

    fn summary(&self) -> String {
        format!(
            "BleRadio(ch={}, aa=0x{:08x}, phy={})",
            self.effective_channel(),
            self.effective_access_address(),
            self.effective_phy().label()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            ("channel", self.effective_channel().to_string()),
            (
                "access_address",
                format!("0x{:08x}", self.effective_access_address()),
            ),
            ("phy", self.effective_phy().label().to_string()),
            ("whitening", self.effective_whitening().to_string()),
        ];

        if let Some(rssi) = self.rssi.value() {
            fields.push(("rssi", rssi.to_string()));
        }
        if let Some(crc_valid) = self.crc_valid.value() {
            fields.push(("crc_valid", crc_valid.to_string()));
        }

        fields
    }

    fn encoded_len(&self) -> usize {
        BleRadio::encoded_len(self)
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        self.encode(out);
        Ok(())
    }

    fn clone_layer(&self) -> Box<dyn Layer> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

impl<R: IntoPacket> core::ops::Div<R> for BleRadio {
    type Output = Packet;

    fn div(self, rhs: R) -> Self::Output {
        Packet::from_layer(self).concat(rhs)
    }
}

#[cfg(test)]
mod tests {
    use crate::field::FieldState;
    use crate::packet::{Packet, Raw};

    use super::*;

    #[test]
    fn ble_radio_builder_defaults_are_defaulted() {
        let radio = BleRadio::new();

        assert_eq!(radio.channel.state(), FieldState::Unset);
        assert_eq!(radio.access_address.state(), FieldState::Defaulted);
        assert_eq!(radio.access_address.value(), Some(&ADVERTISING_ACCESS_ADDRESS));
        assert_eq!(radio.phy.state(), FieldState::Defaulted);
        assert_eq!(radio.phy.value(), Some(&BlePhy::Le1M));
        assert_eq!(radio.whitening.state(), FieldState::Defaulted);
        assert_eq!(radio.whitening.value(), Some(&true));
        assert_eq!(radio.crc_init.state(), FieldState::Defaulted);
        assert_eq!(radio.crc_init.value(), Some(&ADV_CRC_INIT));
        assert_eq!(radio.rssi.state(), FieldState::Unset);
        assert_eq!(radio.crc_valid.state(), FieldState::Unset);
    }

    #[test]
    fn ble_radio_builder_setters_mark_fields_user() {
        let radio = BleRadio::new()
            .channel(38)
            .access_address(0x1234_5678)
            .phy(BlePhy::Le2M)
            .whitening(false)
            .crc_init(0x00AB_CDEF)
            .rssi(-42)
            .crc_valid(false);

        assert_eq!(radio.channel.state(), FieldState::User);
        assert_eq!(radio.access_address.state(), FieldState::User);
        assert_eq!(radio.phy.state(), FieldState::User);
        assert_eq!(radio.whitening.state(), FieldState::User);
        assert_eq!(radio.crc_init.state(), FieldState::User);
        assert_eq!(radio.rssi.state(), FieldState::User);
        assert_eq!(radio.crc_valid.state(), FieldState::User);
    }

    #[test]
    fn ble_radio_builder_advertising_sets_channel_and_default_access_address() {
        let radio = BleRadio::advertising(37);

        assert_eq!(radio.channel.state(), FieldState::User);
        assert_eq!(radio.channel.value(), Some(&37));
        assert_eq!(radio.access_address.state(), FieldState::Defaulted);
        assert_eq!(radio.access_address.value(), Some(&ADVERTISING_ACCESS_ADDRESS));
    }

    #[test]
    fn ble_radio_encode_default_advertising_pseudo_header() {
        let radio = BleRadio::new();
        let mut bytes = Vec::new();

        radio.encode(&mut bytes);

        assert_eq!(
            bytes,
            [
                ADV_CHANNEL_37,
                0,
                0,
                0,
                0xD6,
                0xBE,
                0x89,
                0x8E,
                0x11,
                0x04,
            ]
        );
        assert_eq!(bytes[0], ADV_CHANNEL_37);
        assert_eq!(&bytes[4..8], &ADVERTISING_ACCESS_ADDRESS.to_le_bytes());
    }

    #[test]
    fn ble_radio_encode_encoded_len_is_constant() {
        assert_eq!(BleRadio::new().encoded_len(), BLE_RADIO_PSEUDO_HEADER_LEN);
        assert_eq!(
            BleRadio::advertising(39)
                .phy(BlePhy::LeCoded)
                .whitening(false)
                .crc_valid(true)
                .encoded_len(),
            BLE_RADIO_PSEUDO_HEADER_LEN
        );
    }

    #[test]
    fn ble_radio_layer_packet_summary_includes_radio_fields() {
        let packet = Packet::from_layer(BleRadio::advertising(38));
        let summary = packet.summary();

        assert!(summary.contains("ch=38"));
        assert!(summary.contains("aa=0x8e89bed6"));
    }

    #[test]
    fn ble_radio_decode_parses_pseudo_header_fields() {
        let flags = BLE_RADIO_FLAG_DEWHITENED
            | BLE_RADIO_FLAG_SIGNAL_POWER_VALID
            | BLE_RADIO_FLAG_REFERENCE_ACCESS_ADDRESS_VALID
            | BLE_RADIO_FLAG_CRC_CHECKED
            | BLE_RADIO_FLAG_CRC_VALID
            | (BleRadio::phy_bits(BlePhy::Le2M) << BLE_RADIO_FLAG_PHY_SHIFT);
        let mut bytes = vec![38, (-42i8) as u8, 0, 0, 0x78, 0x56, 0x34, 0x12];
        bytes.extend_from_slice(&flags.to_le_bytes());
        bytes.extend_from_slice(&[0xaa, 0xbb]);

        let (radio, tail) = decode_ble_radio(&bytes).expect("decode BLE radio pseudo-header");

        assert_eq!(tail, &[0xaa, 0xbb]);
        assert_eq!(radio.channel.state(), FieldState::User);
        assert_eq!(radio.channel.value(), Some(&38));
        assert_eq!(radio.access_address.state(), FieldState::User);
        assert_eq!(radio.access_address.value(), Some(&0x1234_5678));
        assert_eq!(radio.phy.state(), FieldState::User);
        assert_eq!(radio.phy.value(), Some(&BlePhy::Le2M));
        assert_eq!(radio.whitening.state(), FieldState::User);
        assert_eq!(radio.whitening.value(), Some(&true));
        assert_eq!(radio.rssi.state(), FieldState::User);
        assert_eq!(radio.rssi.value(), Some(&-42));
        assert_eq!(radio.crc_valid.state(), FieldState::User);
        assert_eq!(radio.crc_valid.value(), Some(&true));
    }

    #[test]
    fn ble_radio_decode_truncated_pseudo_header_is_structured_error() {
        let err = decode_ble_radio(&[0; BLE_RADIO_PSEUDO_HEADER_LEN - 1])
            .expect_err("must reject truncated BLE radio pseudo-header");

        assert_eq!(
            err,
            CrafterError::BufferTooShort {
                context: "ble.radio.pseudo_header",
                required: BLE_RADIO_PSEUDO_HEADER_LEN,
                available: BLE_RADIO_PSEUDO_HEADER_LEN - 1,
            }
        );
    }

    #[test]
    fn ble_radio_div_builds_two_layer_packet() {
        let packet = BleRadio::advertising(37) / Raw::from_bytes([0u8; 4]);

        assert_eq!(packet.len(), 2);
        assert!(packet.layer::<BleRadio>().is_some());
        assert!(packet.layer::<Raw>().is_some());
    }
}
