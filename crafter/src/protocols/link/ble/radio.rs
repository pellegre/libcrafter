//! BLE radio pseudo-header metadata.

use crate::field::Field;

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
