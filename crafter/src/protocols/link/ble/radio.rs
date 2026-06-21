//! BLE radio pseudo-header metadata.

use crate::field::Field;

use super::consts::{ADVERTISING_ACCESS_ADDRESS, ADV_CRC_INIT};

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
}

impl Default for BleRadio {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::field::FieldState;

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
}
