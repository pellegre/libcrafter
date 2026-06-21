//! BLE advertising-channel Link Layer PDU scaffolding.

use crate::error::Result;
use crate::field::Field;
use crate::mac::MacAddr;

use super::consts::BleAdvPduType;

/// BLE advertising-channel Link Layer PDU.
///
/// Address fields use `MacAddr` as the crate's existing six-octet address
/// type. Builder methods accept normal MSB-first display order and store the
/// bytes in BLE little-endian on-air order for later encoder/decoder steps.
#[derive(Debug)]
pub struct BleLlAdv {
    /// Advertising PDU type stored in header bits 0..=3.
    pdu_type: Field<BleAdvPduType>,
    /// Channel Selection bit.
    ch_sel: Field<bool>,
    /// Transmitter address type bit.
    tx_add: Field<bool>,
    /// Receiver address type bit.
    rx_add: Field<bool>,
    /// Advertising payload length octet; auto-filled during compile.
    length: Field<u8>,
    /// Advertiser address (`AdvA`) for advertising PDUs.
    adv_a: Field<MacAddr>,
    /// Target address (`TargetA`) for directed, scan, and connect PDUs.
    target_a: Field<MacAddr>,
    /// Raw trailing payload when no typed Advertising Data list is used.
    payload: Vec<u8>,
}

impl Clone for BleLlAdv {
    fn clone(&self) -> Self {
        Self {
            pdu_type: self.pdu_type.clone(),
            ch_sel: self.ch_sel.clone(),
            tx_add: self.tx_add.clone(),
            rx_add: self.rx_add.clone(),
            length: self.length.clone(),
            adv_a: self.adv_a.clone(),
            target_a: self.target_a.clone(),
            payload: self.payload.clone(),
        }
    }
}

impl BleLlAdv {
    /// Create a BLE advertising PDU with advertising-channel defaults.
    pub fn new() -> Self {
        Self {
            pdu_type: Field::defaulted(BleAdvPduType::AdvInd),
            ch_sel: Field::defaulted(false),
            tx_add: Field::defaulted(true),
            rx_add: Field::defaulted(false),
            length: Field::unset(),
            adv_a: Field::unset(),
            target_a: Field::unset(),
            payload: Vec::new(),
        }
    }

    /// Create an ADV_IND advertising PDU.
    pub fn adv_ind() -> Self {
        Self::new().pdu_type(BleAdvPduType::AdvInd)
    }

    /// Create an ADV_NONCONN_IND advertising PDU.
    pub fn adv_nonconn_ind() -> Self {
        Self::new().pdu_type(BleAdvPduType::AdvNonconnInd)
    }

    /// Create an ADV_SCAN_IND advertising PDU.
    pub fn adv_scan_ind() -> Self {
        Self::new().pdu_type(BleAdvPduType::AdvScanInd)
    }

    /// Create a SCAN_RSP advertising PDU.
    pub fn scan_rsp() -> Self {
        Self::new().pdu_type(BleAdvPduType::ScanRsp)
    }

    /// Create a SCAN_REQ advertising PDU.
    pub fn scan_req() -> Self {
        Self::new().pdu_type(BleAdvPduType::ScanReq)
    }

    /// Create a CONNECT_IND advertising PDU.
    pub fn connect_ind() -> Self {
        Self::new().pdu_type(BleAdvPduType::ConnectInd)
    }

    /// Create an ADV_DIRECT_IND advertising PDU.
    pub fn adv_direct_ind() -> Self {
        Self::new().pdu_type(BleAdvPduType::AdvDirectInd)
    }

    /// Set the advertising PDU type.
    pub fn pdu_type(mut self, pdu_type: BleAdvPduType) -> Self {
        self.pdu_type.set_user(pdu_type);
        self
    }

    /// Set or clear the Channel Selection bit.
    pub fn ch_sel(mut self, ch_sel: bool) -> Self {
        self.ch_sel.set_user(ch_sel);
        self
    }

    /// Set the transmitter address type bit.
    pub fn tx_add(mut self, tx_add: bool) -> Self {
        self.tx_add.set_user(tx_add);
        self
    }

    /// Set the receiver address type bit.
    pub fn rx_add(mut self, rx_add: bool) -> Self {
        self.rx_add.set_user(rx_add);
        self
    }

    /// Set the advertising payload length octet.
    pub fn length(mut self, length: u8) -> Self {
        self.length.set_user(length);
        self
    }

    /// Set the advertiser address (`AdvA`).
    pub fn adv_a(mut self, adv_a: impl Into<MacAddr>) -> Self {
        self.adv_a.set_user(display_to_on_air_address(adv_a.into()));
        self
    }

    /// Set the advertiser address (`AdvA`) from text in MSB-first display order.
    pub fn adv_a_str(self, adv_a: &str) -> Result<Self> {
        Ok(self.adv_a(adv_a.parse::<MacAddr>()?))
    }

    /// Set the target address (`TargetA`).
    pub fn target_a(mut self, target_a: impl Into<MacAddr>) -> Self {
        self.target_a
            .set_user(display_to_on_air_address(target_a.into()));
        self
    }

    /// Set the target address (`TargetA`) from text in MSB-first display order.
    pub fn target_a_str(self, target_a: &str) -> Result<Self> {
        Ok(self.target_a(target_a.parse::<MacAddr>()?))
    }

    /// Set raw trailing payload bytes.
    pub fn payload(mut self, payload: impl Into<Vec<u8>>) -> Self {
        self.payload = payload.into();
        self
    }

    /// Current advertiser address (`AdvA`) in MSB-first display order.
    pub fn adv_a_value(&self) -> Option<MacAddr> {
        self.adv_a.value().copied().map(on_air_to_display_address)
    }

    /// Current target address (`TargetA`) in MSB-first display order.
    pub fn target_a_value(&self) -> Option<MacAddr> {
        self.target_a
            .value()
            .copied()
            .map(on_air_to_display_address)
    }
}

impl Default for BleLlAdv {
    fn default() -> Self {
        Self::new()
    }
}

fn display_to_on_air_address(address: MacAddr) -> MacAddr {
    reverse_address(address)
}

fn on_air_to_display_address(address: MacAddr) -> MacAddr {
    reverse_address(address)
}

fn reverse_address(address: MacAddr) -> MacAddr {
    let [a, b, c, d, e, f] = address.octets();
    MacAddr::new([f, e, d, c, b, a])
}

#[cfg(test)]
mod tests {
    use crate::field::FieldState;

    use super::*;

    #[test]
    fn ble_adv_builder_adv_ind_sets_pdu_type_user() {
        let adv = BleLlAdv::adv_ind();

        assert_eq!(adv.pdu_type.state(), FieldState::User);
        assert_eq!(adv.pdu_type.value(), Some(&BleAdvPduType::AdvInd));
    }

    #[test]
    fn ble_adv_builder_tx_add_setter_marks_field_user() {
        let adv = BleLlAdv::new().tx_add(false);

        assert_eq!(adv.tx_add.state(), FieldState::User);
        assert_eq!(adv.tx_add.value(), Some(&false));
    }

    #[test]
    fn ble_adv_builder_default_tx_add_is_random_address() {
        let adv = BleLlAdv::new();

        assert_eq!(adv.tx_add.state(), FieldState::Defaulted);
        assert_eq!(adv.tx_add.value(), Some(&true));
    }

    #[test]
    fn ble_adv_address_adv_a_str_stores_little_endian_and_gets_display_order() {
        let adv = BleLlAdv::new().adv_a_str("C0:FF:EE:11:22:33").unwrap();

        assert_eq!(
            adv.adv_a.value().copied().unwrap().octets(),
            [0x33, 0x22, 0x11, 0xee, 0xff, 0xc0]
        );
        assert_eq!(
            adv.adv_a_value().unwrap(),
            MacAddr::new([0xc0, 0xff, 0xee, 0x11, 0x22, 0x33])
        );
        assert_eq!(adv.adv_a_value().unwrap().to_string(), "c0:ff:ee:11:22:33");
    }

    #[test]
    fn ble_adv_address_target_a_str_stores_little_endian_and_gets_display_order() {
        let adv = BleLlAdv::new().target_a_str("C0:FF:EE:11:22:33").unwrap();

        assert_eq!(
            adv.target_a.value().copied().unwrap().octets(),
            [0x33, 0x22, 0x11, 0xee, 0xff, 0xc0]
        );
        assert_eq!(
            adv.target_a_value().unwrap(),
            MacAddr::new([0xc0, 0xff, 0xee, 0x11, 0x22, 0x33])
        );
    }
}
