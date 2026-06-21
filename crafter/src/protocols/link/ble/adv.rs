//! BLE advertising-channel Link Layer PDU scaffolding.

use crate::field::Field;
use crate::mac::MacAddr;

use super::consts::BleAdvPduType;

/// BLE advertising-channel Link Layer PDU.
///
/// Address fields use `MacAddr` as the crate's existing six-octet address
/// type. BLE advertising addresses are serialized in little-endian on-air
/// order by the later encoder/decoder steps.
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
        self.adv_a.set_user(adv_a.into());
        self
    }

    /// Set the target address (`TargetA`).
    pub fn target_a(mut self, target_a: impl Into<MacAddr>) -> Self {
        self.target_a.set_user(target_a.into());
        self
    }

    /// Set raw trailing payload bytes.
    pub fn payload(mut self, payload: impl Into<Vec<u8>>) -> Self {
        self.payload = payload.into();
        self
    }
}

impl Default for BleLlAdv {
    fn default() -> Self {
        Self::new()
    }
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
}
