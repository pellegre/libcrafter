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
