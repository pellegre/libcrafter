//! Bluetooth Low Energy advertising link-layer support.
//!
//! This module will hold the BLE radio pseudo-header (`BleRadio`), advertising
//! Link Layer PDU (`BleLlAdv`), and GAP Advertising Data structure layers.

mod ad;
mod adv;
mod consts;
mod radio;

pub use ad::{AdList, AdStructure};
pub(crate) use adv::decode_ble_adv;
pub use adv::{BleAdvPduType, BleLlAdv};
pub(crate) use radio::decode_ble_radio;
pub use radio::{BlePhy, BleRadio};
