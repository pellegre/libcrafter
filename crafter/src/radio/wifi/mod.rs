//! IEEE 802.11 PHY decoding and transmission policy.

mod decoder;
mod tx;

pub(in crate::radio) use decoder::same_occurrence;
pub use decoder::{LegacyWifiDecoder, WifiDecoder};
pub use tx::{
    EncodedWifiTransmission, LegacyWifiPhy, LegacyWifiTransmission, LegacyWifiTxConfig,
    WifiFcsPolicy, WifiPacketEncoder, WifiTxEncoder,
};
