//! IEEE 802.11 PHY decoding and transmission policy.

mod decoder;
mod dsss;
pub(in crate::radio) mod ht;
pub(in crate::radio) mod ofdm;
mod tx;

pub(in crate::radio) use decoder::same_occurrence;
pub use decoder::{LegacyWifiDecoder, WifiDecoder};
pub use dsss::{
    DsssCckDecoder, DsssPlcpFields, DsssPreamble, LegacyDsssCckRate, LegacyDsssCckTransmission,
    LegacyDsssCckTxConfig,
};
pub use ht::{
    HtCoding, HtFormat, HtGuardInterval, HtMcs, HtSignalBits, HtSignalError, HtSignalFields,
    HtTransmission, HtTxConfig,
};
pub use ofdm::{
    DecoderStats, LegacyOfdmDecoder, LegacyOfdmRate, LegacyOfdmTransmission, LegacyOfdmTxConfig,
    OfdmSignalFields, SignalInfo,
};
pub use tx::{
    EncodedWifiTransmission, LegacyWifiPhy, LegacyWifiTransmission, LegacyWifiTxConfig,
    WifiFcsPolicy, WifiPacketEncoder, WifiTxEncoder,
};
