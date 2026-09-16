//! Radio sample transport, packet adapters, Wi-Fi PHYs, and optional HackRF I/O.
//!
//! IQ transport and codec contracts stay separate from typed packet adapters.
//! Wi-Fi owns PHY behavior, while HackRF only implements bounded sample transport.
//! This module is the compatibility facade over those private subsystems.
mod codec;
mod error;
#[cfg(any(feature = "radio-hackrf", test))]
mod hackrf;
mod packet;
mod transport;
mod wifi;

pub use codec::{
    DecodeOutput, FrameFraming, FrameIntegrity, PhyDecoder, PhyDiagnostic, RecoveredFrame,
    ResetReason,
};
pub use error::{RadioError, RadioResult};
#[cfg(feature = "radio-hackrf")]
pub use hackrf::{
    HackRfConfig, HackRfDirection, HackRfDuplex, HackRfDuplexControl, HackRfDuplexSink,
    HackRfDuplexSource, HackRfDuplexStatus, HackRfSource, HackRfStats, HackRfTxConfig,
    HackRfTxSink, HackRfTxStats,
};
pub use packet::{PacketEncoder, RadioPacketSource, RadioPacketWriter, RadioReceiveMetadata};
pub use transport::{
    ComplexSample, Discontinuity, EncodedSamples, GapReason, IqChunk, IqContinuity, IqEvent,
    IqPosition, IqSink, IqSinkOutcome, IqSource, MemoryIqSource, OwnedSamples, ReaderIqSource,
    RxConfig, SampleCompletion, SampleFormat, SampleLoss, StreamEnd, TimeAnchor,
};
pub use wifi::{
    DecoderStats, DsssCckDecoder, DsssPlcpFields, DsssPreamble, EncodedWifiTransmission, HtCoding,
    HtFormat, HtGuardInterval, HtMcs, HtSignalBits, HtSignalError, HtSignalFields, HtTransmission,
    HtTxConfig, LegacyDsssCckRate, LegacyDsssCckTransmission, LegacyDsssCckTxConfig,
    LegacyOfdmDecoder, LegacyOfdmRate, LegacyOfdmTransmission, LegacyOfdmTxConfig,
    LegacyWifiDecoder, LegacyWifiPhy, LegacyWifiTransmission, LegacyWifiTxConfig, OfdmSignalFields,
    ParallelLegacyWifiDecoder, ParallelWifiDecoder, SignalInfo, WifiDecoder, WifiFcsPolicy,
    WifiPacketEncoder, WifiTxEncoder, WindowedLegacyWifiDecoder, WindowedWifiDecoder,
};

/// Compatibility facade for the deterministic in-memory sample sink.
pub type MemoryIqSink<T = LegacyWifiTransmission> = transport::MemoryIqSink<T>;
