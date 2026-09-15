//! Bounded sample transport and packet codec contracts.
//!
//! Sources transfer owned interleaved signed eight-bit I/Q storage. DSP consumes
//! normalized samples lazily: each component is divided by 128, giving [-1, 1).
//! IQ is never a packet layer; recovered frames cross the typed packet boundary.
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
