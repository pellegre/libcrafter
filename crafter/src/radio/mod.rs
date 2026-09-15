//! Bounded sample transport and packet codec contracts.
//!
//! Sources transfer owned interleaved signed eight-bit I/Q storage. DSP consumes
//! normalized samples lazily: each component is divided by 128, giving [-1, 1).
//! IQ is never a packet layer; recovered frames cross the typed packet boundary.
mod ampdu;
mod codec;
mod error;
#[cfg(any(feature = "radio-hackrf", test))]
mod hackrf;
#[cfg(feature = "radio-hackrf")]
mod hackrf_duplex;
#[cfg(any(feature = "radio-hackrf", test))]
mod hackrf_tx;
mod ht;
mod ldpc;
mod packet;
mod parallel;
mod stbc;
mod transport;
mod wifi;
mod windowed;

pub use codec::{
    DecodeOutput, FrameFraming, FrameIntegrity, PhyDecoder, PhyDiagnostic, RecoveredFrame,
    ResetReason,
};
pub use error::{RadioError, RadioResult};
#[cfg(feature = "radio-hackrf")]
pub use hackrf::{HackRfConfig, HackRfSource, HackRfStats};
#[cfg(feature = "radio-hackrf")]
pub use hackrf_duplex::{
    HackRfDirection, HackRfDuplex, HackRfDuplexControl, HackRfDuplexSink, HackRfDuplexSource,
    HackRfDuplexStatus,
};
#[cfg(feature = "radio-hackrf")]
pub use hackrf_tx::{HackRfTxConfig, HackRfTxSink, HackRfTxStats};
pub use ht::{
    HtCoding, HtFormat, HtGuardInterval, HtMcs, HtSignalBits, HtSignalError, HtSignalFields,
    HtTransmission, HtTxConfig,
};
pub use packet::{PacketEncoder, RadioPacketSource, RadioPacketWriter, RadioReceiveMetadata};
pub use parallel::{ParallelLegacyWifiDecoder, ParallelWifiDecoder};
pub use transport::{
    ComplexSample, Discontinuity, EncodedSamples, GapReason, IqChunk, IqContinuity, IqEvent,
    IqPosition, IqSink, IqSinkOutcome, IqSource, MemoryIqSource, OwnedSamples, ReaderIqSource,
    RxConfig, SampleCompletion, SampleFormat, SampleLoss, StreamEnd, TimeAnchor,
};
pub use wifi::{
    DecoderStats, DsssCckDecoder, DsssPlcpFields, DsssPreamble, EncodedWifiTransmission,
    LegacyDsssCckRate, LegacyDsssCckTransmission, LegacyDsssCckTxConfig, LegacyOfdmDecoder,
    LegacyOfdmRate, LegacyOfdmTransmission, LegacyOfdmTxConfig, LegacyWifiDecoder, LegacyWifiPhy,
    LegacyWifiTransmission, LegacyWifiTxConfig, OfdmSignalFields, SignalInfo, WifiDecoder,
    WifiFcsPolicy, WifiPacketEncoder, WifiTxEncoder,
};
pub use windowed::{WindowedLegacyWifiDecoder, WindowedWifiDecoder};

/// Compatibility facade for the deterministic in-memory sample sink.
pub type MemoryIqSink<T = LegacyWifiTransmission> = transport::MemoryIqSink<T>;
