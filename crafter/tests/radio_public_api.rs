#![cfg(feature = "radio")]

use crafter::radio::{
    ComplexSample, DecodeOutput, DecoderStats, Discontinuity, DsssCckDecoder, DsssPlcpFields,
    DsssPreamble, EncodedSamples, EncodedWifiTransmission, FrameFraming, FrameIntegrity, GapReason,
    HtCoding, HtFormat, HtGuardInterval, HtMcs, HtSignalBits, HtSignalError, HtSignalFields,
    HtTransmission, HtTxConfig, IqChunk, IqContinuity, IqEvent, IqPosition, IqSink, IqSinkOutcome,
    IqSource, LegacyDsssCckRate, LegacyDsssCckTransmission, LegacyDsssCckTxConfig,
    LegacyOfdmDecoder, LegacyOfdmRate, LegacyOfdmTransmission, LegacyOfdmTxConfig,
    LegacyWifiDecoder, LegacyWifiPhy, LegacyWifiTransmission, LegacyWifiTxConfig, MemoryIqSink,
    MemoryIqSource, OfdmSignalFields, OwnedSamples, PacketEncoder, ParallelLegacyWifiDecoder,
    ParallelWifiDecoder, PhyDecoder, PhyDiagnostic, RadioError, RadioPacketSource,
    RadioPacketWriter, RadioReceiveMetadata, RadioResult, ReaderIqSource, RecoveredFrame,
    ResetReason, RxConfig, SampleCompletion, SampleFormat, SampleLoss, SignalInfo, StreamEnd,
    TimeAnchor, WifiDecoder, WifiFcsPolicy, WifiPacketEncoder, WifiTxEncoder,
    WindowedLegacyWifiDecoder, WindowedWifiDecoder,
};
use crafter::{prelude, PacketWriter};
use std::{io::Cursor, time::Duration};

fn assert_type<T>() {}
fn assert_iq_source<T: IqSource>() {}
fn assert_phy_decoder<T: PhyDecoder>() {}
fn assert_iq_sink<T: IqSink<OwnedSamples>>() {}
fn assert_packet_encoder<T: PacketEncoder>() {}
fn assert_wifi_encoder<T: WifiTxEncoder>() {}
fn assert_encoded_samples<T: EncodedSamples>() {}
fn assert_wifi_transmission<T: EncodedWifiTransmission>() {}
fn assert_packet_writer<T: PacketWriter>() {}

fn bounds() -> RxConfig {
    RxConfig {
        sample_rate_hz: 20_000_000,
        center_frequency_hz: 2_412_000_000,
        max_chunk_samples: 4,
        max_buffer_samples: 512,
        max_frame_bytes: 4095,
        max_pending_frames: 4,
        max_capture_samples: 4,
        max_duration: Duration::from_secs(1),
    }
}

fn position() -> IqPosition {
    IqPosition {
        epoch: 0,
        sequence: 0,
        sample_index: 0,
        time_anchor: None,
        discontinuity: None,
    }
}

#[test]
fn radio_facade_exports_the_existing_public_surface() {
    assert_type::<RadioError>();
    assert_type::<RadioResult<()>>();
    assert_type::<RxConfig>();
    assert_type::<ComplexSample>();
    assert_type::<TimeAnchor>();
    assert_type::<SampleLoss>();
    assert_type::<GapReason>();
    assert_type::<Discontinuity>();
    assert_type::<IqPosition>();
    assert_type::<IqChunk>();
    assert_type::<StreamEnd>();
    assert_type::<IqEvent>();
    assert_type::<ResetReason>();
    assert_type::<PhyDiagnostic>();
    assert_type::<FrameIntegrity>();
    assert_type::<FrameFraming>();
    assert_type::<RecoveredFrame>();
    assert_type::<DecodeOutput>();
    assert_type::<IqContinuity>();

    assert_type::<DecoderStats>();
    assert_type::<SignalInfo>();
    assert_type::<DsssCckDecoder>();
    assert_type::<LegacyOfdmDecoder>();
    assert_type::<LegacyWifiDecoder>();
    assert_type::<WifiDecoder>();
    assert_type::<ParallelLegacyWifiDecoder>();
    assert_type::<ParallelWifiDecoder>();
    assert_type::<WindowedLegacyWifiDecoder>();
    assert_type::<WindowedWifiDecoder>();

    assert_type::<DsssPlcpFields>();
    assert_type::<DsssPreamble>();
    assert_type::<LegacyDsssCckRate>();
    assert_type::<LegacyDsssCckTxConfig>();
    assert_type::<LegacyDsssCckTransmission>();
    assert_type::<LegacyOfdmRate>();
    assert_type::<LegacyOfdmTxConfig>();
    assert_type::<LegacyOfdmTransmission>();
    assert_type::<OfdmSignalFields>();
    assert_type::<HtCoding>();
    assert_type::<HtFormat>();
    assert_type::<HtGuardInterval>();
    assert_type::<HtMcs>();
    assert_type::<HtSignalBits>();
    assert_type::<HtSignalError>();
    assert_type::<HtSignalFields>();
    assert_type::<HtTransmission>();
    assert_type::<HtTxConfig>();

    assert_type::<SampleFormat>();
    assert_type::<OwnedSamples>();
    assert_type::<SampleCompletion>();
    assert_type::<IqSinkOutcome>();
    assert_type::<WifiPacketEncoder>();
    assert_type::<LegacyWifiPhy>();
    assert_type::<WifiFcsPolicy>();
    assert_type::<LegacyWifiTxConfig>();
    assert_type::<LegacyWifiTransmission>();
    assert_type::<MemoryIqSink<OwnedSamples>>();
    assert_type::<ReaderIqSource<Cursor<Vec<u8>>>>();
    assert_type::<MemoryIqSource>();
    assert_type::<RadioReceiveMetadata>();
    assert_type::<RadioPacketSource<MemoryIqSource, WifiDecoder>>();
    assert_type::<RadioPacketWriter<MemoryIqSink<LegacyWifiTransmission>>>();

    assert_iq_source::<MemoryIqSource>();
    assert_phy_decoder::<DsssCckDecoder>();
    assert_phy_decoder::<LegacyOfdmDecoder>();
    assert_phy_decoder::<WifiDecoder>();
    assert_iq_sink::<MemoryIqSink<OwnedSamples>>();
    assert_packet_encoder::<LegacyWifiTxConfig>();
    assert_packet_encoder::<HtTxConfig>();
    assert_packet_encoder::<WifiPacketEncoder>();
    assert_wifi_encoder::<LegacyWifiTxConfig>();
    assert_wifi_encoder::<HtTxConfig>();
    assert_encoded_samples::<OwnedSamples>();
    assert_wifi_transmission::<LegacyWifiTransmission>();
    assert_wifi_transmission::<HtTransmission>();
    assert_packet_writer::<RadioPacketWriter<MemoryIqSink<LegacyWifiTransmission>>>();

    let source = MemoryIqSource::from_cs8(vec![0, 0], bounds(), position()).unwrap();
    let writer = RadioPacketWriter::new(
        LegacyWifiTxConfig::ofdm(LegacyOfdmRate::Mbps6),
        MemoryIqSink::<LegacyWifiTransmission>::new(),
    );
    assert!(writer.last_transmission().is_none());
    assert!(writer.last_outcome().is_none());
    let _source = RadioPacketSource::new(source, WifiDecoder::new(), bounds()).unwrap();
}

macro_rules! assert_transmit_surface {
    ($surface:path) => {{
        use $surface as api;

        assert_type::<api::DsssPlcpFields>();
        assert_type::<api::DsssPreamble>();
        assert_type::<api::HtCoding>();
        assert_type::<api::HtFormat>();
        assert_type::<api::HtGuardInterval>();
        assert_type::<api::HtMcs>();
        assert_type::<api::HtSignalBits>();
        assert_type::<api::HtSignalError>();
        assert_type::<api::HtSignalFields>();
        assert_type::<api::HtTransmission>();
        assert_type::<api::HtTxConfig>();
        assert_type::<api::IqSinkOutcome>();
        assert_type::<api::LegacyDsssCckRate>();
        assert_type::<api::LegacyDsssCckTransmission>();
        assert_type::<api::LegacyDsssCckTxConfig>();
        assert_type::<api::LegacyOfdmRate>();
        assert_type::<api::LegacyOfdmTransmission>();
        assert_type::<api::LegacyOfdmTxConfig>();
        assert_type::<api::LegacyWifiPhy>();
        assert_type::<api::LegacyWifiTransmission>();
        assert_type::<api::LegacyWifiTxConfig>();
        assert_type::<api::MemoryIqSink<api::OwnedSamples>>();
        assert_type::<api::OfdmSignalFields>();
        assert_type::<api::OwnedSamples>();
        assert_type::<api::RadioPacketWriter<api::MemoryIqSink<api::LegacyWifiTransmission>>>();
        assert_type::<api::SampleCompletion>();
        assert_type::<api::SampleFormat>();
        assert_type::<api::WifiDecoder>();
        assert_type::<api::WifiFcsPolicy>();
        assert_type::<api::WifiPacketEncoder>();

        fn encoded<T: api::EncodedSamples>() {}
        fn wifi_transmission<T: api::EncodedWifiTransmission>() {}
        fn sink<T: api::IqSink<api::OwnedSamples>>() {}
        fn packet_encoder<T: api::PacketEncoder>() {}
        fn wifi_encoder<T: api::WifiTxEncoder>() {}

        encoded::<api::OwnedSamples>();
        wifi_transmission::<api::LegacyWifiTransmission>();
        sink::<api::MemoryIqSink<api::OwnedSamples>>();
        packet_encoder::<api::LegacyWifiTxConfig>();
        packet_encoder::<api::WifiPacketEncoder>();
        wifi_encoder::<api::LegacyWifiTxConfig>();
        wifi_encoder::<api::HtTxConfig>();
    }};
}

#[test]
fn crate_root_preserves_radio_transmit_exports() {
    assert_transmit_surface!(crafter);
}

#[test]
fn prelude_preserves_radio_transmit_exports() {
    assert_transmit_surface!(prelude);
}

#[cfg(feature = "radio-hackrf")]
#[test]
fn hackrf_exports_and_trait_relationships_are_preserved() {
    use crafter::radio::{
        HackRfConfig, HackRfDirection, HackRfDuplex, HackRfDuplexControl, HackRfDuplexSink,
        HackRfDuplexSource, HackRfDuplexStatus, HackRfSource, HackRfStats, HackRfTxConfig,
        HackRfTxSink, HackRfTxStats,
    };

    assert_type::<HackRfConfig>();
    assert_type::<HackRfSource>();
    assert_type::<HackRfStats>();
    assert_type::<HackRfTxConfig>();
    assert_type::<HackRfTxSink>();
    assert_type::<HackRfTxStats>();
    assert_type::<HackRfDirection>();
    assert_type::<HackRfDuplex>();
    assert_type::<HackRfDuplexControl>();
    assert_type::<HackRfDuplexSource>();
    assert_type::<HackRfDuplexSink>();
    assert_type::<HackRfDuplexStatus>();

    assert_iq_source::<HackRfSource>();
    assert_iq_source::<HackRfDuplexSource>();
    assert_iq_sink::<HackRfTxSink>();
    assert_iq_sink::<HackRfDuplexSink>();

    assert_type::<crafter::HackRfTxConfig>();
    assert_type::<crafter::HackRfTxSink>();
    assert_type::<crafter::HackRfTxStats>();
    assert_type::<prelude::HackRfTxConfig>();
    assert_type::<prelude::HackRfTxSink>();
    assert_type::<prelude::HackRfTxStats>();
}
