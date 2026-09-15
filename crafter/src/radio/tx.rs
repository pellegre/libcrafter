//! Packet codecs and protocol-independent sample transmission.

use super::{
    DsssPreamble, EncodedSamples, HtTransmission, HtTxConfig, IqSink, IqSinkOutcome,
    LegacyDsssCckRate, LegacyDsssCckTransmission, LegacyDsssCckTxConfig, LegacyOfdmRate,
    LegacyOfdmTransmission, LegacyOfdmTxConfig, OwnedSamples, RadioError, RadioResult,
    SampleCompletion,
};
use crate::{
    wire::{BackendKind, PacketRecord, PacketWriter, WireError, WriteReport},
    Dot11,
};

/// Codec from the existing typed packet abstraction into transport samples.
pub trait PacketEncoder: Clone {
    type Transmission: EncodedSamples;
    fn encode_packet(&self, record: &PacketRecord) -> RadioResult<Self::Transmission>;
}

/// Legacy and HT20 encoders behind the same protocol-independent sample contract.
#[derive(Debug, Clone, PartialEq)]
pub enum WifiPacketEncoder {
    Legacy(LegacyWifiTxConfig),
    Ht20(HtTxConfig),
}

impl PacketEncoder for WifiPacketEncoder {
    type Transmission = OwnedSamples;

    fn encode_packet(&self, record: &PacketRecord) -> RadioResult<OwnedSamples> {
        fn owned(samples: impl EncodedSamples) -> OwnedSamples {
            OwnedSamples {
                cs8: samples.samples_cs8().to_vec(),
                sample_rate_hz: samples.sample_rate_hz(),
            }
        }
        match self {
            Self::Legacy(config) => config.encode_packet(record).map(owned),
            Self::Ht20(config) => config.encode_packet(record).map(owned),
        }
    }
}

/// One decoder-supported legacy Wi-Fi PHY selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyWifiPhy {
    Ofdm(LegacyOfdmRate),
    DsssCck {
        rate: LegacyDsssCckRate,
        preamble: DsssPreamble,
    },
}

/// MAC FCS policy applied before PHY encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WifiFcsPolicy {
    #[default]
    Auto,
    Explicit([u8; 4]),
}

/// Bounded offline transmit configuration. Construction opens no device.
#[derive(Debug, Clone, PartialEq)]
pub struct LegacyWifiTxConfig {
    pub phy: LegacyWifiPhy,
    pub fcs: WifiFcsPolicy,
    pub ofdm: LegacyOfdmTxConfig,
    pub dsss_cck: LegacyDsssCckTxConfig,
}

impl LegacyWifiTxConfig {
    pub fn ofdm(rate: LegacyOfdmRate) -> Self {
        Self {
            phy: LegacyWifiPhy::Ofdm(rate),
            fcs: WifiFcsPolicy::Auto,
            ofdm: LegacyOfdmTxConfig::new(rate),
            dsss_cck: LegacyDsssCckTxConfig::new(LegacyDsssCckRate::Mbps1, DsssPreamble::Long),
        }
    }

    pub fn dsss_cck(rate: LegacyDsssCckRate, preamble: DsssPreamble) -> Self {
        Self {
            phy: LegacyWifiPhy::DsssCck { rate, preamble },
            fcs: WifiFcsPolicy::Auto,
            ofdm: LegacyOfdmTxConfig::new(LegacyOfdmRate::Mbps6),
            dsss_cck: LegacyDsssCckTxConfig::new(rate, preamble),
        }
    }

    pub fn with_fcs(mut self, fcs: WifiFcsPolicy) -> Self {
        self.fcs = fcs;
        self
    }
}

/// Inspectable owned output for one packet-to-IQ conversion.
#[derive(Debug, Clone, PartialEq)]
pub enum LegacyWifiTransmission {
    Ofdm(LegacyOfdmTransmission),
    DsssCck(LegacyDsssCckTransmission),
}

impl LegacyWifiTransmission {
    pub fn mac_bytes(&self) -> &[u8] {
        match self {
            Self::Ofdm(tx) => &tx.mac_bytes,
            Self::DsssCck(tx) => &tx.mac_bytes,
        }
    }

    pub fn psdu_bytes(&self) -> &[u8] {
        match self {
            Self::Ofdm(tx) => &tx.psdu_bytes,
            Self::DsssCck(tx) => &tx.psdu_bytes,
        }
    }

    pub fn cs8(&self) -> &[i8] {
        match self {
            Self::Ofdm(tx) => &tx.cs8,
            Self::DsssCck(tx) => &tx.cs8,
        }
    }

    pub fn sample_count(&self) -> usize {
        self.cs8().len() / 2
    }

    pub const fn phy(&self) -> LegacyWifiPhy {
        match self {
            Self::Ofdm(tx) => LegacyWifiPhy::Ofdm(tx.rate),
            Self::DsssCck(tx) => LegacyWifiPhy::DsssCck {
                rate: tx.rate,
                preamble: tx.preamble,
            },
        }
    }
}

/// Common behavior of an owned, already encoded Wi-Fi IQ transmission.
pub trait EncodedWifiTransmission: Clone {
    fn mac_bytes(&self) -> &[u8];
    fn psdu_bytes(&self) -> &[u8];
    fn cs8(&self) -> &[i8];
    fn encoded_sample_rate_hz(&self) -> u32 {
        20_000_000
    }

    fn sample_count(&self) -> usize {
        self.cs8().len() / 2
    }
}

impl<T: EncodedWifiTransmission> EncodedSamples for T {
    fn samples_cs8(&self) -> &[i8] {
        self.cs8()
    }
    fn sample_rate_hz(&self) -> u32 {
        EncodedWifiTransmission::encoded_sample_rate_hz(self)
    }
}

impl EncodedWifiTransmission for LegacyWifiTransmission {
    fn encoded_sample_rate_hz(&self) -> u32 {
        match self {
            Self::Ofdm(tx) => tx.sample_rate_hz,
            Self::DsssCck(tx) => tx.sample_rate_hz,
        }
    }
    fn mac_bytes(&self) -> &[u8] {
        self.mac_bytes()
    }

    fn psdu_bytes(&self) -> &[u8] {
        self.psdu_bytes()
    }

    fn cs8(&self) -> &[i8] {
        self.cs8()
    }
}

impl EncodedWifiTransmission for HtTransmission {
    fn encoded_sample_rate_hz(&self) -> u32 {
        self.sample_rate_hz
    }
    fn mac_bytes(&self) -> &[u8] {
        &self.mac_bytes
    }

    fn psdu_bytes(&self) -> &[u8] {
        &self.psdu_bytes
    }

    fn cs8(&self) -> &[i8] {
        &self.cs8
    }
}

/// PHY configuration that can encode one compiled MAC frame.
pub trait WifiTxEncoder: Clone {
    type Transmission: EncodedWifiTransmission;

    fn encode_mac(&self, mac_bytes: &[u8]) -> RadioResult<Self::Transmission>;
}

impl WifiTxEncoder for LegacyWifiTxConfig {
    type Transmission = LegacyWifiTransmission;

    fn encode_mac(&self, mac_bytes: &[u8]) -> RadioResult<Self::Transmission> {
        let fcs = match self.fcs {
            WifiFcsPolicy::Auto => None,
            WifiFcsPolicy::Explicit(bytes) => Some(bytes),
        };
        match self.phy {
            LegacyWifiPhy::Ofdm(rate) => {
                let mut config = self.ofdm.clone();
                config.rate = rate;
                LegacyOfdmTransmission::encode(mac_bytes, fcs, &config)
                    .map(LegacyWifiTransmission::Ofdm)
            }
            LegacyWifiPhy::DsssCck { rate, preamble } => {
                let mut config = self.dsss_cck.clone();
                config.rate = rate;
                config.preamble = preamble;
                LegacyDsssCckTransmission::encode(mac_bytes, fcs, &config)
                    .map(LegacyWifiTransmission::DsssCck)
            }
        }
    }
}

impl WifiTxEncoder for HtTxConfig {
    type Transmission = HtTransmission;

    fn encode_mac(&self, mac_bytes: &[u8]) -> RadioResult<Self::Transmission> {
        let fcs = match self.fcs {
            WifiFcsPolicy::Auto => None,
            WifiFcsPolicy::Explicit(bytes) => Some(bytes),
        };
        HtTransmission::encode(mac_bytes, fcs, self)
    }
}

/// Packet writer using a selected protocol codec and sample sink.
/// Existing Wi-Fi configurations require a bare `Dot11` root.
#[derive(Debug, Clone)]
pub struct RadioPacketWriter<S, C: PacketEncoder = LegacyWifiTxConfig> {
    config: C,
    sink: S,
    last: Option<C::Transmission>,
    last_outcome: Option<IqSinkOutcome>,
}

impl<S, C: PacketEncoder> RadioPacketWriter<S, C> {
    pub const fn new(config: C, sink: S) -> Self {
        Self {
            config,
            sink,
            last: None,
            last_outcome: None,
        }
    }

    pub const fn config(&self) -> &C {
        &self.config
    }

    pub const fn sink(&self) -> &S {
        &self.sink
    }

    pub fn sink_mut(&mut self) -> &mut S {
        &mut self.sink
    }

    pub const fn last_transmission(&self) -> Option<&C::Transmission> {
        self.last.as_ref()
    }

    pub fn into_sink(self) -> S {
        self.sink
    }
    pub fn last_outcome(&self) -> Option<&IqSinkOutcome> {
        self.last_outcome.as_ref()
    }
}

impl<C: WifiTxEncoder> PacketEncoder for C {
    type Transmission = C::Transmission;
    fn encode_packet(&self, record: &PacketRecord) -> RadioResult<Self::Transmission> {
        if !record
            .packet()
            .get(0)
            .is_some_and(|layer| layer.as_any().is::<Dot11>())
        {
            return Err(RadioError::Invalid {
                field: "packet",
                reason: "Wi-Fi IQ transmission requires a bare Dot11 root",
            });
        }
        let compiled = record
            .packet()
            .compile()
            .map_err(|error| RadioError::Source(error.to_string()))?;
        self.encode_mac(compiled.as_bytes())
    }
}

impl<S, C> RadioPacketWriter<S, C>
where
    C: PacketEncoder,
    S: IqSink<C::Transmission>,
{
    pub fn encode_record(&self, record: &PacketRecord) -> RadioResult<C::Transmission> {
        self.config.encode_packet(record)
    }
}

impl<S, C> PacketWriter for RadioPacketWriter<S, C>
where
    C: PacketEncoder,
    S: IqSink<C::Transmission>,
{
    fn write_record(&mut self, record: &PacketRecord) -> crate::wire::Result<WriteReport> {
        self.last = None;
        self.last_outcome = None;
        let requested = record.packet().compile()?.as_bytes().len();
        let transmission = self
            .encode_record(record)
            .map_err(|error| WireError::backend("radio-iq", "encode", error.to_string()))?;
        transmission
            .validate_samples()
            .map_err(|error| WireError::backend("radio-iq", "encode", error.to_string()))?;
        let outcome = self
            .sink
            .write_outcome(&transmission)
            .map_err(|error| WireError::backend("radio-iq", "write", error.to_string()))?;
        self.last_outcome = Some(outcome.clone());
        self.last = Some(transmission);
        if matches!(
            outcome.completion,
            SampleCompletion::Incomplete | SampleCompletion::Cancelled
        ) || outcome
            .samples_supplied
            .is_some_and(|n| n != outcome.samples_requested)
        {
            return Err(WireError::backend(
                "radio-iq",
                "write",
                format!("sample submission failed: {outcome:?}"),
            ));
        }
        Ok(WriteReport::new(
            BackendKind::Other("radio-iq".into()),
            requested,
            requested,
            outcome.live == Some(false),
        )
        .with_target_details(match outcome.live {
            Some(false) => "memory-cs8",
            Some(true) => "live-cs8",
            None => "cs8",
        })
        .with_radio_outcome(outcome))
    }
}
