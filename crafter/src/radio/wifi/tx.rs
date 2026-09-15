//! Wi-Fi packet encoding policy and owned PHY transmissions.

use super::super::{
    error::{RadioError, RadioResult},
    ht::{HtTransmission, HtTxConfig},
    ofdm_tx::{LegacyOfdmRate, LegacyOfdmTransmission, LegacyOfdmTxConfig},
    packet::writer::PacketEncoder,
    transport::{EncodedSamples, OwnedSamples},
};
use super::dsss::{
    DsssPreamble, LegacyDsssCckRate, LegacyDsssCckTransmission, LegacyDsssCckTxConfig,
};
use crate::{wire::PacketRecord, Dot11};

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
