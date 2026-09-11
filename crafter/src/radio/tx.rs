//! Packet-shaped offline legacy Wi-Fi IQ transmission.

use super::{
    DsssPreamble, LegacyDsssCckRate, LegacyDsssCckTransmission, LegacyDsssCckTxConfig,
    LegacyOfdmRate, LegacyOfdmTransmission, LegacyOfdmTxConfig, RadioError, RadioResult,
};
use crate::{
    wire::{BackendKind, PacketRecord, PacketWriter, WireError, WriteReport},
    Dot11,
};

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

/// Backend contract for already encoded, owned Wi-Fi IQ.
pub trait IqSink {
    fn write(&mut self, transmission: &LegacyWifiTransmission) -> RadioResult<()>;
}

/// Deterministic sink retaining every accepted transmission.
#[derive(Debug, Clone, Default)]
pub struct MemoryIqSink {
    transmissions: Vec<LegacyWifiTransmission>,
}

impl MemoryIqSink {
    pub const fn new() -> Self {
        Self {
            transmissions: Vec::new(),
        }
    }

    pub fn transmissions(&self) -> &[LegacyWifiTransmission] {
        &self.transmissions
    }

    pub fn into_transmissions(self) -> Vec<LegacyWifiTransmission> {
        self.transmissions
    }
}

impl IqSink for MemoryIqSink {
    fn write(&mut self, transmission: &LegacyWifiTransmission) -> RadioResult<()> {
        self.transmissions.push(transmission.clone());
        Ok(())
    }
}

/// Packet writer compiling a bare `Dot11` stack into one legacy IQ waveform.
#[derive(Debug, Clone)]
pub struct RadioPacketWriter<S> {
    config: LegacyWifiTxConfig,
    sink: S,
    last: Option<LegacyWifiTransmission>,
}

impl<S> RadioPacketWriter<S> {
    pub const fn new(config: LegacyWifiTxConfig, sink: S) -> Self {
        Self {
            config,
            sink,
            last: None,
        }
    }

    pub const fn config(&self) -> &LegacyWifiTxConfig {
        &self.config
    }

    pub const fn sink(&self) -> &S {
        &self.sink
    }

    pub fn sink_mut(&mut self) -> &mut S {
        &mut self.sink
    }

    pub const fn last_transmission(&self) -> Option<&LegacyWifiTransmission> {
        self.last.as_ref()
    }

    pub fn into_sink(self) -> S {
        self.sink
    }
}

impl<S: IqSink> RadioPacketWriter<S> {
    pub fn encode_record(&self, record: &PacketRecord) -> RadioResult<LegacyWifiTransmission> {
        if !record
            .packet()
            .get(0)
            .is_some_and(|layer| layer.as_any().is::<Dot11>())
        {
            return Err(RadioError::Invalid {
                field: "packet",
                reason: "legacy Wi-Fi IQ transmission requires a bare Dot11 root",
            });
        }
        let compiled = record
            .packet()
            .compile()
            .map_err(|error| RadioError::Source(error.to_string()))?;
        let fcs = match self.config.fcs {
            WifiFcsPolicy::Auto => None,
            WifiFcsPolicy::Explicit(bytes) => Some(bytes),
        };
        match self.config.phy {
            LegacyWifiPhy::Ofdm(rate) => {
                let mut config = self.config.ofdm.clone();
                config.rate = rate;
                LegacyOfdmTransmission::encode(compiled.as_bytes(), fcs, &config)
                    .map(LegacyWifiTransmission::Ofdm)
            }
            LegacyWifiPhy::DsssCck { rate, preamble } => {
                let mut config = self.config.dsss_cck.clone();
                config.rate = rate;
                config.preamble = preamble;
                LegacyDsssCckTransmission::encode(compiled.as_bytes(), fcs, &config)
                    .map(LegacyWifiTransmission::DsssCck)
            }
        }
    }
}

impl<S: IqSink> PacketWriter for RadioPacketWriter<S> {
    fn write_record(&mut self, record: &PacketRecord) -> crate::wire::Result<WriteReport> {
        let transmission = self
            .encode_record(record)
            .map_err(|error| WireError::backend("radio-iq", "encode", error.to_string()))?;
        self.sink
            .write(&transmission)
            .map_err(|error| WireError::backend("radio-iq", "write", error.to_string()))?;
        let requested = transmission.cs8().len();
        let written = requested;
        self.last = Some(transmission);
        Ok(WriteReport::new(
            BackendKind::Other("radio-iq".into()),
            requested,
            written,
            true,
        )
        .with_target_details("offline-cs8"))
    }
}
