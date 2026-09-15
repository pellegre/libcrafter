//! The packet-to-sample boundary for protocol codecs and IQ sinks.

use super::super::{
    error::RadioResult,
    transport::{EncodedSamples, IqSink, IqSinkOutcome, SampleCompletion},
    wifi::LegacyWifiTxConfig,
};
use crate::wire::{BackendKind, PacketRecord, PacketWriter, WireError, WriteReport};

/// Codec from the existing typed packet abstraction into transport samples.
pub trait PacketEncoder: Clone {
    type Transmission: EncodedSamples;
    fn encode_packet(&self, record: &PacketRecord) -> RadioResult<Self::Transmission>;
}

/// Packet writer using a selected protocol codec and sample sink.
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
