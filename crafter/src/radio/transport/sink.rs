use super::super::error::{RadioError, RadioResult};

/// Storage format at the sample transport boundary. One sample is one I/Q pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleFormat {
    Cs8,
}

/// Protocol-independent, already encoded sample storage.
pub trait EncodedSamples: Clone {
    fn samples_cs8(&self) -> &[i8];
    fn sample_rate_hz(&self) -> u32;
    fn sample_format(&self) -> SampleFormat {
        SampleFormat::Cs8
    }
    fn validate_samples(&self) -> RadioResult<()> {
        if self.sample_rate_hz() == 0
            || self.samples_cs8().is_empty()
            || self.samples_cs8().len() % 2 != 0
        {
            return Err(RadioError::Invalid {
                field: "samples",
                reason: "requires a nonzero rate and nonempty complete I/Q pairs",
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedSamples {
    pub cs8: Vec<i8>,
    pub sample_rate_hz: u32,
}

impl EncodedSamples for OwnedSamples {
    fn samples_cs8(&self) -> &[i8] {
        &self.cs8
    }

    fn sample_rate_hz(&self) -> u32 {
        self.sample_rate_hz
    }
}

/// Local completion evidence; none of these states establishes peer reception.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleCompletion {
    Unconfirmed,
    Stored,
    DeviceCompleted,
    Incomplete,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IqSinkOutcome {
    /// Complex samples in the device plan, including repetitions and gaps.
    pub samples_requested: u64,
    /// Plan samples supplied to the sink; unknown for legacy adapters.
    pub samples_supplied: Option<u64>,
    /// Additional transport padding, in complex samples.
    pub padded_samples: u64,
    pub completion: SampleCompletion,
    /// Whether this sink used live hardware, if known.
    pub live: Option<bool>,
}

/// Backend contract for encoded samples, independent of packet protocol.
pub trait IqSink<T: EncodedSamples = crate::radio::LegacyWifiTransmission> {
    fn write(&mut self, transmission: &T) -> RadioResult<()>;

    /// Compatibility path: successful legacy writes establish acceptance only.
    fn write_outcome(&mut self, transmission: &T) -> RadioResult<IqSinkOutcome> {
        self.write(transmission)?;
        Ok(IqSinkOutcome {
            samples_requested: (transmission.samples_cs8().len() / 2) as u64,
            samples_supplied: None,
            padded_samples: 0,
            completion: SampleCompletion::Unconfirmed,
            live: None,
        })
    }
}

/// Deterministic sink retaining every accepted transmission.
#[derive(Debug, Clone, Default)]
pub struct MemoryIqSink<T: EncodedSamples = OwnedSamples> {
    transmissions: Vec<T>,
}

impl<T: EncodedSamples> MemoryIqSink<T> {
    pub const fn new() -> Self {
        Self {
            transmissions: Vec::new(),
        }
    }

    pub fn transmissions(&self) -> &[T] {
        &self.transmissions
    }

    pub fn into_transmissions(self) -> Vec<T> {
        self.transmissions
    }
}

impl<T: EncodedSamples> IqSink<T> for MemoryIqSink<T> {
    fn write(&mut self, transmission: &T) -> RadioResult<()> {
        transmission.validate_samples()?;
        self.transmissions.push(transmission.clone());
        Ok(())
    }

    fn write_outcome(&mut self, transmission: &T) -> RadioResult<IqSinkOutcome> {
        self.write(transmission)?;
        let samples = (transmission.samples_cs8().len() / 2) as u64;
        Ok(IqSinkOutcome {
            samples_requested: samples,
            samples_supplied: Some(samples),
            padded_samples: 0,
            completion: SampleCompletion::Stored,
            live: Some(false),
        })
    }
}
