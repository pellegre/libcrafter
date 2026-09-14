use super::{layout::Layout, resource, Error, Trained, TrainedResource};
use crate::radio::{eht::sig::iq::Fields as SignalFields, sync::Acquisition, ComplexSample};

/// Recover supported one-stream EHT-LTF channels from one 20 MHz PPDU.
pub(in crate::radio) struct Receiver<'a> {
    samples: &'a [ComplexSample],
    acquisition: &'a Acquisition,
    signal: SignalFields,
    layout: Layout,
}

impl<'a> Receiver<'a> {
    pub(in crate::radio) fn recover(
        samples: &'a [ComplexSample],
        acquisition: &'a Acquisition,
        signal: SignalFields,
    ) -> Result<Trained, Error> {
        Self::new(samples, acquisition, signal)?.train()
    }

    fn new(
        samples: &'a [ComplexSample],
        acquisition: &'a Acquisition,
        signal: SignalFields,
    ) -> Result<Self, Error> {
        let layout = Layout::new(&signal, acquisition)?;
        if samples.len() < layout.required {
            return Err(Error::Truncated {
                required: layout.required,
                available: samples.len(),
            });
        }
        Ok(Self {
            samples: &samples[..layout.required],
            acquisition,
            signal,
            layout,
        })
    }

    fn train(self) -> Result<Trained, Error> {
        debug_assert!(self.layout.ltf_symbols > 0);
        let resources: Vec<_> = self
            .layout
            .resources
            .iter()
            .map(|layout| TrainedResource {
                resource: layout.resource,
                users: layout.users.clone(),
                channel: if layout.train {
                    resource::train(
                        self.samples,
                        self.acquisition,
                        layout.resource,
                        self.layout.ltf_size,
                        self.layout.guard,
                        self.layout.ltf_start,
                    )
                } else {
                    None
                },
            })
            .collect();
        if !resources.iter().any(|resource| resource.channel.is_some()) {
            return Err(Error::Samples);
        }
        Ok(Trained {
            signal: self.signal,
            resources,
            data_start: self.layout.data_start,
            guard: self.layout.guard,
        })
    }
}
