use super::{non_ofdma, ofdma, Error};
use crate::radio::{eht::training::Trained, sync::Acquisition, ComplexSample, SignalInfo};

pub(in crate::radio) enum Admission {
    NonOfdma(non_ofdma::Admission),
    Ofdma(ofdma::Admission),
}

impl Admission {
    pub fn required_samples(&self) -> usize {
        match self {
            Self::NonOfdma(admission) => admission.required_samples,
            Self::Ofdma(admission) => admission.required_samples,
        }
    }

    pub fn info(&self) -> SignalInfo {
        match self {
            Self::NonOfdma(admission) => admission.info,
            Self::Ofdma(admission) => admission.info(),
        }
    }
}

pub(in crate::radio) enum Recovered {
    NonOfdma(non_ofdma::Recovered),
    Ofdma(ofdma::Recovered),
}

/// Format-dispatching EHT DATA receiver.
pub(in crate::radio) struct Receiver;

impl Receiver {
    pub fn admit(
        trained: Trained,
        max_psdu: usize,
        max_samples: usize,
    ) -> Result<Admission, Error> {
        match &trained.signal.signal {
            crate::radio::eht::SignalFields::NonOfdma(_) => {
                non_ofdma::Receiver::admit(trained, max_psdu, max_samples).map(Admission::NonOfdma)
            }
            crate::radio::eht::SignalFields::Ofdma(_) => {
                ofdma::Receiver::admit(trained, max_psdu, max_samples).map(Admission::Ofdma)
            }
        }
    }

    pub fn recover_aggregate(
        admission: Admission,
        samples: &[ComplexSample],
        acquisition: &Acquisition,
        max_psdu: usize,
    ) -> Result<Recovered, Error> {
        match admission {
            Admission::NonOfdma(admission) => {
                non_ofdma::Receiver::recover_aggregate(admission, samples, acquisition, max_psdu)
                    .map(Recovered::NonOfdma)
            }
            Admission::Ofdma(admission) => {
                ofdma::Receiver::recover(admission, samples, acquisition, max_psdu)
                    .map(Recovered::Ofdma)
            }
        }
    }
}
