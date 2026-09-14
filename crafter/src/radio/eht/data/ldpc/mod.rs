use super::{Capacity, Error};
use crate::protocols::link::{Dot11EhtTriggerCommonFields, Dot11EhtTriggerUserFields};
use crate::radio::eht::data::scrambler::Descrambler;
use crate::radio::{
    eht::{EhtNonMuUser, EhtOfdmaCommon, EhtResourceUnit},
    ldpc::rate::{self, Layout, Recovery},
};

#[cfg(test)]
mod tests;

pub(in crate::radio::eht) struct Recovered {
    pub psdu: Vec<u8>,
    pub failed_codewords: usize,
    pub first_failure: Option<rate::Error>,
}

/// One admitted EHT20 LDPC stream and its rate-matching layout.
pub(in crate::radio::eht) struct Decoder {
    layout: Layout,
    capacity: Capacity,
    symbols: usize,
}

impl Decoder {
    pub fn for_non_ofdma(
        fields: &crate::radio::eht::ReceivedSignal,
        capacity: Capacity,
        symbols: usize,
    ) -> Result<Self, Error> {
        let layout = Layout::eht(fields, u16::try_from(symbols).map_err(|_| Error::Overflow)?)
            .map_err(Error::Ldpc)?;
        Self::new(layout, capacity, symbols)
    }

    pub fn for_ofdma(
        common: &EhtOfdmaCommon,
        user: &EhtNonMuUser,
        resource: EhtResourceUnit,
        capacity: Capacity,
        symbols: usize,
    ) -> Result<Self, Error> {
        let layout = Layout::eht_ofdma(
            common,
            user,
            resource,
            u16::try_from(symbols).map_err(|_| Error::Overflow)?,
        )
        .map_err(Error::Ldpc)?;
        Self::new(layout, capacity, symbols)
    }

    pub fn for_tb(
        common: &Dot11EhtTriggerCommonFields,
        user: &Dot11EhtTriggerUserFields,
        resource: EhtResourceUnit,
        capacity: Capacity,
        symbols: usize,
    ) -> Result<Self, Error> {
        let layout = Layout::eht_tb(
            common,
            user,
            resource,
            u16::try_from(symbols).map_err(|_| Error::Overflow)?,
        )
        .map_err(Error::Ldpc)?;
        Self::new(layout, capacity, symbols)
    }

    fn new(layout: Layout, capacity: Capacity, symbols: usize) -> Result<Self, Error> {
        if !capacity.ldpc
            || capacity.tail_bits != 0
            || layout.symbols != symbols
            || layout.coded_bits_per_symbol != capacity.coded_per_symbol
            || layout.payload_bits != capacity.data_bits
            || layout.transmitted_bits != capacity.coded_bits
        {
            return Err(Error::Coding);
        }
        Ok(Self {
            layout,
            capacity,
            symbols,
        })
    }

    /// Recover the PSDU from one user's tone-mapped soft metrics.
    pub fn recover(
        self,
        metrics: &[f32],
        max_psdu: usize,
        partial: bool,
    ) -> Result<Recovered, Error> {
        if self.capacity.psdu_bytes > max_psdu {
            return Err(Error::FrameLimit);
        }
        if self.symbols.checked_mul(self.capacity.coded_per_symbol) != Some(metrics.len())
            || metrics.iter().any(|value| !value.is_finite())
        {
            return Err(Error::Fec);
        }
        let mut coded = Vec::new();
        coded
            .try_reserve_exact(self.capacity.coded_bits)
            .map_err(|_| Error::Overflow)?;
        for (symbol, block) in metrics
            .chunks_exact(self.capacity.coded_per_symbol)
            .enumerate()
        {
            let keep = if symbol + 1 == self.symbols {
                self.capacity.coded_last
            } else {
                self.capacity.coded_per_symbol
            };
            coded.extend_from_slice(&block[..keep]);
        }
        if coded.len() != self.capacity.coded_bits {
            return Err(Error::Fec);
        }
        let recovered = if partial {
            self.layout
                .recover_partial(&coded, 64)
                .map_err(Error::Ldpc)?
        } else {
            let (bits, iterations) = self.layout.recover(&coded, 64).map_err(Error::Ldpc)?;
            Recovery {
                bits,
                iterations,
                failed_codewords: 0,
                first_failure: None,
            }
        };
        let psdu = Descrambler::recover(recovered.bits, self.capacity.psdu_bytes)?;
        Ok(Recovered {
            psdu,
            failed_codewords: recovered.failed_codewords,
            first_failure: recovered.first_failure,
        })
    }
}

#[cfg(test)]
fn recover(
    fields: &crate::radio::eht::ReceivedSignal,
    capacity: Capacity,
    symbols: usize,
    metrics: &[f32],
    max_psdu: usize,
    partial: bool,
) -> Result<Recovered, Error> {
    Decoder::for_non_ofdma(fields, capacity, symbols)?.recover(metrics, max_psdu, partial)
}
