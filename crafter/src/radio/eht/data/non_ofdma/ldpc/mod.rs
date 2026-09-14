use super::{Capacity, Error};
use crate::radio::eht::data::scrambler::Descrambler;
use crate::radio::ldpc::rate::{self, Layout, Recovery};

#[cfg(test)]
mod tests;

pub(super) struct Recovered {
    pub psdu: Vec<u8>,
    pub failed_codewords: usize,
    pub first_failure: Option<rate::Error>,
}

/// Recover one admitted EHT20 LDPC payload from tone-ordered soft metrics.
pub(super) fn recover(
    fields: &crate::radio::eht::ReceivedSignal,
    capacity: Capacity,
    symbols: usize,
    metrics: &[f32],
    max_psdu: usize,
    partial: bool,
) -> Result<Recovered, Error> {
    if !capacity.ldpc {
        return Err(Error::Coding);
    }
    if capacity.psdu_bytes > max_psdu {
        return Err(Error::FrameLimit);
    }
    if symbols.checked_mul(capacity.coded_per_symbol) != Some(metrics.len()) {
        return Err(Error::Fec);
    }
    if metrics.iter().any(|value| !value.is_finite()) {
        return Err(Error::Fec);
    }
    let layout = Layout::eht(fields, u16::try_from(symbols).map_err(|_| Error::Overflow)?)
        .map_err(Error::Ldpc)?;
    let mut coded = Vec::new();
    coded
        .try_reserve_exact(capacity.coded_bits)
        .map_err(|_| Error::Overflow)?;
    for (symbol, block) in metrics.chunks_exact(capacity.coded_per_symbol).enumerate() {
        let keep = if symbol + 1 == symbols {
            capacity.coded_last
        } else {
            capacity.coded_per_symbol
        };
        coded.extend_from_slice(&block[..keep]);
    }
    if coded.len() != capacity.coded_bits {
        return Err(Error::Fec);
    }
    let recovered = if partial {
        layout.recover_partial(&coded, 64).map_err(Error::Ldpc)?
    } else {
        let (bits, iterations) = layout.recover(&coded, 64).map_err(Error::Ldpc)?;
        Recovery {
            bits,
            iterations,
            failed_codewords: 0,
            first_failure: None,
        }
    };
    let psdu = Descrambler::recover(recovered.bits, capacity.psdu_bytes)?;
    Ok(Recovered {
        psdu,
        failed_codewords: recovered.failed_codewords,
        first_failure: recovered.first_failure,
    })
}
