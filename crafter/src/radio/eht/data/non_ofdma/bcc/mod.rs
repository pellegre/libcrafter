use super::{Capacity, Error};
use crate::radio::eht::data::scrambler::Descrambler;

#[cfg(test)]
mod tests;

/// Recover one admitted EHT20 BCC payload from deinterleaved soft metrics.
pub(super) fn recover(
    capacity: Capacity,
    symbols: usize,
    metrics: &[f32],
    max_psdu: usize,
) -> Result<Vec<u8>, Error> {
    if capacity.ldpc {
        return Err(Error::Coding);
    }
    if capacity.psdu_bytes > max_psdu {
        return Err(Error::FrameLimit);
    }
    let decoder = crate::radio::bcc::Decoder::new(crate::radio::bcc::Parameters {
        symbols,
        symbol_group: 1,
        coded_per_symbol: capacity.coded_per_symbol,
        coded_last: capacity.coded_last,
        data_per_symbol: capacity.data_per_symbol,
        data_bits: capacity.data_bits,
        rate_num: capacity.rate_num,
        rate_den: capacity.rate_den,
        dcm_filler: capacity.bcc_dcm_filler,
    })
    .map_err(|_| Error::Fec)?;
    Descrambler::recover(
        decoder.recover(metrics).map_err(|_| Error::Fec)?,
        capacity.psdu_bytes,
    )
}
