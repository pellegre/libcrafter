use crate::radio::signal::TRELLIS_SIGNS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) enum Error {
    Parameters,
    Coding,
    Length,
    Metrics,
    Allocation,
}

/// Format-resolved BCC geometry before descrambling and MAC validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) struct Parameters {
    pub symbols: usize,
    pub symbol_group: usize,
    pub coded_per_symbol: usize,
    pub coded_last: usize,
    pub data_per_symbol: usize,
    pub data_bits: usize,
    pub rate_num: usize,
    pub rate_den: usize,
    pub dcm_filler: bool,
}

/// Bounded soft-decision convolutional decoder for an admitted PHY layout.
pub(in crate::radio) struct Decoder {
    parameters: Parameters,
    puncturing: &'static [u8],
}

impl Decoder {
    pub fn new(parameters: Parameters) -> Result<Self, Error> {
        if parameters.symbols == 0
            || parameters.symbol_group == 0
            || parameters.symbol_group > parameters.symbols
            || parameters.coded_per_symbol == 0
            || parameters.coded_last > parameters.coded_per_symbol
            || parameters.data_per_symbol == 0
            || parameters.data_bits == 0
        {
            return Err(Error::Parameters);
        }
        let puncturing: &'static [u8] = match (parameters.rate_num, parameters.rate_den) {
            (1, 2) => &[1, 1],
            (2, 3) => &[1, 1, 1, 0],
            (3, 4) => &[1, 1, 1, 0, 0, 1],
            (5, 6) => &[1, 1, 1, 0, 0, 1, 1, 0, 0, 1],
            _ => return Err(Error::Coding),
        };
        Ok(Self {
            parameters,
            puncturing,
        })
    }

    /// Recover scrambled information bits. The caller owns the PHY-specific
    /// scrambler, SERVICE interpretation, and MAC integrity checks.
    pub fn recover(self, metrics: &[f32]) -> Result<Vec<u8>, Error> {
        let p = self.parameters;
        if p.symbols.checked_mul(p.coded_per_symbol) != Some(metrics.len()) {
            return Err(Error::Length);
        }
        if metrics.iter().any(|value| !value.is_finite()) {
            return Err(Error::Metrics);
        }
        let mut coded = Vec::new();
        coded
            .try_reserve_exact(
                p.symbols
                    .checked_mul(p.coded_per_symbol)
                    .ok_or(Error::Length)?,
            )
            .map_err(|_| Error::Allocation)?;
        for (symbol, block) in metrics.chunks_exact(p.coded_per_symbol).enumerate() {
            let keep = if symbol >= p.symbols - p.symbol_group {
                p.coded_last
            } else {
                p.coded_per_symbol
            };
            for (bit, value) in block[..keep].iter().enumerate() {
                if p.dcm_filler && bit == 2 * p.data_per_symbol {
                    continue;
                }
                coded.push(*value);
            }
        }
        let scale = coded.iter().map(|value| value.abs()).fold(0f32, f32::max);
        if scale == 0. {
            return Err(Error::Metrics);
        }
        let mut history = Vec::new();
        history
            .try_reserve_exact(p.data_bits)
            .map_err(|_| Error::Allocation)?;
        history.resize(p.data_bits, [0u8; 64]);
        let mut costs = [f32::INFINITY; 64];
        costs[0] = 0.;
        let mut cursor = 0;
        for (time, row) in history.iter_mut().enumerate() {
            let mut pair = [0.; 2];
            for (output, value) in pair.iter_mut().enumerate() {
                if self.puncturing[(2 * time + output) % self.puncturing.len()] != 0 {
                    *value = *coded.get(cursor).ok_or(Error::Length)? / scale;
                    cursor += 1;
                }
            }
            let mut next = [f32::INFINITY; 64];
            for (state, cost) in costs.iter().enumerate() {
                for bit in 0..2 {
                    let register = (state << 1) | bit;
                    let signs = TRELLIS_SIGNS[register];
                    let score = cost - pair[0] * signs[0] - pair[1] * signs[1];
                    if score < next[register & 63] {
                        next[register & 63] = score;
                        row[register & 63] = state as u8;
                    }
                }
            }
            let minimum = next.iter().copied().fold(f32::INFINITY, f32::min);
            for cost in &mut next {
                *cost -= minimum;
            }
            costs = next;
        }
        if cursor != coded.len() {
            return Err(Error::Length);
        }
        let mut state = 0;
        let mut bits = Vec::new();
        bits.try_reserve_exact(p.data_bits)
            .map_err(|_| Error::Allocation)?;
        bits.resize(p.data_bits, 0);
        for (time, row) in history.iter().enumerate().rev() {
            bits[time] = (state & 1) as u8;
            state = row[state] as usize;
        }
        Ok(bits)
    }
}
