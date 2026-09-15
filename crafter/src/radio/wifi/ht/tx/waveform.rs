//! HT20 frequency mapping, training, and OFDM waveform primitives.

use super::HtMcs;
use crate::radio::wifi::ofdm::waveform::{self as ofdm, Complex};
use std::f64::consts::PI;

const DATA_CARRIERS: [i32; 52] = [
    -28, -27, -26, -25, -24, -23, -22, -20, -19, -18, -17, -16, -15, -14, -13, -12, -11, -10, -9,
    -8, -6, -5, -4, -3, -2, -1, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    22, 23, 24, 25, 26, 27, 28,
];

pub(super) fn puncture(coded: &[u8], mcs: HtMcs) -> Vec<u8> {
    let pattern: &[u8] = match mcs {
        HtMcs::Mcs0 | HtMcs::Mcs1 | HtMcs::Mcs3 => &[1, 1],
        HtMcs::Mcs5 => &[1, 1, 1, 0],
        HtMcs::Mcs2 | HtMcs::Mcs4 | HtMcs::Mcs6 => &[1, 1, 1, 0, 0, 1],
        HtMcs::Mcs7 => &[1, 1, 1, 0, 0, 1, 1, 0, 0, 1],
    };
    coded
        .iter()
        .enumerate()
        .filter_map(|(index, bit)| (pattern[index % pattern.len()] != 0).then_some(*bit))
        .collect()
}

pub(super) fn ht_interleave(bits: &[u8], bits_per_subcarrier: usize) -> Vec<u8> {
    let rows = 4 * bits_per_subcarrier;
    let columns = 13;
    let mut first = vec![0; bits.len()];
    for row in 0..rows {
        for column in 0..columns {
            first[column * rows + row] = bits[row * columns + column];
        }
    }
    let s = (bits_per_subcarrier / 2).max(1);
    let mut result = vec![0; bits.len()];
    for (index, bit) in first.into_iter().enumerate() {
        let target = s * (index / s) + (index + bits.len() - (columns * index) / bits.len()) % s;
        result[target] = bit;
    }
    result
}

fn ifft57(frequency: &[Complex; 57]) -> [Complex; 64] {
    std::array::from_fn(|time| {
        let mut output = Complex::ZERO;
        for (index, value) in frequency.iter().enumerate() {
            let carrier = index as i32 - 28;
            let angle = 2.0 * PI * carrier as f64 * time as f64 / 64.0;
            let (sin, cos) = angle.sin_cos();
            let rotation = Complex {
                re: cos / 64.0,
                im: sin / 64.0,
            };
            output.re += value.re * rotation.re - value.im * rotation.im;
            output.im += value.re * rotation.im + value.im * rotation.re;
        }
        output
    })
}

pub(super) fn ht_training() -> [Complex; 64] {
    let mut frequency = [Complex::ZERO; 57];
    frequency[0].re = 1.0;
    frequency[1].re = 1.0;
    for (destination, value) in frequency[2..55].iter_mut().zip(ofdm::LONG_TRAINING) {
        destination.re = value as f64;
    }
    frequency[55].re = -1.0;
    frequency[56].re = -1.0;
    ifft57(&frequency)
}

pub(super) fn ht_signal_symbol(bits: &[u8]) -> Vec<Complex> {
    let mut frequency = [Complex::ZERO; 53];
    for (index, carrier) in DATA_CARRIERS[2..50].iter().enumerate() {
        frequency[(*carrier + 26) as usize].im = (2 * bits[index] as i32 - 1) as f64;
    }
    for (carrier, value) in [(-21, 1.0), (-7, 1.0), (7, 1.0), (21, -1.0)] {
        frequency[(carrier + 26) as usize].re = value;
    }
    let time = ofdm::ifft(&frequency);
    let mut output = Vec::with_capacity(80);
    output.extend_from_slice(&time[48..]);
    output.extend_from_slice(&time);
    output
}

pub(super) fn ht_data_symbol(
    bits: &[u8],
    bits_per_subcarrier: usize,
    polarity: i8,
    symbol: usize,
    guard: usize,
) -> Vec<Complex> {
    let mut frequency = [Complex::ZERO; 57];
    for (index, carrier) in DATA_CARRIERS.iter().enumerate() {
        frequency[(*carrier + 28) as usize] = ofdm::constellation(
            &bits[index * bits_per_subcarrier..(index + 1) * bits_per_subcarrier],
        );
    }
    for (pilot, carrier) in [-21, -7, 7, 21].into_iter().enumerate() {
        let sign = [1, 1, 1, -1][(symbol + pilot) % 4];
        frequency[(carrier + 28) as usize].re = (sign * polarity) as f64;
    }
    let time = ifft57(&frequency);
    let mut output = Vec::with_capacity(64 + guard);
    output.extend_from_slice(&time[64 - guard..]);
    output.extend_from_slice(&time);
    output
}
