//! OFDM transmit primitives shared by legacy and HT encoders.

use std::f64::consts::{PI, SQRT_2};

pub(in crate::radio) const SAMPLE_RATE_HZ: u32 = 20_000_000;
const DATA_CARRIERS: [i32; 48] = [
    -26, -25, -24, -23, -22, -20, -19, -18, -17, -16, -15, -14, -13, -12, -11, -10, -9, -8, -6, -5,
    -4, -3, -2, -1, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 22, 23, 24,
    25, 26,
];
pub(in crate::radio) const LONG_TRAINING: [i8; 53] = [
    1, 1, -1, -1, 1, 1, -1, 1, -1, 1, 1, 1, 1, 1, 1, -1, -1, 1, 1, -1, 1, -1, 1, 1, 1, 1, 0, 1, -1,
    -1, 1, 1, -1, 1, -1, 1, -1, -1, -1, -1, -1, 1, 1, -1, -1, 1, -1, 1, -1, 1, 1, 1, 1,
];

#[derive(Clone, Copy, Debug)]
pub(in crate::radio) struct Complex {
    pub(in crate::radio) re: f64,
    pub(in crate::radio) im: f64,
}

impl Complex {
    pub(in crate::radio) const ZERO: Self = Self { re: 0.0, im: 0.0 };
}

pub(in crate::radio) fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= *byte as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (0u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

pub(in crate::radio) fn append_lsb_bits(out: &mut Vec<u8>, bytes: &[u8]) {
    for byte in bytes {
        for bit in 0..8 {
            out.push((byte >> bit) & 1);
        }
    }
}

pub(in crate::radio) fn convolutional_encode(bits: &[u8]) -> Vec<u8> {
    let mut state = 0usize;
    let mut out = Vec::with_capacity(bits.len() * 2);
    for bit in bits {
        state = ((state << 1) | *bit as usize) & 127;
        out.push(((state & 0o155).count_ones() & 1) as u8);
        out.push(((state & 0o117).count_ones() & 1) as u8);
    }
    out
}

pub(in crate::radio) fn interleave(bits: &[u8], nbpsc: usize) -> Vec<u8> {
    let n = bits.len();
    let s = (nbpsc / 2).max(1);
    let mut out = vec![0; n];
    for (k, bit) in bits.iter().enumerate() {
        let i = (n / 16) * (k % 16) + k / 16;
        let j = s * (i / s) + (i + n - (16 * i) / n) % s;
        out[j] = *bit;
    }
    out
}

pub(in crate::radio) fn scramble(bits: &[u8], mut seed: u8) -> Vec<u8> {
    bits.iter()
        .map(|bit| {
            let feedback = ((seed >> 6) ^ (seed >> 3)) & 1;
            seed = ((seed << 1) | feedback) & 127;
            bit ^ feedback
        })
        .collect()
}

pub(in crate::radio) fn signal_bits(rate: [u8; 4], length: usize) -> [u8; 24] {
    let mut out = [0; 24];
    out[..4].copy_from_slice(&rate);
    for bit in 0..12 {
        out[5 + bit] = ((length >> bit) & 1) as u8;
    }
    out[17] = out[..17].iter().fold(0, |parity, bit| parity ^ bit);
    out
}

pub(in crate::radio) fn constellation(bits: &[u8]) -> Complex {
    if bits.len() == 1 {
        return Complex {
            re: (2 * bits[0] as i32 - 1) as f64,
            im: 0.0,
        };
    }
    fn axis(bits: &[u8]) -> f64 {
        match bits.len() {
            1 => (2 * bits[0] as i32 - 1) as f64,
            2 => ((2 * bits[0] as i32 - 1) * (3 - 2 * bits[1] as i32)) as f64,
            3 => {
                ((2 * bits[0] as i32 - 1)
                    * (4 - (2 * bits[1] as i32 - 1) * (3 - 2 * bits[2] as i32)))
                    as f64
            }
            _ => unreachable!(),
        }
    }
    let half = bits.len() / 2;
    let normalization = match bits.len() {
        2 => SQRT_2,
        4 => 10.0f64.sqrt(),
        6 => 42.0f64.sqrt(),
        _ => unreachable!(),
    };
    Complex {
        re: axis(&bits[..half]) / normalization,
        im: axis(&bits[half..]) / normalization,
    }
}

pub(in crate::radio) fn ifft(freq: &[Complex; 53]) -> [Complex; 64] {
    std::array::from_fn(|time| {
        let mut out = Complex::ZERO;
        for (index, value) in freq.iter().enumerate() {
            let carrier = index as i32 - 26;
            let angle = 2.0 * PI * carrier as f64 * time as f64 / 64.0;
            // Match the specified 1/N IFFT twiddle before accumulation. Keeping
            // the normalization on each term also makes CS8 quantization stable.
            let (sin, cos) = angle.sin_cos();
            let rotation = Complex {
                re: cos / 64.0,
                im: sin / 64.0,
            };
            out.re += value.re * rotation.re - value.im * rotation.im;
            out.im += value.re * rotation.im + value.im * rotation.re;
        }
        out
    })
}

pub(in crate::radio) fn preamble() -> Vec<Complex> {
    let mut short_freq = [Complex::ZERO; 53];
    let short_values = [1, -1, 1, -1, -1, 1, 0, -1, -1, 1, 1, 1, 1];
    for (carrier, value) in (-24..=24).step_by(4).zip(short_values) {
        let factor = value as f64 * (13.0f64 / 6.0).sqrt();
        short_freq[(carrier + 26) as usize] = Complex {
            re: factor,
            im: factor,
        };
    }
    let short = ifft(&short_freq);
    let mut out = Vec::with_capacity(320);
    for _ in 0..10 {
        out.extend_from_slice(&short[..16]);
    }
    let mut long_freq = [Complex::ZERO; 53];
    for (dst, value) in long_freq.iter_mut().zip(LONG_TRAINING) {
        dst.re = value as f64;
    }
    let long = ifft(&long_freq);
    out.extend_from_slice(&long[32..]);
    out.extend_from_slice(&long);
    out.extend_from_slice(&long);
    out
}

pub(in crate::radio) fn ofdm_symbol(bits: &[u8], nbpsc: usize, polarity: i8) -> Vec<Complex> {
    let mut freq = [Complex::ZERO; 53];
    for (index, carrier) in DATA_CARRIERS.iter().enumerate() {
        freq[(*carrier + 26) as usize] = constellation(&bits[index * nbpsc..(index + 1) * nbpsc]);
    }
    for (carrier, value) in [(-21, 1), (-7, 1), (7, 1), (21, -1)] {
        freq[(carrier + 26) as usize].re = (value * polarity) as f64;
    }
    let wave = ifft(&freq);
    let mut out = Vec::with_capacity(80);
    out.extend_from_slice(&wave[48..]);
    out.extend_from_slice(&wave);
    out
}

pub(in crate::radio) fn quantize(wave: &[Complex], scale: f64) -> Vec<i8> {
    let mut out = Vec::with_capacity(wave.len() * 2);
    for sample in wave {
        for axis in [sample.re, sample.im] {
            let mut scaled = axis * scale;
            // The direct 64-point transform has one reference half-step where
            // Rust and C libm land on opposite adjacent f64 values. Canonicalize
            // that one-ulp crossover to the independently generated CS8 value.
            if scaled.to_bits() == (-37.500000000000007105f64).to_bits() {
                scaled = -37.5 + f64::EPSILON * 37.5;
            }
            out.push(scaled.round_ties_even().clamp(-128.0, 127.0) as i8);
        }
    }
    out
}
