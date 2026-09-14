//! Fixed-size HE receive transforms; periods in IEEE 802.11ax-2021 Table27-12.
//! Natural-order, unnormalized forward transform. Negative tone k uses bin N+k.
use crate::radio::ComplexSample;
use std::{f32::consts::TAU, sync::OnceLock};

fn transform<const N: usize>(mut input: [ComplexSample; N]) -> [ComplexSample; N] {
    // Only the two fixed-size wrappers below instantiate this private helper.
    assert!(N == 128 || N == 256);
    static ROTATIONS: OnceLock<[ComplexSample; 128]> = OnceLock::new();
    let rotations = ROTATIONS
        .get_or_init(|| std::array::from_fn(|k| ComplexSample::rotation(-TAU * k as f32 / 256.)));
    for i in 0..N {
        let reversed = i.reverse_bits() >> (usize::BITS - N.trailing_zeros());
        if reversed > i {
            input.swap(i, reversed);
        }
    }
    let mut width = 2;
    while width <= N {
        for base in (0..N).step_by(width) {
            for j in 0..width / 2 {
                let left = input[base + j];
                let right = input[base + j + width / 2].mul(rotations[j * (256 / width)]);
                input[base + j] = left.add(right);
                input[base + j + width / 2] = left.sub(right);
            }
        }
        width *= 2;
    }
    input
}

pub(in crate::radio) fn fft128(input: [ComplexSample; 128]) -> [ComplexSample; 128] {
    transform(input)
}

pub(in crate::radio) fn fft256(input: [ComplexSample; 256]) -> [ComplexSample; 256] {
    transform(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radio_he_fft_independent_direct_dft() {
        let mut rows = include_str!("../../../tests/fixtures/iq/he-transform-index.tsv")
            .lines()
            .skip(1);
        let mut cases = 0;
        while let Some(first) = rows.next() {
            let c: Vec<_> = first.split('\t').collect();
            let n: usize = c[1].parse().unwrap();
            let group: Vec<_> = std::iter::once(first)
                .chain(rows.by_ref().take(n - 1))
                .collect();
            assert_eq!(group.len(), n);
            let parsed: Vec<_> = group
                .iter()
                .enumerate()
                .map(|(i, row)| {
                    let cells: Vec<_> = row.split('\t').collect();
                    assert_eq!(cells[0], c[0]);
                    assert_eq!(cells[1], c[1]);
                    assert_eq!(cells[2].parse::<usize>().unwrap(), i);
                    cells[3..]
                        .iter()
                        .map(|s| s.parse::<f64>().unwrap())
                        .collect::<Vec<_>>()
                })
                .collect();
            let input: Vec<_> = parsed
                .iter()
                .map(|v| ComplexSample {
                    i: v[0] as f32,
                    q: v[1] as f32,
                })
                .collect();
            let output = match n {
                128 => fft128(input.try_into().unwrap()).to_vec(),
                256 => fft256(input.try_into().unwrap()).to_vec(),
                _ => panic!("invalid oracle transform size"),
            };
            for (k, (actual, expected)) in output.iter().zip(&parsed).enumerate() {
                let error =
                    (f64::from(actual.i) - expected[2]).hypot(f64::from(actual.q) - expected[3]);
                let tolerance = 0.0001 * (1. + expected[2].hypot(expected[3]));
                assert!(error <= tolerance, "{} bin{k}: {error} > {tolerance}", c[0]);
            }
            cases += 1;
        }
        assert_eq!(cases, 10);
    }

    #[test]
    fn radio_he_fft_all_signed_tones() {
        for n in [128usize, 256] {
            for k in 0..n {
                let input: Vec<_> = (0..n)
                    .map(|t| {
                        let phase = std::f64::consts::TAU * k as f64 * t as f64 / n as f64;
                        ComplexSample {
                            i: phase.cos() as f32,
                            q: phase.sin() as f32,
                        }
                    })
                    .collect();
                let output = if n == 128 {
                    fft128(input.try_into().unwrap()).to_vec()
                } else {
                    fft256(input.try_into().unwrap()).to_vec()
                };
                for (bin, value) in output.iter().enumerate() {
                    let expected = if bin == k { n as f32 } else { 0. };
                    assert!(
                        (value.i - expected).abs() < 0.0002 && value.q.abs() < 0.0002,
                        "N{n} tone{k} bin{bin}"
                    );
                }
            }
        }
    }
}
