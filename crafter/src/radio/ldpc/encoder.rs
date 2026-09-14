//! Systematic GF(2) encoding for the IEEE HT LDPC parity matrices.

use super::{Code, Error, Rate};
use std::sync::OnceLock;

struct ParityInverse {
    rows: Vec<Vec<u64>>,
}

static PARITY_INVERSES: [OnceLock<ParityInverse>; 12] = [const { OnceLock::new() }; 12];

pub(super) fn encode(code: &Code, information: &[u8]) -> Result<Vec<u8>, Error> {
    if information.len() != code.k {
        return Err(Error::InformationCount {
            required: code.k,
            available: information.len(),
        });
    }
    if let Some((index, &value)) = information
        .iter()
        .enumerate()
        .find(|(_, value)| **value > 1)
    {
        return Err(Error::NonBinaryInformation { index, value });
    }

    let parity_bits = code.n - code.k;
    let words = parity_bits.div_ceil(64);
    let mut syndrome = vec![0u64; words];
    for (row, check) in code.checks.iter().enumerate() {
        let value = check
            .iter()
            .filter(|column| **column < code.k)
            .fold(0, |parity, column| parity ^ information[*column]);
        if value != 0 {
            set(&mut syndrome, row);
        }
    }

    let inverse =
        PARITY_INVERSES[cache_index(code.n, code.rate)].get_or_init(|| build_inverse(code));
    if inverse.rows.is_empty() {
        return Err(Error::SingularParity);
    }
    let mut output = Vec::with_capacity(code.n);
    output.extend_from_slice(information);
    for row in &inverse.rows {
        let parity = row.iter().zip(&syndrome).fold(0, |parity, (left, right)| {
            parity ^ ((left & right).count_ones() & 1)
        });
        output.push(parity as u8);
    }
    debug_assert_eq!(code.failed_checks(&output), 0);
    Ok(output)
}

fn cache_index(n: usize, rate: Rate) -> usize {
    let block = match n {
        648 => 0,
        1296 => 1,
        1944 => 2,
        _ => unreachable!("Code construction validates the block length"),
    };
    4 * block + rate.index()
}

fn build_inverse(code: &Code) -> ParityInverse {
    let parity_bits = code.n - code.k;
    let augmented_bits = 2 * parity_bits;
    let augmented_words = augmented_bits.div_ceil(64);
    let mut matrix = vec![vec![0u64; augmented_words]; parity_bits];
    for (row, check) in code.checks.iter().enumerate() {
        for &column in check.iter().filter(|column| **column >= code.k) {
            set(&mut matrix[row], column - code.k);
        }
        set(&mut matrix[row], parity_bits + row);
    }

    for column in 0..parity_bits {
        let Some(pivot) = (column..parity_bits).find(|row| bit(&matrix[*row], column)) else {
            return ParityInverse { rows: Vec::new() };
        };
        matrix.swap(column, pivot);
        let pivot = matrix[column].clone();
        for (row, values) in matrix.iter_mut().enumerate() {
            if row != column && bit(values, column) {
                for (value, pivot) in values.iter_mut().zip(&pivot) {
                    *value ^= pivot;
                }
            }
        }
    }

    let words = parity_bits.div_ceil(64);
    let mut rows = vec![vec![0u64; words]; parity_bits];
    for row in 0..parity_bits {
        for column in 0..parity_bits {
            if bit(&matrix[row], parity_bits + column) {
                set(&mut rows[row], column);
            }
        }
    }
    ParityInverse { rows }
}

fn bit(values: &[u64], index: usize) -> bool {
    values[index / 64] & (1 << (index % 64)) != 0
}

fn set(values: &mut [u64], index: usize) {
    values[index / 64] |= 1 << (index % 64);
}
