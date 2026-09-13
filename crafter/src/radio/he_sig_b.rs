//! HE20 SIG-B common field; IEEE 802.11ax-2021 Tables 27-24/26.
//! Caller establishes uncompressed 20 MHz SIG-B context. No IQ/DATA admission.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeRu20Assignment {
    pub tones: u16,
    /// First column covered in Table 27-26, numbered 1..9 from low to high
    /// frequency. This is not an FFT bin or the ordinal among equal-size RUs.
    pub first_slot: u8,
    /// Zero preserves an explicitly empty RU; otherwise the number of users.
    pub users: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeSigBCommon20Fields {
    allocation_code: u8,
    rus: Vec<HeRu20Assignment>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeSigBError {
    BitCount {
        context: &'static str,
        required: usize,
        available: usize,
    },
    NonBinary {
        index: usize,
        value: u8,
    },
    Crc {
        expected: u8,
        received: u8,
    },
    Tail {
        index: usize,
    },
    ReservedAllocation(u8),
    WiderAllocation(u8),
}
impl std::fmt::Display for HeSigBError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HE SIG-B: {self:?}")
    }
}
impl std::error::Error for HeSigBError {}

impl HeSigBCommon20Fields {
    /// Check the 18-bit common field, including CRC and tail, then map its RUs.
    /// This field is absent when SIG-A indicates SIG-B compression.
    pub fn decode(bits: &[u8]) -> Result<Self, HeSigBError> {
        validate_block(bits, 8, "HE20 SIG-B common")?;
        let code = bits[..8]
            .iter()
            .enumerate()
            .fold(0u8, |v, (i, b)| v | (b << i));
        Ok(Self {
            allocation_code: code,
            rus: allocation(code)?,
        })
    }
    pub fn allocation_code(&self) -> u8 {
        self.allocation_code
    }
    pub fn rus(&self) -> &[HeRu20Assignment] {
        &self.rus
    }
    /// Number of subsequent 21-bit User fields, not User Block fields.
    pub fn user_count(&self) -> u8 {
        self.rus.iter().map(|r| r.users).sum()
    }
}

fn validate_block(bits: &[u8], payload: usize, context: &'static str) -> Result<(), HeSigBError> {
    if bits.len() != payload + 10 {
        return Err(HeSigBError::BitCount {
            context,
            required: payload + 10,
            available: bits.len(),
        });
    }
    if let Some((index, &value)) = bits.iter().enumerate().find(|(_, b)| **b > 1) {
        return Err(HeSigBError::NonBinary { index, value });
    }
    let expected = super::ht::crc(&bits[..payload]) >> 4;
    let received = bits[payload..payload + 4]
        .iter()
        .fold(0, |v, b| (v << 1) | b);
    if expected != received {
        return Err(HeSigBError::Crc { expected, received });
    }
    if let Some(index) = (payload + 4..bits.len()).find(|i| bits[*i] != 0) {
        return Err(HeSigBError::Tail { index });
    }
    Ok(())
}

fn assignment(tones: u16, first_slot: u8, users: u8) -> HeRu20Assignment {
    HeRu20Assignment {
        tones,
        first_slot,
        users,
    }
}

fn pair(rus: &mut Vec<HeRu20Assignment>, start: u8, merged: bool) {
    rus.push(assignment(if merged { 52 } else { 26 }, start, 1));
    if !merged {
        rus.push(assignment(26, start + 1, 1));
    }
}

fn half(rus: &mut Vec<HeRu20Assignment>, start: u8, mask: u8) {
    pair(rus, start, mask & 2 != 0);
    pair(rus, start + 2, mask & 1 != 0);
}

fn allocation(code: u8) -> Result<Vec<HeRu20Assignment>, HeSigBError> {
    let mut rus = Vec::with_capacity(9);
    match code {
        0..=15 => {
            half(&mut rus, 1, code >> 2);
            rus.push(assignment(26, 5, 1));
            half(&mut rus, 6, code & 3);
        }
        16..=23 => {
            half(&mut rus, 1, 3);
            rus.push(assignment(26, 5, 0));
            rus.push(assignment(106, 6, (code & 7) + 1));
        }
        24..=31 => {
            rus.push(assignment(106, 1, (code & 7) + 1));
            rus.push(assignment(26, 5, 0));
            half(&mut rus, 6, 3);
        }
        32..=63 => {
            half(&mut rus, 1, (code - 32) / 8);
            rus.push(assignment(26, 5, 1));
            rus.push(assignment(106, 6, (code & 7) + 1));
        }
        64..=95 => {
            // The printed decimal "72-29" row is a typo: 01001yyy = 72..79.
            rus.push(assignment(106, 1, (code & 7) + 1));
            rus.push(assignment(26, 5, 1));
            half(&mut rus, 6, (code - 64) / 8);
        }
        96..=111 => {
            rus.push(assignment(106, 1, ((code >> 2) & 3) + 1));
            rus.push(assignment(26, 5, 0));
            rus.push(assignment(106, 6, (code & 3) + 1));
        }
        112 => {
            half(&mut rus, 1, 3);
            rus.push(assignment(26, 5, 0));
            half(&mut rus, 6, 3);
        }
        113 => rus.push(assignment(242, 1, 0)),
        128..=191 => {
            rus.push(assignment(106, 1, ((code >> 3) & 7) + 1));
            rus.push(assignment(26, 5, 1));
            rus.push(assignment(106, 6, (code & 7) + 1));
        }
        192..=199 => rus.push(assignment(242, 1, (code & 7) + 1)),
        114 | 115 | 200..=215 => return Err(HeSigBError::WiderAllocation(code)),
        _ => return Err(HeSigBError::ReservedAllocation(code)),
    }
    Ok(rus)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn radio_he_sig_b_common_independent() {
        let rows = include_str!("../../tests/fixtures/iq/he-sig-b-common.tsv");
        assert_eq!(rows.lines().skip(1).count(), 256);
        let mut totals = [0; 3];
        for row in rows.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let code: u8 = c[0].parse().unwrap();
            let bits: Vec<_> = c[1].bytes().map(|b| b - b'0').collect();
            let result = HeSigBCommon20Fields::decode(&bits);
            match c[2] {
                "reserved" => {
                    assert_eq!(result, Err(HeSigBError::ReservedAllocation(code)));
                    totals[1] += 1;
                }
                "wider" => {
                    assert_eq!(result, Err(HeSigBError::WiderAllocation(code)));
                    totals[2] += 1;
                }
                "ok" => {
                    totals[0] += 1;
                    let fields = result.unwrap();
                    assert_eq!(fields.allocation_code(), code);
                    let expected: Vec<_> = c[3]
                        .split(',')
                        .map(|ru| {
                            let n: Vec<u16> = ru.split(':').map(|v| v.parse().unwrap()).collect();
                            assignment(n[0], n[1] as u8, n[2] as u8)
                        })
                        .collect();
                    assert_eq!(fields.rus(), expected, "code {code}");
                    assert_eq!(fields.user_count(), c[4].parse::<u8>().unwrap());
                    assert!(fields.rus().len() <= 9);
                    assert!(fields.user_count() <= 17);
                    assert!(fields
                        .rus()
                        .windows(2)
                        .all(|r| r[0].first_slot < r[1].first_slot));
                }
                _ => panic!("unknown fixture classification"),
            }
            for index in 8..18 {
                let mut bad = bits.clone();
                bad[index] ^= 1;
                let error = HeSigBCommon20Fields::decode(&bad).unwrap_err();
                if index < 12 {
                    assert!(matches!(error, HeSigBError::Crc { .. }));
                } else {
                    assert_eq!(error, HeSigBError::Tail { index });
                }
            }
        }
        assert_eq!(totals, [186, 52, 18]);
    }
    #[test]
    fn radio_he_sig_b_common_bounds() {
        for length in [0, 8, 12, 17, 19, 31, 52] {
            assert!(
                matches!(HeSigBCommon20Fields::decode(&vec![0;length]), Err(HeSigBError::BitCount { required: 18, available, .. }) if available==length)
            );
        }
        for index in 0..18 {
            let mut bits = [0; 18];
            bits[index] = 2;
            assert_eq!(
                HeSigBCommon20Fields::decode(&bits),
                Err(HeSigBError::NonBinary { index, value: 2 })
            );
        }
    }
}
