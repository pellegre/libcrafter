//! HT-SIG fields, IEEE 802.11-2020 19.3.9.4.3-4.
//! Source and edition limitations: docs/wifi-phy-evidence.json.

/// Integrity-checked HT-SIG fields. This does not qualify the signaled PHY mode
/// for reception: MCS, STBC and stream combinations need separate validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HtSignalFields {
    pub mcs: u8,
    pub channel_width_40_mhz: bool,
    /// Zero indicates an NDP, not a malformed length.
    pub psdu_bytes: u16,
    pub smoothing: bool,
    pub not_sounding: bool,
    pub aggregation: bool,
    /// Signaled difference between space-time streams and spatial streams.
    pub stbc: u8,
    pub ldpc: bool,
    pub short_guard_interval: bool,
    pub extension_spatial_streams: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HtSignalError {
    BitCount { required: usize, available: usize },
    NonBinary { index: usize, value: u8 },
    Crc { expected: u8, received: u8 },
    ReservedBit,
    TailBit { index: usize },
}
impl std::fmt::Display for HtSignalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HT-SIG: {self:?}")
    }
}
impl std::error::Error for HtSignalError {}

impl HtSignalFields {
    /// Decode 48 binary bits in transmission order, after BCC decoding.
    /// No allocation or device access occurs; all bits must be exactly 0 or 1.
    pub fn decode(bits: &[u8]) -> Result<Self, HtSignalError> {
        if bits.len() != 48 {
            return Err(HtSignalError::BitCount {
                required: 48,
                available: bits.len(),
            });
        }
        if let Some((index, &value)) = bits.iter().enumerate().find(|(_, v)| **v > 1) {
            return Err(HtSignalError::NonBinary { index, value });
        }
        let expected = crc(&bits[..34]);
        let received = bits[34..42].iter().fold(0u8, |v, b| (v << 1) | b);
        if expected != received {
            return Err(HtSignalError::Crc { expected, received });
        }
        if bits[26] != 1 {
            return Err(HtSignalError::ReservedBit);
        }
        if let Some(index) = (42..48).find(|i| bits[*i] != 0) {
            return Err(HtSignalError::TailBit { index });
        }
        let field = |start: usize, length: usize| {
            bits[start..start + length]
                .iter()
                .enumerate()
                .fold(0u16, |v, (i, b)| v | (u16::from(*b) << i))
        };
        Ok(Self {
            mcs: field(0, 7) as u8,
            channel_width_40_mhz: bits[7] != 0,
            psdu_bytes: field(8, 16),
            smoothing: bits[24] != 0,
            not_sounding: bits[25] != 0,
            aggregation: bits[27] != 0,
            stbc: field(28, 2) as u8,
            ldpc: bits[30] != 0,
            short_guard_interval: bits[31] != 0,
            extension_spatial_streams: field(32, 2) as u8,
        })
    }
}

fn crc(bits: &[u8]) -> u8 {
    let mut state = 255u8;
    for &bit in bits {
        let feedback = (state >> 7) ^ bit;
        state = (state << 1) ^ if feedback != 0 { 0x07 } else { 0 };
    }
    !state
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example() -> Vec<u8> {
        // Published example: 19.3.9.4.4, printed p.2893. Not produced by crafter.
        "111100010010011000000000111000000010101000000000"
            .bytes()
            .map(|b| b - b'0')
            .collect()
    }

    #[test]
    fn radio_ht_signal_published_example_and_all_single_bit_errors() {
        let bits = example();
        let fields = HtSignalFields::decode(&bits).unwrap();
        assert_eq!(fields.mcs, 15);
        assert!(fields.channel_width_40_mhz);
        assert_eq!(fields.psdu_bytes, 100);
        for index in 0..48 {
            let mut changed = bits.clone();
            changed[index] ^= 1;
            assert!(HtSignalFields::decode(&changed).is_err(), "bit {index}");
        }
    }

    #[test]
    fn radio_ht_signal_independent_polynomial_inventory() {
        let index = include_str!("../../tests/fixtures/iq/ht-signal-index.tsv");
        assert_eq!(index.lines().skip(1).count(), 256);
        for line in index.lines().skip(1) {
            let columns: Vec<_> = line.split('\t').collect();
            let bits: Vec<_> = columns[0].bytes().map(|b| b - b'0').collect();
            let f = HtSignalFields::decode(&bits).unwrap();
            let expected: Vec<u16> = columns[1..].iter().map(|n| n.parse().unwrap()).collect();
            assert_eq!(
                expected,
                [
                    u16::from(f.mcs),
                    u16::from(f.channel_width_40_mhz),
                    f.psdu_bytes,
                    u16::from(f.smoothing),
                    u16::from(f.not_sounding),
                    u16::from(f.aggregation),
                    u16::from(f.stbc),
                    u16::from(f.ldpc),
                    u16::from(f.short_guard_interval),
                    u16::from(f.extension_spatial_streams)
                ]
            );
        }
    }

    #[test]
    fn radio_ht_signal_structured_bounds_and_field_errors() {
        let bits = example();
        for size in 0..48 {
            assert_eq!(
                HtSignalFields::decode(&bits[..size]),
                Err(HtSignalError::BitCount {
                    required: 48,
                    available: size
                })
            );
        }
        assert_eq!(
            HtSignalFields::decode(&[0; 49]),
            Err(HtSignalError::BitCount {
                required: 48,
                available: 49
            })
        );
        for index in 0..48 {
            let mut changed = bits.clone();
            changed[index] = 2;
            assert_eq!(
                HtSignalFields::decode(&changed),
                Err(HtSignalError::NonBinary { index, value: 2 })
            );
        }
        for index in 42..48 {
            let mut changed = bits.clone();
            changed[index] = 1;
            assert_eq!(
                HtSignalFields::decode(&changed),
                Err(HtSignalError::TailBit { index })
            );
        }
        let mut reserved = bits;
        reserved[26] = 0;
        let checksum = crc(&reserved[..34]);
        for i in 0..8 {
            reserved[34 + i] = (checksum >> (7 - i)) & 1;
        }
        assert_eq!(
            HtSignalFields::decode(&reserved),
            Err(HtSignalError::ReservedBit)
        );
    }
}
