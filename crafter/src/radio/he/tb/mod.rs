//! HE TB SIG-A; IEEE 802.11ax-2021 Table 27-21 and 27.3.11.7.3-4.
//! Trigger-supplied RU, MCS, coding and training parameters are not inferred.

pub(in crate::radio) mod context;
pub(in crate::radio) mod data;
pub(in crate::radio) mod schedule;

use super::{decode_interleaved_bits, validate_bits, Error as SharedError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    Signal(SharedError),
    NotTb,
    InconsistentSpatialReuse { index: usize },
}

impl From<SharedError> for Error {
    fn from(error: SharedError) -> Self {
        Self::Signal(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TbSignal {
    pub bss_color: u8,
    /// Raw codes by increasing subband frequency, not spatial-reuse permission.
    pub spatial_reuse: [u8; 4],
    pub bandwidth: u8,
    pub txop: u8,
    /// Nine bits copied from UL HE-SIG-A2 Reserved in the triggering frame.
    pub trigger_reserved: u16,
}

impl TbSignal {
    /// Exactly 104 finite, equalized, interleaved BPSK metrics, positive for one.
    /// Caller establishes the SU/TB branch; this does not admit DATA.
    pub fn decode_interleaved(metrics: &[f32]) -> Result<Self, Error> {
        Self::decode(&decode_interleaved_bits(metrics)?)
    }

    pub fn decode(bits: &[u8]) -> Result<Self, Error> {
        validate_bits(bits)?;
        if bits[0] != 0 {
            return Err(Error::NotTb);
        }
        if bits[23] != 1 {
            return Err(SharedError::Reserved { index: 23 }.into());
        }
        let field = |start: usize, width: usize| {
            bits[start..start + width]
                .iter()
                .enumerate()
                .fold(0u16, |value, (i, &bit)| value | (u16::from(bit) << i))
        };
        let bandwidth = field(24, 2) as u8;
        let spatial_reuse = std::array::from_fn(|i| field(7 + 4 * i, 4) as u8);
        for i in 1..4 {
            let same_as = if bandwidth == 0 {
                Some(0)
            } else if bandwidth == 1 && i >= 2 {
                Some(i - 2)
            } else {
                None
            };
            if same_as.is_some_and(|j| spatial_reuse[i] != spatial_reuse[j]) {
                return Err(Error::InconsistentSpatialReuse { index: 7 + 4 * i });
            }
        }
        Ok(Self {
            bss_color: field(1, 6) as u8,
            spatial_reuse,
            bandwidth,
            txop: field(26, 7) as u8,
            trigger_reserved: field(33, 9),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radio_he_tb_crc_truncation_limits() {
        let row = include_str!("../../../../tests/fixtures/iq/he-tb-signal-a-index.tsv")
            .lines()
            .nth(1)
            .unwrap();
        let bits: Vec<_> = row
            .split('\t')
            .next()
            .unwrap()
            .bytes()
            .map(|v| v - b'0')
            .collect();
        let original = TbSignal::decode(&bits).unwrap();
        for index in [40, 41] {
            let mut changed = bits.clone();
            changed[index] ^= 1;
            let decoded = TbSignal::decode(&changed).unwrap();
            assert_eq!(
                decoded.trigger_reserved,
                original.trigger_reserved ^ (1 << (index - 33))
            );
            assert_eq!(decoded.bss_color, original.bss_color);
        }
    }

    #[test]
    fn radio_he_tb_independent_headers() {
        let rows = include_str!("../../../../tests/fixtures/iq/he-tb-signal-a-index.tsv");
        assert_eq!(rows.lines().skip(1).count(), 2048);
        let mut reserved = [false; 512];
        for row in rows.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let bits: Vec<_> = c[0].bytes().map(|v| v - b'0').collect();
            let header = TbSignal::decode(&bits).unwrap();
            let actual = [
                u16::from(header.bandwidth),
                header.bss_color.into(),
                header.spatial_reuse[0].into(),
                header.spatial_reuse[1].into(),
                header.spatial_reuse[2].into(),
                header.spatial_reuse[3].into(),
                header.txop.into(),
                header.trigger_reserved,
            ];
            let expected: Vec<u16> = c[2..].iter().map(|v| v.parse().unwrap()).collect();
            assert_eq!(&actual, expected.as_slice());
            reserved[usize::from(header.trigger_reserved)] = true;
            for scale in [f32::MIN_POSITIVE, 1., f32::MAX] {
                let metrics: Vec<_> = c[1]
                    .bytes()
                    .map(|v| if v == b'1' { scale } else { -scale })
                    .collect();
                assert_eq!(TbSignal::decode_interleaved(&metrics), Ok(header));
            }
        }
        assert!(reserved.into_iter().all(|v| v));
    }

    #[test]
    fn radio_he_tb_header_rejections() {
        let rows = include_str!("../../../../tests/fixtures/iq/he-tb-signal-a-invalid.tsv");
        assert_eq!(rows.lines().skip(1).count(), 57);
        for row in rows.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let bits: Vec<_> = c[1].bytes().map(|v| v - b'0').collect();
            let index: usize = c[3].parse().unwrap();
            let error = TbSignal::decode(&bits).unwrap_err();
            match c[2] {
                "crc" => assert!(
                    matches!(error, Error::Signal(SharedError::Crc { .. })),
                    "{}",
                    c[0]
                ),
                "tail" => assert_eq!(error, SharedError::Tail { index }.into()),
                "reserved" => assert_eq!(error, SharedError::Reserved { index }.into()),
                "not_tb" => assert_eq!(error, Error::NotTb),
                "reuse" => assert_eq!(error, Error::InconsistentSpatialReuse { index }),
                _ => panic!("unknown fixture error"),
            }
        }
        for n in [0, 51, 53] {
            assert_eq!(
                TbSignal::decode(&vec![0; n]),
                Err(SharedError::BitCount { available: n }.into())
            );
        }
        for index in 0..52 {
            let mut bits = [0; 52];
            bits[index] = 2;
            assert_eq!(
                TbSignal::decode(&bits),
                Err(SharedError::NonBinary { index }.into())
            );
        }
        for n in [0, 103, 104, 105] {
            assert_eq!(
                TbSignal::decode_interleaved(&vec![0.; n]),
                Err(SharedError::Metrics.into())
            );
        }
        for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let mut metrics = [1.; 104];
            metrics[17] = value;
            assert_eq!(
                TbSignal::decode_interleaved(&metrics),
                Err(SharedError::Metrics.into())
            );
        }
    }
}
