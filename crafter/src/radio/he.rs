//! HE SU header kernel; IEEE 802.11ax-2021 Tables 27-18/19/35.
//! Caller must establish SU format. This does not admit or publish DATA.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SuSignal {
    pub beam_change: bool,
    pub uplink: bool,
    pub mcs: u8,
    pub bss_color: u8,
    pub spatial_reuse: u8,
    pub bandwidth: u8,
    pub space_time_streams: u8,
    pub midamble_period: Option<u8>,
    pub txop: u8,
    pub ldpc: bool,
    /// None for BCC: the raw bit is reserved and one, not an extra segment.
    pub ldpc_extra_segment: Option<bool>,
    pub beamformed: bool,
    pub pre_fec_padding: u8,
    pub pe_disambiguity: bool,
    pub dcm: bool,
    pub stbc: bool,
    pub ltf_size: u8,
    pub guard_ns: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Error {
    BitCount { available: usize },
    NonBinary { index: usize },
    Crc { expected: u8, received: u8 },
    Tail { index: usize },
    Reserved { index: usize },
    NotSu,
    ReservedMcs(u8),
    ReservedGi,
    Metrics,
}

impl SuSignal {
    /// Two interleaved 52-tone symbols; caller handles constellation rotations.
    pub fn decode_interleaved(metrics: &[f32]) -> Result<Self, Error> {
        if metrics.len() != 104 || metrics.iter().any(|m| !m.is_finite()) {
            return Err(Error::Metrics);
        }
        let scale = metrics.iter().map(|v| v.abs()).fold(0f32, f32::max);
        if scale == 0. {
            return Err(Error::Metrics);
        }
        let coded: [f32; 104] = std::array::from_fn(|k| {
            let bit = k % 52;
            metrics[52 * (k / 52) + 4 * (bit % 13) + bit / 13] / scale
        });
        let pairs: [[f32; 2]; 52] = std::array::from_fn(|i| [coded[2 * i], coded[2 * i + 1]]);
        Self::decode(&super::signal::decode_bcc(&pairs))
    }

    pub fn decode(bits: &[u8]) -> Result<Self, Error> {
        if bits.len() != 52 {
            return Err(Error::BitCount {
                available: bits.len(),
            });
        }
        if let Some(index) = bits.iter().position(|b| *b > 1) {
            return Err(Error::NonBinary { index });
        }
        let expected = super::ht::crc(&bits[..42]) >> 4;
        let received = bits[42..46].iter().fold(0, |v, b| (v << 1) | b);
        if expected != received {
            return Err(Error::Crc { expected, received });
        }
        if let Some(index) = (46..52).find(|i| bits[*i] != 0) {
            return Err(Error::Tail { index });
        }
        if bits[0] == 0 {
            return Err(Error::NotSu);
        }
        for index in [14, 40] {
            if bits[index] != 1 {
                return Err(Error::Reserved { index });
            }
        }
        let field = |start: usize, count: usize| {
            bits[start..start + count]
                .iter()
                .enumerate()
                .fold(0u8, |v, (i, b)| v | (b << i))
        };
        let mcs = field(3, 4);
        if mcs > 11 {
            return Err(Error::ReservedMcs(mcs));
        }
        let ldpc = bits[33] != 0;
        if !ldpc && bits[34] != 1 {
            return Err(Error::Reserved { index: 34 });
        }
        let gi = field(21, 2);
        let mut dcm = bits[7] != 0;
        let mut stbc = bits[35] != 0;
        let (ltf_size, guard_ns) = if dcm && stbc {
            if gi != 3 {
                return Err(Error::ReservedGi);
            }
            dcm = false;
            stbc = false;
            (4, 800)
        } else {
            [(1, 800), (2, 800), (2, 1600), (4, 3200)][usize::from(gi)]
        };
        let doppler = bits[41] != 0;
        Ok(Self {
            beam_change: bits[1] != 0,
            uplink: bits[2] != 0,
            mcs,
            bss_color: field(8, 6),
            spatial_reuse: field(15, 4),
            bandwidth: field(19, 2),
            space_time_streams: field(23, if doppler { 2 } else { 3 }) + 1,
            midamble_period: doppler.then_some(if bits[25] == 0 { 10 } else { 20 }),
            txop: field(26, 7),
            ldpc,
            ldpc_extra_segment: ldpc.then_some(bits[34] != 0),
            beamformed: bits[36] != 0,
            pre_fec_padding: match field(37, 2) {
                0 => 4,
                value => value,
            },
            pe_disambiguity: bits[39] != 0,
            dcm,
            stbc,
            ltf_size,
            guard_ns,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repair(bits: &mut [u8]) {
        let crc = super::super::ht::crc(&bits[..42]);
        for i in 0..4 {
            bits[42 + i] = (crc >> (7 - i)) & 1;
        }
    }

    #[test]
    fn radio_he_su_independent_headers_and_metrics() {
        let rows: Vec<_> = include_str!("../../tests/fixtures/iq/he-signal-a-index.tsv")
            .lines()
            .skip(1)
            .collect();
        assert_eq!(rows.len(), 1984);
        for row in rows {
            let c: Vec<_> = row.split('\t').collect();
            let bits: Vec<_> = c[0].bytes().map(|b| b - b'0').collect();
            let fields = SuSignal::decode(&bits).unwrap();
            let expected: Vec<i32> = c[2..].iter().map(|s| s.parse().unwrap()).collect();
            let actual = [
                i32::from(fields.mcs),
                i32::from(fields.bandwidth),
                i32::from(fields.space_time_streams),
                i32::from(fields.midamble_period.unwrap_or(0)),
                i32::from(fields.dcm),
                i32::from(fields.stbc),
                i32::from(fields.ltf_size),
                i32::from(fields.guard_ns),
                i32::from(fields.ldpc),
                fields.ldpc_extra_segment.map(i32::from).unwrap_or(-1),
                i32::from(fields.pre_fec_padding),
                i32::from(fields.bss_color),
                i32::from(fields.spatial_reuse),
                i32::from(fields.txop),
                i32::from(fields.beam_change),
                i32::from(fields.uplink),
                i32::from(fields.beamformed),
                i32::from(fields.pe_disambiguity),
            ];
            assert_eq!(actual.as_slice(), expected, "{}", c[0]);
            let metrics: Vec<_> = c[1]
                .bytes()
                .map(|b| if b == b'1' { 2. } else { -2. })
                .collect();
            assert_eq!(SuSignal::decode_interleaved(&metrics), Ok(fields));
            for index in 0..46 {
                let mut corrupt = bits.clone();
                corrupt[index] ^= 1;
                // HE transmits only four bits of the eight-bit CRC. Polynomial
                // division independently identifies these single-bit blind spots;
                // do not claim CRC4 detects every error in the protected input.
                if [18, 40, 41].contains(&index) {
                    assert!(!matches!(
                        SuSignal::decode(&corrupt),
                        Err(Error::Crc { .. })
                    ));
                } else {
                    assert!(matches!(SuSignal::decode(&corrupt), Err(Error::Crc { .. })));
                }
            }
        }
    }

    #[test]
    fn radio_he_su_rejects_invalid_inputs() {
        let row = include_str!("../../tests/fixtures/iq/he-signal-a-index.tsv")
            .lines()
            .nth(1)
            .unwrap();
        let bits: Vec<_> = row
            .split('\t')
            .next()
            .unwrap()
            .bytes()
            .map(|b| b - b'0')
            .collect();
        for length in 0..52 {
            assert_eq!(
                SuSignal::decode(&bits[..length]),
                Err(Error::BitCount { available: length })
            );
        }
        let mut oversized = bits.clone();
        oversized.push(0);
        assert_eq!(
            SuSignal::decode(&oversized),
            Err(Error::BitCount { available: 53 })
        );
        for index in 0..52 {
            let mut bad = bits.clone();
            bad[index] = 2;
            assert_eq!(SuSignal::decode(&bad), Err(Error::NonBinary { index }));
        }
        for index in 46..52 {
            let mut bad = bits.clone();
            bad[index] = 1;
            assert_eq!(SuSignal::decode(&bad), Err(Error::Tail { index }));
        }
        for index in [14, 34, 40] {
            let mut bad = bits.clone();
            bad[index] = 0;
            repair(&mut bad);
            assert_eq!(SuSignal::decode(&bad), Err(Error::Reserved { index }));
        }
        let mut bad = bits.clone();
        bad[0] = 0;
        repair(&mut bad);
        assert_eq!(SuSignal::decode(&bad), Err(Error::NotSu));
        for mcs in 12..16 {
            let mut bad = bits.clone();
            for i in 0..4 {
                bad[3 + i] = (mcs >> i) & 1;
            }
            repair(&mut bad);
            assert_eq!(SuSignal::decode(&bad), Err(Error::ReservedMcs(mcs)));
        }
        for gi in 0..3 {
            let mut bad = bits.clone();
            bad[7] = 1;
            bad[35] = 1;
            bad[21] = gi & 1;
            bad[22] = gi >> 1;
            repair(&mut bad);
            assert_eq!(SuSignal::decode(&bad), Err(Error::ReservedGi));
        }
        for metrics in [
            vec![],
            vec![0.; 104],
            vec![1.; 103],
            vec![f32::NAN; 104],
            vec![f32::INFINITY; 104],
        ] {
            assert_eq!(SuSignal::decode_interleaved(&metrics), Err(Error::Metrics));
        }
    }

    #[test]
    fn radio_he_published_crc_example() {
        // 27.3.11.7.3, published input m0..m41 and transmitted output B7..B4.
        let bits: Vec<_> = "110111000000001000000110000000000010011010"
            .bytes()
            .map(|b| b - b'0')
            .collect();
        assert_eq!(bits.len(), 42);
        assert_eq!(super::super::ht::crc(&bits) >> 4, 0b0111);
    }
}
