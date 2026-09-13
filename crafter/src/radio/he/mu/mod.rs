//! HE MU SIG-A; IEEE 802.11ax-2021 Table 27-20 and 27.3.11.7.3-4.
//! Caller establishes MU format. This kernel does not admit DATA.

pub(in crate::radio) mod data;
pub(in crate::radio) mod ldpc;
pub(in crate::radio) mod sig_b;

use super::{decode_interleaved_bits, validate_bits, Error};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MuSignal {
    pub uplink: bool,
    pub sig_b_mcs: u8,
    pub sig_b_dcm: bool,
    pub bss_color: u8,
    /// Raw code, including reserved spatial-reuse values; not a permission.
    pub spatial_reuse: u8,
    pub bandwidth: u8,
    /// Raw four-bit value. Compressed: users minus one. Uncompressed: symbols
    /// minus one, except 15 can mean 16 or more and needs SIG-B resolution.
    pub sig_b_symbols_or_users: u8,
    pub sig_b_compression: bool,
    pub ltf_size: u8,
    pub guard_ns: u16,
    pub ltf_symbols: u8,
    pub midamble_period: Option<u8>,
    pub txop: u8,
    pub ldpc_extra_segment: bool,
    pub stbc: bool,
    pub pre_fec_padding: u8,
    pub pe_disambiguity: bool,
}

impl MuSignal {
    /// Two BPSK, interleaved 52-tone symbols after channel equalization.
    /// Positive metrics favor bit one; exactly 104 finite metrics are required.
    pub fn decode_interleaved(metrics: &[f32]) -> Result<Self, Error> {
        Self::decode(&decode_interleaved_bits(metrics)?)
    }

    /// Validate 52 binary bits, including CRC and tail, then interpret MU fields.
    /// This does not identify the PPDU format from the bits alone.
    pub fn decode(bits: &[u8]) -> Result<Self, Error> {
        validate_bits(bits)?;
        let field = |start: usize, width: usize| {
            bits[start..start + width]
                .iter()
                .enumerate()
                .fold(0u8, |value, (i, bit)| value | (bit << i))
        };
        if bits[33] != 1 {
            return Err(Error::Reserved { index: 33 });
        }
        let sig_b_mcs = field(1, 3);
        if sig_b_mcs > 5 {
            return Err(Error::Reserved { index: 1 });
        }
        let sig_b_dcm = bits[4] != 0;
        if sig_b_dcm && ![0, 1, 3, 4].contains(&sig_b_mcs) {
            return Err(Error::Reserved { index: 4 });
        }
        let bandwidth = field(15, 3);
        let sig_b_compression = bits[22] != 0;
        if sig_b_compression && bandwidth > 3 {
            return Err(Error::Reserved { index: 15 });
        }
        let doppler = bits[25] != 0;
        let raw_ltf = field(34, if doppler { 2 } else { 3 });
        if raw_ltf > if doppler { 2 } else { 4 } {
            return Err(Error::Reserved { index: 34 });
        }
        let (ltf_size, guard_ns) =
            [(4, 800), (2, 800), (2, 1600), (4, 3200)][usize::from(field(23, 2))];
        Ok(Self {
            uplink: bits[0] != 0,
            sig_b_mcs,
            sig_b_dcm,
            bss_color: field(5, 6),
            spatial_reuse: field(11, 4),
            bandwidth,
            sig_b_symbols_or_users: field(18, 4),
            sig_b_compression,
            ltf_size,
            guard_ns,
            ltf_symbols: [1, 2, 4, 6, 8][usize::from(raw_ltf)],
            midamble_period: doppler.then_some(if bits[36] == 0 { 10 } else { 20 }),
            txop: field(26, 7),
            ldpc_extra_segment: bits[37] != 0,
            stbc: bits[38] != 0,
            pre_fec_padding: match field(39, 2) {
                0 => 4,
                value => value,
            },
            pe_disambiguity: bits[41] != 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radio_he_mu_independent_headers() {
        let index = include_str!("../../../../tests/fixtures/iq/he-mu-signal-a-index.tsv");
        for row in index.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let bits: Vec<_> = c[0].bytes().map(|b| b - b'0').collect();
            let h = MuSignal::decode(&bits).unwrap();
            let actual = [
                u16::from(h.uplink),
                h.sig_b_mcs.into(),
                h.sig_b_dcm.into(),
                h.bss_color.into(),
                h.spatial_reuse.into(),
                h.bandwidth.into(),
                h.sig_b_symbols_or_users.into(),
                h.sig_b_compression.into(),
                h.ltf_size.into(),
                h.guard_ns,
                h.ltf_symbols.into(),
                h.midamble_period.unwrap_or(0).into(),
                h.txop.into(),
                h.ldpc_extra_segment.into(),
                h.stbc.into(),
                h.pre_fec_padding.into(),
                h.pe_disambiguity.into(),
            ];
            let expected: Vec<u16> = c[2..].iter().map(|s| s.parse().unwrap()).collect();
            assert_eq!(actual.as_slice(), expected, "{}", c[0]);
            for scale in [f32::MIN_POSITIVE, 1., f32::MAX] {
                let metrics: Vec<_> = c[1]
                    .bytes()
                    .map(|b| if b == b'1' { scale } else { -scale })
                    .collect();
                assert_eq!(MuSignal::decode_interleaved(&metrics), Ok(h));
            }
        }
    }

    #[test]
    fn radio_he_mu_invalid_headers() {
        let index = include_str!("../../../../tests/fixtures/iq/he-mu-signal-a-invalid.tsv");
        for row in index.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let bits: Vec<_> = c[1].bytes().map(|b| b - b'0').collect();
            let error = MuSignal::decode(&bits).unwrap_err();
            match c[2] {
                "crc" => assert!(matches!(error, Error::Crc { .. })),
                "tail" => assert!(matches!(error, Error::Tail { .. })),
                "reserved" => assert_eq!(
                    error,
                    Error::Reserved {
                        index: c[3].parse().unwrap()
                    }
                ),
                _ => panic!("unknown fixture error"),
            }
        }
        for length in [0, 41, 51, 53, 104] {
            assert_eq!(
                MuSignal::decode(&vec![0; length]),
                Err(Error::BitCount { available: length })
            );
        }
        for index in 0..52 {
            let mut bits = [0; 52];
            bits[index] = 2;
            assert_eq!(MuSignal::decode(&bits), Err(Error::NonBinary { index }));
        }
        for length in [0, 52, 103, 104, 105, 208] {
            assert_eq!(
                MuSignal::decode_interleaved(&vec![0.; length]),
                Err(Error::Metrics)
            );
        }
        for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            for index in [0, 51, 52, 103] {
                let mut metrics = [1.; 104];
                metrics[index] = value;
                assert_eq!(MuSignal::decode_interleaved(&metrics), Err(Error::Metrics));
            }
        }
    }
}
