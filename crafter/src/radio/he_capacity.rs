//! HE20 SU payload geometry; IEEE802.11ax-2021 27.3.12 and27.4.3.
use super::he::SuSignal;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Capacity {
    pub bits_per_tone: usize,
    pub spatial_streams: usize,
    pub rate_num: usize,
    pub rate_den: usize,
    pub coded_per_symbol: usize,
    pub data_per_symbol: usize,
    /// Meaningful coded positions in each last STBC-group symbol, before
    /// post-FEC padding; includes the special BCC/DCM BPSK filler when present.
    pub coded_last: usize,
    pub coded_bits: usize,
    /// SERVICE + PSDU + pre-FEC PHY padding + BCC tail (no tail for LDPC).
    pub data_bits: usize,
    pub psdu_bytes: usize,
    pub phy_pad_bits: usize,
    pub tail_bits: usize,
    pub bcc_dcm_filler: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Error {
    Bandwidth,
    Mcs,
    Streams,
    Coding,
    Padding,
    Symbols,
    Overflow,
}

impl Capacity {
    /// Does not check PPDU timing, header CRC, or LDPC puncturing admission.
    pub fn new(a: &SuSignal, symbols: usize) -> Result<Self, Error> {
        if a.bandwidth != 0 {
            return Err(Error::Bandwidth);
        }
        let (bps, num, den) = match a.mcs {
            0 => (1, 1, 2),
            1 => (2, 1, 2),
            2 => (2, 3, 4),
            3 => (4, 1, 2),
            4 => (4, 3, 4),
            5 => (6, 2, 3),
            6 => (6, 3, 4),
            7 => (6, 5, 6),
            8 => (8, 3, 4),
            9 => (8, 5, 6),
            10 => (10, 3, 4),
            11 => (10, 5, 6),
            _ => return Err(Error::Mcs),
        };
        let sts = usize::from(a.space_time_streams);
        if !(1..=8).contains(&sts) || (a.stbc && (sts != 2 || a.dcm)) {
            return Err(Error::Streams);
        }
        let nss = if a.stbc { 1 } else { sts };
        if a.dcm && (!matches!(a.mcs, 0 | 1 | 3 | 4) || nss > 2) {
            return Err(Error::Mcs);
        }
        if (!a.ldpc && (a.mcs > 9 || nss > 4)) || a.ldpc != a.ldpc_extra_segment.is_some() {
            return Err(Error::Coding);
        }
        let padding = usize::from(a.pre_fec_padding);
        if !(1..=4).contains(&padding) {
            return Err(Error::Padding);
        }
        let group = if a.stbc { 2 } else { 1 };
        if symbols < group || symbols % group != 0 {
            return Err(Error::Symbols);
        }
        let cbps = if a.dcm { 117 } else { 234 } * nss * bps;
        // Table27-79 explicitly gives58, not58.5, for DCM BPSK/NSS1.
        let dbps = cbps * num / den;
        let short_cbps = if a.dcm { 30 } else { 60 } * nss * bps;
        let short_dbps = short_cbps * num / den;
        let extra = a.ldpc_extra_segment == Some(true);
        let (rx_symbols, rx_padding) = if extra {
            if padding == 1 {
                (symbols.checked_sub(group).ok_or(Error::Symbols)?, 4)
            } else {
                (symbols, padding - 1)
            }
        } else {
            (symbols, padding)
        };
        let data_last = if rx_padding == 4 {
            dbps
        } else {
            rx_padding * short_dbps
        };
        let data_bits = rx_symbols
            .checked_sub(group)
            .ok_or(Error::Symbols)?
            .checked_mul(dbps)
            .and_then(|v| v.checked_add(group * data_last))
            .ok_or(Error::Overflow)?;
        let tail_bits = if a.ldpc { 0 } else { 6 };
        let payload = data_bits
            .checked_sub(16 + tail_bits)
            .ok_or(Error::Symbols)?;
        let coded_last = if padding == 4 {
            cbps
        } else {
            padding * short_cbps
        };
        let coded_bits = (symbols - group)
            .checked_mul(cbps)
            .and_then(|v| v.checked_add(group * coded_last))
            .ok_or(Error::Overflow)?;
        Ok(Self {
            bits_per_tone: bps,
            spatial_streams: nss,
            rate_num: num,
            rate_den: den,
            coded_per_symbol: cbps,
            data_per_symbol: dbps,
            coded_last,
            coded_bits,
            data_bits,
            psdu_bytes: payload / 8,
            phy_pad_bits: payload % 8,
            tail_bits,
            bcc_dcm_filler: !a.ldpc && a.dcm && a.mcs == 0 && nss == 1,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn header() -> SuSignal {
        SuSignal::decode(
            &b"1000000000000010000000000000000000100000100111000000"
                .iter()
                .map(|b| b - b'0')
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    #[test]
    fn radio_he_capacity_independent_forward_padding() {
        let mut count = 0;
        for row in include_str!("../../tests/fixtures/iq/he-capacity-index.tsv")
            .lines()
            .skip(1)
        {
            let c: Vec<usize> = row.split('\t').map(|v| v.parse().unwrap()).collect();
            let mut a = header();
            a.mcs = c[0] as u8;
            a.space_time_streams = c[1] as u8;
            a.dcm = c[2] != 0;
            a.stbc = c[3] != 0;
            a.ldpc = c[4] != 0;
            a.ldpc_extra_segment = a.ldpc.then_some(c[5] != 0);
            a.pre_fec_padding = c[6] as u8;
            let v = Capacity::new(&a, c[7]).unwrap_or_else(|e| panic!("{row}: {e:?}"));
            assert_eq!(
                [
                    v.bits_per_tone,
                    v.spatial_streams,
                    v.coded_per_symbol,
                    v.data_per_symbol,
                    v.coded_last,
                    v.coded_bits,
                    v.data_bits,
                    v.psdu_bytes,
                    v.phy_pad_bits,
                    v.tail_bits,
                    usize::from(v.bcc_dcm_filler)
                ],
                c[8..],
                "{row}"
            );
            assert_eq!(
                v.data_bits,
                16 + 8 * v.psdu_bytes + v.phy_pad_bits + v.tail_bits
            );
            assert!(v.phy_pad_bits < 8);
            if !a.ldpc {
                let filler = if v.bcc_dcm_filler {
                    c[7] - 1 + usize::from(c[6] == 4)
                } else {
                    0
                };
                assert_eq!(
                    (v.coded_bits - filler) * v.rate_num,
                    v.data_bits * v.rate_den,
                    "{row}"
                );
            }
            count += 1;
        }
        assert_eq!(count, 8253);
    }

    #[test]
    fn radio_he_capacity_rejects_invalid_and_overflow() {
        let base = header();
        for mcs in [12, 255] {
            let mut a = base;
            a.mcs = mcs;
            assert_eq!(Capacity::new(&a, 2), Err(Error::Mcs));
        }
        for sts in [0, 9, 255] {
            let mut a = base;
            a.space_time_streams = sts;
            assert_eq!(Capacity::new(&a, 2), Err(Error::Streams));
        }
        for mcs in [2, 5, 6, 7, 8, 9, 10, 11] {
            let mut a = base;
            a.mcs = mcs;
            a.dcm = true;
            assert_eq!(Capacity::new(&a, 2), Err(Error::Mcs));
        }
        let mut a = base;
        a.dcm = true;
        a.space_time_streams = 3;
        assert_eq!(Capacity::new(&a, 2), Err(Error::Mcs));
        a = base;
        a.stbc = true;
        assert_eq!(Capacity::new(&a, 2), Err(Error::Streams));
        a.space_time_streams = 2;
        a.dcm = true;
        assert_eq!(Capacity::new(&a, 2), Err(Error::Streams));
        a.dcm = false;
        assert_eq!(Capacity::new(&a, 3), Err(Error::Symbols));
        for (mcs, sts) in [(10, 1), (11, 1), (0, 5)] {
            let mut a = base;
            a.mcs = mcs;
            a.space_time_streams = sts;
            assert_eq!(Capacity::new(&a, 2), Err(Error::Coding));
        }
        for padding in [0, 5, 255] {
            let mut a = base;
            a.pre_fec_padding = padding;
            assert_eq!(Capacity::new(&a, 2), Err(Error::Padding));
        }
        assert_eq!(Capacity::new(&base, 0), Err(Error::Symbols));
        assert_eq!(Capacity::new(&base, usize::MAX), Err(Error::Overflow));
        a = base;
        a.ldpc = true;
        a.ldpc_extra_segment = Some(true);
        a.pre_fec_padding = 1;
        assert_eq!(Capacity::new(&a, 1), Err(Error::Symbols));
        a = base;
        a.ldpc = true;
        assert_eq!(Capacity::new(&a, 2), Err(Error::Coding));
        a = base;
        a.ldpc_extra_segment = Some(false);
        assert_eq!(Capacity::new(&a, 2), Err(Error::Coding));
        a = base;
        a.bandwidth = 1;
        assert_eq!(Capacity::new(&a, 2), Err(Error::Bandwidth));
    }
}
