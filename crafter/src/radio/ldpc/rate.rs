//! HT/VHT SU LDPC sizing: IEEE 802.11-2020 19.3.11.7.5 and 21.3.10.5.4.
//! Integer inequalities preserve the strict thresholds in Equations 19-38–40.
use super::Rate;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) enum Error {
    EmptyPayload,
    InvalidCodedBits,
    VhtTiming,
    HeTiming,
    PayloadBitCount { required: usize, available: usize },
    Encoding(super::Error),
    Metrics(super::Error),
    Codeword { index: usize, error: super::Error },
    Shortening { index: usize },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) struct Word {
    pub information_bits: usize,
    pub shortened_bits: usize,
    pub punctured_bits: usize,
    pub repeated_bits: usize,
    pub transmitted_bits: usize,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) struct Layout {
    pub symbols: usize,
    pub codewords: usize,
    pub block_bits: usize,
    pub shortened_bits: usize,
    pub punctured_bits: usize,
    pub repeated_bits: usize,
    /// HT/VHT add a full symbol group; HE adds one padding segment.
    pub extra_symbol_group: bool,
    pub payload_bits: usize,
    pub coded_bits_per_symbol: usize,
    /// Actual FEC observations, excluding HE post-FEC padding.
    pub transmitted_bits: usize,
    pub rate: Rate,
}
pub(in crate::radio) struct Recovery {
    pub bits: Vec<u8>,
    pub iterations: usize,
    pub failed_codewords: usize,
    pub first_failure: Option<Error>,
}

enum HeExtraPolicy {
    Exact,
    Required,
    /// TB27.3.12.5.5 follows the Trigger's explicit branch, not a local
    /// transmitter recommendation. Codeword recovery remains fully checked.
    Signaled,
}
impl Layout {
    /// Encode the scrambled SERVICE and PSDU bits, then apply shortening,
    /// puncturing, and repetition in transmitted codeword order.
    pub(in crate::radio) fn encode(self, bits: &[u8]) -> Result<Vec<u8>, Error> {
        if bits.len() != self.payload_bits {
            return Err(Error::PayloadBitCount {
                required: self.payload_bits,
                available: bits.len(),
            });
        }
        let code = super::Code::new(self.block_bits, self.rate).map_err(Error::Encoding)?;
        let (num, den) = self.rate.ratio();
        let information_bits = self.block_bits * num / den;
        let mut output = Vec::with_capacity(self.symbols * self.coded_bits_per_symbol);
        let mut offset = 0;
        for index in 0..self.codewords {
            let spec = self.word(index).unwrap();
            let end = offset + spec.information_bits;
            let mut information = Vec::with_capacity(information_bits);
            information.extend_from_slice(&bits[offset..end]);
            information.resize(information_bits, 0);
            let word = code.encode(&information).map_err(Error::Encoding)?;
            output.extend_from_slice(&word[..spec.information_bits]);
            output
                .extend_from_slice(&word[information_bits..self.block_bits - spec.punctured_bits]);
            let base = output.len() - (self.block_bits - spec.shortened_bits - spec.punctured_bits);
            for repeat in 0..spec.repeated_bits {
                output.push(output[base + repeat % (self.block_bits - spec.shortened_bits)]);
            }
            offset = end;
        }
        debug_assert_eq!(offset, bits.len());
        debug_assert_eq!(output.len(), self.symbols * self.coded_bits_per_symbol);
        Ok(output)
    }

    /// Restore omitted known-zero information bits and erased parity, combine
    /// repeated observations, and recover the concatenated information stream.
    /// Input is in transmitted codeword order (LDPC bypasses BCC interleaving).
    pub(in crate::radio) fn recover(
        self,
        metrics: &[f32],
        limit: usize,
    ) -> Result<(Vec<u8>, usize), Error> {
        let recovered = self.recover_impl(metrics, limit, false)?;
        Ok((recovered.bits, recovered.iterations))
    }
    /// Retain bounded estimates across damaged codewords for A-MPDU scanning.
    /// The caller must validate SERVICE and every delivered MPDU's FCS.
    pub(in crate::radio) fn recover_partial(
        self,
        metrics: &[f32],
        limit: usize,
    ) -> Result<Recovery, Error> {
        self.recover_impl(metrics, limit, true)
    }
    fn recover_impl(self, metrics: &[f32], limit: usize, partial: bool) -> Result<Recovery, Error> {
        use super::{Code, Error as CodeError};
        let required = self.transmitted_bits;
        if metrics.len() != required {
            return Err(Error::Metrics(CodeError::MetricCount {
                required,
                available: metrics.len(),
            }));
        }
        let mut maximum = 0f32;
        for (index, &m) in metrics.iter().enumerate() {
            if !m.is_finite() {
                return Err(Error::Metrics(CodeError::NonFiniteMetric { index }));
            }
            maximum = maximum.max(m.abs());
        }
        if maximum == 0. {
            return Err(Error::Metrics(CodeError::UnusableMetrics));
        }
        let code = Code::new(self.block_bits, self.rate).map_err(Error::Metrics)?;
        let (num, den) = self.rate.ratio();
        let k = self.block_bits * num / den;
        let mut output = Vec::with_capacity(self.payload_bits);
        let (mut offset, mut iterations) = (0, 0);
        let (mut failed_codewords, mut first_failure) = (0, None);
        for index in 0..self.codewords {
            let spec = self.word(index).unwrap();
            let mut word = vec![0.; self.block_bits]; // Unknown punctures have zero LLR.
            let normalize = |m: f32| 4. * (m / maximum);
            for (i, m) in word[..spec.information_bits].iter_mut().enumerate() {
                *m = normalize(metrics[offset + i]);
            }
            word[spec.information_bits..k].fill(-32.); // Known zero, not an erasure.
            let parity = self.block_bits - k - spec.punctured_bits;
            for (i, m) in word[k..k + parity].iter_mut().enumerate() {
                *m = normalize(metrics[offset + spec.information_bits + i]);
            }
            let base = self.block_bits - spec.shortened_bits - spec.punctured_bits;
            for repeat in 0..spec.repeated_bits {
                let source = repeat % (self.block_bits - spec.shortened_bits);
                let bit = if source < spec.information_bits {
                    source
                } else {
                    source + spec.shortened_bits
                };
                word[bit] += normalize(metrics[offset + base + repeat]);
            }
            let estimate = code
                .estimate(&word, limit)
                .map_err(|error| Error::Codeword { index, error })?;
            let mut bits = estimate.bits;
            let failure = if estimate.failed_checks != 0 {
                Some(Error::Codeword {
                    index,
                    error: CodeError::Nonconvergence {
                        iterations: estimate.iterations,
                        failed_checks: estimate.failed_checks,
                    },
                })
            } else if bits[spec.information_bits..].iter().any(|&b| b != 0) {
                Some(Error::Shortening { index })
            } else {
                None
            };
            if let Some(error) = failure {
                if !partial {
                    return Err(error);
                }
                failed_codewords += 1;
                first_failure.get_or_insert(error);
            }
            bits.truncate(spec.information_bits);
            output.extend(bits);
            iterations += estimate.iterations;
            offset += spec.transmitted_bits;
        }
        Ok(Recovery {
            bits: output,
            iterations,
            failed_codewords,
            first_failure,
        })
    }
    /// u16 dimensions bound all arithmetic even on 32-bit hosts. The enclosing
    /// PHY must additionally validate that its MCS actually permits `coded`.
    pub(in crate::radio) fn new(
        bytes: u16,
        coded: u16,
        rate: Rate,
        stbc: bool,
    ) -> Result<Self, Error> {
        if bytes == 0 {
            return Err(Error::EmptyPayload);
        }
        let (num, den) = rate.ratio();
        let coded = usize::from(coded);
        if coded == 0 || coded * num % den != 0 {
            return Err(Error::InvalidCodedBits);
        }
        let group = if stbc { 2 } else { 1 };
        let payload = 8 * usize::from(bytes) + 16;
        Ok(Self::from_payload(payload, coded, rate, group))
    }
    /// VHT20 SU information includes PHY padding. Timing and the extra-symbol
    /// flag jointly identify the initial symbol count; never use HT's byte
    /// length formula here. IEEE 802.11-2020 21.3.10.5.4.
    pub(in crate::radio) fn vht(
        symbols: u16,
        mcs: u8,
        stbc: bool,
        extra: bool,
    ) -> Result<Self, Error> {
        let (coded, rate) = *[
            (52, Rate::Half),
            (104, Rate::Half),
            (104, Rate::ThreeQuarters),
            (208, Rate::Half),
            (208, Rate::ThreeQuarters),
            (312, Rate::TwoThirds),
            (312, Rate::ThreeQuarters),
            (312, Rate::FiveSixths),
            (416, Rate::ThreeQuarters),
        ]
        .get(usize::from(mcs))
        .ok_or(Error::InvalidCodedBits)?;
        let symbols = usize::from(symbols);
        let group = if stbc { 2 } else { 1 };
        if symbols == 0 || symbols > 1512 || symbols % group != 0 {
            return Err(Error::VhtTiming);
        }
        let initial = symbols
            .checked_sub(usize::from(extra) * group)
            .filter(|n| *n > 0)
            .ok_or(Error::VhtTiming)?;
        let (num, den) = rate.ratio();
        let layout = Self::from_payload(initial * coded * num / den, coded, rate, group);
        if layout.symbols != symbols || layout.extra_symbol_group != extra {
            return Err(Error::VhtTiming);
        }
        Ok(layout)
    }
    /// HE20 SU: invert extra-segment signaling, then validate it against the
    /// forward puncturing threshold. Payload includes pre-FEC padding, not tail.
    /// PHY timing/admission and stream recombination remain caller obligations.
    pub(in crate::radio) fn he(
        a: &crate::radio::he::SuSignal,
        symbols: u16,
    ) -> Result<Self, Error> {
        Self::he_for_format(a, symbols, false)
    }

    /// Format is independently verified; ER bandwidth identifies 242/upper 106 tones.
    pub(in crate::radio) fn he_for_format(
        a: &crate::radio::he::SuSignal,
        symbols: u16,
        er: bool,
    ) -> Result<Self, Error> {
        use crate::radio::he::capacity::Capacity;
        let symbols = usize::from(symbols);
        // Even the shortest HE20 SU preamble/GI cannot fit >400 DATA symbols
        // under the 12-bit L-SIG duration bound. This also bounds integer math.
        if !a.ldpc || symbols == 0 || symbols > 400 {
            return Err(Error::HeTiming);
        }
        let c = Capacity::for_format(a, symbols, er).map_err(|_| Error::HeTiming)?;
        let group = if a.stbc { 2 } else { 1 };
        let extra = a.ldpc_extra_segment.ok_or(Error::HeTiming)?;
        let mut initial = *a;
        initial.ldpc_extra_segment = Some(false);
        let mut initial_symbols = symbols;
        if extra {
            if a.pre_fec_padding == 1 {
                initial.pre_fec_padding = 4;
                initial_symbols = symbols.checked_sub(group).ok_or(Error::HeTiming)?;
            } else {
                initial.pre_fec_padding -= 1;
            }
        }
        let initial_c =
            Capacity::for_format(&initial, initial_symbols, er).map_err(|_| Error::HeTiming)?;
        Self::he_capacities(
            c,
            initial_c,
            symbols,
            group,
            extra,
            initial.pre_fec_padding,
            HeExtraPolicy::Exact,
        )
    }

    /// MU's common extra flag can be requested by another LDPC user. The
    /// caller establishes cross-user signaling consistency and spatial admission.
    pub(in crate::radio) fn he_mu(
        signal: &crate::radio::he::mu::MuSignal,
        user: &crate::radio::he::mu::sig_b::HeSigBUserFields,
        ru_tones: u16,
        symbols: u16,
    ) -> Result<Self, Error> {
        use crate::radio::he::capacity::Capacity;
        let symbols = usize::from(symbols);
        if symbols == 0 || symbols > 400 {
            return Err(Error::HeTiming);
        }
        let c = Capacity::for_mu(signal, user, ru_tones, symbols).map_err(|_| Error::HeTiming)?;
        if c.tail_bits != 0 {
            return Err(Error::HeTiming);
        }
        let group = usize::from(signal.stbc) + 1;
        let extra = signal.ldpc_extra_segment;
        let mut initial = *signal;
        initial.ldpc_extra_segment = false;
        let mut initial_symbols = symbols;
        if extra {
            if initial.pre_fec_padding == 1 {
                initial.pre_fec_padding = 4;
                initial_symbols = symbols.checked_sub(group).ok_or(Error::HeTiming)?;
            } else {
                initial.pre_fec_padding -= 1;
            }
        }
        let initial_c = Capacity::for_mu(&initial, user, ru_tones, initial_symbols)
            .map_err(|_| Error::HeTiming)?;
        Self::he_capacities(
            c,
            initial_c,
            symbols,
            group,
            extra,
            initial.pre_fec_padding,
            HeExtraPolicy::Required,
        )
    }

    /// TB27.3.12.5.5/Eq27-90: undo the signaled extra segment to determine
    /// initial codeword dimensions, then transmit exactly the Trigger budget.
    pub(in crate::radio) fn he_tb(
        common: &crate::Dot11TriggerCommonFields,
        user: &crate::Dot11TriggerUserFields,
        symbols: u16,
    ) -> Result<Self, Error> {
        use crate::radio::he::capacity::Capacity;
        let symbols = usize::from(symbols);
        if !user.ldpc || symbols == 0 || symbols > 400 {
            return Err(Error::HeTiming);
        }
        let c = Capacity::for_tb(common, user, symbols).map_err(|_| Error::HeTiming)?;
        let group = 1 + usize::from(common.stbc);
        let extra = common.ldpc_extra_segment;
        let mut initial = *common;
        initial.ldpc_extra_segment = false;
        let mut initial_symbols = symbols;
        if extra {
            if common.pre_fec_padding_raw == 1 {
                initial.pre_fec_padding_raw = 0; // a_init=4
                initial_symbols = symbols.checked_sub(group).ok_or(Error::HeTiming)?;
            } else {
                initial.pre_fec_padding_raw = if common.pre_fec_padding_raw == 0 {
                    3
                } else {
                    common.pre_fec_padding_raw - 1
                };
            }
        }
        let initial_c =
            Capacity::for_tb(&initial, user, initial_symbols).map_err(|_| Error::HeTiming)?;
        Self::he_capacities(
            c,
            initial_c,
            symbols,
            group,
            extra,
            if initial.pre_fec_padding_raw == 0 {
                4
            } else {
                initial.pre_fec_padding_raw
            },
            HeExtraPolicy::Signaled,
        )
    }

    fn he_capacities(
        c: crate::radio::he::capacity::Capacity,
        initial_c: crate::radio::he::capacity::Capacity,
        symbols: usize,
        group: usize,
        extra: bool,
        initial_padding: u8,
        extra_policy: HeExtraPolicy,
    ) -> Result<Self, Error> {
        let rate = match (c.rate_num, c.rate_den) {
            (1, 2) => Rate::Half,
            (2, 3) => Rate::TwoThirds,
            (3, 4) => Rate::ThreeQuarters,
            (5, 6) => Rate::FiveSixths,
            _ => return Err(Error::InvalidCodedBits),
        };
        let payload = initial_c.data_bits;
        let available = initial_c.coded_bits;
        let (num, den) = rate.ratio();
        let (count, size) = Self::dimensions(payload, available, rate);
        let short = (count * size * num / den).saturating_sub(payload);
        let puncture = (count * size).saturating_sub(available + short);
        let parity = count * size * (den - num) / den;
        let needs_extra = Self::needs_extra(short, puncture, parity, rate);
        let admitted = match extra_policy {
            HeExtraPolicy::Exact => needs_extra == extra,
            HeExtraPolicy::Required => !needs_extra || extra,
            HeExtraPolicy::Signaled => true,
        };
        if !admitted {
            return Err(Error::HeTiming);
        }
        let short_cbps = c.coded_short;
        let expected = available
            + if extra {
                group
                    * if initial_padding == 3 {
                        c.coded_per_symbol - 3 * short_cbps
                    } else {
                        short_cbps
                    }
            } else {
                0
            };
        if expected != c.coded_bits || payload != c.data_bits {
            return Err(Error::HeTiming);
        }
        Ok(Self {
            symbols,
            codewords: count,
            block_bits: size,
            shortened_bits: short,
            punctured_bits: (count * size).saturating_sub(expected + short),
            repeated_bits: expected.saturating_sub(parity + payload),
            extra_symbol_group: extra,
            payload_bits: payload,
            coded_bits_per_symbol: c.coded_per_symbol,
            transmitted_bits: expected,
            rate,
        })
    }
    fn dimensions(payload: usize, available: usize, rate: Rate) -> (usize, usize) {
        let (num, den) = rate.ratio();
        let threshold = |constant| available * den >= payload * den + constant * (den - num);
        match available {
            0..=648 => (1, if threshold(912) { 1296 } else { 648 }),
            649..=1296 => (1, if threshold(1464) { 1944 } else { 1296 }),
            1297..=1944 => (1, 1944),
            1945..=2592 => (2, if threshold(2916) { 1944 } else { 1296 }),
            _ => (payload.div_ceil(1944 * num / den), 1944),
        }
    }
    fn needs_extra(short: usize, puncture: usize, parity: usize, rate: Rate) -> bool {
        let (num, den) = rate.ratio();
        (10 * puncture > parity && 5 * short * (den - num) < 6 * puncture * num)
            || 10 * puncture > 3 * parity
    }
    // Entry points bound dimensions before reaching the shared algorithms.
    fn from_payload(payload: usize, coded: usize, rate: Rate, group: usize) -> Self {
        let (num, den) = rate.ratio();
        let mut available = coded * group * payload.div_ceil(coded * num / den * group);
        let original = available;
        let (count, size) = Self::dimensions(payload, available, rate);
        let short = (count * size * num / den).saturating_sub(payload);
        let mut puncture = (count * size).saturating_sub(available + short);
        let parity = count * size * (den - num) / den;
        if Self::needs_extra(short, puncture, parity, rate) {
            available += coded * group;
            puncture = (count * size).saturating_sub(available + short);
        }
        let repeat = available.saturating_sub(parity + payload);
        Self {
            symbols: available / coded,
            codewords: count,
            block_bits: size,
            shortened_bits: short,
            punctured_bits: puncture,
            repeated_bits: repeat,
            extra_symbol_group: available != original,
            payload_bits: payload,
            coded_bits_per_symbol: coded,
            transmitted_bits: available,
            rate,
        }
    }
    pub(in crate::radio) fn word(self, index: usize) -> Option<Word> {
        if index >= self.codewords {
            return None;
        }
        let share = |total| total / self.codewords + usize::from(index < total % self.codewords);
        let shortened = share(self.shortened_bits);
        let punctured = share(self.punctured_bits);
        let repeated = share(self.repeated_bits);
        let (num, den) = self.rate.ratio();
        Some(Word {
            information_bits: self.block_bits * num / den - shortened,
            shortened_bits: shortened,
            punctured_bits: punctured,
            repeated_bits: repeated,
            transmitted_bits: self.block_bits - shortened - punctured + repeated,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn he_header() -> crate::radio::he::SuSignal {
        let mut a = crate::radio::he::SuSignal::decode(
            &b"1000000000000010000000000000000000100000100111000000"
                .iter()
                .map(|b| b - b'0')
                .collect::<Vec<_>>(),
        )
        .unwrap();
        a.ldpc = true;
        a.ldpc_extra_segment = Some(false);
        a
    }
    #[test]
    fn radio_he_ldpc_independent_geometry() {
        he_geometry(
            include_str!("../../../tests/fixtures/iq/he-ldpc-rate-index.tsv"),
            None,
        );
    }
    #[test]
    fn radio_he_er_ldpc_independent_geometry() {
        he_geometry(
            include_str!("../../../tests/fixtures/iq/he-er106-ldpc-rate-index.tsv"),
            Some(1),
        );
        he_geometry(
            include_str!("../../../tests/fixtures/iq/he-er242-ldpc-rate-index.tsv"),
            Some(0),
        );
        for bandwidth in [0, 1] {
            let mut a = he_header();
            a.bandwidth = bandwidth;
            for symbols in [0, 401, u16::MAX] {
                assert_eq!(
                    Layout::he_for_format(&a, symbols, true),
                    Err(Error::HeTiming)
                );
            }
            for mcs in (if bandwidth == 1 { 1 } else { 3 })..=12 {
                a.mcs = mcs;
                assert!(Layout::he_for_format(&a, 4, true).is_err());
            }
            a.mcs = 0;
            a.space_time_streams = 2;
            assert!(Layout::he_for_format(&a, 4, true).is_err());
            a.stbc = true;
            a.dcm = true;
            assert!(Layout::he_for_format(&a, 4, true).is_err());
            a = he_header();
            a.bandwidth = bandwidth;
            a.ldpc = false;
            assert!(Layout::he_for_format(&a, 4, true).is_err());
            a.ldpc = true;
            a.ldpc_extra_segment = None;
            assert!(Layout::he_for_format(&a, 4, true).is_err());
            a.ldpc_extra_segment = Some(false);
            a.pre_fec_padding = 0;
            assert!(Layout::he_for_format(&a, 4, true).is_err());
        }
        let mut a = he_header();
        a.bandwidth = 2;
        assert!(Layout::he_for_format(&a, 4, true).is_err());
    }
    #[test]
    fn radio_he_tb_ldpc_independent_layouts() {
        let rows = include_str!("../../../tests/fixtures/iq/he-tb-ldpc-layout.tsv");
        assert_eq!(rows.lines().skip(1).count(), 17276);
        let mut differences = [0usize; 2];
        for row in rows.lines().skip(1) {
            let c: Vec<usize> = row.split('\t').map(|s| s.parse().unwrap()).collect();
            let common = crate::Dot11TriggerCommonFields {
                stbc: c[4] == 2,
                pre_fec_padding_raw: (c[9] % 4) as u8,
                ldpc_extra_segment: c[10] != 0,
                ..Default::default()
            };
            let user = crate::Dot11TriggerUserFields {
                aid12: 1,
                ru_allocation: match c[0] {
                    26 => 0,
                    52 => 74,
                    106 => 106,
                    242 => 122,
                    _ => unreachable!(),
                },
                mcs: c[1] as u8,
                ldpc: true,
                dcm: c[3] != 0,
                spatial_allocation: ((c[2] - 1) << 3) as u8,
                ..Default::default()
            };
            let l = Layout::he_tb(&common, &user, c[8] as u16)
                .unwrap_or_else(|e| panic!("{row}: {e:?}"));
            assert_eq!(
                [
                    l.symbols,
                    l.codewords,
                    l.block_bits,
                    l.shortened_bits,
                    l.punctured_bits,
                    l.repeated_bits,
                    l.payload_bits,
                    l.transmitted_bits
                ],
                [c[8], c[11], c[12], c[13], c[14], c[15], c[16], c[17]],
                "{row}"
            );
            assert_eq!(l.extra_symbol_group, c[10] != 0);
            let mut totals = [0; 5];
            for i in 0..l.codewords {
                let word = l.word(i).unwrap();
                for (sum, value) in totals.iter_mut().zip([
                    word.information_bits,
                    word.shortened_bits,
                    word.punctured_bits,
                    word.repeated_bits,
                    word.transmitted_bits,
                ]) {
                    *sum += value;
                }
            }
            assert_eq!(totals, [c[16], c[13], c[14], c[15], c[17]]);
            assert!(l.word(l.codewords).is_none());
            assert!(l.word(usize::MAX).is_none());
            if c[7] != c[10] {
                differences[c[10]] += 1;
            }
            for symbols in [0, 401, u16::MAX] {
                assert_eq!(Layout::he_tb(&common, &user, symbols), Err(Error::HeTiming));
            }
        }
        assert!(differences.iter().all(|n| *n > 1000));
    }

    #[test]
    fn radio_he_tb_ldpc_rejects_invalid_trigger_geometry() {
        let mut common = crate::Dot11TriggerCommonFields::default();
        let mut user = crate::Dot11TriggerUserFields::default();
        assert_eq!(Layout::he_tb(&common, &user, 4), Err(Error::HeTiming));
        user.ldpc = true;
        assert!(Layout::he_tb(&common, &user, 4).is_ok());
        common.pre_fec_padding_raw = 4;
        assert_eq!(Layout::he_tb(&common, &user, 4), Err(Error::HeTiming));
        common.pre_fec_padding_raw = 1;
        common.ldpc_extra_segment = true;
        assert_eq!(Layout::he_tb(&common, &user, 1), Err(Error::HeTiming));
        common.pre_fec_padding_raw = 0;
        user.aid12 = 2046;
        assert_eq!(Layout::he_tb(&common, &user, 4), Err(Error::HeTiming));
    }

    #[test]
    fn radio_he_mu_ldpc_independent_layouts() {
        use crate::radio::{HeSigBUserEncoding, HeSigBUserFields};
        let bits: Vec<_> = include_str!("../../../tests/fixtures/iq/he-mu-signal-a-index.tsv")
            .lines()
            .nth(1)
            .unwrap()
            .split('\t')
            .next()
            .unwrap()
            .bytes()
            .map(|b| b - b'0')
            .collect();
        let mut signal = crate::radio::he::mu::MuSignal::decode(&bits).unwrap();
        signal.bandwidth = 0;
        let rows = include_str!("../../../tests/fixtures/iq/he-mu-ldpc-layout.tsv");
        assert_eq!(rows.lines().skip(1).count(), 13696);
        let mut peer_extra = 0;
        for row in rows.lines().skip(1) {
            let c: Vec<usize> = row.split('\t').map(|s| s.parse().unwrap()).collect();
            signal.stbc = c[4] == 2;
            signal.pre_fec_padding = c[9] as u8;
            signal.ldpc_extra_segment = c[10] != 0;
            let user = HeSigBUserFields {
                sta_id: 1,
                encoding: HeSigBUserEncoding::NonMu {
                    space_time_streams: (c[2] * c[4]) as u8,
                    beamformed: false,
                    mcs: c[1] as u8,
                    dcm: c[3] != 0,
                    ldpc: true,
                },
            };
            let l = Layout::he_mu(&signal, &user, c[0] as u16, c[8] as u16)
                .unwrap_or_else(|e| panic!("{row}: {e:?}"));
            assert_eq!(
                [
                    l.symbols,
                    l.codewords,
                    l.block_bits,
                    l.shortened_bits,
                    l.punctured_bits,
                    l.repeated_bits,
                    l.payload_bits,
                    l.transmitted_bits
                ],
                [c[8], c[11], c[12], c[13], c[14], c[15], c[16], c[17]],
                "{row}"
            );
            assert_eq!(l.extra_symbol_group, c[10] != 0);
            let mut totals = [0; 5];
            for n in 0..l.codewords {
                let w = l.word(n).unwrap();
                for (sum, v) in totals.iter_mut().zip([
                    w.information_bits,
                    w.shortened_bits,
                    w.punctured_bits,
                    w.repeated_bits,
                    w.transmitted_bits,
                ]) {
                    *sum += v;
                }
            }
            assert_eq!(totals, [c[16], c[13], c[14], c[15], c[17]]);
            assert!(l.word(l.codewords).is_none());
            if c[7] == 0 && c[10] == 1 {
                peer_extra += 1;
                if c[0] == 242 {
                    let mut su = he_header();
                    su.mcs = c[1] as u8;
                    su.space_time_streams = (c[2] * c[4]) as u8;
                    su.stbc = signal.stbc;
                    su.dcm = c[3] != 0;
                    su.pre_fec_padding = signal.pre_fec_padding;
                    su.ldpc_extra_segment = Some(true);
                    assert_eq!(Layout::he(&su, c[8] as u16), Err(Error::HeTiming));
                }
            }
            signal.pre_fec_padding = c[6] as u8;
            signal.ldpc_extra_segment = false;
            let initial = Layout::he_mu(&signal, &user, c[0] as u16, c[5] as u16);
            assert_eq!(initial.is_err(), c[7] != 0, "{row}");
            assert_eq!(
                Layout::he_mu(&signal, &user, c[0] as u16, 401),
                Err(Error::HeTiming)
            );
        }
        assert!(peer_extra > 1000);
    }

    fn he_geometry(rows: &str, er_bandwidth: Option<u8>) {
        let mut coverage = [false; 7];
        for row in rows.lines().skip(1) {
            let c: Vec<usize> = row.split('\t').map(|s| s.parse().unwrap()).collect();
            let mut a = he_header();
            a.bandwidth = er_bandwidth.unwrap_or(0);
            a.mcs = c[0] as u8;
            a.stbc = c[3] == 2;
            a.space_time_streams = if a.stbc { 2 } else { c[1] as u8 };
            a.dcm = c[2] != 0;
            a.pre_fec_padding = c[7] as u8;
            a.ldpc_extra_segment = Some(c[8] != 0);
            let l = Layout::he_for_format(&a, c[6] as u16, er_bandwidth.is_some())
                .unwrap_or_else(|e| panic!("{row}: {e:?}"));
            if er_bandwidth == Some(0) {
                assert_eq!(Layout::he(&a, c[6] as u16), Ok(l));
            }
            if er_bandwidth == Some(1) {
                assert!(Layout::he(&a, c[6] as u16).is_err());
            }
            assert_eq!(
                [
                    l.symbols,
                    l.codewords,
                    l.block_bits,
                    l.shortened_bits,
                    l.punctured_bits,
                    l.repeated_bits,
                    usize::from(l.extra_symbol_group),
                    l.payload_bits,
                    l.transmitted_bits
                ],
                [c[6], c[9], c[10], c[11], c[12], c[13], c[8], c[14], c[15]],
                "{row}"
            );
            let mut totals = [0usize; 5];
            for i in 0..l.codewords {
                let w = l.word(i).unwrap();
                for (sum, v) in totals.iter_mut().zip([
                    w.information_bits,
                    w.shortened_bits,
                    w.punctured_bits,
                    w.repeated_bits,
                    w.transmitted_bits,
                ]) {
                    *sum += v;
                }
            }
            assert_eq!(
                totals,
                [
                    l.payload_bits,
                    l.shortened_bits,
                    l.punctured_bits,
                    l.repeated_bits,
                    l.transmitted_bits
                ]
            );
            assert!(l.word(l.codewords).is_none());
            coverage[match l.block_bits {
                648 => 0,
                1296 => 1,
                1944 => 2,
                _ => panic!("block"),
            }] = true;
            coverage[3] |= c[8] != 0 && c[5] == 4;
            coverage[4] |= c[8] != 0 && c[5] == 3;
            coverage[5] |= l.punctured_bits > 0;
            coverage[6] |= l.repeated_bits > 0;
            a.ldpc_extra_segment = Some(c[8] == 0);
            assert_ne!(
                Layout::he_for_format(&a, c[6] as u16, er_bandwidth.is_some()),
                Ok(l)
            );
        }
        assert!(coverage.into_iter().all(|b| b));
        let mut a = he_header();
        for symbols in [0, 401, u16::MAX] {
            assert_eq!(Layout::he(&a, symbols), Err(Error::HeTiming));
        }
        a.ldpc = false;
        assert_eq!(Layout::he(&a, 4), Err(Error::HeTiming));
        a = he_header();
        a.ldpc_extra_segment = None;
        assert!(Layout::he(&a, 4).is_err());
        a = he_header();
        a.pre_fec_padding = 0;
        assert!(Layout::he(&a, 4).is_err());
        a = he_header();
        a.mcs = 12;
        assert!(Layout::he(&a, 4).is_err());
        a = he_header();
        a.bandwidth = 1;
        assert!(Layout::he(&a, 4).is_err());
    }
    #[test]
    fn radio_he_er_ldpc_independent_codeword_recovery() {
        for (bandwidth, rows) in [
            (
                1,
                include_str!("../../../tests/fixtures/iq/he-er106-ldpc-rate-codewords.tsv"),
            ),
            (
                0,
                include_str!("../../../tests/fixtures/iq/he-er242-ldpc-rate-codewords.tsv"),
            ),
        ] {
            for row in rows.lines().skip(1) {
                let c: Vec<_> = row.split('\t').collect();
                let mut a = he_header();
                a.bandwidth = bandwidth;
                a.mcs = c[0].parse().unwrap();
                a.dcm = c[1] == "1";
                a.stbc = c[2] == "2";
                a.space_time_streams = if a.stbc { 2 } else { 1 };
                a.pre_fec_padding = c[4].parse().unwrap();
                a.ldpc_extra_segment = Some(c[5] == "1");
                let l = Layout::he_for_format(&a, c[3].parse().unwrap(), true).unwrap();
                let expected: Vec<_> = c[6].bytes().map(|b| b - b'0').collect();
                let bits: Vec<f32> = c[7]
                    .bytes()
                    .map(|b| if b == b'1' { 1. } else { -1. })
                    .collect();
                for scale in [1., f32::MAX, f32::MIN_POSITIVE] {
                    let metrics: Vec<_> = bits.iter().map(|b| b * scale).collect();
                    assert_eq!(l.recover(&metrics, 64).unwrap().0, expected);
                }
                let mut noisy = bits.clone();
                noisy[7] *= -0.25;
                assert_eq!(l.recover(&noisy, 64).unwrap().0, expected);
                assert!(l.recover(&bits[..bits.len() - 1], 64).is_err());
                let mut bad = bits.clone();
                bad.push(1.);
                assert!(l.recover(&bad, 64).is_err());
                for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
                    bad = bits.clone();
                    bad[0] = value;
                    assert!(l.recover(&bad, 64).is_err());
                }
            }
        }
    }
    #[test]
    fn radio_he_ldpc_independent_codeword_recovery() {
        let rows = include_str!("../../../tests/fixtures/iq/he-ldpc-rate-codewords.tsv");
        assert_eq!(rows.lines().skip(1).count(), 72);
        for row in rows.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let mut a = he_header();
            a.mcs = c[0].parse().unwrap();
            a.pre_fec_padding = c[2].parse().unwrap();
            a.ldpc_extra_segment = Some(c[3] == "1");
            let l = Layout::he(&a, c[1].parse().unwrap()).unwrap();
            let expected: Vec<_> = c[4].bytes().map(|b| b - b'0').collect();
            let bits: Vec<f32> = c[5]
                .bytes()
                .map(|b| if b == b'1' { 1. } else { -1. })
                .collect();
            for scale in [1., f32::MAX, f32::MIN_POSITIVE] {
                let metrics: Vec<_> = bits.iter().map(|b| b * scale).collect();
                assert_eq!(
                    l.recover(&metrics, 64).unwrap().0,
                    expected,
                    "{} {}",
                    c[0],
                    c[1]
                );
            }
            assert!(l.recover(&bits[..bits.len() - 1], 64).is_err());
            let mut noisy = bits.clone();
            noisy[7] *= -0.25;
            assert_eq!(l.recover(&noisy, 64).unwrap().0, expected);
            let mut bad = bits.clone();
            bad.push(1.);
            assert!(l.recover(&bad, 64).is_err());
            bad = bits.clone();
            bad[0] = f32::NAN;
            assert!(l.recover(&bad, 64).is_err());
        }
    }
    #[test]
    fn radio_vht_ldpc_independent_geometry() {
        let mut coverage = [0usize; 3];
        let rows = include_str!("../../../tests/fixtures/iq/vht-ldpc-rate-index.tsv");
        assert_eq!(rows.lines().skip(1).count(), 20412);
        for row in rows.lines().skip(1) {
            let c: Vec<usize> = row.split('\t').map(|v| v.parse().unwrap()).collect();
            let result = Layout::vht(c[3] as u16, c[1] as u8, c[2] == 2, c[9] != 0);
            if c[3] > 1512 {
                assert_eq!(result, Err(Error::VhtTiming));
                continue;
            }
            let layout = result.unwrap_or_else(|e| panic!("{row}: {e:?}"));
            assert_eq!(
                [
                    layout.symbols,
                    layout.codewords,
                    layout.block_bits,
                    layout.shortened_bits,
                    layout.punctured_bits,
                    layout.repeated_bits,
                    usize::from(layout.extra_symbol_group),
                    layout.payload_bits
                ],
                c[3..]
            );
            for (n, value) in [
                layout.punctured_bits,
                layout.repeated_bits,
                usize::from(layout.extra_symbol_group),
            ]
            .into_iter()
            .enumerate()
            {
                coverage[n] += usize::from(value > 0);
            }
            let mut totals = [0usize; 5];
            for index in 0..layout.codewords {
                let w = layout.word(index).unwrap();
                for (sum, value) in totals.iter_mut().zip([
                    w.information_bits,
                    w.shortened_bits,
                    w.punctured_bits,
                    w.repeated_bits,
                    w.transmitted_bits,
                ]) {
                    *sum += value;
                }
            }
            assert_eq!(
                totals,
                [
                    layout.payload_bits,
                    layout.shortened_bits,
                    layout.punctured_bits,
                    layout.repeated_bits,
                    layout.symbols * layout.coded_bits_per_symbol
                ]
            );
            // A wrong extra-symbol flag must not reuse the same geometry.
            assert_ne!(
                Layout::vht(c[3] as u16, c[1] as u8, c[2] == 2, c[9] == 0),
                Ok(layout)
            );
        }
        assert!(coverage.into_iter().all(|n| n > 0));
        for symbols in [0, 1513, u16::MAX] {
            assert_eq!(Layout::vht(symbols, 0, false, false), Err(Error::VhtTiming));
        }
        for mcs in 9..=255 {
            assert_eq!(
                Layout::vht(12, mcs, false, false),
                Err(Error::InvalidCodedBits)
            );
        }
        assert_eq!(Layout::vht(3, 0, true, false), Err(Error::VhtTiming));
        assert_eq!(Layout::vht(1, 0, false, true), Err(Error::VhtTiming));
        assert_eq!(Layout::vht(2, 0, true, true), Err(Error::VhtTiming));
    }
    #[test]
    fn radio_vht_ldpc_independent_recovery() {
        let rows = include_str!("../../../tests/fixtures/iq/vht-ldpc-rate-codewords.tsv");
        let geometry = include_str!("../../../tests/fixtures/iq/vht-ldpc-rate-index.tsv");
        assert_eq!(rows.lines().skip(1).count(), 54);
        for row in rows.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let g: Vec<usize> = geometry
                .lines()
                .skip(1)
                .find(|r| r.split('\t').take(3).eq(c[..3].iter().copied()))
                .unwrap()
                .split('\t')
                .map(|v| v.parse().unwrap())
                .collect();
            let layout = Layout::vht(g[3] as u16, g[1] as u8, g[2] == 2, g[9] != 0).unwrap();
            let expected: Vec<_> = c[3].bytes().map(|b| b - b'0').collect();
            let clean: Vec<_> = c[4]
                .bytes()
                .map(|b| if b == b'1' { 1. } else { -1. })
                .collect();
            for scale in [1., f32::MAX, f32::MIN_POSITIVE] {
                let metrics: Vec<_> = clean.iter().map(|m| m * scale).collect();
                assert_eq!(layout.recover(&metrics, 64).unwrap().0, expected);
            }
            let mut damaged = clean.clone();
            for index in [7, 53] {
                damaged[index] *= -0.25;
            }
            assert_eq!(layout.recover(&damaged, 64).unwrap().0, expected);
            assert!(layout.recover(&clean[..clean.len() - 1], 64).is_err());
        }
    }
    #[test]
    fn radio_ldpc_independent_rate_matched_recovery() {
        let rows: Vec<_> = include_str!("../../../tests/fixtures/iq/ldpc-rate-codewords.tsv")
            .lines()
            .skip(1)
            .collect();
        assert_eq!(rows.len(), 48);
        for row in rows {
            let c: Vec<_> = row.split('\t').collect();
            let mcs = c[1].parse::<usize>().unwrap();
            let (coded, rate) = [
                (52, Rate::Half),
                (104, Rate::Half),
                (104, Rate::ThreeQuarters),
                (208, Rate::Half),
                (208, Rate::ThreeQuarters),
                (312, Rate::TwoThirds),
                (312, Rate::ThreeQuarters),
                (312, Rate::FiveSixths),
            ][mcs];
            let layout = Layout::new(c[0].parse().unwrap(), coded, rate, c[2] == "2").unwrap();
            let expected: Vec<_> = c[3].bytes().map(|b| b - b'0').collect();
            let clean: Vec<_> = c[4]
                .bytes()
                .map(|b| if b == b'1' { 1. } else { -1. })
                .collect();
            let transmitted: Vec<_> = c[4].bytes().map(|b| b - b'0').collect();
            assert_eq!(layout.encode(&expected).unwrap(), transmitted);
            for scale in [1., f32::MAX, f32::MIN_POSITIVE] {
                let metrics: Vec<_> = clean.iter().map(|v| v * scale).collect();
                let (actual, iterations) = layout.recover(&metrics, 64).unwrap_or_else(|e| {
                    panic!(
                        "length={} mcs={mcs} group={} scale={scale}: {e:?}",
                        c[0], c[2]
                    )
                });
                assert_eq!(actual, expected);
                assert!(iterations <= layout.codewords * 64);
            }
            assert!(matches!(
                layout.recover(&clean[..clean.len() - 1], 64),
                Err(Error::Metrics(super::super::Error::MetricCount { .. }))
            ));
            let mut damaged = clean.clone();
            for index in [7, 53] {
                let bit = index % damaged.len();
                damaged[bit] *= -0.25;
            }
            assert_eq!(
                layout
                    .recover(&damaged, 64)
                    .unwrap_or_else(|e| panic!(
                        "damaged length={} mcs={mcs} group={}: {e:?}",
                        c[0], c[2]
                    ))
                    .0,
                expected
            );
            let mut invalid = clean.clone();
            invalid[3] = f32::NAN;
            assert_eq!(
                layout.recover(&invalid, 64),
                Err(Error::Metrics(super::super::Error::NonFiniteMetric {
                    index: 3
                }))
            );
            assert_eq!(
                layout.recover(&vec![0.; clean.len()], 64),
                Err(Error::Metrics(super::super::Error::UnusableMetrics))
            );
        }
    }
    #[test]
    fn radio_ldpc_independent_rate_matching_geometry() {
        let rows: Vec<_> = include_str!("../../../tests/fixtures/iq/ldpc-rate-index.tsv")
            .lines()
            .skip(1)
            .collect();
        assert_eq!(rows.len(), 208);
        let (mut extra, mut punctured, mut repeated) = (0, 0, 0);
        let mut blocks = std::collections::BTreeSet::new();
        for row in rows {
            let c: Vec<usize> = row.split('\t').map(|v| v.parse().unwrap()).collect();
            let rate = match c[5] {
                2 => Rate::Half,
                3 => Rate::TwoThirds,
                4 => Rate::ThreeQuarters,
                6 => Rate::FiveSixths,
                _ => panic!(),
            };
            let layout = Layout::new(c[0] as u16, c[3] as u16, rate, c[2] == 2).unwrap();
            assert_eq!(
                [
                    layout.symbols,
                    layout.codewords,
                    layout.block_bits,
                    layout.shortened_bits,
                    layout.punctured_bits,
                    layout.repeated_bits,
                    usize::from(layout.extra_symbol_group)
                ],
                c[6..],
                "{row}"
            );
            let mut totals = [0usize; 5];
            for index in 0..layout.codewords {
                let word = layout.word(index).unwrap();
                for (sum, value) in totals.iter_mut().zip([
                    word.information_bits,
                    word.shortened_bits,
                    word.punctured_bits,
                    word.repeated_bits,
                    word.transmitted_bits,
                ]) {
                    *sum += value;
                }
                assert!(word.information_bits > 0);
                assert!(word.punctured_bits < layout.block_bits * (c[5] - c[4]) / c[5]);
            }
            assert_eq!(
                totals,
                [
                    layout.payload_bits,
                    layout.shortened_bits,
                    layout.punctured_bits,
                    layout.repeated_bits,
                    layout.symbols * c[3]
                ]
            );
            assert!(layout.word(layout.codewords).is_none());
            assert!(!(layout.punctured_bits > 0 && layout.repeated_bits > 0));
            extra += usize::from(layout.extra_symbol_group);
            punctured += usize::from(layout.punctured_bits > 0);
            repeated += usize::from(layout.repeated_bits > 0);
            blocks.insert(layout.block_bits);
        }
        assert!(extra > 0 && punctured > 0 && repeated > 0);
        assert_eq!(blocks, std::collections::BTreeSet::from([648, 1296, 1944]));
    }
    #[test]
    fn radio_ldpc_rate_dimensions_and_extremes() {
        assert_eq!(
            Layout::new(0, 52, Rate::Half, false),
            Err(Error::EmptyPayload)
        );
        assert_eq!(
            Layout::new(1, 0, Rate::Half, false),
            Err(Error::InvalidCodedBits)
        );
        assert_eq!(
            Layout::new(1, 52, Rate::TwoThirds, false),
            Err(Error::InvalidCodedBits)
        );
        let layout = Layout::new(1, 52, Rate::Half, false).unwrap();
        assert_eq!(
            layout.encode(&[]),
            Err(Error::PayloadBitCount {
                required: 24,
                available: 0
            })
        );
        for rate in [
            Rate::Half,
            Rate::TwoThirds,
            Rate::ThreeQuarters,
            Rate::FiveSixths,
        ] {
            let (_, den) = rate.ratio();
            for coded in [den as u16, (65535 / den * den) as u16] {
                for bytes in [1, 65535] {
                    let layout = Layout::new(bytes, coded, rate, true).unwrap();
                    assert!(layout.symbols > 0 && layout.symbols % 2 == 0);
                    assert_eq!(
                        layout.codewords * layout.block_bits
                            - layout.shortened_bits
                            - layout.punctured_bits
                            + layout.repeated_bits,
                        layout.symbols * usize::from(coded)
                    );
                }
            }
        }
    }
}
