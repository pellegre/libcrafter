//! HE20 SU BCC/LDPC IQ, IEEE802.11ax-2021 27.3.12.5/8/9/10/13/14.
use super::{
    he_capacity::Capacity, he_timing::Timing, he_training::train_su, sync::Acquisition,
    ComplexSample, SignalInfo,
};

const PILOTS: [i32; 8] = [-116, -90, -48, -22, 22, 48, 90, 116];
const SIGNS: [f32; 8] = [1., 1., 1., -1., -1., 1., 1., 1.];

/// Restore constellation groups to LDPC order for one non-DCM 242-tone RU
/// stream. Input is ascending DATA-tone order (pilots excluded). IEEE802.11ax
/// Table27-36/Equation27-95: DTM=9, NSD=234, t(k)=9*(k mod26)+floor(k/26).
pub(super) fn ldpc_order(metrics: &[f32], bits_per_tone: usize) -> Option<Vec<f32>> {
    if !matches!(bits_per_tone, 1 | 2 | 4 | 6 | 8 | 10)
        || metrics.len() != 234 * bits_per_tone
        || metrics.iter().any(|v| !v.is_finite())
    {
        return None;
    }
    let mut ordered = Vec::new();
    ordered.try_reserve_exact(metrics.len()).ok()?;
    for k in 0..234 {
        let start = (9 * (k % 26) + k / 26) * bits_per_tone;
        ordered.extend_from_slice(&metrics[start..start + bits_per_tone]);
    }
    Some(ordered)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Admission {
    pub signal: super::he::SuSignal,
    pub timing: Timing,
    pub capacity: Capacity,
    pub info: SignalInfo,
    /// Total retained samples starting at L-SIG, not additional capacity.
    pub required_samples: usize,
}

/// Header-only, allocation-free admission for the currently implemented DATA
/// layout. Input needs only L-SIG/RL-SIG/HE-SIG-A (320 samples). Timing and
/// capacity follow IEEE802.11ax-2021 Equations27-119..122/140..143. This does
/// not validate training, DATA, MAC framing or FCS.
pub(super) fn admit(
    samples: &[ComplexSample],
    a: &Acquisition,
    max_psdu: usize,
    max_samples: usize,
) -> Option<Admission> {
    // This kernel uses the ordinary legacy preamble, not HE ER/TB layouts.
    if a.signal_start.checked_sub(a.preamble_start)? != 320 {
        return None;
    }
    let prefix = super::he_iq::decode_su_prefix(samples, a)?;
    let h = prefix.signal;
    if h.dcm || h.stbc || h.midamble_period.is_some() || h.space_time_streams != 1 {
        return None;
    }
    let timing = Timing::new(6_000_000, prefix.legacy_length, &h).ok()?;
    let capacity = Capacity::new(&h, timing.data_symbols).ok()?;
    if h.ldpc {
        super::ldpc_rate::Layout::he(&h, u16::try_from(timing.data_symbols).ok()?).ok()?;
    }
    let required_samples = timing.data_end.checked_sub(320)?;
    if capacity.psdu_bytes > max_psdu || required_samples > max_samples {
        return None;
    }
    let stride = 256 + usize::from(h.guard_ns) / 50;
    let info = SignalInfo {
        rate_bps: u32::try_from(
            u64::try_from(capacity.data_per_symbol)
                .ok()?
                .checked_mul(20_000_000)?
                / stride as u64,
        )
        .ok()?,
        coded_bits_per_symbol: capacity.coded_per_symbol,
        data_bits_per_symbol: capacity.data_per_symbol,
        psdu_bytes: capacity.psdu_bytes,
        data_symbols: timing.data_symbols,
        data_start: a.preamble_start.checked_add(timing.data_start as u64)?,
        end_sample_index: a.preamble_start.checked_add(timing.data_end as u64)?,
    };
    Some(Admission {
        signal: h,
        timing,
        capacity,
        info,
        required_samples,
    })
}

/// Input starts at L-SIG. Bytes are not yet MAC/FCS qualified.
pub(super) fn recover(
    samples: &[ComplexSample],
    a: &Acquisition,
    max_psdu: usize,
) -> Option<Vec<u8>> {
    let admitted = admit(samples, a, max_psdu, samples.len())?;
    let trained = train_su(samples, a)?;
    let h = admitted.signal;
    let timing = admitted.timing;
    let c = admitted.capacity;
    debug_assert_eq!(trained.prefix.signal, h);
    debug_assert_eq!(trained.data_start, admitted.info.data_start);
    let mut coded = Vec::new();
    coded
        .try_reserve_exact(timing.data_symbols.checked_mul(c.coded_per_symbol)?)
        .ok()?;
    let energy: f32 = match c.bits_per_tone {
        1 => 1.,
        2 => 2.,
        4 => 10.,
        6 => 42.,
        8 => 170.,
        10 => 682.,
        _ => return None,
    };
    let mut pilot_state = 127u8;
    for _ in 0..4 {
        super::data::feedback(&mut pilot_state);
    }
    let mut slope = 0.;
    for symbol in 0..timing.data_symbols {
        let absolute = a
            .preamble_start
            .checked_add(timing.symbol_start(symbol)? as u64)?
            .checked_add(trained.guard as u64)?;
        let start = usize::try_from(absolute.checked_sub(a.signal_start)?).ok()?;
        let wave = samples.get(start..start.checked_add(256)?)?;
        let mut time = [ComplexSample::ZERO; 256];
        for (n, v) in time.iter_mut().enumerate() {
            let elapsed = absolute
                .checked_add(n as u64)?
                .checked_sub(a.phase_origin)?;
            *v = wave[n].mul(ComplexSample::rotation(-a.frequency_rad * elapsed as f32));
        }
        let bins = super::he_fft::fft256(time);
        let polarity = 1. - 2. * super::data::feedback(&mut pilot_state) as f32;
        let pilots: [(f32, ComplexSample); 8] = std::array::from_fn(|j| {
            let k = PILOTS[j];
            let bin = k.rem_euclid(256) as usize;
            (
                k as f32,
                bins[bin]
                    .mul(trained.channel[bin].conj())
                    .scale(SIGNS[(symbol + j) % 8] * polarity)
                    .mul(ComplexSample::rotation(-slope * k as f32)),
            )
        });
        let common = pilots
            .iter()
            .fold(ComplexSample::ZERO, |sum, (_, v)| sum.add(*v));
        if !common.power().is_finite() || common.power() < 1e-12 {
            return None;
        }
        let reference = common.phase();
        let (mut w, mut x, mut xx, mut y, mut xy) = (0., 0., 0., 0., 0.);
        for (k, v) in pilots {
            let weight = v.power().sqrt();
            let residual = v.mul(ComplexSample::rotation(-reference)).phase();
            w += weight;
            x += weight * k;
            xx += weight * k * k;
            y += weight * residual;
            xy += weight * k * residual;
        }
        let determinant = w * xx - x * x;
        if !determinant.is_finite() || determinant < 1e-12 {
            return None;
        }
        let delta = (w * xy - x * y) / determinant;
        let intercept = reference + (y - delta * x) / w;
        slope += delta;
        let mut interleaved = Vec::with_capacity(c.coded_per_symbol);
        for tone in (-122i32..=-2)
            .chain(2..=122)
            .filter(|k| !PILOTS.contains(k))
        {
            let bin = tone.rem_euclid(256) as usize;
            let channel = trained.channel[bin];
            let power = channel.power();
            if !power.is_finite() {
                return None;
            }
            if power < 1e-12 {
                interleaved.extend(std::iter::repeat(0.).take(c.bits_per_tone));
                continue;
            }
            let v = bins[bin]
                .mul(channel.conj())
                .scale(1. / power)
                .mul(ComplexSample::rotation(-intercept - slope * tone as f32));
            if !v.power().is_finite() {
                return None;
            }
            super::data::demap(
                v.i,
                if c.bits_per_tone == 1 {
                    1
                } else {
                    c.bits_per_tone / 2
                },
                energy.sqrt(),
                power,
                &mut interleaved,
            );
            if c.bits_per_tone > 1 {
                super::data::demap(
                    v.q,
                    c.bits_per_tone / 2,
                    energy.sqrt(),
                    power,
                    &mut interleaved,
                );
            }
        }
        if h.ldpc {
            let ordered = ldpc_order(&interleaved, c.bits_per_tone)?;
            // 27.3.12.5.3: post-FEC padding follows the coded bits in the
            // last symbol (this path admits one stream without STBC only).
            let count = if symbol + 1 == timing.data_symbols {
                c.coded_last
            } else {
                c.coded_per_symbol
            };
            coded.extend_from_slice(ordered.get(..count)?);
        } else {
            let n = c.coded_per_symbol;
            let s = (c.bits_per_tone / 2).max(1);
            for k in 0..n {
                let i = 9 * c.bits_per_tone * (k % 26) + k / 26;
                let j = s * (i / s) + (i + n - 26 * i / n) % s;
                coded.push(*interleaved.get(j)?);
            }
        }
    }
    if h.ldpc {
        let layout =
            super::ldpc_rate::Layout::he(&h, u16::try_from(timing.data_symbols).ok()?).ok()?;
        let (bits, _) = layout.recover(&coded, 64).ok()?;
        super::data::descramble_psdu(bits, c.psdu_bytes).ok()
    } else {
        super::he_bcc::recover(&h, timing.data_symbols, &coded, max_psdu).ok()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn radio_he_ldpc_independent_tone_order() {
        let rows: Vec<_> = include_str!("../../tests/fixtures/iq/he-ldpc-tones.tsv")
            .lines()
            .skip(1)
            .map(|row| {
                let (source, tone) = row.split_once('\t').unwrap();
                (
                    source.parse::<usize>().unwrap(),
                    tone.parse::<usize>().unwrap(),
                )
            })
            .collect();
        assert_eq!(rows.len(), 234);
        for width in [1, 2, 4, 6, 8, 10] {
            let mut wire = vec![0.; 234 * width];
            for &(source, tone) in &rows {
                for bit in 0..width {
                    wire[tone * width + bit] = (source * width + bit) as f32 - 500.;
                }
            }
            let expected: Vec<_> = (0..234 * width).map(|i| i as f32 - 500.).collect();
            assert_eq!(super::ldpc_order(&wire, width), Some(expected));
            assert!(super::ldpc_order(&wire[..wire.len() - 1], width).is_none());
            wire.push(0.);
            assert!(super::ldpc_order(&wire, width).is_none());
            wire.pop();
            for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
                wire[0] = value;
                assert!(super::ldpc_order(&wire, width).is_none());
            }
            for value in [0., -0., f32::MAX, f32::MIN_POSITIVE] {
                wire.fill(value);
                assert!(super::ldpc_order(&wire, width)
                    .unwrap()
                    .iter()
                    .all(|actual| actual.to_bits() == value.to_bits()));
            }
        }
        for width in [0, 3, 5, usize::MAX] {
            assert!(super::ldpc_order(&[], width).is_none());
        }
    }

    use super::*;
    #[test]
    fn radio_he_ldpc_iq_complete_mac_waveforms() {
        let hex = |s: &str| -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        };
        let index = include_str!("../../tests/fixtures/iq/he-ldpc-iq-index.tsv");
        assert_eq!(index.lines().skip(1).count(), 240);
        for row in index.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let (samples, a) = fixture(c[0]);
            let input = &samples[a.signal_start as usize..];
            let expected = hex(c[4]);
            let admitted = admit(&input[..320], &a, expected.len(), input.len()).expect(c[0]);
            assert!(admitted.signal.ldpc);
            let end = admitted.required_samples;
            let psdu = recover(&input[..end], &a, expected.len()).expect(c[0]);
            assert_eq!(psdu, expected, "{}", c[0]);
            assert!(recover(&input[..end - 1], &a, expected.len()).is_none());
            assert!(admit(&input[..320], &a, expected.len() - 1, input.len()).is_none());
            assert!(admit(&input[..320], &a, expected.len(), end - 1).is_none());
            let mut frames = Vec::new();
            let mut bad_fcs = 0;
            for event in super::super::ampdu::Scan::he(&psdu, 16383) {
                match event {
                    super::super::ampdu::Event::Frame { bytes, .. } => frames.push(bytes.to_vec()),
                    super::super::ampdu::Event::Invalid {
                        error: super::super::ampdu::Error::BadFcs,
                        ..
                    } => bad_fcs += 1,
                    _ => {}
                }
            }
            assert_eq!(
                frames,
                c[5].split(',').map(hex).collect::<Vec<_>>(),
                "{}",
                c[0]
            );
            assert_eq!(bad_fcs, c[6].parse::<usize>().unwrap(), "{}", c[0]);
        }
        for row in include_str!("../../tests/fixtures/iq/he-ldpc-iq-invalid-index.tsv")
            .lines()
            .skip(1)
        {
            let name = row.split('\t').next().unwrap();
            let (samples, a) = fixture(name);
            assert!(
                recover(&samples[a.signal_start as usize..], &a, 65535).is_none(),
                "{name}"
            );
        }
    }

    fn fixture(name: &str) -> (Vec<ComplexSample>, Acquisition) {
        let bytes = std::fs::read(format!(
            "{}/tests/fixtures/iq/{name}.cs8",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let samples: Vec<_> = bytes
            .chunks_exact(2)
            .map(|v| ComplexSample {
                i: v[0] as i8 as f32 / 128.,
                q: v[1] as i8 as f32 / 128.,
            })
            .collect();
        let mut sync = super::super::sync::Synchronizer::default();
        let acquired = samples
            .iter()
            .enumerate()
            .find_map(|(i, v)| match sync.push(*v, i as u64) {
                Some(super::super::sync::SyncEvent::Acquired(a)) => Some(a),
                _ => None,
            })
            .expect("independent preamble acquisition");
        (samples, acquired)
    }

    #[test]
    fn radio_he_bcc_iq_complete_mac_aggregates() {
        fn hex(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }
        let rows = include_str!("../../tests/fixtures/iq/he-ampdu-iq-index.tsv");
        assert_eq!(rows.lines().skip(1).count(), 200);
        for row in rows.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let (samples, a) = fixture(c[0]);
            let input = &samples[a.signal_start as usize..];
            let expected_psdu = hex(c[4]);
            let admitted = admit(&input[..320], &a, expected_psdu.len(), input.len()).expect(c[0]);
            let psdu =
                recover(&input[..admitted.required_samples], &a, expected_psdu.len()).expect(c[0]);
            assert_eq!(psdu, expected_psdu, "{}", c[0]);
            let events: Vec<_> = super::super::ampdu::Scan::he(&psdu, 16383).collect();
            let actual: Vec<_> = events
                .iter()
                .filter_map(|e| match e {
                    super::super::ampdu::Event::Frame {
                        delimiter_offset,
                        control_bits,
                        bytes,
                    } => Some((delimiter_offset + 4, bytes.to_vec(), *control_bits)),
                    _ => None,
                })
                .collect();
            let expected: Vec<_> = c[5]
                .split(',')
                .zip(c[6].split(','))
                .zip(c[7].split(','))
                .map(|((offset, bytes), tag)| {
                    (
                        offset.parse::<usize>().unwrap(),
                        hex(bytes),
                        tag.parse::<u8>().unwrap(),
                    )
                })
                .collect();
            assert_eq!(actual, expected, "{}", c[0]);
            for (_, bytes, _) in &actual {
                // The raw 802.11 link decoder expects FCS out of band; the
                // recovered byte contract above deliberately retains it.
                let mac = &bytes[..bytes.len() - 4];
                let packet =
                    crate::Packet::decode_from_link(crate::LinkType::Ieee80211, mac).expect(c[0]);
                assert_eq!(packet.compile().unwrap().as_bytes(), mac, "{}", c[0]);
            }
            let bad_fcs = events
                .iter()
                .filter(|e| {
                    matches!(
                        e,
                        super::super::ampdu::Event::Invalid {
                            error: super::super::ampdu::Error::BadFcs,
                            ..
                        }
                    )
                })
                .count();
            assert_eq!(bad_fcs, c[8].parse::<usize>().unwrap(), "{}", c[0]);
            if c[8] == "0" {
                assert!(
                    !events
                        .iter()
                        .any(|e| matches!(e, super::super::ampdu::Event::Invalid { .. })),
                    "{}",
                    c[0]
                );
            }
        }
    }

    #[test]
    fn radio_he_bcc_header_only_admission() {
        for row in include_str!("../../tests/fixtures/iq/he-bcc-iq-index.tsv")
            .lines()
            .skip(1)
        {
            let c: Vec<_> = row.split('\t').collect();
            let (samples, a) = fixture(c[0]);
            let input = &samples[a.signal_start as usize..];
            let bytes = c[6].len() / 2;
            let start = c[10].parse::<u64>().unwrap();
            let end = c[11].parse::<u64>().unwrap();
            let required = usize::try_from(end - a.signal_start).unwrap();
            let admitted = admit(&input[..320], &a, bytes, required).expect(c[0]);
            assert_eq!(admitted.required_samples, required, "{}", c[0]);
            assert_eq!(admitted.info.psdu_bytes, bytes);
            assert_eq!(admitted.info.data_start, start);
            assert_eq!(admitted.info.end_sample_index, end);
            assert_eq!(admitted.info.data_symbols, c[5].parse::<usize>().unwrap());
            assert_eq!(admitted.signal.mcs, c[1].parse::<u8>().unwrap());
            assert_eq!(admit(input, &a, bytes, required), Some(admitted));
            assert!(admit(&input[..319], &a, bytes, required).is_none());
            assert!(admit(input, &a, bytes - 1, required).is_none());
            assert!(admit(input, &a, bytes, required - 1).is_none());
            assert!(admit(input, &a, usize::MAX, 0).is_none());
            let mut shifted = a.clone();
            let shift = 1u64 << 40;
            shifted.preamble_start += shift;
            shifted.signal_start += shift;
            shifted.phase_origin += shift;
            let high = admit(&input[..320], &shifted, bytes, required).unwrap();
            assert_eq!(high.info.data_start, start + shift);
            assert_eq!(high.info.end_sample_index, end + shift);
            assert_eq!(high.required_samples, required);
        }
        let (samples, a) = fixture("he-bcc-iq-mcs0-ltf4-gi3200-flat");
        let input = &samples[a.signal_start as usize..];
        let mut bad = a.clone();
        bad.preamble_start += 1;
        assert!(admit(input, &bad, usize::MAX, usize::MAX).is_none());
        let shift = u64::MAX - a.signal_start - 400;
        bad = a.clone();
        bad.preamble_start += shift;
        bad.signal_start += shift;
        bad.phase_origin += shift;
        assert!(admit(input, &bad, usize::MAX, usize::MAX).is_none());
        for row in include_str!("../../tests/fixtures/iq/he-bcc-iq-invalid-index.tsv")
            .lines()
            .skip(1)
        {
            let name = row.split('\t').next().unwrap();
            let (samples, a) = fixture(name);
            let input = &samples[a.signal_start as usize..];
            // SERVICE and DATA truncation are not header errors.
            let expected =
                name.ends_with("service") || name.ends_with("truncated") || name.ends_with("ldpc");
            assert_eq!(
                admit(&input[..320], &a, usize::MAX, usize::MAX).is_some(),
                expected,
                "{name}"
            );
        }
    }

    #[test]
    fn radio_he_bcc_iq_independent_complete_waveforms() {
        let mut count = 0;
        for row in include_str!("../../tests/fixtures/iq/he-bcc-iq-index.tsv")
            .lines()
            .skip(1)
        {
            let c: Vec<_> = row.split('\t').collect();
            let (samples, a) = fixture(c[0]);
            let expected: Vec<_> = (0..c[6].len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&c[6][i..i + 2], 16).unwrap())
                .collect();
            let input = &samples[a.signal_start as usize..];
            let decoded = recover(input, &a, 65535).unwrap_or_else(|| panic!("{}", c[0]));
            assert_eq!(decoded, expected, "{}", c[0]);
            let end = c[11].parse::<usize>().unwrap() - a.signal_start as usize;
            assert_eq!(
                recover(&input[..end], &a, expected.len()),
                Some(expected.clone()),
                "{} exactend",
                c[0]
            );
            assert!(
                recover(&input[..end - 1], &a, 65535).is_none(),
                "{} truncated",
                c[0]
            );
            assert!(recover(input, &a, expected.len() - 1).is_none());
            count += 1;
        }
        assert_eq!(count, 151);
    }

    #[test]
    fn radio_he_bcc_iq_invalid_layouts_and_bounds() {
        for row in include_str!("../../tests/fixtures/iq/he-bcc-iq-invalid-index.tsv")
            .lines()
            .skip(1)
        {
            let name = row.split('\t').next().unwrap();
            let (samples, a) = fixture(name);
            assert!(
                recover(&samples[a.signal_start as usize..], &a, 65535).is_none(),
                "{name}"
            );
        }
        let (samples, a) = fixture("he-bcc-iq-mcs0-ltf4-gi3200-flat");
        let input = &samples[a.signal_start as usize..];
        for end in [0, 79, 319, 400, 719] {
            assert!(recover(&input[..end], &a, 65535).is_none());
        }
        let mut bad = a.clone();
        bad.preamble_start = u64::MAX;
        assert!(recover(input, &bad, 65535).is_none());
        let mut nonfinite = input.to_vec();
        nonfinite[1000].i = f32::NAN;
        assert!(recover(&nonfinite, &a, 65535).is_none());
    }
}
