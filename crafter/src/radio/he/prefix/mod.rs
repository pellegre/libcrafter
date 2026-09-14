//! HE20 SU, ER SU, MU and TB preamble prefixes; IEEE 802.11ax-2021 27.3.11/22.
//! No DATA admission or MAC frame publication occurs here.
use super::SuSignal;
use crate::radio::{signaling::corrected_bins, sync::Acquisition, ComplexSample};

pub(in crate::radio) struct Prefix {
    pub er: bool,
    pub signal: SuSignal,
    pub legacy_length: usize,
    pub end_sample: u64,
}

pub(in crate::radio) fn decode_prefix(
    samples: &[ComplexSample],
    a: &Acquisition,
) -> Option<Prefix> {
    decode_su_prefix(samples, a).or_else(|| decode_er_prefix(samples, a))
}

fn bins(samples: &[ComplexSample], start: u64, a: &Acquisition) -> Option<[ComplexSample; 64]> {
    corrected_bins(samples, start, a, 1.)
}

/// Input starts at L-SIG, after ordinary legacy-preamble acquisition.
pub(in crate::radio) fn repeated_su_signal(
    samples: &[ComplexSample],
    a: &Acquisition,
) -> Option<usize> {
    repeated_signal(samples, a, 1)
}

pub(in crate::radio) fn repeated_er_signal(
    samples: &[ComplexSample],
    a: &Acquisition,
) -> Option<usize> {
    repeated_signal(samples, a, 2)
}

fn repeated_signal(samples: &[ComplexSample], a: &Acquisition, remainder: usize) -> Option<usize> {
    let input = samples.get(..160)?;
    let first = crate::radio::signal::decode_signal(&input[..80], a, 4095).ok()?;
    if first.rate_bps != 6_000_000 || first.psdu_bytes % 3 != remainder {
        return None;
    }
    let mut repeated = a.clone();
    repeated.signal_start = a.signal_start.checked_add(80)?;
    let second = crate::radio::signal::decode_signal(&input[80..160], &repeated, 4095).ok()?;
    if second.rate_bps != first.rate_bps || second.psdu_bytes != first.psdu_bytes {
        return None;
    }
    Some(first.psdu_bytes)
}

/// ER is distinguished from MU by QBPSK DATA tones in the second symbol
/// after RL-SIG. Its pilots remain BPSK (27.3.11.7.4/27.3.22).
pub(in crate::radio) fn er_marker(samples: &[ComplexSample], a: &Acquisition) -> Option<()> {
    let observed = bins(samples.get(240..320)?, a.signal_start.checked_add(240)?, a)?;
    let (mut real, mut quadrature) = (0., 0.);
    for tone in (-26i32..=26).filter(|k| ![-21, -7, 0, 7, 21].contains(k)) {
        let k = tone.rem_euclid(64) as usize;
        let value = observed[k].mul(a.channel[k].conj());
        real += value.i * value.i;
        quadrature += value.q * value.q;
    }
    (real.is_finite() && quadrature.is_finite() && quadrature > 1e-12 && quadrature > 4. * real)
        .then_some(())
}

/// Input begins at L-SIG; four SIG-A symbols occupy 480 samples in total.
pub(in crate::radio) fn decode_er_prefix(
    samples: &[ComplexSample],
    a: &Acquisition,
) -> Option<Prefix> {
    let input = samples.get(..480)?;
    let legacy_length = repeated_er_signal(input, a)?;
    er_marker(input, a)?;
    let lsig = bins(&input[..80], a.signal_start, a)?;
    let rlsig = bins(&input[80..160], a.signal_start.checked_add(80)?, a)?;
    // L-LTF is boosted on every active tone; L-SIG/RL-SIG only on the
    // four added edge tones. SIG-A has neither boost (27-7/9/12/18).
    let mut channel = a.channel.map(|v| v.scale(std::f32::consts::FRAC_1_SQRT_2));
    for (tone, sign) in [(36, -1.), (37, -1.), (27, -1.), (28, 1.)] {
        channel[tone] = lsig[tone]
            .add(rlsig[tone])
            .scale(0.5 * sign * std::f32::consts::FRAC_1_SQRT_2);
    }
    let mut metrics = [0.; 208];
    for symbol in 0..4 {
        let offset = 160 + symbol * 80;
        // p2/p3=+1, p4/p5=-1. Rotation applies to DATA tones, never pilots.
        let observed = corrected_bins(
            &input[offset..offset + 80],
            a.signal_start.checked_add(offset as u64)?,
            a,
            if symbol < 2 { 1. } else { -1. },
        )?;
        for (j, tone) in (-28i32..=28)
            .filter(|k| ![-21, -7, 0, 7, 21].contains(k))
            .enumerate()
        {
            let k = tone.rem_euclid(64) as usize;
            let value = observed[k].mul(channel[k].conj());
            metrics[52 * symbol + j] = if symbol == 1 { value.q } else { value.i };
        }
    }
    Some(Prefix {
        er: true,
        signal: SuSignal::decode_er_repeated(&metrics).ok()?,
        legacy_length,
        end_sample: a.signal_start.checked_add(480)?,
    })
}

/// Decode HE SU signaling only after the repeated legacy header is checked.
pub(in crate::radio) fn decode_su_prefix(
    samples: &[ComplexSample],
    a: &Acquisition,
) -> Option<Prefix> {
    let input = samples.get(..320)?;
    let legacy_length = repeated_su_signal(input, a)?;
    let signal = SuSignal::decode_interleaved(&bpsk_metrics(input, a)?).ok()?;
    if signal.bandwidth != 0 {
        return None;
    }
    Some(Prefix {
        er: false,
        signal,
        legacy_length,
        end_sample: a.signal_start.checked_add(320)?,
    })
}

/// MU shares the modulo-two L-SIG with ER, but uses two BPSK SIG-A symbols.
/// Only 20 MHz signaling is admitted; this does not establish DATA integrity.
pub(in crate::radio) fn decode_mu_prefix(
    samples: &[ComplexSample],
    a: &Acquisition,
) -> Option<crate::radio::he::mu::MuSignal> {
    let input = samples.get(..320)?;
    a.signal_start.checked_add(320)?;
    repeated_er_signal(input, a)?;
    let signal =
        crate::radio::he::mu::MuSignal::decode_interleaved(&bpsk_metrics(input, a)?).ok()?;
    (signal.bandwidth == 0).then_some(signal)
}

/// TB shares the modulo-one L-SIG with SU. DATA needs a separate Trigger.
pub(in crate::radio) fn decode_tb_prefix(
    samples: &[ComplexSample],
    a: &Acquisition,
) -> Option<crate::radio::he::tb::TbSignal> {
    let input = samples.get(..320)?;
    a.signal_start.checked_add(320)?;
    repeated_su_signal(input, a)?;
    let signal =
        crate::radio::he::tb::TbSignal::decode_interleaved(&bpsk_metrics(input, a)?).ok()?;
    (signal.bandwidth == 0).then_some(signal)
}

fn bpsk_metrics(input: &[ComplexSample], a: &Acquisition) -> Option<[f32; 104]> {
    let input = input.get(..320)?;
    let lsig = bins(&input[..80], a.signal_start, a)?;
    let rlsig = bins(&input[80..160], a.signal_start.checked_add(80)?, a)?;
    // HE L-LTF already includes epsilon=sqrt(52/56), matching signaling
    // per-tone amplitude (27.3.11.4). Do not apply VHT's extra rescaling.
    let mut channel = a.channel;
    for (tone, sign) in [(36, -1.), (37, -1.), (27, -1.), (28, 1.)] {
        channel[tone] = lsig[tone].add(rlsig[tone]).scale(0.5 * sign);
    }
    let mut metrics = [0.; 104];
    for symbol in 0..2 {
        let offset = 160 + symbol * 80;
        let observed = bins(
            &input[offset..offset + 80],
            a.signal_start.checked_add(offset as u64)?,
            a,
        )?;
        let (mut desired, mut other) = (0., 0.);
        for (j, tone) in (-28i32..=28)
            .filter(|k| ![-21, -7, 0, 7, 21].contains(k))
            .enumerate()
        {
            let k = tone.rem_euclid(64) as usize;
            let value = observed[k].mul(channel[k].conj());
            metrics[52 * symbol + j] = value.i;
            desired += value.i * value.i;
            other += value.q * value.q;
        }
        if !desired.is_finite() || !other.is_finite() || desired < 1e-12 || desired <= 4. * other {
            return None;
        }
    }
    Some(metrics)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn radio_he_tb_prefix_independent_iq() {
        for row in include_str!("../../../../tests/fixtures/iq/he-tb-prefix-index.tsv")
            .lines()
            .skip(1)
        {
            let c: Vec<_> = row.split('\t').collect();
            let (samples, a) = fixture(c[0]);
            let input = &samples[a.signal_start as usize..];
            let bits: Vec<_> = c[1].bytes().map(|b| b - b'0').collect();
            assert_eq!(
                decode_tb_prefix(input, &a),
                crate::radio::he::tb::TbSignal::decode(&bits).ok(),
                "{}",
                c[0]
            );
            assert_eq!(a.preamble_start, 37);
            assert!(decode_su_prefix(input, &a).is_none());
            assert!(decode_mu_prefix(input, &a).is_none());
            for end in [0, 79, 159, 239, 319] {
                assert!(decode_tb_prefix(&input[..end], &a).is_none());
            }
        }
    }

    #[test]
    fn radio_he_tb_prefix_rejections() {
        for index in [
            include_str!("../../../../tests/fixtures/iq/he-tb-prefix-invalid-index.tsv"),
            include_str!("../../../../tests/fixtures/iq/he-su-prefix-index.tsv"),
            include_str!("../../../../tests/fixtures/iq/he-mu-prefix-index.tsv"),
            include_str!("../../../../tests/fixtures/iq/he-er-prefix-index.tsv"),
        ] {
            for row in index.lines().skip(1) {
                let name = row.split('\t').next().unwrap();
                let (samples, a) = fixture(name);
                assert!(
                    decode_tb_prefix(&samples[a.signal_start as usize..], &a).is_none(),
                    "{name}"
                );
            }
        }
        let (samples, a) = fixture("he-tb-prefix-v0-a0-clean");
        let input = &samples[a.signal_start as usize..];
        for index in [16, 96, 176, 256, 319] {
            for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
                let mut bad = input.to_vec();
                bad[index].i = value;
                assert!(decode_tb_prefix(&bad, &a).is_none());
            }
        }
        for offset in [40, 319] {
            let mut overflow = a.clone();
            overflow.signal_start = u64::MAX - offset;
            overflow.phase_origin = overflow.signal_start - (a.signal_start - a.phase_origin);
            assert!(decode_tb_prefix(input, &overflow).is_none());
        }
    }

    #[test]
    fn radio_he_mu_prefix_independent_iq() {
        for row in include_str!("../../../../tests/fixtures/iq/he-mu-prefix-index.tsv")
            .lines()
            .skip(1)
        {
            let c: Vec<_> = row.split('\t').collect();
            let (samples, a) = fixture(c[0]);
            let input = &samples[a.signal_start as usize..];
            let bits: Vec<_> = c[1].bytes().map(|b| b - b'0').collect();
            assert_eq!(
                decode_mu_prefix(input, &a),
                crate::radio::he::mu::MuSignal::decode(&bits).ok(),
                "{}",
                c[0]
            );
            assert_eq!(a.preamble_start, 37);
            assert!(decode_su_prefix(input, &a).is_none());
            assert!(er_marker(input, &a).is_none());
            for end in [0, 79, 159, 239, 319] {
                assert!(decode_mu_prefix(&input[..end], &a).is_none());
            }
        }
    }

    #[test]
    fn radio_he_mu_prefix_rejections() {
        for index in [
            include_str!("../../../../tests/fixtures/iq/he-mu-prefix-invalid-index.tsv"),
            include_str!("../../../../tests/fixtures/iq/he-su-prefix-index.tsv"),
            include_str!("../../../../tests/fixtures/iq/he-er-prefix-index.tsv"),
        ] {
            for row in index.lines().skip(1) {
                let name = row.split('\t').next().unwrap();
                let (samples, a) = fixture(name);
                assert!(
                    decode_mu_prefix(&samples[a.signal_start as usize..], &a).is_none(),
                    "{name}"
                );
            }
        }
        let (samples, a) = fixture("he-mu-prefix-mcs0-dcm0-gi0-comp0-clean");
        let input = &samples[a.signal_start as usize..];
        for index in [16, 96, 176, 256, 319] {
            for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
                let mut bad = input.to_vec();
                bad[index].i = value;
                assert!(decode_mu_prefix(&bad, &a).is_none());
            }
        }
        for offset in [40, 319] {
            let mut overflow = a.clone();
            overflow.signal_start = u64::MAX - offset;
            overflow.phase_origin = overflow.signal_start - (a.signal_start - a.phase_origin);
            assert!(decode_mu_prefix(input, &overflow).is_none());
        }
    }

    #[test]
    fn radio_he_er_prefix_independent_iq() {
        let rows = include_str!("../../../../tests/fixtures/iq/he-er-prefix-index.tsv");
        assert_eq!(rows.lines().skip(1).count(), 288);
        for row in rows.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let (samples, a) = fixture(c[0]);
            let input = &samples[a.signal_start as usize..];
            let prefix = decode_er_prefix(input, &a).expect(c[0]);
            let bits: Vec<_> = c[1].bytes().map(|b| b - b'0').collect();
            assert_eq!(
                prefix.signal,
                SuSignal::decode_er(&bits).unwrap(),
                "{}",
                c[0]
            );
            assert_eq!(prefix.legacy_length, 302);
            assert_eq!(prefix.end_sample, 837);
            assert!(decode_su_prefix(input, &a).is_none());
            assert_eq!(a.preamble_start, 37);
            for end in [0, 79, 159, 239, 319, 399, 479] {
                assert!(decode_er_prefix(&input[..end], &a).is_none());
            }
        }
    }

    #[test]
    fn radio_he_er_prefix_rejections() {
        for row in include_str!("../../../../tests/fixtures/iq/he-er-prefix-invalid-index.tsv")
            .lines()
            .skip(1)
        {
            let name = row.split('\t').next().unwrap();
            let (samples, a) = fixture(name);
            assert!(
                decode_er_prefix(&samples[a.signal_start as usize..], &a).is_none(),
                "{name}"
            );
        }
        let (samples, a) = fixture("he-er-prefix-bw0-mcs0-gi0-plain-bcc-clean");
        let input = &samples[a.signal_start as usize..];
        for index in [16, 96, 176, 256, 336, 479] {
            for invalid in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
                let mut bad = input.to_vec();
                bad[index].i = invalid;
                assert!(decode_er_prefix(&bad, &a).is_none());
            }
        }
        let mut overflow = a.clone();
        overflow.signal_start = u64::MAX - 40;
        assert!(decode_er_prefix(input, &overflow).is_none());
    }

    fn fixture(name: &str) -> (Vec<ComplexSample>, Acquisition) {
        let bytes = std::fs::read(format!(
            "{}/tests/fixtures/iq/{name}.cs8",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let samples: Vec<_> = bytes
            .chunks_exact(2)
            .map(|b| ComplexSample {
                i: b[0] as i8 as f32 / 128.,
                q: b[1] as i8 as f32 / 128.,
            })
            .collect();
        let mut sync = crate::radio::sync::Synchronizer::default();
        let a = samples
            .iter()
            .enumerate()
            .find_map(|(n, s)| match sync.push(*s, n as u64) {
                Some(crate::radio::sync::SyncEvent::Acquired(a)) => Some(a),
                _ => None,
            })
            .expect("independent legacy acquisition");
        (samples, a)
    }

    #[test]
    fn radio_he_su_prefix_independent_iq() {
        let rows: Vec<_> = include_str!("../../../../tests/fixtures/iq/he-su-prefix-index.tsv")
            .lines()
            .skip(1)
            .collect();
        assert_eq!(rows.len(), 96);
        for row in rows {
            let c: Vec<_> = row.split('\t').collect();
            let (samples, a) = fixture(c[0]);
            let prefix = decode_su_prefix(&samples[a.signal_start as usize..], &a)
                .unwrap_or_else(|| panic!("{}", c[0]));
            let bits: Vec<_> = c[1].bytes().map(|b| b - b'0').collect();
            assert_eq!(prefix.signal, SuSignal::decode(&bits).unwrap(), "{}", c[0]);
            assert_eq!(prefix.legacy_length, c[2].parse::<usize>().unwrap());
            assert_eq!(prefix.end_sample, c[3].parse::<u64>().unwrap());
            assert_eq!(a.preamble_start, 37);
        }
    }

    #[test]
    fn radio_he_su_prefix_rejections() {
        for row in include_str!("../../../../tests/fixtures/iq/he-su-prefix-invalid-index.tsv")
            .lines()
            .skip(1)
        {
            let name = row.split('\t').next().unwrap();
            let (samples, a) = fixture(name);
            assert!(
                decode_su_prefix(&samples[a.signal_start as usize..], &a).is_none(),
                "{name}"
            );
        }
        let (samples, a) = fixture("he-su-prefix-0-gi0-clean");
        let input = &samples[a.signal_start as usize..];
        for end in 0..320 {
            assert!(decode_su_prefix(&input[..end], &a).is_none());
        }
        for value in [ComplexSample::ZERO, ComplexSample { i: f32::NAN, q: 0. }] {
            assert!(decode_su_prefix(&vec![value; 320], &a).is_none());
        }
        let mut overflow = a.clone();
        overflow.signal_start = u64::MAX - 40;
        assert!(decode_su_prefix(input, &overflow).is_none());
    }
}
