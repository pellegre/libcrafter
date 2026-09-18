//! OFDM DATA demodulation, pilot tracking, coding recovery, and descrambling.

use super::{
    signal::{SignalInfo, TRELLIS_SIGNS},
    sync::{fft64, Acquisition},
};
use crate::radio::{
    wifi::{
        ht::stbc,
        recovery::{self, DecodeAttempt, Profile},
    },
    ComplexSample, PhyDiagnostic,
};

fn feedback(state: &mut u8) -> u8 {
    let bit = ((*state >> 6) ^ (*state >> 3)) & 1;
    *state = ((*state << 1) | bit) & 127;
    bit
}
fn axis(label: usize, width: usize) -> f32 {
    let sign = 2. * (label & 1) as f32 - 1.;
    match width {
        1 => sign,
        2 => sign * (3. - 2. * ((label >> 1) & 1) as f32),
        _ => {
            sign * (4.
                - (2. * ((label >> 1) & 1) as f32 - 1.) * (3. - 2. * ((label >> 2) & 1) as f32))
        }
    }
}
// Max-log bit metrics, weighted by channel power; punctures later have zero weight.
fn demap(value: f32, width: usize, scale: f32, weight: f32, out: &mut Vec<f32>) {
    for bit in 0..width {
        let mut distance = [f32::INFINITY; 2];
        for label in 0..1 << width {
            let d = (value - axis(label, width) / scale).powi(2);
            let b = (label >> bit) & 1;
            distance[b] = distance[b].min(d);
        }
        out.push((distance[0] - distance[1]) * weight);
    }
}
// Signed distance to each nearest Gray-bit decision boundary. Unlike max-log
// squared distances, an outer QAM point does not dominate the sign-bit metric.
fn demap_boundaries(value: f32, width: usize, scale: f32, out: &mut Vec<f32>) {
    let x = value * scale;
    out.push(x);
    if width >= 2 {
        out.push((if width == 2 { 2. } else { 4. }) - x.abs());
    }
    if width == 3 {
        out.push(2. - (4. - x.abs()).abs());
    }
}

// Confidence in a nearest constellation coordinate decreases at decision
// boundaries. Ambiguous DATA tones contribute less to the phase estimate.
fn nearest_axis(value: f32, width: usize, scale: f32) -> (f32, f32) {
    let mut best = (f32::INFINITY, 0.);
    let mut second = f32::INFINITY;
    for label in 0..1 << width {
        let point = axis(label, width) / scale;
        let distance = (value - point).powi(2);
        if distance < best.0 {
            second = best.0;
            best = (distance, point);
        } else {
            second = second.min(distance);
        }
    }
    (best.1, (second - best.0) / (second + 1e-12))
}

fn refine_data_phase(
    bins: &[ComplexSample; 64],
    channel: &[ComplexSample; 64],
    edge: i32,
    nbpsc: usize,
    scale: f32,
    iterations: u8,
    mut phase: f32,
    mut slope: f32,
) -> (f32, f32) {
    for _ in 0..iterations {
        let (mut w, mut x, mut xx, mut y, mut xy) = (0., 0., 0., 0., 0.);
        for k in (-edge..=edge).filter(|k| ![-21, -7, 0, 7, 21].contains(k)) {
            let bin = k.rem_euclid(64) as usize;
            let power = channel[bin].power();
            if !power.is_finite() || power < 1e-12 {
                continue;
            }
            let value = bins[bin]
                .mul(channel[bin].conj())
                .scale(1. / power)
                .mul(ComplexSample::rotation(-phase - slope * k as f32));
            let width = if nbpsc == 1 { 1 } else { nbpsc / 2 };
            let (i, ci) = nearest_axis(value.i, width, scale);
            let (q, cq) = if nbpsc == 1 {
                (0., 1.)
            } else {
                nearest_axis(value.q, width, scale)
            };
            let point = ComplexSample { i, q };
            let error = value.mul(point.conj()).phase();
            let weight = power * point.power() * ci.min(cq);
            let carrier = k as f32;
            w += weight;
            x += weight * carrier;
            xx += weight * carrier * carrier;
            y += weight * error;
            xy += weight * carrier * error;
        }
        let determinant = w * xx - x * x;
        if determinant.is_finite() && determinant > 1e-12 {
            let delta = (w * xy - x * y) / determinant;
            phase += (y - delta * x) / w;
            slope += delta;
        }
    }
    (phase, slope)
}

pub(super) fn decode_data(
    samples: &[ComplexSample],
    a: &Acquisition,
    info: SignalInfo,
) -> DecodeAttempt {
    recovery::recover(false, |profile| {
        DecodeAttempt::plain(decode_data_profile(
            samples, a, info, None, false, None, profile,
        ))
    })
}

#[cfg(test)]
pub(super) fn decode_data_mode(
    samples: &[ComplexSample],
    a: &Acquisition,
    info: SignalInfo,
    ht_guard: Option<usize>,
) -> Result<(Vec<u8>, PhyDiagnostic), ()> {
    recovery::recover(false, |profile| {
        DecodeAttempt::plain(decode_data_profile(
            samples, a, info, ht_guard, false, None, profile,
        ))
    })
    .decoded
}
pub(in crate::radio) fn decode_data_profile(
    samples: &[ComplexSample],
    a: &Acquisition,
    info: SignalInfo,
    ht_guard: Option<usize>,
    greenfield: bool,
    stbc_second: Option<&[ComplexSample; 64]>,
    profile: Profile,
) -> Result<(Vec<u8>, PhyDiagnostic), ()> {
    let (coded, tracking) = demodulate_data_profile(
        samples,
        a,
        info,
        ht_guard,
        true,
        greenfield,
        stbc_second,
        profile,
    )?;
    Ok((recover_bcc(&coded, info)?, tracking))
}

// Q correction mixes each FFT bin with its conjugate mirror. Apply the
// same transform to the known-training observations and the DATA samples.
fn balanced_channel(a: &Acquisition, ht: bool) -> Acquisition {
    let sign = |k: usize| {
        let carrier = if k < 32 { k as i32 } else { k as i32 - 64 };
        match carrier {
            -26..=26 => super::sync::LONG[(carrier + 26) as usize] as f32,
            -28 | -27 if ht => 1.,
            27 | 28 if ht => -1.,
            _ => 0.,
        }
    };
    let [gain, leakage] = a.iq_balance;
    let alpha = ComplexSample {
        i: (1. + gain) / 2.,
        q: -gain * leakage / 2.,
    };
    let beta = ComplexSample {
        i: (1. - gain) / 2.,
        q: -gain * leakage / 2.,
    };
    let mut corrected = a.clone();
    corrected.channel = std::array::from_fn(|k| {
        let other = (64 - k) % 64;
        let value = a.channel[k].scale(sign(k));
        let mirror = a.channel[other].scale(sign(other)).conj();
        alpha.mul(value).add(beta.mul(mirror)).scale(sign(k))
    });
    corrected
}

pub(in crate::radio) fn demodulate_data_profile(
    samples: &[ComplexSample],
    a: &Acquisition,
    info: SignalInfo,
    ht_guard: Option<usize>,
    bcc_interleaving: bool,
    greenfield: bool,
    stbc_second: Option<&[ComplexSample; 64]>,
    profile: Profile,
) -> Result<(Vec<f32>, PhyDiagnostic), ()> {
    if profile.correct_iq && stbc_second.is_some() {
        return Err(());
    }
    let balanced;
    let apply_iq = profile.correct_iq && stbc_second.is_none();
    let a = if apply_iq {
        balanced = balanced_channel(a, ht_guard.is_some());
        &balanced
    } else {
        a
    };
    let guard = ht_guard.unwrap_or(16);
    let stride = 64 + guard;
    let carriers = if ht_guard.is_some() { 52 } else { 48 };
    let columns = if ht_guard.is_some() { 13 } else { 16 };
    let edge: i32 = if ht_guard.is_some() { 28 } else { 26 };
    if samples.len() != info.data_symbols * stride || ![8, 16].contains(&guard) {
        return Err(());
    }
    if stbc_second.is_some() && (ht_guard.is_none() || info.data_symbols % 2 != 0) {
        return Err(());
    }
    let nbpsc = info.coded_bits_per_symbol / carriers;
    let scale: f32 = match nbpsc {
        1 => 1.,
        2 => 2.,
        4 => 10.,
        _ => 42.,
    };
    let mut coded = Vec::with_capacity(info.data_symbols * info.coded_bits_per_symbol);
    let mut pilot_state = 127;
    for _ in 0..if greenfield {
        2
    } else if ht_guard.is_some() {
        3
    } else {
        1
    } {
        feedback(&mut pilot_state);
    }
    let mut phase_slope = 0.;
    let mut preceding = [ComplexSample::ZERO; 64];
    let (mut sum_x, mut sum_xx, mut sum_y, mut sum_xy) = (0f64, 0f64, 0f64, 0f64);
    let (mut residual_energy, mut residual_weight) = (0f64, 0f64);
    for symbol in 0..info.data_symbols {
        // Start the FFT inside the cyclic prefix instead of at its trailing
        // edge. Pilot slope measures accumulated clock drift in
        // samples; follow it without resampling or changing source positions.
        let advance = if profile.track_timing {
            guard as isize * profile.guard_quarters as isize / 4
                + (phase_slope * 64. / std::f32::consts::TAU).round() as isize
        } else {
            0
        };
        let nominal = symbol * stride + guard;
        let window_start =
            (nominal as isize - advance).clamp(0, (samples.len() - 64) as isize) as usize;
        let actual_advance = nominal as isize - window_start as isize;
        let time = std::array::from_fn(|n| {
            let sample = samples[window_start + n].mul(ComplexSample::rotation(
                -a.frequency_rad
                    * (info.data_start + (window_start + n) as u64 - a.phase_origin) as f32,
            ));
            if apply_iq {
                ComplexSample {
                    i: sample.i,
                    q: (sample.q - a.iq_balance[1] * sample.i) * a.iq_balance[0],
                }
            } else {
                sample
            }
        });
        let shifted = fft64(time);
        // Undo the known integer window shift before pilot fitting, so its
        // phase ramp cannot be mistaken for additional sampling-clock drift.
        let bins: [_; 64] = std::array::from_fn(|k| {
            shifted[k].mul(ComplexSample::rotation(
                std::f32::consts::TAU * actual_advance as f32 * k as f32 / 64.,
            ))
        });
        let polarity = 1. - 2. * feedback(&mut pilot_state) as f32;
        // Sampling-clock drift is a phase slope across subcarriers, not a
        // common carrier rotation. Remove the previous slope before measuring
        // residual pilot phases, then fit a weighted line each symbol.
        let pilots = std::array::from_fn::<_, 4, _>(|j| {
            let k: i32 = [-21, -7, 7, 21][j];
            let sign = [1., 1., 1., -1.][if ht_guard.is_some() {
                (symbol + j) % 4
            } else {
                j
            }];
            let bin = k.rem_euclid(64) as usize;
            let corrected = if let Some(second) = stbc_second {
                let prediction = a.channel[bin]
                    .scale([1., 1., -1., -1.][(symbol + j) % 4])
                    .add(second[bin].scale([1., -1., -1., 1.][(symbol + j) % 4]))
                    .scale(polarity);
                bins[bin].mul(prediction.conj())
            } else {
                bins[bin].mul(a.channel[bin].conj()).scale(sign * polarity)
            };
            let corrected = if profile.boundary_metrics && stbc_second.is_none() {
                corrected.scale(1. / a.channel[bin].power().max(1e-12))
            } else {
                corrected
            };
            let value = corrected.mul(ComplexSample::rotation(-phase_slope * k as f32));
            (k as f32, value)
        });
        let common = pilots
            .iter()
            .fold(ComplexSample::ZERO, |sum, (_, v)| sum.add(*v));
        if !common.power().is_finite() || common.power() < 1e-12 {
            return Err(());
        }
        let reference = common.phase();
        let (mut w, mut x, mut xx, mut y, mut xy) = (0., 0., 0., 0., 0.);
        for (k, value) in pilots {
            let weight = value.power().sqrt();
            let residual = value.mul(ComplexSample::rotation(-reference)).phase();
            w += weight;
            x += weight * k;
            xx += weight * k * k;
            y += weight * residual;
            xy += weight * k * residual;
        }
        let determinant = w * xx - x * x;
        if !determinant.is_finite() || determinant < 1e-12 {
            return Err(());
        }
        // Clock drift changes slowly between symbols. Filter the slope
        // innovation so noise on four pilots does not rotate every DATA tone.
        // Refit common phase for the applied slope and retain its residuals.
        let slope_delta = if profile.common_phase {
            0.
        } else {
            profile.pilot_alpha * (w * xy - x * y) / determinant
        };
        let intercept = if profile.common_phase {
            reference
        } else {
            reference + (y - slope_delta * x) / w
        };
        phase_slope += slope_delta;
        let time = (symbol * stride) as f64;
        sum_x += time;
        sum_xx += time * time;
        sum_y += phase_slope as f64;
        sum_xy += time * phase_slope as f64;
        for (k, value) in pilots {
            let weight = value.power().sqrt() as f64;
            let error = value
                .mul(ComplexSample::rotation(-intercept - slope_delta * k))
                .phase() as f64;
            residual_energy += weight * error * error;
            residual_weight += weight;
        }
        // DATA decisions refine only this symbol's correction. Pilot-derived
        // clock tracking remains independent, avoiding decision-error drift.
        let (intercept, data_slope) = if stbc_second.is_none() {
            refine_data_phase(
                &bins,
                &a.channel,
                edge,
                nbpsc,
                scale.sqrt(),
                profile.decision_iterations,
                intercept,
                phase_slope,
            )
        } else {
            (intercept, phase_slope)
        };
        if stbc_second.is_some() && symbol % 2 == 0 {
            for k in (-edge..=edge).filter(|k| ![-21, -7, 0, 7, 21].contains(k)) {
                preceding[k.rem_euclid(64) as usize] = bins[k.rem_euclid(64) as usize]
                    .mul(ComplexSample::rotation(-intercept - data_slope * k as f32));
            }
            continue;
        }
        let mut interleaved = Vec::with_capacity(info.coded_bits_per_symbol);
        let mut companion = stbc_second.map(|_| Vec::with_capacity(info.coded_bits_per_symbol));
        for k in (-edge..=edge).filter(|k| ![-21, -7, 0, 7, 21].contains(k)) {
            let rotation = ComplexSample::rotation(-intercept - data_slope * k as f32);
            let k = k.rem_euclid(64) as usize;
            let power = a.channel[k].power() + stbc_second.map_or(0., |second| second[k].power());
            if !power.is_finite() || power < 1e-12 {
                interleaved.extend(std::iter::repeat(0.).take(nbpsc));
                if let Some(other) = &mut companion {
                    other.extend(std::iter::repeat(0.).take(nbpsc));
                }
                continue;
            }
            let v = if let Some(second) = stbc_second {
                let raw = bins[k].mul(rotation);
                let pair = stbc::recover_pair([a.channel[k], second[k]], [preceding[k], raw])
                    .map_err(|_| ())?;
                let other = companion.as_mut().ok_or(())?;
                demap(
                    pair[1].i,
                    if nbpsc == 1 { 1 } else { nbpsc / 2 },
                    scale.sqrt(),
                    power,
                    other,
                );
                if nbpsc > 1 {
                    demap(pair[1].q, nbpsc / 2, scale.sqrt(), power, other);
                }
                pair[0]
            } else {
                // Preserve the legacy equalizer operation order.
                bins[k]
                    .mul(a.channel[k].conj())
                    .mul(rotation)
                    .scale(1. / power)
            };
            if !v.power().is_finite() {
                return Err(());
            }
            if profile.boundary_metrics && stbc_second.is_none() {
                let width = if nbpsc == 1 { 1 } else { nbpsc / 2 };
                demap_boundaries(v.i, width, scale.sqrt(), &mut interleaved);
                if nbpsc > 1 {
                    demap_boundaries(v.q, width, scale.sqrt(), &mut interleaved);
                }
                continue;
            }
            demap(
                v.i,
                if nbpsc == 1 { 1 } else { nbpsc / 2 },
                scale.sqrt(),
                power,
                &mut interleaved,
            );
            if nbpsc > 1 {
                demap(v.q, nbpsc / 2, scale.sqrt(), power, &mut interleaved);
            }
        }
        for block in std::iter::once(interleaved).chain(companion) {
            let n = info.coded_bits_per_symbol;
            if !bcc_interleaving {
                coded.extend(block);
                continue;
            }
            let s = (nbpsc / 2).max(1);
            for k in 0..n {
                let i = (n / columns) * (k % columns) + k / columns;
                let j = s * (i / s) + (i + n - columns * i / n) % s;
                coded.push(block[j]);
            }
        }
    }
    let symbols = info.data_symbols as f64;
    let sampling_clock_offset_ppm = (!profile.common_phase && info.data_symbols > 1).then(|| {
        let slope_per_sample =
            (symbols * sum_xy - sum_x * sum_y) / (symbols * sum_xx - sum_x * sum_x);
        (-slope_per_sample * 64. / std::f64::consts::TAU * 1e6) as f32
    });
    Ok((
        coded,
        PhyDiagnostic::OfdmTracking {
            sampling_clock_offset_ppm,
            pilot_residual_rms_rad: (residual_energy / residual_weight).sqrt() as f32,
            data_symbols: info.data_symbols,
        },
    ))
}

fn recover_bcc(coded: &[f32], info: SignalInfo) -> Result<Vec<u8>, ()> {
    let pattern: &[u8] = if info.data_bits_per_symbol * 2 == info.coded_bits_per_symbol {
        &[1, 1]
    } else if info.data_bits_per_symbol * 3 == info.coded_bits_per_symbol * 2 {
        &[1, 1, 1, 0]
    } else if info.data_bits_per_symbol * 4 == info.coded_bits_per_symbol * 3 {
        &[1, 1, 1, 0, 0, 1]
    } else if info.data_bits_per_symbol * 6 == info.coded_bits_per_symbol * 5 {
        &[1, 1, 1, 0, 0, 1, 1, 0, 0, 1]
    } else {
        return Err(());
    };
    // Six nonscrambled TAIL zeros terminate this encoder before PAD. Trace
    // only through that boundary; padding must not choose the PSDU's path.
    // IEEE 802.11-2020 17.3.5.3 and 19.3.11.1 (one BCC encoder).
    let count = 16 + 8 * info.psdu_bytes + 6;
    let mut metric = [f32::INFINITY; 64];
    metric[0] = 0.;
    let mut history = vec![[0u8; 64]; count];
    let mut cursor = 0;
    for t in 0..count {
        let row = &mut history[t];
        let mut pair = [0.; 2];
        for j in 0..2 {
            if pattern[(2 * t + j) % pattern.len()] == 1 {
                pair[j] = coded[cursor];
                cursor += 1;
            }
        }
        let mut next = [f32::INFINITY; 64];
        for (state, cost) in metric.iter().enumerate() {
            for bit in 0..2 {
                let reg = (state << 1) | bit;
                let [a, b] = TRELLIS_SIGNS[reg];
                let score = cost - pair[0] * a - pair[1] * b;
                let dest = reg & 63;
                if score < next[dest] {
                    next[dest] = score;
                    row[dest] = state as u8;
                }
            }
        }
        // Future trellis extensions cannot change any surviving path's prefix.
        // Once every state has an invalid SERVICE field, no final traceback can
        // produce a deliverable frame. Keep all possible states, not just the
        // currently cheapest path, to preserve the full decoder's decisions.
        if t == 47 && !possible_service_prefix(&history[..48]) {
            return Err(());
        }
        let minimum = next.iter().copied().fold(f32::INFINITY, f32::min);
        for cost in &mut next {
            *cost -= minimum;
        }
        metric = next;
    }
    let mut state = 0; // Known encoder state immediately after TAIL.
    let mut bits = vec![0; count];
    for t in (0..count).rev() {
        bits[t] = (state & 1) as u8;
        state = history[t][state] as usize;
    }
    descramble_psdu(bits, info.psdu_bytes)
}

pub(in crate::radio) fn descramble_psdu(
    mut bits: Vec<u8>,
    psdu_bytes: usize,
) -> Result<Vec<u8>, ()> {
    let tail = 16 + 8 * psdu_bytes;
    if bits.len() < tail {
        return Err(());
    }
    let seed = (1u8..128)
        .find(|seed| {
            let mut s = *seed;
            bits[..7].iter().all(|b| *b == feedback(&mut s))
        })
        .ok_or(())?;
    let mut state = seed;
    for bit in &mut bits {
        *bit ^= feedback(&mut state);
    }
    // Receive PLCP discards padding after the PSDU (802.11-2007 17.3.12).
    // Errors in those bits do not invalidate an otherwise FCS-valid PSDU.
    if bits[..16].iter().any(|b| *b != 0) {
        return Err(());
    }
    Ok(bits[16..tail]
        .chunks_exact(8)
        .map(|b| b.iter().enumerate().fold(0, |v, (i, b)| v | (b << i)))
        .collect())
}
fn possible_service_prefix(history: &[[u8; 64]]) -> bool {
    for final_state in 0..64 {
        let mut state = final_state;
        for row in history[16..].iter().rev() {
            state = row[state] as usize;
        }
        let mut service = [0u8; 16];
        for t in (0..16).rev() {
            service[t] = (state & 1) as u8;
            state = history[t][state] as usize;
        }
        if (1u8..128).any(|mut seed| service.iter().all(|b| *b == feedback(&mut seed))) {
            return true;
        }
    }
    false
}

pub(in crate::radio) fn valid_fcs(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    let mut crc = !0u32;
    for byte in &bytes[..bytes.len() - 4] {
        crc ^= *byte as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb88320u32 & (0u32.wrapping_sub(crc & 1)));
        }
    }
    (!crc).to_le_bytes() == bytes[bytes.len() - 4..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radio_bcc_uses_termination_despite_tail_erasures_and_noisy_padding() {
        // Coded bits and expected bytes come from the independent Python
        // oracle. Erasing TAIL removes its measured evidence; the specified
        // zero terminal state still disambiguates the end of the trellis.
        for (mbps, coded_bits, data_bits, pattern) in [
            (6, 48, 24, &[1, 1][..]),
            (9, 48, 36, &[1, 1, 1, 0, 0, 1][..]),
            (12, 96, 48, &[1, 1][..]),
            (18, 96, 72, &[1, 1, 1, 0, 0, 1][..]),
            (24, 192, 96, &[1, 1][..]),
            (36, 192, 144, &[1, 1, 1, 0, 0, 1][..]),
            (48, 288, 192, &[1, 1, 1, 0][..]),
            (54, 288, 216, &[1, 1, 1, 0, 0, 1][..]),
        ] {
            let stem = format!(
                "{}/tests/fixtures/iq/ofdm-tx-{mbps}",
                env!("CARGO_MANIFEST_DIR")
            );
            let fixture = std::fs::read_to_string(format!("{stem}.json")).unwrap();
            let bits: Vec<u8> = fixture
                .split_once("\"coded\":[")
                .unwrap()
                .1
                .split_once(']')
                .unwrap()
                .0
                .split(',')
                .map(|bit| bit.parse().unwrap())
                .collect();
            let expected = std::fs::read(format!("{stem}.psdu")).unwrap();
            let tail = 16 + 8 * expected.len();
            let info = SignalInfo {
                rate_bps: mbps * 1_000_000,
                coded_bits_per_symbol: coded_bits,
                data_bits_per_symbol: data_bits,
                psdu_bytes: expected.len(),
                data_symbols: bits.len() / 2 / data_bits,
                data_start: 0,
                end_sample_index: 0,
            };
            for pad_metric in [-100., 0., 100.] {
                let soft: Vec<_> = bits
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| pattern[index % pattern.len()] != 0)
                    .map(|(index, bit)| {
                        if index < 2 * tail {
                            if *bit == 1 {
                                16.
                            } else {
                                -16.
                            }
                        } else if index < 2 * (tail + 6) {
                            0.
                        } else {
                            pad_metric
                        }
                    })
                    .collect();
                assert_eq!(
                    recover_bcc(&soft, info),
                    Ok(expected.clone()),
                    "{mbps} Mbps pad={pad_metric}"
                );
            }
        }
    }
}
