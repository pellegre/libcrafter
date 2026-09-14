//! HE20 MU single-stream RUs, ax-2021 27.3.11.8/10 and 27.3.12.
//! Returned PSDUs are not MAC/FCS qualified. No spatial separation is inferred.
use super::sig_b::{iq::Fields, HeSigBUserEncoding};
use crate::radio::{
    he::{capacity::Capacity, timing::Timing},
    sync::Acquisition,
    ComplexSample,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) enum Error {
    Header,
    Timing,
    Layout,
    Unsupported,
    Unused,
    Limit,
    Samples,
    Training,
    Metrics,
    Allocation,
    Bcc(crate::radio::he::bcc::Error),
    Ldpc(crate::radio::he::mu::ldpc::Error),
}

#[derive(Debug)]
pub(in crate::radio) struct Payload {
    pub psdu: Vec<u8>,
    pub failed_codewords: usize,
    pub first_failure: Option<crate::radio::ldpc::rate::Error>,
}

#[derive(Debug)]
pub(in crate::radio) struct Recovered {
    pub fields: Fields,
    pub timing: Timing,
    /// Original SIG-B order, including unused users and failed headers.
    pub users: Vec<Result<Payload, Error>>,
}

/// Checked SIG-B to bounded DATA retention. No payload or MAC integrity is
/// established here; at least one RU must have a supported user layout.
pub(in crate::radio) fn admit(
    samples: &[ComplexSample],
    a: &Acquisition,
    fields: &Fields,
    max_samples: usize,
) -> Result<Timing, Error> {
    if a.signal_start.checked_sub(a.preamble_start) != Some(320) {
        return Err(Error::Layout);
    }
    let length = crate::radio::he::iq::repeated_er_signal(samples, a).ok_or(Error::Header)?;
    let timing = Timing::for_mu(6_000_000, length, &fields.signal, fields.symbols)
        .map_err(|_| Error::Timing)?;
    let needed = timing.data_end.checked_sub(320).ok_or(Error::Timing)?;
    a.preamble_start
        .checked_add(timing.data_end as u64)
        .ok_or(Error::Timing)?;
    if needed > max_samples || timing.data_symbols > 400 {
        return Err(Error::Limit);
    }
    let layout = fields.layout().map_err(|_| Error::Layout)?;
    // 27.3.12.12 forbids STBC throughout a PPDU containing any MU-MIMO RU.
    if fields.signal.stbc && layout.iter().any(|ru| ru.users.len() > 1) {
        return Err(Error::Unsupported);
    }
    let streams = if fields.signal.stbc { 2 } else { 1 };
    let supported = (layout.len() != 1 || timing.ltf_symbols == streams)
        && layout.iter().any(|ru| {
            ru.users.len() == 1
                && ru.users.clone().any(|i| {
                    fields.users[i].is_ok_and(|user| {
                        matches!(
                            user.encoding,
                            HeSigBUserEncoding::NonMu {
                                space_time_streams,
                                ..
                            } if usize::from(space_time_streams) == streams
                        ) && Capacity::for_mu(
                            &fields.signal,
                            &user,
                            (ru.tones.count() + ru.tones.pilots().len()) as u16,
                            timing.data_symbols,
                        )
                        .is_ok()
                    })
                })
        });
    if !supported {
        return Err(Error::Unsupported);
    }
    Ok(timing)
}

/// Input begins at L-SIG, not at the legacy preamble. Bounds cover the entire
/// DATA region before per-user allocation. Header recovery does not emit frames.
pub(in crate::radio) fn recover(
    samples: &[ComplexSample],
    a: &Acquisition,
    max_psdu: usize,
    max_samples: usize,
    partial: bool,
) -> Result<Recovered, Error> {
    if a.signal_start.checked_sub(a.preamble_start) != Some(320) {
        return Err(Error::Layout);
    }
    let fields = crate::radio::he::mu::sig_b::iq::recover(samples, a).map_err(|_| Error::Header)?;
    let timing = admit(samples, a, &fields, max_samples)?;
    let needed = timing.data_end.checked_sub(320).ok_or(Error::Timing)?;
    if needed > max_samples || timing.data_symbols > 400 {
        return Err(Error::Limit);
    }
    if samples.len() < needed {
        return Err(Error::Samples);
    }
    let layout = fields.layout().map_err(|_| Error::Layout)?;
    let mut users = Vec::with_capacity(fields.users.len());
    let pilots: Vec<_> = layout
        .iter()
        .filter(|ru| !ru.users.is_empty())
        .flat_map(|ru| ru.tones.pilots().iter().copied())
        .collect();
    let stbc_bins = if fields.signal.stbc {
        Some(stbc_observations(
            samples, a, &fields, &layout, &timing, &pilots,
        )?)
    } else {
        None
    };
    for ru in &layout {
        for index in ru.users.clone() {
            let result = (|| {
                let user = fields.users[index].map_err(|_| Error::Header)?;
                let (dcm, ldpc) = match user.encoding {
                    HeSigBUserEncoding::Unused { .. } => return Err(Error::Unused),
                    HeSigBUserEncoding::NonMu {
                        space_time_streams,
                        dcm,
                        ldpc,
                        ..
                    } if space_time_streams == if fields.signal.stbc { 2 } else { 1 }
                        && ru.users.len() == 1 =>
                    {
                        (dcm, ldpc)
                    }
                    _ => return Err(Error::Unsupported),
                };
                // 27.3.11.10: a single RU's LTF count is determined by its
                // streams; a multi-RU PPDU may signal extra training symbols.
                let group = if fields.signal.stbc { 2 } else { 1 };
                if layout.len() == 1 && timing.ltf_symbols != group {
                    return Err(Error::Layout);
                }
                let size = (ru.tones.count() + ru.tones.pilots().len()) as u16;
                let c = Capacity::for_mu(&fields.signal, &user, size, timing.data_symbols)
                    .map_err(|_| Error::Layout)?;
                if c.psdu_bytes > max_psdu {
                    return Err(Error::Limit);
                }
                if ldpc {
                    crate::radio::ldpc::rate::Layout::he_mu(
                        &fields.signal,
                        &user,
                        size,
                        timing.data_symbols as u16,
                    )
                    .map_err(|_| Error::Layout)?;
                }
                let guard = usize::from(fields.signal.guard_ns) / 50;
                let training =
                    timing.ltf_symbols * (64 * usize::from(fields.signal.ltf_size) + guard);
                let train = |cp| {
                    if fields.signal.stbc {
                        let phase = crate::radio::he::training::stbc_mu_phase(
                            samples,
                            a,
                            &fields.signal,
                            cp,
                            &pilots,
                        )
                        .ok_or(Error::Training)?;
                        crate::radio::he::training::train_stbc_ru_with_phase(
                            samples,
                            a,
                            ru.tones,
                            &fields.signal,
                            cp,
                            Some(&phase),
                        )
                        .ok_or(Error::Training)
                    } else {
                        crate::radio::he::training::train_ru_field(
                            samples,
                            a,
                            ru.tones,
                            fields.signal.ltf_size,
                            fields.signal.guard_ns,
                            cp,
                        )
                        .map(|h| [h, [ComplexSample::ZERO; 256]])
                        .ok_or(Error::Training)
                    }
                };
                let cp = usize::try_from(
                    fields
                        .end_sample
                        .checked_sub(a.signal_start)
                        .ok_or(Error::Timing)?,
                )
                .map_err(|_| Error::Timing)?
                .checked_add(80)
                .ok_or(Error::Timing)?;
                // Non-STBC uses the first LTF's +1 coefficient. STBC
                // separates both channels using all signaled LTFs.
                let mut channel = train(cp)?;
                let mut demod = crate::radio::he::ru::symbol::Demodulator::new(
                    ru.tones,
                    c.bits_per_tone,
                    ldpc,
                    dcm,
                )
                .ok_or(Error::Unsupported)?;
                let mut metrics = Vec::new();
                metrics
                    .try_reserve_exact(
                        timing
                            .data_symbols
                            .checked_mul(c.coded_per_symbol)
                            .ok_or(Error::Limit)?,
                    )
                    .map_err(|_| Error::Allocation)?;
                let mut pilot = 127;
                // Equation27-108: L-SIG + RL-SIG + two SIG-A + SIG-B.
                for _ in 0..4 + fields.symbols {
                    crate::radio::data::feedback(&mut pilot);
                }
                for symbol in (0..timing.data_symbols).step_by(group) {
                    let offset = timing.symbol_start(symbol).ok_or(Error::Timing)?;
                    if let Some(period) = fields.signal.midamble_period.map(usize::from) {
                        if symbol > 0 && symbol % period == 0 && symbol / period <= timing.midambles
                        {
                            channel =
                                train(offset.checked_sub(training + 320).ok_or(Error::Timing)?)?;
                            demod.reset();
                        }
                    }
                    let start = offset
                        .checked_add(guard)
                        .and_then(|n| n.checked_sub(320))
                        .ok_or(Error::Timing)?;
                    let elapsed = a
                        .signal_start
                        .checked_add(start as u64)
                        .and_then(|n| n.checked_sub(a.phase_origin))
                        .ok_or(Error::Timing)?;
                    if fields.signal.stbc {
                        let bins = stbc_bins.as_ref().ok_or(Error::Metrics)?;
                        let pair = [
                            *bins.get(symbol).ok_or(Error::Timing)?,
                            *bins.get(symbol + 1).ok_or(Error::Timing)?,
                        ];
                        let blocks = demod
                            .recover_stbc_bins(&pair, &channel)
                            .ok_or(Error::Metrics)?;
                        for block in blocks {
                            metrics.extend(block);
                        }
                    } else {
                        let polarity = 1. - 2. * crate::radio::data::feedback(&mut pilot) as f32;
                        let block = demod
                            .recover(
                                samples.get(start..start + 256).ok_or(Error::Samples)?,
                                &channel[0],
                                a.frequency_rad,
                                elapsed,
                                symbol,
                                polarity,
                            )
                            .ok_or(Error::Metrics)?;
                        metrics.extend(block);
                    }
                }
                if ldpc {
                    let decode = |metrics: &[f32]| {
                        crate::radio::he::mu::ldpc::recover(
                            &fields.signal,
                            &user,
                            size,
                            timing.data_symbols,
                            metrics,
                            max_psdu,
                            partial,
                        )
                    };
                    let mut result = decode(&metrics);
                    if timing.midambles == 0
                        && (result.is_err()
                            || result.as_ref().is_ok_and(|r| r.failed_codewords > 0))
                    {
                        if let Some(bins) = &stbc_bins {
                            let refined =
                                refine_stbc_channels(bins, &channel, ru.tones, c.bits_per_tone)
                                    .ok_or(Error::Metrics)?;
                            let mut retry = Vec::new();
                            retry
                                .try_reserve_exact(metrics.len())
                                .map_err(|_| Error::Allocation)?;
                            for pair in bins.chunks_exact(2) {
                                retry.extend(
                                    demod
                                        .recover_stbc_bins(&[pair[0], pair[1]], &refined)
                                        .ok_or(Error::Metrics)?
                                        .into_iter()
                                        .flatten(),
                                );
                            }
                            let candidate = decode(&retry);
                            if candidate.as_ref().is_ok_and(|r| {
                                result
                                    .as_ref()
                                    .map_or(true, |old| r.failed_codewords < old.failed_codewords)
                            }) {
                                result = candidate;
                            }
                        }
                    }
                    let r = result.map_err(Error::Ldpc)?;
                    Ok(Payload {
                        psdu: r.psdu,
                        failed_codewords: r.failed_codewords,
                        first_failure: r.first_failure,
                    })
                } else {
                    let psdu = crate::radio::he::bcc::recover_mu(
                        &fields.signal,
                        &user,
                        size,
                        timing.data_symbols,
                        &metrics,
                        max_psdu,
                    )
                    .map_err(Error::Bcc)?;
                    Ok(Payload {
                        psdu,
                        failed_codewords: 0,
                        first_failure: None,
                    })
                }
            })();
            users.push(result);
        }
    }
    Ok(Recovered {
        fields,
        timing,
        users,
    })
}

/// One decision-directed refinement, anchored by the training estimate.
/// Only constellation decisions within a conservative distance contribute;
/// neither these decisions nor the fitted channels establish MAC integrity.
fn refine_stbc_channels(
    bins: &[[ComplexSample; 256]],
    prior: &[[ComplexSample; 256]; 2],
    tones: crate::radio::he::ru::Tones,
    bits: usize,
) -> Option<[[ComplexSample; 256]; 2]> {
    if bins.len() < 2
        || bins.len() > 400
        || bins.len() % 2 != 0
        || !matches!(bits, 1 | 2 | 4 | 6 | 8 | 10)
    {
        return None;
    }
    let energy: f32 = match bits {
        1 => 1.,
        2 => 2.,
        4 => 10.,
        6 => 42.,
        8 => 170.,
        _ => 682.,
    };
    let scale = energy.sqrt();
    let maximum = ((1usize << (bits / 2)) - 1) as f32;
    let nearest = |v: ComplexSample| {
        if bits == 1 {
            ComplexSample {
                i: if v.i < 0. { -1. } else { 1. },
                q: 0.,
            }
        } else {
            let axis = |v: f32| {
                (2. * ((v * scale + maximum) / 2.).round().clamp(0., maximum) - maximum) / scale
            };
            ComplexSample {
                i: axis(v.i),
                q: axis(v.q),
            }
        }
    };
    let mut result = *prior;
    for k in tones.data() {
        let bin = k.rem_euclid(256) as usize;
        let power = prior[0][bin].power() + prior[1][bin].power();
        if !power.is_finite() {
            return None;
        }
        if power < 1e-12 {
            continue;
        }
        let mut numerator = [prior[0][bin].scale(2.), prior[1][bin].scale(2.)];
        let mut denominator = 2.;
        for pair in bins.chunks_exact(2) {
            let y = [pair[0][bin], pair[1][bin]];
            let x = crate::radio::stbc::recover_pair([prior[0][bin], prior[1][bin]], y).ok()?;
            let s = [nearest(x[0]), nearest(x[1])];
            let error = x[0].sub(s[0]).power().max(x[1].sub(s[1]).power()) * energy;
            let weight = (1. - 2. * error).max(0.);
            if weight == 0. {
                continue;
            }
            denominator += weight * (s[0].power() + s[1].power());
            numerator[0] = numerator[0].add(
                s[0].conj()
                    .mul(y[0])
                    .add(s[1].conj().mul(y[1]))
                    .scale(weight),
            );
            numerator[1] = numerator[1].add(s[0].mul(y[1]).sub(s[1].mul(y[0])).scale(weight));
        }
        let candidate = [
            numerator[0].scale(1. / denominator),
            numerator[1].scale(1. / denominator),
        ];
        let change =
            candidate[0].sub(prior[0][bin]).power() + candidate[1].sub(prior[1][bin]).power();
        if !change.is_finite() {
            return None;
        }
        if change <= 0.25 * power {
            result[0][bin] = candidate[0];
            result[1][bin] = candidate[1];
        }
    }
    Some(result)
}

/// Correct the common oscillator/clock once for the complete MU DATA field.
/// Pool per-RU pilots without pooling their physical channels. Cache at most
/// the already-admitted 400 FFT symbols, using fallible allocation.
fn stbc_observations(
    samples: &[ComplexSample],
    a: &Acquisition,
    fields: &Fields,
    layout: &[crate::radio::he::mu::sig_b::iq::RuLayout],
    timing: &Timing,
    pilots: &[i32],
) -> Result<Vec<[ComplexSample; 256]>, Error> {
    let guard = usize::from(fields.signal.guard_ns) / 50;
    let training = timing.ltf_symbols * (64 * usize::from(fields.signal.ltf_size) + guard);
    let train = |cp| {
        crate::radio::he::training::stbc_mu_pilot_channel(samples, a, &fields.signal, cp, pilots)
            .ok_or(Error::Training)
    };
    let cp = usize::try_from(
        fields
            .end_sample
            .checked_sub(a.signal_start)
            .ok_or(Error::Timing)?,
    )
    .map_err(|_| Error::Timing)?
    .checked_add(80)
    .ok_or(Error::Timing)?;
    let mut channel = train(cp)?;
    let mut slope = 0.;
    let mut pilot = 127;
    for _ in 0..4 + fields.symbols {
        crate::radio::data::feedback(&mut pilot);
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(timing.data_symbols)
        .map_err(|_| Error::Allocation)?;
    for symbol in 0..timing.data_symbols {
        let offset = timing.symbol_start(symbol).ok_or(Error::Timing)?;
        if let Some(period) = fields.signal.midamble_period.map(usize::from) {
            if symbol > 0 && symbol % period == 0 && symbol / period <= timing.midambles {
                channel = train(offset.checked_sub(training + 320).ok_or(Error::Timing)?)?;
                slope = 0.;
            }
        }
        let start = offset
            .checked_add(guard)
            .and_then(|n| n.checked_sub(320))
            .ok_or(Error::Timing)?;
        let elapsed = a
            .signal_start
            .checked_add(start as u64)
            .and_then(|n| n.checked_sub(a.phase_origin))
            .ok_or(Error::Timing)?;
        let polarity = 1. - 2. * crate::radio::data::feedback(&mut pilot) as f32;
        let pilot_map: Vec<_> = layout
            .iter()
            .filter(|ru| !ru.users.is_empty())
            .flat_map(|ru| {
                ru.tones
                    .pilots()
                    .iter()
                    .enumerate()
                    .map(move |(j, &k)| (k, ru.tones.pilot_sign(symbol, j) * polarity))
            })
            .collect();
        let (mut bins, phase, next_slope) = crate::radio::he::ru::symbol::observe_with_pilots(
            samples.get(start..start + 256).ok_or(Error::Samples)?,
            &channel,
            a.frequency_rad,
            elapsed,
            &pilot_map,
            slope,
        )
        .ok_or(Error::Metrics)?;
        slope = next_slope;
        for k in -122i32..=122 {
            let bin = k.rem_euclid(256) as usize;
            bins[bin] = bins[bin].mul(ComplexSample::rotation(-phase - slope * k as f32));
            if !bins[bin].power().is_finite() {
                return Err(Error::Metrics);
            }
        }
        output.push(bins);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radio_he_mu_stbc_refinement_bounds() {
        let tones = crate::radio::he::ru::Tones::ru(26, 1).unwrap();
        let mut prior = [[ComplexSample::ZERO; 256]; 2];
        let h = [
            ComplexSample { i: 1., q: 0.1 },
            ComplexSample { i: 0.4, q: -0.2 },
        ];
        let mut bins = vec![[ComplexSample::ZERO; 256]; 32];
        for k in tones.data() {
            let bin = k.rem_euclid(256) as usize;
            for stream in 0..2 {
                prior[stream][bin] = h[stream].scale(1.03);
            }
            for (n, pair) in bins.chunks_exact_mut(2).enumerate() {
                let x0 = if n % 2 == 0 { 1. } else { -1. };
                let x1 = if n % 3 == 0 { -1. } else { 1. };
                pair[0][bin] = h[0].scale(x0).sub(h[1].scale(x1));
                pair[1][bin] = h[0].scale(x1).add(h[1].scale(x0));
            }
        }
        let refined = refine_stbc_channels(&bins, &prior, tones, 1).unwrap();
        for k in tones.data() {
            let bin = k.rem_euclid(256) as usize;
            for stream in 0..2 {
                assert!(
                    refined[stream][bin].sub(h[stream]).power()
                        < prior[stream][bin].sub(h[stream]).power() / 4.
                );
            }
        }
        assert!(refine_stbc_channels(&[], &prior, tones, 1).is_none());
        assert!(refine_stbc_channels(&bins[..3], &prior, tones, 1).is_none());
        assert!(
            refine_stbc_channels(&vec![[ComplexSample::ZERO; 256]; 402], &prior, tones, 1)
                .is_none()
        );
        assert!(refine_stbc_channels(&bins, &prior, tones, 3).is_none());
        let bin = tones.data().next().unwrap().rem_euclid(256) as usize;
        bins[0][bin].i = f32::NAN;
        assert!(refine_stbc_channels(&bins, &prior, tones, 1).is_none());
    }

    #[test]
    fn radio_he_mu_mixed_high_rate_channel_recovery() {
        for name in [
            "he-mu-mixed-a0-s1-o18-p3",
            "he-mu-mixed-a0-s1-o20-p2",
            "he-mu-mixed-a0-s1-o20-p3",
        ] {
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
                .find_map(|(n, &s)| match sync.push(s, n as u64) {
                    Some(crate::radio::sync::SyncEvent::Acquired(a)) => Some(a),
                    _ => None,
                })
                .unwrap();
            let input = &samples[a.signal_start as usize..];
            let fields = crate::radio::he::mu::sig_b::iq::recover(input, &a).unwrap();
            let actual = recover(input, &a, 65535, input.len(), true).unwrap();
            for (i, user) in actual.users.iter().enumerate() {
                assert_eq!(
                    user.as_ref()
                        .unwrap_or_else(|e| panic!("{name} user{i}: {e:?}"))
                        .failed_codewords,
                    0
                );
            }
            let timing = admit(input, &a, &fields, input.len()).unwrap();
            let layout = fields.layout().unwrap();
            let pilots: Vec<_> = layout
                .iter()
                .flat_map(|ru| ru.tones.pilots().iter().copied())
                .collect();
            let observations =
                stbc_observations(input, &a, &fields, &layout, &timing, &pilots).unwrap();
            let cp = (fields.end_sample - a.signal_start) as usize + 80;
            let phase =
                crate::radio::he::training::stbc_mu_phase(input, &a, &fields.signal, cp, &pilots)
                    .unwrap();
            for (index, ru) in layout.iter().enumerate() {
                let user = fields.users[index].unwrap();
                if !matches!(
                    user.encoding,
                    HeSigBUserEncoding::NonMu {
                        mcs: 10 | 11,
                        ldpc: true,
                        ..
                    }
                ) {
                    continue;
                }
                let fitted = crate::radio::he::training::train_stbc_ru_with_phase(
                    input,
                    &a,
                    ru.tones,
                    &fields.signal,
                    cp,
                    Some(&phase),
                )
                .unwrap();
                let mut known = [[ComplexSample::ZERO; 256]; 2];
                let mut correlation = ComplexSample::ZERO;
                let mut energy = 0.;
                for k in ru.tones.active() {
                    let angle = std::f32::consts::TAU * k as f32 / 256.;
                    let external = ComplexSample { i: 1., q: 0. }.add(
                        ComplexSample { i: 0., q: 0.25 }.mul(ComplexSample::rotation(-3. * angle)),
                    );
                    let paths = [
                        ComplexSample { i: 0.85, q: 0.1 }.add(
                            ComplexSample { i: 0.2, q: -0.1 }
                                .mul(ComplexSample::rotation(-5. * angle)),
                        ),
                        ComplexSample { i: 0.45, q: -0.2 }
                            .add(
                                ComplexSample { i: 0., q: -0.15 }
                                    .mul(ComplexSample::rotation(-7. * angle)),
                            )
                            .mul(ComplexSample::rotation(8. * angle)),
                    ];
                    for stream in 0..2 {
                        let h = paths[stream].mul(external).mul(ComplexSample::rotation(
                            index as f32 * [0.31, -0.43][stream],
                        ));
                        let bin = k.rem_euclid(256) as usize;
                        known[stream][bin] = h;
                        if !ru.tones.pilots().contains(&k) {
                            correlation = correlation.add(fitted[stream][bin].mul(h.conj()));
                            energy += h.power();
                        }
                    }
                }
                let gain = correlation.scale(1. / energy);
                let mut error = 0.;
                for stream in 0..2 {
                    for k in ru.tones.active() {
                        let bin = k.rem_euclid(256) as usize;
                        known[stream][bin] = known[stream][bin].mul(gain);
                        error += known[stream][bin].sub(fitted[stream][bin]).power();
                    }
                }
                let c = Capacity::for_mu(&fields.signal, &user, 26, timing.data_symbols).unwrap();
                let demod = crate::radio::he::ru::symbol::Demodulator::new(
                    ru.tones,
                    c.bits_per_tone,
                    true,
                    false,
                )
                .unwrap();
                let mut metrics = Vec::new();
                for pair in observations.chunks_exact(2) {
                    metrics.extend(
                        demod
                            .recover_stbc_bins(&[pair[0], pair[1]], &known)
                            .unwrap()
                            .into_iter()
                            .flatten(),
                    );
                }
                let recovered = crate::radio::he::mu::ldpc::recover(
                    &fields.signal,
                    &user,
                    26,
                    timing.data_symbols,
                    &metrics,
                    65535,
                    true,
                )
                .unwrap();
                assert!(
                    (error / (energy * gain.power())).sqrt() < 0.06,
                    "{name} user{index}"
                );
                assert_eq!(recovered.failed_codewords, 0);
            }
        }
    }

    #[test]
    fn radio_he_mu_stbc_admission_and_bounds() {
        let bytes = include_bytes!(
            "../../../../tests/fixtures/iq/he-mu-stbc-a0-m4-l1-ltf4-g16-n2-p0-c0-flat.cs8"
        );
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
            .find_map(|(n, &s)| match sync.push(s, n as u64) {
                Some(crate::radio::sync::SyncEvent::Acquired(a)) => Some(a),
                _ => None,
            })
            .unwrap();
        let input = &samples[a.signal_start as usize..];
        let fields = crate::radio::he::mu::sig_b::iq::recover(input, &a).unwrap();
        let prefix_end = (fields.end_sample - a.signal_start) as usize;
        let timing = admit(&input[..prefix_end], &a, &fields, input.len()).unwrap();
        assert_eq!(timing.data_symbols % 2, 0);
        let strict = recover(input, &a, 65535, input.len(), false).unwrap();
        let partial = recover(input, &a, 65535, input.len(), true).unwrap();
        for (s, p) in strict.users.iter().zip(&partial.users) {
            assert_eq!(s.as_ref().unwrap().psdu, p.as_ref().unwrap().psdu);
            assert_eq!(p.as_ref().unwrap().failed_codewords, 0);
        }
        assert!(matches!(
            recover(&input[..input.len() - 1], &a, 65535, input.len(), false),
            Err(Error::Samples)
        ));
        assert!(matches!(
            recover(input, &a, 65535, input.len() - 1, false),
            Err(Error::Limit)
        ));
        let limited = recover(input, &a, 0, input.len(), false).unwrap();
        assert!(limited.users.iter().all(|u| matches!(u, Err(Error::Limit))));
        let mut erased = input.to_vec();
        erased[prefix_end + 80..timing.data_start - 320].fill(ComplexSample::ZERO);
        assert!(matches!(
            recover(&erased, &a, 65535, erased.len(), false),
            Err(Error::Training)
        ));
        for n in [0, 1, 3, 5, 7, 9] {
            let mut bad = fields.clone();
            bad.signal.ltf_symbols = n;
            assert!(admit(input, &a, &bad, input.len()).is_err());
        }
        let mut bad = fields.clone();
        bad.signal.stbc = false;
        assert!(matches!(
            admit(input, &a, &bad, input.len()),
            Err(Error::Unsupported)
        ));
        let mut bad = fields.clone();
        for user in bad.users.iter_mut().flatten() {
            if let HeSigBUserEncoding::NonMu { dcm, .. } = &mut user.encoding {
                *dcm = true;
            }
        }
        assert!(matches!(
            admit(input, &a, &bad, input.len()),
            Err(Error::Unsupported)
        ));
        // A spatially shared RU forbids STBC throughout the packet.
        let mut bad = fields;
        bad.signal.sig_b_compression = true;
        bad.signal.sig_b_symbols_or_users = 1;
        bad.common = None;
        bad.users.truncate(2);
        assert!(matches!(
            admit(input, &a, &bad, input.len()),
            Err(Error::Unsupported)
        ));
    }

    #[test]
    fn radio_he_mu_complete_psdu_waveforms() {
        let rows = include_str!("../../../../tests/fixtures/iq/he-mu-data-iq-index.tsv");
        assert_eq!(rows.lines().skip(1).count(), 252);
        for row in rows.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let bytes = std::fs::read(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/iq")
                    .join(format!("{}.cs8", c[0])),
            )
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
                .find_map(|(n, &s)| match sync.push(s, n as u64) {
                    Some(crate::radio::sync::SyncEvent::Acquired(a)) => Some(a),
                    _ => None,
                })
                .unwrap();
            let input = &samples[a.signal_start as usize..];
            let result = recover(input, &a, 65535, input.len(), false)
                .unwrap_or_else(|e| panic!("{}: {e:?}", c[0]));
            let expected: Vec<_> = c[11].split(',').collect();
            assert_eq!(result.users.len(), expected.len(), "{}", c[0]);
            assert_eq!(result.fields.users.len(), expected.len());
            assert_eq!(result.timing.data_symbols, c[10].parse().unwrap());
            if c[1] == "192" && c[3] == "1" {
                let partial = recover(input, &a, 65535, input.len(), true).unwrap();
                for (strict, partial) in result.users.iter().zip(&partial.users) {
                    let strict = strict.as_ref().unwrap();
                    let partial = partial.as_ref().unwrap();
                    assert_eq!(partial.psdu, strict.psdu);
                    assert_eq!(partial.failed_codewords, 0);
                    assert_eq!(partial.first_failure, None);
                }
            }
            for (i, (user, expected)) in result.users.iter().zip(expected).enumerate() {
                if c[9] == "user-crc" && i < 2 {
                    assert!(matches!(user, Err(Error::Header)), "{}: {user:?}", c[0]);
                    continue;
                }
                if c[9] == "service" && i == 0 {
                    assert!(
                        matches!(
                            user,
                            Err(Error::Bcc(crate::radio::he::bcc::Error::Service)
                                | Error::Ldpc(crate::radio::he::mu::ldpc::Error::Service))
                        ),
                        "{}: {user:?}",
                        c[0]
                    );
                    continue;
                }
                let payload = user
                    .as_ref()
                    .unwrap_or_else(|e| panic!("{} user{i}: {e:?}", c[0]));
                let bytes: Vec<_> = expected
                    .as_bytes()
                    .chunks_exact(2)
                    .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
                    .collect();
                assert_eq!(payload.psdu, bytes, "{} user{i}", c[0]);
                assert_eq!(payload.failed_codewords, 0);
                assert_eq!(payload.first_failure, None);
            }
            assert!(matches!(
                recover(&input[..input.len() - 1], &a, 65535, input.len(), false),
                Err(Error::Samples)
            ));
            assert!(matches!(
                recover(input, &a, 65535, input.len() - 1, false),
                Err(Error::Limit)
            ));
            if c[9] == "none" {
                let limited = recover(input, &a, 0, input.len(), false).unwrap();
                for (limited, original) in limited.users.iter().zip(&result.users) {
                    if original.as_ref().unwrap().psdu.is_empty() {
                        assert!(limited.as_ref().unwrap().psdu.is_empty());
                    } else {
                        assert!(matches!(limited, Err(Error::Limit)));
                    }
                }
            }
        }
    }
}
