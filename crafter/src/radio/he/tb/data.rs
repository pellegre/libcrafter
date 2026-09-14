//! Trigger-configured isolated HE20 TB user DATA, IEEE802.11ax-2021 27.3.
//! Caller establishes exchange association and no overlapping spatial users.
//! Returned PSDUs are not MAC/FCS-qualified frames.
use crate::radio::{
    he::{capacity::Capacity, timing::Timing},
    sync::Acquisition,
    ComplexSample,
};
use crate::{Dot11TriggerCommonFields, Dot11TriggerUserFields};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) enum Error {
    Header,
    Context,
    Timing,
    Unsupported,
    Limit,
    Samples,
    Training,
    Metrics,
    Allocation,
    Bcc(crate::radio::he::bcc::Error),
    Ldpc(crate::radio::he::mu::ldpc::Error),
}

#[derive(Debug)]
pub(in crate::radio) struct Recovered {
    pub signal: crate::radio::he::tb::TbSignal,
    pub timing: Timing,
    pub psdu: Vec<u8>,
    pub failed_codewords: usize,
    pub first_failure: Option<crate::radio::ldpc::rate::Error>,
}

#[derive(Clone, Copy)]
pub(in crate::radio) struct Admission {
    pub signal: crate::radio::he::tb::TbSignal,
    pub timing: Timing,
    pub capacity: Capacity,
    /// Total retained samples from L-SIG through DATA, excluding packet extension.
    pub required_samples: usize,
    tones: crate::radio::he::ru::Tones,
    size: usize,
    guard: usize,
}

/// Admit from only L-SIG/RL-SIG/HE-SIG-A (320 samples), before retaining DATA.
/// Uses the same checked Trigger geometry as recovery; neither acquisition nor
/// header agreement proves that the caller selected the correct exchange.
pub(in crate::radio) fn admit(
    samples: &[ComplexSample],
    a: &Acquisition,
    common: &Dot11TriggerCommonFields,
    user: &Dot11TriggerUserFields,
    max_psdu: usize,
    max_samples: usize,
) -> Result<Admission, Error> {
    if a.signal_start.checked_sub(a.preamble_start) != Some(320) {
        return Err(Error::Timing);
    }
    let signal = crate::radio::he::iq::decode_tb_prefix(samples, a).ok_or(Error::Header)?;
    let length = crate::radio::he::iq::repeated_su_signal(samples, a).ok_or(Error::Header)?;
    if signal.bandwidth != common.bandwidth
        || signal.trigger_reserved != common.sig_a2_reserved
        || signal.spatial_reuse
            != std::array::from_fn(|i| ((common.spatial_reuse >> (4 * i)) & 15) as u8)
    {
        return Err(Error::Context);
    }
    let timing = Timing::for_tb(6_000_000, length, common).map_err(|_| Error::Timing)?;
    let needed = timing.data_end.checked_sub(320).ok_or(Error::Timing)?;
    a.preamble_start
        .checked_add(timing.packet_end as u64)
        .ok_or(Error::Timing)?;
    if needed > max_samples || timing.data_symbols > 400 {
        return Err(Error::Limit);
    }
    let (size, guard) = match common.gi_ltf {
        1 if !common.masked_ltf => (2, 32),
        2 if !common.masked_ltf => (4, 64),
        _ => return Err(Error::Unsupported),
    };
    let tones = crate::radio::he::ru::Tones::from_trigger(common.bandwidth, user.ru_allocation)
        .ok_or(Error::Unsupported)?;
    let c = Capacity::for_tb(common, user, timing.data_symbols).map_err(|_| Error::Unsupported)?;
    // RA count bits are not spatial-stream indices. Scheduled isolated users
    // start at STS zero; other allocations require spatial separation.
    if c.spatial_streams != 1
        || (matches!(user.aid12, 1..=2007) && user.spatial_allocation & 7 != 0)
    {
        return Err(Error::Unsupported);
    }
    let group = 1 + usize::from(common.stbc);
    if tones.count() + tones.pilots().len() == 242 && timing.ltf_symbols != group {
        return Err(Error::Unsupported);
    }
    if c.psdu_bytes > max_psdu {
        return Err(Error::Limit);
    }
    if user.ldpc {
        crate::radio::ldpc::rate::Layout::he_tb(common, user, timing.data_symbols as u16)
            .map_err(|_| Error::Unsupported)?;
    }
    Ok(Admission {
        signal,
        timing,
        capacity: c,
        required_samples: needed,
        tones,
        size,
        guard,
    })
}

/// Input begins at L-SIG. Common pre-HE acquisition provides coarse carrier
/// correction; this user's RU pilots track its residual phase independently.
/// No separation of overlapping spatial users is inferred.
pub(in crate::radio) fn recover(
    samples: &[ComplexSample],
    a: &Acquisition,
    common: &Dot11TriggerCommonFields,
    user: &Dot11TriggerUserFields,
    max_psdu: usize,
    max_samples: usize,
    partial: bool,
) -> Result<Recovered, Error> {
    let Admission {
        signal,
        timing,
        capacity: c,
        required_samples,
        tones,
        size,
        guard,
    } = admit(samples, a, common, user, max_psdu, max_samples)?;
    if samples.len() < required_samples {
        return Err(Error::Samples);
    }
    let group = 1 + usize::from(common.stbc);
    let training = timing.ltf_symbols * (64 * size + guard);
    let train = |cp| {
        if common.stbc {
            crate::radio::he::training::train_tb_stbc_ru_field(samples, a, tones, common, cp)
        } else {
            crate::radio::he::training::train_tb_ru_field(samples, a, tones, common, cp)
                .map(|h| [h, [ComplexSample::ZERO; 256]])
        }
        .ok_or(Error::Training)
    };
    // TB's 8us STF ends at PPDU sample800, or480 relative to L-SIG.
    let mut channel = train(480)?;
    // CS8's1/128 quantization step gives complex FFT-domain variance
    // 256 * 2 * (1/128)^2 /12. Guard-bin observations can raise this floor.
    let mut demod = crate::radio::he::ru::symbol::Demodulator::for_tb(
        tones,
        c.bits_per_tone,
        user.ldpc,
        user.dcm,
        256. / (6. * 128. * 128.),
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
    let period = common
        .doppler
        .then_some(if common.ltf_symbols_midamble < 4 {
            10
        } else {
            20
        });
    let mut pilot = 127;
    let retain = !common.stbc
        && user.ldpc
        && !user.dcm
        && c.bits_per_tone >= 8
        && tones.count() == 234
        && timing.midambles == 0;
    let mut observed = Vec::new();
    if retain {
        observed
            .try_reserve_exact(timing.data_symbols)
            .map_err(|_| Error::Allocation)?;
    }
    // Eq27-111: TB p[n+4], independent of the number of training symbols.
    for _ in 0..4 {
        crate::radio::data::feedback(&mut pilot);
    }
    for symbol in (0..timing.data_symbols).step_by(group) {
        let offset = timing.symbol_start(symbol).ok_or(Error::Timing)?;
        if period.is_some_and(|p| symbol > 0 && symbol % p == 0 && symbol / p <= timing.midambles) {
            channel = train(offset.checked_sub(training + 320).ok_or(Error::Timing)?)?;
            demod.reset();
        }
        let mut starts = [0; 2];
        let mut elapsed = [0; 2];
        let mut polarity = [0.; 2];
        for j in 0..group {
            starts[j] = timing
                .symbol_start(symbol + j)
                .and_then(|n| n.checked_add(guard))
                .and_then(|n| n.checked_sub(320))
                .ok_or(Error::Timing)?;
            elapsed[j] = a
                .signal_start
                .checked_add(starts[j] as u64)
                .and_then(|n| n.checked_sub(a.phase_origin))
                .ok_or(Error::Timing)?;
            polarity[j] = 1. - 2. * crate::radio::data::feedback(&mut pilot) as f32;
        }
        let wave = |j: usize| samples.get(starts[j]..starts[j].checked_add(256)?);
        if common.stbc {
            let blocks = demod
                .recover_stbc_pair(
                    [
                        wave(0).ok_or(Error::Samples)?,
                        wave(1).ok_or(Error::Samples)?,
                    ],
                    &channel,
                    a.frequency_rad,
                    elapsed,
                    symbol,
                    polarity,
                )
                .ok_or(Error::Metrics)?;
            for block in blocks {
                metrics.extend(block);
            }
        } else {
            let (block, observation) = demod
                .recover_observed(
                    wave(0).ok_or(Error::Samples)?,
                    &channel[0],
                    a.frequency_rad,
                    elapsed[0],
                    symbol,
                    polarity[0],
                )
                .ok_or(Error::Metrics)?;
            metrics.extend(block);
            if retain {
                observed.push(observation);
            }
        }
    }
    let (psdu, failed_codewords, first_failure) = if user.ldpc {
        let decode = |metrics: &[f32], partial| {
            crate::radio::he::mu::ldpc::recover_tb(
                common,
                user,
                timing.data_symbols,
                metrics,
                max_psdu,
                partial,
            )
        };
        let mut result = decode(&metrics, partial);
        if retain && result.as_ref().map_or(true, |r| r.failed_codewords != 0) {
            if let Some(clock) = crate::radio::he::ru::symbol::fit_pilot_clock(&observed) {
                let mut retry = Vec::new();
                retry
                    .try_reserve_exact(metrics.len())
                    .map_err(|_| Error::Allocation)?;
                let mut usable = true;
                for (observation, (phase, slope)) in observed.iter().zip(clock) {
                    if let Some(block) =
                        demod.recover_observation(observation, &channel[0], phase, slope)
                    {
                        retry.extend(block);
                    } else {
                        usable = false;
                        break;
                    }
                }
                if usable {
                    // Keep the initial partial estimate unless this retry fully
                    // converges and validates SERVICE. No known payload input.
                    if let Ok(candidate) = decode(&retry, false) {
                        result = Ok(candidate);
                    }
                }
            }
        }
        let result = result.map_err(Error::Ldpc)?;
        (result.psdu, result.failed_codewords, result.first_failure)
    } else {
        (
            crate::radio::he::bcc::recover_tb(
                common,
                user,
                timing.data_symbols,
                &metrics,
                max_psdu,
            )
            .map_err(Error::Bcc)?,
            0,
            None,
        )
    };
    Ok(Recovered {
        signal,
        timing,
        psdu,
        failed_codewords,
        first_failure,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radio_he_tb_simultaneous_ru_users() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/iq");
        let rows = std::fs::read_to_string(root.join("he-tb-multi-iq-index.tsv")).unwrap();
        assert_eq!(rows.lines().skip(1).count(), 276);
        let mut failures = Vec::new();
        let mut users = 0;
        for row in rows.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let number = |i: usize| c[i].parse::<usize>().unwrap();
            let ru = number(1);
            let nltf = number(9);
            let period = number(10);
            let common = Dot11TriggerCommonFields {
                ul_length: number(11) as u16,
                gi_ltf: if number(7) == 2 { 1 } else { 2 },
                ltf_symbols_midamble: ([1, 2, 4, 6, 8].iter().position(|&v| v == nltf).unwrap()
                    + if period == 20 { 4 } else { 0 }) as u8,
                stbc: number(6) != 0,
                doppler: period != 0,
                pre_fec_padding_raw: number(12) as u8,
                ldpc_extra_segment: number(13) != 0,
                ..Default::default()
            };
            let bytes = std::fs::read(root.join(format!("{}.cs8", c[0]))).unwrap();
            let samples: Vec<_> = bytes
                .chunks_exact(2)
                .map(|b| ComplexSample {
                    i: b[0] as i8 as f32 / 128.,
                    q: b[1] as i8 as f32 / 128.,
                })
                .collect();
            let mut sync = crate::radio::sync::Synchronizer::default();
            let Some(a) =
                samples
                    .iter()
                    .enumerate()
                    .find_map(|(n, &s)| match sync.push(s, n as u64) {
                        Some(crate::radio::sync::SyncEvent::Acquired(a)) => Some(a),
                        _ => None,
                    })
            else {
                failures.push(format!("{} acquisition", c[0]));
                continue;
            };
            let input = &samples[a.signal_start as usize..];
            let expected: Vec<_> = c[16].split(',').collect();
            assert_eq!(expected.len(), number(2));
            for (index, expected) in expected.into_iter().enumerate() {
                users += 1;
                let user = Dot11TriggerUserFields {
                    aid12: (index + 1) as u16,
                    ru_allocation: (2
                        * (index
                            + match ru {
                                26 => 0,
                                52 => 37,
                                106 => 53,
                                _ => unreachable!(),
                            })) as u8,
                    mcs: number(3) as u8,
                    ldpc: number(4) != 0,
                    dcm: number(5) != 0,
                    ..Default::default()
                };
                let expected: Vec<_> = expected
                    .as_bytes()
                    .chunks_exact(2)
                    .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
                    .collect();
                match recover(input, &a, &common, &user, 65535, input.len(), false) {
                    Ok(result) if result.psdu == expected && result.failed_codewords == 0 => {}
                    Ok(_) => failures.push(format!("{} user{index}: bytes", c[0])),
                    Err(e) => failures.push(format!("{} user{index}: {e:?}", c[0])),
                }
            }
        }
        assert_eq!(users, 1380);
        assert!(
            failures.is_empty(),
            "{}/{} failures: {:?}",
            failures.len(),
            users,
            &failures[..failures.len().min(30)]
        );
    }

    #[test]
    fn radio_he_tb_isolated_user_iq() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/iq");
        let rows = std::fs::read_to_string(root.join("he-tb-data-iq-index.tsv")).unwrap();
        assert_eq!(rows.lines().skip(1).count(), 282);
        for row in rows.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let number = |i: usize| c[i].parse::<usize>().unwrap();
            let ru = number(1);
            let index = number(2);
            let raw_ru = match ru {
                26 => index - 1,
                52 => 37 + index - 1,
                106 => 53 + index - 1,
                242 => 61,
                _ => unreachable!(),
            };
            let nltf = number(9);
            let period = number(10);
            let common = Dot11TriggerCommonFields {
                ul_length: number(11) as u16,
                gi_ltf: if number(7) == 2 { 1 } else { 2 },
                ltf_symbols_midamble: ([1, 2, 4, 6, 8].iter().position(|&v| v == nltf).unwrap()
                    + if period == 20 { 4 } else { 0 }) as u8,
                stbc: number(6) != 0,
                doppler: period != 0,
                pre_fec_padding_raw: number(12) as u8,
                ldpc_extra_segment: number(13) != 0,
                ..Default::default()
            };
            let user = Dot11TriggerUserFields {
                ru_allocation: (raw_ru * 2) as u8,
                mcs: number(3) as u8,
                ldpc: number(4) != 0,
                dcm: number(5) != 0,
                ..Default::default()
            };
            let bytes = std::fs::read(root.join(format!("{}.cs8", c[0]))).unwrap();
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
                .unwrap_or_else(|| panic!("{} acquisition", c[0]));
            let input = &samples[a.signal_start as usize..];
            let header = &input[..320];
            let admitted = admit(header, &a, &common, &user, 65535, input.len()).unwrap();
            assert_eq!(admitted.required_samples, input.len(), "{}", c[0]);
            assert_eq!(admitted.timing.data_symbols, number(14));
            assert_eq!(admitted.capacity.psdu_bytes, c[16].len() / 2);
            assert!(admit(
                header,
                &a,
                &common,
                &user,
                admitted.capacity.psdu_bytes,
                admitted.required_samples
            )
            .is_ok());
            assert!(matches!(
                admit(
                    header,
                    &a,
                    &common,
                    &user,
                    65535,
                    admitted.required_samples - 1
                ),
                Err(Error::Limit)
            ));
            if admitted.capacity.psdu_bytes > 0 {
                assert!(matches!(
                    admit(
                        header,
                        &a,
                        &common,
                        &user,
                        admitted.capacity.psdu_bytes - 1,
                        input.len()
                    ),
                    Err(Error::Limit)
                ));
            }
            for cut in [0, 79, 159, 239, 319] {
                assert!(matches!(
                    admit(&header[..cut], &a, &common, &user, 65535, input.len()),
                    Err(Error::Header)
                ));
            }
            let mut shifted = a.clone();
            let delta = u64::MAX - 800 - a.preamble_start;
            shifted.preamble_start += delta;
            shifted.signal_start += delta;
            shifted.phase_origin += delta;
            // L-SIG's legacy duration check may reject this before TB timing;
            // either layer must prevent an absolute sample-index overflow.
            assert!(admit(header, &shifted, &common, &user, 65535, input.len()).is_err());
            assert!(matches!(
                recover(header, &a, &common, &user, 65535, input.len(), false),
                Err(Error::Samples)
            ));
            let result = recover(input, &a, &common, &user, 65535, input.len(), false);
            if c[15] == "service" {
                assert!(
                    matches!(
                        result,
                        Err(Error::Bcc(crate::radio::he::bcc::Error::Service)
                            | Error::Ldpc(crate::radio::he::mu::ldpc::Error::Service))
                    ),
                    "{}: {result:?}",
                    c[0]
                );
                continue;
            }
            let result = result.unwrap_or_else(|e| panic!("{}: {e:?}", c[0]));
            let expected: Vec<_> = c[16]
                .as_bytes()
                .chunks_exact(2)
                .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
                .collect();
            assert_eq!(result.psdu, expected, "{}", c[0]);
            assert_eq!(result.timing.data_symbols, number(14));
            assert_eq!(result.signal.bss_color, 37);
            assert_eq!(result.failed_codewords, 0);
            assert_eq!(result.first_failure, None);
            if user.ldpc && ru == 242 {
                let partial = recover(input, &a, &common, &user, 65535, input.len(), true).unwrap();
                assert_eq!(partial.psdu, expected);
                assert_eq!(partial.failed_codewords, 0);
                assert_eq!(partial.first_failure, None);
            }
            let mut spatial = user;
            spatial.spatial_allocation = 1;
            assert!(matches!(
                recover(input, &a, &common, &spatial, 65535, input.len(), false),
                Err(Error::Unsupported)
            ));
            let mut masked = common;
            masked.masked_ltf = true;
            assert!(matches!(
                admit(header, &a, &masked, &user, 65535, input.len()),
                Err(Error::Unsupported)
            ));
            assert!(matches!(
                recover(input, &a, &masked, &user, 65535, input.len(), false),
                Err(Error::Unsupported)
            ));
            let mut nonfinite = input.to_vec();
            nonfinite[result.timing.data_start - 320 + number(8) + 8].i = f32::NAN;
            assert!(recover(&nonfinite, &a, &common, &user, 65535, input.len(), false).is_err());
            assert!(matches!(
                recover(
                    &input[..input.len() - 1],
                    &a,
                    &common,
                    &user,
                    65535,
                    input.len(),
                    false
                ),
                Err(Error::Samples)
            ));
            assert!(matches!(
                recover(input, &a, &common, &user, 65535, input.len() - 1, false),
                Err(Error::Limit)
            ));
            if !expected.is_empty() {
                assert!(matches!(
                    recover(input, &a, &common, &user, 0, input.len(), false),
                    Err(Error::Limit)
                ));
            }
            let mut bad = common;
            bad.sig_a2_reserved ^= 1;
            assert!(matches!(
                admit(header, &a, &bad, &user, 65535, input.len()),
                Err(Error::Context)
            ));
            assert!(matches!(
                recover(input, &a, &bad, &user, 65535, input.len(), false),
                Err(Error::Context)
            ));
        }
    }
}
