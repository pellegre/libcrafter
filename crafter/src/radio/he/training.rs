//! HE20 SU/ER training and isolated MU RU estimation; IEEE802.11ax-2021 27.3.11.10.
use super::{
    iq::{decode_prefix, Prefix},
    ru::Tones,
};
use crate::radio::{sync::Acquisition, ComplexSample};

// Equation27-43, exactly245 signed tones in ascending order -122..122.
// Equations27-41/42 use the same signed-tone order, with sparse training.
const LTF1: &[u8;245] = b"00-000+000+000-000+000-000+000+000+000+000-000-000+000+000+000-000-000-000+000-000-000+000+000-000-000+000-000-000+000-0000000-000+000+000+000+000+000+000-000-000-000-000-000+000-000-000-000+000-000-000+000-000-000+000-000+000-000-000-000-000-00";
const LTF2: &[u8;245] = b"-0-0-0+0+0-0+0-0-0-0-0+0-0+0-0-0+0+0-0+0+0+0+0+0-0+0-0+0-0-0+0+0-0+0-0-0-0-0+0-0+0+0+0-0-0+0-0-0-0-0-0+0-0-0-0+0+0+0-0-0+000+0-0+0+0-0+0+0-0+0+0-0-0+0-0+0+0+0+0-0+0-0+0+0-0-0+0-0-0-0-0-0+0-0+0+0-0-0+0+0-0+0-0-0-0-0+0-0+0+0+0-0-0+0-0-0-0-0-0+0-0+";
const LTF4: &[u8;245] = b"--+-+-+++-+++--+-----++----++-+-++++-+--++-++++--+---++++-++----+--++-+----+-+------++-----+--+++-+++-+-+-----+++---+-+++000-+-+-++-+++--+--+-+-+++-+++--+-----++------+-+----+-++--+----++-+++++++-++----+--++-+----+-+--++++--+++++-++---+---+-+-++";

pub(in crate::radio) struct Trained {
    pub prefix: Prefix,
    pub channel: [ComplexSample; 256],
    pub second: Option<[ComplexSample; 256]>,
    pub data_start: u64,
    pub guard: usize,
}

impl Trained {
    /// ER LTFs, including midambles, have sqrt2 amplitude relative to DATA
    /// (27.3.10, 27-58). Restore the DATA channel scale after each estimate.
    pub fn normalize_er(&mut self) {
        if self.prefix.er {
            for value in &mut self.channel {
                *value = value.scale(std::f32::consts::FRAC_1_SQRT_2);
            }
            if let Some(second) = &mut self.second {
                for value in second {
                    *value = value.scale(std::f32::consts::FRAC_1_SQRT_2);
                }
            }
        }
    }
}

/// Fit a finite impulse response to sparse measurements. This receiver model
/// includes four precursor samples and delays within the cyclic prefix; it
/// averages quantization noise instead of amplifying it at interpolated tones.
/// The diagonal ridge stabilizes missing DC/edge measurements. This is not a
/// claim that channels outside the guard interval can be reconstructed.
/// For small RUs the system may be underdetermined; the ridge selects an
/// estimate without claiming unique recovery of the physical delay taps.
fn delay_fit(
    channel: &mut [ComplexSample; 256],
    tones: &[i32],
    guard: usize,
    allocation: Tones,
) -> Option<()> {
    let count = guard.checked_add(4)?;
    if count > 68 || tones.is_empty() {
        return None;
    }
    let mut normal = vec![vec![ComplexSample::ZERO; count + 1]; count];
    for &tone in tones {
        let basis: Vec<_> = (0..count)
            .map(|n| {
                ComplexSample::rotation(
                    -std::f32::consts::TAU * tone as f32 * (n as f32 - 4.) / 256.,
                )
            })
            .collect();
        for i in 0..count {
            let conjugate = basis[i].conj();
            for (j, &v) in basis.iter().enumerate() {
                normal[i][j] = normal[i][j].add(conjugate.mul(v));
            }
            normal[i][count] =
                normal[i][count].add(conjugate.mul(channel[tone.rem_euclid(256) as usize]));
        }
    }
    for (i, row) in normal.iter_mut().enumerate() {
        row[i].i += 0.001 * tones.len() as f32;
    }
    // Partial-pivot complex Gaussian elimination of the regularized normal equations.
    for col in 0..count {
        let pivot = (col..count)
            .max_by(|&a, &b| normal[a][col].power().total_cmp(&normal[b][col].power()))?;
        normal.swap(col, pivot);
        let divisor = normal[col][col];
        if !divisor.power().is_finite() || divisor.power() < 1e-12 {
            return None;
        }
        let inverse = divisor.conj().scale(1. / divisor.power());
        let (before, rest) = normal.split_at_mut(col);
        let (pivot_row, after) = rest.split_first_mut()?;
        for value in &mut pivot_row[col..] {
            *value = value.mul(inverse);
        }
        for row in before.iter_mut().chain(after) {
            let factor = row[col];
            for (value, &pivot_value) in row[col..].iter_mut().zip(&pivot_row[col..]) {
                *value = value.sub(factor.mul(pivot_value));
            }
        }
    }
    for tone in allocation.active() {
        let mut value = ComplexSample::ZERO;
        for (n, row) in normal.iter().enumerate() {
            value = value.add(row[count].mul(ComplexSample::rotation(
                -std::f32::consts::TAU * tone as f32 * (n as f32 - 4.) / 256.,
            )));
        }
        if !value.power().is_finite() {
            return None;
        }
        channel[tone.rem_euclid(256) as usize] = value;
    }
    Some(())
}

/// Input begins at L-SIG. Reject unsupported training layouts explicitly.
pub(in crate::radio) fn train_su(samples: &[ComplexSample], a: &Acquisition) -> Option<Trained> {
    let prefix = decode_prefix(samples, a)?;
    let fields = prefix.signal;
    // Prefix then80 samples of HE-STF; ER repeats SIG-A (160 extra samples).
    let cp = 400 + 160 * usize::from(prefix.er);
    let (channel, second) = if fields.stbc {
        let [first, second] = if prefix.er {
            train_stbc_for_format(samples, a, &fields, cp, true)?
        } else {
            train_stbc_field(samples, a, &fields, cp)?
        };
        (first, Some(second))
    } else {
        (
            if prefix.er {
                train_for_format(samples, a, &fields, cp, true)?
            } else {
                train_field(samples, a, &fields, cp)?
            },
            None,
        )
    };
    let guard = usize::from(fields.guard_ns) / 50;
    let mut trained = Trained {
        prefix,
        channel,
        second,
        data_start: a.signal_start.checked_add(
            (cp + (1 + usize::from(fields.stbc)) * (guard + 64 * usize::from(fields.ltf_size)))
                as u64,
        )?,
        guard,
    };
    trained.normalize_er();
    Some(trained)
}

/// A preamble LTF or identical midamble field. `cp` is relative to L-SIG;
/// absolute phase uses the original acquisition, not a restarted CFO clock.
pub(in crate::radio) fn train_field(
    samples: &[ComplexSample],
    a: &Acquisition,
    fields: &super::SuSignal,
    cp: usize,
) -> Option<[ComplexSample; 256]> {
    train_for_format(samples, a, fields, cp, false)
}

pub(in crate::radio) fn train_for_format(
    samples: &[ComplexSample],
    a: &Acquisition,
    fields: &super::SuSignal,
    cp: usize,
    er: bool,
) -> Option<[ComplexSample; 256]> {
    let allocation = Tones::new(er, fields.bandwidth)?;
    if fields.space_time_streams != 1 || fields.stbc {
        return None;
    }
    let (mut channel, trained, guard) = observe_for_format(samples, a, fields, cp, er)?;
    let energy: f32 = channel.iter().map(|v| v.power()).sum();
    if !energy.is_finite() || energy < 1e-9 {
        return None;
    }
    delay_fit(&mut channel, &trained, guard, allocation)?;
    Some(channel)
}

/// SU uses P on DATA tones and R on pilots: the second LTF observes
/// -h1+h2 on DATA, but -(h1+h2) on pilots (27-55..57). Never treat
/// those pilot observations as separate-channel measurements.
pub(in crate::radio) fn train_stbc_field(
    samples: &[ComplexSample],
    a: &Acquisition,
    fields: &super::SuSignal,
    cp: usize,
) -> Option<[[ComplexSample; 256]; 2]> {
    train_stbc_for_format(samples, a, fields, cp, false)
}

pub(in crate::radio) fn train_stbc_for_format(
    samples: &[ComplexSample],
    a: &Acquisition,
    fields: &super::SuSignal,
    cp: usize,
    er: bool,
) -> Option<[[ComplexSample; 256]; 2]> {
    let allocation = Tones::new(er, fields.bandwidth)?;
    if !fields.stbc || fields.dcm || fields.space_time_streams != 2 {
        return None;
    }
    let (first, tones, guard) = observe_for_format(samples, a, fields, cp, er)?;
    let next = cp.checked_add(guard + 64 * usize::from(fields.ltf_size))?;
    let (second, _, _) = observe_for_format(samples, a, fields, next, er)?;
    let pilots = allocation.pilots();
    let mut phase = ComplexSample::ZERO;
    for &tone in tones.iter().filter(|k| pilots.contains(k)) {
        let bin = tone.rem_euclid(256) as usize;
        phase = phase.sub(second[bin].mul(first[bin].conj()));
    }
    if !phase.power().is_finite() {
        return None;
    }
    // A pilot null cannot measure residual phase: retain the acquisition CFO.
    let correction = ComplexSample::rotation(if phase.power() > 1e-18 {
        -phase.phase()
    } else {
        0.
    });
    let data: Vec<_> = tones.into_iter().filter(|k| !pilots.contains(k)).collect();
    let mut channels = [[ComplexSample::ZERO; 256]; 2];
    for &tone in &data {
        let bin = tone.rem_euclid(256) as usize;
        let separated =
            crate::radio::stbc::separate_training([first[bin], second[bin].mul(correction)])
                .ok()?;
        channels[0][bin] = separated[0];
        channels[1][bin] = separated[1];
    }
    let energy: f32 = channels.iter().flatten().map(|v| v.power()).sum();
    if !energy.is_finite() || energy < 1e-9 {
        return None;
    }
    // Remove each known STS cyclic shift for delay fitting, then restore it.
    // Keeping a common physical delay interval avoids fitting extra noise
    // degrees of freedom just to accommodate STS2's -400 ns shift.
    for (stream, channel) in channels.iter_mut().enumerate() {
        for &tone in &data {
            let bin = tone.rem_euclid(256) as usize;
            channel[bin] = channel[bin].mul(ComplexSample::rotation(
                -std::f32::consts::TAU * tone as f32 * (8 * stream) as f32 / 256.,
            ));
        }
        delay_fit(channel, &data, guard, allocation)?;
        for tone in allocation.active() {
            let bin = tone.rem_euclid(256) as usize;
            channel[bin] = channel[bin].mul(ComplexSample::rotation(
                std::f32::consts::TAU * tone as f32 * (8 * stream) as f32 / 256.,
            ));
        }
    }
    Some(channels)
}

#[cfg(test)]
fn observe_field(
    samples: &[ComplexSample],
    a: &Acquisition,
    fields: &super::SuSignal,
    cp: usize,
) -> Option<([ComplexSample; 256], Vec<i32>, usize)> {
    observe_for_format(samples, a, fields, cp, false)
}

fn observe_for_format(
    samples: &[ComplexSample],
    a: &Acquisition,
    fields: &super::SuSignal,
    cp: usize,
    er: bool,
) -> Option<([ComplexSample; 256], Vec<i32>, usize)> {
    let allocation = Tones::new(er, fields.bandwidth)?;
    observe_ru(samples, a, allocation, fields.ltf_size, fields.guard_ns, cp)
}

/// Isolated one-stream RU LTF, with spatial admission and symbol position
/// established by the caller. No STBC/MU-MIMO separation or DATA admission.
/// Expects the common LTF sequence polarity; any orthogonal training-matrix
/// coefficient must be accounted for by the caller.
pub(in crate::radio) fn train_ru_field(
    samples: &[ComplexSample],
    a: &Acquisition,
    allocation: Tones,
    ltf_size: u8,
    guard_ns: u16,
    cp: usize,
) -> Option<[ComplexSample; 256]> {
    if !matches!((ltf_size, guard_ns), (2, 800 | 1600) | (4, 800 | 3200)) {
        return None;
    }
    let (mut channel, tones, guard) = observe_ru(samples, a, allocation, ltf_size, guard_ns, cp)?;
    let energy: f32 = channel.iter().map(|v| v.power()).sum();
    if !energy.is_finite() || energy < 1e-9 {
        return None;
    }
    delay_fit(&mut channel, &tones, guard, allocation)?;
    Some(channel)
}

/// Separate the two STBC channels of one MU RU using all signaled LTFs.
/// The caller establishes STBC/STS admission and the RU's LTF position.
/// DATA uses P, pilots use R (27-55..57); P6 is complex, not P4 repeated.
pub(in crate::radio) fn train_stbc_ru_field(
    samples: &[ComplexSample],
    a: &Acquisition,
    allocation: Tones,
    fields: &crate::radio::he::mu::MuSignal,
    cp: usize,
) -> Option<[[ComplexSample; 256]; 2]> {
    train_stbc_ru_with_phase(samples, a, allocation, fields, cp, None)
}

pub(in crate::radio) struct StbcPhase([(f32, f32); 8]);

/// All RUs share the transmitter's oscillator and symbol clock, but need not
/// share a propagation channel or spatial mapping. Correlate each LTF pilot
/// with itself in LTF1 before pooling; R's coefficient is common to every STS
/// and RU (27-56). Fit a frequency slope as well as common phase so sampling
/// clock drift is not mistaken for different per-RU oscillator phases.
pub(in crate::radio) fn stbc_mu_phase(
    samples: &[ComplexSample],
    a: &Acquisition,
    fields: &crate::radio::he::mu::MuSignal,
    cp: usize,
    pilots: &[i32],
) -> Option<StbcPhase> {
    if !fields.stbc || !matches!(fields.ltf_symbols, 2 | 4 | 6 | 8) || pilots.is_empty() {
        return None;
    }
    let allocation = Tones::ru(242, 1)?;
    let (first, _, guard) =
        observe_ru(samples, a, allocation, fields.ltf_size, fields.guard_ns, cp)?;
    let stride = guard + 64 * usize::from(fields.ltf_size);
    let mut corrections = [(0., 0.); 8];
    for j in 1..usize::from(fields.ltf_symbols) {
        let (observed, _, _) = observe_ru(
            samples,
            a,
            allocation,
            fields.ltf_size,
            fields.guard_ns,
            cp.checked_add(j.checked_mul(stride)?)?,
        )?;
        let coefficient = mu_stbc_training_column(usize::from(fields.ltf_symbols), j)?[0].conj();
        let mut values = Vec::with_capacity(pilots.len());
        let mut common = ComplexSample::ZERO;
        for &k in pilots {
            if !allocation.contains(k) {
                return None;
            }
            let bin = k.rem_euclid(256) as usize;
            let value = observed[bin].mul(first[bin].conj()).mul(coefficient);
            if !value.power().is_finite() {
                return None;
            }
            common = common.add(value);
            values.push((k as f32, value));
        }
        if !common.power().is_finite() {
            return None;
        }
        if common.power() < 1e-18 {
            continue;
        }
        let reference = common.phase();
        let (mut w, mut x, mut xx, mut y, mut xy) = (0., 0., 0., 0., 0.);
        for (k, v) in values {
            let weight = v.power().sqrt();
            let residual = v.mul(ComplexSample::rotation(-reference)).phase();
            w += weight;
            x += weight * k;
            xx += weight * k * k;
            y += weight * residual;
            xy += weight * k * residual;
        }
        let determinant = w * xx - x * x;
        if !determinant.is_finite() {
            return None;
        }
        let slope = if determinant > 1e-12 {
            (w * xy - x * y) / determinant
        } else {
            0.
        };
        let phase = reference + (y - slope * x) / w;
        if !slope.is_finite() || !phase.is_finite() {
            return None;
        }
        corrections[j] = (phase, slope);
    }
    Some(StbcPhase(corrections))
}

pub(in crate::radio) fn stbc_mu_pilot_channel(
    samples: &[ComplexSample],
    a: &Acquisition,
    fields: &crate::radio::he::mu::MuSignal,
    cp: usize,
    pilots: &[i32],
) -> Option<[ComplexSample; 256]> {
    let phases = stbc_mu_phase(samples, a, fields, cp, pilots)?;
    let allocation = Tones::ru(242, 1)?;
    let stride = usize::from(fields.guard_ns) / 50 + 64 * usize::from(fields.ltf_size);
    let count = usize::from(fields.ltf_symbols);
    let mut channel = [ComplexSample::ZERO; 256];
    for j in 0..count {
        let (observed, _, _) = observe_ru(
            samples,
            a,
            allocation,
            fields.ltf_size,
            fields.guard_ns,
            cp.checked_add(j.checked_mul(stride)?)?,
        )?;
        let p = mu_stbc_training_column(count, j)?[0].conj();
        let (phase, slope) = phases.0[j];
        for &k in pilots {
            let bin = k.rem_euclid(256) as usize;
            let coefficient = ComplexSample::rotation(-phase - slope * k as f32)
                .mul(p)
                .scale(1. / count as f32);
            channel[bin] = channel[bin].add(observed[bin].mul(coefficient));
        }
    }
    let energy: f32 = channel.iter().map(|v| v.power()).sum();
    if !energy.is_finite() || energy < 1e-9 {
        return None;
    }
    Some(channel)
}

pub(in crate::radio) fn train_stbc_ru_with_phase(
    samples: &[ComplexSample],
    a: &Acquisition,
    allocation: Tones,
    fields: &crate::radio::he::mu::MuSignal,
    cp: usize,
    shared: Option<&StbcPhase>,
) -> Option<[[ComplexSample; 256]; 2]> {
    train_stbc_ru_layout(
        samples,
        a,
        allocation,
        RuTraining {
            stbc: fields.stbc,
            ltf_symbols: fields.ltf_symbols,
            ltf_size: fields.ltf_size,
            guard_ns: fields.guard_ns,
        },
        cp,
        shared,
    )
}

#[derive(Clone, Copy)]
struct RuTraining {
    stbc: bool,
    ltf_symbols: u8,
    ltf_size: u8,
    guard_ns: u16,
}

fn tb_ru_training(common: &crate::Dot11TriggerCommonFields) -> Option<RuTraining> {
    if common.bandwidth != 0 || common.masked_ltf || !matches!(common.trigger_type, 0..=2 | 4..=6) {
        return None;
    }
    // Table27-31: 1x1600 is full-bandwidth UL MU-MIMO, not isolated OFDMA.
    let (ltf_size, guard_ns) = match common.gi_ltf {
        1 => (2, 1600),
        2 => (4, 3200),
        _ => return None,
    };
    let code = common.ltf_symbols_midamble;
    let ltf_symbols = if common.doppler {
        match code {
            0..=2 => [1, 2, 4][usize::from(code)],
            4..=6 => [1, 2, 4][usize::from(code - 4)],
            _ => return None,
        }
    } else {
        *[1, 2, 4, 6, 8].get(usize::from(code))?
    };
    Some(RuTraining {
        stbc: common.stbc,
        ltf_symbols,
        ltf_size,
        guard_ns,
    })
}

/// Isolated TB RU, one DATA stream. The caller establishes the user's RU,
/// starting stream zero, sample position and acquisition; no exchange is inferred.
pub(in crate::radio) fn train_tb_ru_field(
    samples: &[ComplexSample],
    a: &Acquisition,
    allocation: Tones,
    common: &crate::Dot11TriggerCommonFields,
    cp: usize,
) -> Option<[ComplexSample; 256]> {
    let fields = tb_ru_training(common)?;
    if fields.stbc
        || (allocation.count() + allocation.pilots().len() == 242 && fields.ltf_symbols != 1)
    {
        return None;
    }
    if allocation.count() < 234 {
        return train_ru_field(samples, a, allocation, fields.ltf_size, fields.guard_ns, cp);
    }
    let (mut channel, tones, guard) =
        observe_ru(samples, a, allocation, fields.ltf_size, fields.guard_ns, cp)?;
    let energy: f32 = channel.iter().map(|v| v.power()).sum();
    if !energy.is_finite() || energy < 1e-9 {
        return None;
    }
    adaptive_delay_fit(&mut channel, &tones, guard, allocation)?;
    Some(channel)
}

/// Isolated TB STBC RU: use only this user's pilot phase, never a phase pooled
/// across independent transmitters. No masked or spatial MU-MIMO separation.
pub(in crate::radio) fn train_tb_stbc_ru_field(
    samples: &[ComplexSample],
    a: &Acquisition,
    allocation: Tones,
    common: &crate::Dot11TriggerCommonFields,
    cp: usize,
) -> Option<[[ComplexSample; 256]; 2]> {
    let fields = tb_ru_training(common)?;
    if allocation.count() + allocation.pilots().len() == 242 && fields.ltf_symbols != 2 {
        return None;
    }
    train_stbc_ru_layout(samples, a, allocation, fields, cp, None)
}

fn train_stbc_ru_layout(
    samples: &[ComplexSample],
    a: &Acquisition,
    allocation: Tones,
    fields: RuTraining,
    cp: usize,
    shared: Option<&StbcPhase>,
) -> Option<[[ComplexSample; 256]; 2]> {
    let count = usize::from(fields.ltf_symbols);
    if !fields.stbc
        || !matches!(count, 2 | 4 | 6 | 8)
        || !matches!(
            (fields.ltf_size, fields.guard_ns),
            (2, 800 | 1600) | (4, 800 | 3200)
        )
    {
        return None;
    }
    let (first, tones, guard) =
        observe_ru(samples, a, allocation, fields.ltf_size, fields.guard_ns, cp)?;
    let pilots = allocation.pilots();
    let data: Vec<_> = tones
        .iter()
        .copied()
        .filter(|k| !pilots.contains(k))
        .collect();
    let stride = guard + 64 * usize::from(fields.ltf_size);
    let mut channels = [[ComplexSample::ZERO; 256]; 2];
    let mut pilot_channel = [ComplexSample::ZERO; 256];
    for j in 0..count {
        let observed = if j == 0 {
            first
        } else {
            observe_ru(
                samples,
                a,
                allocation,
                fields.ltf_size,
                fields.guard_ns,
                cp.checked_add(j.checked_mul(stride)?)?,
            )?
            .0
        };
        let p = mu_stbc_training_column(count, j)?;
        let mut phase = ComplexSample::ZERO;
        for &tone in tones.iter().filter(|k| pilots.contains(k)) {
            let bin = tone.rem_euclid(256) as usize;
            phase = phase.add(observed[bin].mul(first[bin].conj()).mul(p[0].conj()));
        }
        if !phase.power().is_finite() {
            return None;
        }
        // A summed-channel pilot null cannot measure residual phase.
        let (phase, slope) = shared.map(|v| v.0[j]).unwrap_or_else(|| {
            (
                if phase.power() > 1e-18 {
                    phase.phase()
                } else {
                    0.
                },
                0.,
            )
        });
        for &tone in pilots {
            let bin = tone.rem_euclid(256) as usize;
            let coefficient = ComplexSample::rotation(-phase - slope * tone as f32)
                .mul(p[0].conj())
                .scale(1. / count as f32);
            pilot_channel[bin] = pilot_channel[bin].add(observed[bin].mul(coefficient));
        }
        for (stream, channel) in channels.iter_mut().enumerate() {
            for &tone in &data {
                let coefficient = ComplexSample::rotation(-phase - slope * tone as f32)
                    .mul(p[stream].conj())
                    .scale(1. / count as f32);
                let bin = tone.rem_euclid(256) as usize;
                channel[bin] = channel[bin].add(observed[bin].mul(coefficient));
            }
        }
    }
    let energy: f32 = channels.iter().flatten().map(|v| v.power()).sum();
    if !energy.is_finite() || energy < 1e-9 {
        return None;
    }
    let observations = channels;
    let mut selected = [guard; 2];
    for (stream, channel) in channels.iter_mut().enumerate() {
        for &tone in &data {
            let bin = tone.rem_euclid(256) as usize;
            channel[bin] = channel[bin].mul(ComplexSample::rotation(
                -std::f32::consts::TAU * tone as f32 * (8 * stream) as f32 / 256.,
            ));
        }
        if allocation.count() < 234 {
            selected[stream] = adaptive_delay_fit(channel, &data, guard, allocation)?;
        } else {
            delay_fit(channel, &data, guard, allocation)?;
        }
        for tone in allocation.active() {
            let bin = tone.rem_euclid(256) as usize;
            channel[bin] = channel[bin].mul(ComplexSample::rotation(
                std::f32::consts::TAU * tone as f32 * (8 * stream) as f32 / 256.,
            ));
        }
    }
    if allocation.count() < 234 {
        channels = joint_stbc_fit(
            &observations,
            &pilot_channel,
            &data,
            pilots,
            selected,
            allocation,
        )?;
    }
    // R trains the summed pilot channel directly. Preserve that observation
    // rather than deriving DATA phase from two independently interpolated
    // pilot values, which can introduce a large phase bias near a pilot null.
    // The individual pilot channels are not separately observable: retain the
    // fitted difference and constrain their sum to the averaged R measurement.
    for &tone in pilots {
        let bin = tone.rem_euclid(256) as usize;
        let correction = pilot_channel[bin]
            .sub(channels[0][bin].add(channels[1][bin]))
            .scale(0.5);
        channels[0][bin] = channels[0][bin].add(correction);
        channels[1][bin] = channels[1][bin].add(correction);
    }
    Some(channels)
}

/// Select delay-model complexity from held-out training measurements, not
/// decoded DATA or an assumed physical channel. Neither narrow allocations nor
/// noisy full-band training justify all guard-interval taps solely from the GI.
/// Keep the full guard candidate so long-delay channels remain representable.
fn adaptive_delay_fit(
    channel: &mut [ComplexSample; 256],
    tones: &[i32],
    guard: usize,
    allocation: Tones,
) -> Option<usize> {
    let observed = *channel;
    let mut best = (f32::INFINITY, guard);
    for candidate in [4, 8, 16, 32, 64].into_iter().filter(|&n| n <= guard) {
        let mut error = 0.;
        for fold in 0..2 {
            // Irregular holdouts avoid the delay aliasing of a decimated
            // grid, particularly with sparse 2x training.
            let held = |i: usize| (7 * i + i / 3 + 5 * fold) % 11 < 3;
            let train: Vec<_> = tones
                .iter()
                .enumerate()
                .filter(|(i, _)| !held(*i))
                .map(|(_, k)| *k)
                .collect();
            let mut fitted = observed;
            delay_fit(&mut fitted, &train, candidate, allocation)?;
            for (_, &k) in tones.iter().enumerate().filter(|(i, _)| held(*i)) {
                let bin = k.rem_euclid(256) as usize;
                error += fitted[bin].sub(observed[bin]).power();
            }
        }
        if error.is_finite() && error < best.0 {
            best = (error, candidate);
        }
    }
    if !best.0.is_finite() {
        return None;
    }
    delay_fit(channel, tones, best.1, allocation)?;
    Some(best.1)
}

/// Fit both physical channels jointly: DATA trains each stream separately,
/// while R pilots constrain their sum. Treating those pilots only as output
/// replacements throws away information useful to sparse DATA interpolation.
fn joint_stbc_fit(
    observed: &[[ComplexSample; 256]; 2],
    summed: &[ComplexSample; 256],
    data: &[i32],
    pilots: &[i32],
    guards: [usize; 2],
    allocation: Tones,
) -> Option<[[ComplexSample; 256]; 2]> {
    let counts = [guards[0].checked_add(4)?, guards[1].checked_add(4)?];
    if counts.iter().any(|&n| n > 68) || data.is_empty() {
        return None;
    }
    let count = counts[0] + counts[1];
    let basis = |k: i32, stream: usize, n: usize| {
        ComplexSample::rotation(
            -std::f32::consts::TAU * k as f32 * (n as f32 - 4. - (8 * stream) as f32) / 256.,
        )
    };
    let mut normal = vec![vec![ComplexSample::ZERO; count + 1]; count];
    let mut add = |row: &[ComplexSample], value: ComplexSample| {
        for i in 0..count {
            for j in 0..count {
                normal[i][j] = normal[i][j].add(row[i].conj().mul(row[j]));
            }
            normal[i][count] = normal[i][count].add(row[i].conj().mul(value));
        }
    };
    for &k in data {
        for stream in 0..2 {
            let mut row = vec![ComplexSample::ZERO; count];
            let offset = if stream == 0 { 0 } else { counts[0] };
            for n in 0..counts[stream] {
                row[offset + n] = basis(k, stream, n);
            }
            add(&row, observed[stream][k.rem_euclid(256) as usize]);
        }
    }
    for &k in pilots {
        let row: Vec<_> = (0..2)
            .flat_map(|stream| (0..counts[stream]).map(move |n| basis(k, stream, n)))
            .collect();
        add(&row, summed[k.rem_euclid(256) as usize]);
    }
    for (i, row) in normal.iter_mut().enumerate() {
        row[i].i += 0.001 * data.len() as f32;
    }
    for col in 0..count {
        let pivot = (col..count)
            .max_by(|&a, &b| normal[a][col].power().total_cmp(&normal[b][col].power()))?;
        normal.swap(col, pivot);
        let divisor = normal[col][col];
        if !divisor.power().is_finite() || divisor.power() < 1e-12 {
            return None;
        }
        let inverse = divisor.conj().scale(1. / divisor.power());
        let (before, rest) = normal.split_at_mut(col);
        let (pivot_row, after) = rest.split_first_mut()?;
        for value in &mut pivot_row[col..] {
            *value = value.mul(inverse);
        }
        for row in before.iter_mut().chain(after) {
            let factor = row[col];
            for (value, &p) in row[col..].iter_mut().zip(&pivot_row[col..]) {
                *value = value.sub(factor.mul(p));
            }
        }
    }
    let mut result = [[ComplexSample::ZERO; 256]; 2];
    for stream in 0..2 {
        let offset = if stream == 0 { 0 } else { counts[0] };
        for k in allocation.active() {
            let mut value = ComplexSample::ZERO;
            for n in 0..counts[stream] {
                value = value.add(normal[offset + n][count].mul(basis(k, stream, n)));
            }
            if !value.power().is_finite() {
                return None;
            }
            result[stream][k.rem_euclid(256) as usize] = value;
        }
    }
    Some(result)
}

fn mu_stbc_training_column(count: usize, j: usize) -> Option<[ComplexSample; 2]> {
    if j >= count || !matches!(count, 2 | 4 | 6 | 8) {
        return None;
    }
    if count == 6 {
        let sign = [1., -1., 1., 1., 1., -1.][j];
        Some([
            ComplexSample { i: sign, q: 0. },
            ComplexSample::rotation(-std::f32::consts::TAU * j as f32 / 6.).scale(sign),
        ])
    } else {
        Some([
            ComplexSample {
                i: [1., -1., 1., 1.][j % 4],
                q: 0.,
            },
            ComplexSample {
                i: [1., 1., -1., 1.][j % 4],
                q: 0.,
            },
        ])
    }
}

fn observe_ru(
    samples: &[ComplexSample],
    a: &Acquisition,
    allocation: Tones,
    ltf_size: u8,
    guard_ns: u16,
    cp: usize,
) -> Option<([ComplexSample; 256], Vec<i32>, usize)> {
    let (sequence, nfft, guard) = match (ltf_size, guard_ns) {
        (1, 800) => (LTF1, 64, 16),
        (2, 800) => (LTF2, 128, 16),
        (2, 1600) => (LTF2, 128, 32),
        (4, 800) => (LTF4, 256, 16),
        (4, 3200) => (LTF4, 256, 64),
        _ => return None,
    };
    let useful = cp.checked_add(guard)?;
    let wave = samples.get(useful..useful.checked_add(nfft)?)?;
    let start = a.signal_start.checked_add(useful as u64)?;
    let mut time = [ComplexSample::ZERO; 256];
    for (n, value) in time.iter_mut().take(nfft).enumerate() {
        let elapsed = start.checked_add(n as u64)?.checked_sub(a.phase_origin)?;
        *value = wave[n].mul(ComplexSample::rotation(-a.frequency_rad * elapsed as f32));
    }
    let mut bins = [ComplexSample::ZERO; 256];
    match nfft {
        64 => bins[..64].copy_from_slice(&crate::radio::sync::fft64(time[..64].try_into().ok()?)),
        128 => bins[..128]
            .copy_from_slice(&crate::radio::he::fft::fft128(time[..128].try_into().ok()?)),
        _ => bins = crate::radio::he::fft::fft256(time),
    }
    // Equations27-5/58 define K_HE-LTF = K_RU * nfft/256, without rounding.
    // This differs from counting populated tones (60.5/121 versus60/122).
    // Compensate both that normalization and the shorter FFT's gain.
    let scale = (256. / nfft as f32).sqrt();
    let mut channel = [ComplexSample::ZERO; 256];
    for (i, sign) in sequence.iter().enumerate() {
        if !allocation.contains(i as i32 - 122) {
            continue;
        }
        let k = (i as i32 - 122).rem_euclid(256) as usize;
        let multiplier = match sign {
            b'+' => 1.,
            b'-' => -1.,
            _ => continue,
        };
        let short_bin = ((i as i32 - 122) / (256 / nfft) as i32).rem_euclid(nfft as i32) as usize;
        channel[k] = bins[short_bin].scale(multiplier * scale);
    }
    let trained: Vec<i32> = sequence
        .iter()
        .enumerate()
        .filter(|(_, s)| **s != b'0')
        .map(|(i, _)| i as i32 - 122)
        .filter(|tone| allocation.contains(*tone))
        .collect();
    Some((channel, trained, guard))
}

#[cfg(test)]
mod tests {
    #[test]
    fn radio_he_tb_full_ru_delay_selection_preserves_long_paths() {
        let allocation = super::Tones::ru(242, 1).unwrap();
        for step in [1, 2] {
            let tones: Vec<_> = allocation.active().filter(|k| k % step == 0).collect();
            for delay in [0, 24, 50] {
                let mut truth = [super::ComplexSample::ZERO; 256];
                let mut observed = truth;
                let mut state = 0x4321u32;
                for k in allocation.active() {
                    let bin = k.rem_euclid(256) as usize;
                    truth[bin] = super::ComplexSample { i: 1., q: 0. }.add(
                        super::ComplexSample::rotation(
                            -std::f32::consts::TAU * k as f32 * delay as f32 / 256.,
                        )
                        .scale(0.25),
                    );
                    let mut noise = || {
                        state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                        (state as f64 / u32::MAX as f64 - 0.5) as f32 * 0.04
                    };
                    observed[bin] = truth[bin].add(super::ComplexSample {
                        i: noise(),
                        q: noise(),
                    });
                }
                let mut fitted = observed;
                let selected =
                    super::adaptive_delay_fit(&mut fitted, &tones, 64, allocation).unwrap();
                let error = |h: &[super::ComplexSample; 256]| {
                    allocation
                        .active()
                        .map(|k| {
                            h[k.rem_euclid(256) as usize]
                                .sub(truth[k.rem_euclid(256) as usize])
                                .power()
                        })
                        .sum::<f32>()
                };
                assert!(
                    error(&fitted) / 242. < 0.03f32.powi(2),
                    "step={step} delay={delay} selected={selected}"
                );
                if delay == 0 {
                    let mut fixed = observed;
                    super::delay_fit(&mut fixed, &tones, 64, allocation).unwrap();
                    assert!(error(&fitted) < error(&fixed));
                } else {
                    assert!(selected >= delay);
                }
            }
        }
    }
    use super::*;
    #[test]
    fn radio_he_tb_training_mode_admission() {
        let mut common = crate::Dot11TriggerCommonFields::default();
        for (gi, size, guard) in [(1, 2, 1600), (2, 4, 3200)] {
            common.gi_ltf = gi;
            for doppler in [false, true] {
                common.doppler = doppler;
                for code in 0..8 {
                    common.ltf_symbols_midamble = code;
                    let expected = if doppler {
                        [
                            Some(1),
                            Some(2),
                            Some(4),
                            None,
                            Some(1),
                            Some(2),
                            Some(4),
                            None,
                        ][usize::from(code)]
                    } else {
                        [
                            Some(1),
                            Some(2),
                            Some(4),
                            Some(6),
                            Some(8),
                            None,
                            None,
                            None,
                        ][usize::from(code)]
                    };
                    let result = tb_ru_training(&common);
                    assert_eq!(result.map(|v| v.ltf_symbols), expected);
                    if let Some(result) = result {
                        assert_eq!((result.ltf_size, result.guard_ns), (size, guard));
                    }
                }
            }
        }
        common = crate::Dot11TriggerCommonFields::default();
        for gi in [0, 3, 4, 255] {
            common.gi_ltf = gi;
            assert!(tb_ru_training(&common).is_none());
        }
        common.gi_ltf = 1;
        common.masked_ltf = true;
        assert!(tb_ru_training(&common).is_none());
        common.masked_ltf = false;
        for bandwidth in [1, 2, 3, 255] {
            common.bandwidth = bandwidth;
            assert!(tb_ru_training(&common).is_none());
        }
        common.bandwidth = 0;
        for variant in [3, 7, 15, 255] {
            common.trigger_type = variant;
            assert!(tb_ru_training(&common).is_none());
        }
    }

    #[test]
    fn radio_he_mu_tb_stbc_ru_training_channels() {
        let (_, mut a) = fixture("he-training4-gi800-flat-gain160");
        a.signal_start = 0;
        a.phase_origin = 0;
        a.frequency_rad = 0.018;
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
        let mut fields = crate::radio::he::mu::MuSignal::decode(&bits).unwrap();
        fields.stbc = true;
        for (rows, count, long_delay) in [
            (
                include_str!("../../../tests/fixtures/iq/he-mu-stbc-training-index.tsv"),
                768,
                false,
            ),
            (
                include_str!("../../../tests/fixtures/iq/he-mu-stbc-training-long-index.tsv"),
                192,
                true,
            ),
        ] {
            assert_eq!(rows.lines().skip(1).count(), count);
            for row in rows.lines().skip(1) {
                let c: Vec<_> = row.split('\t').collect();
                let ru: u16 = c[1].parse().unwrap();
                let allocation = Tones::ru(ru, c[2].parse().unwrap()).unwrap();
                fields.ltf_size = c[3].parse().unwrap();
                fields.guard_ns = c[4].parse::<u16>().unwrap() * 50;
                fields.ltf_symbols = c[5].parse().unwrap();
                let branch: usize = c[6].parse().unwrap();
                let bytes = std::fs::read(format!(
                    "{}/tests/fixtures/iq/{}.cs8",
                    env!("CARGO_MANIFEST_DIR"),
                    c[0]
                ))
                .unwrap();
                let wave: Vec<_> = bytes
                    .chunks_exact(2)
                    .map(|b| ComplexSample {
                        i: b[0] as i8 as f32 / 128.,
                        q: b[1] as i8 as f32 / 128.,
                    })
                    .collect();
                let channels = train_stbc_ru_field(&wave, &a, allocation, &fields, 0)
                    .unwrap_or_else(|| panic!("{}", c[0]));
                if fields.guard_ns >= 1600 {
                    let common = crate::Dot11TriggerCommonFields {
                        stbc: true,
                        gi_ltf: if fields.ltf_size == 2 { 1 } else { 2 },
                        ltf_symbols_midamble: match fields.ltf_symbols {
                            2 => 1,
                            4 => 2,
                            6 => 3,
                            8 => 4,
                            _ => unreachable!(),
                        },
                        ..Default::default()
                    };
                    let tb = train_tb_stbc_ru_field(&wave, &a, allocation, &common, 0);
                    if ru == 242 && fields.ltf_symbols != 2 {
                        assert!(tb.is_none());
                    } else {
                        assert_eq!(tb, Some(channels), "TB {}", c[0]);
                        assert!(train_tb_stbc_ru_field(
                            &wave[..wave.len() - 1],
                            &a,
                            allocation,
                            &common,
                            0
                        )
                        .is_none());
                        assert!(
                            train_tb_stbc_ru_field(&wave, &a, allocation, &common, usize::MAX)
                                .is_none()
                        );
                    }
                }
                let gain = c[7].parse::<f32>().unwrap() / 128.
                    * 4.
                    * (52. / f32::from(ru)).sqrt()
                    * std::f32::consts::FRAC_1_SQRT_2;
                let mut error = 0.;
                let mut energy = 0.;
                for k in allocation.active() {
                    let angle = std::f32::consts::TAU * k as f32 / 256.;
                    let guard = f32::from(fields.guard_ns) / 50.;
                    let expected = [
                        if branch == 1 {
                            ComplexSample::ZERO
                        } else {
                            ComplexSample { i: 1., q: 0.25 }.mul(ComplexSample::rotation(
                                -(if long_delay { guard - 3. } else { 3. }) * angle,
                            ))
                        },
                        if branch == 2 {
                            ComplexSample::ZERO
                        } else {
                            ComplexSample { i: 0.6, q: -0.3 }
                                .mul(ComplexSample::rotation(
                                    -(if long_delay { guard - 6. } else { 0. }) * angle,
                                ))
                                .add(ComplexSample { i: 0., q: 0.2 }.mul(ComplexSample::rotation(
                                    -(if long_delay { guard - 2. } else { 5. }) * angle,
                                )))
                                .mul(ComplexSample::rotation(8. * angle))
                        },
                    ];
                    for stream in 0..2 {
                        let h = expected[stream]
                            .mul(ComplexSample::rotation(0.7))
                            .scale(gain);
                        error += channels[stream][k.rem_euclid(256) as usize].sub(h).power();
                        energy += h.power();
                    }
                }
                assert!(
                    (error / energy).sqrt() < 0.06,
                    "{}: {}",
                    c[0],
                    (error / energy).sqrt()
                );
                for k in -128i32..128 {
                    if !allocation.contains(k) {
                        assert!(channels
                            .iter()
                            .all(|h| h[k.rem_euclid(256) as usize].power() == 0.));
                    }
                }
                assert!(
                    train_stbc_ru_field(&wave[..wave.len() - 1], &a, allocation, &fields, 0)
                        .is_none()
                );
                assert!(train_stbc_ru_field(&wave, &a, allocation, &fields, usize::MAX).is_none());
                assert!(train_stbc_ru_field(
                    &vec![ComplexSample::ZERO; wave.len()],
                    &a,
                    allocation,
                    &fields,
                    0
                )
                .is_none());
                let mut bad = wave.clone();
                bad[wave.len() - 1].i = f32::NAN;
                assert!(train_stbc_ru_field(&bad, &a, allocation, &fields, 0).is_none());
            }
        }
        for count in [0, 1, 3, 5, 7, 9, 255] {
            fields.ltf_symbols = count;
            assert!(train_stbc_ru_field(&[], &a, Tones::ru(26, 1).unwrap(), &fields, 0).is_none());
        }
    }

    #[test]
    fn radio_he_mu_tb_ru_training_channels() {
        let (_, mut a) = fixture("he-training4-gi800-flat-gain160");
        a.signal_start = 0;
        a.phase_origin = 0;
        a.frequency_rad = 0.;
        let rows = include_str!("../../../tests/fixtures/iq/he-mu-training-index.tsv");
        assert_eq!(rows.lines().skip(1).count(), 384);
        for row in rows.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let ru: u16 = c[1].parse().unwrap();
            let allocation = Tones::ru(ru, c[2].parse().unwrap()).unwrap();
            let size = c[3].parse().unwrap();
            let guard = c[4].parse::<u16>().unwrap() * 50;
            let bytes = std::fs::read(format!(
                "{}/tests/fixtures/iq/{}.cs8",
                env!("CARGO_MANIFEST_DIR"),
                c[0]
            ))
            .unwrap();
            let wave: Vec<_> = bytes
                .chunks_exact(2)
                .map(|b| ComplexSample {
                    i: b[0] as i8 as f32 / 128.,
                    q: b[1] as i8 as f32 / 128.,
                })
                .collect();
            let channel = train_ru_field(&wave, &a, allocation, size, guard, 0)
                .unwrap_or_else(|| panic!("{}", c[0]));
            let mut trained_channels = vec![channel];
            if guard >= 1600 {
                let mut common = crate::Dot11TriggerCommonFields {
                    gi_ltf: if size == 2 { 1 } else { 2 },
                    ..Default::default()
                };
                for code in 0..=4 {
                    common.ltf_symbols_midamble = code;
                    let tb = train_tb_ru_field(&wave, &a, allocation, &common, 0);
                    if ru == 242 && code != 0 {
                        assert!(tb.is_none());
                    } else if ru == 242 {
                        // TB selects model complexity from held-out LTF tones.
                        // Check against the same independent physical channel,
                        // not bit equality with the fixed-delay MU estimator.
                        trained_channels.push(tb.unwrap());
                    } else {
                        assert_eq!(tb, Some(channel), "TB {}", c[0]);
                    }
                }
            }
            let gain = c[5].parse::<f32>().unwrap() / 128. * 4. * (52. / f32::from(ru)).sqrt();
            for channel in trained_channels {
                let mut error = 0.;
                let mut energy = 0.;
                for k in allocation.active() {
                    let h = ComplexSample { i: 1., q: 0. }
                        .add(if c[6] == "1" {
                            ComplexSample { i: 0., q: 0.25 }.mul(ComplexSample::rotation(
                                -std::f32::consts::TAU * k as f32 * 3. / 256.,
                            ))
                        } else {
                            ComplexSample::ZERO
                        })
                        .scale(gain);
                    error += channel[k.rem_euclid(256) as usize].sub(h).power();
                    energy += h.power();
                }
                assert!(
                    (error / energy).sqrt() < 0.06,
                    "{}: {}",
                    c[0],
                    (error / energy).sqrt()
                );
                for k in -128i32..128 {
                    if !allocation.contains(k) {
                        assert_eq!(channel[k.rem_euclid(256) as usize].power(), 0.);
                    }
                }
            }
            assert!(
                train_ru_field(&wave[..wave.len() - 1], &a, allocation, size, guard, 0).is_none()
            );
            assert!(train_ru_field(&wave, &a, allocation, size, guard, usize::MAX).is_none());
            assert!(train_ru_field(
                &vec![ComplexSample::ZERO; wave.len()],
                &a,
                allocation,
                size,
                guard,
                0
            )
            .is_none());
            let mut bad = wave.clone();
            bad[usize::from(guard) / 50].i = f32::NAN;
            assert!(train_ru_field(&bad, &a, allocation, size, guard, 0).is_none());
        }
        for (size, guard) in [(1, 800), (2, 3200), (4, 1600), (0, 0), (255, u16::MAX)] {
            assert!(train_ru_field(&[], &a, Tones::ru(26, 1).unwrap(), size, guard, 0).is_none());
        }
    }
    #[test]
    fn radio_he_er106_training_channels() {
        let (samples, mut a) = fixture("he-training4-gi800-flat-gain160");
        let mut fields = decode_prefix(&samples[a.signal_start as usize..], &a)
            .unwrap()
            .signal;
        a.signal_start = 0;
        a.phase_origin = 0;
        a.frequency_rad = 0.;
        let rows = include_str!("../../../tests/fixtures/iq/he-er106-training-index.tsv");
        assert_eq!(rows.lines().skip(1).count(), 54);
        for row in rows.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            fields.bandwidth = 1;
            fields.ltf_size = c[1].parse().unwrap();
            fields.guard_ns = c[2].parse::<u16>().unwrap() * 50;
            fields.stbc = c[3] == "1";
            fields.space_time_streams = if fields.stbc { 2 } else { 1 };
            let bytes = std::fs::read(format!(
                "{}/tests/fixtures/iq/{}.cs8",
                env!("CARGO_MANIFEST_DIR"),
                c[0]
            ))
            .unwrap();
            let wave: Vec<_> = bytes
                .chunks_exact(2)
                .map(|b| ComplexSample {
                    i: b[0] as i8 as f32 / 128.,
                    q: b[1] as i8 as f32 / 128.,
                })
                .collect();
            assert_eq!(wave.len(), c[6].parse::<usize>().unwrap());
            let recover = |input: &[ComplexSample], er| {
                if fields.stbc {
                    train_stbc_for_format(input, &a, &fields, 0, er).map(|v| v.to_vec())
                } else {
                    train_for_format(input, &a, &fields, 0, er).map(|v| vec![v])
                }
            };
            assert!(recover(&wave, false).is_none());
            assert!(recover(&wave[..wave.len() - 1], true).is_none());
            assert!(recover(&vec![ComplexSample::ZERO; wave.len()], true).is_none());
            let mut bad = wave.clone();
            bad[usize::from(fields.guard_ns) / 50].i = f32::NAN;
            assert!(recover(&bad, true).is_none());
            let channels = recover(&wave, true).unwrap_or_else(|| panic!("{}", c[0]));
            let gain = c[4].parse::<f32>().unwrap() / 128.
                * 4.
                * (52f32 / 106.).sqrt()
                * (2. / f32::from(fields.space_time_streams)).sqrt();
            for (stream, channel) in channels.iter().enumerate() {
                let mut error = 0.;
                let mut energy = 0.;
                for (k, value) in channel.iter().enumerate().take(123).skip(17) {
                    let expected = if stream == 0 {
                        ComplexSample { i: 1., q: 0. }.add(if c[5] == "1" {
                            ComplexSample { i: 0., q: 0.25 }.mul(ComplexSample::rotation(
                                -std::f32::consts::TAU * k as f32 * 3. / 256.,
                            ))
                        } else {
                            ComplexSample::ZERO
                        })
                    } else {
                        ComplexSample { i: 0.55, q: 0.35 }.mul(ComplexSample::rotation(
                            std::f32::consts::TAU * k as f32 * 8. / 256.,
                        ))
                    }
                    .scale(gain);
                    error += value.sub(expected).power();
                    energy += expected.power();
                }
                assert!(
                    (error / energy).sqrt() < 0.06,
                    "{} stream{stream}: {}",
                    c[0],
                    (error / energy).sqrt()
                );
                assert!(channel[..17]
                    .iter()
                    .chain(&channel[123..])
                    .all(|v| v.power() == 0.));
            }
        }
    }
    #[test]
    fn radio_he_ltf_fractional_normalization() {
        let (samples, mut a) = fixture("he-training4-gi800-flat-gain160");
        let mut fields = decode_prefix(&samples[a.signal_start as usize..], &a)
            .unwrap()
            .signal;
        a.frequency_rad = 0.;
        for (size, guard_ns, norm, sequence) in [
            (1, 800, 60.5f64, LTF1),
            (2, 800, 121., LTF2),
            (2, 1600, 121., LTF2),
            (4, 800, 242., LTF4),
            (4, 3200, 242., LTF4),
        ] {
            fields.ltf_size = size;
            fields.guard_ns = guard_ns;
            let guard = usize::from(guard_ns) / 50;
            let nfft = 64 * usize::from(size);
            // One known modulated tone, evaluated directly from Eq27-58 in
            // double precision. Absolute gain detects the populated-count bug
            // independently of equalization, quantization and channel fitting.
            let tone = 28usize;
            let sign = match sequence[tone + 122] {
                b'+' => 1.,
                b'-' => -1.,
                _ => panic!("unmodulated"),
            };
            let mut wave = vec![ComplexSample::ZERO; guard + nfft];
            for n in 0..nfft {
                let phase = std::f64::consts::TAU * tone as f64 * n as f64 / 256.;
                let amplitude = sign / (256. * norm.sqrt());
                wave[guard + n] = ComplexSample {
                    i: (amplitude * phase.cos()) as f32,
                    q: (amplitude * phase.sin()) as f32,
                };
            }
            let (channel, _, _) = observe_field(&wave, &a, &fields, 0).unwrap();
            assert!(
                (channel[tone].i - 1. / 242f32.sqrt()).abs() < 1e-6,
                "ltf{size}: {:?}",
                channel[tone]
            );
            assert!(channel[tone].q.abs() < 1e-6);
        }
    }
    #[test]
    fn radio_he_stbc_training_bounds() {
        for row in include_str!("../../../tests/fixtures/iq/he-stbc-iq-index.tsv")
            .lines()
            .skip(1)
            .filter(|r| r.starts_with("he-stbc-iq-mcs0-bcc-") && r.contains("-pad1-flat\t"))
        {
            let c: Vec<_> = row.split('\t').collect();
            let (samples, a) = fixture(c[0]);
            let input = &samples[a.signal_start as usize..];
            let trained = train_su(input, &a).expect(c[0]);
            let fields = trained.prefix.signal;
            let end = (trained.data_start - a.signal_start) as usize;
            assert!(trained.second.is_some());
            assert!(train_stbc_field(&input[..end], &a, &fields, 400).is_some());
            assert!(train_stbc_field(&input[..end - 1], &a, &fields, 400).is_none());
            assert!(train_stbc_field(input, &a, &fields, usize::MAX).is_none());
            let mut bad_a = a.clone();
            bad_a.signal_start = u64::MAX - 40;
            assert!(train_stbc_field(input, &bad_a, &fields, 400).is_none());
            for n in [400 + trained.guard, end - 1] {
                for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
                    let mut bad_input = input.to_vec();
                    bad_input[n].q = bad;
                    assert!(train_stbc_field(&bad_input, &a, &fields, 400).is_none());
                }
            }
            let mut zero = input.to_vec();
            zero[400..end].fill(ComplexSample::ZERO);
            assert!(train_stbc_field(&zero, &a, &fields, 400).is_none());
            let mut bad = fields;
            bad.dcm = true;
            assert!(train_stbc_field(input, &a, &bad, 400).is_none());
            bad = fields;
            bad.space_time_streams = 1;
            assert!(train_stbc_field(input, &a, &bad, 400).is_none());
        }
    }

    fn train_su4(samples: &[ComplexSample], a: &Acquisition) -> Option<Trained> {
        let trained = train_su(samples, a)?;
        (trained.prefix.signal.ltf_size == 4).then_some(trained)
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
            .find_map(|(i, s)| match sync.push(*s, i as u64) {
                Some(crate::radio::sync::SyncEvent::Acquired(a)) => Some(a),
                _ => None,
            })
            .expect("independent preamble acquisition");
        (samples, a)
    }

    #[test]
    fn radio_he_training4_independent_channels_and_probe() {
        let rows: Vec<_> = include_str!("../../../tests/fixtures/iq/he-training4-index.tsv")
            .lines()
            .skip(1)
            .chain(
                include_str!("../../../tests/fixtures/iq/he-training-sparse-index.tsv")
                    .lines()
                    .skip(1),
            )
            .collect();
        assert_eq!(rows.len(), 60);
        assert_eq!(LTF4.iter().filter(|b| **b != b'0').count(), 242);
        for row in rows {
            let c: Vec<_> = row.split('\t').collect();
            let (samples, a) = fixture(c[0]);
            let trained = train_su(&samples[a.signal_start as usize..], &a)
                .unwrap_or_else(|| panic!("{}", c[0]));
            if c.len() == 15 {
                assert_eq!(trained.prefix.signal.ltf_size, c[14].parse::<u8>().unwrap());
            }
            assert_eq!(a.preamble_start, 37);
            assert_eq!(trained.prefix.end_sample, 677);
            assert_eq!(trained.prefix.signal.beam_change, c[2] == "1");
            assert_eq!(trained.guard, c[1].parse::<usize>().unwrap());
            assert_eq!(trained.data_start, c[11].parse::<u64>().unwrap());
            let beam = ComplexSample {
                i: c[7].parse().unwrap(),
                q: c[8].parse().unwrap(),
            };
            let taps: Vec<_> = c[6]
                .split(';')
                .map(|s| {
                    let v: Vec<f32> = s.split(':').map(|n| n.parse().unwrap()).collect();
                    (v[0], ComplexSample { i: v[1], q: v[2] })
                })
                .collect();
            let mut expected = [ComplexSample::ZERO; 256];
            let mut fit = ComplexSample::ZERO;
            let mut denominator = 0.;
            for k in (-122i32..=-2).chain(2..=122) {
                let bin = k.rem_euclid(256) as usize;
                for (delay, h) in &taps {
                    let phase = -std::f32::consts::TAU * k as f32 * delay / 256.;
                    expected[bin] = expected[bin].add(h.mul(ComplexSample::rotation(phase)));
                }
                expected[bin] = expected[bin].mul(beam);
                fit = fit.add(trained.channel[bin].mul(expected[bin].conj()));
                denominator += expected[bin].power();
            }
            let fit = fit.scale(1. / denominator);
            let amplitude = c[5].parse::<f32>().unwrap() / 128. * 4. * (52f32 / 242.).sqrt();
            assert!(
                (fit.power().sqrt() / amplitude - 1.).abs() < 0.04,
                "{} amplitude",
                c[0]
            );
            let mut residual = 0.;
            let mut energy = 0.;
            for k in 0..256 {
                residual += trained.channel[k].sub(expected[k].mul(fit)).power();
                energy += trained.channel[k].power();
            }
            assert!((residual / energy).sqrt() < 0.08, "{} channel shape", c[0]);

            // Known uncoded probe tests the trained channel, not MAC decoding.
            let start = trained.data_start as usize + trained.guard;
            let time = std::array::from_fn(|n| {
                let elapsed = start as u64 + n as u64 - a.phase_origin;
                samples[start + n].mul(ComplexSample::rotation(-a.frequency_rad * elapsed as f32))
            });
            let observed = crate::radio::he::fft::fft256(time);
            let mut corrected = Vec::new();
            let mut common = ComplexSample::ZERO;
            for (tone, bit) in (-122i32..=-2).chain(2..=122).zip(c[9].bytes()) {
                let bin = tone.rem_euclid(256) as usize;
                let sign = if bit == b'1' { 1. } else { -1. };
                let value = observed[bin].mul(trained.channel[bin].conj()).scale(sign);
                common = common.add(value);
                corrected.push(value);
            }
            assert_eq!(corrected.len(), 242);
            let rotation = ComplexSample::rotation(-common.phase());
            assert!(
                corrected.iter().all(|v| v.mul(rotation).i > 0.),
                "{} probe signs",
                c[0]
            );
        }
    }

    #[test]
    fn radio_he_training4_bounds_and_invalid_modes() {
        for row in include_str!("../../../tests/fixtures/iq/he-training4-invalid-index.tsv")
            .lines()
            .skip(1)
        {
            let name = row.split('\t').next().unwrap();
            let (samples, a) = fixture(name);
            if name.ends_with("stbc") {
                // Historical unsupported-mode fixture: it has a STBC header
                // but only one LTF followed by an uncoded probe. Training
                // estimates alone cannot qualify that probe as valid DATA.
                assert!(
                    crate::radio::he::iq::decode_su_prefix(&samples[a.signal_start as usize..], &a)
                        .unwrap()
                        .signal
                        .stbc
                );
                continue;
            }
            assert!(
                train_su4(&samples[a.signal_start as usize..], &a).is_none(),
                "{name}"
            );
        }
        let (samples, a) = fixture("he-training4-gi800-flat-gain160");
        let input = &samples[a.signal_start as usize..];
        for end in [0, 79, 319, 399, 400, 415, 671] {
            assert!(train_su4(&input[..end], &a).is_none());
        }
        let mut overflow = a.clone();
        overflow.signal_start = u64::MAX - 40;
        assert!(train_su4(input, &overflow).is_none());
    }

    #[test]
    fn radio_he_training_sparse_bounds_and_nonfinite() {
        for row in include_str!("../../../tests/fixtures/iq/he-training-sparse-index.tsv")
            .lines()
            .skip(1)
        {
            let c: Vec<_> = row.split('\t').collect();
            let (samples, a) = fixture(c[0]);
            let end = c[11].parse::<usize>().unwrap() - a.signal_start as usize;
            let input = &samples[a.signal_start as usize..];
            assert!(train_su(&input[..end - 1], &a).is_none());
            assert!(train_su(&input[..end], &a).is_some());
            for invalid in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
                let mut bad = input.to_vec();
                bad[end - 1].i = invalid;
                assert!(train_su(&bad, &a).is_none(), "{} {invalid}", c[0]);
            }
        }
    }
}
