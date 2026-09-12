//! VHT20 SISO BCC IQ kernel. Streaming admission and MPDU publication are separate.
//! IEEE 802.11-2020 21.3.8/10/20; source map in docs/wifi-phy-evidence.json.
#![allow(dead_code)] // Wired into WifiDecoder after independent full-IQ validation.
use super::{
    sync::{fft64, Acquisition},
    *,
};

fn corrected_bins(
    samples: &[ComplexSample],
    start: u64,
    a: &Acquisition,
) -> Option<[ComplexSample; 64]> {
    if samples.len() != 80 {
        return None;
    }
    let mut time = [ComplexSample::ZERO; 64];
    for (n, sample) in time.iter_mut().enumerate() {
        let elapsed = start
            .checked_add(16 + n as u64)?
            .checked_sub(a.phase_origin)?;
        *sample = samples[16 + n].mul(ComplexSample::rotation(-a.frequency_rad * elapsed as f32));
    }
    let bins = fft64(time);
    let mut pilot = ComplexSample::ZERO;
    // p1, p2 and p3 are all +1. Pilot tones never receive the SIG-A2 +j rotation.
    for (k, sign) in [(43, 1.), (57, 1.), (7, 1.), (21, -1.)] {
        pilot = pilot.add(bins[k].mul(a.channel[k].conj()).scale(sign));
    }
    if !pilot.power().is_finite() || pilot.power() < 1e-12 {
        return None;
    }
    let rotation = ComplexSample::rotation(-pilot.phase());
    let equalized = std::array::from_fn(|k| bins[k].mul(a.channel[k].conj()).mul(rotation));
    if equalized.iter().any(|v| !v.power().is_finite()) {
        return None;
    }
    Some(equalized)
}

pub(super) fn signal_a(samples: &[ComplexSample], a: &Acquisition) -> Option<VhtSignalAFields> {
    if samples.len() != 160 {
        return None;
    }
    let mut metrics = [0.; 96];
    for symbol in 0..2 {
        let bins = corrected_bins(
            &samples[symbol * 80..(symbol + 1) * 80],
            a.signal_start.checked_add(80 + symbol as u64 * 80)?,
            a,
        )?;
        let (mut desired, mut orthogonal) = (0., 0.);
        for (j, tone) in (-26i32..=26)
            .filter(|k| ![-21, -7, 0, 7, 21].contains(k))
            .enumerate()
        {
            let v = bins[tone.rem_euclid(64) as usize];
            let (axis, other) = if symbol == 0 { (v.i, v.q) } else { (v.q, v.i) };
            desired += axis * axis;
            orthogonal += other * other;
            metrics[symbol * 48 + j] = axis;
        }
        if desired < 1e-12 || desired <= 4. * orthogonal {
            return None;
        }
    }
    VhtSignalAFields::decode_interleaved(&metrics).ok()
}

pub(super) fn signal_b(
    samples: &[ComplexSample],
    start: u64,
    a: &Acquisition,
) -> Option<VhtSignalB20Fields> {
    let bins = corrected_bins(samples, start, a)?;
    let metrics: Vec<_> = (-28i32..=28)
        .filter(|k| ![-21, -7, 0, 7, 21].contains(k))
        .map(|tone| bins[tone.rem_euclid(64) as usize].i)
        .collect();
    VhtSignalB20Fields::decode_interleaved(&metrics, false).ok()
}

pub(super) struct Decoded {
    pub signal_a: VhtSignalAFields,
    pub signal_b: VhtSignalB20Fields,
    pub info: SignalInfo,
    pub bytes: Vec<u8>,
    pub tracking: PhyDiagnostic,
}

/// Samples begin at L-SIG and may include trailing samples. Acquisition must
/// come from the legacy preamble; no fixture timing or frequency hint is used.
pub(super) fn decode(samples: &[ComplexSample], a: &Acquisition) -> Result<Decoded, ()> {
    let legacy =
        super::signal::decode_signal(samples.get(..80).ok_or(())?, a, 4095).map_err(|_| ())?;
    let fields = signal_a(samples.get(80..240).ok_or(())?, a).ok_or(())?;
    let VhtSignalAUsers::Single {
        space_time_streams: 1,
        mcs,
        ldpc: false,
        ..
    } = fields.users
    else {
        return Err(());
    };
    if fields.bandwidth_code != 0 || fields.stbc || fields.ldpc_extra_symbol {
        return Err(());
    }
    let (nbpsc, ndbps) = *[
        (1usize, 26usize),
        (2, 52),
        (2, 78),
        (4, 104),
        (4, 156),
        (6, 208),
        (6, 234),
        (6, 260),
        (8, 312),
    ]
    .get(usize::from(mcs))
    .ok_or(())?;
    let timing = super::vht_timing::Timing::new(
        legacy.rate_bps,
        legacy.psdu_bytes,
        1,
        fields.short_guard_interval,
        fields.short_gi_disambiguation,
        false,
    )
    .map_err(|_| ())?;
    let count = timing.data_symbols * ndbps;
    let psdu_bytes = count.checked_sub(22).ok_or(())? / 8;
    let data_offset = timing.data_start.checked_sub(320).ok_or(())?;
    let end_offset = timing.data_end.checked_sub(320).ok_or(())?;
    let info = SignalInfo {
        rate_bps: (ndbps as u64 * 20_000_000 / if fields.short_guard_interval { 72 } else { 80 })
            as u32,
        coded_bits_per_symbol: 52 * nbpsc,
        data_bits_per_symbol: ndbps,
        psdu_bytes,
        data_symbols: timing.data_symbols,
        data_start: a.signal_start.checked_add(data_offset as u64).ok_or(())?,
        end_sample_index: a.signal_start.checked_add(end_offset as u64).ok_or(())?,
    };
    let trained = super::ht::train_single_stream(
        samples.get(320..400).ok_or(())?,
        a.signal_start.checked_add(320).ok_or(())?,
        a,
    )
    .ok_or(())?;
    let sig_b = signal_b(
        samples.get(400..480).ok_or(())?,
        a.signal_start.checked_add(400).ok_or(())?,
        &trained,
    )
    .ok_or(())?;
    if sig_b.apep_length_bounds().ok_or(())?.0 as usize > psdu_bytes {
        return Err(());
    }
    let (bytes, tracking) = super::data::decode_vht_bcc_data(
        samples.get(data_offset..end_offset).ok_or(())?,
        &trained,
        info,
        if fields.short_guard_interval { 8 } else { 16 },
        sig_b,
    )?;
    Ok(Decoded {
        signal_a: fields,
        signal_b: sig_b,
        info,
        bytes,
        tracking,
    })
}

#[cfg(test)]
#[path = "vht_iq_tests.rs"]
mod tests;
