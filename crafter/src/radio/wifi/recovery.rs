//! Bounded DATA retries; integrity-valid bytes always retain their first result.
use super::{ht::ampdu, ofdm::demod::valid_fcs};
use crate::radio::PhyDiagnostic;
use std::ops::Range;

#[derive(Clone, Copy)]
pub(in crate::radio) struct Profile {
    pub track_timing: bool,
    pub pilot_alpha: f32,
    pub decision_iterations: u8,
    /// Equalized pilot sum and boundary-distance metrics without clock fitting.
    pub common_phase: bool,
    pub boundary_metrics: bool,
    pub guard_eighths: u8,
    pub correct_iq: bool,
    pub mmse: bool,
    pub progressive_pilots: bool,
    pub early_training: u8,
}

impl Profile {
    pub const TRACKED: Self = Self {
        track_timing: true,
        pilot_alpha: 0.3,
        decision_iterations: 0,
        common_phase: false,
        boundary_metrics: false,
        guard_eighths: 4,
        correct_iq: false,
        mmse: false,
        progressive_pilots: false,
        early_training: 0,
    };
    const ALL: [Self; 22] = [
        Self {
            track_timing: false,
            pilot_alpha: 1.,
            decision_iterations: 0,
            common_phase: false,
            boundary_metrics: false,
            guard_eighths: 4,
            correct_iq: false,
            mmse: false,
            progressive_pilots: false,
            early_training: 0,
        },
        Self {
            track_timing: true,
            pilot_alpha: 1.,
            decision_iterations: 0,
            common_phase: false,
            boundary_metrics: false,
            guard_eighths: 4,
            correct_iq: false,
            mmse: false,
            progressive_pilots: false,
            early_training: 0,
        },
        Self {
            track_timing: false,
            pilot_alpha: 0.3,
            decision_iterations: 0,
            common_phase: false,
            boundary_metrics: false,
            guard_eighths: 4,
            correct_iq: false,
            mmse: false,
            progressive_pilots: false,
            early_training: 0,
        },
        Self::TRACKED,
        Self {
            decision_iterations: 1,
            ..Self::TRACKED
        },
        Self {
            decision_iterations: 3,
            ..Self::TRACKED
        },
        Self {
            common_phase: true,
            boundary_metrics: true,
            ..Self::TRACKED
        },
        Self {
            common_phase: true,
            boundary_metrics: true,
            track_timing: false,
            ..Self::TRACKED
        },
        Self {
            common_phase: true,
            boundary_metrics: true,
            decision_iterations: 3,
            ..Self::TRACKED
        },
        Self {
            boundary_metrics: true,
            ..Self::TRACKED
        },
        Self {
            boundary_metrics: true,
            decision_iterations: 3,
            ..Self::TRACKED
        },
        Self {
            boundary_metrics: true,
            common_phase: true,
            decision_iterations: 0,
            guard_eighths: 2,
            ..Self::TRACKED
        },
        Self {
            boundary_metrics: true,
            common_phase: false,
            decision_iterations: 3,
            guard_eighths: 2,
            ..Self::TRACKED
        },
        Self {
            boundary_metrics: true,
            common_phase: true,
            decision_iterations: 0,
            guard_eighths: 6,
            ..Self::TRACKED
        },
        Self {
            boundary_metrics: true,
            common_phase: false,
            decision_iterations: 3,
            guard_eighths: 6,
            ..Self::TRACKED
        },
        Self {
            boundary_metrics: true,
            correct_iq: true,
            ..Self::TRACKED
        },
        Self {
            boundary_metrics: true,
            correct_iq: true,
            decision_iterations: 3,
            ..Self::TRACKED
        },
        Self {
            boundary_metrics: true,
            correct_iq: true,
            mmse: true,
            ..Self::TRACKED
        },
        Self {
            boundary_metrics: true,
            correct_iq: true,
            track_timing: false,
            progressive_pilots: true,
            ..Self::TRACKED
        },
        Self {
            boundary_metrics: true,
            early_training: 3,
            common_phase: true,
            guard_eighths: 2,
            ..Self::TRACKED
        },
        Self {
            boundary_metrics: true,
            early_training: 2,
            decision_iterations: 3,
            guard_eighths: 4,
            ..Self::TRACKED
        },
        Self {
            boundary_metrics: true,
            early_training: 1,
            common_phase: true,
            guard_eighths: 1,
            ..Self::TRACKED
        },
    ];
}

pub(in crate::radio) struct DecodeAttempt {
    pub decoded: Result<(Vec<u8>, PhyDiagnostic), ()>,
    pub output_diagnostics: Vec<PhyDiagnostic>,
    pub frame_diagnostics: Vec<PhyDiagnostic>,
    pub failure_diagnostics: Vec<PhyDiagnostic>,
    /// Only members independently verified in an actual attempt may be
    /// published after merging. Re-scanning mixed untrusted bytes is insufficient.
    pub aggregate_members: Option<Vec<Range<usize>>>,
}

impl DecodeAttempt {
    pub fn plain(decoded: Result<(Vec<u8>, PhyDiagnostic), ()>) -> Self {
        Self {
            decoded,
            output_diagnostics: Vec::new(),
            frame_diagnostics: Vec::new(),
            failure_diagnostics: Vec::new(),
            aggregate_members: None,
        }
    }
}

fn members(bytes: &[u8]) -> (Vec<Range<usize>>, bool) {
    let Ok(scan) = ampdu::Scan::new(bytes, 4095) else {
        return (Vec::new(), false);
    };
    let mut ranges = Vec::new();
    let mut complete = true;
    for event in scan {
        match event {
            ampdu::Event::Frame {
                delimiter_offset,
                bytes,
                ..
            } => {
                ranges.push(delimiter_offset..delimiter_offset + 4 + bytes.len());
            }
            ampdu::Event::Empty { .. } => {}
            ampdu::Event::Invalid {
                error: ampdu::Error::TrailingPadding { available: 0..=3 },
                ..
            } => {}
            ampdu::Event::Invalid { .. } => complete = false,
        }
    }
    complete &= !ranges.is_empty();
    (ranges, complete)
}

pub(in crate::radio) fn recover(
    aggregate: bool,
    mut decode: impl FnMut(Profile) -> DecodeAttempt,
) -> DecodeAttempt {
    let mut best: Option<DecodeAttempt> = None;
    let mut trusted: Vec<Range<usize>> = Vec::new();
    let mut attempts = 0;
    for profile in Profile::ALL {
        attempts += 1;
        let current = decode(profile);
        let Ok((bytes, _)) = &current.decoded else {
            if best.is_none() {
                best = Some(current);
            }
            continue;
        };
        if !aggregate {
            if valid_fcs(bytes) {
                best = Some(current);
                break;
            }
            if best.as_ref().map_or(true, |b| b.decoded.is_err()) {
                best = Some(current);
            }
            continue;
        }
        let (ranges, complete) = members(bytes);
        if trusted.is_empty() {
            trusted = ranges;
            best = Some(current);
            if complete {
                break;
            }
            continue;
        }
        // Copy only a checked delimiter and its FCS-valid MPDU. Existing
        // checked members cannot be overwritten by a different hypothesis.
        let previous = best.as_mut().unwrap();
        let (retained, _) = previous.decoded.as_mut().unwrap();
        if retained.len() != bytes.len() {
            continue;
        }
        for range in ranges {
            if trusted
                .iter()
                .any(|old| range.start < old.end && old.start < range.end)
            {
                continue;
            }
            retained[range.clone()].copy_from_slice(&bytes[range.clone()]);
            trusted.push(range);
        }
        if members(retained).1 {
            break;
        }
    }
    let mut result = best.unwrap(); // The profile set is nonempty.
    if attempts > 1 {
        result
            .frame_diagnostics
            .push(PhyDiagnostic::OfdmRecovery { attempts });
        if aggregate {
            trusted.sort_by_key(|range| range.start);
            result.aggregate_members = Some(trusted);
        }
    }
    result
}

#[cfg(all(test, not(crafter_packaged)))]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        let row = include_str!("../../../tests/fixtures/iq/ampdu-index.tsv")
            .lines()
            .find(|line| line.starts_with(&format!("{name}\t")))
            .unwrap();
        row.split('\t')
            .nth(1)
            .unwrap()
            .as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    }

    fn attempt(bytes: Vec<u8>) -> DecodeAttempt {
        DecodeAttempt::plain(Ok((
            bytes,
            PhyDiagnostic::OfdmTracking {
                sampling_clock_offset_ppm: Some(0.),
                pilot_residual_rms_rad: 0.,
                data_symbols: 10,
            },
        )))
    }

    fn rewrite_fcs(bytes: &mut [u8]) {
        let split = bytes.len() - 4;
        let mut crc = !0u32;
        for byte in &bytes[..split] {
            crc ^= *byte as u32;
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0xedb88320 & 0u32.wrapping_sub(crc & 1));
            }
        }
        bytes[split..].copy_from_slice(&(!crc).to_le_bytes());
    }

    #[test]
    fn radio_recovery_retains_original_and_complementary_aggregate_members() {
        for name in ["alignments", "duplicate"] {
            let original = fixture(name);
            let (ranges, complete) = members(&original);
            assert!(complete && ranges.len() >= 2);
            let mut first = original.clone();
            let mut second = original.clone();
            for (index, range) in ranges.iter().enumerate() {
                if index % 2 == 1 {
                    first[range.start + 4] ^= 1;
                } else {
                    // A different, FCS-valid alternative at an already checked
                    // offset must not replace the first recovered MPDU.
                    second[range.start + 4] ^= 2;
                    rewrite_fcs(&mut second[range.start + 4..range.end]);
                }
            }
            let mut calls = 0;
            let recovered = recover(true, |_| {
                calls += 1;
                attempt(if calls == 1 {
                    first.clone()
                } else {
                    second.clone()
                })
            });
            assert_eq!(calls, 2);
            assert_eq!(recovered.aggregate_members.as_ref(), Some(&ranges));
            assert_eq!(recovered.decoded.unwrap().0, original);
            assert!(recovered
                .frame_diagnostics
                .contains(&PhyDiagnostic::OfdmRecovery { attempts: 2 }));
        }
    }

    #[test]
    fn radio_recovery_stops_at_first_valid_psdu_and_bounds_failures() {
        let bytes = include_bytes!("../../../tests/fixtures/iq/ofdm-tx-6.psdu").to_vec();
        let mut calls = 0;
        let recovered = recover(false, |_| {
            calls += 1;
            attempt(bytes.clone())
        });
        assert_eq!(calls, 1);
        assert_eq!(recovered.decoded.unwrap().0, bytes);
        assert!(recovered.frame_diagnostics.is_empty());

        let mut bad = bytes.clone();
        bad[0] ^= 1;
        calls = 0;
        let recovered = recover(false, |_| {
            calls += 1;
            attempt(if calls == 1 {
                bad.clone()
            } else {
                bytes.clone()
            })
        });
        assert_eq!(calls, 2);
        assert_eq!(recovered.decoded.unwrap().0, bytes);

        calls = 0;
        let failed = recover(false, |_| {
            calls += 1;
            DecodeAttempt::plain(Err(()))
        });
        assert_eq!(calls, Profile::ALL.len());
        assert!(failed.decoded.is_err());
    }
}
