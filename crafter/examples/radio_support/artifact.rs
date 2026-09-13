//! Example-local artifact vocabulary. No network or device access.
#![allow(dead_code)]
use crafter::radio::*;
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    io::{BufRead, Write},
    time::{Duration, SystemTime},
};
pub type Result<T> = std::result::Result<T, Box<dyn Error>>;
pub const SCHEMA: &str = "crafter.radio.receive/v2";
pub fn supported_schema(v: &serde_json::Value) -> bool {
    v == SCHEMA || v == "crafter.radio.receive/v1"
}
pub fn phy_family(rate: u32) -> &'static str {
    match rate {
        1_000_000 | 2_000_000 => "dsss",
        5_500_000 | 11_000_000 => "cck",
        6_000_000 | 9_000_000 | 12_000_000 | 18_000_000 | 24_000_000 | 36_000_000 | 48_000_000
        | 54_000_000 => "legacy_ofdm",
        _ => "unknown",
    }
}
/// PHY family comes from validated signaling when available, not rate guessing.
pub fn frame_phy(frame: &RecoveredFrame) -> &'static str {
    if frame.diagnostics.iter().any(|d| {
        matches!(
            d,
            PhyDiagnostic::HeSignal { .. }
                | PhyDiagnostic::HeErSignal { .. }
                | PhyDiagnostic::HeMuSignal { .. }
        )
    }) {
        return "he";
    }
    if frame
        .diagnostics
        .iter()
        .any(|d| matches!(d, PhyDiagnostic::VhtSignalA { .. }))
    {
        "vht"
    } else if frame
        .diagnostics
        .iter()
        .any(|d| matches!(d, PhyDiagnostic::HtSignal { .. }))
    {
        "ht"
    } else {
        phy_family(frame.rate_bps)
    }
}
pub fn he_signal_metadata(f: &HeSuSignalFields, preamble_sample_index: u64) -> serde_json::Value {
    serde_json::json!({"format":"su", "mcs":f.mcs, "bandwidth_code":f.bandwidth,
        "space_time_streams":f.space_time_streams, "guard_interval_ns":f.guard_ns,
        "ltf_size":f.ltf_size, "coding":if f.ldpc {"ldpc"} else {"bcc"},
        "dcm":f.dcm, "stbc":f.stbc, "midamble_period":f.midamble_period,
        "bss_color":f.bss_color, "uplink":f.uplink, "beam_change":f.beam_change,
        "beamformed":f.beamformed, "spatial_reuse":f.spatial_reuse, "txop":f.txop,
        "pre_fec_padding":f.pre_fec_padding, "pe_disambiguity":f.pe_disambiguity,
        "ldpc_extra_segment":f.ldpc_extra_segment, "preamble_sample_index":preamble_sample_index})
}
pub fn he_er_signal_metadata(
    f: &HeSuSignalFields,
    preamble_sample_index: u64,
) -> serde_json::Value {
    let mut metadata = he_signal_metadata(f, preamble_sample_index);
    metadata["format"] = "er_su".into();
    metadata["ru_tones"] = (if f.bandwidth == 0 { 242 } else { 106 }).into();
    metadata["channel_width_mhz"] = 20.into();
    metadata
}
pub fn he_mu_signal_metadata(
    f: &HeMuSignalFields,
    preamble_sample_index: u64,
) -> serde_json::Value {
    serde_json::json!({"format":"mu", "bandwidth_code":f.bandwidth,
        "sig_b_mcs":f.sig_b_mcs, "sig_b_dcm":f.sig_b_dcm,
        "sig_b_compression":f.sig_b_compression,
        "sig_b_symbols_or_users_raw":f.sig_b_symbols_or_users,
        "ltf_size":f.ltf_size, "ltf_symbols":f.ltf_symbols,
        "guard_interval_ns":f.guard_ns, "midamble_period":f.midamble_period,
        "bss_color":f.bss_color, "uplink":f.uplink, "spatial_reuse":f.spatial_reuse,
        "txop":f.txop, "stbc":f.stbc, "pre_fec_padding":f.pre_fec_padding,
        "pe_disambiguity":f.pe_disambiguity, "ldpc_extra_segment":f.ldpc_extra_segment,
        "preamble_sample_index":preamble_sample_index})
}
pub fn he_metadata(frame: &RecoveredFrame) -> Option<serde_json::Value> {
    frame.diagnostics.iter().find_map(|d| match d {
        PhyDiagnostic::HeMuSignal {
            fields,
            preamble_sample_index,
        } => Some(he_mu_signal_metadata(fields, *preamble_sample_index)),
        PhyDiagnostic::HeSignal {
            fields,
            preamble_sample_index,
        } => Some(he_signal_metadata(fields, *preamble_sample_index)),
        PhyDiagnostic::HeErSignal {
            fields,
            preamble_sample_index,
        } => Some(he_er_signal_metadata(fields, *preamble_sample_index)),
        _ => None,
    })
}
pub fn vht_metadata(frame: &RecoveredFrame) -> Option<serde_json::Value> {
    frame.diagnostics.iter().find_map(|d| match d {
        PhyDiagnostic::VhtSignalA {
            fields: f,
            preamble_sample_index,
        } => {
            let VhtSignalAUsers::Single {
                space_time_streams,
                mcs,
                ldpc,
                beamformed,
                partial_aid,
            } = f.users
            else {
                return None;
            };
            let sig_b = frame.diagnostics.iter().find_map(|d| match d {
                PhyDiagnostic::VhtSignalB {
                    fields,
                    preamble_sample_index: index,
                } if index == preamble_sample_index => fields.apep_length_bounds(),
                _ => None,
            });
            Some(serde_json::json!({
                "mcs":mcs, "bandwidth_code":f.bandwidth_code,
                "space_time_streams":space_time_streams, "stbc":f.stbc,
                "coding":if ldpc {"ldpc"} else {"bcc"},
                "guard_interval_ns":if f.short_guard_interval {400} else {800},
                "short_gi_disambiguation":f.short_gi_disambiguation,
                "txop_ps_not_allowed":f.txop_ps_not_allowed, "ldpc_extra_symbol":f.ldpc_extra_symbol,
                "group_id":f.group_id, "partial_aid":partial_aid, "beamformed":beamformed,
                "apep_length_bounds":sig_b, "service_crc_verified":sig_b.is_some(),
                "preamble_sample_index":preamble_sample_index,
            }))
        }
        _ => None,
    })
}
pub fn ht_metadata(frame: &RecoveredFrame) -> Option<serde_json::Value> {
    frame.diagnostics.iter().find_map(|d| match d {
        PhyDiagnostic::HtSignal {
            fields: f,
            preamble_sample_index,
        } => {
            let mut metadata = ht_signal_metadata(f, *preamble_sample_index);
            if frame.diagnostics.iter().any(|d| matches!(d,
                PhyDiagnostic::HtGreenfield { preamble_sample_index: index } if index == preamble_sample_index)) {
                metadata["format"] = "greenfield".into();
            }
            Some(metadata)
        },
        _ => None,
    })
}
pub fn ht_signal_metadata(f: &HtSignalFields, preamble_sample_index: u64) -> serde_json::Value {
    serde_json::json!({
        "mcs":f.mcs, "bandwidth_mhz":if f.channel_width_40_mhz {40} else {20},
        "psdu_bytes":f.psdu_bytes, "smoothing":f.smoothing, "not_sounding":f.not_sounding,
        "aggregation":f.aggregation, "stbc":f.stbc, "coding":if f.ldpc {"ldpc"} else {"bcc"},
        "guard_interval_ns":if f.short_guard_interval {400} else {800},
        "extension_spatial_streams":f.extension_spatial_streams,
        "preamble_sample_index":preamble_sample_index,
    })
}
pub fn ampdu_metadata(frame: &RecoveredFrame) -> Option<serde_json::Value> {
    frame.diagnostics.iter().find_map(|d| match d {
        PhyDiagnostic::Ampdu {
            delimiter_offset,
            control_bits,
        } => Some(serde_json::json!({
            "delimiter_offset":delimiter_offset, "control_bits":control_bits,
        })),
        _ => None,
    })
}
pub const MAX_LINE: usize = 1_048_576;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub sample_rate_hz: u32,
    pub center_frequency_hz: u64,
    pub max_chunk_samples: usize,
    pub max_buffer_samples: usize,
    pub max_frame_bytes: usize,
    pub max_pending_frames: usize,
    pub max_capture_samples: u64,
    pub max_duration_ns: u64,
}
impl From<&RxConfig> for Config {
    fn from(c: &RxConfig) -> Self {
        Self {
            sample_rate_hz: c.sample_rate_hz,
            center_frequency_hz: c.center_frequency_hz,
            max_chunk_samples: c.max_chunk_samples,
            max_buffer_samples: c.max_buffer_samples,
            max_frame_bytes: c.max_frame_bytes,
            max_pending_frames: c.max_pending_frames,
            max_capture_samples: c.max_capture_samples,
            max_duration_ns: c.max_duration.as_nanos().min(u64::MAX as u128) as u64,
        }
    }
}
// At most 1 GiB of queued CS8 data, excluding chunk metadata and decoder state.
// This is an opt-in ceiling, not an allocation or the default queue size.
pub const MAX_EXAMPLE_BUFFER_SAMPLES: usize = 536_870_912;

impl Config {
    pub fn rx(&self) -> Result<RxConfig> {
        let c = RxConfig {
            sample_rate_hz: self.sample_rate_hz,
            center_frequency_hz: self.center_frequency_hz,
            max_chunk_samples: self.max_chunk_samples,
            max_buffer_samples: self.max_buffer_samples,
            max_frame_bytes: self.max_frame_bytes,
            max_pending_frames: self.max_pending_frames,
            max_capture_samples: self.max_capture_samples,
            max_duration: Duration::from_nanos(self.max_duration_ns),
        };
        c.validate()?;
        // Example-side limits keep untrusted artifact metadata from requesting huge allocations.
        if c.max_chunk_samples > 262_144
            || c.max_buffer_samples > MAX_EXAMPLE_BUFFER_SAMPLES
            || c.max_frame_bytes > 16383
            || c.max_pending_frames > 1024
        {
            return Err("artifact allocation bounds exceeded".into());
        }
        Ok(c)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Anchor {
    pub sample_index: u64,
    pub unix_ns: u64,
    pub uncertainty_ns: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Position {
    pub epoch: u64,
    pub sequence: u64,
    pub sample_index: u64,
    pub anchor: Option<Anchor>,
    pub gap_reason: Option<String>,
    pub lost_samples: Option<u64>,
}
impl From<&IqPosition> for Position {
    fn from(p: &IqPosition) -> Self {
        Self {
            epoch: p.epoch,
            sequence: p.sequence,
            sample_index: p.sample_index,
            anchor: p.time_anchor.as_ref().map(|a| Anchor {
                sample_index: a.sample_index,
                unix_ns: unix_ns(a.time),
                uncertainty_ns: a.uncertainty.as_nanos().min(u64::MAX as u128) as u64,
            }),
            gap_reason: p.discontinuity.map(|d| format!("{:?}", d.reason)),
            lost_samples: p.discontinuity.and_then(|d| {
                if let SampleLoss::Known(n) = d.loss {
                    Some(n)
                } else {
                    None
                }
            }),
        }
    }
}
impl Position {
    pub fn iq(&self) -> Result<IqPosition> {
        Ok(IqPosition {
            epoch: self.epoch,
            sequence: self.sequence,
            sample_index: self.sample_index,
            time_anchor: self.anchor.as_ref().map(|a| TimeAnchor {
                sample_index: a.sample_index,
                time: SystemTime::UNIX_EPOCH + Duration::from_nanos(a.unix_ns),
                uncertainty: Duration::from_nanos(a.uncertainty_ns),
            }),
            discontinuity: match self.gap_reason.as_deref() {
                None => None,
                Some(s) => Some(Discontinuity {
                    reason: match s {
                        "SourceLoss" => GapReason::SourceLoss,
                        "QueueOverflow" => GapReason::QueueOverflow,
                        "Reconfiguration" => GapReason::Reconfiguration,
                        "Reordered" => GapReason::Reordered,
                        _ => return Err("unknown gap reason".into()),
                    },
                    loss: self
                        .lost_samples
                        .map(SampleLoss::Known)
                        .unwrap_or(SampleLoss::Unknown),
                }),
            },
        })
    }
}
pub fn unix_ns(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(u64::MAX as u128) as u64
}
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 15) as usize] as char);
    }
    encoded
}
pub fn unhex(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 || !s.is_ascii() {
        return Err("invalid hex length or encoding".into());
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|c| Ok(u8::from_str_radix(std::str::from_utf8(c)?, 16)?))
        .collect()
}
pub fn write_json(w: &mut impl Write, v: &impl Serialize) -> Result<()> {
    serde_json::to_writer(&mut *w, v)?;
    w.write_all(b"\n")?;
    Ok(())
}
pub fn read_json(r: &mut impl BufRead) -> Result<Option<serde_json::Value>> {
    let mut line = Vec::new();
    let n = std::io::Read::take(&mut *r, (MAX_LINE + 1) as u64).read_until(b'\n', &mut line)?;
    if n == 0 {
        return Ok(None);
    }
    if n > MAX_LINE || line.last() != Some(&b'\n') {
        return Err("oversize or incomplete JSON line".into());
    }
    Ok(Some(serde_json::from_slice(&line)?))
}
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut c = !0u32;
    for b in bytes {
        c ^= *b as u32;
        for _ in 0..8 {
            c = (c >> 1) ^ if c & 1 != 0 { 0xedb88320 } else { 0 };
        }
    }
    !c
}
pub fn valid_fcs(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && crc32(&bytes[..bytes.len() - 4]).to_le_bytes() == bytes[bytes.len() - 4..]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn radio_artifact_vht_frame_allocation_bounds() {
        let mut config = Config::from(&RxConfig {
            sample_rate_hz: 20_000_000,
            center_frequency_hz: 5_180_000_000,
            max_chunk_samples: 128,
            max_buffer_samples: 120_000,
            max_frame_bytes: 4095,
            max_pending_frames: 8,
            max_capture_samples: 1_000_000,
            max_duration: Duration::from_secs(1),
        });
        for limit in [4095, 4096, 16383] {
            config.max_frame_bytes = limit;
            assert_eq!(config.rx().unwrap().max_frame_bytes, limit);
        }
        for limit in [0, 16384, usize::MAX] {
            config.max_frame_bytes = limit;
            assert!(config.rx().is_err(), "limit={limit}");
        }
    }
}
