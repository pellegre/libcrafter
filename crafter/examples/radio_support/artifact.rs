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
pub const SCHEMA: &str = "crafter.radio.receive/v1";
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
pub const MAX_EXAMPLE_BUFFER_SAMPLES: usize = 16_777_216;

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
            || c.max_frame_bytes > 4095
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
