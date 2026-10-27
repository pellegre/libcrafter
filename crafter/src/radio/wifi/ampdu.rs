//! HT and VHT A-MPDU framing, IEEE 802.11-2020 9.7.1–2 and informative Annex O.2.
//! Only FCS-valid MPDUs are emitted. Bad FCS resumes four-byte scanning too,
//! so a false delimiter cannot hide a later valid MPDU inside its stated span.
use crate::radio::{DecodeOutput, PhyDiagnostic, RadioError, RadioResult, RecoveredFrame};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio::wifi) enum Error {
    AggregateLength { limit: usize, available: usize },
    TruncatedDelimiter { required: usize, available: usize },
    Signature { received: u8 },
    Crc { expected: u8, received: u8 },
    TruncatedMpdu { required: usize, available: usize },
    MpduLimit { limit: usize, available: usize },
    BadFcs,
    VhtOrder,
    ReservedBit,
    TrailingPadding { available: usize },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Delimiter {
    pub mpdu_bytes: usize,
    /// Preserve the low nibble; HT length does not use the VHT high-length bits.
    pub control_bits: u8,
}
impl Delimiter {
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        Self::decode_format(bytes, false)
    }
    pub(in crate::radio::wifi) fn decode_format(bytes: &[u8], vht: bool) -> Result<Self, Error> {
        if bytes.len() < 4 {
            return Err(Error::TruncatedDelimiter {
                required: 4,
                available: bytes.len(),
            });
        }
        if bytes[3] != 0x4e {
            return Err(Error::Signature { received: bytes[3] });
        }
        let bits = std::array::from_fn::<_, 16, _>(|i| (bytes[i / 8] >> (i % 8)) & 1);
        // C7 is B16, the first transmitted (low) bit of the CRC octet.
        let expected = super::ht::crc(&bits).reverse_bits();
        if bytes[2] != expected {
            return Err(Error::Crc {
                expected,
                received: bytes[2],
            });
        }
        let header = u16::from_le_bytes([bytes[0], bytes[1]]);
        Ok(Self {
            mpdu_bytes: usize::from(header >> 4)
                | if vht {
                    usize::from(header & 12) << 10
                } else {
                    0
                },
            control_bits: bytes[0] & 15,
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio::wifi) enum Event<'a> {
    Frame {
        delimiter_offset: usize,
        control_bits: u8,
        bytes: &'a [u8],
    },
    Empty {
        delimiter_offset: usize,
    },
    Invalid {
        offset: usize,
        error: Error,
    },
}
pub(in crate::radio::wifi) struct Scan<'a> {
    bytes: &'a [u8],
    offset: usize,
    max_mpdu: usize,
    pending: Option<Event<'a>>,
    vht: bool,
    eof: bool,
    smpdu: bool,
    frames: usize,
}
impl<'a> Scan<'a> {
    pub(in crate::radio::wifi) fn new(bytes: &'a [u8], max_mpdu: usize) -> Result<Self, Error> {
        Self::with_format(bytes, max_mpdu, false)
    }
    pub(in crate::radio::wifi) fn vht(bytes: &'a [u8], max_mpdu: usize) -> Result<Self, Error> {
        Self::with_format(bytes, max_mpdu, true)
    }
    fn with_format(bytes: &'a [u8], max_mpdu: usize, vht: bool) -> Result<Self, Error> {
        let limit = if vht { 1_048_575 } else { 65535 };
        if bytes.len() > limit {
            return Err(Error::AggregateLength {
                limit,
                available: bytes.len(),
            });
        }
        Ok(Self {
            bytes,
            offset: 0,
            max_mpdu,
            pending: None,
            vht,
            eof: false,
            smpdu: false,
            frames: 0,
        })
    }
}
impl<'a> Iterator for Scan<'a> {
    type Item = Event<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(event) = self.pending.take() {
            return Some(event);
        }
        let offset = self.offset;
        if offset >= self.bytes.len() {
            return None;
        }
        if self.bytes.len() - offset < 4 {
            self.offset = self.bytes.len();
            if self.vht {
                return None;
            }
            return Some(Event::Invalid {
                offset,
                error: Error::TruncatedDelimiter {
                    required: 4,
                    available: self.bytes.len() - offset,
                },
            });
        }
        self.offset += 4; // Resynchronize on the next aligned candidate after errors.
        let parsed = if self.vht {
            Delimiter::decode_format(&self.bytes[offset..offset + 4], true)
        } else {
            Delimiter::decode(&self.bytes[offset..offset + 4])
        };
        let delimiter = match parsed {
            Ok(d) => d,
            Err(error) => return Some(Event::Invalid { offset, error }),
        };
        let eof = delimiter.control_bits & 1 != 0;
        if self.vht {
            if delimiter.control_bits & 2 != 0 {
                return Some(Event::Invalid {
                    offset,
                    error: Error::ReservedBit,
                });
            }
            if (self.eof && !eof)
                || (delimiter.mpdu_bytes != 0 && (self.smpdu || (eof && self.frames != 0)))
            {
                return Some(Event::Invalid {
                    offset,
                    error: Error::VhtOrder,
                });
            }
        }
        if delimiter.mpdu_bytes == 0 {
            if self.vht && eof {
                self.eof = true;
            }
            return Some(Event::Empty {
                delimiter_offset: offset,
            });
        }
        let available = self.bytes.len() - (offset + 4);
        if delimiter.mpdu_bytes > available {
            return Some(Event::Invalid {
                offset,
                error: Error::TruncatedMpdu {
                    required: delimiter.mpdu_bytes,
                    available,
                },
            });
        }
        if delimiter.mpdu_bytes > self.max_mpdu {
            return Some(Event::Invalid {
                offset,
                error: Error::MpduLimit {
                    limit: self.max_mpdu,
                    available: delimiter.mpdu_bytes,
                },
            });
        }
        let end = offset + 4 + delimiter.mpdu_bytes;
        let bytes = &self.bytes[offset + 4..end];
        if !super::ofdm::demod::valid_fcs(bytes) {
            return Some(Event::Invalid {
                offset,
                error: Error::BadFcs,
            });
        }
        if self.vht {
            self.frames += 1;
            self.eof = eof;
            self.smpdu = eof;
        }
        self.offset = end;
        if end < self.bytes.len() {
            let padding = (4 - end % 4) % 4;
            if self.vht {
                self.offset += padding.min(self.bytes.len() - end);
            } else if self.bytes.len() - end <= padding {
                self.pending = Some(Event::Invalid {
                    offset: end,
                    error: Error::TrailingPadding {
                        available: self.bytes.len() - end,
                    },
                });
                self.offset = self.bytes.len();
            } else {
                self.offset += padding;
            }
        }
        Some(Event::Frame {
            delimiter_offset: offset,
            control_bits: delimiter.control_bits,
            bytes,
        })
    }
}

#[cfg(all(test, not(crafter_packaged)))]
mod tests {
    use super::*;
    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    }
    #[test]
    fn radio_ampdu_independent_delimiter_crc_and_fields() {
        let rows: Vec<_> = include_str!("../../../tests/fixtures/iq/ampdu-delimiters.tsv")
            .lines()
            .skip(1)
            .collect();
        assert_eq!(rows.len(), 4096);
        for row in rows {
            let c: Vec<_> = row.split('\t').collect();
            let bytes = hex(c[0]);
            assert_eq!(
                Delimiter::decode(&bytes).unwrap(),
                Delimiter {
                    mpdu_bytes: c[1].parse().unwrap(),
                    control_bits: c[2].parse().unwrap()
                }
            );
            for bit in 0..32 {
                let mut bad = bytes.clone();
                bad[bit / 8] ^= 1 << (bit % 8);
                assert!(Delimiter::decode(&bad).is_err(), "{row}, bit={bit}");
            }
        }
        for count in 0..4 {
            assert_eq!(
                Delimiter::decode(&[0; 4][..count]),
                Err(Error::TruncatedDelimiter {
                    required: 4,
                    available: count
                })
            );
        }
    }
    #[test]
    fn radio_ampdu_independent_boundaries_and_resynchronization() {
        let rows: Vec<_> = include_str!("../../../tests/fixtures/iq/ampdu-index.tsv")
            .lines()
            .skip(1)
            .collect();
        assert_eq!(rows.len(), 9);
        for row in rows {
            let c: Vec<_> = row.split('\t').collect();
            let bytes = hex(c[1]);
            let offsets: Vec<usize> = c[2].split(',').map(|s| s.parse().unwrap()).collect();
            let expected: Vec<Vec<u8>> = c[3].split(',').map(hex).collect();
            let events: Vec<_> = Scan::new(&bytes, 4095).unwrap().collect();
            let actual: Vec<_> = events
                .iter()
                .filter_map(|e| match e {
                    Event::Frame {
                        delimiter_offset,
                        bytes,
                        ..
                    } => Some((delimiter_offset + 4, bytes.to_vec())),
                    _ => None,
                })
                .collect();
            assert_eq!(
                actual,
                offsets.into_iter().zip(expected).collect::<Vec<_>>(),
                "{}",
                c[0]
            );
            if c[0].starts_with("bad_")
                || c[0].starts_with("truncated_")
                || c[0] == "false_long_delimiter"
            {
                assert!(
                    events.iter().any(|e| matches!(e, Event::Invalid { .. })),
                    "{}",
                    c[0]
                );
            }
            let limited: Vec<_> = Scan::new(&bytes, 1).unwrap().collect();
            assert!(!limited.iter().any(|e| matches!(e, Event::Frame { .. })));
        }
        assert!(matches!(
            Scan::new(&vec![0; 65536], 4095),
            Err(Error::AggregateLength { .. })
        ));
        assert!(Scan::new(&[], 4095).unwrap().next().is_none());
    }
}

pub(in crate::radio) struct AggregateCounts {
    pub valid_frames: u64,
    pub invalid_fcs: u64,
}

pub(in crate::radio) fn publish(
    mut frame: RecoveredFrame,
    limit: usize,
    out: &mut DecodeOutput,
    members: Option<&[std::ops::Range<usize>]>,
    vht: bool,
) -> RadioResult<AggregateCounts> {
    let bytes = std::mem::take(&mut frame.bytes);
    let scan = (if vht {
        Scan::vht(&bytes, frame.config.max_frame_bytes)
    } else {
        Scan::new(&bytes, frame.config.max_frame_bytes)
    })
    .map_err(|_| RadioError::Limit {
        context: if vht {
            "VHT aggregate bytes"
        } else {
            "HT aggregate bytes"
        },
        limit: if vht { 1_048_575 } else { 65535 },
        actual: bytes.len() as u64,
    })?;
    let (mut delimiters, mut fcs, mut truncated, mut oversized) = (0, 0, 0, 0);
    let mut valid_frames = 0u64;
    let verified = members.into_iter().flatten().map(|range| {
        // Ranges originate in Scan and are retained only across equal-length
        // PSDUs. Their complete checked delimiter and MPDU bytes stay intact.
        let member = &bytes[range.clone()];
        let delimiter = Delimiter::decode_format(&member[..4], vht).unwrap();
        Event::Frame {
            delimiter_offset: range.start,
            control_bits: delimiter.control_bits,
            bytes: &member[4..],
        }
    });
    for event in scan
        .filter(|event| members.is_none() || !matches!(event, Event::Frame { .. }))
        .chain(verified)
    {
        match event {
            Event::Frame {
                delimiter_offset,
                control_bits,
                bytes,
            } => {
                if out.frames.len() >= limit {
                    return Err(RadioError::Limit {
                        context: if vht {
                            "VHT aggregate pending frames"
                        } else {
                            "HT aggregate pending frames"
                        },
                        limit: limit as u64,
                        actual: (out.frames.len() + 1) as u64,
                    });
                }
                let mut recovered = frame.clone();
                recovered.bytes = bytes.to_vec();
                recovered.diagnostics.push(PhyDiagnostic::Ampdu {
                    delimiter_offset,
                    control_bits,
                });
                out.frames.push(recovered);
                valid_frames = valid_frames.saturating_add(1);
            }
            Event::Empty { .. } => {}
            Event::Invalid { error, .. } => match error {
                Error::BadFcs => fcs += 1,
                Error::TruncatedMpdu { .. } => truncated += 1,
                Error::MpduLimit { .. } => oversized += 1,
                _ => delimiters += 1,
            },
        }
    }
    if delimiters + fcs + truncated + oversized != 0 {
        out.diagnostics.push(PhyDiagnostic::AmpduErrors {
            preamble_sample_index: frame.start.sample_index,
            invalid_delimiters: delimiters,
            invalid_fcs: fcs,
            truncated_mpdus: truncated,
            oversized_mpdus: oversized,
        });
    }
    Ok(AggregateCounts {
        valid_frames,
        invalid_fcs: fcs as u64,
    })
}
