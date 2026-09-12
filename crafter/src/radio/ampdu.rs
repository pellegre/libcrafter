//! HT/VHT A-MPDU framing, IEEE 802.11-2020 9.7.1–2, 10.12.6–8 and Annex O.2.
//! Only FCS-valid MPDUs are emitted. Bad FCS resumes four-byte scanning too,
//! so a false delimiter cannot hide a later valid MPDU inside its stated span.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Error {
    AggregateLength { limit: usize, available: usize },
    TruncatedDelimiter { required: usize, available: usize },
    Signature { received: u8 },
    Crc { expected: u8, received: u8 },
    TruncatedMpdu { required: usize, available: usize },
    MpduLimit { limit: usize, available: usize },
    BadFcs,
    TrailingPadding { available: usize },
    EofOrder,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Delimiter {
    pub mpdu_bytes: usize,
    /// Preserve the low nibble; HT length does not use the VHT high-length bits.
    pub control_bits: u8,
}
impl Delimiter {
    pub(super) fn decode_vht(bytes: &[u8]) -> Result<Self, Error> {
        let mut delimiter = Self::decode(bytes)?;
        delimiter.mpdu_bytes |= usize::from(delimiter.control_bits & 12) << 10;
        // Unlike HT, these two bits belong to the length, not reserved flags.
        delimiter.control_bits &= 3;
        Ok(delimiter)
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, Error> {
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
            mpdu_bytes: usize::from(header >> 4),
            control_bits: bytes[0] & 15,
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Event<'a> {
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
pub(super) struct Scan<'a> {
    bytes: &'a [u8],
    offset: usize,
    max_mpdu: usize,
    pending: Option<Event<'a>>,
    vht: bool,
    eof: bool,
    frame_seen: bool,
}
impl<'a> Scan<'a> {
    pub(super) fn new(bytes: &'a [u8], max_mpdu: usize) -> Result<Self, Error> {
        if bytes.len() > 65535 {
            return Err(Error::AggregateLength {
                limit: 65535,
                available: bytes.len(),
            });
        }
        Ok(Self {
            bytes,
            offset: 0,
            max_mpdu,
            pending: None,
            vht: false,
            eof: false,
            frame_seen: false,
        })
    }
    /// Borrow an already bounded PSDU. VHT's pre-EOF length constraint must
    /// be enforced by PHY admission, not by applying HT's total byte limit.
    pub(super) fn vht(bytes: &'a [u8], max_mpdu: usize) -> Self {
        Self {
            bytes,
            offset: 0,
            max_mpdu,
            pending: None,
            vht: true,
            eof: false,
            frame_seen: false,
        }
    }
    fn accept_order(&mut self, delimiter: Delimiter) -> bool {
        let eof = delimiter.control_bits & 1 != 0;
        if self.vht
            && ((self.eof && (!eof || delimiter.mpdu_bytes != 0))
                || (self.frame_seen && eof && delimiter.mpdu_bytes != 0))
        {
            self.offset = self.bytes.len();
            return false;
        }
        self.eof |= self.vht && eof;
        self.frame_seen |= delimiter.mpdu_bytes != 0;
        true
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
            if self.vht && (self.frame_seen || self.eof) {
                return None; // 0..3 EOF padding octets, content unspecified.
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
        let delimiter = match if self.vht {
            Delimiter::decode_vht(&self.bytes[offset..offset + 4])
        } else {
            Delimiter::decode(&self.bytes[offset..offset + 4])
        } {
            Ok(d) => d,
            Err(error) => return Some(Event::Invalid { offset, error }),
        };
        if delimiter.mpdu_bytes == 0 {
            if !self.accept_order(delimiter) {
                return Some(Event::Invalid {
                    offset,
                    error: Error::EofOrder,
                });
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
        if !super::data::valid_fcs(bytes) {
            return Some(Event::Invalid {
                offset,
                error: Error::BadFcs,
            });
        }
        // A false delimiter with a bad MPDU must not poison EOF state and
        // hide a later FCS-valid frame during aligned resynchronization.
        if !self.accept_order(delimiter) {
            return Some(Event::Invalid {
                offset,
                error: Error::EofOrder,
            });
        }
        self.offset = end;
        if end < self.bytes.len() {
            let padding = (4 - end % 4) % 4;
            if self.bytes.len() - end <= padding {
                if !self.vht {
                    self.pending = Some(Event::Invalid {
                        offset: end,
                        error: Error::TrailingPadding {
                            available: self.bytes.len() - end,
                        },
                    });
                }
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

#[cfg(test)]
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
    fn radio_vht_ampdu_independent_delimiters() {
        let rows = include_str!("../../tests/fixtures/iq/vht-ampdu-delimiters.tsv");
        assert_eq!(rows.lines().skip(1).count(), 16384);
        for row in rows.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let bytes = hex(c[0]);
            let length = c[1].parse::<usize>().unwrap();
            let flags = c[2].parse::<u8>().unwrap();
            assert_eq!(
                Delimiter::decode_vht(&bytes),
                Ok(Delimiter {
                    mpdu_bytes: length,
                    control_bits: flags,
                })
            );
            // The same wire bytes intentionally have different HT semantics.
            assert_eq!(Delimiter::decode(&bytes).unwrap().mpdu_bytes, length & 4095);
            for bit in 0..32 {
                let mut bad = bytes.clone();
                bad[bit / 8] ^= 1 << (bit % 8);
                assert!(Delimiter::decode_vht(&bad).is_err(), "{row}, bit={bit}");
            }
        }
        for count in 0..4 {
            assert!(Delimiter::decode_vht(&[0; 4][..count]).is_err());
        }
    }
    #[test]
    fn radio_vht_ampdu_independent_recovery() {
        let rows = include_str!("../../tests/fixtures/iq/vht-ampdu-index.tsv");
        assert_eq!(rows.lines().skip(1).count(), 144);
        for row in rows.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let bytes = hex(c[1]);
            let offsets = c[2]
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.parse::<usize>().unwrap());
            let frames = c[3].split(',').filter(|s| !s.is_empty()).map(hex);
            let events: Vec<_> = Scan::vht(&bytes, 16383).collect();
            assert!(events.len() <= bytes.len().div_ceil(4) + 1);
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
            assert_eq!(actual, offsets.zip(frames).collect::<Vec<_>>(), "{}", c[0]);
            assert_eq!(
                events.iter().any(|e| matches!(e, Event::Invalid { .. })),
                c[4] == "1",
                "{}: {events:?}",
                c[0]
            );
            if c[0].starts_with("after-smpdu-")
                || c[0].contains("after-eof-padding")
                || c[0] == "smpdu-after-frame"
            {
                assert!(
                    matches!(
                        events.last(),
                        Some(Event::Invalid {
                            error: Error::EofOrder,
                            ..
                        })
                    ),
                    "{}",
                    c[0]
                );
            }
            assert!(!Scan::vht(&bytes, 1).any(|e| matches!(e, Event::Frame { .. })));
        }
        assert!(Scan::vht(&[], 16383).next().is_none());
    }
    #[test]
    fn radio_vht_ampdu_complete_iq_psdu_framing() {
        // Independently generated waveform PSDUs have PHY-dependent capacity
        // and padding. Framing must remove that padding without removing FCS.
        for row in include_str!("../../tests/fixtures/iq/vht-bcc-iq-index.tsv")
            .lines()
            .skip(1)
        {
            let c: Vec<_> = row.split('\t').collect();
            let psdu = hex(c[7]);
            let mpdu = hex(c[8]);
            let events: Vec<_> = Scan::vht(&psdu, 16383).collect();
            assert!(
                !events.iter().any(|e| matches!(e, Event::Invalid { .. })),
                "{}: {events:?}",
                c[0]
            );
            let frames: Vec<_> = events
                .iter()
                .filter_map(|e| match e {
                    Event::Frame { bytes, .. } => Some(*bytes),
                    _ => None,
                })
                .collect();
            assert_eq!(frames, vec![mpdu.as_slice()], "{}", c[0]);
        }
    }
    #[test]
    fn radio_ampdu_independent_delimiter_crc_and_fields() {
        let rows: Vec<_> = include_str!("../../tests/fixtures/iq/ampdu-delimiters.tsv")
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
        let rows: Vec<_> = include_str!("../../tests/fixtures/iq/ampdu-index.tsv")
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
