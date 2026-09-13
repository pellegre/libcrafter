//! The only IQ-to-packet boundary: recovered MAC bytes enter the normal parser.
use std::collections::VecDeque;

use super::*;
use crate::wire::{
    BackendKind, PacketMetadata, PacketOrigin, PacketRecord, PacketSource, WireError,
};
use crate::{CrafterError, Packet};

/// RF context retained independently from the packet's Wi-Fi annotations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadioReceiveMetadata {
    pub config: RxConfig,
    pub start: IqPosition,
    pub end_sample_index: u64,
    pub rate_bps: u32,
    pub integrity: FrameIntegrity,
    /// Number of original trailer bytes omitted from packet parsing.
    pub stripped_fcs_bytes: usize,
    pub diagnostics: Vec<PhyDiagnostic>,
}

/// Bounded synchronous adapter over an already configured receive-only source.
///
/// `bounds` caps queued frames and frame sizes independently of the decoder.
/// Source/decoder contracts enforce sample, duration and DSP allocation bounds.
/// Diagnostics describe the most recent decoder call, including terminal resets;
/// they are replaced on each call to avoid an unbounded event history.
/// No live acquisition is enabled by constructing this adapter.
pub struct RadioPacketSource<S, D> {
    source: S,
    decoder: D,
    bounds: RxConfig,
    pending: VecDeque<RecoveredFrame>,
    diagnostics: Vec<PhyDiagnostic>,
    end: Option<StreamEnd>,
    failed: bool,
}
impl<S: IqSource, D: PhyDecoder> RadioPacketSource<S, D> {
    pub fn new(source: S, decoder: D, bounds: RxConfig) -> RadioResult<Self> {
        bounds.validate()?;
        Ok(Self {
            source,
            decoder,
            bounds,
            pending: VecDeque::new(),
            diagnostics: Vec::new(),
            end: None,
            failed: false,
        })
    }
    pub fn diagnostics(&self) -> &[PhyDiagnostic] {
        &self.diagnostics
    }
    pub fn end(&self) -> Option<StreamEnd> {
        self.end
    }
    pub fn decoder(&self) -> &D {
        &self.decoder
    }
    /// Cancel acquisition, discard queued frames and reset partial decoder state.
    pub fn cancel(&mut self) {
        self.source.cancel();
        self.pending.clear();
        self.diagnostics = self
            .decoder
            .reset(ResetReason::End(StreamEnd::Cancelled))
            .diagnostics;
        self.end = Some(StreamEnd::Cancelled);
    }
    fn fail(&mut self, error: RadioError) -> WireError {
        self.cancel();
        self.failed = true;
        WireError::backend("radio", "receive", error.to_string())
    }
}
impl<S: IqSource, D: PhyDecoder> PacketSource for RadioPacketSource<S, D> {
    fn next_record(&mut self) -> crate::wire::Result<Option<PacketRecord>> {
        loop {
            if let Some(frame) = self.pending.pop_front() {
                return frame_record(frame).map(Some);
            }
            if self.failed || self.end.is_some() {
                return Ok(None);
            }
            let event = self.source.next_event().map_err(|e| self.fail(e))?;
            if let IqEvent::End(end) = &event {
                self.end = Some(*end);
            }
            let output = self.decoder.consume(event).map_err(|e| self.fail(e))?;
            self.diagnostics = output.diagnostics;
            if output.frames.len() > self.bounds.max_pending_frames {
                return Err(self.fail(RadioError::Limit {
                    context: "pending frames",
                    limit: self.bounds.max_pending_frames as u64,
                    actual: output.frames.len() as u64,
                }));
            }
            if let Some(frame) = output
                .frames
                .iter()
                .find(|f| f.bytes.len() > self.bounds.max_frame_bytes)
            {
                return Err(self.fail(RadioError::Limit {
                    context: "recovered frame bytes",
                    limit: self.bounds.max_frame_bytes as u64,
                    actual: frame.bytes.len() as u64,
                }));
            }
            self.pending.extend(output.frames);
        }
    }
}
fn frame_record(frame: RecoveredFrame) -> crate::wire::Result<PacketRecord> {
    if frame.link_type != LinkType::Ieee80211 {
        return Err(CrafterError::invalid_field_value(
            "radio link type",
            "requires IEEE 802.11 MAC bytes",
        )
        .into());
    }
    if frame.integrity == FrameIntegrity::InvalidFcs {
        return Err(CrafterError::invalid_field_value(
            "radio FCS",
            "invalid integrity cannot become a packet",
        )
        .into());
    }
    let stripped = if frame.integrity == FrameIntegrity::ValidFcs {
        4
    } else {
        0
    };
    let len =
        frame.bytes.len().checked_sub(stripped).ok_or_else(|| {
            CrafterError::buffer_too_short("radio FCS", stripped, frame.bytes.len())
        })?;
    let packet = Packet::decode_from_link(LinkType::Ieee80211, &frame.bytes[..len])?;
    let original_len = u32::try_from(frame.bytes.len()).map_err(|_| {
        CrafterError::invalid_field_value("radio frame length", "exceeds metadata length")
    })?;
    let metadata = PacketMetadata::new()
        .with_origin(PacketOrigin::Captured)
        .with_backend(BackendKind::Other("radio".into()))
        .with_link_type(LinkType::Ieee80211)
        .with_original_len(original_len)
        .with_captured_bytes(frame.bytes)
        .with_radio_metadata(RadioReceiveMetadata {
            config: frame.config,
            start: frame.start,
            end_sample_index: frame.end_sample_index,
            rate_bps: frame.rate_bps,
            integrity: frame.integrity,
            stripped_fcs_bytes: stripped,
            diagnostics: frame.diagnostics,
        });
    Ok(PacketRecord::from_packet_metadata(packet, metadata))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Dot11Metadata, Sniffer};
    use crate::Dot11;
    use std::io::Cursor;

    fn config() -> RxConfig {
        RxConfig {
            sample_rate_hz: 20_000_000,
            center_frequency_hz: 2_412_000_000,
            max_chunk_samples: 10000,
            max_buffer_samples: 120000,
            max_frame_bytes: 4095,
            max_pending_frames: 4,
            max_capture_samples: 1000000,
            max_duration: Duration::from_secs(1),
        }
    }
    fn position() -> IqPosition {
        IqPosition {
            epoch: 0,
            sequence: 0,
            sample_index: 0,
            time_anchor: Some(TimeAnchor {
                sample_index: 0,
                time: SystemTime::UNIX_EPOCH,
                uncertainty: Duration::from_micros(5),
            }),
            discontinuity: None,
        }
    }
    #[test]
    fn radio_he_packet_source_preserves_frames_and_metadata() {
        for row in include_str!("../../tests/fixtures/iq/he-ampdu-iq-index.tsv")
            .lines()
            .skip(1)
            .filter(|r| r.starts_with("he-ampdu-iq-mcs9-ltf4-gi3200-"))
            .chain(
                include_str!("../../tests/fixtures/iq/he-ldpc-iq-index.tsv")
                    .lines()
                    .skip(1)
                    .filter(|r| r.starts_with("he-ldpc-iq-mcs11-ltf1-gi800-")),
            )
            .chain(
                include_str!("../../tests/fixtures/iq/he-midamble-iq-index.tsv")
                    .lines()
                    .skip(1)
                    .filter(|r| {
                        r.starts_with("he-midamble-iq-mcs11-ldpc-ltf1-gi800-p10-n12\t")
                            || r.starts_with("he-midamble-iq-mcs0-bcc-ltf1-gi800-p10-n12\t")
                    }),
            )
            .chain(
                include_str!("../../tests/fixtures/iq/he-stbc-iq-index.tsv")
                    .lines()
                    .skip(1)
                    .filter(|r| {
                        r.starts_with("he-stbc-iq-mcs0-bcc-ltf1-gi800-pad3-changing\t")
                            || r.starts_with("he-stbc-iq-mcs11-ldpc-ltf4-gi3200-pad4-changing\t")
                    }),
            )
            .chain(
                include_str!("../../tests/fixtures/iq/he-dcm-iq-index.tsv")
                    .lines()
                    .skip(1)
                    .filter(|r| {
                        r.starts_with("he-dcm-iq-mcs0-bcc-ltf1-gi800-pad3\t")
                            || r.starts_with("he-dcm-iq-mcs4-ldpc-ltf4-gi3200-pad4\t")
                    }),
            )
            .chain(
                include_str!("../../tests/fixtures/iq/he-er-iq-index.tsv")
                    .lines()
                    .skip(1)
                    .chain(
                        include_str!("../../tests/fixtures/iq/he-er106-iq-index.tsv")
                            .lines()
                            .skip(1),
                    )
                    .filter(|r| {
                        let name = r.split('\t').next().unwrap();
                        name.contains("-mcs0-") && name.ends_with("-ltf4-gi3200-pad3")
                    }),
            )
        {
            let c: Vec<_> = row.split('\t').collect();
            let er = c[0].starts_with("he-er");
            let midamble = c[0].starts_with("he-midamble");
            let dcm = if er {
                c[11] == "1"
            } else {
                c[0].starts_with("he-dcm")
            };
            let stbc = if er {
                c[12] == "1"
            } else {
                c[0].starts_with("he-stbc")
            };
            let ldpc = if midamble || dcm || stbc || er {
                c[2] == "1"
            } else {
                c[0].starts_with("he-ldpc")
            };
            let bytes = std::fs::read(format!(
                "{}/tests/fixtures/iq/{}.cs8",
                env!("CARGO_MANIFEST_DIR"),
                c[0]
            ))
            .unwrap();
            let source = ReaderIqSource::new(Cursor::new(bytes), config(), position()).unwrap();
            let source = RadioPacketSource::new(source, WifiDecoder::new(), config()).unwrap();
            let records = Sniffer::new(source)
                .with(Dot11Metadata::new())
                .collect_records()
                .unwrap();
            let expected: Vec<Vec<u8>> = c[if dcm || stbc || er {
                7
            } else if midamble {
                9
            } else if ldpc {
                5
            } else {
                6
            }]
            .split(',')
            .map(|s| {
                s.as_bytes()
                    .chunks_exact(2)
                    .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
                    .collect()
            })
            .collect();
            assert_eq!(records.len(), expected.len());
            for (record, bytes) in records.iter().zip(expected) {
                assert_eq!(record.metadata().captured_bytes().unwrap(), bytes);
                assert_eq!(
                    record.packet().compile().unwrap().as_bytes(),
                    &bytes[..bytes.len() - 4]
                );
                assert!(record.packet().layer::<Dot11>().is_some());
                let rf = record.metadata().radio().unwrap();
                assert_eq!(rf.stripped_fcs_bytes, 4);
                assert_eq!(rf.start.sample_index, 37);
                assert_eq!(rf.start.time_anchor, position().time_anchor);
                assert!(rf.diagnostics.iter().any(|d| {
                    let fields = match d {
                        PhyDiagnostic::HeSignal { fields, .. } if !er => fields,
                        PhyDiagnostic::HeErSignal { fields, .. } if er => fields,
                        _ => return false,
                    };
                    fields.mcs == c[1].parse::<u8>().unwrap()
                        && fields.bandwidth == u8::from(c[0].starts_with("he-er106-"))
                        && fields.ldpc == ldpc
                        && fields.dcm == dcm
                        && fields.stbc == stbc
                        && fields.midamble_period
                            == if midamble || ((dcm || stbc || er) && c[5] != "0") {
                                Some(c[5].parse().unwrap())
                            } else {
                                None
                            }
                }));
                assert_eq!(record.metadata(), &record.metadata().clone());
            }
        }
    }
    #[test]
    fn radio_ht_ampdu_packet_source_keeps_duplicate_mpdus() {
        for row in include_str!("../../tests/fixtures/iq/ht-ampdu-index.tsv")
            .lines()
            .skip(1)
            .filter(|row| {
                row.starts_with("ht-ampdu-7-gi800-")
                    && row.split('\t').next().unwrap().ends_with("duplicate")
            })
            .chain(
                include_str!("../../tests/fixtures/iq/vht-ampdu-iq-index.tsv")
                    .lines()
                    .skip(1)
                    .filter(|row| row.starts_with("vht-ampdu-8-gi800-duplicate\t")),
            )
            .chain(
                include_str!("../../tests/fixtures/iq/vht-ldpc-iq-index.tsv")
                    .lines()
                    .skip(1)
                    .filter(|row| row.starts_with("vht-ldpc-8-gi800-duplicate\t")),
            )
            .chain(
                include_str!("../../tests/fixtures/iq/vht-stbc-iq-index.tsv")
                    .lines()
                    .skip(1)
                    .filter(|row| row.starts_with("vht-stbc-8-ldpc-gi800-duplicate\t")),
            )
        {
            let fields: Vec<_> = row.split('\t').collect();
            let bytes = std::fs::read(format!(
                "{}/tests/fixtures/iq/{}.cs8",
                env!("CARGO_MANIFEST_DIR"),
                fields[0]
            ))
            .unwrap();
            let source = ReaderIqSource::new(Cursor::new(bytes), config(), position()).unwrap();
            let source = RadioPacketSource::new(source, WifiDecoder::new(), config()).unwrap();
            let records = Sniffer::new(source)
                .with(Dot11Metadata::new())
                .collect_records()
                .unwrap();
            assert_eq!(records.len(), 2);
            let vht = fields[0].starts_with("vht-");
            let expected: Vec<u8> = fields[if vht { 5 } else { 6 }]
                .split(',')
                .next()
                .unwrap()
                .as_bytes()
                .chunks_exact(2)
                .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
                .collect();
            for (record, offset) in records.iter().zip([0, 60]) {
                assert_eq!(record.metadata().captured_bytes().unwrap(), expected);
                assert_eq!(
                    record.packet().compile().unwrap().as_ref(),
                    &expected[..expected.len() - 4]
                );
                assert!(record.packet().layer::<Dot11>().is_some());
                assert!(record.metadata().wifi().is_some());
                let rf = record.metadata().radio().unwrap();
                assert_eq!(
                    rf.diagnostics
                        .iter()
                        .any(|d| matches!(d, PhyDiagnostic::VhtSignalB { .. })),
                    vht
                );
                assert_eq!(rf.start.sample_index, 37);
                assert_eq!(rf.start.time_anchor, position().time_anchor);
                assert_eq!(rf.stripped_fcs_bytes, 4);
                assert!(rf.diagnostics.contains(&PhyDiagnostic::Ampdu {
                    delimiter_offset: offset,
                    control_bits: 0
                }));
                assert_eq!(record.metadata(), &record.metadata().clone());
            }
        }
    }
    #[test]
    fn radio_ht_ldpc_packet_source_preserves_bytes_and_metadata() {
        let bytes = include_bytes!("../../tests/fixtures/iq/ht-ldpc-7-gi800-len100-clean.cs8");
        let source =
            ReaderIqSource::new(Cursor::new(bytes.to_vec()), config(), position()).unwrap();
        let source = RadioPacketSource::new(source, WifiDecoder::new(), config()).unwrap();
        let records = Sniffer::new(source)
            .with(Dot11Metadata::new())
            .collect_records()
            .unwrap();
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert!(record.packet().layer::<Dot11>().is_some());
        assert!(record.metadata().wifi().is_some());
        let row = include_str!("../../tests/fixtures/iq/ht-ldpc-index.tsv")
            .lines()
            .find(|r| r.starts_with("ht-ldpc-7-gi800-len100-clean\t"))
            .unwrap();
        let hex = row.split('\t').nth(4).unwrap();
        let expected: Vec<_> = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(record.metadata().captured_bytes().unwrap(), expected);
        assert_eq!(
            record.packet().compile().unwrap().as_ref(),
            &expected[..expected.len() - 4]
        );
        let rf = record.metadata().radio().unwrap();
        assert_eq!(rf.stripped_fcs_bytes, 4);
        assert_eq!(rf.start.time_anchor, position().time_anchor);
        assert!(rf.diagnostics.iter().any(
            |d| matches!(d,PhyDiagnostic::HtSignal{fields,..} if fields.ldpc && fields.mcs==7)
        ));
        assert!(rf
            .diagnostics
            .iter()
            .any(|d| matches!(d, PhyDiagnostic::Ldpc { .. })));
        assert_eq!(record.metadata(), &record.metadata().clone());
    }
    #[test]
    fn radio_sniffer_original_bytes_and_both_metadata_survive() {
        let bytes = include_bytes!("../../tests/fixtures/iq/ofdm-6-clean.cs8");
        let mut samples = bytes.to_vec();
        samples.extend_from_slice(bytes);
        // Both frames are delivered from a single source chunk.
        assert!(samples.len() / 2 < config().max_chunk_samples);
        let source = ReaderIqSource::new(Cursor::new(samples), config(), position()).unwrap();
        let source = RadioPacketSource::new(source, LegacyOfdmDecoder::new(), config()).unwrap();
        let records = Sniffer::new(source)
            .with(Dot11Metadata::new())
            .collect_records()
            .unwrap();
        assert_eq!(records.len(), 2);
        for record in &records {
            assert!(record.packet().layer::<Dot11>().is_some());
            assert!(record.metadata().wifi().is_some());
            assert!(record.metadata().medium().is_some());
            let rf = record.metadata().radio().unwrap();
            assert_eq!(rf.integrity, FrameIntegrity::ValidFcs);
            assert_eq!(rf.start.time_anchor, position().time_anchor);
            assert_eq!(rf.config, config());
            assert_eq!(rf.stripped_fcs_bytes, 4);
            let captured = record.metadata().captured_bytes().unwrap();
            let parsed = record.packet().compile().unwrap();
            assert_eq!(parsed.as_ref(), &captured[..captured.len() - 4]);
            assert_eq!(record.metadata().clone(), record.metadata().clone());
        }
        assert!(
            records[1].metadata().radio().unwrap().start.sample_index
                > records[0].metadata().radio().unwrap().start.sample_index
        );
    }
    struct Events(VecDeque<IqEvent>);
    impl IqSource for Events {
        fn next_event(&mut self) -> RadioResult<IqEvent> {
            Ok(self.0.pop_front().unwrap_or(IqEvent::End(StreamEnd::Eof)))
        }
        fn cancel(&mut self) {
            self.0.clear();
        }
    }
    #[test]
    fn radio_packet_source_gap_and_eof_discard_partial_frames() {
        let bytes = include_bytes!("../../tests/fixtures/iq/ofdm-6-clean.cs8");
        let chunk = |part: &[u8], p| {
            IqEvent::Chunk(
                IqChunk::new(config(), p, part.iter().map(|b| *b as i8).collect()).unwrap(),
            )
        };
        let mut next = position();
        next.sequence = 1;
        next.sample_index = 300;
        next.discontinuity = Some(Discontinuity {
            reason: GapReason::QueueOverflow,
            loss: SampleLoss::Unknown,
        });
        let events = Events(VecDeque::from([
            chunk(&bytes[..600], position()),
            chunk(&bytes[600..], next),
        ]));
        let mut source =
            RadioPacketSource::new(events, LegacyOfdmDecoder::new(), config()).unwrap();
        assert!(source.next_record().unwrap().is_none());
        assert_eq!(source.end(), Some(StreamEnd::Eof));
        assert!(source
            .diagnostics()
            .contains(&PhyDiagnostic::Reset(ResetReason::End(StreamEnd::Eof))));
        assert!(source.next_record().unwrap().is_none());
        assert_eq!(source.decoder().stats().valid_frames, 0);
    }
    struct Frames(Vec<RecoveredFrame>);
    impl PhyDecoder for Frames {
        fn consume(&mut self, _: IqEvent) -> RadioResult<DecodeOutput> {
            Ok(DecodeOutput {
                frames: std::mem::take(&mut self.0),
                diagnostics: vec![],
            })
        }
        fn reset(&mut self, _: ResetReason) -> DecodeOutput {
            self.0.clear();
            DecodeOutput::default()
        }
    }
    fn frame(bytes: Vec<u8>, integrity: FrameIntegrity) -> RecoveredFrame {
        RecoveredFrame {
            bytes,
            integrity,
            link_type: LinkType::Ieee80211,
            config: config(),
            start: position(),
            end_sample_index: 500,
            rate_bps: 6000000,
            diagnostics: vec![],
        }
    }
    #[test]
    fn radio_packet_source_structured_parse_errors_and_fcs_policy() {
        let mut source = RadioPacketSource::new(
            Events(VecDeque::new()),
            Frames(vec![
                frame(vec![0], FrameIntegrity::FcsAbsent),
                frame(vec![0], FrameIntegrity::ValidFcs),
            ]),
            config(),
        )
        .unwrap();
        assert!(matches!(
            source.next_record(),
            Err(WireError::Packet(CrafterError::BufferTooShort {
                available: 1,
                ..
            }))
        ));
        assert!(matches!(
            source.next_record(),
            Err(WireError::Packet(CrafterError::BufferTooShort {
                context: "radio FCS",
                required: 4,
                available: 1
            }))
        ));
        assert!(source.next_record().unwrap().is_none());
        assert!(matches!(
            frame_record(frame(vec![0; 24], FrameIntegrity::InvalidFcs)),
            Err(WireError::Packet(CrafterError::InvalidFieldValue {
                field: "radio FCS",
                ..
            }))
        ));
        let record = frame_record(frame(
            vec![0xd4, 0, 0, 0, 2, 0, 0, 0, 0, 1],
            FrameIntegrity::FcsAbsent,
        ))
        .unwrap();
        assert_eq!(record.metadata().radio().unwrap().stripped_fcs_bytes, 0);
        assert_eq!(
            record.packet().compile().unwrap().as_ref(),
            record.metadata().captured_bytes().unwrap()
        );
    }
    #[test]
    fn radio_packet_source_bounds_and_cancellation() {
        let frames = (0..5)
            .map(|_| frame(vec![0; 24], FrameIntegrity::FcsAbsent))
            .collect();
        let mut source =
            RadioPacketSource::new(Events(VecDeque::new()), Frames(frames), config()).unwrap();
        assert!(matches!(
            source.next_record(),
            Err(WireError::Backend { .. })
        ));
        assert!(source.next_record().unwrap().is_none());
        let mut source = RadioPacketSource::new(
            Events(VecDeque::new()),
            Frames(vec![frame(vec![0; 24], FrameIntegrity::FcsAbsent)]),
            config(),
        )
        .unwrap();
        source.cancel();
        assert_eq!(source.end(), Some(StreamEnd::Cancelled));
        assert!(source.next_record().unwrap().is_none());
    }
}
