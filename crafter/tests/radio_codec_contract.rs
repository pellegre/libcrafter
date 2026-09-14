#![cfg(feature = "radio")]

use crafter::prelude::*;
use crafter::radio::*;
use std::time::Duration;

// An Ethernet test codec maps each octet to I with zero Q. Its wire contract is
// intentionally simple enough for independently specified sample expectations.
#[derive(Clone, Default)]
struct OctetCodec;

impl PacketEncoder for OctetCodec {
    type Transmission = OwnedSamples;
    fn encode_packet(&self, record: &PacketRecord) -> RadioResult<OwnedSamples> {
        Ok(OwnedSamples {
            cs8: record
                .packet()
                .compile()
                .unwrap()
                .as_bytes()
                .iter()
                .flat_map(|byte| [*byte as i8, 0])
                .collect(),
            sample_rate_hz: 1_000_000,
        })
    }
}

impl PhyDecoder for OctetCodec {
    fn consume(&mut self, event: IqEvent) -> RadioResult<DecodeOutput> {
        match event {
            IqEvent::Chunk(chunk) => Ok(DecodeOutput {
                frames: vec![RecoveredFrame {
                    bytes: chunk.cs8().chunks_exact(2).map(|iq| iq[0] as u8).collect(),
                    link_type: LinkType::Ethernet,
                    integrity: FrameIntegrity::FcsAbsent,
                    framing: FrameFraming::default(),
                    config: chunk.config().clone(),
                    start: chunk.position().clone(),
                    end_sample_index: chunk.position().sample_index + chunk.len() as u64,
                    rate_bps: 8_000_000,
                    diagnostics: vec![],
                }],
                diagnostics: vec![],
            }),
            IqEvent::End(end) => Ok(self.reset(ResetReason::End(end))),
        }
    }
    fn reset(&mut self, reason: ResetReason) -> DecodeOutput {
        DecodeOutput {
            frames: vec![],
            diagnostics: vec![PhyDiagnostic::Reset(reason)],
        }
    }
}

const ETHERNET: [u8; 16] = [2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0x88, 0xb5, 0x37, 0x91];

fn config() -> RxConfig {
    RxConfig {
        sample_rate_hz: 1_000_000,
        center_frequency_hz: 100_000_000,
        max_chunk_samples: 64,
        max_buffer_samples: 128,
        max_frame_bytes: 128,
        max_pending_frames: 4,
        max_capture_samples: 128,
        max_duration: Duration::from_secs(1),
    }
}

fn position() -> IqPosition {
    IqPosition {
        epoch: 7,
        sequence: 3,
        sample_index: 100,
        time_anchor: None,
        discontinuity: None,
    }
}

fn record() -> PacketRecord {
    PacketRecord::new(Packet::decode_from_link(LinkType::Ethernet, &ETHERNET).unwrap())
}

#[test]
fn non_wifi_codec_uses_shared_packet_and_sample_interfaces() {
    let mut writer = RadioPacketWriter::new(OctetCodec, MemoryIqSink::new());
    let report = writer.write_record(&record()).unwrap();
    assert_eq!(report.bytes_requested(), 16);
    assert_eq!(report.bytes_written(), 16);
    let samples = &writer.sink().transmissions()[0];
    assert_eq!(samples.sample_rate_hz, 1_000_000);
    assert_eq!(
        samples.cs8,
        vec![
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, -120, 0, -75,
            0, 55, 0, -111, 0
        ]
    );
    let outcome = report.radio_outcome().unwrap();
    assert_eq!(outcome.samples_requested, 16);
    assert_eq!(outcome.samples_supplied, Some(16));
    assert_eq!(outcome.completion, SampleCompletion::Stored);
    assert!(report.is_dry_run());

    let memory = MemoryIqSource::from_cs8(samples.cs8.clone(), config(), position()).unwrap();
    let mut source = RadioPacketSource::new(memory, OctetCodec, config()).unwrap();
    let received = source.next_record().unwrap().unwrap();
    assert!(received.packet().layer::<Ethernet>().is_some());
    assert_eq!(received.packet().compile().unwrap().as_bytes(), ETHERNET);
    assert_eq!(
        received.metadata().captured_bytes(),
        Some(ETHERNET.as_slice())
    );
    assert_eq!(received.metadata().link_type(), Some(LinkType::Ethernet));
    assert!(received.metadata().wifi_capture().is_none());
    let radio = received.metadata().radio().unwrap();
    assert_eq!(radio.start, position());
    assert_eq!(radio.end_sample_index, 116);
    assert_eq!(radio.framing.trailer_bytes, 0);
    assert!(source.next_record().unwrap().is_none());
    assert_eq!(source.end(), Some(StreamEnd::Eof));
    assert!(source.next_record().unwrap().is_none());
}

#[test]
fn codec_framing_controls_trailer_removal_for_non_wifi_packets() {
    struct TrailerCodec;
    impl PhyDecoder for TrailerCodec {
        fn consume(&mut self, event: IqEvent) -> RadioResult<DecodeOutput> {
            let mut output = OctetCodec.consume(event)?;
            for frame in &mut output.frames {
                frame.framing.trailer_bytes = 2;
            }
            Ok(output)
        }
        fn reset(&mut self, reason: ResetReason) -> DecodeOutput {
            OctetCodec.reset(reason)
        }
    }
    let original: Vec<u8> = ETHERNET.into_iter().chain([0xaa, 0xbb]).collect();
    let samples = original.iter().flat_map(|b| [*b as i8, 0]).collect();
    let memory = MemoryIqSource::from_cs8(samples, config(), position()).unwrap();
    let mut source = RadioPacketSource::new(memory, TrailerCodec, config()).unwrap();
    let record = source.next_record().unwrap().unwrap();
    assert_eq!(record.packet().compile().unwrap().as_bytes(), ETHERNET);
    assert_eq!(
        record.metadata().captured_bytes(),
        Some(original.as_slice())
    );
    let radio = record.metadata().radio().unwrap();
    assert_eq!(radio.framing.trailer_bytes, 2);
    assert_eq!(radio.stripped_fcs_bytes, 0);
}

#[test]
fn cancellation_and_source_failures_remain_terminal() {
    let memory = MemoryIqSource::from_cs8(vec![0; 32], config(), position()).unwrap();
    let mut source = RadioPacketSource::new(memory, OctetCodec, config()).unwrap();
    source.cancel();
    assert_eq!(source.end(), Some(StreamEnd::Cancelled));
    assert!(source.next_record().unwrap().is_none());
    assert_eq!(
        source.diagnostics(),
        &[PhyDiagnostic::Reset(ResetReason::End(StreamEnd::Cancelled))]
    );

    struct Failed;
    impl IqSource for Failed {
        fn next_event(&mut self) -> RadioResult<IqEvent> {
            Err(RadioError::Source("sample read failed".into()))
        }
        fn cancel(&mut self) {}
    }
    let mut source = RadioPacketSource::new(Failed, OctetCodec, config()).unwrap();
    assert!(source
        .next_record()
        .unwrap_err()
        .to_string()
        .contains("sample read failed"));
    assert!(source.next_record().unwrap().is_none());
}

struct OutcomeSink(SampleCompletion, u64);
impl IqSink<OwnedSamples> for OutcomeSink {
    fn write(&mut self, _: &OwnedSamples) -> RadioResult<()> {
        Ok(())
    }
    fn write_outcome(&mut self, _: &OwnedSamples) -> RadioResult<IqSinkOutcome> {
        Ok(IqSinkOutcome {
            samples_requested: 16,
            samples_supplied: Some(self.1),
            padded_samples: 8,
            completion: self.0,
            live: Some(true),
        })
    }
}

#[test]
fn live_completion_and_partial_or_cancelled_outcomes_are_distinct() {
    let mut writer = RadioPacketWriter::new(
        OctetCodec,
        OutcomeSink(SampleCompletion::DeviceCompleted, 16),
    );
    let report = writer.write_record(&record()).unwrap();
    assert!(!report.is_dry_run());
    assert_eq!(report.target_details(), Some("live-cs8"));
    assert_eq!(
        report.radio_outcome().unwrap().completion,
        SampleCompletion::DeviceCompleted
    );
    for (completion, supplied) in [
        (SampleCompletion::Incomplete, 8),
        (SampleCompletion::Cancelled, 0),
        (SampleCompletion::DeviceCompleted, 15),
    ] {
        let mut writer = RadioPacketWriter::new(OctetCodec, OutcomeSink(completion, supplied));
        assert!(writer.write_record(&record()).is_err());
        assert_eq!(
            writer.last_outcome().unwrap().samples_supplied,
            Some(supplied)
        );
    }
}

#[test]
fn legacy_sink_acceptance_does_not_invent_completion() {
    struct LegacySink;
    impl IqSink<OwnedSamples> for LegacySink {
        fn write(&mut self, _: &OwnedSamples) -> RadioResult<()> {
            Ok(())
        }
    }
    let mut writer = RadioPacketWriter::new(OctetCodec, LegacySink);
    let report = writer.write_record(&record()).unwrap();
    let outcome = report.radio_outcome().unwrap();
    assert_eq!(outcome.live, None);
    assert_eq!(outcome.samples_supplied, None);
    assert_eq!(outcome.completion, SampleCompletion::Unconfirmed);
}

#[test]
fn malformed_samples_and_sink_errors_do_not_leave_stale_success() {
    let mut sink = MemoryIqSink::new();
    for samples in [
        OwnedSamples {
            cs8: vec![1],
            sample_rate_hz: 1,
        },
        OwnedSamples {
            cs8: vec![1, 2],
            sample_rate_hz: 0,
        },
    ] {
        assert!(sink.write(&samples).is_err());
    }
    assert!(sink.transmissions().is_empty());
    struct Flaky(bool);
    impl IqSink<OwnedSamples> for Flaky {
        fn write(&mut self, _: &OwnedSamples) -> RadioResult<()> {
            if std::mem::replace(&mut self.0, true) {
                Err(RadioError::Source("sink unavailable".into()))
            } else {
                Ok(())
            }
        }
    }
    let mut writer = RadioPacketWriter::new(OctetCodec, Flaky(false));
    writer.write_record(&record()).unwrap();
    assert!(writer.last_transmission().is_some());
    assert!(writer
        .write_record(&record())
        .unwrap_err()
        .to_string()
        .contains("sink unavailable"));
    assert!(writer.last_outcome().is_none());
    assert!(writer.last_transmission().is_none());
}
