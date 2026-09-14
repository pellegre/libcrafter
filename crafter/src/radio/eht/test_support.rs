use crate::radio::{
    sync::{Acquisition, SyncEvent, Synchronizer},
    ComplexSample, DecodeOutput, IqChunk, IqEvent, IqPosition, PhyDecoder, RxConfig, StreamEnd,
};
use std::time::Duration;

pub(super) fn fixture(bytes: &[u8]) -> (Vec<ComplexSample>, Acquisition) {
    let samples: Vec<_> = bytes
        .chunks_exact(2)
        .map(|bytes| ComplexSample {
            i: bytes[0] as i8 as f32 / 128.,
            q: bytes[1] as i8 as f32 / 128.,
        })
        .collect();
    let mut synchronizer = Synchronizer::default();
    for (index, sample) in samples.iter().enumerate() {
        if let Some(SyncEvent::Acquired(acquisition)) = synchronizer.push(*sample, index as u64) {
            return (samples, acquisition);
        }
    }
    panic!("fixture did not acquire")
}

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

pub(super) fn feed(decoder: &mut impl PhyDecoder, bytes: &[u8], size: usize) -> DecodeOutput {
    let mut result = DecodeOutput::default();
    for (sequence, part) in bytes.chunks(size * 2).enumerate() {
        let chunk = IqChunk::new(
            config(),
            IqPosition {
                epoch: 0,
                sequence: sequence as u64,
                sample_index: (sequence * size) as u64,
                time_anchor: None,
                discontinuity: None,
            },
            part.iter().map(|value| *value as i8).collect(),
        )
        .unwrap();
        let mut output = decoder.consume(IqEvent::Chunk(chunk)).unwrap();
        result.frames.append(&mut output.frames);
        result.diagnostics.append(&mut output.diagnostics);
    }
    let mut output = decoder.consume(IqEvent::End(StreamEnd::Eof)).unwrap();
    result.diagnostics.append(&mut output.diagnostics);
    result
}
