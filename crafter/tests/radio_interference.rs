#![cfg(feature = "radio")]

use crafter::radio::*;
use std::{io::Cursor, time::Duration};

#[test]
fn radio_periodic_interference_then_independent_frame() {
    let mut bytes = Vec::new();
    for n in 0..4096 {
        let phase = std::f32::consts::TAU * (n % 16) as f32 / 16.;
        bytes.push((64. * phase.cos()).round() as i8 as u8);
        bytes.push((64. * phase.sin()).round() as i8 as u8);
    }
    bytes.extend_from_slice(&[0; 384 * 2]);
    bytes.extend_from_slice(include_bytes!("fixtures/iq/ofdm-6-clean.cs8"));
    let expected_hex = include_str!("fixtures/iq/ofdm-index.tsv")
        .lines()
        .find(|line| line.starts_with("ofdm-6-clean\t"))
        .unwrap()
        .split('\t')
        .nth(6)
        .unwrap();
    let expected: Vec<u8> = expected_hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    for chunk_samples in [1, 17, 65536] {
        let config = RxConfig {
            sample_rate_hz: 20_000_000,
            center_frequency_hz: 2_412_000_000,
            max_chunk_samples: chunk_samples,
            max_buffer_samples: 120_000,
            max_frame_bytes: 4095,
            max_pending_frames: 4,
            max_capture_samples: 100_000,
            max_duration: Duration::from_secs(1),
        };
        let position = IqPosition {
            epoch: 0,
            sequence: 0,
            sample_index: 0,
            time_anchor: None,
            discontinuity: None,
        };
        let mut source = ReaderIqSource::new(Cursor::new(&bytes), config, position).unwrap();
        let mut decoder = LegacyOfdmDecoder::new();
        let mut frames = Vec::new();
        loop {
            let event = source.next_event().unwrap();
            let end = matches!(event, IqEvent::End(_));
            frames.extend(decoder.consume(event).unwrap().frames);
            if end {
                break;
            }
        }
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].bytes, expected);
        assert_eq!(frames[0].integrity, FrameIntegrity::ValidFcs);
        assert_eq!(frames[0].start.sample_index, 4096 + 384 + 37);
    }
}
