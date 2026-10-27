//! Independent forward-generated IEEE 802.11-2020 VHT20 receiver corpus.
use super::*;
use crate::radio::*;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf, time::Duration};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/iq")
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn config() -> RxConfig {
    RxConfig {
        sample_rate_hz: 20_000_000,
        center_frequency_hz: 5_220_000_000,
        max_chunk_samples: 4096,
        max_buffer_samples: 400_000,
        max_frame_bytes: 16383,
        max_pending_frames: 32,
        max_capture_samples: 5_000_000,
        max_duration: Duration::from_secs(1),
    }
}
fn feed(bytes: &[u8], size: usize, bounds: RxConfig) -> RadioResult<DecodeOutput> {
    let mut decoder = WifiDecoder::new();
    let mut result = DecodeOutput::default();
    for (sequence, part) in bytes.chunks(size * 2).enumerate() {
        let chunk = IqChunk::new(
            bounds.clone(),
            IqPosition {
                epoch: 0,
                sequence: sequence as u64,
                sample_index: (sequence * size) as u64,
                time_anchor: None,
                discontinuity: None,
            },
            part.iter().map(|b| *b as i8).collect(),
        )?;
        let mut out = decoder.consume(IqEvent::Chunk(chunk))?;
        result.frames.append(&mut out.frames);
        result.diagnostics.append(&mut out.diagnostics);
    }
    let mut out = decoder.consume(IqEvent::End(StreamEnd::Eof))?;
    result.frames.append(&mut out.frames);
    result.diagnostics.append(&mut out.diagnostics);
    Ok(result)
}

#[test]
fn independent_streaming_waveforms() {
    let index = fs::read_to_string(root().join("vht20-index.tsv")).unwrap();
    let mut coverage = std::collections::BTreeSet::new();
    for line in index.lines().skip(1) {
        let c: Vec<_> = line.split('\t').collect();
        let bytes = fs::read(root().join(format!("{}.cs8", c[0]))).unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(&bytes)), c[5]);
        let expected: Vec<_> = c[4].split(',').map(unhex).collect();
        for chunk in [79, 4096] {
            let out = feed(&bytes, chunk, config()).unwrap();
            assert_eq!(
                out.frames.len(),
                expected.len(),
                "{} chunk={chunk}: {:?}",
                c[0],
                out.diagnostics
            );
            for (frame, expected) in out.frames.iter().zip(&expected) {
                assert_eq!(&frame.bytes, expected, "{} chunk={chunk}", c[0]);
                assert_eq!(frame.start.sample_index, 37, "{}", c[0]);
                assert_eq!(
                    frame.end_sample_index,
                    c[6].parse::<u64>().unwrap(),
                    "{}",
                    c[0]
                );
                assert_eq!(frame.integrity, FrameIntegrity::ValidFcs);
                assert!(frame.diagnostics.iter().any(|d|matches!(d,PhyDiagnostic::VhtSignal {fields,..}
                    if matches!(fields.users,VhtSignalAUsers::Single {mcs,ldpc,..} if mcs==c[2].parse::<u8>().unwrap() && ldpc==(c[1]=="ldpc"))
                        && fields.short_guard_interval==(c[3]=="8"))));
                assert!(frame
                    .diagnostics
                    .iter()
                    .any(|d| matches!(d, PhyDiagnostic::VhtSignalB { .. })));
            }
        }
        coverage.insert((
            c[1].to_owned(),
            c[2].parse::<u8>().unwrap(),
            c[3].parse::<usize>().unwrap(),
        ));
    }
    assert_eq!(coverage.len(), 36);
}

#[test]
fn independent_invalid_waveforms_and_truncation() {
    let index = fs::read_to_string(root().join("vht20-invalid-index.tsv")).unwrap();
    for line in index.lines().skip(1) {
        let c: Vec<_> = line.split('\t').collect();
        let bytes = fs::read(root().join(format!("{}.cs8", c[0]))).unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(&bytes)), c[2]);
        let out = feed(&bytes, 79, config()).unwrap();
        assert!(out.frames.is_empty(), "{}: {:?}", c[0], out.frames);
    }
    let bytes = fs::read(root().join("vht-bcc-0-gi400-case0-clean.cs8")).unwrap();
    for cut in [350, 550, 700, 2924] {
        assert!(
            feed(&bytes[..cut * 2], 79, config())
                .unwrap()
                .frames
                .is_empty(),
            "cut={cut}"
        );
    }
    let first = feed(&bytes, 1, config()).unwrap();
    assert_eq!(first.frames.len(), 1);
    let mut bounded = config();
    bounded.max_buffer_samples = 1024;
    bounded.max_chunk_samples = 512;
    let out = feed(&bytes, 79, bounded).unwrap();
    assert!(out.frames.is_empty());
    assert!(out.diagnostics.contains(&PhyDiagnostic::UnsupportedPhy));
}

#[test]
fn independent_ldpc_symbol_geometry() {
    let index = fs::read_to_string(root().join("vht20-ldpc-rate-index.tsv")).unwrap();
    let mut cases = 0;
    for line in index.lines().skip(1) {
        let c: Vec<usize> = line.split('\t').map(|v| v.parse().unwrap()).collect();
        if c[2] != 1 {
            continue;
        }
        let mcs = VhtMcs::try_from(c[1] as u8).unwrap();
        let actual = super::layout::ldpc_receive(c[3], mcs, c[9] != 0).unwrap();
        assert_eq!(
            [
                actual.symbols,
                actual.codewords,
                actual.block_bits,
                actual.shortened_bits,
                actual.punctured_bits,
                actual.repeated_bits,
                usize::from(actual.extra_symbol_group),
                actual.payload_bits
            ],
            c[3..],
            "{line}"
        );
        cases += 1;
    }
    assert!(cases > 9000);
}

#[test]
fn packet_transmissions_recover_complete_mpdus() {
    let index = fs::read_to_string(root().join("vht20-index.tsv")).unwrap();
    let row: Vec<_> = index.lines().nth(1).unwrap().split('\t').collect();
    let mpdu = unhex(row[4]);
    let mac = &mpdu[..mpdu.len() - 4];
    for mcs in VhtMcs::ALL {
        for coding in [VhtCoding::Bcc, VhtCoding::Ldpc] {
            for guard in [VhtGuardInterval::Long, VhtGuardInterval::Short] {
                let tx = VhtTransmission::encode(
                    mac,
                    None,
                    &VhtTxConfig::new(mcs)
                        .with_coding(coding)
                        .with_guard_interval(guard),
                )
                .unwrap();
                let bytes: Vec<_> = tx.cs8.iter().map(|b| *b as u8).collect();
                let out = feed(&bytes, 79, config()).unwrap();
                assert_eq!(
                    out.frames.len(),
                    1,
                    "mcs={mcs:?} coding={coding:?} guard={guard:?}: {:?}",
                    out.diagnostics
                );
                assert_eq!(out.frames[0].bytes, mpdu);
                assert_eq!(out.frames[0].start.sample_index, tx.leading_samples as u64);
                assert_eq!(
                    out.frames[0].end_sample_index,
                    (tx.data_start + tx.data_samples) as u64
                );
            }
        }
    }
}

#[test]
fn discontinuities_clear_vht_candidates_and_output_bounds_are_explicit() {
    let bytes = fs::read(root().join("vht-bcc-0-gi400-case0-clean.cs8")).unwrap();
    let mut decoder = WifiDecoder::new();
    let mut recovered = Vec::new();
    for (sequence, start, stop) in [(0, 0, 750), (1, 767, bytes.len() / 2)] {
        let chunk = IqChunk::new(
            config(),
            IqPosition {
                epoch: 0,
                sequence,
                sample_index: start as u64,
                time_anchor: None,
                discontinuity: (sequence == 1).then_some(Discontinuity {
                    reason: GapReason::QueueOverflow,
                    loss: SampleLoss::Known(17),
                }),
            },
            bytes[start * 2..stop * 2]
                .iter()
                .map(|b| *b as i8)
                .collect(),
        )
        .unwrap();
        recovered.extend(decoder.consume(IqEvent::Chunk(chunk)).unwrap().frames);
    }
    assert!(recovered.is_empty());
    let duplicate = fs::read(root().join("vht-ldpc-0-gi400-duplicate.cs8")).unwrap();
    let mut bounded = config();
    bounded.max_pending_frames = 3;
    assert!(matches!(
        feed(&duplicate, 4096, bounded),
        Err(RadioError::Limit { .. })
    ));
}

#[test]
fn parallel_and_windowed_dispatch_preserve_vht_occurrences() {
    let bytes = fs::read(root().join("vht-ldpc-7-gi400-duplicate.cs8")).unwrap();
    let expected = feed(&bytes, 4096, config()).unwrap().frames;
    let mut bounds = config();
    bounds.max_buffer_samples = 16_000_000;
    let mut decoders: Vec<Box<dyn PhyDecoder>> = vec![
        Box::new(ParallelWifiDecoder::new().unwrap()),
        Box::new(WindowedWifiDecoder::new(2).unwrap()),
    ];
    for decoder in &mut decoders {
        let mut frames = Vec::new();
        for (seq, part) in bytes.chunks(8192).enumerate() {
            let event = IqEvent::Chunk(
                IqChunk::new(
                    bounds.clone(),
                    IqPosition {
                        epoch: 0,
                        sequence: seq as u64,
                        sample_index: (seq * 4096) as u64,
                        time_anchor: None,
                        discontinuity: None,
                    },
                    part.iter().map(|b| *b as i8).collect(),
                )
                .unwrap(),
            );
            frames.extend(decoder.consume(event).unwrap().frames);
        }
        frames.extend(
            decoder
                .consume(IqEvent::End(StreamEnd::Eof))
                .unwrap()
                .frames,
        );
        assert_eq!(frames.len(), expected.len());
        for (a, b) in frames.iter().zip(&expected) {
            assert_eq!(a.bytes, b.bytes);
            assert_eq!(a.start.sample_index, b.start.sample_index);
            assert_eq!(a.start.epoch, b.start.epoch);
            assert_eq!(a.start.time_anchor, b.start.time_anchor);
            assert_eq!(a.end_sample_index, b.end_sample_index);
            assert!(a
                .diagnostics
                .iter()
                .any(|d| matches!(d, PhyDiagnostic::VhtSignal { .. })));
        }
    }
}
