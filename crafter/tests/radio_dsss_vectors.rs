#![cfg(feature = "radio")]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fs, path::PathBuf};

fn bytes(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|v| u8::from_str_radix(std::str::from_utf8(v).unwrap(), 16).unwrap())
        .collect()
}
fn digest(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn mac_crc(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb88320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}
fn header_crc(data: &[u8]) -> u16 {
    // MSB register form, independent of Python's reflected register.
    let mut crc = 0xffffu16;
    for byte in data {
        for k in 0..8 {
            let feedback = (crc >> 15) ^ u16::from((byte >> k) & 1);
            crc <<= 1;
            if feedback != 0 {
                crc ^= 0x1021;
            }
        }
    }
    (!crc).reverse_bits()
}

#[test]
fn independent_dsss_inventory_and_literal_truth() {
    assert_eq!(header_crc(&[0x0a, 0, 0xc0, 0]), 0xeada);
    assert_eq!(mac_crc(b"123456789"), 0xcbf43926);
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/iq");
    let manifest: Value =
        serde_json::from_slice(&fs::read(root.join("dsss-manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["sample_rate_hz"], 20_000_000);
    assert_eq!(manifest["chip_rate_hz"], 11_000_000);
    assert_eq!(manifest["generator_version"], "1");
    let fixtures = manifest["fixtures"].as_array().unwrap();
    assert_eq!(fixtures.len(), 25);
    let index = fs::read_to_string(root.join("dsss-index.tsv")).unwrap();
    assert_eq!(index.lines().skip(1).count(), fixtures.len());
    let mut names = HashSet::new();
    let mut combinations = HashSet::new();
    let mut cck55 = HashSet::new();
    let mut cck11 = HashSet::new();
    for (entry, line) in fixtures.iter().zip(index.lines().skip(1)) {
        let name = entry["name"].as_str().unwrap();
        assert!(names.insert(name));
        let columns: Vec<_> = line.split('\t').collect();
        assert_eq!(columns.len(), 7);
        assert_eq!(columns[0], name);
        let iq = fs::read(root.join(format!("{name}.cs8"))).unwrap();
        assert_eq!(
            iq.len(),
            entry["sample_count"].as_u64().unwrap() as usize * 2
        );
        assert!(iq.len() < 500_000);
        assert_eq!(digest(&iq), entry["sha256"].as_str().unwrap());
        assert_eq!(columns[5], entry["sha256"].as_str().unwrap());
        let truth_bytes = fs::read(root.join(format!("{name}.json"))).unwrap();
        assert_eq!(
            digest(&truth_bytes),
            entry["intermediate_sha256"].as_str().unwrap()
        );
        let truth: Value = serde_json::from_slice(&truth_bytes).unwrap();
        let psdu = bytes(entry["psdu_hex"].as_str().unwrap());
        let split = psdu.len() - 4;
        assert_eq!(
            mac_crc(&psdu[..split]) == u32::from_le_bytes(psdu[split..].try_into().unwrap()),
            entry["fcs_valid"].as_bool().unwrap()
        );
        let header = bytes(entry["header_hex"].as_str().unwrap());
        assert_eq!(
            header_crc(&header[..4]) == u16::from_le_bytes(header[4..].try_into().unwrap()),
            entry["header_crc_valid"].as_bool().unwrap()
        );
        let rate = entry["rate_bps"].as_u64().unwrap();
        assert_eq!(columns[1].parse::<u64>().unwrap(), rate);
        assert_eq!(columns[2], entry["preamble"].as_str().unwrap());
        assert_eq!(
            columns[3].parse::<u64>().unwrap(),
            entry["sample_count"].as_u64().unwrap()
        );
        assert_eq!(columns[4], entry["psdu_hex"].as_str().unwrap());
        assert_eq!(columns[6], entry["expected"].as_str().unwrap());
        let length = (psdu.len() as u64 * 8_000_000).div_ceil(rate);
        assert_eq!(entry["length_us"], length);
        assert_eq!(
            entry["length_extension"],
            u64::from(rate == 11_000_000 && 11 * length - 8 * psdu.len() as u64 >= 8)
        );
        let raw = truth["input_bits"].as_array().unwrap();
        let scrambled = truth["scrambled_bits"].as_array().unwrap();
        assert_eq!(raw.len(), scrambled.len());
        for n in 7..raw.len() {
            assert_eq!(
                raw[n].as_u64().unwrap(),
                scrambled[n].as_u64().unwrap()
                    ^ scrambled[n - 4].as_u64().unwrap()
                    ^ scrambled[n - 7].as_u64().unwrap()
            );
        }
        if name.contains("-clean-") {
            combinations.insert((rate, entry["preamble"].as_str().unwrap()));
        }
        for symbol in truth["cck_symbols"].as_array().unwrap() {
            let bits = symbol["bits"].as_array().unwrap();
            assert_eq!(symbol["chips"].as_array().unwrap().len(), 8);
            if rate == 5_500_000 {
                cck55.insert((bits[2].as_u64().unwrap(), bits[3].as_u64().unwrap()));
            } else {
                for k in [2, 4, 6] {
                    cck11.insert((k, bits[k].as_u64().unwrap(), bits[k + 1].as_u64().unwrap()));
                }
            }
        }
    }
    assert_eq!(combinations.len(), 7);
    assert!(!combinations.contains(&(1_000_000, "short")));
    assert_eq!(cck55.len(), 4);
    assert_eq!(cck11.len(), 12);
}

use crafter::radio::*;
fn config() -> RxConfig {
    RxConfig {
        sample_rate_hz: 20_000_000,
        center_frequency_hz: 2_437_000_000,
        max_chunk_samples: 100_000,
        max_buffer_samples: 100_000,
        max_frame_bytes: 4096,
        max_pending_frames: 8,
        max_capture_samples: 1_000_000,
        max_duration: std::time::Duration::from_secs(1),
    }
}
fn chunk(data: &[u8], sequence: u64, offset: u64) -> IqChunk {
    IqChunk::new(
        config(),
        IqPosition {
            epoch: 0,
            sequence,
            sample_index: offset,
            time_anchor: None,
            discontinuity: None,
        },
        data.iter().map(|&b| b as i8).collect(),
    )
    .unwrap()
}
#[test]
fn radio_dsss_payload_vectors_exact_bytes_and_positions() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/iq");
    let index = fs::read_to_string(root.join("dsss-index.tsv")).unwrap();
    for line in index.lines().skip(1) {
        let c: Vec<_> = line.split('\t').collect();
        if c[1].parse::<u32>().unwrap() > 2_000_000 {
            continue;
        }
        let input = fs::read(root.join(format!("{}.cs8", c[0]))).unwrap();
        for width in [1, 137, 4096, 100_000] {
            let mut decoder = DsssCckDecoder::new();
            let mut frames = Vec::new();
            for (n, part) in input.chunks(width * 2).enumerate() {
                frames.extend(
                    decoder
                        .consume(IqEvent::Chunk(chunk(part, n as u64, (n * width) as u64)))
                        .unwrap()
                        .frames,
                );
            }
            frames.extend(
                decoder
                    .consume(IqEvent::End(StreamEnd::Eof))
                    .unwrap()
                    .frames,
            );
            let expected = c[6] == "frame";
            assert_eq!(
                frames.len(),
                usize::from(expected),
                "{} width {width}, {:?}",
                c[0],
                decoder.stats()
            );
            if let Some(frame) = frames.first() {
                assert_eq!(frame.bytes, bytes(c[4]), "{} width {width}", c[0]);
                assert_eq!(frame.rate_bps, c[1].parse::<u32>().unwrap());
                assert_eq!(frame.integrity, FrameIntegrity::ValidFcs);
                assert!(frame.start.sample_index.abs_diff(37) <= 3);
                let duration = if c[2] == "short" { 1920 } else { 3840 };
                let end = 37
                    + duration
                    + (frame.bytes.len() as u64 * 8 * 20_000_000 / u64::from(frame.rate_bps));
                assert!(
                    frame.end_sample_index.abs_diff(end) <= 4,
                    "{} end {} expected {end}",
                    c[0],
                    frame.end_sample_index
                );
                assert!(
                    matches!(frame.diagnostics[0], PhyDiagnostic::Dsss { short_preamble, .. } if short_preamble == (c[2] == "short"))
                );
            }
            if c[0].contains("bad_fcs") {
                assert_eq!(decoder.stats().invalid_fcs, 1);
            }
            if c[0].contains("truncated_payload") {
                assert_eq!(decoder.stats().truncated_frames, 1);
            }
        }
    }
}
#[test]
fn radio_dsss_payload_gaps_and_terminal_reset() {
    let input = include_bytes!("fixtures/iq/dsss-10-long-clean-48.cs8");
    for variant in 0..7 {
        let mut decoder = DsssCckDecoder::new();
        assert!(decoder
            .consume(IqEvent::Chunk(chunk(&input[..9000], 0, 0)))
            .unwrap()
            .frames
            .is_empty());
        if variant < 5 {
            let mut p = IqPosition {
                epoch: 0,
                sequence: 1,
                sample_index: 4500,
                time_anchor: None,
                discontinuity: None,
            };
            let mut cfg = config();
            match variant {
                0 => p.epoch += 1,
                1 => p.sequence += 1,
                2 => p.sample_index += 1,
                3 => {
                    p.discontinuity = Some(Discontinuity {
                        reason: GapReason::SourceLoss,
                        loss: SampleLoss::Unknown,
                    })
                }
                _ => cfg.center_frequency_hz += 1,
            }
            let tail =
                IqChunk::new(cfg, p, input[9000..].iter().map(|&b| b as i8).collect()).unwrap();
            assert!(decoder
                .consume(IqEvent::Chunk(tail))
                .unwrap()
                .frames
                .is_empty());
        } else {
            let end = if variant == 5 {
                StreamEnd::Eof
            } else {
                StreamEnd::Cancelled
            };
            let output = decoder.consume(IqEvent::End(end)).unwrap();
            assert!(output.diagnostics.contains(&PhyDiagnostic::TruncatedFrame));
            assert!(decoder
                .consume(IqEvent::Chunk(chunk(input, 0, 0)))
                .unwrap()
                .frames
                .is_empty());
        }
        assert_eq!(decoder.stats().truncated_frames, 1);
        assert_eq!(decoder.stats().invalid_fcs, 0);
        decoder.reset(ResetReason::Explicit);
        assert_eq!(
            decoder
                .consume(IqEvent::Chunk(chunk(input, 0, 0)))
                .unwrap()
                .frames
                .len(),
            1
        );
    }
}

#[test]
fn radio_dsss_limits_and_unsupported_payload() {
    let input = include_bytes!("fixtures/iq/dsss-10-long-clean-48.cs8");
    let mut decoder = DsssCckDecoder::new();
    let mut cfg = config();
    cfg.max_frame_bytes = 47;
    let c = chunk(input, 0, 0);
    let bounded = IqChunk::new(
        cfg,
        c.position().clone(),
        input.iter().map(|&b| b as i8).collect(),
    )
    .unwrap();
    assert!(decoder
        .consume(IqEvent::Chunk(bounded))
        .unwrap()
        .frames
        .is_empty());
    assert!(decoder.stats().rejected_frames > 0);
    let mut cfg = config();
    cfg.max_pending_frames = 1;
    let repeated: Vec<u8> = input.iter().chain(input.iter()).copied().collect();
    let two = IqChunk::new(
        cfg,
        c.position().clone(),
        repeated.iter().map(|&b| b as i8).collect(),
    )
    .unwrap();
    decoder.reset(ResetReason::Explicit);
    let output = decoder.consume(IqEvent::Chunk(two)).unwrap();
    assert_eq!(output.frames.len(), 1);
    assert_eq!(decoder.stats().valid_frames, 2);
    assert_eq!(decoder.stats().dropped_frames, 1);
    assert!(output.diagnostics.iter().any(|d| matches!(
        d,
        PhyDiagnostic::Reset(ResetReason::Gap(Discontinuity {
            reason: GapReason::QueueOverflow,
            ..
        }))
    )));
    let cck = include_bytes!("fixtures/iq/dsss-110-long-clean-48.cs8");
    decoder.reset(ResetReason::Explicit);
    let output = decoder.consume(IqEvent::Chunk(chunk(cck, 0, 0))).unwrap();
    assert!(output.frames.is_empty());
    assert!(output.diagnostics.contains(&PhyDiagnostic::UnsupportedPhy));
}
