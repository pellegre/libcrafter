#![cfg(feature = "radio")]

use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

#[test]
fn radio_vht_signal_a_public_paths() {
    use crafter::prelude::{VhtSignalAError, VhtSignalAFields, VhtSignalAUsers};
    let input: Vec<_> = include_str!("fixtures/iq/vht-signal-a-index.tsv")
        .lines()
        .nth(1)
        .unwrap()
        .split('\t')
        .next()
        .unwrap()
        .bytes()
        .map(|b| b - b'0')
        .collect();
    let result: Result<crafter::radio::VhtSignalAFields, crafter::VhtSignalAError> =
        VhtSignalAFields::decode(&input);
    assert!(matches!(
        result.unwrap().users,
        VhtSignalAUsers::Single { .. }
    ));
    assert_eq!(
        VhtSignalAFields::decode(&[]),
        Err(VhtSignalAError::BitCount {
            required: 48,
            available: 0
        })
    );
}

#[test]
fn radio_vht_signal_a_independent_inventory() {
    let inventory = include_str!("fixtures/iq/vht-signal-a-index.tsv");
    assert_eq!(
        hex(&Sha256::digest(inventory.as_bytes())),
        "653021668de364d2ce3c7716968d0e32a54eb297df0c67ead63b0f96e5e2d81f"
    );
    let mut headers = std::collections::BTreeSet::new();
    let mut groups = std::collections::BTreeSet::new();
    let mut single_user = 0;
    let mut multi_user = 0;
    for row in inventory.lines().skip(1) {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 13);
        assert_eq!(c[0].len(), 48);
        assert_eq!(c[12].len(), 96);
        assert!(c[0]
            .bytes()
            .chain(c[12].bytes())
            .all(|b| b == b'0' || b == b'1'));
        assert!(headers.insert(c[0]));
        let number = |i: usize| c[i].parse::<usize>().unwrap();
        let group = number(2);
        let width = number(1);
        assert!(width <= 3 && group <= 63);
        groups.insert((group, width));
        for i in [3, 5, 6, 7, 8, 9, 11] {
            assert!(number(i) <= 1);
        }
        assert!(number(6) <= number(5));
        assert_eq!(&c[0][42..], "000000");
        if group == 0 || group == 63 {
            single_user += 1;
            assert!(number(10) <= 9);
            let nsts = (number(4) & 7) + 1;
            assert!(number(3) == 0 || nsts % 2 == 0);
        } else {
            multi_user += 1;
            assert_eq!(number(3), 0);
            assert_eq!(number(11), 1);
            assert_ne!(number(10) & 8, 0);
            for user in 0..4 {
                let nsts = (number(4) >> (3 * user)) & 7;
                assert!(nsts <= 4);
                if nsts == 0 {
                    let coding = if user == 0 {
                        number(9)
                    } else {
                        (number(10) >> (user - 1)) & 1
                    };
                    assert_eq!(coding, 1);
                }
            }
        }
    }
    assert_eq!((single_user, multi_user), (640, 1240));
    assert_eq!(headers.len(), 1880);
    assert_eq!(groups.len(), 64 * 4);
}

#[test]
fn radio_extension_training_independent_waveform_integrity() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/iq");
    let rows: Vec<_> = include_str!("fixtures/iq/ht-extension-index.tsv")
        .lines()
        .skip(1)
        .collect();
    assert_eq!(rows.len(), 540);
    let mut matrix = std::collections::BTreeSet::new();
    for row in rows {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 13);
        let number = |i: usize| c[i].parse::<usize>().unwrap();
        let bytes = fs::read(root.join(format!("{}.cs8", c[0]))).unwrap();
        assert_eq!(hex(&Sha256::digest(&bytes)), c[5]);
        assert_eq!(bytes.len(), 2 * number(6));
        assert!(number(1) < 8 && number(9) < 2 && number(10) < 2 && number(11) < 2);
        assert!((1..=3).contains(&number(12)));
        assert!(1 + number(11) + number(12) <= 4);
        let extra = [0, 1, 2, 4][number(12)];
        assert!(1 + number(11) + extra <= 5);
        if number(10) == 1 {
            assert_eq!(number(2), 16);
        }
        if number(11) == 1 {
            assert_eq!(number(3) % 2, 0);
        }
        assert!([8, 16].contains(&number(2)));
        assert_eq!(
            number(7),
            37 + (if number(10) == 1 { 480 } else { 720 }) + 80 * (number(11) + extra)
        );
        assert_eq!(number(8), number(7) + (64 + number(2)) * number(3));
        assert_eq!(number(6), number(8) + 64);
        let psdu: Vec<_> = (0..c[4].len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&c[4][i..i + 2], 16).unwrap())
            .collect();
        let end = psdu.len() - 4;
        assert_eq!(
            crc(&psdu[..end]),
            u32::from_le_bytes(psdu[end..].try_into().unwrap())
        );
        assert!([100, 4095].contains(&psdu.len()));
        if psdu.len() == 4095 {
            assert!([0, 7].contains(&number(1)) && c[0].ends_with("offset"));
        }
        assert!(matrix.insert((
            number(1),
            number(2),
            number(9),
            number(10),
            number(11),
            number(12),
            psdu.len(),
            c[0].ends_with("offset")
        )));
    }
    assert_eq!(matrix.len(), 540);
    let aggregates: Vec<_> = include_str!("fixtures/iq/ht-extension-ampdu-index.tsv")
        .lines()
        .skip(1)
        .collect();
    assert_eq!(aggregates.len(), 62);
    for row in aggregates {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 12);
        let bytes = fs::read(root.join(format!("{}.cs8", c[0]))).unwrap();
        assert_eq!(hex(&Sha256::digest(&bytes)), c[7]);
        assert_eq!(bytes.len() / 2, c[8].parse::<usize>().unwrap() + 64);
    }
}

#[test]
fn radio_stbc_independent_waveform_integrity() {
    // Inventory integrity is distinct from receiver support.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/iq");
    let rows: Vec<_> = include_str!("fixtures/iq/ht-stbc-index.tsv")
        .lines()
        .skip(1)
        .collect();
    assert_eq!(rows.len(), 192);
    let mut matrix = std::collections::BTreeSet::new();
    for row in rows {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 11);
        let number = |i: usize| c[i].parse::<usize>().unwrap();
        let bytes = fs::read(root.join(format!("{}.cs8", c[0]))).unwrap();
        assert_eq!(hex(&Sha256::digest(&bytes)), c[5]);
        assert_eq!(bytes.len(), 2 * number(6));
        assert_eq!(number(3) % 2, 0);
        assert!([8, 16].contains(&number(2)));
        assert!(number(1) < 8 && number(9) < 2 && number(10) < 2);
        let greenfield = number(10) == 1;
        if greenfield {
            assert_eq!(number(2), 16);
        }
        assert_eq!(number(7), 37 + if greenfield { 560 } else { 800 });
        assert_eq!(number(8), number(7) + (64 + number(2)) * number(3));
        assert_eq!(number(6), number(8) + 64);
        let psdu: Vec<_> = (0..c[4].len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&c[4][i..i + 2], 16).unwrap())
            .collect();
        let end = psdu.len() - 4;
        assert_eq!(
            crc(&psdu[..end]),
            u32::from_le_bytes(psdu[end..].try_into().unwrap())
        );
        assert!([100, 4095].contains(&psdu.len()));
        assert!(matrix.insert((
            number(1),
            number(2),
            number(9),
            greenfield,
            psdu.len(),
            c[0].ends_with("offset")
        )));
    }
    let invalid: Vec<_> = include_str!("fixtures/iq/ht-stbc-invalid-index.tsv")
        .lines()
        .skip(1)
        .collect();
    assert_eq!(invalid.len(), 9);
    let mut faults = std::collections::BTreeSet::new();
    for row in invalid {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 4);
        let bytes = fs::read(root.join(format!("{}.cs8", c[0]))).unwrap();
        assert_eq!(hex(&Sha256::digest(&bytes)), c[2]);
        assert_eq!(bytes.len(), 2 * c[3].parse::<usize>().unwrap());
        assert!(faults.insert(c[1]));
    }
}

#[test]
fn radio_greenfield_independent_fixture_integrity() {
    // This checks oracle artifacts, not receive support or interoperability.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/iq");
    let rows: Vec<_> = include_str!("fixtures/iq/ht-greenfield-index.tsv")
        .lines()
        .skip(1)
        .collect();
    assert_eq!(rows.len(), 64);
    let mut matrix = std::collections::BTreeSet::new();
    for row in rows {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 10);
        let iq = fs::read(root.join(format!("{}.cs8", c[0]))).unwrap();
        assert_eq!(hex(&Sha256::digest(&iq)), c[5]);
        let number = |i: usize| c[i].parse::<usize>().unwrap();
        assert_eq!(iq.len(), 2 * number(6));
        assert_eq!(number(2), 16);
        assert_eq!(number(7), 37 + 480);
        assert_eq!(number(8), number(7) + 80 * number(3));
        assert_eq!(number(6), number(8) + 64);
        let psdu: Vec<_> = (0..c[4].len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&c[4][i..i + 2], 16).unwrap())
            .collect();
        let end = psdu.len() - 4;
        assert_eq!(
            crc(&psdu[..end]),
            u32::from_le_bytes(psdu[end..].try_into().unwrap())
        );
        assert!(number(1) < 8 && number(9) < 2);
        assert!([100, 4095].contains(&psdu.len()));
        assert!(matrix.insert((number(1), number(9), psdu.len(), c[0].ends_with("offset"))));
    }
    assert_eq!(matrix.len(), 64);
}

#[test]
fn radio_sampling_clock_exact_frame_recovery() {
    use crafter::radio::*;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/iq");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("ofdm-clock-manifest.json")).unwrap()).unwrap();
    let mut failures = Vec::new();
    for fixture in manifest["fixtures"].as_array().unwrap() {
        let name = fixture["name"].as_str().unwrap();
        let bytes = fs::read(root.join(format!("{name}.cs8"))).unwrap();
        let mut coordinates = None;
        for chunk in [127, 65536] {
            let config = RxConfig {
                sample_rate_hz: 20_000_000,
                center_frequency_hz: 2_412_000_000,
                max_chunk_samples: chunk,
                max_buffer_samples: 120_000,
                max_frame_bytes: 4095,
                max_pending_frames: 4,
                max_capture_samples: 200_000,
                max_duration: std::time::Duration::from_secs(1),
            };
            let position = IqPosition {
                epoch: 7,
                sequence: 0,
                sample_index: 1_000_000,
                time_anchor: None,
                discontinuity: None,
            };
            let mut source =
                ReaderIqSource::new(std::io::Cursor::new(&bytes), config, position).unwrap();
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
            if frames.len() != 1
                || hex(&frames[0].bytes) != fixture["psdu_hex"].as_str().unwrap()
                || frames[0].integrity != FrameIntegrity::ValidFcs
            {
                failures.push(format!("{name} chunk={chunk} frames={}", frames.len()));
            } else {
                let frame = &frames[0];
                let tracking = frame
                    .diagnostics
                    .iter()
                    .find_map(|d| match d {
                        PhyDiagnostic::OfdmTracking {
                            sampling_clock_offset_ppm,
                            pilot_residual_rms_rad,
                            data_symbols,
                        } => Some((
                            *sampling_clock_offset_ppm,
                            *pilot_residual_rms_rad,
                            *data_symbols,
                        )),
                        _ => None,
                    })
                    .expect("tracking metadata");
                assert!(
                    tracking.1.is_finite() && tracking.1 >= 0. && tracking.1 < 0.2,
                    "{name}: {tracking:?}"
                );
                let ppm = tracking.0.expect("multiple DATA symbols");
                assert!(ppm.is_finite());
                if name.contains("max_length") {
                    let expected = fixture["receiver_clock_ppm"].as_i64().unwrap() as f32;
                    assert!(
                        (ppm - expected).abs() < 2.,
                        "{name}: measured {ppm}, expected {expected}"
                    );
                }
                assert_eq!(frame.start.epoch, 7);
                assert_eq!(
                    frame.start.sample_index,
                    1_000_000 + fixture["preamble_start"].as_u64().unwrap(),
                    "{name}"
                );
                let current = (frame.start.sample_index, frame.end_sample_index);
                if let Some(previous) = coordinates {
                    assert_eq!(current, previous, "{name}");
                }
                coordinates = Some(current);
                // The receiver reports its consumed FFT extent, in original
                // source coordinates, not a resampled or zero-based timeline.
                let bits = frame.bytes.len() * 8 + 22;
                let symbols = bits.div_ceil(frame.rate_bps as usize / 250_000);
                assert_eq!(tracking.2, symbols);
                assert_eq!(
                    frame.end_sample_index,
                    frame.start.sample_index + 400 + symbols as u64 * 80
                );
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// Deliberately byte-oriented MAC CRC; fixture generation uses Python zlib.
fn crc(bytes: &[u8]) -> u32 {
    let mut value = !0u32;
    for byte in bytes {
        value ^= u32::from(*byte);
        for _ in 0..8 {
            value = (value >> 1) ^ (0xedb88320 & (0u32.wrapping_sub(value & 1)));
        }
    }
    !value
}

#[test]
fn radio_sampling_clock_vector_inventory_and_integrity() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/iq");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("ofdm-clock-manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["schema"], "crafter.radio.ofdm-clock/v1");
    assert_eq!(manifest["sample_rate_hz"], 20_000_000);
    assert_eq!(manifest["format"], "cs8");
    let fixtures = manifest["fixtures"].as_array().unwrap();
    assert_eq!(fixtures.len(), 48);
    let mut combinations = std::collections::BTreeSet::new();
    for fixture in fixtures {
        let name = fixture["name"].as_str().unwrap();
        let rate = fixture["rate_mbps"].as_u64().unwrap();
        let ppm = fixture["receiver_clock_ppm"].as_i64().unwrap();
        assert!([6, 9, 12, 18, 24, 36, 48, 54].contains(&rate));
        assert!([-20, 0, 20].contains(&ppm));
        assert_eq!(fixture["cfo_hz"], 0);
        let maximum = name.contains("max_length");
        assert!(combinations.insert((rate, ppm, maximum)));
        let iq = fs::read(root.join(format!("{name}.cs8"))).unwrap();
        assert_eq!(
            iq.len() as u64,
            2 * fixture["sample_count"].as_u64().unwrap()
        );
        assert_eq!(
            hex(&Sha256::digest(&iq)),
            fixture["sha256"].as_str().unwrap()
        );
        let encoded = fixture["psdu_hex"].as_str().unwrap();
        assert_eq!(encoded.len() % 2, 0);
        let psdu: Vec<u8> = encoded
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(psdu.len() == 4095, maximum);
        let split = psdu.len() - 4;
        assert_eq!(
            crc(&psdu[..split]),
            u32::from_le_bytes(psdu[split..].try_into().unwrap())
        );
        let symbols = (16 + 8 * psdu.len() + 6).div_ceil(rate as usize * 4);
        let origin = fixture["preamble_start"].as_u64().unwrap();
        let ratio = 1.0 + ppm as f64 * 1e-6;
        let expected_end = (origin as f64 + (400 + 80 * symbols) as f64 * ratio).ceil() as u64;
        assert_eq!(fixture["frame_end"], expected_end);
        assert_eq!(
            fixture["sample_count"],
            (origin as f64 + (432 + 80 * symbols) as f64 * ratio).ceil() as u64
        );
    }
    for (field, file) in [
        ("generator_sha256", "ofdm_clock_vectors.py"),
        ("encoder_sha256", "ofdm_vectors.py"),
    ] {
        let source = root
            .join("../../../../tools/oracle/engine/backends")
            .join(file);
        assert_eq!(
            manifest[field].as_str().unwrap(),
            hex(&Sha256::digest(fs::read(source).unwrap()))
        );
    }
}

#[test]
fn radio_independent_vector_inventory_and_integrity() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/iq");
    let index = fs::read_to_string(root.join("ofdm-index.tsv")).unwrap();
    let rates = [6, 9, 12, 18, 24, 36, 48, 54];
    assert_eq!(crc(b"123456789"), 0xcbf43926);
    assert_eq!(index.lines().skip(1).count(), 20);
    for (i, line) in index.lines().skip(1).enumerate() {
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 10);
        let name = fields[0];
        let number = |n: usize| fields[n].parse::<usize>().unwrap();
        let samples = fs::read(root.join(format!("{name}.cs8"))).unwrap();
        assert_eq!(samples.len(), number(5) * 2);
        assert_eq!(hex(&Sha256::digest(&samples)), fields[7]);
        let psdu: Vec<u8> = fields[6]
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let split = psdu.len() - 4;
        let received = u32::from_le_bytes(psdu[split..].try_into().unwrap());
        assert_eq!(crc(&psdu[..split]) == received, fields[8] == "True");
        assert_eq!(number(4), (16 + 8 * psdu.len() + 6).div_ceil(number(3)));
        let full_samples = 37 + 400 + 80 * number(4) + 32;
        assert_eq!(
            number(5),
            full_samples - if name.ends_with("truncated") { 73 } else { 0 }
        );
        if i < 8 {
            assert_eq!(number(1), rates[i]);
            assert_eq!(fields[9], "frame");
            assert_eq!(number(2), [1, 1, 2, 2, 4, 4, 6, 6][i]);
        }
        if i == 0 {
            // Fixed independently generated golden FCS, not calculated from fixture metadata.
            assert_eq!(received, 0x2dc356fb);
        }
        let intermediate = fs::read_to_string(root.join(format!("{name}.json"))).unwrap();
        for key in [
            "signal",
            "signal_coded",
            "signal_interleaved",
            "data",
            "scrambled",
            "coded",
            "punctured",
            "interleaved",
        ] {
            assert!(intermediate.contains(&format!("\"{key}\":")));
        }
    }
    let manifest = fs::read_to_string(root.join("ofdm-manifest.json")).unwrap();
    assert!(manifest.contains("\"sample_rate_hz\": 20000000"));
    assert!(manifest.contains("\"generator_version\": \"6\""));
}
