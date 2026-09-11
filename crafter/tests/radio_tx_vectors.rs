#![cfg(feature = "radio")]

use crafter::radio::{
    DsssCckDecoder, DsssPreamble, IqChunk, IqEvent, IqPosition, LegacyDsssCckRate,
    LegacyDsssCckTransmission, LegacyDsssCckTxConfig, LegacyOfdmDecoder, LegacyOfdmRate,
    LegacyOfdmTransmission, LegacyOfdmTxConfig, PhyDecoder, PhyDiagnostic, RecoveredFrame,
    RxConfig,
};
use serde_json::Value;
use std::{fs, path::PathBuf, time::Duration};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/iq")
}

fn rates() -> [(LegacyOfdmRate, &'static str); 8] {
    [
        (LegacyOfdmRate::Mbps6, "ofdm-tx-6"),
        (LegacyOfdmRate::Mbps9, "ofdm-tx-9"),
        (LegacyOfdmRate::Mbps12, "ofdm-tx-12"),
        (LegacyOfdmRate::Mbps18, "ofdm-tx-18"),
        (LegacyOfdmRate::Mbps24, "ofdm-tx-24"),
        (LegacyOfdmRate::Mbps36, "ofdm-tx-36"),
        (LegacyOfdmRate::Mbps48, "ofdm-tx-48"),
        (LegacyOfdmRate::Mbps54, "ofdm-tx-54"),
    ]
}

fn dsss_rates() -> [(LegacyDsssCckRate, DsssPreamble, &'static str); 7] {
    [
        (
            LegacyDsssCckRate::Mbps1,
            DsssPreamble::Long,
            "dsss-tx-1-long",
        ),
        (
            LegacyDsssCckRate::Mbps2,
            DsssPreamble::Long,
            "dsss-tx-2-long",
        ),
        (
            LegacyDsssCckRate::Mbps5_5,
            DsssPreamble::Long,
            "dsss-tx-5.5-long",
        ),
        (
            LegacyDsssCckRate::Mbps11,
            DsssPreamble::Long,
            "dsss-tx-11-long",
        ),
        (
            LegacyDsssCckRate::Mbps2,
            DsssPreamble::Short,
            "dsss-tx-2-short",
        ),
        (
            LegacyDsssCckRate::Mbps5_5,
            DsssPreamble::Short,
            "dsss-tx-5.5-short",
        ),
        (
            LegacyDsssCckRate::Mbps11,
            DsssPreamble::Short,
            "dsss-tx-11-short",
        ),
    ]
}

fn fixture_cs8(stem: &str) -> Vec<i8> {
    fs::read(fixtures().join(format!("{stem}.cs8")))
        .unwrap()
        .into_iter()
        .map(|byte| byte as i8)
        .collect()
}

fn fixture_psdu(stem: &str) -> Vec<u8> {
    fs::read(fixtures().join(format!("{stem}.psdu"))).unwrap()
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

fn assert_cs8(stem: &str, actual: &[i8]) {
    let expected = fixture_cs8(stem);
    assert_eq!(actual.len(), expected.len(), "{stem} sample byte length");
    let differences: Vec<_> = actual
        .iter()
        .zip(&expected)
        .enumerate()
        .filter(|(_, (a, b))| a != b)
        .take(20)
        .collect();
    if !differences.is_empty() {
        panic!("{stem} CS8 mismatches: {differences:?}");
    }
}

fn decode(cs8: &[i8], chunk_samples: usize, max_frame_bytes: usize) -> Vec<Vec<u8>> {
    let config = RxConfig {
        sample_rate_hz: 20_000_000,
        center_frequency_hz: 2_412_000_000,
        max_chunk_samples: chunk_samples,
        max_buffer_samples: 400_000,
        max_frame_bytes,
        max_pending_frames: 4,
        max_capture_samples: 1_000_000,
        max_duration: Duration::from_secs(1),
    };
    let mut decoder = LegacyOfdmDecoder::new();
    let mut frames = Vec::new();
    let mut sample_index = 0u64;
    for (sequence, chunk) in cs8.chunks(chunk_samples * 2).enumerate() {
        let event = IqEvent::Chunk(
            IqChunk::new(
                config.clone(),
                IqPosition {
                    epoch: 0,
                    sequence: sequence as u64,
                    sample_index,
                    time_anchor: None,
                    discontinuity: None,
                },
                chunk.to_vec(),
            )
            .unwrap(),
        );
        sample_index += (chunk.len() / 2) as u64;
        frames.extend(
            decoder
                .consume(event)
                .unwrap()
                .frames
                .into_iter()
                .map(|frame| frame.bytes),
        );
    }
    frames
}

fn decode_dsss(cs8: &[i8], chunk_samples: usize, max_frame_bytes: usize) -> Vec<RecoveredFrame> {
    let config = RxConfig {
        sample_rate_hz: 20_000_000,
        center_frequency_hz: 2_412_000_000,
        max_chunk_samples: chunk_samples,
        max_buffer_samples: 400_000,
        max_frame_bytes,
        max_pending_frames: 4,
        max_capture_samples: 1_000_000,
        max_duration: Duration::from_secs(1),
    };
    let mut decoder = DsssCckDecoder::new();
    let mut frames = Vec::new();
    let mut sample_index = 0u64;
    for (sequence, chunk) in cs8.chunks(chunk_samples * 2).enumerate() {
        let event = IqEvent::Chunk(
            IqChunk::new(
                config.clone(),
                IqPosition {
                    epoch: 0,
                    sequence: sequence as u64,
                    sample_index,
                    time_anchor: None,
                    discontinuity: None,
                },
                chunk.to_vec(),
            )
            .unwrap(),
        );
        sample_index += (chunk.len() / 2) as u64;
        frames.extend(decoder.consume(event).unwrap().frames);
    }
    frames
}

#[test]
fn radio_dsss_tx_matches_all_oracle_vectors_and_round_trips() {
    let manifest: Value =
        serde_json::from_slice(&fs::read(fixtures().join("dsss-transmit-manifest.json")).unwrap())
            .unwrap();
    let cases = manifest["cases"].as_array().unwrap();
    for (rate, preamble, stem) in dsss_rates() {
        let psdu = fixture_psdu(stem);
        let tx = LegacyDsssCckTransmission::encode(
            &psdu[..psdu.len() - 4],
            None,
            &LegacyDsssCckTxConfig::new(rate, preamble),
        )
        .unwrap();
        let oracle = cases
            .iter()
            .find(|case| case["artifact_stem"] == stem)
            .unwrap();
        assert_eq!(tx.psdu_bytes, psdu, "{stem} PSDU");
        assert_cs8(stem, &tx.cs8);
        assert_eq!(tx.rate.bps() as u64, oracle["rate_bps"].as_u64().unwrap());
        assert_eq!(tx.preamble.is_short(), oracle["preamble"] == "short");
        assert_eq!(
            tx.sample_count() as u64,
            oracle["sample_count"].as_u64().unwrap()
        );
        assert_eq!(
            tx.plcp.transmitted.as_slice(),
            decode_hex(oracle["header_hex"].as_str().unwrap())
        );
        assert!((tx.payload_start_sample - oracle["payload_start"].as_f64().unwrap()).abs() < 1e-9);
        assert!((tx.frame_end_sample - oracle["frame_end"].as_f64().unwrap()).abs() < 1e-9);
        for chunk_samples in [1, 37, 509, tx.sample_count()] {
            let decoded = decode_dsss(&tx.cs8, chunk_samples, 4095);
            assert_eq!(decoded.len(), 1, "{stem} chunks={chunk_samples}");
            assert_eq!(decoded[0].bytes, psdu, "{stem} chunks={chunk_samples}");
            assert_eq!(decoded[0].rate_bps, rate.bps());
            assert!(
                decoded[0]
                    .start
                    .sample_index
                    .abs_diff(tx.leading_samples as u64)
                    <= 3
            );
            assert!(
                decoded[0]
                    .end_sample_index
                    .abs_diff(tx.frame_end_sample.ceil() as u64)
                    <= 3
            );
            assert!(matches!(
                decoded[0].diagnostics.as_slice(),
                [PhyDiagnostic::Dsss { short_preamble, .. }] if *short_preamble == preamble.is_short()
            ));
        }
    }
}

#[test]
fn radio_dsss_tx_preserves_explicit_malformed_wire_fields() {
    let canonical = fixture_psdu("dsss-tx-1-long");
    let mac = &canonical[..canonical.len() - 4];
    let wrong_fcs = LegacyDsssCckTransmission::encode(
        mac,
        Some([0; 4]),
        &LegacyDsssCckTxConfig::new(LegacyDsssCckRate::Mbps1, DsssPreamble::Long),
    )
    .unwrap();
    assert_eq!(
        wrong_fcs.psdu_bytes,
        fixture_psdu("dsss-tx-1-long-explicit-wrong-fcs")
    );
    assert_cs8("dsss-tx-1-long-explicit-wrong-fcs", &wrong_fcs.cs8);
    assert!(decode_dsss(&wrong_fcs.cs8, 73, 4095).is_empty());

    let mut config = LegacyDsssCckTxConfig::new(LegacyDsssCckRate::Mbps1, DsssPreamble::Long);
    config.plcp_override = Some([10, 0, 0xc0, 0x02, 0xc9, 0xc9]);
    let wrong_plcp = LegacyDsssCckTransmission::encode(mac, None, &config).unwrap();
    assert_cs8("dsss-tx-1-long-explicit-wrong-plcp-crc", &wrong_plcp.cs8);
    assert!(decode_dsss(&wrong_plcp.cs8, 73, 4095).is_empty());
}

#[test]
fn radio_ofdm_tx_matches_all_oracle_vectors_and_round_trips() {
    let manifest: Value =
        serde_json::from_slice(&fs::read(fixtures().join("ofdm-transmit-manifest.json")).unwrap())
            .unwrap();
    let cases = manifest["cases"].as_array().unwrap();
    for (rate, stem) in rates() {
        let psdu = fixture_psdu(stem);
        let tx = LegacyOfdmTransmission::encode(
            &psdu[..psdu.len() - 4],
            None,
            &LegacyOfdmTxConfig::new(rate),
        )
        .unwrap();
        let oracle = cases
            .iter()
            .find(|case| case["artifact_stem"] == stem)
            .unwrap();
        assert_eq!(tx.psdu_bytes, psdu, "{stem} PSDU");
        assert_cs8(stem, &tx.cs8);
        assert_eq!(tx.rate.mbps() as u64, oracle["rate_mbps"].as_u64().unwrap());
        assert_eq!(
            tx.sample_count() as u64,
            oracle["sample_count"].as_u64().unwrap()
        );
        assert_eq!(tx.data_symbols as u64, oracle["nsym"].as_u64().unwrap());
        assert_eq!(
            tx.signal.transmitted.as_slice(),
            oracle["signal_bits"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_u64().unwrap() as u8)
                .collect::<Vec<_>>()
        );
        for chunk_samples in [1, 17, 257, tx.sample_count()] {
            assert_eq!(
                decode(&tx.cs8, chunk_samples, 4095),
                vec![psdu.clone()],
                "{stem} chunks={chunk_samples}"
            );
        }
    }
}

#[test]
fn radio_ofdm_tx_preserves_explicit_malformed_wire_fields() {
    let canonical = fixture_psdu("ofdm-tx-6");
    let mac = &canonical[..canonical.len() - 4];

    let wrong_fcs = LegacyOfdmTransmission::encode(
        mac,
        Some([0; 4]),
        &LegacyOfdmTxConfig::new(LegacyOfdmRate::Mbps6),
    )
    .unwrap();
    assert_eq!(
        wrong_fcs.psdu_bytes,
        fixture_psdu("ofdm-tx-6-explicit-wrong-fcs")
    );
    assert_cs8("ofdm-tx-6-explicit-wrong-fcs", &wrong_fcs.cs8);
    assert!(decode(&wrong_fcs.cs8, 73, 4095).is_empty());

    let mut config = LegacyOfdmTxConfig::new(LegacyOfdmRate::Mbps6);
    config.signal_override = Some([
        1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
    ]);
    let wrong_signal = LegacyOfdmTransmission::encode(mac, None, &config).unwrap();
    assert_cs8("ofdm-tx-6-explicit-wrong-signal", &wrong_signal.cs8);
    assert!(decode(&wrong_signal.cs8, 73, 4095).is_empty());
}

#[test]
fn radio_ofdm_tx_minimum_and_maximum_lengths() {
    for bytes in [0usize, 4091] {
        let mac = vec![0x5a; bytes];
        for rate in LegacyOfdmRate::ALL {
            let tx =
                LegacyOfdmTransmission::encode(&mac, None, &LegacyOfdmTxConfig::new(rate)).unwrap();
            assert_eq!(tx.psdu_bytes.len(), bytes + 4);
            assert_eq!(decode(&tx.cs8, 509, 4095), vec![tx.psdu_bytes.clone()]);
        }
    }
}
