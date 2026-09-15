#![cfg(feature = "radio")]
#[path = "../examples/radio_support/artifact.rs"]
mod artifact;
#[path = "../examples/radio_support/compare.rs"]
#[allow(dead_code)]
mod compare;
#[path = "../examples/radio_support/ht_compare.rs"]
mod ht_compare;
#[path = "../examples/radio_support/interface_qualification.rs"]
mod interface_qualification;
#[path = "../examples/radio_support/transmit_compare.rs"]
#[allow(dead_code)]
mod transmit_compare;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";

#[test]
fn unknown_reference_configuration_requires_explicit_scope_and_inventory() {
    let report = json!({"qualification_gaps":[compare::REFERENCE_HT_CONFIGURATION_GAP]});
    let run = json!({"phy_scope":"known_fields","evidence_gaps":report["qualification_gaps"]});
    let inventory = json!([{"mode":"reference-ht-configuration","reason":"reference omits configuration fields"}]);
    assert!(interface_qualification::check_rx_gaps(&report, &run, &inventory).is_ok());
    assert_eq!(report["qualification_gaps"].as_array().unwrap().len(), 1);
    for value in [
        json!({}),
        json!({"phy_scope":"known_fields"}),
        json!({"evidence_gaps":report["qualification_gaps"]}),
    ] {
        assert!(interface_qualification::check_rx_gaps(&report, &value, &inventory).is_err());
    }
    for value in [
        json!([]),
        json!([{"mode":"reference-ht-configuration","reason":""}]),
        json!([{"mode":"another-mode","reason":"unverified"}]),
    ] {
        assert!(interface_qualification::check_rx_gaps(&report, &run, &value).is_err());
    }
    for gaps in [
        json!(["synthetic unknown gap"]),
        json!([
            compare::REFERENCE_HT_CONFIGURATION_GAP,
            "synthetic unknown gap"
        ]),
        json!([
            compare::REFERENCE_HT_CONFIGURATION_GAP,
            compare::REFERENCE_HT_CONFIGURATION_GAP
        ]),
    ] {
        let changed = json!({"qualification_gaps":gaps});
        let declared = json!({"phy_scope":"known_fields","evidence_gaps":gaps});
        assert!(interface_qualification::check_rx_gaps(&changed, &declared, &inventory).is_err());
    }
    let complete = json!({"qualification_gaps":[]});
    assert!(interface_qualification::check_rx_gaps(&complete, &json!({}), &json!([])).is_ok());
    assert!(interface_qualification::check_rx_gaps(&complete, &run, &inventory).is_err());
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "crafter-interface-qualification-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn artifact(&self, name: &str, bytes: &[u8]) -> Value {
        fs::write(self.0.join(name), bytes).unwrap();
        json!({"path":name,"sha256":artifact::hex(&Sha256::digest(bytes))})
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn manifest() -> Value {
    let commands = [
        "tools/oracle/run specs validate --strict",
        "cargo test -p crafter --all-features --all-targets",
        "cargo test -p probe-adapters",
        ".agents/scripts/check-crafter-release --static",
        "cargo test -p crafter --features radio --test interface_qualification",
    ];
    json!({"schema":interface_qualification::SCHEMA,"complete":true,"revision":REVISION,
        "gates":commands.map(|command|json!({"command":command,"exit_code":0,"revision":REVISION})),
        "untested_modes":[{"mode":"synthetic-unsupported-mode","reason":"no independent observation"}],
        "unresolved_failures":[],"rx":[],"tx":{}})
}

#[test]
fn accepts_complete_revision_bound_manifest_and_retains_untested_inventory() {
    assert_eq!(
        interface_qualification::manifest(&manifest()).unwrap(),
        REVISION
    );
}

#[test]
fn rejects_stale_failed_missing_duplicate_and_incomplete_gate_evidence() {
    for (pointer, replacement) in [
        ("/revision", json!("not-a-revision")),
        ("/complete", json!(false)),
        ("/unresolved_failures", json!(["synthetic failure"])),
        (
            "/gates/0/revision",
            json!("ffffffffffffffffffffffffffffffffffffffff"),
        ),
        ("/gates/1/exit_code", json!(1)),
        ("/gates", json!([])),
        ("/untested_modes/0/reason", json!("")),
    ] {
        let mut value = manifest();
        *value.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            interface_qualification::manifest(&value).is_err(),
            "{pointer}"
        );
    }
    let mut value = manifest();
    let duplicate = value["gates"][0].clone();
    value["gates"].as_array_mut().unwrap().push(duplicate);
    assert!(interface_qualification::manifest(&value).is_err());
}

#[test]
fn verifies_nonempty_artifact_bytes_and_rejects_changed_missing_and_escaping_files() {
    let dir = Scratch::new();
    let reference = dir.artifact("evidence.json", br#"{"synthetic":true}"#);
    assert!(interface_qualification::file(&dir.0, &reference, "synthetic").is_ok());
    fs::write(dir.0.join("evidence.json"), b"changed").unwrap();
    assert!(interface_qualification::file(&dir.0, &reference, "synthetic").is_err());
    let mut reference = reference;
    for path in ["missing.json", "../evidence.json", "/evidence.json"] {
        reference["path"] = json!(path);
        assert!(interface_qualification::file(&dir.0, &reference, "synthetic").is_err());
    }
    let empty = dir.artifact("empty", b"");
    assert!(interface_qualification::file(&dir.0, &empty, "synthetic").is_err());
}

#[cfg(unix)]
#[test]
fn rejects_symlink_escape_even_when_digest_matches() {
    let dir = Scratch::new();
    let outside = Scratch::new();
    let mut reference = outside.artifact("outside.json", b"synthetic");
    std::os::unix::fs::symlink(outside.0.join("outside.json"), dir.0.join("linked.json")).unwrap();
    reference["path"] = json!("linked.json");
    assert!(interface_qualification::file(&dir.0, &reference, "synthetic").is_err());
}

#[test]
fn gate_success_cannot_substitute_for_live_or_replayed_hardware_evidence() {
    let dir = Scratch::new();
    let mut value = manifest();
    let log = dir.artifact("gate.log", b"synthetic gate output\n");
    for gate in value["gates"].as_array_mut().unwrap() {
        gate["log"] = log.clone();
    }
    let path = dir.0.join("summary.json");
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let error = interface_qualification::verify(path.to_str().unwrap())
        .unwrap_err()
        .to_string();
    assert!(error.contains("fresh live RX"), "{error}");
}

#[test]
fn monitor_comparison_requires_independent_radio_artifacts() {
    let dir = Scratch::new();
    let path = dir.0.join("monitor.json");
    for value in [
        json!({"api":"PacketWire","backend":"monitor","receiver_backend":"monitor"}),
        json!({"api":"PacketWire","backend":"monitor","receiver_backend":"hackrf"}),
    ] {
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(interface_qualification::compare_monitor_transmit(path.to_str().unwrap()).is_err());
    }
}

#[test]
fn fixed_targets_require_both_denominators_matches_and_per_family_fractions() {
    let report = json!({"hackrf_valid_count":10,"eligible_dongle_count":20,"exact_matches":8,
        "hackrf_fraction":0.8,"dongle_fraction":0.4});
    let target = json!({"schema":"crafter.interface.rx-targets/v1","thresholds":[{
        "family":"all","minimum_hackrf":10,"minimum_reference":20,"minimum_matches":8,
        "hackrf_fraction":0.8,"dongle_fraction":0.4}]});
    assert!(interface_qualification::check_targets(&report, &target).is_ok());
    for key in [
        "hackrf_valid_count",
        "eligible_dongle_count",
        "exact_matches",
        "hackrf_fraction",
        "dongle_fraction",
    ] {
        let mut failed = report.clone();
        failed[key] = json!(0);
        assert!(
            interface_qualification::check_targets(&failed, &target).is_err(),
            "{key}"
        );
    }
    let mut per_family = target.clone();
    per_family["thresholds"][0]["family"] = json!("ht");
    assert!(interface_qualification::check_targets(&report, &per_family).is_err());
    let mut invalid = target;
    invalid["thresholds"][0]["hackrf_fraction"] = json!(1.1);
    assert!(interface_qualification::check_targets(&report, &invalid).is_err());
}

#[test]
fn bounded_source_loss_is_not_promoted_to_continuous_capture() {
    let acquisition = json!({"received_samples":1000,"verified_samples":800,
        "discarded_samples":200,"queue_overflows":0,"unknown_loss_intervals":1});
    assert!(interface_qualification::check_acquisition(&acquisition).is_ok());
    for (key, value) in [
        ("received_samples", Value::Null),
        ("unknown_loss_intervals", Value::Null),
        ("verified_samples", json!(0)),
        ("verified_samples", json!(1001)),
        ("discarded_samples", json!(1001)),
        ("queue_overflows", json!(1)),
    ] {
        let mut invalid = acquisition.clone();
        invalid[key] = value;
        assert!(
            interface_qualification::check_acquisition(&invalid).is_err(),
            "{key}"
        );
    }
}

#[test]
fn iq_receipt_checks_actual_binary_length_continuity_metadata_and_terminal() {
    let dir = Scratch::new();
    let config = json!({"sample_rate_hz":20_000_000,"center_frequency_hz":2_412_000_000u64,
        "max_chunk_samples":1024,"max_buffer_samples":4096,"max_frame_bytes":4095,
        "max_pending_frames":16,"max_capture_samples":2048,"max_duration_ns":1_000_000_000u64});
    let header = json!({"kind":"header","schema":"crafter.radio.receive/v2","config":config,
        "packet_interface":true,"iq_encoding":"cs8-binary/v1"});
    let chunk = json!({"kind":"chunk","config":config,"position":{"epoch":0,"sequence":0,
        "sample_index":0,"anchor":null,"gap_reason":null,"lost_samples":null},"samples":2,"verified_prefix":true});
    let terminal = json!({"kind":"terminal","reason":"LimitReached"});
    let receive = format!("{header}\n{chunk}\n{terminal}\n");
    dir.artifact("receive.jsonl", receive.as_bytes());
    let mut iq = format!("{header}\n{chunk}\n").into_bytes();
    iq.extend_from_slice(&[1, 2, 3, 4, b'\n']);
    iq.extend_from_slice(format!("{terminal}\n").as_bytes());
    let artifact = dir.artifact("samples.iq", &iq);
    let run = json!({"iq":artifact});
    assert!(interface_qualification::verify_iq(&dir.0, &run, &dir.0.join("receive.jsonl")).is_ok());
    let mut changed_chunk = chunk.clone();
    changed_chunk["position"]["sample_index"] = json!(7);
    fs::write(
        dir.0.join("receive.jsonl"),
        format!("{header}\n{changed_chunk}\n{terminal}\n"),
    )
    .unwrap();
    assert!(
        interface_qualification::verify_iq(&dir.0, &run, &dir.0.join("receive.jsonl")).is_err()
    );
    fs::write(dir.0.join("receive.jsonl"), &receive).unwrap();
    for bytes in [
        format!("{header}\n{chunk}\n").into_bytes(),
        [
            format!("{header}\n{chunk}\n").as_bytes(),
            &[1, 2, 3, 4, b'\n'],
        ]
        .concat(),
    ] {
        let artifact = dir.artifact("samples.iq", &bytes);
        assert!(interface_qualification::verify_iq(
            &dir.0,
            &json!({"iq":artifact}),
            &dir.0.join("receive.jsonl")
        )
        .is_err());
    }
}

#[test]
fn only_frames_inside_verified_segments_are_eligible_after_a_gap() {
    use crafter::prelude::*;
    use crafter::radio::PacketEncoder;
    let dir = Scratch::new();
    let record = PacketRecord::new(Dot11::data() / Raw::from("synthetic segment"));
    let encoded = LegacyWifiTxConfig::ofdm(LegacyOfdmRate::Mbps6)
        .encode_packet(&record)
        .unwrap();
    let config = json!({"sample_rate_hz":20_000_000,"center_frequency_hz":2_412_000_000u64,
        "max_chunk_samples":100,"max_buffer_samples":1000,"max_frame_bytes":4095,
        "max_pending_frames":16,"max_capture_samples":1000,"max_duration_ns":1_000_000_000u64});
    let position = |index, sequence| {
        json!({"epoch":0,"sequence":sequence,"sample_index":index,
        "anchor":{"sample_index":0,"unix_ns":1_500_000_000u64,"uncertainty_ns":1},
        "gap_reason":null,"lost_samples":null})
    };
    let chunk = |index, sequence| {
        json!({"kind":"chunk","config":config,
        "position":position(index,sequence),"samples":100,"verified_prefix":true})
    };
    let frame = |ordinal, start, end, sequence| {
        json!({"kind":"frame","ordinal":ordinal,
        "config":config,"position":position(start,sequence),"end_sample_index":end,
        "phy":"legacy_ofdm","rate_bps":6_000_000,"fcs":"present_valid",
        "original_mac_hex":artifact::hex(encoded.psdu_bytes())})
    };
    let records = [
        json!({"kind":"header","schema":artifact::SCHEMA,"config":config}),
        chunk(0, 0),
        frame(1, 10, 20, 0),
        chunk(200, 1),
        frame(2, 50, 210, 0),
        frame(3, 210, 220, 1),
        json!({"kind":"terminal","reason":"Eof"}),
        json!({"kind":"summary","complete":true,"terminal":"Eof",
            "decoder":{"valid_frames":3,"dropped_frames":0},"parsed_packets":3,"parser_failures":0}),
    ];
    let path = dir.0.join("segments.jsonl");
    fs::write(
        &path,
        records.iter().map(|r| format!("{r}\n")).collect::<String>(),
    )
    .unwrap();
    let policy = serde_json::from_value(json!({"schema":"crafter.radio.comparison-policy/v1",
        "overlap_ns":[1_000_000_000u64,2_000_000_000u64],
        "hackrf_capture_ns":[1_000_000_000u64,2_000_000_000u64],
        "reference_capture_ns":[1_000_000_000u64,2_000_000_000u64],
        "center_frequency_hz":2_412_000_000u64,"reference_uncertainty_ns":1,
        "match_window_ns":1000,"anchors":[],"max_observations":10}))
    .unwrap();
    let (frames, counts, evidence) =
        compare::load_recovered(path.to_str().unwrap(), &policy).unwrap();
    assert_eq!(frames.iter().map(|f| f.id).collect::<Vec<_>>(), [1, 3]);
    assert_eq!(counts.excluded["unqualified_continuity"], 1);
    assert_eq!(evidence["gaps"], 1);
}
