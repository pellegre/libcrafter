//! Offline verification of revision-bound public packet interface evidence.
use super::{
    artifact::{read_json, Config, Result},
    compare, transmit_compare,
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{BufReader, Read},
    path::Path,
};

pub const SCHEMA: &str = "crafter.interface.qualification/v1";
const GATES: [&str; 5] = [
    "tools/oracle/run specs validate --strict",
    "cargo test -p crafter --all-features --all-targets",
    "cargo test -p probe-adapters",
    ".agents/scripts/check-crafter-release --static",
    "cargo test -p crafter --features radio --test interface_qualification",
];

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("missing {key}").into())
}

fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    value[key]
        .as_array()
        .ok_or_else(|| format!("missing {key} array").into())
}

fn state(value: &Value, revision: &str) -> Result<()> {
    if value["revision"] != revision
        || value["cleanup"] != true
        || value["invalidating_failures"] != 0
    {
        return Err("revision, cleanup, or invalidating failure mismatch".into());
    }
    Ok(())
}

pub(super) fn file(base: &Path, value: &Value, label: &str) -> Result<std::path::PathBuf> {
    let path = transmit_compare::verified_file(base, value, label)?;
    // Resolve symlinks as well as lexical components before trusting the child.
    if !path.canonicalize()?.starts_with(base.canonicalize()?) {
        return Err(format!("{label} escapes artifact directory").into());
    }
    Ok(path)
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| "artifact path is not UTF-8".into())
}

fn json_file(base: &Path, value: &Value, label: &str) -> Result<(std::path::PathBuf, Value)> {
    let path = file(base, value, label)?;
    let value = serde_json::from_reader(File::open(&path)?)?;
    Ok((path, value))
}

pub(super) fn manifest(value: &Value) -> Result<&str> {
    let revision = text(value, "revision")?;
    if value["schema"] != SCHEMA
        || value["complete"] != true
        || revision.len() != 40
        || !revision
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !array(value, "unresolved_failures")?.is_empty()
    {
        return Err("invalid or incomplete interface qualification".into());
    }
    for mode in array(value, "untested_modes")? {
        text(mode, "mode")?;
        text(mode, "reason")?;
    }
    let gates = array(value, "gates")?;
    let mut seen = BTreeSet::new();
    for gate in gates {
        let command = text(gate, "command")?;
        if !seen.insert(command) || gate["revision"] != revision || gate["exit_code"] != 0 {
            return Err("duplicate, stale, or failed deterministic gate".into());
        }
    }
    if !GATES.iter().all(|command| seen.contains(command)) {
        return Err("missing required deterministic gate".into());
    }
    Ok(revision)
}

pub(super) fn verify_iq(base: &Path, run: &Value, receive: &Path) -> Result<()> {
    let iq = file(base, &run["iq"], "original IQ")?;
    let mut iq = BufReader::new(File::open(iq)?);
    let header = read_json(&mut iq)?.ok_or("missing IQ header")?;
    let mut decoded = BufReader::new(File::open(receive)?);
    let received_header = read_json(&mut decoded)?.ok_or("missing receive header")?;
    if !super::artifact::supported_schema(&header["schema"])
        || header["kind"] != "header"
        || header["iq_encoding"] != "cs8-binary/v1"
        || received_header["packet_interface"] != true
        || header["config"] != received_header["config"]
    {
        return Err("IQ encoding, configuration, or public interface provenance differs".into());
    }
    let config: Config = serde_json::from_value(header["config"].clone())?;
    config.rx()?;
    let mut terminal = false;
    let mut samples = 0u64;
    while let Some(chunk) = read_json(&mut iq)? {
        if terminal {
            return Err("IQ data after terminal".into());
        }
        match chunk["kind"].as_str() {
            Some("chunk") => {
                let count = chunk["samples"].as_u64().ok_or("missing IQ sample count")?;
                if count == 0 || count > config.max_chunk_samples as u64 {
                    return Err("invalid IQ chunk length".into());
                }
                samples = samples.checked_add(count).ok_or("IQ sample overflow")?;
                if samples > config.max_capture_samples {
                    return Err("IQ capture bound exceeded".into());
                }
                let mut bytes = vec![0; count as usize * 2 + 1];
                iq.read_exact(&mut bytes)?;
                if bytes.last() != Some(&b'\n') {
                    return Err("invalid IQ binary separator".into());
                }
                let received = loop {
                    let record = read_json(&mut decoded)?.ok_or("receive omits IQ chunk")?;
                    if record["kind"] == "chunk" {
                        break record;
                    }
                };
                for key in ["config", "position", "samples", "verified_prefix"] {
                    if received[key] != chunk[key] {
                        return Err(format!("receive/IQ {key} differs").into());
                    }
                }
            }
            Some("terminal")
                if matches!(
                    chunk["reason"].as_str(),
                    Some("Eof" | "LimitReached" | "Cancelled")
                ) =>
            {
                terminal = true
            }
            _ => return Err("failed or malformed IQ recording".into()),
        }
    }
    if !terminal || samples == 0 {
        return Err("incomplete IQ recording".into());
    }
    while let Some(record) = read_json(&mut decoded)? {
        if record["kind"] == "chunk" {
            return Err("receive has extra IQ chunks".into());
        }
    }
    Ok(())
}

pub(super) fn check_rx_gaps(report: &Value, run: &Value, inventory: &Value) -> Result<()> {
    let gaps = array(report, "qualification_gaps")?;
    if gaps.is_empty() {
        if !run["evidence_gaps"].is_null() && run["evidence_gaps"] != json!([]) {
            return Err("declared RX evidence gaps differ from observations".into());
        }
        return Ok(());
    }
    if gaps != &vec![json!(compare::REFERENCE_HT_CONFIGURATION_GAP)]
        || run["evidence_gaps"] != report["qualification_gaps"]
        || run["phy_scope"] != "known_fields"
    {
        return Err("unresolved or undisclosed RX evidence gap".into());
    }
    let disclosed = inventory.as_array().is_some_and(|entries| {
        entries.iter().any(|entry| {
            entry["mode"] == "reference-ht-configuration" && text(entry, "reason").is_ok()
        })
    });
    if !disclosed {
        return Err("unverified reference HT configuration missing from inventory".into());
    }
    Ok(())
}

fn receive(base: &Path, run: &Value, revision: &str, inventory: &Value) -> Result<Value> {
    state(run, revision)?;
    if run["api"] != "PacketWire"
        || run["backends"] != json!(["hackrf", "monitor"])
        || run["reference_capture_drops"] != 0
    {
        return Err("RX requires both public interface backends and loss evidence".into());
    }
    let kind = text(run, "kind")?;
    if !matches!(kind, "live" | "replay") {
        return Err("unknown RX qualification kind".into());
    }
    let receive = file(base, &run["receive"], "receive")?;
    let reference = file(base, &run["reference"], "reference")?;
    verify_iq(base, run, &receive)?;
    file(
        base,
        &run["overlap_evidence"],
        "independent overlap evidence",
    )?;
    let (_, policy) = json_file(base, &run["policy"], "policy")?;
    let policy: compare::Policy = serde_json::from_value(policy)?;
    policy.validate()?;
    let (a, ac, evidence) = compare::load_recovered(path_text(&receive)?, &policy)?;
    let (b, bc) = compare::load_reference(path_text(&reference)?, &policy)?;
    if evidence["receive_summary"]["parser_failures"] != 0 {
        return Err("RX parser failure".into());
    }
    if kind == "live" {
        check_acquisition(&evidence["acquisition"])?;
    }
    let report = compare::report(a, ac, b, bc, policy, evidence);
    if report["status"] != "measured" || report["exact_matches"].as_u64().unwrap_or(0) == 0 {
        return Err("no eligible exact RX matches".into());
    }
    check_rx_gaps(&report, run, inventory)?;
    let (_, recorded) = json_file(base, &run["comparison"], "RX comparison")?;
    for key in [
        "schema",
        "policy",
        "matches",
        "exact_matches",
        "families",
        "rates",
        "hackrf",
        "reference",
    ] {
        if recorded[key] != report[key] {
            return Err(format!("RX comparison differs from recomputed {key}").into());
        }
    }
    if kind == "replay" {
        let (_, baseline) = json_file(base, &run["baseline_comparison"], "replay baseline")?;
        if baseline["matches"] != report["matches"]
            || baseline["exact_matches"] != report["exact_matches"]
        {
            return Err("saved-IQ occurrence regression".into());
        }
    }
    Ok(report)
}

pub(super) fn check_acquisition(acquisition: &Value) -> Result<()> {
    let mut counts = BTreeMap::new();
    for key in [
        "received_samples",
        "verified_samples",
        "discarded_samples",
        "queue_overflows",
        "unknown_loss_intervals",
    ] {
        counts.insert(
            key,
            acquisition[key]
                .as_u64()
                .ok_or_else(|| format!("missing RX acquisition {key}"))?,
        );
    }
    if counts["verified_samples"] == 0
        || counts["verified_samples"] > counts["received_samples"]
        || counts["discarded_samples"] > counts["received_samples"]
        || counts["queue_overflows"] != 0
    {
        return Err("invalid or overflowed live RX acquisition".into());
    }
    // The original-record matcher validates each frame's uninterrupted sample
    // segment. Source loss outside that segment remains in reported evidence.
    Ok(())
}

pub(super) fn check_targets(report: &Value, targets: &Value) -> Result<()> {
    if report["policy"]["frame_control"] != targets["frame_control"] {
        return Err("RX frame selection differs from frozen target scope".into());
    }
    let thresholds = array(targets, "thresholds")?;
    if targets["schema"] != "crafter.interface.rx-targets/v1" || thresholds.is_empty() {
        return Err("missing fixed RX targets".into());
    }
    let mut families = BTreeSet::new();
    for target in thresholds {
        let family = text(target, "family")?;
        if !families.insert(family)
            || !matches!(family, "all" | "dsss" | "cck" | "legacy_ofdm" | "ht")
        {
            return Err("invalid RX target family".into());
        }
        let measured = if family == "all" {
            report
        } else {
            &report["families"][family]
        };
        for (required, actual) in [
            ("minimum_hackrf", "hackrf_valid_count"),
            ("minimum_reference", "eligible_dongle_count"),
            ("minimum_matches", "exact_matches"),
        ] {
            let minimum = target[required]
                .as_u64()
                .filter(|n| *n > 0)
                .ok_or("missing positive RX minimum")?;
            if measured[actual].as_u64().unwrap_or(0) < minimum {
                return Err(format!("RX target {family}/{required} failed").into());
            }
        }
        for fraction in ["hackrf_fraction", "dongle_fraction"] {
            let minimum = target[fraction]
                .as_f64()
                .filter(|n| *n > 0.0 && *n <= 1.0)
                .ok_or("invalid RX fraction target")?;
            if measured[fraction].as_f64().unwrap_or(0.0) < minimum {
                return Err(format!("RX target {family}/{fraction} failed").into());
            }
        }
    }
    Ok(())
}

fn monitor_radio(base: &Path, monitor: &Value, plan: &Path) -> Result<Value> {
    let receive = file(
        base,
        &monitor["receive"],
        "monitor TX independent radio receive",
    )?;
    verify_iq(base, monitor, &receive)?;
    file(
        base,
        &monitor["overlap_evidence"],
        "monitor TX overlap evidence",
    )?;
    let (_, policy) = json_file(base, &monitor["policy"], "monitor TX receive policy")?;
    let policy: compare::Policy = serde_json::from_value(policy)?;
    policy.validate()?;
    let (frames, _, evidence) = compare::load_recovered(path_text(&receive)?, &policy)?;
    if evidence["receive_summary"]["parser_failures"] != 0 {
        return Err("monitor TX independent receive failure".into());
    }
    check_acquisition(&evidence["acquisition"])?;
    let mut preambles = BTreeMap::new();
    let mut reader = BufReader::new(File::open(&receive)?);
    while let Some(record) = read_json(&mut reader)? {
        if record["kind"] == "frame" {
            let preamble = if record["phy"] == "legacy_ofdm" {
                Some(false)
            } else {
                match record["preamble"].as_str() {
                    Some("long") => Some(false),
                    Some("short") => Some(true),
                    _ => None,
                }
            };
            preambles.insert(
                record["ordinal"].as_u64().ok_or("missing frame ordinal")?,
                preamble,
            );
        }
    }
    let observed = frames
        .into_iter()
        .map(|frame| {
            let preamble = preambles.get(&frame.id).copied().flatten();
            (frame.bytes, frame.rate_bps, preamble, frame.ht)
        })
        .collect();
    let mut report = transmit_compare::compare_received(path_text(plan)?, observed)?;
    report["receiver_evidence"] = evidence;
    Ok(report)
}

/// Materialize the same independent radio comparison used by qualification.
pub fn compare_monitor_transmit(path: &str) -> Result<Value> {
    let value: Value = serde_json::from_reader(File::open(path)?)?;
    let base = Path::new(path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if value["api"] != "PacketWire"
        || value["backend"] != "monitor"
        || value["receiver_backend"] != "hackrf"
    {
        return Err("expected monitor transmission with independent radio reception".into());
    }
    let plan = file(base, &value["plan"], "monitor TX plan")?;
    monitor_radio(base, &value, &plan)
}

pub fn verify(path: &str) -> Result<Value> {
    let value: Value = serde_json::from_reader(File::open(path)?)?;
    let revision = manifest(&value)?;
    let base = Path::new(path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    for gate in array(&value, "gates")? {
        file(base, &gate["log"], "gate log")?;
    }
    let mut kinds = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut rx = Vec::new();
    let mut live_iq = BTreeSet::new();
    let mut live_reference = BTreeSet::new();
    for run in array(&value, "rx")? {
        if !ids.insert(text(run, "id")?) {
            return Err("duplicate RX run id".into());
        }
        let report = receive(base, run, revision, &value["untested_modes"])?;
        if run["kind"] == "live" {
            let (_, targets) = json_file(base, &value["rx_targets"], "fixed RX targets")?;
            if run["targets_sha256"] != value["rx_targets"]["sha256"] {
                return Err("live RX targets differ from frozen baseline".into());
            }
            let (_, baseline) =
                json_file(base, &targets["baseline_comparison"], "RX target baseline")?;
            check_targets(&baseline, &targets)?;
            check_targets(&report, &targets)?;
            if !live_iq.insert(text(&run["iq"], "sha256")?)
                || !live_reference.insert(text(&run["reference"], "sha256")?)
            {
                return Err("live RX acquisition reused across runs".into());
            }
        }
        rx.push(report);
        kinds.insert(text(run, "kind")?);
    }
    if !kinds.contains("live") || !kinds.contains("replay") {
        return Err("both fresh live RX and saved-IQ replay are required".into());
    }
    if live_iq.len() < 3 {
        return Err("RX qualification requires three independent live runs".into());
    }
    let mut tx = Vec::new();
    for family in ["legacy", "ht20"] {
        let (path, aggregate) = json_file(base, &value["tx"][family], "HackRF TX aggregate")?;
        if aggregate["revision"] != revision
            || aggregate["family"].as_str().unwrap_or("legacy") != family
        {
            return Err("TX aggregate revision or family differs".into());
        }
        for run in array(&aggregate, "runs")? {
            if run["api"] != "PacketWire" || run["backend"] != "hackrf" {
                return Err("HackRF TX qualification must exercise PacketWire".into());
            }
            let aggregate_base = path.parent().ok_or("missing aggregate directory")?;
            let plan = file(aggregate_base, &run["plan"], "HackRF TX plan")?;
            let capture = file(aggregate_base, &run["capture"], "HackRF TX capture")?;
            let (_, recorded) =
                json_file(aggregate_base, &run["comparison"], "HackRF TX comparison")?;
            let report = transmit_compare::compare(path_text(&plan)?, path_text(&capture)?)?;
            if report["status"] != "passed" || report != recorded {
                return Err("HackRF TX comparison differs from independent capture".into());
            }
            for transmit in array(run, "transmits")? {
                file(aggregate_base, transmit, "HackRF TX submission")?;
            }
        }
        tx.push(transmit_compare::verify_qualification(path_text(&path)?)?);
    }
    let monitor = &value["tx"]["monitor"];
    state(monitor, revision)?;
    if monitor["api"] != "PacketWire"
        || monitor["backend"] != "monitor"
        || monitor["reference_capture_drops"] != 0
    {
        return Err("invalid monitor TX interface evidence".into());
    }
    let plan = file(base, &monitor["plan"], "monitor TX plan")?;
    let (_, submission) = json_file(base, &monitor["submission"], "monitor submission")?;
    state(&submission, revision)?;
    if submission["api"] != "PacketWire"
        || submission["backend"] != "monitor"
        || submission["submitted_packets"].as_u64().unwrap_or(0) == 0
        || submission["failed_packets"] != 0
    {
        return Err("monitor submission incomplete".into());
    }
    let report = match text(monitor, "receiver_backend")? {
        "hackrf" => monitor_radio(base, monitor, &plan)?,
        "monitor" => {
            let capture = file(base, &monitor["capture"], "monitor TX independent capture")?;
            transmit_compare::compare(path_text(&plan)?, path_text(&capture)?)?
        }
        _ => return Err("unknown monitor TX independent receiver".into()),
    };
    let (_, recorded) = json_file(base, &monitor["comparison"], "monitor TX comparison")?;
    if report["status"] != "passed"
        || report != recorded
        || report["required_cases"].as_u64().unwrap_or(0) == 0
        || submission["submitted_packets"].as_u64().unwrap_or(0)
            < report["required_cases"].as_u64().unwrap_or(u64::MAX)
    {
        return Err("monitor TX independent reception failed".into());
    }
    Ok(
        json!({"schema":SCHEMA,"status":"passed","revision":revision,
        "rx":rx,"hackrf_tx":tx,"monitor_tx":report,"untested_modes":value["untested_modes"]}),
    )
}
