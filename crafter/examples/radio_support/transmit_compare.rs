//! Exact comparison of an offline transmit manifest with a radiotap capture.

use super::artifact::{hex, read_json, unhex, valid_fcs, Result};
use crafter::{LinkType, Packet, Radiotap};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{BufReader, Read},
    path::{Component, Path, PathBuf},
};

pub const PLAN_SCHEMA: &str = "crafter.radio.transmit/v1";
pub const REPORT_SCHEMA: &str = "crafter.radio.transmit-comparison/v1";
pub const QUALIFICATION_SCHEMA: &str = "crafter.radio.transmit-qualification/v1";
const MATRIX_CASE_IDS: [&str; 15] = [
    "ofdm-6-long",
    "ofdm-9-long",
    "ofdm-12-long",
    "ofdm-18-long",
    "ofdm-24-long",
    "ofdm-36-long",
    "ofdm-48-long",
    "ofdm-54-long",
    "dsss-1-long",
    "dsss-2-long",
    "dsss-2-short",
    "cck-5_5-long",
    "cck-5_5-short",
    "cck-11-long",
    "cck-11-short",
];

#[derive(Debug, Clone)]
struct PlannedCase {
    id: String,
    mac: Vec<u8>,
    rate_bps: u32,
    short: bool,
}

#[derive(Debug, Clone)]
struct Observed {
    mac: Vec<u8>,
    rate_bps: u32,
    short: bool,
    fcs: &'static str,
}

fn load_plan(path: &str) -> Result<Vec<PlannedCase>> {
    let mut reader = BufReader::new(File::open(path)?);
    let header = read_json(&mut reader)?.ok_or("empty transmit artifact")?;
    if header["schema"] != PLAN_SCHEMA || header["kind"] != "header" {
        return Err("invalid transmit header".into());
    }
    let declared = header["case_count"].as_u64().ok_or("missing case count")? as usize;
    let mut cases = Vec::with_capacity(declared);
    let mut summary = None;
    while let Some(value) = read_json(&mut reader)? {
        match value["kind"].as_str() {
            Some("case") => {
                let id = value["case_id"]
                    .as_str()
                    .ok_or("missing case id")?
                    .to_owned();
                if cases.iter().any(|case: &PlannedCase| case.id == id) {
                    return Err("duplicate transmit case".into());
                }
                cases.push(PlannedCase {
                    id,
                    mac: unhex(value["mac_hex"].as_str().ok_or("missing MAC bytes")?)?,
                    rate_bps: value["rate_bps"]
                        .as_u64()
                        .and_then(|v| u32::try_from(v).ok())
                        .ok_or("invalid rate")?,
                    short: value["preamble"] == "short",
                });
            }
            Some("summary") => summary = Some(value),
            _ => return Err("unexpected transmit record".into()),
        }
    }
    let summary = summary.ok_or("missing transmit summary")?;
    if summary["complete"] != true || summary["terminal"] != "complete" || cases.len() != declared {
        return Err("incomplete transmit artifact".into());
    }
    Ok(cases)
}

fn observed_frame(data: &[u8], original_len: u32) -> std::result::Result<Observed, &'static str> {
    if data.len() != original_len as usize || data.len() < 8 || data[0] != 0 {
        return Err("truncated_or_framing");
    }
    let header_len = u16::from_le_bytes([data[2], data[3]]) as usize;
    if !(8..=data.len()).contains(&header_len) {
        return Err("truncated_or_framing");
    }
    let packet = Packet::decode_from_link(LinkType::Radiotap, &data[..header_len])
        .map_err(|_| "unsupported_radiotap")?;
    let radiotap = packet.layer::<Radiotap>().ok_or("unsupported_radiotap")?;
    let flags = radiotap.flags_value().ok_or("missing_flags")?;
    if flags.failed_fcs()
        || radiotap
            .rx_flags_value()
            .is_some_and(|flags| flags.bits() & 2 != 0)
    {
        return Err("invalid_fcs_or_phy");
    }
    let rate_bps = u32::from(radiotap.rate_value().ok_or("missing_rate")?) * 500_000;
    let short = flags.bits() & 2 != 0;
    if rate_bps == 1_000_000 && short {
        return Err("invalid_preamble");
    }
    let mut mac = data[header_len..].to_vec();
    let fcs = if flags.fcs_present() {
        if !valid_fcs(&mac) {
            return Err("invalid_fcs_or_phy");
        }
        mac.truncate(mac.len() - 4);
        "present_valid"
    } else {
        "absent"
    };
    Ok(Observed {
        mac,
        rate_bps,
        short,
        fcs,
    })
}

fn compare_cases(
    cases: &[PlannedCase],
    observed: &[Observed],
    exclusions: BTreeMap<String, u64>,
) -> Value {
    let mut available = observed.to_vec();
    let mut results = Vec::with_capacity(cases.len());
    for case in cases {
        let exact = available.iter().position(|frame| {
            frame.mac == case.mac && frame.rate_bps == case.rate_bps && frame.short == case.short
        });
        let bytes_only = available.iter().any(|frame| frame.mac == case.mac);
        let match_value = exact.map(|index| available.remove(index));
        results.push(json!({
            "case_id": case.id, "rate_bps": case.rate_bps,
            "preamble": if case.short {"short"} else {"long"},
            "status": if match_value.is_some() {"passed"} else if bytes_only {"metadata_mismatch"} else {"missing"},
            "fcs": match_value.as_ref().map(|frame| frame.fcs),
            "mac_hex": hex(&case.mac)
        }));
    }
    let passed = results
        .iter()
        .filter(|result| result["status"] == "passed")
        .count();
    json!({
        "schema": REPORT_SCHEMA, "status": if passed == cases.len() {"passed"} else {"failed"},
        "required_cases": cases.len(), "passed_cases": passed,
        "unmatched_observations": available.len(), "exclusions": exclusions, "cases": results
    })
}

pub fn compare(plan: &str, capture: &str) -> Result<Value> {
    let cases = load_plan(plan)?;
    let mut cap = pcap::Capture::from_file(capture)?;
    if cap.get_datalink() != pcap::Linktype(127) {
        return Err("capture requires radiotap pcap".into());
    }
    let mut frames = Vec::new();
    let mut exclusions = BTreeMap::new();
    loop {
        match cap.next_packet() {
            Ok(packet) => match observed_frame(packet.data, packet.header.len) {
                Ok(frame) => frames.push(frame),
                Err(reason) => *exclusions.entry(reason.to_owned()).or_insert(0) += 1,
            },
            Err(pcap::Error::NoMorePackets) => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(compare_cases(&cases, &frames, exclusions))
}

fn qualified_path(base: &Path, relative: &str) -> Result<PathBuf> {
    let path = Path::new(relative);
    if relative.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(format!("qualification path must be a relative child: {relative}").into());
    }
    Ok(base.join(path))
}

fn sha256(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65_536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(hex(&digest.finalize()))
}

fn verified_file(base: &Path, value: &Value, label: &str) -> Result<PathBuf> {
    let relative = value["path"]
        .as_str()
        .ok_or_else(|| format!("missing {label} path"))?;
    let expected = value["sha256"]
        .as_str()
        .ok_or_else(|| format!("missing {label} sha256"))?;
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("invalid {label} sha256: {relative}").into());
    }
    let path = qualified_path(base, relative)?;
    let metadata = path.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(format!("empty or invalid {label}: {relative}").into());
    }
    if sha256(&path)? != expected.to_ascii_lowercase() {
        return Err(format!("{label} digest mismatch: {relative}").into());
    }
    Ok(path)
}

fn verify_transmit(path: &Path) -> Result<BTreeSet<String>> {
    let mut reader = BufReader::new(File::open(path)?);
    let header = read_json(&mut reader)?.ok_or("empty live transmit artifact")?;
    if header["schema"] != PLAN_SCHEMA
        || header["kind"] != "header"
        || header["offline"] != false
        || match header["case_count"].as_u64() {
            Some(count) => count == 0 || count > 15,
            None => true,
        }
    {
        return Err("invalid live transmit header".into());
    }
    let mut cases = BTreeSet::new();
    let mut summary = None;
    while let Some(value) = read_json(&mut reader)? {
        match value["kind"].as_str() {
            Some("case") => {
                let id = value["case_id"].as_str().ok_or("missing live case id")?;
                if !cases.insert(id.to_owned())
                    || value["terminal"] != "complete"
                    || value["requested_samples"].as_u64().is_none()
                    || value["requested_samples"] != value["supplied_samples"]
                    || value["completed_repetitions"].as_u64().unwrap_or(0) == 0
                    || value["firmware_shortfalls"] != 0
                    || value["stopped"] != true
                {
                    return Err(format!("invalid live transmit case: {id}").into());
                }
            }
            Some("summary") if summary.is_none() => summary = Some(value),
            _ => return Err("unexpected live transmit record".into()),
        }
    }
    let declared = header["case_count"].as_u64().unwrap() as usize;
    let expected = MATRIX_CASE_IDS.into_iter().collect::<BTreeSet<_>>();
    if cases.len() != declared
        || !cases.iter().all(|id| expected.contains(id.as_str()))
        || match summary.as_ref() {
            Some(value) => value["complete"] != true || value["terminal"] != "complete",
            None => true,
        }
    {
        return Err("incomplete live transmit artifact".into());
    }
    Ok(cases)
}

pub fn verify_qualification(path: &str) -> Result<Value> {
    let value: Value = serde_json::from_reader(File::open(path)?)?;
    if value["schema"] != QUALIFICATION_SCHEMA || value["complete"] != true {
        return Err("invalid or incomplete transmit qualification".into());
    }
    let runs = value["runs"]
        .as_array()
        .ok_or("missing qualification runs")?;
    if runs.len() < 3 {
        return Err("qualification requires at least three runs".into());
    }
    let revision = value["revision"]
        .as_str()
        .ok_or("missing qualification revision")?;
    if revision.len() != 40
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("qualification revision must be a lowercase 40-hex commit".into());
    }
    let base = Path::new(path).parent().unwrap_or_else(|| Path::new("."));
    let mut verified = Vec::with_capacity(runs.len());
    let mut run_ids = BTreeSet::new();
    let mut capture_paths = BTreeSet::new();
    let mut comparison_paths = BTreeSet::new();
    let mut transmit_paths = BTreeSet::new();
    for run in runs {
        let id = run["id"].as_str().ok_or("missing qualification run id")?;
        if !run_ids.insert(id.to_owned()) {
            return Err(format!("duplicate qualification run id: {id}").into());
        }
        if run["revision"] != revision
            || run["cleanup"] != true
            || run["invalidating_failures"] != 0
            || match run["settings"].as_object() {
                Some(settings) => settings.is_empty(),
                None => true,
            }
        {
            return Err(format!("invalid qualification run state: {id}").into());
        }
        let capture = verified_file(base, &run["capture"], "capture")?;
        if !capture_paths.insert(capture.clone()) {
            return Err(format!("qualification capture reused by run: {id}").into());
        }
        let comparison = verified_file(base, &run["comparison"], "comparison")?;
        if !comparison_paths.insert(comparison.clone()) {
            return Err(format!("qualification comparison reused by run: {id}").into());
        }
        let report: Value = serde_json::from_reader(File::open(&comparison)?)?;
        if report["schema"] != REPORT_SCHEMA
            || report["status"] != "passed"
            || report["required_cases"] != 15
            || report["passed_cases"] != 15
        {
            return Err(
                format!("qualification comparison failed: {}", comparison.display()).into(),
            );
        }
        let report_cases = report["cases"]
            .as_array()
            .ok_or("missing comparison cases")?;
        let passed_ids = report_cases
            .iter()
            .filter_map(|case| {
                (case["status"] == "passed")
                    .then(|| case["case_id"].as_str().map(str::to_owned))
                    .flatten()
            })
            .collect::<BTreeSet<_>>();
        if passed_ids != MATRIX_CASE_IDS.into_iter().map(str::to_owned).collect() {
            return Err(format!("qualification comparison matrix failed: {id}").into());
        }
        let transmits = run["transmits"]
            .as_array()
            .ok_or("missing qualification transmit artifacts")?;
        if transmits.is_empty() {
            return Err(format!("qualification run has no transmits: {id}").into());
        }
        let mut transmitted_cases = BTreeSet::new();
        for transmit in transmits {
            let transmit_path = verified_file(base, transmit, "transmit")?;
            if !transmit_paths.insert(transmit_path.clone()) {
                return Err(format!("qualification transmit reused by run: {id}").into());
            }
            transmitted_cases.extend(verify_transmit(&transmit_path)?);
        }
        if transmitted_cases != MATRIX_CASE_IDS.into_iter().map(str::to_owned).collect() {
            return Err(format!("qualification run transmit matrix is incomplete: {id}").into());
        }
        verified.push(json!({
            "id": id, "comparison": comparison.strip_prefix(base)?.display().to_string(),
            "capture_bytes": capture.metadata()?.len(), "transmit_artifacts": transmits.len(),
            "passed_cases": 15
        }));
    }
    Ok(
        json!({"schema":QUALIFICATION_SCHEMA,"status":"passed","verified_runs":verified.len(),"runs":verified}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn planned(id: &str, byte: u8, rate: u32, short: bool) -> PlannedCase {
        PlannedCase {
            id: id.into(),
            mac: vec![byte],
            rate_bps: rate,
            short,
        }
    }
    fn seen(byte: u8, rate: u32, short: bool) -> Observed {
        Observed {
            mac: vec![byte],
            rate_bps: rate,
            short,
            fcs: "absent",
        }
    }

    #[test]
    fn matching_consumes_duplicate_occurrences_one_to_one() {
        let cases = [
            planned("a", 1, 6_000_000, false),
            planned("b", 1, 6_000_000, false),
        ];
        let report = compare_cases(&cases, &[seen(1, 6_000_000, false)], BTreeMap::new());
        assert_eq!(report["passed_cases"], 1);
        assert_eq!(report["status"], "failed");
    }

    #[test]
    fn matching_rejects_rate_and_preamble_mismatch() {
        let cases = [planned("a", 1, 2_000_000, true)];
        let report = compare_cases(&cases, &[seen(1, 2_000_000, false)], BTreeMap::new());
        assert_eq!(report["cases"][0]["status"], "metadata_mismatch");
    }

    #[test]
    fn qualification_transmit_artifacts_allow_subsets_and_reject_shortfalls() {
        let root = std::env::temp_dir().join(format!(
            "crafter-transmit-qualification-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("transmit.jsonl");
        let artifact = |shortfalls| {
            format!(
            "{{\"schema\":\"{PLAN_SCHEMA}\",\"kind\":\"header\",\"case_count\":2,\"offline\":false}}\n\
             {{\"schema\":\"{PLAN_SCHEMA}\",\"kind\":\"case\",\"case_id\":\"ofdm-54-long\",\"terminal\":\"complete\",\"requested_samples\":10,\"supplied_samples\":10,\"completed_repetitions\":1,\"firmware_shortfalls\":{shortfalls},\"stopped\":true}}\n\
             {{\"schema\":\"{PLAN_SCHEMA}\",\"kind\":\"case\",\"case_id\":\"cck-11-short\",\"terminal\":\"complete\",\"requested_samples\":10,\"supplied_samples\":10,\"completed_repetitions\":1,\"firmware_shortfalls\":0,\"stopped\":true}}\n\
             {{\"schema\":\"{PLAN_SCHEMA}\",\"kind\":\"summary\",\"complete\":true,\"terminal\":\"complete\"}}\n"
        )
        };
        fs::write(&path, artifact(0)).unwrap();
        let cases = verify_transmit(&path).unwrap();
        assert_eq!(cases.len(), 2);
        assert!(cases.contains("ofdm-54-long"));
        fs::write(&path, artifact(1)).unwrap();
        assert!(verify_transmit(&path).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
