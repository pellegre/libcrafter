//! Exact comparison of an offline transmit manifest with a radiotap capture.

use super::artifact::{hex, read_json, unhex, valid_fcs, Result};
use super::ht_compare::HtPhy;
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
const LEGACY_MATRIX_CASE_IDS: [&str; 15] = [
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

fn matrix_case_ids(family: &str) -> Result<BTreeSet<String>> {
    match family {
        "legacy" => Ok(LEGACY_MATRIX_CASE_IDS
            .into_iter()
            .map(str::to_owned)
            .collect()),
        "ht20" => {
            let mut ids = BTreeSet::new();
            for format in ["mixed", "greenfield"] {
                for coding in ["bcc", "ldpc"] {
                    for guard in ["gi800", "gi400"] {
                        if format == "greenfield" && guard == "gi400" {
                            continue;
                        }
                        for mcs in 0..8 {
                            ids.insert(format!("ht20-{format}-{coding}-mcs{mcs}-{guard}"));
                        }
                    }
                }
            }
            Ok(ids)
        }
        _ => Err(format!("unknown transmit family: {family}").into()),
    }
}

#[derive(Debug, Clone)]
enum PlannedPhy {
    Legacy {
        rate_bps: u32,
        short_preamble: bool,
    },
    Ht20 {
        mcs: u8,
        short_gi: bool,
        ldpc: bool,
        greenfield: bool,
    },
}

impl PlannedPhy {
    fn matches(&self, observed: &ObservedPhy) -> bool {
        fn agrees<T: PartialEq>(observed: Option<T>, planned: T) -> bool {
            match observed {
                Some(observed) => observed == planned,
                None => true,
            }
        }
        match (self, observed) {
            (
                Self::Legacy {
                    rate_bps,
                    short_preamble,
                },
                ObservedPhy::Legacy {
                    rate_bps: observed_rate,
                    short_preamble: observed_short,
                },
            ) => rate_bps == observed_rate && short_preamble == observed_short,
            (
                Self::Ht20 {
                    mcs,
                    short_gi,
                    ldpc,
                    greenfield,
                },
                ObservedPhy::Ht20(observed),
            ) => {
                observed.mcs == *mcs
                    && observed.short_gi == *short_gi
                    && agrees(observed.ldpc, *ldpc)
                    && agrees(observed.greenfield, *greenfield)
                    && agrees(observed.stbc, 0)
                    && agrees(observed.extension_spatial_streams, 0)
                    && agrees(observed.aggregation, false)
            }
            _ => false,
        }
    }

    fn metadata(&self) -> Value {
        match self {
            Self::Legacy {
                rate_bps,
                short_preamble,
            } => json!({
                "phy":"legacy", "rate_bps":rate_bps,
                "preamble":if *short_preamble {"short"} else {"long"}
            }),
            Self::Ht20 {
                mcs,
                short_gi,
                ldpc,
                greenfield,
            } => json!({
                "phy":"ht20", "mcs":mcs,
                "guard_interval_ns":if *short_gi {400} else {800},
                "coding":if *ldpc {"ldpc"} else {"bcc"},
                "preamble":if *greenfield {"greenfield"} else {"mixed"}
            }),
        }
    }
}

#[derive(Debug, Clone)]
struct PlannedCase {
    id: String,
    mac: Vec<u8>,
    phy: PlannedPhy,
}

#[derive(Debug, Clone)]
enum ObservedPhy {
    Legacy { rate_bps: u32, short_preamble: bool },
    Ht20(HtPhy),
}

#[derive(Debug, Clone)]
struct Observed {
    mac: Vec<u8>,
    phy: ObservedPhy,
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
                let rate_bps = value["rate_bps"]
                    .as_u64()
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or("invalid rate")?;
                let phy = if value["phy"] == "ht20" {
                    let mcs = value["mcs"]
                        .as_u64()
                        .filter(|value| *value < 8)
                        .ok_or("invalid HT MCS")? as u8;
                    let short_gi = match value["guard_interval_ns"].as_u64() {
                        Some(400) => true,
                        Some(800) => false,
                        _ => return Err("invalid HT guard interval".into()),
                    };
                    let ldpc = match value["coding"].as_str() {
                        Some("bcc") => false,
                        Some("ldpc") => true,
                        _ => return Err("invalid HT coding".into()),
                    };
                    let greenfield = match value["preamble"].as_str() {
                        Some("mixed") => false,
                        Some("greenfield") if !short_gi => true,
                        _ => return Err("invalid HT preamble".into()),
                    };
                    let expected_rate = HtPhy {
                        mcs,
                        short_gi,
                        ldpc: Some(ldpc),
                        stbc: Some(0),
                        greenfield: Some(greenfield),
                        extension_spatial_streams: Some(0),
                        aggregation: Some(false),
                        ampdu_reference: None,
                        delimiter_offset: None,
                    }
                    .rate_bps();
                    if rate_bps != expected_rate {
                        return Err("inconsistent HT rate".into());
                    }
                    PlannedPhy::Ht20 {
                        mcs,
                        short_gi,
                        ldpc,
                        greenfield,
                    }
                } else if matches!(value["phy"].as_str(), Some("legacy_ofdm" | "dsss" | "cck")) {
                    let short_preamble = match value["preamble"].as_str() {
                        Some("short") => true,
                        Some("long") => false,
                        _ => return Err("invalid legacy preamble".into()),
                    };
                    PlannedPhy::Legacy {
                        rate_bps,
                        short_preamble,
                    }
                } else {
                    return Err("unknown planned PHY".into());
                };
                cases.push(PlannedCase {
                    id,
                    mac: unhex(value["mac_hex"].as_str().ok_or("missing MAC bytes")?)?,
                    phy,
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
    let phy = match radiotap.mcs_value() {
        Some(mcs) => ObservedPhy::Ht20(
            HtPhy::reference(mcs, radiotap.a_mpdu_status_value()).map_err(|_| "unsupported_ht")?,
        ),
        None => {
            let rate_bps = u32::from(radiotap.rate_value().ok_or("missing_rate")?) * 500_000;
            let short_preamble = flags.bits() & 2 != 0;
            if rate_bps == 1_000_000 && short_preamble {
                return Err("invalid_preamble");
            }
            ObservedPhy::Legacy {
                rate_bps,
                short_preamble,
            }
        }
    };
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
    Ok(Observed { mac, phy, fcs })
}

fn compare_cases(
    cases: &[PlannedCase],
    observed: &[Observed],
    exclusions: BTreeMap<String, u64>,
) -> Value {
    let mut available = observed.to_vec();
    let mut results = Vec::with_capacity(cases.len());
    for case in cases {
        let exact = available
            .iter()
            .position(|frame| frame.mac == case.mac && case.phy.matches(&frame.phy));
        let bytes_only = available.iter().any(|frame| frame.mac == case.mac);
        let match_value = exact.map(|index| available.remove(index));
        let mut result = json!({
            "case_id": case.id,
            "status": if match_value.is_some() {"passed"} else if bytes_only {"metadata_mismatch"} else {"missing"},
            "fcs": match_value.as_ref().map(|frame| frame.fcs),
            "mac_hex": hex(&case.mac)
        });
        result
            .as_object_mut()
            .expect("comparison result is an object")
            .extend(
                case.phy
                    .metadata()
                    .as_object()
                    .expect("PHY metadata is an object")
                    .clone(),
            );
        results.push(result);
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

fn verify_transmit(path: &Path) -> Result<(String, BTreeSet<String>)> {
    let mut reader = BufReader::new(File::open(path)?);
    let header = read_json(&mut reader)?.ok_or("empty live transmit artifact")?;
    let family = header["family"].as_str().unwrap_or("legacy");
    let expected = matrix_case_ids(family)?;
    if header["schema"] != PLAN_SCHEMA
        || header["kind"] != "header"
        || header["offline"] != false
        || match header["case_count"].as_u64() {
            Some(count) => count == 0 || count > expected.len() as u64,
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
    if cases.len() != declared
        || !cases.iter().all(|id| expected.contains(id))
        || match summary.as_ref() {
            Some(value) => value["complete"] != true || value["terminal"] != "complete",
            None => true,
        }
    {
        return Err("incomplete live transmit artifact".into());
    }
    Ok((family.to_owned(), cases))
}

pub fn verify_qualification(path: &str) -> Result<Value> {
    let value: Value = serde_json::from_reader(File::open(path)?)?;
    if value["schema"] != QUALIFICATION_SCHEMA || value["complete"] != true {
        return Err("invalid or incomplete transmit qualification".into());
    }
    let family = value["family"].as_str().unwrap_or("legacy");
    let expected_cases = matrix_case_ids(family)?;
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
            || report["required_cases"] != expected_cases.len()
            || report["passed_cases"] != expected_cases.len()
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
        if passed_ids != expected_cases {
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
            let (transmit_family, cases) = verify_transmit(&transmit_path)?;
            if transmit_family != family {
                return Err(format!("qualification transmit family differs: {id}").into());
            }
            transmitted_cases.extend(cases);
        }
        if transmitted_cases != expected_cases {
            return Err(format!("qualification run transmit matrix is incomplete: {id}").into());
        }
        verified.push(json!({
            "id": id, "comparison": comparison.strip_prefix(base)?.display().to_string(),
            "capture_bytes": capture.metadata()?.len(), "transmit_artifacts": transmits.len(),
            "passed_cases": expected_cases.len()
        }));
    }
    Ok(
        json!({"schema":QUALIFICATION_SCHEMA,"family":family,"status":"passed","verified_runs":verified.len(),"runs":verified}),
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
            phy: PlannedPhy::Legacy {
                rate_bps: rate,
                short_preamble: short,
            },
        }
    }
    fn seen(byte: u8, rate: u32, short: bool) -> Observed {
        Observed {
            mac: vec![byte],
            phy: ObservedPhy::Legacy {
                rate_bps: rate,
                short_preamble: short,
            },
            fcs: "absent",
        }
    }

    fn planned_ht(byte: u8, mcs: u8, short_gi: bool, ldpc: bool) -> PlannedCase {
        PlannedCase {
            id: format!("ht-{mcs}"),
            mac: vec![byte],
            phy: PlannedPhy::Ht20 {
                mcs,
                short_gi,
                ldpc,
                greenfield: false,
            },
        }
    }

    fn seen_ht(byte: u8, mcs: u8, short_gi: bool, ldpc: Option<bool>) -> Observed {
        Observed {
            mac: vec![byte],
            phy: ObservedPhy::Ht20(HtPhy {
                mcs,
                short_gi,
                ldpc,
                stbc: Some(0),
                greenfield: Some(false),
                extension_spatial_streams: Some(0),
                aggregation: None,
                ampdu_reference: None,
                delimiter_offset: None,
            }),
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
    fn matching_ht_requires_mcs_gi_and_known_coding_to_agree() {
        let case = planned_ht(1, 7, true, true);
        let report = compare_cases(
            std::slice::from_ref(&case),
            &[seen_ht(1, 7, true, Some(true))],
            BTreeMap::new(),
        );
        assert_eq!(report["passed_cases"], 1);

        let mismatch = compare_cases(
            std::slice::from_ref(&case),
            &[seen_ht(1, 7, false, Some(true))],
            BTreeMap::new(),
        );
        assert_eq!(mismatch["cases"][0]["status"], "metadata_mismatch");

        let unknown_coding = compare_cases(
            std::slice::from_ref(&case),
            &[seen_ht(1, 7, true, None)],
            BTreeMap::new(),
        );
        assert_eq!(unknown_coding["passed_cases"], 1);
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
        let (family, cases) = verify_transmit(&path).unwrap();
        assert_eq!(family, "legacy");
        assert_eq!(cases.len(), 2);
        assert!(cases.contains("ofdm-54-long"));
        fs::write(&path, artifact(1)).unwrap();
        assert!(verify_transmit(&path).is_err());

        fs::write(
            &path,
            format!(
                "{{\"schema\":\"{PLAN_SCHEMA}\",\"kind\":\"header\",\"family\":\"ht20\",\"case_count\":2,\"offline\":false}}\n\
                 {{\"schema\":\"{PLAN_SCHEMA}\",\"kind\":\"case\",\"case_id\":\"ht20-mixed-bcc-mcs0-gi800\",\"terminal\":\"complete\",\"requested_samples\":10,\"supplied_samples\":10,\"completed_repetitions\":1,\"firmware_shortfalls\":0,\"stopped\":true}}\n\
                 {{\"schema\":\"{PLAN_SCHEMA}\",\"kind\":\"case\",\"case_id\":\"ht20-greenfield-ldpc-mcs7-gi800\",\"terminal\":\"complete\",\"requested_samples\":10,\"supplied_samples\":10,\"completed_repetitions\":1,\"firmware_shortfalls\":0,\"stopped\":true}}\n\
                 {{\"schema\":\"{PLAN_SCHEMA}\",\"kind\":\"summary\",\"complete\":true,\"terminal\":\"complete\"}}\n"
            ),
        )
        .unwrap();
        let (family, cases) = verify_transmit(&path).unwrap();
        assert_eq!(family, "ht20");
        assert_eq!(cases.len(), 2);
        fs::remove_dir_all(root).unwrap();
    }
}
