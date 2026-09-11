//! Exact comparison of an offline transmit manifest with a radiotap capture.

use super::artifact::{hex, read_json, unhex, valid_fcs, Result};
use crafter::{LinkType, Packet, Radiotap};
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs::File, io::BufReader, path::Path};

pub const PLAN_SCHEMA: &str = "crafter.radio.transmit/v1";
pub const REPORT_SCHEMA: &str = "crafter.radio.transmit-comparison/v1";
pub const QUALIFICATION_SCHEMA: &str = "crafter.radio.transmit-qualification/v1";

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
    let base = Path::new(path).parent().unwrap_or_else(|| Path::new("."));
    let mut verified = Vec::with_capacity(runs.len());
    for run in runs {
        let relative = run["comparison"]
            .as_str()
            .ok_or("missing comparison path")?;
        let report: Value = serde_json::from_reader(File::open(base.join(relative))?)?;
        if report["schema"] != REPORT_SCHEMA
            || report["status"] != "passed"
            || report["required_cases"] != 15
            || report["passed_cases"] != 15
        {
            return Err(format!("qualification comparison failed: {relative}").into());
        }
        verified.push(json!({"comparison": relative, "passed_cases": 15}));
    }
    Ok(
        json!({"schema":QUALIFICATION_SCHEMA,"status":"passed","verified_runs":verified.len(),"runs":verified}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
