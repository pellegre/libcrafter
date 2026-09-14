//! Offline-first Wi-Fi packet-to-IQ transmission example.

use crafter::prelude::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const SCHEMA: &str = "crafter.radio.transmit/v1";

#[derive(Clone, Copy)]
enum CasePhy {
    Legacy(LegacyWifiPhy),
    Ht20 {
        mcs: HtMcs,
        format: HtFormat,
        coding: HtCoding,
        guard_interval: HtGuardInterval,
    },
}

#[derive(Clone)]
struct Case {
    id: String,
    phy: CasePhy,
}

fn legacy_cases(matrix: bool) -> Vec<Case> {
    if !matrix {
        return vec![Case {
            id: "ofdm-6-long".into(),
            phy: CasePhy::Legacy(LegacyWifiPhy::Ofdm(LegacyOfdmRate::Mbps6)),
        }];
    }
    let mut cases = LegacyOfdmRate::ALL
        .into_iter()
        .map(|rate| Case {
            id: match rate {
                LegacyOfdmRate::Mbps6 => "ofdm-6-long",
                LegacyOfdmRate::Mbps9 => "ofdm-9-long",
                LegacyOfdmRate::Mbps12 => "ofdm-12-long",
                LegacyOfdmRate::Mbps18 => "ofdm-18-long",
                LegacyOfdmRate::Mbps24 => "ofdm-24-long",
                LegacyOfdmRate::Mbps36 => "ofdm-36-long",
                LegacyOfdmRate::Mbps48 => "ofdm-48-long",
                LegacyOfdmRate::Mbps54 => "ofdm-54-long",
            }
            .into(),
            phy: CasePhy::Legacy(LegacyWifiPhy::Ofdm(rate)),
        })
        .collect::<Vec<_>>();
    for (rate, preamble, id) in [
        (LegacyDsssCckRate::Mbps1, DsssPreamble::Long, "dsss-1-long"),
        (LegacyDsssCckRate::Mbps2, DsssPreamble::Long, "dsss-2-long"),
        (
            LegacyDsssCckRate::Mbps2,
            DsssPreamble::Short,
            "dsss-2-short",
        ),
        (
            LegacyDsssCckRate::Mbps5_5,
            DsssPreamble::Long,
            "cck-5_5-long",
        ),
        (
            LegacyDsssCckRate::Mbps5_5,
            DsssPreamble::Short,
            "cck-5_5-short",
        ),
        (LegacyDsssCckRate::Mbps11, DsssPreamble::Long, "cck-11-long"),
        (
            LegacyDsssCckRate::Mbps11,
            DsssPreamble::Short,
            "cck-11-short",
        ),
    ] {
        cases.push(Case {
            id: id.into(),
            phy: CasePhy::Legacy(LegacyWifiPhy::DsssCck { rate, preamble }),
        });
    }
    cases
}

fn ht20_cases(matrix: bool) -> Vec<Case> {
    if !matrix {
        return vec![Case {
            id: "ht20-mixed-bcc-mcs0-gi800".into(),
            phy: CasePhy::Ht20 {
                mcs: HtMcs::Mcs0,
                format: HtFormat::Mixed,
                coding: HtCoding::Bcc,
                guard_interval: HtGuardInterval::Long,
            },
        }];
    }
    let mut cases = Vec::with_capacity(48);
    for format in [HtFormat::Mixed, HtFormat::Greenfield] {
        for coding in [HtCoding::Bcc, HtCoding::Ldpc] {
            for guard_interval in [HtGuardInterval::Long, HtGuardInterval::Short] {
                if format == HtFormat::Greenfield && guard_interval == HtGuardInterval::Short {
                    continue;
                }
                for mcs in HtMcs::ALL {
                    let format_label = match format {
                        HtFormat::Mixed => "mixed",
                        HtFormat::Greenfield => "greenfield",
                    };
                    let coding_label = match coding {
                        HtCoding::Bcc => "bcc",
                        HtCoding::Ldpc => "ldpc",
                    };
                    let guard_label = match guard_interval {
                        HtGuardInterval::Short => "gi400",
                        HtGuardInterval::Long => "gi800",
                    };
                    cases.push(Case {
                        id: format!(
                            "ht20-{format_label}-{coding_label}-mcs{}-{guard_label}",
                            mcs.index()
                        ),
                        phy: CasePhy::Ht20 {
                            mcs,
                            format,
                            coding,
                            guard_interval,
                        },
                    });
                }
            }
        }
    }
    cases
}

fn cases(matrix: bool, family: &str) -> Result<Vec<Case>> {
    match family {
        "legacy" => Ok(legacy_cases(matrix)),
        "ht20" => Ok(ht20_cases(matrix)),
        _ => Err(format!("unknown --family: {family}; expected legacy or ht20").into()),
    }
}

#[cfg(any(feature = "radio-hackrf", test))]
fn selected_cases(matrix: bool, family: &str, case_id: &str) -> Result<Vec<Case>> {
    let cases = cases(matrix, family)?;
    if case_id == "all" {
        return Ok(cases);
    }
    cases
        .into_iter()
        .find(|case| case.id == case_id)
        .map(|case| vec![case])
        .ok_or_else(|| format!("unknown or unavailable --case-id: {case_id}").into())
}

fn packet(case_id: &str) -> Packet {
    let case_tag = legacy_cases(true)
        .into_iter()
        .chain(ht20_cases(true))
        .position(|case| case.id == case_id)
        .expect("case ID comes from the closed transmit matrix") as u8;
    let payload = (0..72)
        .map(|offset| case_tag.wrapping_add(offset))
        .collect::<Vec<_>>();
    let dot11 = Dot11::data();
    dot11
        .addr1(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x01]))
        .addr2(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x02]))
        .addr3(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x03]))
        .sequence_number(0x321)
        / Raw::from(payload)
}

fn labels(phy: LegacyWifiPhy) -> (&'static str, u32, &'static str) {
    match phy {
        LegacyWifiPhy::Ofdm(rate) => ("legacy_ofdm", u32::from(rate.mbps()) * 1_000_000, "long"),
        LegacyWifiPhy::DsssCck { rate, preamble } => (
            if rate.bps() <= 2_000_000 {
                "dsss"
            } else {
                "cck"
            },
            rate.bps(),
            if preamble.is_short() { "short" } else { "long" },
        ),
    }
}

fn case_metadata(phy: CasePhy) -> Value {
    match phy {
        CasePhy::Legacy(phy) => {
            let (phy, rate_bps, preamble) = labels(phy);
            json!({"phy":phy,"rate_bps":rate_bps,"preamble":preamble})
        }
        CasePhy::Ht20 {
            mcs,
            format,
            coding,
            guard_interval,
        } => json!({
            "phy":"ht20", "mcs":mcs.index(),
            "rate_bps":mcs.rate_bps(guard_interval),
            "preamble":match format { HtFormat::Mixed=>"mixed", HtFormat::Greenfield=>"greenfield" },
            "coding":match coding { HtCoding::Bcc=>"bcc", HtCoding::Ldpc=>"ldpc" },
            "guard_interval_ns":match guard_interval { HtGuardInterval::Short=>400, HtGuardInterval::Long=>800 }
        }),
    }
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn run(
    matrix: bool,
    family: &str,
    save_iq: Option<&Path>,
    mut output: impl Write,
) -> Result<Vec<Value>> {
    let selected = cases(matrix, family)?;
    serde_json::to_writer(
        &mut output,
        &json!({
            "schema": SCHEMA, "kind": "header", "case_count": selected.len(),
            "sample_format": "cs8", "sample_rate_hz": 20_000_000,
            "family":family, "offline": true
        }),
    )?;
    writeln!(output)?;
    let mut records = Vec::with_capacity(selected.len());
    for case in selected {
        let (mac_bytes, psdu_bytes, cs8, sample_count) = match case.phy {
            CasePhy::Legacy(phy) => {
                let config = match phy {
                    LegacyWifiPhy::Ofdm(rate) => LegacyWifiTxConfig::ofdm(rate),
                    LegacyWifiPhy::DsssCck { rate, preamble } => {
                        LegacyWifiTxConfig::dsss_cck(rate, preamble)
                    }
                };
                let writer = RadioPacketWriter::new(config, MemoryIqSink::new());
                let transmission = writer.encode_record(&PacketRecord::new(packet(&case.id)))?;
                (
                    transmission.mac_bytes().to_vec(),
                    transmission.psdu_bytes().to_vec(),
                    transmission.cs8().to_vec(),
                    transmission.sample_count(),
                )
            }
            CasePhy::Ht20 {
                mcs,
                format,
                coding,
                guard_interval,
            } => {
                let config = HtTxConfig::new(mcs)
                    .with_format(format)
                    .with_coding(coding)
                    .with_guard_interval(guard_interval);
                let writer = RadioPacketWriter::new(config, MemoryIqSink::new());
                let transmission = writer.encode_record(&PacketRecord::new(packet(&case.id)))?;
                (
                    transmission.mac_bytes.clone(),
                    transmission.psdu_bytes.clone(),
                    transmission.cs8.clone(),
                    transmission.sample_count(),
                )
            }
        };
        let digest = format!(
            "{:x}",
            Sha256::digest(cs8.iter().map(|v| *v as u8).collect::<Vec<_>>())
        );
        let path = save_iq.map(|root| root.join(format!("{}.cs8", case.id)));
        if let Some(path) = &path {
            let bytes = cs8.iter().map(|v| *v as u8).collect::<Vec<_>>();
            write_new(path, &bytes)?;
        }
        let mut record = json!({
            "schema": SCHEMA, "kind": "case", "case_id": case.id,
            "mac_hex": hex(&mac_bytes), "psdu_hex": hex(&psdu_bytes),
            "sample_count": sample_count, "cs8_sha256": digest,
            "iq_path": path.map(|p| p.display().to_string())
        });
        record
            .as_object_mut()
            .expect("case record is an object")
            .extend(
                case_metadata(case.phy)
                    .as_object()
                    .expect("case metadata is an object")
                    .clone(),
            );
        serde_json::to_writer(&mut output, &record)?;
        writeln!(output)?;
        records.push(record);
    }
    serde_json::to_writer(
        &mut output,
        &json!({
            "schema": SCHEMA, "kind": "summary", "complete": true,
            "case_count": records.len(), "terminal": "complete"
        }),
    )?;
    writeln!(output)?;
    Ok(records)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_args() -> Result<(bool, String, Option<PathBuf>)> {
    let mut matrix = false;
    let mut family = "legacy".to_owned();
    let mut save = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--matrix" => matrix = true,
            "--family" => family = args.next().ok_or("--family requires NAME")?,
            "--save-iq" => save = Some(PathBuf::from(args.next().ok_or("--save-iq requires DIR")?)),
            _ => return Err(format!("unknown argument: {arg}").into()),
        }
    }
    cases(false, &family)?;
    Ok((matrix, family, save))
}

fn main() -> Result<()> {
    #[cfg(feature = "radio-hackrf")]
    if std::env::args().nth(1).as_deref() == Some("--live-hackrf") {
        return run_live(std::env::args().skip(2).collect());
    }
    let (matrix, family, save) = parse_args()?;
    run(matrix, &family, save.as_deref(), std::io::stdout())?;
    Ok(())
}

#[cfg(feature = "radio-hackrf")]
fn run_live(args: Vec<String>) -> Result<()> {
    use std::{collections::BTreeMap, time::Duration};
    let mut values = BTreeMap::new();
    let mut index = 0;
    while index < args.len() {
        let key = args[index]
            .strip_prefix("--")
            .ok_or("live arguments require --name VALUE")?;
        let value = args.get(index + 1).ok_or("live argument missing value")?;
        if values.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(format!("duplicate live argument: --{key}").into());
        }
        index += 2;
    }
    let required = |name: &str| -> Result<String> {
        values
            .get(name)
            .cloned()
            .ok_or_else(|| -> Box<dyn Error> { format!("missing explicit --{name}").into() })
    };
    let boolean = |name: &str| -> Result<bool> {
        match required(name)?.as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(format!("--{name} requires true or false").into()),
        }
    };
    let config = HackRfTxConfig {
        serial: required("serial")?,
        center_frequency_hz: required("frequency-hz")?.parse()?,
        sample_rate_hz: required("sample-rate-hz")?.parse()?,
        baseband_filter_hz: required("filter-hz")?.parse()?,
        tx_vga_gain_db: required("tx-gain-db")?.parse()?,
        amplifier_enabled: boolean("amplifier")?,
        antenna_power_enabled: boolean("antenna-power")?,
        max_duration: Duration::from_millis(required("max-duration-ms")?.parse()?),
        max_supplied_samples: required("max-samples")?.parse()?,
        repetitions: required("repetitions")?.parse()?,
        inter_burst_gap_samples: required("gap-samples")?.parse()?,
    };
    let case_gap = Duration::from_millis(required("case-gap-ms")?.parse()?);
    if case_gap > Duration::from_secs(10) {
        return Err("--case-gap-ms must not exceed 10000".into());
    }
    let ofdm_scale: f64 = required("ofdm-scale")?.parse()?;
    if !ofdm_scale.is_finite() || ofdm_scale <= 0.0 {
        return Err("--ofdm-scale must be finite and greater than zero".into());
    }
    let matrix = boolean("matrix")?;
    let family = values.get("family").map(String::as_str).unwrap_or("legacy");
    let case_id = required("case-id")?;
    let mut sink = HackRfTxSink::open_live(config)?;
    let selected = selected_cases(matrix, family, &case_id)?;
    let selected_len = selected.len();
    println!(
        "{}",
        json!({
            "schema":SCHEMA,"kind":"header","case_count":selected.len(),"offline":false,
            "family":family,"case_selector":case_id,"ofdm_scale":ofdm_scale,
            "case_gap_ms":case_gap.as_millis()
        })
    );
    for (index, case) in selected.into_iter().enumerate() {
        match case.phy {
            CasePhy::Legacy(phy) => {
                let phy_config = match phy {
                    LegacyWifiPhy::Ofdm(rate) => {
                        let mut config = LegacyWifiTxConfig::ofdm(rate);
                        config.ofdm.scale = ofdm_scale;
                        config
                    }
                    LegacyWifiPhy::DsssCck { rate, preamble } => {
                        LegacyWifiTxConfig::dsss_cck(rate, preamble)
                    }
                };
                let mut writer = RadioPacketWriter::new(phy_config, sink);
                writer.write_record(&PacketRecord::new(packet(&case.id)))?;
                sink = writer.into_sink();
            }
            CasePhy::Ht20 {
                mcs,
                format,
                coding,
                guard_interval,
            } => {
                let mut phy_config = HtTxConfig::new(mcs)
                    .with_format(format)
                    .with_coding(coding)
                    .with_guard_interval(guard_interval);
                phy_config.scale = ofdm_scale;
                let mut writer = RadioPacketWriter::new(phy_config, sink);
                writer.write_record(&PacketRecord::new(packet(&case.id)))?;
                sink = writer.into_sink();
            }
        }
        let stats = sink.last_stats().ok_or("missing HackRF terminal stats")?;
        let mut record = json!({
            "schema":SCHEMA,"kind":"case","case_id":case.id,"terminal":"complete",
            "requested_samples":stats.requested_samples,"supplied_samples":stats.supplied_samples,
            "padded_samples":stats.padded_samples,"callbacks":stats.callbacks,
            "completed_repetitions":stats.completed_repetitions,"firmware_shortfalls":stats.firmware_shortfalls,
            "stopped":stats.stopped
        });
        record
            .as_object_mut()
            .expect("case record is an object")
            .extend(
                case_metadata(case.phy)
                    .as_object()
                    .expect("case metadata is an object")
                    .clone(),
            );
        println!("{record}");
        if index + 1 < selected_len {
            std::thread::sleep(case_gap);
        }
    }
    println!(
        "{}",
        json!({"schema":SCHEMA,"kind":"summary","complete":true,"terminal":"complete"})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_is_complete_and_unique() {
        let cases = cases(true, "legacy").unwrap();
        assert_eq!(cases.len(), 15);
        let ids = cases
            .iter()
            .map(|case| case.id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(ids.len(), 15);
        assert_eq!(
            selected_cases(true, "legacy", "ofdm-54-long")
                .unwrap()
                .len(),
            1
        );
        assert!(selected_cases(false, "legacy", "ofdm-54-long").is_err());
    }

    #[test]
    fn ht20_matrix_is_complete_and_unique() {
        let cases = cases(true, "ht20").unwrap();
        assert_eq!(cases.len(), 48);
        let ids = cases
            .iter()
            .map(|case| case.id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(ids.len(), 48);
        assert_eq!(
            selected_cases(true, "ht20", "ht20-greenfield-ldpc-mcs7-gi800")
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn offline_artifact_has_header_cases_and_terminal_summary() {
        let mut bytes = Vec::new();
        let records = run(true, "legacy", None, &mut bytes).unwrap();
        assert_eq!(records.len(), 15);
        let lines = String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 17);
        assert_eq!(lines[0]["schema"], SCHEMA);
        assert_eq!(lines.last().unwrap()["complete"], true);
    }

    #[test]
    fn offline_ht20_artifact_covers_every_transmit_mode() {
        let mut bytes = Vec::new();
        let records = run(true, "ht20", None, &mut bytes).unwrap();
        assert_eq!(records.len(), 48);
        assert!(records.iter().all(|record| record["phy"] == "ht20"));
    }
}
