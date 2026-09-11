//! Offline-first legacy Wi-Fi packet-to-IQ transmission example.

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
struct Case {
    id: &'static str,
    phy: LegacyWifiPhy,
}

fn cases(matrix: bool) -> Vec<Case> {
    if !matrix {
        return vec![Case {
            id: "ofdm-6-long",
            phy: LegacyWifiPhy::Ofdm(LegacyOfdmRate::Mbps6),
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
            },
            phy: LegacyWifiPhy::Ofdm(rate),
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
            id,
            phy: LegacyWifiPhy::DsssCck { rate, preamble },
        });
    }
    cases
}

fn packet(case_id: &str) -> Packet {
    let dot11 = Dot11::data();
    dot11
        .addr1(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x01]))
        .addr2(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x02]))
        .addr3(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x03]))
        .sequence_number(0x321)
        / Raw::from(format!("crafter legacy Wi-Fi transmit {case_id}"))
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

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn run(matrix: bool, save_iq: Option<&Path>, mut output: impl Write) -> Result<Vec<Value>> {
    let selected = cases(matrix);
    serde_json::to_writer(
        &mut output,
        &json!({
            "schema": SCHEMA, "kind": "header", "case_count": selected.len(),
            "sample_format": "cs8", "sample_rate_hz": 20_000_000,
            "offline": true
        }),
    )?;
    writeln!(output)?;
    let mut records = Vec::with_capacity(selected.len());
    for case in selected {
        let config = match case.phy {
            LegacyWifiPhy::Ofdm(rate) => LegacyWifiTxConfig::ofdm(rate),
            LegacyWifiPhy::DsssCck { rate, preamble } => {
                LegacyWifiTxConfig::dsss_cck(rate, preamble)
            }
        };
        let writer = RadioPacketWriter::new(config, MemoryIqSink::new());
        let transmission = writer.encode_record(&PacketRecord::new(packet(case.id)))?;
        let (phy, rate_bps, preamble) = labels(case.phy);
        let digest = format!(
            "{:x}",
            Sha256::digest(
                transmission
                    .cs8()
                    .iter()
                    .map(|v| *v as u8)
                    .collect::<Vec<_>>()
            )
        );
        let path = save_iq.map(|root| root.join(format!("{}.cs8", case.id)));
        if let Some(path) = &path {
            let bytes = transmission
                .cs8()
                .iter()
                .map(|v| *v as u8)
                .collect::<Vec<_>>();
            write_new(path, &bytes)?;
        }
        let record = json!({
            "schema": SCHEMA, "kind": "case", "case_id": case.id,
            "phy": phy, "rate_bps": rate_bps, "preamble": preamble,
            "mac_hex": hex(transmission.mac_bytes()), "psdu_hex": hex(transmission.psdu_bytes()),
            "sample_count": transmission.sample_count(), "cs8_sha256": digest,
            "iq_path": path.map(|p| p.display().to_string())
        });
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

fn parse_args() -> Result<(bool, Option<PathBuf>)> {
    let mut matrix = false;
    let mut save = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--matrix" => matrix = true,
            "--save-iq" => save = Some(PathBuf::from(args.next().ok_or("--save-iq requires DIR")?)),
            _ => return Err(format!("unknown argument: {arg}").into()),
        }
    }
    Ok((matrix, save))
}

fn main() -> Result<()> {
    #[cfg(feature = "radio-hackrf")]
    if std::env::args().nth(1).as_deref() == Some("--live-hackrf") {
        return run_live(std::env::args().skip(2).collect());
    }
    let (matrix, save) = parse_args()?;
    run(matrix, save.as_deref(), std::io::stdout())?;
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
    let matrix = required("matrix")? == "true";
    let mut sink = HackRfTxSink::open_live(config)?;
    let selected = cases(matrix);
    println!(
        "{}",
        json!({"schema":SCHEMA,"kind":"header","case_count":selected.len(),"offline":false})
    );
    for case in selected {
        let phy_config = match case.phy {
            LegacyWifiPhy::Ofdm(rate) => LegacyWifiTxConfig::ofdm(rate),
            LegacyWifiPhy::DsssCck { rate, preamble } => {
                LegacyWifiTxConfig::dsss_cck(rate, preamble)
            }
        };
        let mut writer = RadioPacketWriter::new(phy_config, sink);
        writer.write_record(&PacketRecord::new(packet(case.id)))?;
        let stats = writer
            .sink()
            .last_stats()
            .ok_or("missing HackRF terminal stats")?;
        println!(
            "{}",
            json!({
                "schema":SCHEMA,"kind":"case","case_id":case.id,"terminal":"complete",
                "requested_samples":stats.requested_samples,"supplied_samples":stats.supplied_samples,
                "padded_samples":stats.padded_samples,"callbacks":stats.callbacks,
                "completed_repetitions":stats.completed_repetitions,"firmware_shortfalls":stats.firmware_shortfalls,
                "stopped":stats.stopped
            })
        );
        sink = writer.into_sink();
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
        let cases = cases(true);
        assert_eq!(cases.len(), 15);
        let ids = cases
            .iter()
            .map(|case| case.id)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(ids.len(), 15);
    }

    #[test]
    fn offline_artifact_has_header_cases_and_terminal_summary() {
        let mut bytes = Vec::new();
        let records = run(true, None, &mut bytes).unwrap();
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
}
