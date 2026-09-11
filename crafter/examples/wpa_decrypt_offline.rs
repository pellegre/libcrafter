mod common;

use std::{env, path::PathBuf};

use common::{arg_value, print_help_if_requested, ExampleResult};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example wpa_decrypt_offline -- [--pcap FILE] [--jsonl] [--pass-originals]\n\nRead a WPA2-PSK CCMP pcap through PacketWire, Sniffer, and WpaDecrypt without live Wi-Fi access. Set both CRAFTER_WPA_SSID and CRAFTER_WPA_PASSPHRASE to inspect a private capture; their values are never printed.",
    ) {
        return Ok(());
    }

    let path = arg_value("--pcap").map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/pcaps/wpa2-psk-ccmp-unicast.pcap")
    });
    let (ssid, passphrase) = match (
        env::var("CRAFTER_WPA_SSID").ok(),
        env::var("CRAFTER_WPA_PASSPHRASE").ok(),
    ) {
        (None, None) => ("libcrafter-wpa".to_string(), "libcrafter-pass".to_string()),
        (Some(ssid), Some(passphrase)) => (ssid, passphrase),
        _ => return Err("CRAFTER_WPA_SSID and CRAFTER_WPA_PASSPHRASE must be set together".into()),
    };
    let source = PacketWire::pcap_file(path.clone()).open()?.source()?;
    let records = Sniffer::new(source)
        .with(Dot11Metadata::new())
        .with(
            WpaDecrypt::new()
                .network(ssid, passphrase)?
                .network_bytes(b"\xffdry-run".as_slice(), "unused-passphrase")?
                .with_config(
                    WpaDecryptConfig::new()
                        .pass_originals(common::flag_present("--pass-originals")),
                ),
        )
        .collect_records()?;

    if common::flag_present("--jsonl") {
        for (index, record) in records.iter().enumerate() {
            let compiled = record.packet().compile()?;
            println!(
                "{}",
                serde_json::json!({
                    "index": index,
                    "summary": record.packet().summary(),
                    "compiled_hex": compiled.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
                    "decrypt_state": record.metadata().wifi().and_then(|wifi| wifi.decrypt_state()).map(|state| format!("{state:?}")),
                    "handshake": record.metadata().wifi().and_then(|wifi| wifi.wpa_metadata()).map(|wpa| format!("{:?}", wpa.handshake_status())),
                    "reason": record.metadata().wifi().and_then(|wifi| wifi.wpa_metadata()).and_then(|wpa| wpa.decrypt_reason()).map(|reason| format!("{reason:?}")),
                })
            );
        }
        return Ok(());
    }

    println!("example: wpa_decrypt_offline");
    println!("mode: offline");
    println!("pcap: {}", path.display());
    println!("records: {}", records.len());

    for (index, record) in records.iter().enumerate() {
        println!("record[{index}] summary: {}", record.packet().summary());

        if let Some(wifi) = record.metadata().wifi() {
            println!(
                "record[{index}] wifi: ssid={} bssid={:?} transmitter={:?} receiver={:?} decrypt_state={:?}",
                ssid_label(wifi.ssid()),
                wifi.bssid(),
                wifi.transmitter(),
                wifi.receiver(),
                wifi.decrypt_state()
            );

            if let Some(wpa) = wifi.wpa_metadata() {
                println!(
                    "record[{index}] wpa: cipher={:?} akm={:?} key_kind={:?} key_id={:?} packet_number={:?} handshake={:?} credentials={:?} reason={:?}",
                    wpa.cipher(),
                    wpa.akm(),
                    wpa.key_kind(),
                    wpa.key_id(),
                    wpa.packet_number(),
                    wpa.handshake_status(),
                    wpa.credential_status(),
                    wpa.decrypt_reason()
                );
            }
        }
    }

    Ok(())
}

fn ssid_label(ssid: Option<&[u8]>) -> String {
    match ssid {
        Some(bytes) if bytes.is_ascii() => String::from_utf8_lossy(bytes).into_owned(),
        Some(bytes) => format!("{bytes:02x?}"),
        None => "-".to_string(),
    }
}
