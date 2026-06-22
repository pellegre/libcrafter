use crafter::core::{
    Ah, Arp, Bgp, Dhcp, Dns, Dot11, Eapol, EapolKey, Esp, Ethernet, Icmpv4, Icmpv6, Ipv4, Ipv6,
    Ipv6FragmentHeader, Ipv6MobileRoutingHeader, Ipv6RoutingHeader, Ipv6SegmentRoutingHeader,
    Layer, LinuxSll, LlcSnap, NullLoopback, Radiotap, Raw, Rip, Ripng, Tcp, Udp, Vlan,
};
use crafter::prelude::*;
use crafter::protocols::igmp::IgmpExtension;
use crafter::wire::backend::pcap::{
    PcapLinkType, PcapReader, PcapRecord, PcapTimestamp, PcapWriter, TimestampPrecision,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

type ExampleResult<T> = std::result::Result<T, Box<dyn Error>>;

const BACKEND_NAME: &str = "libcrafter";

#[derive(Debug)]
enum Command {
    Read {
        path: PathBuf,
    },
    Write {
        path: PathBuf,
        input: Option<PathBuf>,
        link_type: PcapLinkType,
    },
}

#[derive(Debug, Deserialize)]
struct EncodedVector {
    raw_hex: Option<String>,
    hex: Option<String>,
    metadata: Option<Value>,
}

fn main() -> ExampleResult<()> {
    match parse_args()? {
        Command::Read { path } => read_pcap_report(path),
        Command::Write {
            path,
            input,
            link_type,
        } => write_pcap_report(path, input, link_type),
    }
}

fn parse_args() -> ExampleResult<Command> {
    let mut read_path = None;
    let mut write_path = None;
    let mut input = None;
    let mut link_type = PcapLinkType::Ethernet;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            "--read-pcap" | "--read" => {
                read_path = Some(PathBuf::from(next_value(&mut args, &arg)?));
            }
            "--write-pcap" | "--write" => {
                write_path = Some(PathBuf::from(next_value(&mut args, &arg)?));
            }
            "--input" => {
                let value = next_value(&mut args, &arg)?;
                input = input_path(value);
            }
            "--link-type" => {
                link_type = parse_link_type(&next_value(&mut args, &arg)?)?;
            }
            _ if arg.starts_with("--read-pcap=") => {
                read_path = Some(PathBuf::from(value_after_equals(&arg)));
            }
            _ if arg.starts_with("--read=") => {
                read_path = Some(PathBuf::from(value_after_equals(&arg)));
            }
            _ if arg.starts_with("--write-pcap=") => {
                write_path = Some(PathBuf::from(value_after_equals(&arg)));
            }
            _ if arg.starts_with("--write=") => {
                write_path = Some(PathBuf::from(value_after_equals(&arg)));
            }
            _ if arg.starts_with("--input=") => {
                input = input_path(value_after_equals(&arg));
            }
            _ if arg.starts_with("--link-type=") => {
                link_type = parse_link_type(&value_after_equals(&arg))?;
            }
            _ => return Err(format!("unknown argument: {arg}").into()),
        }
    }

    match (read_path, write_path) {
        (Some(path), None) => Ok(Command::Read { path }),
        (None, Some(path)) => Ok(Command::Write {
            path,
            input,
            link_type,
        }),
        (Some(_), Some(_)) => Err("choose only one of --read-pcap or --write-pcap".into()),
        (None, None) => Err("missing --read-pcap or --write-pcap".into()),
    }
}

fn next_value(args: &mut impl Iterator<Item = String>, option: &str) -> ExampleResult<String> {
    args.next()
        .ok_or_else(|| format!("{option} requires a value").into())
}

fn value_after_equals(arg: &str) -> String {
    arg.split_once('=')
        .map(|(_, value)| value.to_string())
        .unwrap_or_default()
}

fn input_path(value: String) -> Option<PathBuf> {
    if value == "-" {
        None
    } else {
        Some(PathBuf::from(value))
    }
}

fn parse_link_type(value: &str) -> ExampleResult<PcapLinkType> {
    Ok(match value {
        "ethernet" | "link:ethernet" => PcapLinkType::Ethernet,
        "linux_cooked" | "linux-sll" | "linux_sll" | "link:linux-sll" => PcapLinkType::LinuxSll,
        "null_loopback" | "null-loopback" | "link:null-loopback" => PcapLinkType::NullLoopback,
        "dot11" | "ieee80211" | "ieee802_11" | "link:dot11" | "link:ieee80211" => {
            PcapLinkType::Ieee80211
        }
        "radiotap" | "ieee80211_radio" | "ieee80211_radiotap" | "link:radiotap" => {
            PcapLinkType::Ieee80211Radiotap
        }
        "bluetooth_le_ll_with_phdr"
        | "bluetooth-le-ll-with-phdr"
        | "btle_ll_with_phdr"
        | "btle-with-phdr"
        | "link:bluetooth-le-ll-with-phdr"
        | "link:bluetooth_le_ll_with_phdr"
        | "dlt_256"
        | "linktype_bluetooth_le_ll_with_phdr" => PcapLinkType::BluetoothLeLl,
        "raw" | "raw_ip" | "link:raw" => PcapLinkType::RawIp,
        _ => return Err(format!("unsupported pcap link type: {value}").into()),
    })
}

fn print_usage() {
    println!(
        "usage: cargo run -p oracle-adapters --bin pcap -- (--read-pcap PATH | --write-pcap PATH --input PATH|-) [--link-type ethernet]\n\nRead or write classic pcap files for oracle validation and emit JSON metadata."
    );
}

fn read_pcap_report(path: PathBuf) -> ExampleResult<()> {
    let mut reader = PcapReader::open(&path)?;
    let header_link_type = reader.pcap_link_type();
    let mut records = Vec::new();
    let mut index = 0usize;

    while let Some(record) = reader.next_record()? {
        records.push(record_json(index, &record));
        index += 1;
    }

    let report = json!({
        "artifacts": [path.display().to_string()],
        "artifact_paths": [path.display().to_string()],
        "backend": BACKEND_NAME,
        "backend_versions": {},
        "count": records.len(),
        "failures": [],
        "libcrafter": {
            "version": env!("CARGO_PKG_VERSION")
        },
        "metadata": {
            "pcap": path.display().to_string(),
            "link_type": link_type_json(header_link_type),
            "records": records
        },
        "mode": "pcap",
        "profile": "unknown",
        "reproduction_commands": [],
        "results": [],
        "seed": 0,
        "selected_specs": [],
        "status": "read"
    });

    serde_json::to_writer_pretty(io::stdout(), &report)?;
    println!();
    Ok(())
}

fn write_pcap_report(
    path: PathBuf,
    input: Option<PathBuf>,
    link_type: PcapLinkType,
) -> ExampleResult<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let input_text = read_input(input)?;
    let document: Value = serde_json::from_str(&input_text)?;
    let vectors = extract_vectors(&document)?;
    let mut writer = PcapWriter::create(&path, link_type)?;
    let mut records = Vec::with_capacity(vectors.len());

    for (index, vector) in vectors.iter().enumerate() {
        let bytes = decode_hex(vector_hex(vector)?)?;
        let timestamp = timestamp_from_vector(vector, index)?;
        let original_len = u32::try_from(bytes.len())?;
        let record = PcapRecord::new(timestamp, original_len, bytes, link_type)?;
        writer.write_record(&record)?;
        records.push(record_json(index, &record));
    }
    writer.flush()?;

    let report = json!({
        "artifacts": [path.display().to_string()],
        "artifact_paths": [path.display().to_string()],
        "backend": BACKEND_NAME,
        "backend_versions": {},
        "count": records.len(),
        "failures": [],
        "libcrafter": {
            "version": env!("CARGO_PKG_VERSION")
        },
        "metadata": {
            "pcap": path.display().to_string(),
            "link_type": link_type_json(link_type),
            "records": records
        },
        "mode": "pcap",
        "profile": document.get("profile").cloned().unwrap_or(Value::Null),
        "reproduction_commands": [],
        "results": [],
        "seed": document.get("seed").cloned().unwrap_or(Value::Null),
        "selected_specs": document.get("selected_specs").cloned().unwrap_or_else(|| Value::Array(Vec::new())),
        "status": "written"
    });

    serde_json::to_writer_pretty(io::stdout(), &report)?;
    println!();
    Ok(())
}

fn read_input(input: Option<PathBuf>) -> ExampleResult<String> {
    match input {
        Some(path) => Ok(fs::read_to_string(path)?),
        None => {
            let mut buffer = String::new();
            io::stdin().read_to_string(&mut buffer)?;
            Ok(buffer)
        }
    }
}

fn extract_vectors(document: &Value) -> ExampleResult<Vec<EncodedVector>> {
    let vectors = if let Some(value) = document.pointer("/metadata/vectors") {
        value
    } else if let Some(value) = document.get("vectors") {
        value
    } else if let Some(value) = document.get("cases") {
        value
    } else if document.is_array() {
        document
    } else {
        return Err(
            "input JSON must contain metadata.vectors, vectors, cases, or be an array".into(),
        );
    };

    Ok(serde_json::from_value(vectors.clone())?)
}

fn record_json(index: usize, record: &PcapRecord) -> Value {
    let raw_hex = hex_bytes(record.data());
    let mut record_json = json!({
        "index": index,
        "raw_hex": raw_hex,
        "root": root_for_link_type(record.pcap_link_type()),
        "link_type": link_type_json(record.pcap_link_type()),
        "timestamp": timestamp_json(record.timestamp()),
        "layers": []
    });

    match record.decode() {
        Ok(packet) => {
            let layers = packet.iter().map(normalized_layer_name).collect::<Vec<_>>();
            record_json["layers"] = json!(layers);
            record_json["summary"] = json!(packet.summary());
        }
        Err(err) => {
            record_json["decode_error"] = json!(err.to_string());
        }
    }

    record_json
}

fn timestamp_from_vector(vector: &EncodedVector, index: usize) -> ExampleResult<PcapTimestamp> {
    let Some(metadata) = vector.metadata.as_ref() else {
        return PcapTimestamp::micros(1_700_000_000 + index as u64, 0).map_err(Into::into);
    };
    let Some(timestamp) = metadata.pointer("/pcap_record/timestamp") else {
        return PcapTimestamp::micros(1_700_000_000 + index as u64, 0).map_err(Into::into);
    };
    let seconds = timestamp
        .get("seconds")
        .and_then(Value::as_u64)
        .ok_or("pcap timestamp seconds must be an integer")?;
    let fractional = timestamp
        .get("fractional")
        .and_then(Value::as_u64)
        .ok_or("pcap timestamp fractional must be an integer")?;
    let fractional = u32::try_from(fractional)?;
    let precision = timestamp
        .get("precision")
        .and_then(Value::as_str)
        .unwrap_or("microseconds");
    match precision {
        "microseconds" => PcapTimestamp::micros(seconds, fractional).map_err(Into::into),
        "nanoseconds" => PcapTimestamp::nanos(seconds, fractional).map_err(Into::into),
        _ => Err(format!("unsupported pcap timestamp precision: {precision}").into()),
    }
}

fn vector_hex(vector: &EncodedVector) -> ExampleResult<&str> {
    vector
        .raw_hex
        .as_deref()
        .or(vector.hex.as_deref())
        .ok_or_else(|| "encoded vector is missing raw_hex or hex".into())
}

fn timestamp_json(timestamp: PcapTimestamp) -> Value {
    let nanos = match timestamp.precision() {
        TimestampPrecision::Microseconds => timestamp.fractional() * 1_000,
        TimestampPrecision::Nanoseconds => timestamp.fractional(),
    };
    json!({
        "seconds": timestamp.seconds(),
        "fractional": timestamp.fractional(),
        "precision": precision_name(timestamp.precision()),
        "nanos": nanos
    })
}

fn link_type_json(link_type: PcapLinkType) -> Value {
    json!({
        "name": link_type_name(link_type),
        "datalink": link_type.datalink()
    })
}

fn link_type_name(link_type: PcapLinkType) -> &'static str {
    match link_type {
        PcapLinkType::NullLoopback => "null_loopback",
        PcapLinkType::Ethernet => "ethernet",
        PcapLinkType::RawIp => "raw",
        PcapLinkType::LinuxSll => "linux_sll",
        PcapLinkType::Ieee80211 => "ieee80211",
        PcapLinkType::Ieee80211Radiotap => "radiotap",
        PcapLinkType::BluetoothLeLl => "bluetooth_le_ll_with_phdr",
        PcapLinkType::Ieee802154WithFcs => "ieee802154_withfcs",
        PcapLinkType::Ieee802154NoFcs => "ieee802154_nofcs",
        PcapLinkType::Ieee802154Tap => "ieee802154_tap",
        PcapLinkType::Unknown(_) => "unknown",
    }
}

fn root_for_link_type(link_type: PcapLinkType) -> &'static str {
    match link_type {
        PcapLinkType::NullLoopback => "link:null-loopback",
        PcapLinkType::Ethernet => "link:ethernet",
        PcapLinkType::RawIp => "link:raw",
        PcapLinkType::LinuxSll => "link:linux-sll",
        PcapLinkType::Ieee80211 => "link:dot11",
        PcapLinkType::Ieee80211Radiotap => "link:radiotap",
        PcapLinkType::BluetoothLeLl => "link:bluetooth-le-ll-with-phdr",
        PcapLinkType::Ieee802154WithFcs | PcapLinkType::Ieee802154NoFcs => "link:ieee802154",
        PcapLinkType::Ieee802154Tap => "link:ieee802154-tap",
        PcapLinkType::Unknown(_) => "link:raw",
    }
}

fn precision_name(precision: TimestampPrecision) -> &'static str {
    match precision {
        TimestampPrecision::Microseconds => "microseconds",
        TimestampPrecision::Nanoseconds => "nanoseconds",
    }
}

fn normalized_layer_name(layer: &dyn Layer) -> String {
    if layer.as_any().is::<Ethernet>() {
        "ethernet"
    } else if layer.as_any().is::<Arp>() {
        "arp"
    } else if layer.as_any().is::<Vlan>() {
        "vlan"
    } else if layer.as_any().is::<LinuxSll>() {
        "linux_sll"
    } else if layer.as_any().is::<NullLoopback>() {
        "null_loopback"
    } else if layer.as_any().is::<Radiotap>() {
        "radiotap"
    } else if layer.as_any().is::<Dot11>() {
        "dot11"
    } else if layer.as_any().is::<LlcSnap>() {
        "llc_snap"
    } else if layer.as_any().is::<Eapol>() {
        "eapol"
    } else if layer.as_any().is::<EapolKey>() {
        "eapol_key"
    } else if layer.as_any().is::<Ipv4>() {
        "ipv4"
    } else if layer.as_any().is::<Ipv6>() {
        "ipv6"
    } else if layer.as_any().is::<Ipv6FragmentHeader>() {
        "ipv6_fragment"
    } else if layer.as_any().is::<Ipv6RoutingHeader>()
        || layer.as_any().is::<Ipv6MobileRoutingHeader>()
        || layer.as_any().is::<Ipv6SegmentRoutingHeader>()
    {
        "ipv6_routing"
    } else if layer.as_any().is::<Udp>() {
        "udp"
    } else if layer.as_any().is::<Tcp>() {
        "tcp"
    } else if layer.as_any().is::<Bgp>() {
        "bgp"
    } else if layer.as_any().is::<Rip>() {
        // The Scapy reference and the decode adapter normalize RIP/RIPng to the
        // lowercase oracle layer names; mirror them so the pcap-roundtrip decoded
        // layer lists match (libcrafter's Layer::name is "Rip"/"Ripng").
        "rip"
    } else if layer.as_any().is::<Ripng>() {
        "ripng"
    } else if layer.as_any().is::<Icmpv4>() {
        "icmp"
    } else if layer.as_any().is::<Icmpv6>() {
        "icmpv6"
    } else if layer.as_any().is::<Igmp>() {
        "igmp"
    } else if layer.as_any().is::<IgmpQuery>() {
        "igmp_query"
    } else if layer.as_any().is::<IgmpReport>() {
        "igmp_report"
    } else if layer.as_any().is::<IgmpExtension>() {
        "igmp_extension"
    } else if layer.as_any().is::<Dns>() {
        "dns"
    } else if layer.as_any().is::<Dhcp>() {
        "dhcp"
    } else if layer.as_any().is::<Esp>() {
        // The Scapy reference normalizes ESP to the lowercase oracle name; mirror
        // it here so the pcap-roundtrip decoded layer lists match across backends
        // (libcrafter's Layer::name is "Esp").
        "esp"
    } else if layer.as_any().is::<Ah>() {
        "ah"
    } else if layer.as_any().is::<Raw>() {
        "payload"
    } else {
        layer.name()
    }
    .to_string()
}

fn decode_hex(hex: &str) -> ExampleResult<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return Err("raw_hex must contain an even number of characters".into());
    }

    let mut out = Vec::with_capacity(hex.len() / 2);
    for index in (0..hex.len()).step_by(2) {
        out.push(u8::from_str_radix(&hex[index..index + 2], 16)?);
    }
    Ok(out)
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
