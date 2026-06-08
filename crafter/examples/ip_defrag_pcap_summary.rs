mod common;

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use common::{
    arg_value, default_target_path, ensure_parent, flag_present, print_help_if_requested,
    ExampleResult,
};
use crafter::prelude::*;
use sha1::{Digest, Sha1};

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example ip_defrag_pcap_summary -- [--pcap FILE] [--out FILE] [--stdout]\n\nRead an offline pcap, run IpDefrag, and write machine-readable JSON transform artifacts.",
    ) {
        return Ok(());
    }

    let pcap_path = arg_value("--pcap")
        .or_else(|| arg_value("--in"))
        .map(PathBuf::from)
        .unwrap_or_else(default_fragment_pcap);
    let out_path = arg_value("--out")
        .map(PathBuf::from)
        .unwrap_or_else(|| default_target_path("examples/ip-defrag-pcap-summary.json"));

    let mut source = PacketWire::pcap_file(pcap_path.clone()).open()?.source()?;
    let mut transform = IpDefrag::new();
    let mut output_records = Vec::new();

    while let Some(record) = source.next_record()? {
        let output = transform.defrag_record(record)?;
        output_records.extend(output.into_records());
    }

    let json = transform_artifact_json(&pcap_path, &out_path, &transform, &output_records)?;
    if flag_present("--stdout") {
        println!("{json}");
    } else {
        ensure_parent(&out_path)?;
        fs::write(&out_path, json)?;
        println!("example: ip_defrag_pcap_summary");
        println!("mode: offline");
        println!("pcap: {}", pcap_path.display());
        println!("json: {}", out_path.display());
        println!("input fragment count: {}", transform.fragments_observed());
        println!("output packet count: {}", output_records.len());
    }

    Ok(())
}

fn default_fragment_pcap() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/pcaps/raw-ipv4-ipfragment-generated.pcap")
}

fn transform_artifact_json(
    pcap_path: &Path,
    out_path: &Path,
    transform: &IpDefrag,
    records: &[PacketRecord],
) -> ExampleResult<String> {
    let mut json = String::new();
    let stats = transform.stats();

    writeln!(&mut json, "{{")?;
    writeln!(
        &mut json,
        "  \"tool\": {},",
        json_string("ip_defrag_pcap_summary")
    )?;
    writeln!(&mut json, "  \"pcap\": {},", json_path(pcap_path))?;
    writeln!(&mut json, "  \"json\": {},", json_path(out_path))?;
    writeln!(&mut json, "  \"transform\": {},", json_string("IpDefrag"))?;
    writeln!(
        &mut json,
        "  \"input_record_count\": {},",
        stats.input_count()
    )?;
    writeln!(
        &mut json,
        "  \"input_fragment_count\": {},",
        stats.fragments_observed()
    )?;
    writeln!(&mut json, "  \"output_packet_count\": {},", records.len())?;
    writeln!(
        &mut json,
        "  \"pending_datagram_count\": {},",
        transform.pending_datagram_count()
    )?;
    writeln!(&mut json, "  \"stats\": {{")?;
    writeln!(
        &mut json,
        "    \"emitted_count\": {},",
        stats.emitted_count()
    )?;
    writeln!(
        &mut json,
        "    \"pass_through_count\": {},",
        stats.pass_through_count()
    )?;
    writeln!(
        &mut json,
        "    \"completed_datagrams\": {},",
        stats.completed_datagrams()
    )?;
    writeln!(
        &mut json,
        "    \"evicted_datagrams\": {},",
        stats.evicted_datagrams()
    )?;
    writeln!(&mut json, "    \"conflicts\": {},", stats.conflicts())?;
    writeln!(&mut json, "    \"errors\": {}", stats.errors())?;
    writeln!(&mut json, "  }},")?;
    writeln!(&mut json, "  \"outputs\": [")?;
    for (index, record) in records.iter().enumerate() {
        write_record_json(&mut json, index, record)?;
        if index + 1 != records.len() {
            writeln!(&mut json, ",")?;
        } else {
            writeln!(&mut json)?;
        }
    }
    writeln!(&mut json, "  ]")?;
    writeln!(&mut json, "}}")?;

    Ok(json)
}

fn write_record_json(json: &mut String, index: usize, record: &PacketRecord) -> ExampleResult<()> {
    let packet = record.packet();
    let compiled = packet.compile()?;
    let payload = packet.layers::<Raw>().last().map(Raw::as_bytes);

    writeln!(json, "    {{")?;
    writeln!(json, "      \"index\": {index},")?;
    writeln!(
        json,
        "      \"summary\": {},",
        json_string(&packet.summary())
    )?;
    writeln!(json, "      \"packet_len\": {},", compiled.len())?;
    writeln!(
        json,
        "      \"packet_hash\": {},",
        json_string(&sha1_hex(&compiled))
    )?;
    writeln!(
        json,
        "      \"packet_hash_algorithm\": {},",
        json_string("sha1")
    )?;
    match payload {
        Some(bytes) => {
            writeln!(json, "      \"payload_len\": {},", bytes.len())?;
            writeln!(
                json,
                "      \"payload_hash\": {},",
                json_string(&sha1_hex(bytes))
            )?;
        }
        None => {
            writeln!(json, "      \"payload_len\": null,")?;
            writeln!(json, "      \"payload_hash\": null,")?;
        }
    }
    writeln!(
        json,
        "      \"payload_hash_algorithm\": {},",
        json_string("sha1")
    )?;
    writeln!(
        json,
        "      \"payload_hash_source\": {},",
        json_string("last_raw_layer")
    )?;
    write_record_metadata_json(json, record.metadata())?;
    writeln!(json, "    }}")?;
    Ok(())
}

fn write_record_metadata_json(json: &mut String, metadata: &PacketMetadata) -> ExampleResult<()> {
    writeln!(json, "      \"metadata\": {{")?;
    writeln!(
        json,
        "        \"origin\": {},",
        json_string(&format!("{:?}", metadata.origin()))
    )?;
    writeln!(
        json,
        "        \"backend\": {},",
        json_string(&format!("{:?}", metadata.backend()))
    )?;
    writeln!(
        json,
        "        \"pcap_link_type\": {},",
        json_optional_debug(metadata.pcap_link_type())
    )?;
    writeln!(
        json,
        "        \"captured_len\": {},",
        json_optional_u32(metadata.captured_len())
    )?;
    writeln!(
        json,
        "        \"original_len\": {},",
        json_optional_u32(metadata.original_len())
    )?;
    write_defrag_metadata_json(json, metadata.ip_defrag_metadata())?;
    writeln!(json, ",")?;
    write_transform_traces_json(json, metadata.transforms())?;
    writeln!(json, "      }}")?;
    Ok(())
}

fn write_defrag_metadata_json(
    json: &mut String,
    metadatas: &[IpDefragMetadata],
) -> ExampleResult<()> {
    writeln!(json, "        \"ip_defrag_metadata\": [")?;
    for (index, metadata) in metadatas.iter().enumerate() {
        writeln!(json, "          {{")?;
        writeln!(
            json,
            "            \"family\": {},",
            json_string(metadata.family().label())
        )?;
        writeln!(
            json,
            "            \"identification\": {},",
            metadata.identification()
        )?;
        writeln!(
            json,
            "            \"datagram_key\": {},",
            json_optional_string(metadata.datagram_key())
        )?;
        writeln!(
            json,
            "            \"fragment_count\": {},",
            metadata.fragment_count()
        )?;
        writeln!(
            json,
            "            \"duplicate_count\": {},",
            metadata.duplicate_count()
        )?;
        writeln!(
            json,
            "            \"overlap_status\": {},",
            json_string(&format!("{:?}", metadata.overlap_status()))
        )?;
        writeln!(
            json,
            "            \"conflict\": {},",
            metadata.has_conflict()
        )?;
        writeln!(
            json,
            "            \"total_len\": {},",
            json_optional_u32(metadata.total_len())
        )?;
        writeln!(
            json,
            "            \"eviction_reason\": {},",
            json_optional_debug(metadata.eviction_reason())
        )?;
        writeln!(json, "            \"byte_ranges\": [")?;
        for (range_index, range) in metadata.byte_ranges().iter().enumerate() {
            write!(
                json,
                "              {{\"start\": {}, \"end\": {}, \"len\": {}}}",
                range.start(),
                range.end(),
                range.len()
            )?;
            if range_index + 1 != metadata.byte_ranges().len() {
                writeln!(json, ",")?;
            } else {
                writeln!(json)?;
            }
        }
        writeln!(json, "            ]")?;
        write!(json, "          }}")?;
        if index + 1 != metadatas.len() {
            writeln!(json, ",")?;
        } else {
            writeln!(json)?;
        }
    }
    write!(json, "        ]")?;
    Ok(())
}

fn write_transform_traces_json(json: &mut String, traces: &[TransformTrace]) -> ExampleResult<()> {
    writeln!(json, "        \"transform_traces\": [")?;
    for (index, trace) in traces.iter().enumerate() {
        write!(
            json,
            "          {{\"name\": {}, \"note\": {}}}",
            json_string(trace.name()),
            json_optional_string(trace.note())
        )?;
        if index + 1 != traces.len() {
            writeln!(json, ",")?;
        } else {
            writeln!(json)?;
        }
    }
    writeln!(json, "        ]")?;
    Ok(())
}

fn sha1_hex(bytes: &[u8]) -> String {
    let digest = Sha1::digest(bytes);
    hex_bytes(&digest)
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn json_path(path: &Path) -> String {
    json_string(&path.display().to_string())
}

fn json_optional_debug<T>(value: Option<T>) -> String
where
    T: std::fmt::Debug,
{
    value
        .map(|value| json_string(&format!("{value:?}")))
        .unwrap_or_else(|| "null".to_string())
}

fn json_optional_string(value: Option<&str>) -> String {
    value.map(json_string).unwrap_or_else(|| "null".to_string())
}

fn json_optional_u32(value: Option<u32>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_string())
}

fn json_string(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for ch in value.chars() {
        match ch {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            ch if ch.is_control() => {
                write!(&mut output, "\\u{:04x}", ch as u32)
                    .expect("writing to a String cannot fail");
            }
            ch => output.push(ch),
        }
    }
    output.push('"');
    output
}
