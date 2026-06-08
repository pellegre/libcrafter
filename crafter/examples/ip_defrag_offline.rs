mod common;

use common::{local_ipv4, print_help_if_requested, remote_ipv4, ExampleResult};
use crafter::prelude::*;

const MTU: usize = 44;
const IDENTIFICATION: u16 = 0x4501;
const RAW_PROTOCOL: u8 = 253;
const PAYLOAD: &[u8] = b"offline defrag example payload from documentation address space";

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example ip_defrag_offline\n\nReplay generated memory fragments into IpDefrag without opening a live interface.",
    ) {
        return Ok(());
    }

    let fragments = generated_fragments()?;
    let fragment_count = fragments.len();
    let mut source = VecPacketSource::new(reordered(fragments));
    let mut defrag = IpDefrag::new();
    let mut reassembled = Vec::new();

    while let Some(record) = source.next_record()? {
        reassembled.extend(defrag.defrag_record(record)?.into_records());
    }

    if reassembled.len() != 1 {
        return Err(format!("expected one reassembled packet, got {}", reassembled.len()).into());
    }

    let record = &reassembled[0];
    let Some(raw) = record.packet().layer::<Raw>() else {
        return Err("reassembled packet did not preserve a Raw payload".into());
    };
    if raw.as_bytes() != PAYLOAD {
        return Err("reassembled payload did not match the generated input".into());
    }

    println!("example: ip_defrag_offline");
    println!("mode: offline");
    println!("source kind: memory records");
    println!(
        "documentation address pair: {} -> {}",
        local_ipv4(),
        remote_ipv4()
    );
    println!("input fragments: {fragment_count}");
    println!("reassembled records: {}", reassembled.len());
    println!("summary: {}", record.packet().summary());
    println!("payload bytes: {}", raw.as_bytes().len());
    println!("defrag inputs: {}", defrag.input_count());
    println!("defrag fragments observed: {}", defrag.fragments_observed());
    println!("defrag outputs: {}", defrag.emitted_count());

    for metadata in record.metadata().ip_defrag_metadata() {
        println!(
            "defrag metadata: family={} id=0x{:x} fragments={} duplicates={} total_len={:?}",
            metadata.family().label(),
            metadata.identification(),
            metadata.fragment_count(),
            metadata.duplicate_count(),
            metadata.total_len()
        );
    }

    Ok(())
}

fn generated_fragments() -> ExampleResult<Vec<PacketRecord>> {
    let packet = Ipv4::with_addresses(local_ipv4(), remote_ipv4())
        .protocol(RAW_PROTOCOL)
        .identification(IDENTIFICATION)
        .ttl(64)
        / Raw::from_bytes(PAYLOAD);
    let mut fragment = IpFragment::new(MTU);

    Ok(fragment
        .fragment_record(PacketRecord::new(packet))?
        .into_records())
}

fn reordered(mut records: Vec<PacketRecord>) -> Vec<PacketRecord> {
    if records.len() > 1 {
        records.rotate_right(1);
    }
    records
}
