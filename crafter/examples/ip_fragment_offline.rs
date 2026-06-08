mod common;

use common::{local_ipv6, print_help_if_requested, remote_ipv6, ExampleResult};
use crafter::prelude::*;
use crafter::wire::PacketWriter;

const MTU: usize = 1280;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example ip_fragment_offline\n\nWrite IpFragment output into an in-memory writer without opening a live interface.",
    ) {
        return Ok(());
    }

    let payload = generated_payload(1301);
    let packet = Ipv6::new()
        .src(local_ipv6())
        .dst(remote_ipv6())
        .hop_limit(64)
        / Udp::new().sport(45000).dport(45001)
        / Raw::from_bytes(&payload);
    let original_len = packet.compile()?.len();
    let mut fragment = IpFragment::new(MTU);
    let output = fragment.fragment_record(PacketRecord::new(packet))?;
    let mut writer = MemoryPacketWriter::dry_run().with_target_details("offline-memory-writer");

    for record in output.into_records() {
        writer.write_record(&record)?;
    }

    let writes = writer.into_writes();
    if writes.len() < 2 {
        return Err(format!("expected fragmented output, got {} write(s)", writes.len()).into());
    }

    println!("example: ip_fragment_offline");
    println!("mode: offline");
    println!("writer: memory");
    println!(
        "documentation address pair: {} -> {}",
        local_ipv6(),
        remote_ipv6()
    );
    println!("mtu: {MTU}");
    println!("original bytes: {original_len}");
    println!("fragment inputs: {}", fragment.input_count());
    println!("fragment outputs: {}", fragment.emitted_count());
    println!("memory writes: {}", writes.len());

    for (index, write) in writes.iter().enumerate() {
        let metadata = write
            .record()
            .metadata()
            .ip_fragment_metadata()
            .first()
            .ok_or("fragment record is missing IpFragment metadata")?;
        let range = metadata.byte_range();

        println!(
            "write[{index}]: bytes={} dry_run={} fragment={}/{} range={}..{} offset={} more={}",
            write.report().bytes_written(),
            write.report().is_dry_run(),
            metadata.fragment_index() + 1,
            metadata.fragment_count(),
            range.start(),
            range.end(),
            metadata.fragment_offset(),
            metadata.more_fragments()
        );
    }

    Ok(())
}

fn generated_payload(len: usize) -> Vec<u8> {
    (0..len).map(|index| b'a' + (index % 26) as u8).collect()
}
