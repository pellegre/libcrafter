mod common;

use common::{
    arg_value, default_target_path, parse_usize_arg, print_help_if_requested, write_example_pcap,
    ExampleResult, EXAMPLE_PCAP_LINK_TYPE,
};

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example pcap_write -- [--out FILE] [--count N]\n\nBuild deterministic Ethernet/IPv4/TCP packets and write an offline pcap file.",
    ) {
        return Ok(());
    }

    let path = arg_value("--out")
        .map(Into::into)
        .unwrap_or_else(|| default_target_path("examples/pcap-write.pcap"));
    let count = parse_usize_arg("--count", 5)?;
    let packets = write_example_pcap(&path, count)?;

    println!("example: pcap_write");
    println!("mode: offline");
    println!("pcap: {}", path.display());
    println!("packets: {}", packets.len());
    println!("link_type: {:?}", EXAMPLE_PCAP_LINK_TYPE);
    for (index, packet) in packets.iter().enumerate() {
        println!("packet[{index}]: {}", packet.summary());
    }

    Ok(())
}
