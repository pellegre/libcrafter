mod common;

use common::{
    arg_value, default_target_path, parse_usize_arg, print_help_if_requested, write_example_pcap,
    ExampleResult,
};

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example dump_pcap -- [--out FILE] [--count N]\n\nBuild deterministic Ethernet/IPv4/TCP packets and dump them to a pcap file.",
    ) {
        return Ok(());
    }

    let path = arg_value("--out")
        .map(Into::into)
        .unwrap_or_else(|| default_target_path("libcrafter-example-dump.pcap"));
    let count = parse_usize_arg("--count", 5)?;
    let packets = write_example_pcap(&path, count)?;

    println!("wrote {} packets to {}", packets.len(), path.display());

    Ok(())
}
