mod common;

use common::{
    local_ipv4, print_batch_send_report, print_help_if_requested, remote_ipv4, ExampleResult,
    EXAMPLE_IFACE,
};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example batch_send --\n\nBuild TCP SYN packets and inspect positional dry-run batch send reports.",
    ) {
        return Ok(());
    }

    let packets = (0..3)
        .map(|index| {
            Ipv4::new()
                .src(local_ipv4())
                .dst(remote_ipv4())
                .id(0x5000 + index)
                .ttl(64)
                / Tcp::new()
                    .sport(49152 + index)
                    .dport(80)
                    .seq(0x1000 + u32::from(index))
                    .flags(TCP_FLAG_SYN)
        })
        .collect::<Vec<_>>();
    let report = send_packets(
        &packets,
        BatchSend::new()
            .iface(EXAMPLE_IFACE)
            .network_layer()
            .dry_run()
            .retries(1),
    )?;

    println!("example: batch_send");
    println!("mode: dry-run");
    println!("requests: {}", report.len());
    print_batch_send_report("tcp syn probes", &report);
    for (index, packet) in packets.iter().enumerate() {
        println!("request {index}: {}", packet.summary());
    }

    Ok(())
}
