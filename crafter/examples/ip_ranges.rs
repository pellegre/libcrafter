mod common;

use common::{print_help_if_requested, ExampleResult};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example ip_ranges --\n\nParse documentation-safe IPv4 range and number expressions.",
    ) {
        return Ok(());
    }

    let direct = Ipv4Range::parse("192.0.2.10-192.0.2.12")?;
    let wildcard = parse_ip_range("198.51.100.20,21,22")?;
    let cidr_strings = get_ip_strings("203.0.113.0/30")?;
    let ports = parse_numbers("80,443,8000-8002")?;

    println!("example: ip_ranges");
    println!("mode: offline");
    println!("Ipv4Range::parse len: {}", direct.len());
    println!("Ipv4Range::parse addresses: {:?}", direct.addresses());
    println!(
        "Ipv4Range contains 192.0.2.11: {}",
        direct.contains("192.0.2.11".parse()?)
    );
    println!("parse_ip_range len: {}", wildcard.len());
    println!(
        "parse_ip_range addresses: {:?}",
        wildcard.iter().collect::<Vec<_>>()
    );
    println!("get_ip_strings: {:?}", cidr_strings);
    println!("parse_numbers: {:?}", ports);

    Ok(())
}
