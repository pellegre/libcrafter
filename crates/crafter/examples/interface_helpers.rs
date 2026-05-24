mod common;

use common::{arg_or, print_help_if_requested, ExampleResult, EXAMPLE_IFACE};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example interface_helpers -- [--iface IFACE]\n\nInspect interface helper APIs without requiring the selected interface to exist.",
    ) {
        return Ok(());
    }

    let iface = arg_or("--iface", EXAMPLE_IFACE);
    let table = interfaces();

    println!("example: interface_helpers");
    println!("mode: offline");
    println!("selected interface: {iface}");
    println!("interfaces discovered: {}", table.len());
    for interface in table.iter().take(4) {
        println!(
            "interface: {} up={} loopback={} running={} ipv4={:?} ipv6={:?}",
            interface.name(),
            interface.is_up(),
            interface.is_loopback(),
            interface.is_running(),
            interface.first_ipv4(),
            interface.first_ipv6(false)
        );
    }

    print_result(
        "find_interface",
        find_interface(&iface).map(|info| {
            format!(
                "{} mac={:?} addresses={}",
                info.name(),
                info.mac_address(),
                info.addresses().len()
            )
        }),
    );
    print_result("default_interface_name", default_interface_name());
    print_result("get_my_mac", get_my_mac(&iface).map(|mac| mac.to_string()));
    print_result("get_my_ip", get_my_ip(&iface).map(|ip| ip.to_string()));
    print_result(
        "get_my_ipv6",
        get_my_ipv6(&iface, false).map(|ip| ip.to_string()),
    );

    let range = get_ip_strings("192.0.2.10-192.0.2.12")?;
    println!("get_ip_strings: {:?}", range);

    Ok(())
}

fn print_result<T, E>(label: &str, result: std::result::Result<T, E>)
where
    T: std::fmt::Display,
    E: std::fmt::Display,
{
    match result {
        Ok(value) => println!("{label}: {value}"),
        Err(err) => println!("{label} error: {err}"),
    }
}
