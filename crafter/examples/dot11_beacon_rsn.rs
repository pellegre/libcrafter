mod common;

use common::{print_help_if_requested, ExampleResult};
use crafter::prelude::*;

const AP_MAC: MacAddr = MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x10]);

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example dot11_beacon_rsn --\n\nBuild and decode an offline bare Dot11 beacon carrying a typed RSN IE.",
    ) {
        return Ok(());
    }

    let rsn = RsnInformation::new()
        .with_group_cipher_suite(RSN_CIPHER_SUITE_GCMP_256)
        .with_pairwise_cipher_list([RSN_CIPHER_SUITE_GCMP_256])
        .with_akm_list([RSN_AKM_SUITE_SAE])
        .with_capabilities(
            RsnCapabilities::new()
                .with_management_frame_protection_capable(true)
                .with_management_frame_protection_required(true),
        );
    let beacon = Dot11::beacon()
        .addr1(MacAddr::BROADCAST)
        .addr2(AP_MAC)
        .addr3(AP_MAC)
        .sequence_number(7)
        .with_beacon_fixed_fields(Dot11BeaconFixedFields::new(
            0x0102_0304_0506_0708,
            100,
            DOT11_CAPABILITY_ESS | DOT11_CAPABILITY_PRIVACY,
        ))
        .ssid(b"libcrafter-rsn")
        .supported_rates([0x82, 0x84, 0x8b, 0x96])
        .ds_parameter_set(6)
        .with_rsn_information(&rsn)?;

    let compiled = Packet::from_layer(beacon).compile()?;
    let decoded = Packet::decode_from_link(LinkType::Ieee80211, compiled.as_bytes())?;

    println!("mode: offline");
    println!("summary: {}", decoded.summary());
    println!("show:\n{}", decoded.show());
    if let Some(dot11) = decoded.layer::<Dot11>() {
        if let Some(decoded_rsn) = dot11.rsn_information() {
            let decoded_rsn = decoded_rsn?;
            println!("Rsn group cipher: {}", decoded_rsn.group_cipher_suite());
            println!("Rsn akm suites: {}", decoded_rsn.akm_suites().len());
        }
    }
    println!("hexdump:\n{}", compiled.hexdump());

    Ok(())
}
