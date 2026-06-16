//! Public-API integration tests for monitor-mode radiotap injection.
//!
//! These exercise the feature through `crafter::prelude::*` only, with no real
//! interface and no transmission: a dry-run injection plan is inspectable, and a
//! live link-layer send to a missing interface fails cleanly.

use crafter::prelude::*;

/// Documentation-safe BSSID in the `02:00:5e:..` range.
const BSSID: MacAddr = MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x06]);

/// Build a radiotap-led 802.11 beacon suitable for monitor-mode injection.
fn inject_beacon_packet() -> Packet {
    Radiotap::monitor_tx(2, RadiotapChannel::channel_2ghz(6), RadiotapTxFlags::NO_ACK)
        / Dot11::beacon()
            .addr1(MacAddr::BROADCAST)
            .addr2(BSSID)
            .addr3(BSSID)
            .sequence_number(0)
            .with_beacon_fixed_fields(Dot11BeaconFixedFields::new(0, 100, DOT11_CAPABILITY_ESS))
            .ssid(b"libcrafter-inject-dry-run")
            .supported_rates([0x82, 0x84, 0x8b, 0x96])
            .ds_parameter_set(6)
}

#[test]
fn radiotap_injection_dry_run_plan_is_inspectable() {
    let packet = inject_beacon_packet();
    let plan = packet
        .send_dry_run(
            SendOptions::new()
                .iface("dot11-monitor-dry-run")
                .link_layer(),
        )
        .unwrap();

    assert_eq!(plan.interface(), "dot11-monitor-dry-run");
    assert!(plan.target().is_link_layer());
    assert_eq!(
        plan.target(),
        SendTarget::LinkLayer {
            link_type: LinkType::Radiotap
        }
    );

    // The compiled bytes lead with a radiotap header (version byte 0x00).
    assert_eq!(plan.bytes()[0], 0x00);

    // The planned length matches the compiled packet length.
    assert_eq!(plan.len(), packet.compile().unwrap().len());
}

#[test]
fn radiotap_live_send_to_missing_interface_reports_not_found() {
    let packet = inject_beacon_packet();
    let error = packet
        .send(
            SendOptions::new()
                .iface("missing-crafter-wifi0")
                .link_layer()
                .live(),
        )
        .unwrap_err();

    match error {
        NetError::InterfaceNotFound { name } => {
            assert_eq!(name, "missing-crafter-wifi0");
        }
        other => panic!("expected InterfaceNotFound for missing monitor interface, got {other}"),
    }
}
