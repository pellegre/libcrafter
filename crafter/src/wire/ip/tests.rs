use super::{IpDefrag, IpDefragConfig, IpFragment, IpFragmentConfig};
use crate::wire::record::{BackendKind, PacketOrigin, PacketRecord};
use crate::wire::transform::PacketTransform;
use crate::Raw;

fn record(payload: &'static str) -> PacketRecord {
    PacketRecord::new(Raw::from(payload))
        .with_origin(PacketOrigin::Generated)
        .with_backend(BackendKind::Memory)
        .with_interface("lo")
}

#[test]
fn ip_defrag_passes_records_through_initially() {
    let input = record("payload");
    let expected_summary = input.packet().summary();
    let expected_metadata = input.metadata().clone();
    let mut transform = IpDefrag::new();

    let output = transform.defrag_record(input).unwrap();

    assert_eq!(transform.name(), "ip-defrag");
    assert_eq!(transform.input_count(), 1);
    assert_eq!(transform.emitted_count(), 1);
    assert_eq!(output.len(), 1);
    assert_eq!(output.records()[0].packet().summary(), expected_summary);
    assert_eq!(output.records()[0].metadata(), &expected_metadata);
}

#[test]
fn ip_fragment_passes_records_through_initially() {
    let input = record("payload");
    let expected_summary = input.packet().summary();
    let expected_metadata = input.metadata().clone();
    let mut transform = IpFragment::new(1280);

    let output = transform.fragment_record(input).unwrap();

    assert_eq!(transform.name(), "ip-fragment");
    assert_eq!(transform.config().mtu(), 1280);
    assert_eq!(transform.input_count(), 1);
    assert_eq!(transform.emitted_count(), 1);
    assert_eq!(output.len(), 1);
    assert_eq!(output.records()[0].packet().summary(), expected_summary);
    assert_eq!(output.records()[0].metadata(), &expected_metadata);
}

#[test]
fn ip_defrag_config_exposes_passthrough_policy() {
    let config = IpDefragConfig::new().pass_non_fragments(false);
    let transform = IpDefrag::new().with_config(config);

    assert!(!transform.config().emits_non_fragments());
}

#[test]
fn ip_fragment_config_exposes_mtu_and_df_policy() {
    let config = IpFragmentConfig::new(1500).honor_dont_fragment(false);
    let transform = IpFragment::with_config(config);

    assert_eq!(transform.config().mtu(), 1500);
    assert!(!transform.config().honors_dont_fragment());
}
