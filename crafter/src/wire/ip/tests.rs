use super::{
    IpDefrag, IpDefragConfig, IpDefragEvictionReason, IpDefragMetadata, IpDefragOverlapStatus,
    IpFragment, IpFragmentConfig, IpFragmentFamily, IpFragmentMetadata, IpFragmentRange,
    IpFragmentReason,
};
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

#[test]
fn ip_fragment_metadata_exposes_emission_details() {
    let metadata = IpFragmentMetadata::new(
        IpFragmentFamily::Ipv6,
        1280,
        0xfeed_beef,
        4,
        false,
        5,
        4,
        IpFragmentRange::new(32, 48),
    )
    .with_original_len(2048)
    .with_reason(IpFragmentReason::Fragmented);

    assert_eq!(metadata.family(), IpFragmentFamily::Ipv6);
    assert_eq!(metadata.family().version(), 6);
    assert_eq!(metadata.family().label(), "ipv6");
    assert_eq!(metadata.mtu(), 1280);
    assert_eq!(metadata.identification(), 0xfeed_beef);
    assert_eq!(metadata.fragment_offset(), 4);
    assert_eq!(metadata.fragment_offset_bytes(), 32);
    assert!(!metadata.more_fragments());
    assert_eq!(metadata.fragment_count(), 5);
    assert_eq!(metadata.emitted_index(), 4);
    assert_eq!(metadata.byte_range(), IpFragmentRange::new(32, 48));
    assert_eq!(metadata.byte_range().len(), 16);
    assert_eq!(metadata.original_len(), Some(2048));
    assert_eq!(metadata.reason(), Some(&IpFragmentReason::Fragmented));
}

#[test]
fn ip_defrag_metadata_exposes_overlap_duplicates_and_eviction() {
    let metadata = IpDefragMetadata::new(IpFragmentFamily::Ipv4, 0x1234)
        .with_datagram_key("192.0.2.1>198.51.100.1 proto=17 id=0x1234")
        .with_fragment_count(3)
        .with_duplicate_count(2)
        .with_overlap_status(IpDefragOverlapStatus::Conflicting)
        .with_byte_range(IpFragmentRange::new(0, 24))
        .with_byte_range(IpFragmentRange::new(16, 40))
        .with_total_len(60)
        .with_eviction_reason(IpDefragEvictionReason::Conflict);

    assert_eq!(metadata.family(), IpFragmentFamily::Ipv4);
    assert_eq!(metadata.identification(), 0x1234);
    assert_eq!(
        metadata.datagram_key(),
        Some("192.0.2.1>198.51.100.1 proto=17 id=0x1234")
    );
    assert_eq!(metadata.fragment_count(), 3);
    assert_eq!(metadata.duplicate_count(), 2);
    assert_eq!(
        metadata.overlap_status(),
        IpDefragOverlapStatus::Conflicting
    );
    assert!(metadata.overlap_status().has_overlap());
    assert!(metadata.has_conflict());
    assert_eq!(
        metadata.byte_ranges(),
        &[IpFragmentRange::new(0, 24), IpFragmentRange::new(16, 40)]
    );
    assert_eq!(metadata.total_len(), Some(60));
    assert_eq!(
        metadata.eviction_reason(),
        Some(&IpDefragEvictionReason::Conflict)
    );
    assert!(!metadata.timed_out());
}
