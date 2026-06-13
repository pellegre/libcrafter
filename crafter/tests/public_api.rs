use std::net::{Ipv4Addr, Ipv6Addr};

use crafter::prelude::*;

fn documentation_mac(last_octet: u8) -> MacAddr {
    MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, last_octet])
}

#[test]
fn prelude_builds_and_compiles_packet() -> crafter::Result<()> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Icmpv4::echo_request().id(0x4242).seq(1)
        / Raw::from("hello");

    let compiled = packet.compile()?;

    assert!(!compiled.is_empty());
    assert_eq!(compiled.as_bytes()[0] >> 4, 4);
    assert!(packet.summary().contains("Icmp(type=echo-request"));

    Ok(())
}

#[test]
fn public_api_ip_fragment_exports() {
    use crafter::wire::{
        IpDefrag as WireIpDefrag, IpDefragConfig as WireIpDefragConfig,
        IpDefragEvictionReason as WireIpDefragEvictionReason,
        IpDefragMetadata as WireIpDefragMetadata,
        IpDefragOverlapPolicy as WireIpDefragOverlapPolicy,
        IpDefragOverlapStatus as WireIpDefragOverlapStatus, IpDefragStats as WireIpDefragStats,
        IpFragment as WireIpFragment, IpFragmentConfig as WireIpFragmentConfig,
        IpFragmentFamily as WireIpFragmentFamily, IpFragmentMetadata as WireIpFragmentMetadata,
        IpFragmentRange as WireIpFragmentRange, IpFragmentReason as WireIpFragmentReason,
        IpFragmentStats as WireIpFragmentStats,
        Ipv4DontFragmentPolicy as WireIpv4DontFragmentPolicy,
        Ipv4FragmentIdentificationPolicy as WireIpv4FragmentIdentificationPolicy,
        Ipv6AtomicFragmentPolicy as WireIpv6AtomicFragmentPolicy,
        Ipv6FragmentIdentificationPolicy as WireIpv6FragmentIdentificationPolicy,
    };

    let prelude_defrag = IpDefrag::new().with_config(
        IpDefragConfig::new()
            .overlap_policy(IpDefragOverlapPolicy::PassThroughConflicting)
            .ipv6_atomic_fragments(Ipv6AtomicFragmentPolicy::Normalize),
    );
    let prelude_fragment = IpFragment::with_config(
        IpFragmentConfig::new(1280)
            .dont_fragment_policy(Ipv4DontFragmentPolicy::PassThrough)
            .ipv4_identification_policy(Ipv4FragmentIdentificationPolicy::Fixed(0x1234))
            .ipv6_identification(0x0102_0304),
    );
    let _: IpDefragStats = prelude_defrag.stats();
    let _: IpFragmentStats = prelude_fragment.stats();
    let _: IpDefragMetadata = IpDefragMetadata::new(IpFragmentFamily::Ipv4, 0x1234)
        .with_overlap_status(IpDefragOverlapStatus::NonConflicting)
        .with_eviction_reason(IpDefragEvictionReason::Timeout);
    let _: IpFragmentMetadata = IpFragmentMetadata::new(
        IpFragmentFamily::Ipv6,
        1280,
        0x0102_0304,
        0,
        false,
        1,
        0,
        IpFragmentRange::new(0, 8),
    )
    .with_reason(IpFragmentReason::AlreadyFits);

    let wire_defrag = WireIpDefrag::new().with_config(
        WireIpDefragConfig::new()
            .overlap_policy(WireIpDefragOverlapPolicy::RejectConflicting)
            .ipv6_atomic_fragments(WireIpv6AtomicFragmentPolicy::PassThrough),
    );
    let wire_fragment = WireIpFragment::with_config(
        WireIpFragmentConfig::new(1280)
            .dont_fragment_policy(WireIpv4DontFragmentPolicy::FragmentAnyway)
            .ipv4_identification_policy(WireIpv4FragmentIdentificationPolicy::Fixed(0x4321))
            .ipv6_identification(0x0403_0201),
    );
    let _: WireIpDefragStats = wire_defrag.stats();
    let _: WireIpFragmentStats = wire_fragment.stats();
    let _: WireIpDefragMetadata = WireIpDefragMetadata::new(WireIpFragmentFamily::Ipv4, 0x4321)
        .with_overlap_status(WireIpDefragOverlapStatus::None)
        .with_eviction_reason(WireIpDefragEvictionReason::ByteLimit);
    let _: WireIpFragmentMetadata = WireIpFragmentMetadata::new(
        WireIpFragmentFamily::Ipv4,
        1280,
        0x4321,
        0,
        false,
        1,
        0,
        WireIpFragmentRange::new(0, 8),
    )
    .with_reason(WireIpFragmentReason::DontFragment);

    let _: crafter::IpDefragStats = crafter::IpDefrag::new().stats();
    let _: crafter::IpFragmentStats = crafter::IpFragment::new(1280).stats();
    let _: crafter::Ipv4FragmentIdentificationPolicy =
        WireIpv4FragmentIdentificationPolicy::PreserveOrGenerate;
    let _: crafter::Ipv6FragmentIdentificationPolicy =
        WireIpv6FragmentIdentificationPolicy::Generate;
}

#[test]
fn public_api_ip_fragment_smoke() -> std::result::Result<(), Box<dyn std::error::Error>> {
    const IPV4_MTU: usize = 44;
    const IPV6_MTU: usize = 1280;
    const RAW_IPV4_PROTOCOL: u8 = 253;

    let ipv4_payload = b"public api ipv4 defrag smoke payload from documentation space";
    let ipv4_header = Ipv4::with_addresses(
        Ipv4Addr::new(192, 0, 2, 59),
        Ipv4Addr::new(198, 51, 100, 59),
    )
    .protocol(RAW_IPV4_PROTOCOL)
    .identification(0x5904);
    let ipv4_packet = ipv4_header / Raw::from_bytes(ipv4_payload);
    assert_eq!(ipv4_packet.compile()?.as_bytes()[0] >> 4, 4);

    let mut ipv4_fragment = IpFragment::new(IPV4_MTU);
    let mut ipv4_fragments = ipv4_fragment
        .fragment_record(PacketRecord::new(ipv4_packet))?
        .into_records();
    assert!(ipv4_fragments.len() > 1);
    ipv4_fragments.rotate_right(1);

    let reassembled = Sniffer::new(VecPacketSource::new(ipv4_fragments))
        .with(IpDefrag::new())
        .collect_records()?;
    assert_eq!(reassembled.len(), 1);
    let raw = reassembled[0]
        .packet()
        .layer::<Raw>()
        .expect("reassembled IPv4 packet should expose the Raw payload");
    assert_eq!(raw.as_bytes(), ipv4_payload);
    assert_eq!(
        reassembled[0]
            .metadata()
            .ip_defrag_metadata()
            .first()
            .map(IpDefragMetadata::fragment_count),
        Some(3)
    );

    let ipv6_payload: Vec<u8> = (0..1301).map(|index| b'a' + (index % 26) as u8).collect();
    let ipv6_packet = Ipv6::new()
        .src(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 59))
        .dst(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 59))
        .hop_limit(64)
        / Udp::new().sport(5900).dport(5901)
        / Raw::from_bytes(&ipv6_payload);
    assert_eq!(ipv6_packet.compile()?.as_bytes()[0] >> 4, 6);

    let reports = Transmitter::new(
        MemoryPacketWriter::dry_run().with_target_details("public-api-fragment-smoke"),
    )
    .with(IpFragment::with_config(
        IpFragmentConfig::new(IPV6_MTU).ipv6_identification(0x5900_0059),
    ))
    .send(ipv6_packet)?;
    assert!(reports.len() > 1);
    assert!(reports.iter().all(|report| report.is_dry_run()));
    assert!(reports
        .iter()
        .all(|report| report.backend() == &BackendKind::Memory));
    assert!(reports
        .iter()
        .all(|report| report.bytes_requested() <= IPV6_MTU));

    Ok(())
}

#[test]
fn public_api_dot11_phase15_radiotap_llc_and_send_plan() -> crafter::Result<()> {
    let station = documentation_mac(0x01);
    let access_point = documentation_mac(0x02);
    let destination = documentation_mac(0x03);
    let to_ds = Dot11::data().frame_control_value().with_to_ds(true);
    let radiotap_flags = crafter::protocols::link::RADIOTAP_FLAGS_FCS_PRESENT
        | crafter::protocols::link::RADIOTAP_FLAGS_FAILED_FCS;

    let packet = Radiotap::new()
        .flags(radiotap_flags)
        .rate(12)
        .antenna_signal(-42)
        / Dot11::data()
            .frame_control(to_ds)
            .addr1(access_point)
            .addr2(station)
            .addr3(destination)
            .sequence_number(0x42)
        / LlcSnap::new().ethertype(ETHERTYPE_IPV4)
        / Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Icmpv4::echo_request().id(0x4242).seq(1)
        / Raw::from("phase15");

    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_link(LinkType::Radiotap, compiled.as_bytes())?;
    let radiotap = decoded.layer::<Radiotap>().unwrap();
    let dot11 = decoded.layer::<Dot11>().unwrap();
    let llc = decoded.layer::<LlcSnap>().unwrap();

    assert_eq!(radiotap.version_value(), Some(0));
    assert_eq!(radiotap.rate_value(), Some(12));
    assert_eq!(radiotap.antenna_signal_value(), Some(-42));
    assert_eq!(radiotap.fcs_status().unwrap().present(), true);
    assert_eq!(radiotap.fcs_status().unwrap().failed(), true);
    assert_eq!(dot11.frame_type(), Dot11FrameType::Data);
    assert_eq!(dot11.data_subtype(), Some(Dot11DataSubtype::Data));
    assert_eq!(dot11.source(), Some(station));
    assert_eq!(dot11.destination(), Some(destination));
    assert_eq!(dot11.bssid(), Some(access_point));
    assert_eq!(
        dot11.sequence_control_value().unwrap().sequence_number(),
        0x42
    );
    assert_eq!(llc.ethertype_value(), ETHERTYPE_IPV4);
    assert!(decoded.layer::<Ipv4>().is_some());
    assert!(decoded.summary().contains("Radiotap("));

    let plan = packet
        .send_dry_run(SendOptions::new().iface("wifi-dryrun0"))
        .expect("radiotap dry-run send plan");
    assert_eq!(plan.interface(), "wifi-dryrun0");
    assert_eq!(plan.requested_mode(), SendMode::Auto);
    assert_eq!(
        plan.target(),
        SendTarget::LinkLayer {
            link_type: LinkType::Radiotap,
        }
    );
    assert_eq!(plan.bytes(), compiled.as_bytes());

    Ok(())
}

#[test]
fn public_api_dot11_phase15_eapol_key_and_rsn_builders() -> crafter::Result<()> {
    let station = documentation_mac(0x11);
    let access_point = documentation_mac(0x12);
    let key_information = EapolKeyInformation::new()
        .with_descriptor_version(2)
        .with_key_type(true)
        .with_key_ack(true)
        .with_key_mic(true)
        .with_secure(true);
    let eapol_key = EapolKey::new()
        .key_information(key_information)
        .key_length(16)
        .replay_counter(7)
        .nonce([0x11; 32])
        .iv([0x22; 16])
        .rsc([0x33; 8])
        .id([0x44; 8])
        .mic([0x55; 16])
        .key_data([0xaa, 0xbb, 0xcc]);
    let eapol_packet = Dot11::data()
        .addr1(access_point)
        .addr2(station)
        .addr3(access_point)
        / LlcSnap::new().ethertype(ETHERTYPE_EAPOL)
        / Eapol::key()
        / eapol_key.clone();

    let eapol_bytes = eapol_packet.compile()?;
    let decoded_eapol = Packet::decode_from_link(LinkType::Ieee80211, eapol_bytes.as_bytes())?;
    let decoded_header = decoded_eapol.layer::<Eapol>().unwrap();
    let decoded_key = decoded_eapol.layer::<EapolKey>().unwrap();

    assert_eq!(decoded_header.version_value(), EAPOL_VERSION_2);
    assert_eq!(decoded_header.packet_type_kind(), EapolType::Key);
    assert_eq!(decoded_key.descriptor_type_kind(), EapolDescriptorType::Rsn);
    assert_eq!(decoded_key.key_information_value(), key_information);
    assert_eq!(decoded_key.key_length_value(), 16);
    assert_eq!(decoded_key.replay_counter_value(), 7);
    assert_eq!(decoded_key.key_data_length_value(), Some(3));
    assert_eq!(decoded_key.key_data_bytes(), &[0xaa, 0xbb, 0xcc]);
    assert_eq!(
        decoded_key.rsn_handshake_metadata().descriptor_type(),
        EapolDescriptorType::Rsn
    );
    assert_eq!(decoded_eapol.compile()?.as_bytes(), eapol_bytes.as_bytes());

    let rsn = RsnInformation::new()
        .with_pairwise_cipher_list([RSN_CIPHER_SUITE_CCMP_128])
        .with_akm_list([RSN_AKM_SUITE_PSK])
        .with_capabilities(
            RsnCapabilities::new()
                .with_management_frame_protection_capable(true)
                .with_management_frame_protection_required(true),
        );
    let rsn_tag = Dot11TaggedParameter::from_rsn_information(&rsn)?;
    let beacon = Dot11::beacon()
        .addr1(MacAddr::BROADCAST)
        .addr2(access_point)
        .addr3(access_point)
        .ssid(b"phase15")
        .tag(rsn_tag.clone());
    let beacon_bytes = Packet::from_layer(beacon).compile()?;
    let decoded_beacon = Packet::decode_from_link(LinkType::Ieee80211, beacon_bytes.as_bytes())?;
    let dot11 = decoded_beacon.layer::<Dot11>().unwrap();

    assert_eq!(rsn_tag.id(), DOT11_TAG_RSN);
    assert_eq!(rsn_tag.rsn_information().unwrap()?, rsn);
    assert_eq!(
        dot11.management_subtype(),
        Some(Dot11ManagementSubtype::Beacon)
    );
    assert_eq!(dot11.rsn_information().unwrap()?, rsn);
    assert_eq!(
        dot11
            .rsn_information_elements()
            .collect::<crafter::Result<Vec<_>>>()?,
        vec![rsn]
    );

    Ok(())
}

#[test]
fn public_api_dot11_phase15_pcap_link_types_decode() -> crafter::Result<()> {
    use crafter::wire::backend::pcap::PcapLinkType;

    let station = documentation_mac(0x21);
    let access_point = documentation_mac(0x22);
    let bare_packet = Dot11::data()
        .addr1(access_point)
        .addr2(station)
        .addr3(access_point)
        / LlcSnap::new().ethertype(ETHERTYPE_IPV6)
        / Ipv6::with_addresses(
            Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 2),
        )
        .nh(IPPROTO_IPV6_NO_NEXT);
    let radiotap_packet = Radiotap::new() / bare_packet.clone();
    let bare_bytes = bare_packet.compile()?;
    let radiotap_bytes = radiotap_packet.compile()?;

    assert_eq!(PcapLinkType::Ieee80211.datalink(), 105);
    assert_eq!(PcapLinkType::Ieee80211Radiotap.datalink(), 127);
    assert_eq!(PcapLinkType::from_datalink(105), PcapLinkType::Ieee80211);
    assert_eq!(
        PcapLinkType::from_datalink(127),
        PcapLinkType::Ieee80211Radiotap
    );
    assert_eq!(PcapLinkType::Ieee80211.link_type(), LinkType::Ieee80211);
    assert_eq!(
        PcapLinkType::Ieee80211Radiotap.link_type(),
        LinkType::Radiotap
    );

    let decoded_bare = PcapLinkType::Ieee80211.decode(bare_bytes.as_bytes())?;
    assert!(decoded_bare.layer::<Dot11>().is_some());
    assert!(decoded_bare.layer::<LlcSnap>().is_some());
    assert!(decoded_bare.layer::<Ipv6>().is_some());

    let decoded_radiotap = PcapLinkType::Ieee80211Radiotap.decode(radiotap_bytes.as_bytes())?;
    assert!(decoded_radiotap.layer::<Radiotap>().is_some());
    assert!(decoded_radiotap.layer::<Dot11>().is_some());
    assert!(decoded_radiotap.layer::<LlcSnap>().is_some());

    Ok(())
}

#[test]
fn public_api_dot11() -> crafter::Result<()> {
    let receiver = MacAddr::new([0x02, 0x00, 0x5e, 0x11, 0x00, 0x01]);
    let transmitter = MacAddr::new([0x02, 0x00, 0x5e, 0x11, 0x00, 0x02]);
    let destination = MacAddr::new([0x02, 0x00, 0x5e, 0x11, 0x00, 0x03]);
    let source = MacAddr::new([0x02, 0x00, 0x5e, 0x11, 0x00, 0x04]);
    let frame_control = Dot11FrameControl::new()
        .with_frame_type(DOT11_FRAME_TYPE_DATA)
        .with_subtype(DOT11_DATA_SUBTYPE_QOS_DATA)
        .with_to_ds(true)
        .with_from_ds(true)
        .with_protected(true);
    let sequence_control = Dot11SequenceControl::new()
        .with_sequence_number(0x123)
        .with_fragment_number(7);

    let dot11 = Dot11::qos_data()
        .frame_control(frame_control)
        .duration_id(0x1234)
        .addr1(receiver)
        .addr2(transmitter)
        .addr3(destination)
        .addr4(source)
        .sequence_control(sequence_control)
        .qos_control(0xabcd);
    let packet = dot11.clone() / Raw::from("wifi");
    let compiled = packet.compile()?;

    assert_eq!(
        compiled.as_bytes().len(),
        DOT11_DATA_ADDR4_HEADER_LEN + DOT11_QOS_CONTROL_LEN + 4
    );
    assert_eq!(&compiled.as_bytes()[0..2], &frame_control.compile());
    assert_eq!(dot11.frame_type(), Dot11FrameType::Data);
    assert_eq!(dot11.data_subtype(), Some(Dot11DataSubtype::QosData));
    assert_eq!(dot11.source(), Some(source));
    assert_eq!(dot11.destination(), Some(destination));
    assert_eq!(dot11.bssid(), None);
    assert!(dot11.is_protected());
    assert_eq!(
        dot11.sequence_control_value().unwrap().sequence_number(),
        0x123
    );
    assert_eq!(
        dot11_subtype_label(DOT11_FRAME_TYPE_DATA, DOT11_DATA_SUBTYPE_QOS_DATA),
        "qos-data"
    );

    let ssid = Dot11TaggedParameter::new(0, [b't', b'e', b's', b't']);
    let beacon = Dot11::beacon()
        .addr1(MacAddr::BROADCAST)
        .addr2(transmitter)
        .addr3(transmitter)
        .tag(ssid.clone());
    let beacon_bytes = Packet::from_layer(beacon.clone()).compile()?;

    assert_eq!(ssid.id(), 0);
    assert_eq!(ssid.data(), b"test");
    assert_eq!(beacon.tagged_parameters(), &[ssid.clone()]);
    assert_eq!(
        beacon.management_subtype(),
        Some(Dot11ManagementSubtype::Beacon)
    );
    assert_eq!(
        beacon_bytes.as_bytes().len(),
        DOT11_DATA_HEADER_LEN + DOT11_MGMT_BEACON_FIXED_LEN + ssid.encoded_len()
    );

    let root_frame_control: crafter::Dot11FrameControl =
        crafter::Dot11FrameControl::from_bits(crafter::DOT11_FC_PROTECTED);
    let core_sequence_control: crafter::core::Dot11SequenceControl =
        crafter::core::Dot11SequenceControl::new().with_sequence_number(7);
    let protocols_frame_type = crafter::protocols::Dot11FrameType::from_raw(
        crafter::protocols::DOT11_FRAME_TYPE_MANAGEMENT,
    );
    let link_tag = crafter::protocols::link::Dot11TaggedParameter::new(221, [1, 2, 3]);

    assert!(root_frame_control.protected());
    assert_eq!(core_sequence_control.sequence_number(), 7);
    assert_eq!(
        protocols_frame_type,
        crafter::protocols::Dot11FrameType::Management
    );
    assert_eq!(link_tag.id(), 221);
    assert_eq!(
        crafter::dot11_frame_type_label(crafter::DOT11_FRAME_TYPE_DATA),
        "data"
    );
    assert_eq!(
        crafter::core::dot11_control_subtype_label(crafter::core::DOT11_CONTROL_SUBTYPE_ACK),
        "ack"
    );
    assert_eq!(
        crafter::protocols::dot11_category_label(crafter::protocols::DOT11_CATEGORY_PUBLIC),
        "public"
    );
    assert_eq!(DOT11_MIN_HEADER_LEN, 10);
    assert_eq!(
        crafter::protocols::DOT11_DATA_HEADER_LEN,
        DOT11_DATA_HEADER_LEN
    );

    Ok(())
}

#[test]
fn ipv4_protocol_public_api_paths_are_usable() -> crafter::Result<()> {
    let prelude_protocol: Ipv4Protocol = Ipv4Protocol::Icmpv4;
    let root_protocol: crafter::Ipv4Protocol = crafter::Ipv4Protocol::Tcp;
    let core_protocol: crafter::core::Ipv4Protocol = crafter::core::Ipv4Protocol::Udp;
    let protocols_protocol: crafter::protocols::Ipv4Protocol =
        crafter::protocols::Ipv4Protocol::Icmpv6;
    let ipv4_module_protocol: crafter::protocols::ipv4::Ipv4Protocol =
        crafter::protocols::ipv4::Ipv4Protocol::Icmpv4;

    let prelude_packet =
        (Ipv4::new().ipv4_protocol(prelude_protocol) / Raw::from("prelude")).compile()?;
    let root_packet = (crafter::Ipv4::new().ipv4_protocol(root_protocol)
        / crafter::Raw::from("root"))
    .compile()?;
    let core_packet = (crafter::core::Ipv4::new().ipv4_protocol(core_protocol)
        / crafter::core::Raw::from("core"))
    .compile()?;
    let protocols_packet = (crafter::protocols::Ipv4::new().ipv4_protocol(protocols_protocol)
        / crafter::protocols::Raw::from("protocols"))
    .compile()?;
    let ipv4_module_packet = (crafter::protocols::ipv4::Ipv4::new()
        .ipv4_protocol(ipv4_module_protocol)
        / crafter::protocols::Raw::from("ipv4-module"))
    .compile()?;

    assert_eq!(u8::from(prelude_protocol), IPPROTO_ICMP);
    assert_eq!(u8::from(root_protocol), crafter::IPPROTO_TCP);
    assert_eq!(u8::from(core_protocol), crafter::core::IPPROTO_UDP);
    assert_eq!(
        u8::from(protocols_protocol),
        crafter::protocols::IPPROTO_ICMPV6
    );
    assert_eq!(
        u8::from(ipv4_module_protocol),
        crafter::protocols::ipv4::IPPROTO_ICMP
    );
    assert_eq!(prelude_packet.as_bytes()[9], IPPROTO_ICMP);
    assert_eq!(root_packet.as_bytes()[9], crafter::IPPROTO_TCP);
    assert_eq!(core_packet.as_bytes()[9], crafter::core::IPPROTO_UDP);
    assert_eq!(
        protocols_packet.as_bytes()[9],
        crafter::protocols::IPPROTO_ICMPV6
    );
    assert_eq!(
        ipv4_module_packet.as_bytes()[9],
        crafter::protocols::ipv4::IPPROTO_ICMP
    );

    Ok(())
}

#[test]
fn canonical_ip_module_paths_are_usable() -> crafter::Result<()> {
    let dscp = crafter::protocols::ip::shared::Dscp::ef();
    let ecn = crafter::protocols::ip::shared::Ecn::capable_1();
    let ds_field = (dscp.value() << 2) | ecn.value();

    let v4_protocol = crafter::protocols::ip::v4::Ipv4Protocol::Udp;
    let v4_packet = (crafter::protocols::ip::v4::Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        .dscp(dscp)
        .ecn(ecn)
        .ipv4_protocol(v4_protocol)
        / crafter::Raw::from("v4"))
    .compile()?;

    assert_eq!(v4_packet.as_bytes()[0] >> 4, 4);
    assert_eq!(v4_packet.as_bytes()[1], ds_field);
    assert_eq!(
        v4_packet.as_bytes()[9],
        crafter::protocols::ip::v4::IPPROTO_UDP
    );
    assert_eq!(
        u8::from(v4_protocol),
        crafter::protocols::ip::v4::IPPROTO_UDP
    );

    let v6_header = crafter::protocols::ip::v6::Ipv6::with_addresses(
        Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1),
        Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 2),
    )
    .dscp(dscp)
    .ecn(ecn)
    .nh(crafter::protocols::ip::v6::IPPROTO_IPV6_NO_NEXT);
    let v6_packet = (v6_header / crafter::Raw::from("v6")).compile()?;
    let v6_traffic_class = ((v6_packet.as_bytes()[0] & 0x0f) << 4) | (v6_packet.as_bytes()[1] >> 4);
    let v6_option = crafter::protocols::ip::v6::Ipv6Option::router_alert(
        crafter::protocols::ip::v6::IPV6_ROUTER_ALERT_MLD,
    );

    assert_eq!(v6_packet.as_bytes()[0] >> 4, 6);
    assert_eq!(v6_traffic_class, ds_field);
    assert_eq!(
        v6_packet.as_bytes()[6],
        crafter::protocols::ip::v6::IPPROTO_IPV6_NO_NEXT
    );
    assert_eq!(v6_option.router_alert_value_label(), Some("MLD"));

    Ok(())
}

#[test]
fn public_module_paths_expose_representative_items() -> crafter::Result<()> {
    let packet = crafter::core::Packet::from_layer(crafter::core::Raw::from("core"));
    assert_eq!(packet.compile()?.as_bytes(), b"core");

    let pcap_input = crafter::wire::PacketWire::pcap_file("fixtures/input.pcap");
    assert_eq!(
        pcap_input.target().path(),
        Some(std::path::Path::new("fixtures/input.pcap"))
    );

    let pcap_recorder =
        crafter::wire::PacketWire::pcap_recorder("fixtures/output.pcap", crafter::LinkType::Raw);
    assert_eq!(
        pcap_recorder.target().pcap_link_type(),
        Some(crafter::wire::backend::pcap::PcapLinkType::RawIp)
    );

    let timestamp = crafter::wire::backend::pcap::PcapTimestamp::micros(7, 11).unwrap();
    let record = crafter::wire::PacketRecord::new(crafter::Raw::from("wire")).with_pcap_metadata(
        timestamp,
        4,
        4,
        crafter::wire::backend::pcap::PcapLinkType::RawIp,
    );
    assert_eq!(record.metadata().timestamp(), Some(timestamp));
    assert_eq!(record.metadata().original_len(), Some(4));
    assert_eq!(record.metadata().captured_len(), Some(4));
    assert_eq!(record.metadata().link_type(), Some(crafter::LinkType::Raw));

    let send_options = crafter::net::SendOptions::new()
        .iface("dry-run0")
        .network_layer()
        .dry_run();
    assert!(send_options.is_dry_run());
    assert_eq!(send_options.interface_name(), Some("dry-run0"));

    let _socket_options = crafter::net::socket::SendOptions::new().dry_run();
    let _range = crafter::net::range::Ipv4Range::parse("192.0.2.1").unwrap();
    let _batch = crafter::net::batch::BatchSendRecv::new().dry_run();
    let _matcher = crafter::net::send_recv::ReplyMatcher::from_packet(&packet);

    Ok(())
}

#[test]
fn dscp_and_ecn_helpers_are_public_and_raw_safe() -> crafter::Result<()> {
    let prelude_dscp: Dscp = Dscp::ef();
    let root_dscp = crafter::Dscp::new(46)?;
    let core_dscp = crafter::core::Dscp::cs1();
    let protocols_dscp = crafter::protocols::Dscp::class_selector(7)?;
    let ip_dscp = crafter::protocols::ipv4::Dscp::cs0();

    assert_eq!(prelude_dscp, root_dscp);
    assert_eq!(prelude_dscp.value(), 46);
    assert_eq!(core_dscp.value(), 8);
    assert_eq!(protocols_dscp, crafter::Dscp::cs7());
    assert_eq!(ip_dscp, Dscp::default_forwarding());
    assert_eq!(u8::from(Dscp::new(63)?), 63);
    assert!(Dscp::new(64).is_err());
    assert!(Dscp::class_selector(8).is_err());

    let prelude_ecn: Ecn = Ecn::capable_0();
    let root_ecn = crafter::Ecn::new(2)?;
    let core_ecn = crafter::core::Ecn::ect1();
    let protocols_ecn = crafter::protocols::Ecn::ce();
    let ip_ecn = crafter::protocols::ipv4::Ecn::not_ect();

    assert_eq!(prelude_ecn, root_ecn);
    assert_eq!(prelude_ecn, Ecn::ect0());
    assert_eq!(prelude_ecn.value(), 2);
    assert_eq!(core_ecn.value(), 1);
    assert_eq!(protocols_ecn.value(), 3);
    assert_eq!(ip_ecn.value(), 0);
    assert_eq!(u8::from(Ecn::new(3)?), 3);
    assert!(Ecn::new(4).is_err());

    let ipv6 = Ipv6::new().dscp(Dscp::ef()).ecn(Ecn::capable_0());
    assert_eq!(ipv6.traffic_class_value(), 0xba);
    assert_eq!(ipv6.dscp_value(), Dscp::ef());
    assert_eq!(ipv6.ecn_value(), Ecn::ect0());

    Ok(())
}

#[test]
fn ipv6_option() -> crafter::Result<()> {
    let prelude_option: Ipv6Option = Ipv6Option::pad1();
    let core_option = crafter::core::Ipv6Option::padn(3)?;
    let root_option = crafter::Ipv6Option::generic(0x63, [0xaa])?;
    let protocols_option = crafter::protocols::Ipv6Option::unknown(0xc2, [0, 0, 0, 1])?;
    let ipv6_module_option = crafter::protocols::ipv6::Ipv6Option::pad_n_data([0xde, 0xad])?;

    let prelude_iter: Ipv6OptionIter =
        Ipv6OptionIter::new(&[IPV6_OPTION_PAD1, IPV6_OPTION_PADN, 1, 0]);
    let core_iter = crafter::core::Ipv6OptionIter::new(&[crafter::core::IPV6_OPTION_PAD1]);
    let protocols_iter =
        crafter::protocols::Ipv6OptionIter::new(&[crafter::protocols::IPV6_OPTION_PAD1]);

    let prelude_action: Ipv6OptionAction = Ipv6OptionAction::Skip;
    let root_action: crafter::Ipv6OptionAction =
        crafter::Ipv6OptionAction::DiscardSendIcmpIfNotMulticast;
    let core_action = crafter::core::Ipv6OptionAction::from_bits(2)?;
    let protocols_action = crafter::protocols::Ipv6OptionAction::from_option_type(0x63);

    assert_eq!(IPV6_OPTION_PAD1, 0);
    assert_eq!(crafter::core::IPV6_OPTION_PADN, 1);
    assert_eq!(crafter::protocols::IPV6_OPTION_PAD1, 0);
    assert_eq!(crafter::protocols::ipv6::IPV6_OPTION_PADN, 1);

    assert_eq!(prelude_option.encode()?, vec![IPV6_OPTION_PAD1]);
    assert_eq!(core_option.encode()?, vec![IPV6_OPTION_PADN, 1, 0]);
    assert_eq!(root_option.kind(), 0x63);
    assert_eq!(root_option.option_type(), 0x63);
    assert_eq!(root_option.data(), &[0xaa]);
    assert_eq!(root_option.action(), Ipv6OptionAction::Discard);
    assert!(root_option.may_change_en_route());
    assert_eq!(root_option.option_number(), 3);
    assert_eq!(root_option.encode()?, vec![0x63, 1, 0xaa]);
    assert_eq!(protocols_option.action(), root_action);
    assert!(!protocols_option.change_en_route());
    assert_eq!(protocols_option.rest(), 2);
    assert_eq!(
        ipv6_module_option.encode()?,
        vec![IPV6_OPTION_PADN, 2, 0xde, 0xad]
    );

    assert_eq!(
        prelude_iter.collect::<crafter::Result<Vec<_>>>()?,
        vec![prelude_option.clone(), core_option.clone()]
    );
    assert_eq!(
        core_iter.collect::<crafter::Result<Vec<_>>>()?,
        vec![Ipv6Option::Pad1]
    );
    assert_eq!(
        protocols_iter.collect::<crafter::Result<Vec<_>>>()?,
        vec![Ipv6Option::Pad1]
    );
    assert_eq!(prelude_action.bits(), 0);
    assert_eq!(root_action.bits(), 3);
    assert_eq!(core_action, Ipv6OptionAction::DiscardSendIcmp);
    assert_eq!(protocols_action, Ipv6OptionAction::Discard);

    Ok(())
}

#[test]
fn hop_by_hop() -> crafter::Result<()> {
    let src = Ipv6Addr::new(0x2001, 0x0db8, 0x0010, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0x2001, 0x0db8, 0x0020, 0, 0, 0, 0, 2);

    let prelude_header: Ipv6HopByHopOptionsHeader = Ipv6HopByHopOptionsHeader::new()
        .option(Ipv6Option::generic(0x1e, [0xaa])?)
        .push_option(Ipv6Option::pad1());
    let root_header = crafter::Ipv6HopByHopOptionsHeader::new()
        .nh(IPPROTO_IPV6_NO_NEXT)
        .header_ext_len(1);
    let core_header = crafter::core::Ipv6HopByHopOptionsHeader::new();
    let protocols_header = crafter::protocols::Ipv6HopByHopOptionsHeader::new();
    let ipv6_module_header = crafter::protocols::ipv6::Ipv6HopByHopOptionsHeader::new();

    let packet = crafter::Ipv6::with_addresses(src, dst)
        / prelude_header.clone()
        / crafter::Udp::new().sport(12345).dport(33434)
        / crafter::Raw::from("hbh");
    let compiled = packet.compile()?;

    assert_eq!(compiled.as_bytes()[6], IPPROTO_IPV6_HOPOPTS);
    assert_eq!(compiled.as_bytes()[40], IPPROTO_UDP);
    assert_eq!(compiled.as_bytes()[41], 0);
    assert_eq!(
        &compiled.as_bytes()[42..46],
        &[0x1e, 1, 0xaa, IPV6_OPTION_PAD1]
    );
    assert_eq!(&compiled.as_bytes()[46..48], &[0, 0]);

    assert_eq!(prelude_header.options_value().len(), 2);
    assert_eq!(prelude_header.options_list()[0].option_type(), 0x1e);
    assert_eq!(root_header.next_header_value(), IPPROTO_IPV6_NO_NEXT);
    assert_eq!(root_header.header_ext_len_value(), Some(1));
    assert_eq!(core_header.encoded_len(), 8);
    assert_eq!(protocols_header.encoded_len(), 8);
    assert_eq!(ipv6_module_header.encoded_len(), 8);

    Ok(())
}

#[test]
fn destination_options() -> crafter::Result<()> {
    let src = Ipv6Addr::new(0x2001, 0x0db8, 0x0010, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0x2001, 0x0db8, 0x0020, 0, 0, 0, 0, 2);

    let prelude_header: Ipv6DestinationOptionsHeader = Ipv6DestinationOptionsHeader::new()
        .option(Ipv6Option::generic(0x1e, [0xaa])?)
        .push_option(Ipv6Option::pad1());
    let root_header = crafter::Ipv6DestinationOptionsHeader::new()
        .nh(IPPROTO_IPV6_NO_NEXT)
        .header_ext_len(1);
    let core_header = crafter::core::Ipv6DestinationOptionsHeader::new();
    let protocols_header = crafter::protocols::Ipv6DestinationOptionsHeader::new();
    let ipv6_module_header = crafter::protocols::ipv6::Ipv6DestinationOptionsHeader::new();

    let packet = crafter::Ipv6::with_addresses(src, dst)
        / prelude_header.clone()
        / crafter::Udp::new().sport(12345).dport(33434)
        / crafter::Raw::from("dst");
    let compiled = packet.compile()?;

    assert_eq!(compiled.as_bytes()[6], IPPROTO_IPV6_DSTOPTS);
    assert_eq!(compiled.as_bytes()[40], IPPROTO_UDP);
    assert_eq!(compiled.as_bytes()[41], 0);
    assert_eq!(
        &compiled.as_bytes()[42..46],
        &[0x1e, 1, 0xaa, IPV6_OPTION_PAD1]
    );
    assert_eq!(&compiled.as_bytes()[46..48], &[0, 0]);

    assert_eq!(prelude_header.options_value().len(), 2);
    assert_eq!(prelude_header.options_list()[0].option_type(), 0x1e);
    assert_eq!(root_header.next_header_value(), IPPROTO_IPV6_NO_NEXT);
    assert_eq!(root_header.header_ext_len_value(), Some(1));
    assert_eq!(core_header.encoded_len(), 8);
    assert_eq!(protocols_header.encoded_len(), 8);
    assert_eq!(ipv6_module_header.encoded_len(), 8);

    Ok(())
}

#[test]
fn udp_public_api_paths_are_usable() -> crafter::Result<()> {
    let prelude_udp: Udp = Udp::new().sport(1111).dport(2222);
    let core_udp = crafter::core::Udp::new().sport(3333).dport(4444);
    let root_udp = crafter::Udp::new().sport(5555).dport(6666);
    let protocols_udp = crafter::protocols::Udp::new().sport(7777).dport(8888);
    let transport_udp = crafter::protocols::transport::Udp::new()
        .sport(9999)
        .dport(10000);
    let prelude_options: UdpOptions = UdpOptions::from_bytes([UDP_OPTION_NOP]);
    let core_options = crafter::core::UdpOptions::from_bytes([UDP_OPTION_EOL]);
    let root_options = crafter::UdpOptions::from_bytes([UDP_OPTION_REQ]);
    let protocols_options = crafter::protocols::UdpOptions::from_bytes([UDP_OPTION_RES]);
    let transport_options = crafter::protocols::transport::UdpOptions::from_bytes([UDP_OPTION_MDS]);

    let prelude_packet = (prelude_udp / Raw::from("prelude")).compile()?;
    let core_packet = (core_udp / crafter::core::Raw::from("core")).compile()?;
    let root_packet = (root_udp / crafter::Raw::from("root")).compile()?;
    let protocols_packet =
        (protocols_udp / crafter::protocols::Raw::from("protocols")).compile()?;
    let transport_packet =
        (transport_udp / crafter::protocols::Raw::from("transport")).compile()?;

    assert_eq!(&prelude_packet.as_bytes()[0..2], &1111u16.to_be_bytes());
    assert_eq!(&prelude_packet.as_bytes()[2..4], &2222u16.to_be_bytes());
    assert_eq!(&core_packet.as_bytes()[0..2], &3333u16.to_be_bytes());
    assert_eq!(&core_packet.as_bytes()[2..4], &4444u16.to_be_bytes());
    assert_eq!(&root_packet.as_bytes()[0..2], &5555u16.to_be_bytes());
    assert_eq!(&root_packet.as_bytes()[2..4], &6666u16.to_be_bytes());
    assert_eq!(&protocols_packet.as_bytes()[0..2], &7777u16.to_be_bytes());
    assert_eq!(&protocols_packet.as_bytes()[2..4], &8888u16.to_be_bytes());
    assert_eq!(&transport_packet.as_bytes()[0..2], &9999u16.to_be_bytes());
    assert_eq!(&transport_packet.as_bytes()[2..4], &10000u16.to_be_bytes());
    assert_eq!(prelude_options.as_bytes(), &[UDP_OPTION_NOP]);
    assert_eq!(core_options.as_bytes(), &[UDP_OPTION_EOL]);
    assert_eq!(root_options.as_bytes(), &[UDP_OPTION_REQ]);
    assert_eq!(protocols_options.as_bytes(), &[UDP_OPTION_RES]);
    assert_eq!(transport_options.as_bytes(), &[UDP_OPTION_MDS]);

    Ok(())
}

#[test]
fn udp_option_constants_and_statuses_are_public() {
    let prelude_checksum_status: UdpChecksumStatus = UdpChecksumStatus::NotChecked;
    let prelude_option_status: UdpOptionStatus = UdpOptionStatus::NoSurplus;
    let core_checksum_status: crafter::core::UdpChecksumStatus =
        crafter::core::UdpChecksumStatus::Valid;
    let root_option_status: crafter::UdpOptionStatus = crafter::UdpOptionStatus::Unsupported;
    let protocols_checksum_status: crafter::protocols::UdpChecksumStatus =
        crafter::protocols::UdpChecksumStatus::Ipv4NoChecksum;
    let transport_option_status: crafter::protocols::transport::UdpOptionStatus =
        crafter::protocols::transport::UdpOptionStatus::OptionChecksumInvalid;

    assert_eq!(UDP_HEADER_LEN, 8);
    assert_eq!(crafter::core::UDP_OPTION_EOL, 0);
    assert_eq!(crafter::UDP_OPTION_NOP, 1);
    assert_eq!(crafter::UDP_OPTION_APC, 2);
    assert_eq!(crafter::protocols::UDP_OPTION_FRAG, 3);
    assert_eq!(crafter::protocols::transport::UDP_OPTION_MDS, 4);
    assert_eq!(crafter::UDP_OPTION_MRDS, 5);
    assert_eq!(crafter::UDP_OPTION_REQ, 6);
    assert_eq!(crafter::UDP_OPTION_RES, 7);
    assert_eq!(crafter::protocols::transport::UDP_OPTION_TIME, 8);
    assert_eq!(crafter::UDP_OPTION_AUTH, 9);
    assert_eq!(crafter::UDP_OPTION_UNASSIGNED_SAFE_START, 10);
    assert_eq!(crafter::UDP_OPTION_UNASSIGNED_SAFE_END, 126);
    assert_eq!(crafter::UDP_OPTION_EXP, 127);
    assert_eq!(crafter::UDP_OPTION_RESERVED_SAFE_START, 128);
    assert_eq!(crafter::UDP_OPTION_RESERVED_SAFE_END, 191);
    assert_eq!(crafter::UDP_OPTION_UCMP, 192);
    assert_eq!(crafter::UDP_OPTION_UENC, 193);
    assert_eq!(crafter::UDP_OPTION_UNASSIGNED_UNSAFE_START, 194);
    assert_eq!(crafter::UDP_OPTION_UNASSIGNED_UNSAFE_END, 253);
    assert_eq!(crafter::UDP_OPTION_UEXP, 254);
    assert_eq!(crafter::UDP_OPTION_RESERVED_UNSAFE, 255);

    assert_eq!(prelude_checksum_status, UdpChecksumStatus::NotChecked);
    assert_eq!(prelude_option_status, UdpOptionStatus::NoSurplus);
    assert_eq!(
        core_checksum_status,
        crafter::core::UdpChecksumStatus::Valid
    );
    assert_eq!(root_option_status, crafter::UdpOptionStatus::Unsupported);
    assert_eq!(
        protocols_checksum_status,
        crafter::protocols::UdpChecksumStatus::Ipv4NoChecksum
    );
    assert_eq!(
        transport_option_status,
        crafter::protocols::transport::UdpOptionStatus::OptionChecksumInvalid
    );
    assert_eq!(
        udp_option_kind_class(UDP_OPTION_TIME),
        UdpOptionKindClass::KnownSafe
    );
    assert_eq!(
        crafter::core::udp_option_kind_class(crafter::core::UDP_OPTION_UEXP),
        crafter::core::UdpOptionKindClass::ExperimentalUnsafe
    );
    assert_eq!(
        crafter::protocols::udp_option_kind_class(crafter::protocols::UDP_OPTION_AUTH),
        crafter::protocols::UdpOptionKindClass::ReservedSafe
    );
    assert!(crafter::udp_option_kind_is_unsafe(crafter::UDP_OPTION_UEXP));
    assert!(crafter::protocols::udp_option_kind_is_unsupported(
        crafter::protocols::UDP_OPTION_FRAG
    ));
    assert!(crafter::protocols::transport::udp_option_kind_is_unsafe(
        crafter::protocols::transport::UDP_OPTION_RESERVED_UNSAFE
    ));
}

#[test]
fn udp_option_enum_and_iterator_public_paths_are_usable() -> crafter::Result<()> {
    let prelude_option: UdpOption = UdpOption::no_operation();
    let core_option = crafter::core::UdpOption::maximum_datagram_size(0x05b4);
    let root_option = crafter::UdpOption::extended_generic(crafter::UDP_OPTION_EXP, [0x12, 0x34]);
    let iter = crafter::protocols::UdpOptionIter::new(&[
        crafter::UDP_OPTION_NOP,
        crafter::UDP_OPTION_MDS,
        4,
        0x05,
        0xb4,
    ]);
    let transport_options = crafter::protocols::transport::UdpOptions::from_options(vec![
        prelude_option.clone(),
        core_option.clone(),
        root_option.clone(),
    ])?;

    assert_eq!(prelude_option.kind(), crafter::UDP_OPTION_NOP);
    assert_eq!(
        core_option.encode()?,
        vec![crafter::UDP_OPTION_MDS, 4, 0x05, 0xb4]
    );
    assert_eq!(
        root_option.encode()?,
        vec![crafter::UDP_OPTION_EXP, 255, 0, 6, 0x12, 0x34]
    );
    assert_eq!(
        iter.collect::<crafter::Result<Vec<_>>>()?,
        vec![prelude_option, core_option.clone()]
    );
    assert_eq!(transport_options.status(), UdpOptionStatus::Valid);
    assert_eq!(core_option.maximum_datagram_size_value(), Some(0x05b4));

    Ok(())
}

#[test]
fn udp_options_prelude_typed_packet_builds_and_inspects() -> crafter::Result<()> {
    let options = UdpOptions::new()
        .udp_option(UdpOption::maximum_datagram_size(1200))?
        .udp_option(UdpOption::maximum_reassembled_datagram_size(9000, 8))?
        .udp_option(UdpOption::echo_request(0x0102_0304))?
        .udp_option(UdpOption::echo_response(0x0506_0708))?
        .udp_option(UdpOption::timestamp(0x1122_3344, 0x5566_7788))?
        .udp_option(UdpOption::experimental(0x1234, [0xaa, 0xbb]))?
        .udp_option(UdpOption::unsafe_experimental(0x5678, [0xcc]))?;
    let parsed = options.options();
    let checksum_status: UdpChecksumStatus = UdpChecksumStatus::Valid;

    assert_eq!(options.status(), UdpOptionStatus::Valid);
    assert_eq!(options.option_checksum_value(), None);
    assert_eq!(options.alignment_bytes(), None);
    assert_eq!(
        options.option_iter().collect::<crafter::Result<Vec<_>>>()?,
        parsed
    );
    assert_eq!(checksum_status, UdpChecksumStatus::Valid);
    assert_eq!(parsed[0].maximum_datagram_size_value(), Some(1200));
    assert_eq!(
        parsed[1].maximum_reassembled_datagram_size_values(),
        Some((9000, 8))
    );
    assert_eq!(parsed[2].echo_request_token(), Some(0x0102_0304));
    assert_eq!(parsed[3].echo_response_token(), Some(0x0506_0708));
    assert_eq!(
        parsed[4].timestamp_values(),
        Some((0x1122_3344, 0x5566_7788))
    );
    assert_eq!(parsed[5].experiment_id(), Some(0x1234));
    assert_eq!(parsed[5].experiment_data(), Some(&[0xaa, 0xbb][..]));
    assert_eq!(parsed[6].experiment_id(), Some(0x5678));
    assert_eq!(parsed[6].experiment_data(), Some(&[0xcc][..]));
    assert_eq!(
        parsed[6].kind_class(),
        UdpOptionKindClass::ExperimentalUnsafe
    );
    assert!(parsed[6].is_unsafe());
    assert!(!parsed[6].is_unsupported());

    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 30))
        .dst(Ipv4Addr::new(198, 51, 100, 40))
        / Udp::new().sport(53003).dport(9998)
        / Raw::from("data")
        / options;

    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let udp = decoded.layer::<Udp>().unwrap();
    let raw = decoded.layer::<Raw>().unwrap();
    let decoded_options = decoded.layer::<UdpOptions>().unwrap();

    assert_eq!(udp.source_port_value(), 53003);
    assert_eq!(udp.destination_port_value(), 9998);
    assert_eq!(udp.length_value(), Some((UDP_HEADER_LEN + 4) as u16));
    assert_eq!(raw.as_bytes(), b"data");
    assert_eq!(decoded_options.status(), UdpOptionStatus::Valid);
    assert!(decoded_options.option_checksum_value().is_some());
    assert_eq!(
        decoded_options.options()[2].echo_request_token(),
        Some(0x0102_0304)
    );
    assert_eq!(
        decoded_options.options()[4].timestamp_values(),
        Some((0x1122_3344, 0x5566_7788))
    );

    Ok(())
}

#[test]
fn tcp_public_api_paths_are_usable() -> crafter::Result<()> {
    let prelude_tcp: Tcp = Tcp::new().sport(1111).dport(2222);
    let core_tcp = crafter::core::Tcp::new().sport(3333).dport(4444);
    let root_tcp = crafter::Tcp::new().sport(5555).dport(6666);
    let protocols_tcp = crafter::protocols::Tcp::new().sport(7777).dport(8888);
    let transport_tcp = crafter::protocols::transport::Tcp::new()
        .sport(9999)
        .dport(10000);

    let prelude_packet = (prelude_tcp / Raw::from("prelude")).compile()?;
    let core_packet = (core_tcp / crafter::core::Raw::from("core")).compile()?;
    let root_packet = (root_tcp / crafter::Raw::from("root")).compile()?;
    let protocols_packet =
        (protocols_tcp / crafter::protocols::Raw::from("protocols")).compile()?;
    let transport_packet =
        (transport_tcp / crafter::protocols::Raw::from("transport")).compile()?;

    assert_eq!(&prelude_packet.as_bytes()[0..2], &1111u16.to_be_bytes());
    assert_eq!(&prelude_packet.as_bytes()[2..4], &2222u16.to_be_bytes());
    assert_eq!(&core_packet.as_bytes()[0..2], &3333u16.to_be_bytes());
    assert_eq!(&core_packet.as_bytes()[2..4], &4444u16.to_be_bytes());
    assert_eq!(&root_packet.as_bytes()[0..2], &5555u16.to_be_bytes());
    assert_eq!(&root_packet.as_bytes()[2..4], &6666u16.to_be_bytes());
    assert_eq!(&protocols_packet.as_bytes()[0..2], &7777u16.to_be_bytes());
    assert_eq!(&protocols_packet.as_bytes()[2..4], &8888u16.to_be_bytes());
    assert_eq!(&transport_packet.as_bytes()[0..2], &9999u16.to_be_bytes());
    assert_eq!(&transport_packet.as_bytes()[2..4], &10000u16.to_be_bytes());

    Ok(())
}

#[test]
fn tcp_option_constants_and_types_are_public() -> crafter::Result<()> {
    // TCP option/types reach through prelude, core, root, protocols, and
    // protocols::transport, mirroring the UDP public-api coverage.
    let prelude_option: TcpOption = TcpOption::maximum_segment_size(1460);
    let core_option = crafter::core::TcpOption::window_scale(7);
    let root_option = crafter::TcpOption::sack_permitted();
    let protocols_option = crafter::protocols::TcpOption::timestamp(0x1122_3344, 0x5566_7788);
    let transport_option = crafter::protocols::transport::TcpOption::generic(0xfe, [0xaa, 0xbb]);

    let prelude_sack: TcpSackBlock = TcpSackBlock::new(100, 200);
    let core_sack = crafter::core::TcpSackBlock::new(300, 400);
    let root_sack = crafter::TcpSackBlock::new(500, 600);
    let protocols_sack = crafter::protocols::TcpSackBlock::new(700, 800);
    let transport_sack = crafter::protocols::transport::TcpSackBlock::new(900, 1000);

    let prelude_edo: TcpExtendedDataOffset = TcpExtendedDataOffset::Request;
    let core_edo = crafter::core::TcpExtendedDataOffset::HeaderLength { header_length: 16 };
    let root_edo = crafter::TcpExtendedDataOffset::HeaderAndSegmentLength {
        header_length: 16,
        segment_length: 1200,
    };
    let protocols_edo = crafter::protocols::TcpExtendedDataOffset::Request;
    let transport_edo = crafter::protocols::transport::TcpExtendedDataOffset::Request;

    let prelude_iter: TcpOptionIter = TcpOptionIter::new(&[TCP_OPTION_NOP, TCP_OPTION_EOL]);
    let core_iter = crafter::core::TcpOptionIter::new(&[crafter::core::TCP_OPTION_NOP]);
    let root_iter = crafter::TcpOptionIter::new(&[crafter::TCP_OPTION_NOP]);
    let protocols_iter =
        crafter::protocols::TcpOptionIter::new(&[crafter::protocols::TCP_OPTION_NOP]);
    let transport_iter = crafter::protocols::transport::TcpOptionIter::new(&[
        crafter::protocols::transport::TCP_OPTION_NOP,
    ]);

    // Existing TCP option constants through the same public paths.
    assert_eq!(TCP_OPTION_EOL, 0);
    assert_eq!(crafter::core::TCP_OPTION_NOP, 1);
    assert_eq!(crafter::TCP_OPTION_MSS, 2);
    assert_eq!(crafter::protocols::TCP_OPTION_WINDOW_SCALE, 3);
    assert_eq!(crafter::protocols::transport::TCP_OPTION_SACK_PERMITTED, 4);
    assert_eq!(crafter::TCP_OPTION_SACK, 5);
    assert_eq!(crafter::core::TCP_OPTION_TIMESTAMP, 8);
    assert_eq!(crafter::protocols::TCP_OPTION_MPTCP, 30);
    assert_eq!(crafter::protocols::transport::TCP_OPTION_FAST_OPEN, 34);
    assert_eq!(crafter::TCP_OPTION_EDO, 237);
    assert_eq!(crafter::core::TCP_EDO_REQUEST_LEN, 2);
    assert_eq!(crafter::protocols::TCP_EDO_HEADER_LEN, 4);
    assert_eq!(
        crafter::protocols::transport::TCP_EDO_HEADER_AND_SEGMENT_LEN,
        6
    );

    // Existing TCP flag constants through the same public paths.
    assert_eq!(TCP_FLAG_FIN, 0x001);
    assert_eq!(crafter::core::TCP_FLAG_SYN, 0x002);
    assert_eq!(crafter::TCP_FLAG_RST, 0x004);
    assert_eq!(crafter::protocols::TCP_FLAG_PSH, 0x008);
    assert_eq!(crafter::protocols::transport::TCP_FLAG_ACK, 0x010);
    assert_eq!(crafter::TCP_FLAG_URG, 0x020);
    assert_eq!(crafter::core::TCP_FLAG_ECE, 0x040);
    assert_eq!(crafter::protocols::TCP_FLAG_CWR, 0x080);

    // TCP_FLAG_NS stays as a compatibility alias for the 0x100 control bit.
    assert_eq!(TCP_FLAG_NS, 0x100);
    assert_eq!(crafter::core::TCP_FLAG_NS, 0x100);
    assert_eq!(crafter::TCP_FLAG_NS, 0x100);
    assert_eq!(crafter::protocols::TCP_FLAG_NS, 0x100);
    assert_eq!(crafter::protocols::transport::TCP_FLAG_NS, 0x100);

    // The new TCP_FLAG_AE compatibility alias shares the bit with TCP_FLAG_NS.
    // It is exported through protocols::transport.
    assert_eq!(crafter::protocols::transport::TCP_FLAG_AE, 0x100);
    assert_eq!(
        crafter::protocols::transport::TCP_FLAG_AE,
        crafter::protocols::transport::TCP_FLAG_NS
    );

    assert_eq!(prelude_option.kind(), TCP_OPTION_MSS);
    assert_eq!(core_option.kind(), crafter::core::TCP_OPTION_WINDOW_SCALE);
    assert_eq!(root_option.kind(), crafter::TCP_OPTION_SACK_PERMITTED);
    assert_eq!(
        protocols_option.kind(),
        crafter::protocols::TCP_OPTION_TIMESTAMP
    );
    assert_eq!(transport_option.kind(), 0xfe);
    assert_eq!(transport_option.encode()?, vec![0xfe, 4, 0xaa, 0xbb]);

    assert_eq!(prelude_sack, TcpSackBlock::new(100, 200));
    assert_eq!(core_sack.left_edge, 300);
    assert_eq!(root_sack.right_edge, 600);
    assert_eq!(protocols_sack.left_edge, 700);
    assert_eq!(transport_sack.right_edge, 1000);

    assert_eq!(prelude_edo.option_len(), crafter::TCP_EDO_REQUEST_LEN);
    assert_eq!(core_edo.option_len(), crafter::TCP_EDO_HEADER_LEN);
    assert_eq!(
        root_edo.option_len(),
        crafter::TCP_EDO_HEADER_AND_SEGMENT_LEN
    );
    assert_eq!(protocols_edo, TcpExtendedDataOffset::Request);
    assert_eq!(transport_edo, TcpExtendedDataOffset::Request);

    assert_eq!(
        prelude_iter.collect::<crafter::Result<Vec<_>>>()?,
        vec![TcpOption::NoOperation, TcpOption::EndOfList]
    );
    assert_eq!(
        core_iter.collect::<crafter::Result<Vec<_>>>()?,
        vec![TcpOption::NoOperation]
    );
    assert_eq!(
        root_iter.collect::<crafter::Result<Vec<_>>>()?,
        vec![TcpOption::NoOperation]
    );
    assert_eq!(
        protocols_iter.collect::<crafter::Result<Vec<_>>>()?,
        vec![TcpOption::NoOperation]
    );
    assert_eq!(
        transport_iter.collect::<crafter::Result<Vec<_>>>()?,
        vec![TcpOption::NoOperation]
    );

    // The Tcp layer accepts the option/flag constants and round-trips them.
    let mss = TcpOption::maximum_segment_size(1460).encode()?;
    let tcp: Tcp = Tcp::new()
        .sport(40000)
        .dport(80)
        .flag(TCP_FLAG_SYN, true)
        .flag(TCP_FLAG_NS, true)
        .option(&mss);
    assert_eq!(tcp.flags_value() & TCP_FLAG_SYN, TCP_FLAG_SYN);
    assert_eq!(tcp.flags_value() & TCP_FLAG_NS, TCP_FLAG_NS);
    assert_eq!(
        tcp.option_iter().collect::<crafter::Result<Vec<_>>>()?,
        vec![TcpOption::maximum_segment_size(1460)]
    );

    Ok(())
}

#[test]
fn tcp_new_option_kind_constants_are_public() {
    // The newer IANA TCP option-kind constants (User Timeout, TCP-AO, MD5,
    // TCP-ENO, Accurate ECN, RFC 6994 experimental ExID kinds) are exported on
    // the same public path the other newer TCP option constants use:
    // crafter::protocols::transport. They name the wire value only.
    use crafter::protocols::transport::{
        TCP_OPTION_ACCURATE_ECN_ORDER_0, TCP_OPTION_ACCURATE_ECN_ORDER_1,
        TCP_OPTION_EXPERIMENTAL_1, TCP_OPTION_EXPERIMENTAL_2, TCP_OPTION_MD5_SIGNATURE,
        TCP_OPTION_TCP_AUTHENTICATION, TCP_OPTION_TCP_ENO, TCP_OPTION_USER_TIMEOUT,
    };

    assert_eq!(TCP_OPTION_MD5_SIGNATURE, 19);
    assert_eq!(TCP_OPTION_USER_TIMEOUT, 28);
    assert_eq!(TCP_OPTION_TCP_AUTHENTICATION, 29);
    assert_eq!(TCP_OPTION_TCP_ENO, 69);
    assert_eq!(TCP_OPTION_ACCURATE_ECN_ORDER_0, 172);
    assert_eq!(TCP_OPTION_ACCURATE_ECN_ORDER_1, 174);
    assert_eq!(TCP_OPTION_EXPERIMENTAL_1, 253);
    assert_eq!(TCP_OPTION_EXPERIMENTAL_2, 254);

    // The option-length minimum/fixed-length constants are reachable too.
    use crafter::protocols::transport::{
        TCP_OPTION_ACCURATE_ECN_MIN_LEN, TCP_OPTION_EXPERIMENTAL_MIN_LEN,
        TCP_OPTION_TCP_AUTHENTICATION_MIN_LEN, TCP_OPTION_TCP_ENO_MIN_LEN,
        TCP_OPTION_USER_TIMEOUT_LEN,
    };
    assert_eq!(TCP_OPTION_USER_TIMEOUT_LEN, 4);
    assert_eq!(TCP_OPTION_TCP_AUTHENTICATION_MIN_LEN, 4);
    assert_eq!(TCP_OPTION_TCP_ENO_MIN_LEN, 2);
    assert_eq!(TCP_OPTION_ACCURATE_ECN_MIN_LEN, 2);
    assert_eq!(TCP_OPTION_EXPERIMENTAL_MIN_LEN, 4);
}

#[test]
fn tcp_option_kind_classification_helpers_are_public() {
    // The TcpOptionKindClass enum and the kind-class helpers reach through
    // prelude, core, root, protocols, and protocols::transport, mirroring the
    // UDP classification coverage.
    let prelude_class: TcpOptionKindClass = TcpOptionKindClass::Assigned;
    let core_class: crafter::core::TcpOptionKindClass =
        crafter::core::TcpOptionKindClass::Experimental;
    let root_class: crafter::TcpOptionKindClass = crafter::TcpOptionKindClass::Unassigned;
    let protocols_class: crafter::protocols::TcpOptionKindClass =
        crafter::protocols::TcpOptionKindClass::Assigned;
    let transport_class: crafter::protocols::transport::TcpOptionKindClass =
        crafter::protocols::transport::TcpOptionKindClass::Experimental;

    assert_eq!(prelude_class, TcpOptionKindClass::Assigned);
    assert_eq!(core_class, crafter::core::TcpOptionKindClass::Experimental);
    assert_eq!(root_class, crafter::TcpOptionKindClass::Unassigned);
    assert_eq!(
        protocols_class,
        crafter::protocols::TcpOptionKindClass::Assigned
    );
    assert_eq!(
        transport_class,
        crafter::protocols::transport::TcpOptionKindClass::Experimental
    );

    // tcp_option_kind_class / _is_assigned / _is_experimental are exported on
    // every path that exports TcpOption.
    assert_eq!(
        tcp_option_kind_class(TCP_OPTION_MSS),
        TcpOptionKindClass::Assigned
    );
    assert_eq!(
        crafter::core::tcp_option_kind_class(crafter::core::TCP_OPTION_NOP),
        crafter::core::TcpOptionKindClass::Assigned
    );
    assert_eq!(
        crafter::tcp_option_kind_class(crafter::protocols::transport::TCP_OPTION_EXPERIMENTAL_1),
        crafter::TcpOptionKindClass::Experimental
    );
    assert_eq!(
        crafter::protocols::tcp_option_kind_class(200),
        crafter::protocols::TcpOptionKindClass::Unassigned
    );
    assert!(crafter::protocols::transport::tcp_option_kind_is_assigned(
        crafter::protocols::transport::TCP_OPTION_USER_TIMEOUT
    ));
    assert!(crafter::tcp_option_kind_is_assigned(TCP_OPTION_MSS));
    assert!(crafter::core::tcp_option_kind_is_experimental(
        crafter::protocols::transport::TCP_OPTION_EXPERIMENTAL_2
    ));
    assert!(!crafter::protocols::tcp_option_kind_is_experimental(
        TCP_OPTION_MSS
    ));

    // tcp_option_kind_name is the display helper; it is exported through
    // crafter::protocols::transport alongside the newer TCP items.
    assert_eq!(
        crafter::protocols::transport::tcp_option_kind_name(
            crafter::protocols::transport::TCP_OPTION_USER_TIMEOUT
        ),
        "UTO"
    );
    assert_eq!(
        crafter::protocols::transport::tcp_option_kind_name(200),
        "opt"
    );
}

#[test]
fn tcp_new_option_variants_are_public() -> crafter::Result<()> {
    // The new typed TcpOption variants (User Timeout, TCP-AO, TCP-ENO, Accurate
    // ECN, RFC 6994 experimental) are constructible and inspectable through the
    // public TcpOption type on every path that exports it. Each is byte-preserving
    // and round-trips through encode/decode.
    let user_timeout: TcpOption = TcpOption::user_timeout(true, 240);
    let authentication = crafter::core::TcpOption::tcp_authentication(1, 2, vec![0xaa, 0xbb, 0xcc]);
    let eno = crafter::TcpOption::tcp_eno(vec![0x01, 0x02]);
    let accurate_ecn = crafter::protocols::TcpOption::accurate_ecn_order_0(vec![0x11, 0x22, 0x33]);
    let accurate_ecn_1 = crafter::protocols::transport::TcpOption::accurate_ecn_order_1(vec![0x44]);
    let experimental =
        crafter::protocols::transport::TcpOption::experimental_1(0x1234, vec![0x55, 0x66]);
    let fast_open = TcpOption::fast_open(vec![0x01, 0x02, 0x03, 0x04]);
    let fast_open_request = TcpOption::fast_open_cookie_request();
    let mptcp = TcpOption::multipath_tcp(
        crafter::protocols::transport::MPTCP_SUBTYPE_MP_CAPABLE,
        vec![0x00, 0x01],
    );

    // Typed accessors read back the values byte-for-byte.
    assert_eq!(user_timeout.user_timeout_value(), Some((true, 240)));
    assert_eq!(
        user_timeout.kind(),
        crafter::protocols::transport::TCP_OPTION_USER_TIMEOUT
    );
    assert_eq!(
        authentication.tcp_authentication_value(),
        Some((1, 2, &[0xaa, 0xbb, 0xcc][..]))
    );
    assert_eq!(authentication.key_id(), Some(1));
    assert_eq!(authentication.rnext_key_id(), Some(2));
    assert_eq!(eno.tcp_eno_suboptions(), Some(&[0x01, 0x02][..]));
    // accurate_ecn_order() returns the AccECN kind byte that encodes the counter
    // order (172 for AccECN0, 174 for AccECN1).
    assert_eq!(
        accurate_ecn.accurate_ecn_order(),
        Some(crafter::protocols::transport::TCP_OPTION_ACCURATE_ECN_ORDER_0)
    );
    assert_eq!(
        accurate_ecn.accurate_ecn_data(),
        Some(&[0x11, 0x22, 0x33][..])
    );
    assert!(accurate_ecn_1.is_accurate_ecn());
    assert_eq!(
        accurate_ecn_1.accurate_ecn_order(),
        Some(crafter::protocols::transport::TCP_OPTION_ACCURATE_ECN_ORDER_1)
    );
    assert_eq!(experimental.experiment_id(), Some(0x1234));
    assert_eq!(experimental.experiment_data(), Some(&[0x55, 0x66][..]));
    assert!(experimental.is_experimental());
    assert_eq!(
        fast_open.fast_open_cookie(),
        Some(&[0x01, 0x02, 0x03, 0x04][..])
    );
    assert!(fast_open_request.is_fast_open_cookie_request());
    assert!(mptcp.is_multipath_tcp());
    assert_eq!(
        mptcp.mptcp_subtype(),
        Some(crafter::protocols::transport::MPTCP_SUBTYPE_MP_CAPABLE)
    );

    // The kind_name display helper is reachable on the option itself.
    assert_eq!(user_timeout.kind_name(), "UTO");
    assert_eq!(eno.kind_name(), "ENO");

    // Each variant round-trips byte-for-byte through encode then decode.
    for option in [
        user_timeout,
        authentication,
        eno,
        accurate_ecn,
        accurate_ecn_1,
        experimental,
        fast_open,
        fast_open_request,
        mptcp,
    ] {
        let encoded = option.encode()?;
        let decoded = TcpOption::decode_all(&encoded)?;
        assert_eq!(decoded, vec![option]);
    }

    Ok(())
}

#[test]
fn tcp_sizing_helpers_are_public() {
    // The TCP segment sizing helpers are exported on the same public path the
    // other newer TCP items use: crafter::protocols::transport. They are pure
    // const helpers for packet builders and model no connection state.
    use crafter::protocols::transport::{
        effective_mss, effective_mss_ipv4, effective_mss_ipv6, has_fin, has_syn, max_tcp_payload,
        option_budget, remaining_option_budget, sequence_space_len, tcp_header_len,
        valid_window_scale,
    };

    // The sizing constants behind the helpers are reachable too.
    use crafter::protocols::transport::{
        IPV4_HEADER_LEN_FOR_MSS, IPV6_HEADER_LEN_FOR_MSS, IPV6_MINIMUM_MTU, TCP_DEFAULT_IPV4_MSS,
        TCP_FIXED_HEADER_LEN, TCP_MAX_OPTION_BYTES, TCP_WINDOW_SCALE_MAX_SHIFT,
    };

    assert_eq!(TCP_FIXED_HEADER_LEN, 20);
    assert_eq!(TCP_MAX_OPTION_BYTES, 40);
    assert_eq!(TCP_DEFAULT_IPV4_MSS, 536);
    assert_eq!(IPV6_MINIMUM_MTU, 1280);
    assert_eq!(IPV4_HEADER_LEN_FOR_MSS, 20);
    assert_eq!(IPV6_HEADER_LEN_FOR_MSS, 40);
    assert_eq!(TCP_WINDOW_SCALE_MAX_SHIFT, 14);

    // Header / option-budget helpers.
    assert_eq!(tcp_header_len(0), 20);
    assert_eq!(tcp_header_len(3), 24); // padded to the 32-bit boundary.
    assert_eq!(option_budget(), 40);
    assert_eq!(remaining_option_budget(12), 28);
    assert_eq!(remaining_option_budget(100), 0); // saturates at zero.

    // max_tcp_payload subtracts the IP and TCP headers from the path MTU.
    assert_eq!(max_tcp_payload(1500, 20, 20), 1460);
    assert_eq!(max_tcp_payload(40, 20, 20), 0); // saturates, never underflows.

    // Effective MSS guidance for both IP versions.
    assert_eq!(effective_mss_ipv4(None), 536);
    assert_eq!(effective_mss_ipv4(Some(1500)), 1460);
    assert_eq!(effective_mss_ipv6(None), 1220);
    assert_eq!(effective_mss(false, Some(1500)), 1460);
    assert_eq!(effective_mss(true, None), 1220);

    // Sequence-space helpers.
    assert!(has_syn(TCP_FLAG_SYN));
    assert!(!has_syn(TCP_FLAG_ACK));
    assert!(has_fin(TCP_FLAG_FIN));
    assert_eq!(sequence_space_len(TCP_FLAG_SYN, 0), 1);
    assert_eq!(sequence_space_len(TCP_FLAG_SYN | TCP_FLAG_FIN, 10), 12);
    assert_eq!(sequence_space_len(TCP_FLAG_ACK, 5), 5);

    // Window-scale validity guidance (RFC 7323 section 2.3).
    assert!(valid_window_scale(0));
    assert!(valid_window_scale(TCP_WINDOW_SCALE_MAX_SHIFT));
    assert!(!valid_window_scale(15));

    // The same helpers are also reachable as methods on the Tcp segment.
    let tcp: Tcp = Tcp::new().flags(TCP_FLAG_SYN | TCP_FLAG_FIN);
    assert!(tcp.has_syn());
    assert!(tcp.has_fin());
    assert_eq!(tcp.sequence_space_len(7), 9);
}

#[test]
fn tcp_mptcp_subtype_constants_are_public() {
    // The MPTCP subtype constants (RFC 8684 section 3 / IANA MPTCP Option
    // Subtypes registry) are reachable through the same public path the other
    // newer TCP option constants use: crafter::protocols::transport.
    use crafter::protocols::transport::{
        MPTCP_SUBTYPE_ADD_ADDR, MPTCP_SUBTYPE_DSS, MPTCP_SUBTYPE_MP_CAPABLE,
        MPTCP_SUBTYPE_MP_EXPERIMENTAL, MPTCP_SUBTYPE_MP_FAIL, MPTCP_SUBTYPE_MP_FASTCLOSE,
        MPTCP_SUBTYPE_MP_JOIN, MPTCP_SUBTYPE_MP_PRIO, MPTCP_SUBTYPE_REMOVE_ADDR,
        MPTCP_SUBTYPE_TCPRST,
    };

    assert_eq!(MPTCP_SUBTYPE_MP_CAPABLE, 0x0);
    assert_eq!(MPTCP_SUBTYPE_MP_JOIN, 0x1);
    assert_eq!(MPTCP_SUBTYPE_DSS, 0x2);
    assert_eq!(MPTCP_SUBTYPE_ADD_ADDR, 0x3);
    assert_eq!(MPTCP_SUBTYPE_REMOVE_ADDR, 0x4);
    assert_eq!(MPTCP_SUBTYPE_MP_PRIO, 0x5);
    assert_eq!(MPTCP_SUBTYPE_MP_FAIL, 0x6);
    assert_eq!(MPTCP_SUBTYPE_MP_FASTCLOSE, 0x7);
    assert_eq!(MPTCP_SUBTYPE_TCPRST, 0x8);
    assert_eq!(MPTCP_SUBTYPE_MP_EXPERIMENTAL, 0xf);

    // The MP_TCPRST Reason Codes registry (RFC 8684 section 3.6) is exported on
    // the same public path for byte inspection of the MP_TCPRST subtype.
    use crafter::protocols::transport::{
        MPTCP_TCPRST_REASON_ADMINISTRATIVELY_PROHIBITED, MPTCP_TCPRST_REASON_LACK_OF_RESOURCES,
        MPTCP_TCPRST_REASON_MIDDLEBOX_INTERFERENCE, MPTCP_TCPRST_REASON_MPTCP_SPECIFIC,
        MPTCP_TCPRST_REASON_TOO_MUCH_OUTSTANDING_DATA,
        MPTCP_TCPRST_REASON_UNACCEPTABLE_PERFORMANCE, MPTCP_TCPRST_REASON_UNSPECIFIED,
    };

    assert_eq!(MPTCP_TCPRST_REASON_UNSPECIFIED, 0x00);
    assert_eq!(MPTCP_TCPRST_REASON_MPTCP_SPECIFIC, 0x01);
    assert_eq!(MPTCP_TCPRST_REASON_LACK_OF_RESOURCES, 0x02);
    assert_eq!(MPTCP_TCPRST_REASON_ADMINISTRATIVELY_PROHIBITED, 0x03);
    assert_eq!(MPTCP_TCPRST_REASON_TOO_MUCH_OUTSTANDING_DATA, 0x04);
    assert_eq!(MPTCP_TCPRST_REASON_UNACCEPTABLE_PERFORMANCE, 0x05);
    assert_eq!(MPTCP_TCPRST_REASON_MIDDLEBOX_INTERFERENCE, 0x06);
}

#[test]
fn tcp_mptcp_tcprst_reason_constants_are_public() {
    // The MP_TCPRST Reason Codes (RFC 8684 section 3.6 / IANA "MPTCP MP_TCPRST
    // Reason Codes" registry) are exposed as inspectable packet data through the
    // same public path the other newer TCP option constants use:
    // crafter::protocols::transport. They name the wire value only; crafter
    // implements no MPTCP connection recovery or subflow policy.
    use crafter::protocols::transport::{
        MPTCP_TCPRST_REASON_ADMINISTRATIVELY_PROHIBITED, MPTCP_TCPRST_REASON_LACK_OF_RESOURCES,
        MPTCP_TCPRST_REASON_MIDDLEBOX_INTERFERENCE, MPTCP_TCPRST_REASON_MPTCP_SPECIFIC,
        MPTCP_TCPRST_REASON_TOO_MUCH_OUTSTANDING_DATA,
        MPTCP_TCPRST_REASON_UNACCEPTABLE_PERFORMANCE, MPTCP_TCPRST_REASON_UNSPECIFIED,
    };

    // RFC 8684 section 3.6 reason code values, 0x00..=0x06.
    assert_eq!(MPTCP_TCPRST_REASON_UNSPECIFIED, 0x00);
    assert_eq!(MPTCP_TCPRST_REASON_MPTCP_SPECIFIC, 0x01);
    assert_eq!(MPTCP_TCPRST_REASON_LACK_OF_RESOURCES, 0x02);
    assert_eq!(MPTCP_TCPRST_REASON_ADMINISTRATIVELY_PROHIBITED, 0x03);
    assert_eq!(MPTCP_TCPRST_REASON_TOO_MUCH_OUTSTANDING_DATA, 0x04);
    assert_eq!(MPTCP_TCPRST_REASON_UNACCEPTABLE_PERFORMANCE, 0x05);
    assert_eq!(MPTCP_TCPRST_REASON_MIDDLEBOX_INTERFERENCE, 0x06);

    // The byte-preserving accessor reads the Reason byte from a generic MP_TCPRST
    // option without acting on it, and ignores non-MP_TCPRST MPTCP options.
    use crafter::protocols::transport::{TcpOption, MPTCP_SUBTYPE_TCPRST};
    let tcprst = TcpOption::multipath_tcp(
        MPTCP_SUBTYPE_TCPRST,
        vec![0x00, MPTCP_TCPRST_REASON_ADMINISTRATIVELY_PROHIBITED],
    );
    assert_eq!(
        tcprst.mptcp_tcprst_reason(),
        Some(MPTCP_TCPRST_REASON_ADMINISTRATIVELY_PROHIBITED)
    );

    let dss =
        TcpOption::multipath_tcp(crafter::protocols::transport::MPTCP_SUBTYPE_DSS, vec![0x00]);
    assert_eq!(dss.mptcp_tcprst_reason(), None);
}

#[test]
fn udp_dhcp_helpers_compile_expected_ports() -> crafter::Result<()> {
    let client = (Udp::dhcp_client() / Raw::from("discover")).compile()?;
    let server = (Udp::dhcp_server() / Raw::from("offer")).compile()?;

    assert_eq!(&client.as_bytes()[0..2], &68u16.to_be_bytes());
    assert_eq!(&client.as_bytes()[2..4], &67u16.to_be_bytes());
    assert_eq!(&server.as_bytes()[0..2], &67u16.to_be_bytes());
    assert_eq!(&server.as_bytes()[2..4], &68u16.to_be_bytes());

    Ok(())
}

#[test]
fn udp_dns_packet_compiles_and_decodes() -> crafter::Result<()> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 53))
        .id(0x1237)
        .ttl(61)
        / Udp::new().sport(53001).dport(DNS_PORT)
        / Dns::new()
            .id(0xbeef)
            .question(DnsQuestion::new("example.com.", DNS_TYPE_A));

    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let udp = decoded.layer::<Udp>().unwrap();
    let dns = decoded.layer::<Dns>().unwrap();

    assert_eq!(udp.source_port_value(), 53001);
    assert_eq!(udp.destination_port_value(), DNS_PORT);
    assert_eq!(dns.id_value(), 0xbeef);
    assert_eq!(dns.questions()[0].name(), "example.com.");
    assert_eq!(dns.questions()[0].question_type(), DNS_TYPE_A);

    Ok(())
}

#[test]
fn udp_raw_payload_packet_compiles_and_decodes() -> crafter::Result<()> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 20))
        .dst(Ipv4Addr::new(198, 51, 100, 30))
        / Udp::new().sport(53002).dport(9999)
        / Raw::from("payload");

    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let udp = decoded.layer::<Udp>().unwrap();
    let raw = decoded.layer::<Raw>().unwrap();

    assert_eq!(udp.source_port_value(), 53002);
    assert_eq!(udp.destination_port_value(), 9999);
    assert_eq!(raw.as_bytes(), b"payload");

    Ok(())
}

#[test]
fn ipv4_public_api_paths_expose_enriched_helpers() -> crafter::Result<()> {
    let dscp = Dscp::new(46)?;
    let ecn = Ecn::Ce;
    let ipv4 = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 44))
        .dst(Ipv4Addr::new(198, 51, 100, 44))
        .dscp(dscp)
        .ecn(ecn)
        .identification(0x1234)
        .reserved_flag(true)
        .dont_fragment(true)
        .more_fragments(true)
        .fragment_offset(7)
        .ipv4_protocol(Ipv4Protocol::Gre);

    assert_eq!(dscp.value(), 46);
    assert_eq!(Dscp::from_ds_field(0xbb), dscp);
    assert_eq!(u8::from(dscp), 46);
    assert_eq!(Ecn::new(3)?, Ecn::Ce);
    assert_eq!(Ecn::from_ds_field(0xbb), ecn);
    assert_eq!(u8::from(ecn), 3);
    assert_eq!(ipv4.ds_field_value(), 0xbb);
    assert_eq!(ipv4.dscp_value(), dscp);
    assert_eq!(ipv4.ecn_value(), ecn);

    let fragment: Ipv4FragmentInfo = ipv4.fragment_info();
    assert_eq!(fragment.identification(), 0x1234);
    assert_eq!(
        fragment.flags(),
        IPV4_FLAG_RESERVED | IPV4_FLAG_DONT_FRAGMENT | IPV4_FLAG_MORE_FRAGMENTS
    );
    assert_eq!(fragment.fragment_offset(), 7);
    assert!(fragment.is_reserved_flag_set());
    assert!(fragment.is_dont_fragment());
    assert!(fragment.has_more_fragments());
    assert!(fragment.is_fragmented());
    assert!(ipv4.is_reserved_flag_set());
    assert!(ipv4.is_dont_fragment());
    assert!(ipv4.has_more_fragments());
    assert!(ipv4.is_fragmented());

    let compiled = (ipv4 / Raw::from("gre")).compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let decoded_ipv4 = decoded.layer::<Ipv4>().unwrap();
    assert_eq!(decoded_ipv4.checksum_status(), Ipv4ChecksumStatus::Valid);
    assert!(decoded_ipv4.summary().contains("proto=gre(47)"));

    let timestamp = Ipv4Option::timestamp(5, 1, [0x0102_0304]);
    let timestamp_with_addresses =
        Ipv4Option::timestamp_with_addresses(5, 2, [(Ipv4Addr::new(192, 0, 2, 1), 0x1112_1314)]);
    let timestamp_prespecified =
        Ipv4Option::timestamp_prespecified(5, 3, [(Ipv4Addr::new(198, 51, 100, 1), 0x2122_2324)]);
    let router_alert = Ipv4Option::router_alert(0xbeef);
    assert_eq!(timestamp.kind(), IPV4_OPTION_TIMESTAMP);
    assert_eq!(timestamp.timestamp_pointer(), Some(5));
    assert_eq!(timestamp.timestamp_overflow(), Some(1));
    assert_eq!(timestamp.timestamp_flag(), Some(0));
    assert_eq!(timestamp.timestamp_values(), Some(&[0x0102_0304][..]));
    assert_eq!(timestamp_with_addresses.timestamp_pointer(), Some(5));
    assert_eq!(timestamp_with_addresses.timestamp_overflow(), Some(2));
    assert_eq!(timestamp_with_addresses.timestamp_flag(), Some(1));
    assert_eq!(
        timestamp_with_addresses.timestamp_address_values(),
        Some(&[(Ipv4Addr::new(192, 0, 2, 1), 0x1112_1314)][..])
    );
    assert_eq!(timestamp_prespecified.timestamp_pointer(), Some(5));
    assert_eq!(timestamp_prespecified.timestamp_overflow(), Some(3));
    assert_eq!(timestamp_prespecified.timestamp_flag(), Some(3));
    assert_eq!(
        timestamp_prespecified.timestamp_address_values(),
        Some(&[(Ipv4Addr::new(198, 51, 100, 1), 0x2122_2324)][..])
    );
    assert_eq!(router_alert.kind(), IPV4_OPTION_ROUTER_ALERT);
    assert_eq!(router_alert.router_alert_value(), Some(0xbeef));

    let mut encoded_options = Vec::new();
    encoded_options.extend(timestamp.encode()?);
    encoded_options.extend(timestamp_with_addresses.encode()?);
    encoded_options.extend(timestamp_prespecified.encode()?);
    encoded_options.extend(router_alert.encode()?);
    let parsed = Ipv4Option::decode_all(&encoded_options)?;
    assert_eq!(
        parsed,
        vec![
            timestamp,
            timestamp_with_addresses,
            timestamp_prespecified,
            router_alert
        ]
    );
    assert_eq!(
        Ipv4OptionIter::new(&encoded_options).collect::<crafter::Result<Vec<_>>>()?,
        parsed
    );

    for (value, copied, class, number, experimental) in [
        (IPV4_OPTION_EOL, false, 0, 0, false),
        (IPV4_OPTION_NOP, false, 0, 1, false),
        (IPV4_OPTION_TIMESTAMP, false, 2, 4, false),
        (IPV4_OPTION_ROUTER_ALERT, true, 0, 20, false),
        (IPV4_OPTION_EXPERIMENTAL_1, false, 0, 30, true),
        (IPV4_OPTION_EXPERIMENTAL_2, false, 2, 30, true),
        (IPV4_OPTION_EXPERIMENTAL_3, true, 0, 30, true),
        (IPV4_OPTION_EXPERIMENTAL_4, true, 2, 30, true),
    ] {
        let kind = Ipv4OptionKind::new(value);
        assert_eq!(kind.value(), value);
        assert_eq!(kind.copied(), copied);
        assert_eq!(kind.class(), class);
        assert_eq!(kind.number(), number);
        assert_eq!(kind.is_experimental(), experimental);
        assert_eq!(u8::from(Ipv4OptionKind::from(value)), value);
        assert_eq!(
            kind.experimental_label(),
            experimental.then_some("RFC3692-style Experiment")
        );
    }

    let root_fragment: crafter::Ipv4FragmentInfo = fragment;
    let core_checksum: crafter::core::Ipv4ChecksumStatus = decoded_ipv4.checksum_status();
    let protocols_kind =
        crafter::protocols::Ipv4OptionKind::new(crafter::protocols::IPV4_OPTION_TIMESTAMP);
    let deep_kind = crafter::protocols::ipv4::Ipv4OptionKind::new(
        crafter::protocols::ipv4::IPV4_OPTION_ROUTER_ALERT,
    );
    let deep_checksum: crafter::protocols::ipv4::Ipv4ChecksumStatus =
        crafter::protocols::ipv4::Ipv4ChecksumStatus::Valid;
    let deep_fragment: crafter::protocols::ipv4::Ipv4FragmentInfo = decoded_ipv4.fragment_info();

    assert_eq!(root_fragment, fragment);
    assert_eq!(core_checksum, Ipv4ChecksumStatus::Valid);
    assert_eq!(protocols_kind.class(), 2);
    assert_eq!(deep_kind.number(), 20);
    assert_eq!(deep_checksum, Ipv4ChecksumStatus::Valid);
    assert_eq!(deep_fragment.flags(), fragment.flags());
    assert_eq!(crafter::IPPROTO_GRE, IPPROTO_GRE);
    assert_eq!(crafter::core::IPPROTO_ESP, IPPROTO_ESP);
    assert_eq!(crafter::protocols::IPPROTO_AH, IPPROTO_AH);
    assert_eq!(crafter::protocols::ipv4::IPPROTO_OSPF, IPPROTO_OSPF);
    assert_eq!(crafter::IPPROTO_SCTP, IPPROTO_SCTP);
    assert_eq!(
        crafter::core::IPPROTO_EXPERIMENTAL_1,
        IPPROTO_EXPERIMENTAL_1
    );
    assert_eq!(
        crafter::protocols::IPPROTO_EXPERIMENTAL_2,
        IPPROTO_EXPERIMENTAL_2
    );
    assert_eq!(u8::from(Ipv4Protocol::Gre), IPPROTO_GRE);
    assert_eq!(u8::from(Ipv4Protocol::Esp), IPPROTO_ESP);
    assert_eq!(u8::from(Ipv4Protocol::Ah), IPPROTO_AH);
    assert_eq!(u8::from(Ipv4Protocol::Ospf), IPPROTO_OSPF);
    assert_eq!(u8::from(Ipv4Protocol::Sctp), IPPROTO_SCTP);
    assert_eq!(
        u8::from(Ipv4Protocol::Experimental1),
        IPPROTO_EXPERIMENTAL_1
    );
    assert_eq!(
        u8::from(Ipv4Protocol::Experimental2),
        IPPROTO_EXPERIMENTAL_2
    );

    Ok(())
}

#[test]
fn wpa_config_builder_public_api() -> crafter::Result<()> {
    let pmk = [0x2a; 32];
    let decryptor = WpaDecrypt::new()
        .network("lab-ssid", "12345678")?
        .network_bytes(b"\xffssid".as_slice(), "abcdefgh")?
        .with_network(WpaNetwork::pmk_bytes(b"pmk-ssid".as_slice(), pmk)?)
        .with_config(
            WpaDecryptConfig::new()
                .pass_originals(false)
                .only_ciphers([WpaCipher::Ccmp128, WpaCipher::Tkip])
                .allow_cipher(WpaCipher::Ccmp128),
        );

    assert!(!decryptor.config().emits_originals());
    assert_eq!(
        decryptor.config().supported_ciphers(),
        &[WpaCipher::Ccmp128, WpaCipher::Tkip]
    );
    assert!(decryptor.config().supports_cipher(WpaCipher::Ccmp128));
    assert_eq!(decryptor.networks().len(), 3);
    assert_eq!(decryptor.networks()[0].ssid(), b"lab-ssid");
    assert_eq!(decryptor.networks()[0].ssid_str(), Some("lab-ssid"));
    assert!(decryptor.networks()[0].uses_passphrase());
    assert_eq!(decryptor.networks()[1].ssid(), b"\xffssid");
    assert_eq!(decryptor.networks()[1].ssid_str(), None);
    assert!(decryptor.networks()[2].uses_pmk());
    assert_eq!(decryptor.networks()[2].pmk_value(), Some(pmk));

    let debug = format!("{decryptor:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("12345678"));
    assert!(!debug.contains("abcdefgh"));

    Ok(())
}

#[test]
fn wpa_decrypt_sniffer_public_api() -> crafter::Result<()> {
    let pcap = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/pcaps/wpa2-psk-ccmp-unicast.pcap");
    let source = PacketWire::pcap_file(pcap.clone())
        .open()
        .expect("WPA fixture pcap should open")
        .source()
        .expect("WPA fixture pcap should expose source capability");
    let decryptor = WpaDecrypt::new()
        .network("libcrafter-wpa", "libcrafter-pass")?
        .network_bytes(b"\xffunused".as_slice(), "abcdefgh")?
        .with_config(
            WpaDecryptConfig::new()
                .pass_originals(false)
                .only_ciphers([WpaCipher::Ccmp128]),
        );
    let records = Sniffer::new(source)
        .with(Dot11Metadata::new())
        .with(decryptor)
        .collect_records()
        .expect("WPA fixture pcap should decrypt");

    let decrypted = records
        .iter()
        .find(|record| record.metadata().origin() == PacketOrigin::Transformed)
        .expect("WPA fixture should emit one transformed decrypted record");

    assert_eq!(decrypted.metadata().backend(), &BackendKind::PcapFile);
    assert_eq!(decrypted.metadata().file(), Some(pcap.as_path()));
    assert_eq!(decrypted.metadata().link_type(), Some(LinkType::Ethernet));
    assert!(decrypted.packet().layer::<Ethernet>().is_some());
    assert!(decrypted.packet().layer::<Ipv4>().is_some());
    assert_eq!(
        decrypted.packet().layer::<Raw>().unwrap().as_bytes(),
        b"libcrafter wpa"
    );

    let wifi = decrypted
        .metadata()
        .wifi()
        .expect("decrypted record should keep Wi-Fi metadata");
    assert_eq!(wifi.ssid(), Some(b"libcrafter-wpa".as_slice()));
    assert_eq!(
        wifi.bssid(),
        Some(MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x20, 0x01]))
    );
    assert_eq!(wifi.key_id(), Some(1));
    assert_eq!(wifi.decrypt_state(), Some(WifiDecryptState::Decrypted));

    let wpa = wifi
        .wpa_metadata()
        .expect("decrypted record should include WPA metadata");
    assert_eq!(wpa.cipher(), Some(WpaCipher::Ccmp128));
    assert_eq!(wpa.akm(), Some(WpaAkm::Psk));
    assert_eq!(wpa.key_kind(), Some(WpaKeyKind::Pairwise));
    assert_eq!(wpa.packet_number(), Some(0x33));
    assert_eq!(wpa.decrypt_reason(), Some(WpaDecryptReason::Decrypted));
    assert_eq!(wpa.credential_status(), Some(WpaCredentialStatus::Matched));
    assert_eq!(wpa.credentials_matched(), Some(true));
    assert_eq!(
        wpa.handshake_status(),
        Some(WpaHandshakeStatus::MicVerified)
    );

    Ok(())
}

#[test]
fn wpa_config_builder_rejects_invalid_public_passphrase() {
    let err = WpaDecrypt::new().network("lab-ssid", "short").unwrap_err();

    match err {
        crafter::CrafterError::InvalidFieldValue { field, reason } => {
            assert_eq!(field, "wpa.passphrase");
            assert_eq!(reason, "must be 8 to 63 octets");
        }
        other => panic!("invalid WPA passphrase should be structured, got {other:?}"),
    }
}
