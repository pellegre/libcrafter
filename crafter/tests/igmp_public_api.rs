//! Public-surface baseline test for the IGMP layer.
//!
//! Pins that the bootstrap IGMP type, constants, and registry metadata are
//! reachable through `crafter::prelude::*` and stay inside the standard packet
//! abstraction. The test is fully offline and uses documentation address space.

use std::net::Ipv4Addr;

use crafter::prelude::*;

const DOC_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const DOC_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 1);

#[test]
fn igmp_public_api_builds_via_prelude() -> crafter::Result<()> {
    let igmp = Igmp::membership_query()
        .with_max_response_code(10)
        .with_group_address(DOC_GROUP);

    assert_eq!(igmp.igmp_type(), IgmpType::MembershipQuery);
    assert_eq!(igmp.type_meta().status, IgmpTypeStatus::Assigned);
    assert_eq!(igmp.code_meta().status, IgmpTypeStatus::Assigned);
    assert_eq!(
        igmp_type(IGMP_TYPE_MEMBERSHIP_QUERY),
        IgmpType::MembershipQuery
    );
    assert_eq!(
        igmp_type_name(IGMP_TYPE_V2_MEMBERSHIP_REPORT),
        Some("IGMPv2 Membership Report")
    );
    assert_eq!(
        igmp_code_name(IGMP_TYPE_MEMBERSHIP_QUERY, IGMP_QUERY_CODE_V1),
        Some("IGMP Version 1")
    );
    assert_eq!(
        igmp_type_status(IGMP_TYPE_RESERVED),
        IgmpTypeStatus::Reserved
    );
    let _: IgmpTypeMeta = igmp_type_meta(IGMP_TYPE_MEMBERSHIP_QUERY);
    let _: IgmpCodeMeta = igmp_code_meta(IGMP_TYPE_MEMBERSHIP_QUERY, IGMP_QUERY_CODE_V1);

    let packet = Ipv4::new()
        .src(DOC_SRC)
        .dst(DOC_GROUP)
        .ipv4_protocol(Ipv4Protocol::Igmp)
        / igmp;
    let compiled = packet.compile()?;

    assert_eq!(IGMP_HEADER_LEN, IGMP_FIXED_HEADER_LEN);
    assert_eq!(compiled.as_bytes()[9], IPPROTO_IGMP);
    assert_eq!(compiled.as_bytes()[20], IGMP_TYPE_MEMBERSHIP_QUERY);
    assert_eq!(compiled.as_bytes()[21], 10);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let decoded_igmp = decoded.layer::<Igmp>().expect("decoded IGMP layer");
    assert_eq!(decoded_igmp.igmp_type(), IgmpType::MembershipQuery);
    assert_eq!(decoded_igmp.max_response_code_value(), 10);
    assert_eq!(decoded_igmp.group_address_value(), DOC_GROUP);

    Ok(())
}
