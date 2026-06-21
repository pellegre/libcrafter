//! IGMP probe stimulus packet helpers.
//!
//! These helpers materialize IPv4/IGMP packets for probe plans. They only build
//! packet plans through libcrafter's packet abstraction; sending and capture
//! remain owned by the probe runner's dry-run/live dispatch.

use crafter::prelude::*;
use std::net::Ipv4Addr;

use crate::common::{required_str, ExampleResult, ProbePlan};

/// Probe default for link-local IGMP control traffic.
pub const IGMP_PROBE_DEFAULT_TTL: u8 = 1;
/// Deterministic Max Response Time for simple v2 Membership Query probes.
pub const IGMP_PROBE_QUERY_MAX_RESPONSE_TENTHS: u8 = 10;
/// Deterministic Max Response Code for simple v3 Membership Query probes.
pub const IGMP_PROBE_V3_QUERY_MAX_RESPONSE_CODE: u8 = 100;
/// RFC 9776 all-IGMPv3-routers destination used by v3 reports.
pub const IGMPV3_REPORT_DESTINATION: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 22);

/// Build an IGMP stimulus packet for known IGMP probe case names.
///
/// The current shared probe-plan schema carries the IPv4 envelope fields but no
/// IGMP-specific source-list or record-list fields. Richer probe cases can call
/// the explicit helpers below until the planner grows dedicated IGMP fields.
pub fn igmp_packet(plan: &ProbePlan) -> ExampleResult<Packet> {
    match plan.case.as_str() {
        "igmp-query" | "igmp-membership-query" | "igmp-v2-membership-query" => {
            igmp_query_packet(plan)
        }
        "igmp-v3-query" | "igmp-v3-query-general" | "igmp-v3-membership-query" => {
            igmp_v3_general_query_packet(plan)
        }
        "igmp-report" | "igmp-membership-report" | "igmp-v2-membership-report" => {
            igmp_report_packet(plan)
        }
        "igmp-v3-report" | "igmp-v3-report-empty" | "igmp-v3-membership-report" => {
            igmp_v3_report_packet(plan)
        }
        "igmp-leave" | "igmp-leave-group" | "igmp-v2-leave-group" => igmp_leave_packet(plan),
        other => Err(format!("unsupported IGMP probe case {other}").into()),
    }
}

/// Build a simple IGMPv2 Membership Query packet from a probe plan.
pub fn igmp_query_packet(plan: &ProbePlan) -> ExampleResult<Packet> {
    let (source, destination, ttl) = plan_ipv4_fields(plan)?;
    Ok(igmp_membership_query(
        source,
        destination,
        ttl,
        IGMP_PROBE_QUERY_MAX_RESPONSE_TENTHS,
    ))
}

/// Build a simple IGMPv3 General Query packet from a probe plan.
pub fn igmp_v3_general_query_packet(plan: &ProbePlan) -> ExampleResult<Packet> {
    let (source, destination, ttl) = plan_ipv4_fields(plan)?;
    Ok(igmp_v3_general_query(
        source,
        destination,
        ttl,
        IGMP_PROBE_V3_QUERY_MAX_RESPONSE_CODE,
    ))
}

/// Build an IGMPv2 Membership Report packet from a probe plan.
///
/// Until the probe schema has a separate IGMP group field, the IPv4 destination
/// is also used as the fixed-header Group Address. That matches direct
/// group-destination report probes while preserving explicit envelope control.
pub fn igmp_report_packet(plan: &ProbePlan) -> ExampleResult<Packet> {
    let (source, destination, ttl) = plan_ipv4_fields(plan)?;
    Ok(igmp_v2_membership_report(
        source,
        destination,
        ttl,
        destination,
    ))
}

/// Build an empty IGMPv3 Membership Report packet from a probe plan.
pub fn igmp_v3_report_packet(plan: &ProbePlan) -> ExampleResult<Packet> {
    let (source, destination, ttl) = plan_ipv4_fields(plan)?;
    Ok(igmp_v3_membership_report(source, destination, ttl))
}

/// Build an IGMPv2 Leave Group packet from a probe plan.
///
/// Until the probe schema has a separate IGMP group field, the IPv4 destination
/// is also used as the fixed-header Group Address. Future cases that target the
/// all-routers destination can use [`igmp_v2_leave_group`] directly.
pub fn igmp_leave_packet(plan: &ProbePlan) -> ExampleResult<Packet> {
    let (source, destination, ttl) = plan_ipv4_fields(plan)?;
    Ok(igmp_v2_leave_group(source, destination, ttl, destination))
}

/// Build an IPv4/IGMPv2 Membership Query with an explicit envelope.
pub fn igmp_membership_query(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    ttl: u8,
    max_response_time_tenths: u8,
) -> Packet {
    igmp_ipv4(source, destination, ttl)
        / Igmp::membership_query().with_v2_max_response_time_tenths(max_response_time_tenths)
}

/// Build an IPv4/IGMPv3 General Query with an explicit envelope.
pub fn igmp_v3_general_query(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    ttl: u8,
    max_response_code: u8,
) -> Packet {
    igmp_ipv4(source, destination, ttl)
        / Igmp::membership_query()
            .with_max_response_code(max_response_code)
            .with_group_address(Ipv4Addr::UNSPECIFIED)
        / IgmpQuery::general()
}

/// Build an IPv4/IGMPv3 Group-Specific Query with an explicit envelope.
pub fn igmp_v3_group_specific_query(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    ttl: u8,
    max_response_code: u8,
    group_address: Ipv4Addr,
) -> Packet {
    igmp_ipv4(source, destination, ttl)
        / Igmp::membership_query()
            .with_max_response_code(max_response_code)
            .with_group_address(group_address)
        / IgmpQuery::group_specific()
}

/// Build an IPv4/IGMPv2 Membership Report with an explicit envelope and group.
pub fn igmp_v2_membership_report(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    ttl: u8,
    group_address: Ipv4Addr,
) -> Packet {
    igmp_ipv4(source, destination, ttl) / Igmp::v2_membership_report(group_address)
}

/// Build an IPv4/IGMPv3 Membership Report with no group records.
pub fn igmp_v3_membership_report(source: Ipv4Addr, destination: Ipv4Addr, ttl: u8) -> Packet {
    igmp_ipv4(source, destination, ttl) / Igmp::v3_membership_report() / IgmpReport::new()
}

/// Build an IPv4/IGMPv3 Membership Report with one MODE_IS_INCLUDE record.
pub fn igmp_v3_include_report(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    ttl: u8,
    group_address: Ipv4Addr,
    source_addresses: impl Into<Vec<Ipv4Addr>>,
) -> Packet {
    let record =
        IgmpGroupRecord::mode_is_include(group_address).with_source_addresses(source_addresses);
    igmp_ipv4(source, destination, ttl)
        / Igmp::v3_membership_report()
        / IgmpReport::from_group_records(vec![record])
}

/// Build an IPv4/IGMPv2 Leave Group with an explicit envelope and group.
pub fn igmp_v2_leave_group(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    ttl: u8,
    group_address: Ipv4Addr,
) -> Packet {
    igmp_ipv4(source, destination, ttl) / Igmp::v2_leave_group(group_address)
}

fn igmp_ipv4(source: Ipv4Addr, destination: Ipv4Addr, ttl: u8) -> Ipv4 {
    Ipv4::new()
        .src(source)
        .dst(destination)
        .ttl(ttl)
        .ipv4_protocol(Ipv4Protocol::Igmp)
}

fn plan_ipv4_fields(plan: &ProbePlan) -> ExampleResult<(Ipv4Addr, Ipv4Addr, u8)> {
    let source = parse_ipv4_field(plan.source_ipv4.as_deref(), "source_ipv4")?;
    let destination = parse_ipv4_field(plan.destination_ipv4.as_deref(), "destination_ipv4")?;
    Ok((
        source,
        destination,
        plan.ttl.unwrap_or(IGMP_PROBE_DEFAULT_TTL),
    ))
}

fn parse_ipv4_field(value: Option<&str>, field: &str) -> ExampleResult<Ipv4Addr> {
    Ok(required_str(value, field)?.parse()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::base_plan;

    fn igmp_plan(case: &str) -> ProbePlan {
        let mut plan = base_plan(case);
        plan.source_ipv4 = Some("192.0.2.10".to_string());
        plan.destination_ipv4 = Some("233.252.0.42".to_string());
        plan
    }

    #[test]
    fn igmp_query_packet_requires_source_ipv4() {
        let mut plan = igmp_plan("igmp-query");
        plan.source_ipv4 = None;

        let err = igmp_query_packet(&plan).unwrap_err().to_string();

        assert!(err.contains("source_ipv4"), "got: {err}");
    }

    #[test]
    fn igmp_query_packet_builds_v2_membership_query() {
        let plan = igmp_plan("igmp-query");
        let packet = igmp_query_packet(&plan).unwrap();
        let bytes = packet.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();

        let ipv4 = decoded.layer::<Ipv4>().expect("ipv4 layer present");
        assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 10));
        assert_eq!(ipv4.destination(), Ipv4Addr::new(233, 252, 0, 42));
        assert_eq!(ipv4.ttl_value(), IGMP_PROBE_DEFAULT_TTL);
        assert_eq!(ipv4.protocol_value(), IPPROTO_IGMP);

        let igmp = decoded.layer::<Igmp>().expect("igmp layer present");
        assert_eq!(igmp.igmp_type(), IgmpType::MembershipQuery);
        assert_eq!(
            igmp.v2_max_response_time_tenths(),
            IGMP_PROBE_QUERY_MAX_RESPONSE_TENTHS
        );
        assert_eq!(igmp.group_address_value(), Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn igmp_v3_general_query_packet_adds_typed_query_body() {
        let mut plan = igmp_plan("igmp-v3-query-general");
        plan.ttl = Some(7);
        let packet = igmp_v3_general_query_packet(&plan).unwrap();
        let bytes = packet.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();

        let ipv4 = decoded.layer::<Ipv4>().expect("ipv4 layer present");
        assert_eq!(ipv4.ttl_value(), 7);
        assert_eq!(ipv4.protocol_value(), IPPROTO_IGMP);

        let igmp = decoded.layer::<Igmp>().expect("igmp layer present");
        assert_eq!(igmp.igmp_type(), IgmpType::MembershipQuery);
        assert_eq!(
            igmp.max_response_code_value(),
            IGMP_PROBE_V3_QUERY_MAX_RESPONSE_CODE
        );
        assert_eq!(igmp.group_address_value(), Ipv4Addr::UNSPECIFIED);

        let query = decoded
            .layer::<IgmpQuery>()
            .expect("igmp query body present");
        assert_eq!(query.number_of_sources_value(), 0);
    }

    #[test]
    fn igmp_report_packet_builds_v2_membership_report() {
        let plan = igmp_plan("igmp-report");
        let packet = igmp_report_packet(&plan).unwrap();
        let bytes = packet.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();

        let igmp = decoded.layer::<Igmp>().expect("igmp layer present");
        assert_eq!(igmp.igmp_type(), IgmpType::V2MembershipReport);
        assert_eq!(igmp.group_address_value(), Ipv4Addr::new(233, 252, 0, 42));
    }

    #[test]
    fn igmp_v3_include_report_builds_recorded_report() {
        let packet = igmp_v3_include_report(
            Ipv4Addr::new(192, 0, 2, 10),
            IGMPV3_REPORT_DESTINATION,
            IGMP_PROBE_DEFAULT_TTL,
            Ipv4Addr::new(233, 252, 0, 60),
            vec![Ipv4Addr::new(192, 0, 2, 77)],
        );
        let bytes = packet.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();

        let ipv4 = decoded.layer::<Ipv4>().expect("ipv4 layer present");
        assert_eq!(ipv4.destination(), IGMPV3_REPORT_DESTINATION);

        let report = decoded.layer::<IgmpReport>().expect("igmp report present");
        assert_eq!(report.number_of_group_records_value(), 1);
        assert_eq!(
            report.group_records()[0].record_type(),
            IgmpRecordType::ModeIsInclude
        );
        assert_eq!(
            report.group_records()[0].multicast_address(),
            Ipv4Addr::new(233, 252, 0, 60)
        );
        assert_eq!(
            report.group_records()[0].source_addresses(),
            &[Ipv4Addr::new(192, 0, 2, 77)]
        );
    }

    #[test]
    fn igmp_leave_packet_builds_v2_leave_group() {
        let plan = igmp_plan("igmp-leave");
        let packet = igmp_leave_packet(&plan).unwrap();
        let bytes = packet.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();

        let igmp = decoded.layer::<Igmp>().expect("igmp layer present");
        assert_eq!(igmp.igmp_type(), IgmpType::V2LeaveGroup);
        assert_eq!(igmp.group_address_value(), Ipv4Addr::new(233, 252, 0, 42));
    }

    #[test]
    fn igmp_packet_dispatches_known_cases_and_rejects_unknown() {
        for case in [
            "igmp-v2-membership-query",
            "igmp-v3-query-general",
            "igmp-v2-membership-report",
            "igmp-v3-report-empty",
            "igmp-v2-leave-group",
        ] {
            let plan = igmp_plan(case);
            igmp_packet(&plan).unwrap();
        }

        let plan = igmp_plan("igmp-unsupported");
        let err = igmp_packet(&plan).unwrap_err().to_string();
        assert!(err.contains("unsupported IGMP probe case"), "got: {err}");
    }
}
