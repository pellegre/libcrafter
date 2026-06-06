//! IPv4 summary and inspection formatting helpers.

use crate::protocols::ip::shared::{Dscp, Ecn};

use super::fragment::flags_summary;
use super::header::{Ipv4, Ipv4ChecksumStatus};
use super::options::option_count_summary;
use super::protocol::protocol_summary;

pub(super) fn summary(ipv4: &Ipv4) -> String {
    let mut fields = vec![
        format!("src={}", ipv4.source()),
        format!("dst={}", ipv4.destination()),
        format!("proto={}", protocol_summary(ipv4.protocol_value())),
    ];

    if ipv4.ds_field_value() != 0 {
        fields.push(format!(
            "ds={}",
            ds_field_summary(ipv4.dscp_value(), ipv4.ecn_value())
        ));
    }
    if ipv4.flags_value() != 0 {
        fields.push(format!("flags={}", flags_summary(ipv4.flags_value())));
    }
    if ipv4.fragment_offset_value() != 0 {
        fields.push(format!("fragment_offset={}", ipv4.fragment_offset_value()));
    }
    let checksum_status = checksum_status_summary(ipv4.checksum_status());
    if !checksum_status.is_empty() {
        fields.push(format!("checksum_status={checksum_status}"));
    }
    if !ipv4.option_bytes().is_empty() {
        fields.push(format!(
            "options={}",
            option_count_summary(ipv4.option_bytes())
        ));
    }

    format!("Ipv4({})", fields.join(", "))
}

pub(super) fn inspection_fields(ipv4: &Ipv4) -> Vec<(&'static str, String)> {
    vec![
        ("version", ipv4.version_value().to_string()),
        ("ihl", ipv4.ihl_value().to_string()),
        ("tos", ipv4.tos_value().to_string()),
        ("dscp", dscp_summary(ipv4.dscp_value())),
        ("ecn", ecn_summary(ipv4.ecn_value()).to_string()),
        (
            "total_length",
            ipv4.total_length_value()
                .map(|value| value.to_string())
                .unwrap_or_else(|| "auto".to_string()),
        ),
        ("id", format!("0x{:04x}", ipv4.identification_value())),
        ("flags", flags_summary(ipv4.flags_value())),
        ("fragment_offset", ipv4.fragment_offset_value().to_string()),
        ("ttl", ipv4.ttl_value().to_string()),
        ("protocol", protocol_summary(ipv4.protocol_value())),
        (
            "checksum",
            ipv4.checksum_value()
                .map(|value| format!("0x{value:04x}"))
                .unwrap_or_else(|| "auto".to_string()),
        ),
        (
            "checksum_status",
            checksum_status_inspection(ipv4.checksum_status()).to_string(),
        ),
        ("src", ipv4.source().to_string()),
        ("dst", ipv4.destination().to_string()),
        ("option_count", option_count_summary(ipv4.option_bytes())),
        ("options", hex_bytes(ipv4.option_bytes())),
    ]
}

fn checksum_status_summary(status: Ipv4ChecksumStatus) -> &'static str {
    match status {
        Ipv4ChecksumStatus::Invalid => "invalid",
        Ipv4ChecksumStatus::NotChecked | Ipv4ChecksumStatus::Valid => "",
    }
}

fn checksum_status_inspection(status: Ipv4ChecksumStatus) -> &'static str {
    match status {
        Ipv4ChecksumStatus::NotChecked => "not_checked",
        Ipv4ChecksumStatus::Valid => "valid",
        Ipv4ChecksumStatus::Invalid => "invalid",
    }
}

fn ds_field_summary(dscp: Dscp, ecn: Ecn) -> String {
    format!("dscp={}/ecn={}", dscp.value(), ecn_summary(ecn))
}

fn dscp_summary(dscp: Dscp) -> String {
    dscp.value().to_string()
}

fn ecn_summary(ecn: Ecn) -> &'static str {
    match ecn {
        Ecn::NotEct => "Not-ECT",
        Ecn::Ect1 => "ECT(1)",
        Ecn::Ect0 => "ECT(0)",
        Ecn::Ce => "CE",
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::new();

    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            output.push(' ');
        }
        output.push_str(&format!("{byte:02x}"));
    }

    output
}
