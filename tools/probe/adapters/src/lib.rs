//! libcrafter probe stimulus endpoint.
//!
//! The `stimulus_endpoint` binary builds outgoing probe packets with
//! libcrafter, optionally sends them and captures the peer response, decodes
//! that response through libcrafter, and validates the observed behavior
//! against the probe plan's contract.
//!
//! The implementation is split into a shared [`common`] module (request/plan
//! contracts, dry-run/live dispatch, response and artifact helpers) and one
//! module per protocol family: [`icmp`], [`tcp`], [`dns`], [`udp`], [`dhcp`],
//! and [`arp`]. The binary is a thin wrapper that calls [`common::run`].

// The `plan_json` builder serializes the full probe-plan contract through a
// single `json!` literal; the field count pushes the macro past serde_json's
// default recursion limit, so raise it for the crate.
#![recursion_limit = "512"]

pub mod arp;
pub mod common;
pub mod dhcp;
pub mod dns;
pub mod icmp;
pub mod tcp;
pub mod udp;

#[cfg(test)]
pub(crate) mod test_support {
    use crate::common::ProbePlan;

    /// Build a `ProbePlan` with every optional field unset for a given case.
    ///
    /// Case-module unit tests start from this and set only the fields the case
    /// under test consumes, which keeps the "required field missing" error
    /// tests honest.
    pub fn base_plan(case: &str) -> ProbePlan {
        ProbePlan {
            case: case.to_string(),
            sequence: 0,
            expected_response: None,
            identifier: None,
            sequence_number: None,
            payload_hex: None,
            source_ipv4: None,
            destination_ipv4: None,
            expected_reply_source_ipv4: None,
            expected_reply_destination_ipv4: None,
            source_port: None,
            destination_port: None,
            tcp_sequence_number: None,
            expected_acknowledgment_number: None,
            window: None,
            query_id: None,
            query_name: None,
            query_type: None,
            query_type_value: None,
            query_class_value: None,
            expected_answer_name: None,
            expected_answer_type: None,
            expected_answer_type_value: None,
            expected_answer_data: None,
            expected_txt_strings: None,
            expected_mx_preference: None,
            expected_mx_exchange: None,
            expected_srv_priority: None,
            expected_srv_weight: None,
            expected_srv_port: None,
            expected_srv_target: None,
            expected_answer_count: None,
            original_name: None,
            absent_name: None,
            present_name: None,
            present_type: None,
            present_type_value: None,
            canonical_name: None,
            terminal_ipv4: None,
            expected_cname_answer: None,
            edns_udp_payload_size: None,
            edns_version: None,
            edns_do: None,
            edns_request_options: None,
            expected_edns_udp_payload_size: None,
            expected_edns_version: None,
            expected_edns_extended_rcode: None,
            expected_edns_do: None,
            expected_edns_options: None,
            expected_response_code: None,
            answer_ttl: None,
            ttl: None,
            expected_icmp_type: None,
            expected_icmp_code: None,
            expected_embedded_prefix_hex: None,
            expected_embedded_prefix_length: None,
            send_count: None,
            sends: None,
            client_mac: None,
            transaction_id: None,
            requested_ipv4: None,
            server_identifier: None,
            client_ciaddr: None,
            client_identifier_hex: None,
            expected_client_identifier_hex: None,
            hostname: None,
            expected_hostname: None,
            parameter_request_list: None,
            expected_message_type_value: None,
            expected_yiaddr: None,
            expected_yiaddr_zero: None,
            expected_no_lease_time: None,
            expected_server_identifier: None,
            expected_message: None,
            expected_subnet_mask: None,
            expected_router_ipv4: None,
            expected_dns_ipv4: None,
            expected_lease_time: None,
            expected_renewal_time: None,
            expected_rebinding_time: None,
            dhcp_sends: None,
            ethertype: None,
            hardware_type: None,
            protocol_type: None,
            operation: None,
            sender_hardware_addr: None,
            sender_protocol_addr: None,
            target_hardware_addr: None,
            target_protocol_addr: None,
            ethernet_source: None,
            ethernet_destination: None,
            validation: None,
        }
    }
}
