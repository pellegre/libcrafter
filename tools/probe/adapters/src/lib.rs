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
#![recursion_limit = "256"]

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
            expected_answer_count: None,
            original_name: None,
            absent_name: None,
            present_name: None,
            present_type: None,
            present_type_value: None,
            canonical_name: None,
            terminal_ipv4: None,
            expected_cname_answer: None,
            expected_response_code: None,
            answer_ttl: None,
            ttl: None,
            expected_icmp_type: None,
            expected_icmp_code: None,
            expected_embedded_prefix_hex: None,
            expected_embedded_prefix_length: None,
        }
    }
}
