//! SCTP behavioral probe cases.
//!
//! SCTP probe cases are intentionally planned-only at this stage. The Python
//! planner records packet-layer intent, controlled-peer requirements, capture
//! filters, and validation metadata; this adapter makes the Rust stimulus
//! endpoint understand those cases in dry-run mode without sending traffic.

use serde_json::{json, Value};

use crate::common::{
    observed_response, plan_json, ExampleResult, ProbeOutcome, ProbePlan, StimulusEndpointRequest,
};

pub fn is_sctp_case(case: &str) -> bool {
    matches!(
        case,
        "sctp-native-data-exchange"
            | "sctp-init-handshake-plan"
            | "sctp-udp-encap-data-exchange"
            | "sctp-abort-error-observation"
    )
}

pub fn run_sctp_dry_run(
    _request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let metadata = json!({
        "dry_run": true,
        "probe_plan": plan_json(plan),
        "planned_only": true,
        "packet": plan.packet,
        "validation": validation_json(plan),
        "capture_filter": capture_filter(plan),
        "peer_contract": peer_contract_json(plan),
        "stimulus_driver": plan.stimulus_driver,
    });
    let observed = observed_response(
        plan,
        false,
        None,
        json!({}),
        json!({
            "planned_only": true,
            "packet": plan.packet,
            "validation": validation_json(plan),
            "capture_filter": capture_filter(plan),
            "peer_contract": peer_contract_json(plan),
            "stimulus_driver": plan.stimulus_driver,
        }),
    );
    let result = json!({
        "case": plan.case,
        "sequence": plan.sequence,
        "status": "planned",
        "endpoint_role": "stimulus",
        "passed": null,
        "observed_response": observed,
        "metadata": metadata,
    });
    Ok(ProbeOutcome {
        result,
        observed_response: observed,
        sent: false,
        received: false,
    })
}

pub fn capture_filter(plan: &ProbePlan) -> String {
    if let Some(filter) = plan
        .capture_filter
        .as_deref()
        .filter(|filter| !filter.is_empty())
    {
        return filter.to_string();
    }
    if plan.case == "sctp-udp-encap-data-exchange" {
        return format!(
            "udp and src host {} and dst host {} and src port 9899 and dst port 9899",
            plan.expected_reply_source_ipv4.as_deref().unwrap_or(""),
            plan.expected_reply_destination_ipv4
                .as_deref()
                .unwrap_or(""),
        );
    }
    format!(
        "sctp and src host {} and dst host {} and src port {} and dst port {}",
        plan.expected_reply_source_ipv4.as_deref().unwrap_or(""),
        plan.expected_reply_destination_ipv4
            .as_deref()
            .unwrap_or(""),
        plan.destination_port.unwrap_or(0),
        plan.source_port.unwrap_or(0),
    )
}

pub fn peer_contract_json(plan: &ProbePlan) -> Value {
    plan.peer_contract.clone().unwrap_or_else(|| {
        json!({
            "required": true,
            "kind": "sctp-controlled-peer",
            "protocol": plan.protocol.as_deref().unwrap_or("sctp"),
            "port": plan.destination_port,
            "planned_only": plan.planned_only.unwrap_or(true),
            "requires_controlled_peer": true,
        })
    })
}

pub fn validation_json(plan: &ProbePlan) -> Value {
    if let Some(validation) = plan
        .sctp
        .as_ref()
        .and_then(|sctp| sctp.get("validation"))
        .cloned()
    {
        return validation;
    }
    json!({
        "planned_only": true,
        "driver": "sctp_probe",
        "expected_decode": "sctp",
        "source_ipv4": plan.expected_reply_source_ipv4,
        "destination_ipv4": plan.expected_reply_destination_ipv4,
        "source_port": plan.destination_port,
        "destination_port": plan.source_port,
    })
}
