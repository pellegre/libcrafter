//! Provider-neutral libcrafter execution smoke protocol.

use std::fs;
use std::io::{self, Read};
use std::net::Ipv4Addr;
use std::process::ExitCode;

use crafter::prelude::{Ipv4, Ipv4Protocol, NetworkLayer, Packet, Raw, Udp};
use serde::{Deserialize, Serialize};

const SCHEMA_VERSION: u8 = 1;
const PROTOCOL: &str = "crafter-smoke-v1";
const MAX_INPUT_BYTES: u64 = 4 * 1024;
const MAX_PAYLOAD_BYTES: usize = 256;
const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const DESTINATION: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);
const SOURCE_PORT: u16 = 42_000;
const DESTINATION_PORT: u16 = 53_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema_version: u8,
    protocol: String,
    payload: String,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct Checks {
    ipv4: bool,
    udp: bool,
    payload: bool,
    strict_roundtrip: bool,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct Response {
    schema_version: u8,
    protocol: &'static str,
    result: &'static str,
    input_bytes: usize,
    compiled_bytes: usize,
    summary: String,
    checks: Checks,
}

#[derive(Serialize)]
struct ErrorResponse<'a> {
    schema_version: u8,
    protocol: &'static str,
    result: &'static str,
    error: &'a str,
}

fn main() -> ExitCode {
    match run() {
        Ok(response) => match write_response(&response) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => fail(&error),
        },
        Err(error) => fail(&error),
    }
}

fn run() -> Result<Response, String> {
    let mut input = String::new();
    io::stdin()
        .take(MAX_INPUT_BYTES + 1)
        .read_to_string(&mut input)
        .map_err(|error| format!("could not read request: {error}"))?;
    if input.len() as u64 > MAX_INPUT_BYTES {
        return Err(format!("request exceeds {MAX_INPUT_BYTES} bytes"));
    }
    let request: Request = serde_json::from_str(&input)
        .map_err(|error| format!("request is not valid JSON: {error}"))?;
    execute(request)
}

fn execute(request: Request) -> Result<Response, String> {
    if request.schema_version != SCHEMA_VERSION {
        return Err("unsupported schema_version".into());
    }
    if request.protocol != PROTOCOL {
        return Err("unsupported smoke protocol".into());
    }
    if request.payload.len() > MAX_PAYLOAD_BYTES {
        return Err(format!("payload exceeds {MAX_PAYLOAD_BYTES} bytes"));
    }

    let packet = Ipv4::new()
        .src(SOURCE)
        .dst(DESTINATION)
        .id(0x5a5a)
        .ttl(64)
        .ipv4_protocol(Ipv4Protocol::Udp)
        / Udp::new().sport(SOURCE_PORT).dport(DESTINATION_PORT)
        / Raw::from(request.payload.as_str());
    let compiled = packet
        .compile()
        .map_err(|error| format!("packet compile failed: {error}"))?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())
        .map_err(|error| format!("packet decode failed: {error}"))?;
    let recompiled = decoded
        .compile()
        .map_err(|error| format!("decoded packet compile failed: {error}"))?;

    let checks = Checks {
        ipv4: decoded.layer::<Ipv4>().is_some(),
        udp: decoded.layer::<Udp>().is_some(),
        payload: decoded
            .layer::<Raw>()
            .is_some_and(|raw| raw.as_bytes() == request.payload.as_bytes()),
        strict_roundtrip: compiled.as_bytes() == recompiled.as_bytes(),
    };
    if !checks.ipv4 || !checks.udp || !checks.payload || !checks.strict_roundtrip {
        return Err("packet roundtrip checks did not all pass".into());
    }

    Ok(Response {
        schema_version: SCHEMA_VERSION,
        protocol: PROTOCOL,
        result: "passed",
        input_bytes: request.payload.len(),
        compiled_bytes: compiled.len(),
        summary: decoded.summary(),
        checks,
    })
}

fn write_response(response: &Response) -> Result<(), String> {
    let encoded = serde_json::to_string(response)
        .map_err(|error| format!("could not encode response: {error}"))?;
    fs::write("result.json", format!("{encoded}\n"))
        .map_err(|error| format!("could not write result.json: {error}"))?;
    println!("{encoded}");
    Ok(())
}

fn fail(error: &str) -> ExitCode {
    let response = ErrorResponse {
        schema_version: SCHEMA_VERSION,
        protocol: PROTOCOL,
        result: "failed",
        error,
    };
    match serde_json::to_string(&response) {
        Ok(encoded) => eprintln!("{encoded}"),
        Err(_) => eprintln!("crafter smoke failed"),
    }
    ExitCode::from(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(payload: &str) -> Request {
        Request {
            schema_version: SCHEMA_VERSION,
            protocol: PROTOCOL.into(),
            payload: payload.into(),
        }
    }

    #[test]
    fn smoke_contract_roundtrips_typed_packet_bytes() {
        let response = execute(request("provider-neutral smoke")).unwrap();
        assert_eq!(response.result, "passed");
        assert_eq!(response.input_bytes, 22);
        assert_eq!(response.compiled_bytes, 20 + 8 + 22);
        assert_eq!(
            response.checks,
            Checks {
                ipv4: true,
                udp: true,
                payload: true,
                strict_roundtrip: true,
            }
        );
        assert!(response.summary.contains("Ipv4"));
        assert!(response.summary.contains("Udp"));
    }

    #[test]
    fn smoke_contract_rejects_unknown_versions_and_protocols() {
        let mut wrong_version = request("smoke");
        wrong_version.schema_version = 2;
        assert_eq!(
            execute(wrong_version).unwrap_err(),
            "unsupported schema_version"
        );

        let mut wrong_protocol = request("smoke");
        wrong_protocol.protocol = "different".into();
        assert_eq!(
            execute(wrong_protocol).unwrap_err(),
            "unsupported smoke protocol"
        );
    }

    #[test]
    fn smoke_contract_enforces_the_payload_bound_in_bytes() {
        let payload = "é".repeat(129);
        assert_eq!(payload.len(), 258);
        assert_eq!(
            execute(request(&payload)).unwrap_err(),
            "payload exceeds 256 bytes"
        );
    }
}
