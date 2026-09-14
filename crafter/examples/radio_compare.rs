//! Offline original-frame comparison. See docs/radio.md for the required policy.
#[path = "radio_support/artifact.rs"]
mod artifact;
#[path = "radio_support/compare.rs"]
mod compare;
#[path = "radio_support/ht_compare.rs"]
mod ht_compare;
#[path = "radio_support/transmit_compare.rs"]
mod transmit_compare;
#[path = "radio_support/vht_compare.rs"]
mod vht_compare;
fn main() -> artifact::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--compare-transmit") {
        if args.len() != 4 {
            return Err(
                "usage: radio_compare --compare-transmit PLAN.jsonl CAPTURE.pcap REPORT.json"
                    .into(),
            );
        }
        let report = transmit_compare::compare(&args[1], &args[2])?;
        artifact::write_json(&mut std::fs::File::create(&args[3])?, &report)?;
        artifact::write_json(&mut std::io::stdout(), &report)?;
        if report["status"] != "passed" {
            return Err("transmit comparison requirements failed".into());
        }
        return Ok(());
    }
    if args.first().map(String::as_str) == Some("--verify-transmit-qualification") {
        if args.len() != 2 {
            return Err(
                "usage: radio_compare --verify-transmit-qualification QUALIFICATION.json".into(),
            );
        }
        return artifact::write_json(
            &mut std::io::stdout(),
            &transmit_compare::verify_qualification(&args[1])?,
        );
    }
    if args.len() != 3 {
        return Err("usage: radio_compare RECEIVE.jsonl REFERENCE.pcap POLICY.json".into());
    }
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut hashes = Vec::new();
    for path in &args {
        let mut f = std::fs::File::open(path)?;
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let n = f.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            digest.update(&buffer[..n]);
        }
        hashes.push(artifact::hex(&digest.finalize()));
    }
    let policy: compare::Policy = serde_json::from_reader(std::fs::File::open(&args[2])?)?;
    policy.validate()?;
    let (a, ac, mut e) = compare::load_recovered(&args[0], &policy)?;
    let (b, bc) = compare::load_reference(&args[1], &policy)?;
    e["input_sha256"] =
        serde_json::json!({"receive":hashes[0],"reference":hashes[1],"policy":hashes[2]});
    e["reference_capture_loss"] = serde_json::json!("not_available_in_pcap");
    for (path, expected) in args.iter().zip(&hashes) {
        let mut f = std::fs::File::open(path)?;
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let n = f.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            digest.update(&buffer[..n]);
        }
        if artifact::hex(&digest.finalize()) != *expected {
            return Err("comparison input changed during processing".into());
        }
    }
    artifact::write_json(
        &mut std::io::stdout(),
        &compare::report(a, ac, b, bc, policy, e),
    )
}
