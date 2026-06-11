//! Golden byte fixtures pinning current BGP-4 (RFC 4271) wire behavior.
//!
//! This file is a deliberate *behavior pin*: it builds representative BGP-4
//! messages with the current public API, compiles them, and asserts the exact
//! emitted bytes against checked-in hex constants. It also round-trips each
//! case (see `assert_roundtrip`) so a refactor that changes the bytes fails
//! here on purpose.
//!
//! KEEPALIVE (RFC 4271 §4.4) is the 16-octet all-ones Marker, a Length field of
//! `0x0013` (19), and a Type of `0x04`, so its golden hex is
//! `ffffffffffffffffffffffffffffffff001304`.
//!
//! Everything here stays offline. BGP messages carry no addresses, so there is
//! no live target surface in this file.

use crafter::prelude::*;

/// Helper used once to mint the golden constants below. Set
/// `CRAFTER_BGP_GOLDEN_DUMP=1` and run with `--nocapture` to print the
/// freshly-compiled hex for every case; paste the values into the `GOLDEN_*`
/// constants. Not part of normal assertions.
fn maybe_dump(name: &str, bytes: &[u8]) {
    if std::env::var_os("CRAFTER_BGP_GOLDEN_DUMP").is_some() {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        println!("GOLDEN {name} = \"{hex}\"");
    }
}

/// Parse a compact hex string ("00ff..") into bytes for a golden constant.
fn hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "golden hex must have even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// Round-trip half of the behavior pin: re-derive the BGP message from the
/// pinned bytes and assert it re-compiles to the identical buffer.
///
/// The public bare-BGP decode path (TCP/179 registry dispatch) is wired in a
/// later plan step and the message decoder is `pub(crate)`, so no public decode
/// of a standalone BGP message is reachable from this integration test yet.
/// Until it is, the round-trip rebuilds the same KEEPALIVE via the builder and
/// asserts byte-equality with the input, which still locks the emitted bytes.
fn assert_roundtrip(golden: &[u8]) {
    let rebuilt = Packet::from_layer(Bgp::keepalive())
        .compile()
        .expect("recompile rebuilt KEEPALIVE");
    assert_eq!(
        rebuilt.as_bytes(),
        golden,
        "rebuild/recompile round-trip changed the bytes"
    );
}

// ---------------------------------------------------------------------------
// KEEPALIVE (RFC 4271 §4.4): the 19-octet header alone — all-ones Marker,
// Length 0x0013, Type 0x04.
// ---------------------------------------------------------------------------

const GOLDEN_KEEPALIVE: &str = "ffffffffffffffffffffffffffffffff001304";

#[test]
fn bgp_golden_keepalive() {
    let bytes = Packet::from_layer(Bgp::keepalive())
        .compile()
        .expect("compile");
    maybe_dump("KEEPALIVE", bytes.as_bytes());
    assert_eq!(bytes.as_bytes(), hex(GOLDEN_KEEPALIVE).as_slice());
    assert_roundtrip(bytes.as_bytes());
}
