//! Golden byte fixtures pinning current IPv4 RIP (RFC 1058 / RFC 2453) wire
//! behavior.
//!
//! This file is a deliberate *behavior pin*: it builds representative RIP
//! messages with the current public API, compiles the `Rip` payload, and
//! asserts the exact emitted bytes against checked-in hex constants derived from
//! the RFC layout. It also round-trips each case (decode the pinned bytes and
//! compare field values via the public accessors) so a refactor that changes the
//! bytes fails here on purpose.
//!
//! The IPv4 RIP message is the 4-octet header (command, version, 2-octet
//! reserved; RFC 1058 §3.1 / RFC 2453 §4) followed by zero or more fixed
//! 20-octet route table entries (address family, route tag, IPv4 address, subnet
//! mask, next hop, metric; RFC 2453 §4). RIPv2 authentication rides in a leading
//! AFI-0xFFFF entry (RFC 2453 §4.1 / RFC 4822 §3).
//!
//! Everything here stays offline and uses documentation address space
//! (`192.0.2.0/24`, `198.51.100.0/24`), so there is no live target surface.

use std::net::Ipv4Addr;

use crafter::prelude::*;
use crafter::protocols::rip::{decode, RipAuth, RipDigestAlgorithm, RipEntry};

/// Helper used once to mint the golden constants below. Set
/// `CRAFTER_RIP_GOLDEN_DUMP=1` and run with `--nocapture` to print the
/// freshly-compiled hex for every case; paste the values into the `GOLDEN_*`
/// constants. Not part of normal assertions.
fn maybe_dump(name: &str, bytes: &[u8]) {
    if std::env::var_os("CRAFTER_RIP_GOLDEN_DUMP").is_some() {
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

/// Compile the RIP payload of a built `Rip` layer to its exact wire bytes.
fn rip_bytes(rip: Rip) -> Vec<u8> {
    Packet::from_layer(rip)
        .compile()
        .expect("compile RIP layer")
        .as_bytes()
        .to_vec()
}

// ---------------------------------------------------------------------------
// RIPv1 whole-table request (RFC 1058 §3.4.1).
//
// A RIPv1 Request asking for the full routing table carries the 4-octet header
// — command 0x01 (Request), version 0x01, reserved 0x0000 — followed by a
// single special entry: address family 0, all address/tag/mask/next-hop octets
// zero, and metric 16 (infinity), the whole-table sentinel.
//
//   header : 01 01 0000
//   entry  : 0000 0000 00000000 00000000 00000000 00000010
// ---------------------------------------------------------------------------

const GOLDEN_V1_REQUEST: &str = "010100000000000000000000000000000000000000000010";

fn build_v1_request() -> Rip {
    Rip::request()
        .version(RIP_VERSION_1)
        .entry(RipEntry::whole_table_request())
}

#[test]
fn rip_golden_v1_whole_table_request() {
    let bytes = rip_bytes(build_v1_request());
    maybe_dump("V1_REQUEST", &bytes);
    assert_eq!(bytes, hex(GOLDEN_V1_REQUEST));

    let decoded = decode(&bytes).expect("decode RIPv1 request golden");
    assert_eq!(decoded.command(), RipCommand::Request);
    assert_eq!(decoded.version_value(), RIP_VERSION_1);
    assert_eq!(decoded.reserved_value(), 0);
    assert_eq!(decoded.entries().len(), 1);
    let entry = &decoded.entries()[0];
    assert_eq!(entry.address_family_value(), 0);
    assert_eq!(entry.address_value(), Ipv4Addr::UNSPECIFIED);
    assert_eq!(entry.metric_value(), RIP_METRIC_INFINITY);
    assert!(entry.is_whole_table_request());
}

// ---------------------------------------------------------------------------
// RIPv2 response with one route (RFC 2453 §4): route tag, subnet mask, and next
// hop all set.
//
//   header : 02 02 0000                       command Response, version 2
//   entry  : 0002                             address family IP (2)
//            00ea                             route tag 234
//            c0000200                         address 192.0.2.0
//            ffffff00                         subnet mask 255.255.255.0
//            c6336401                         next hop 198.51.100.1
//            00000003                         metric 3
// ---------------------------------------------------------------------------

const GOLDEN_V2_RESPONSE: &str = "02020000000200eac0000200ffffff00c633640100000003";

fn build_v2_response() -> Rip {
    Rip::response().version(RIP_VERSION_2).entry(
        RipEntry::ipv2_route(
            Ipv4Addr::new(192, 0, 2, 0),
            Ipv4Addr::new(255, 255, 255, 0),
            3,
        )
        .with_route_tag(234)
        .with_next_hop(Ipv4Addr::new(198, 51, 100, 1)),
    )
}

#[test]
fn rip_golden_v2_response_route() {
    let bytes = rip_bytes(build_v2_response());
    maybe_dump("V2_RESPONSE", &bytes);
    assert_eq!(bytes, hex(GOLDEN_V2_RESPONSE));

    let decoded = decode(&bytes).expect("decode RIPv2 response golden");
    assert_eq!(decoded.command(), RipCommand::Response);
    assert_eq!(decoded.version_value(), RIP_VERSION_2);
    assert_eq!(decoded.entries().len(), 1);
    let entry = &decoded.entries()[0];
    assert_eq!(entry.address_family_value(), RIP_AFI_IP);
    assert_eq!(entry.route_tag_value(), 234);
    assert_eq!(entry.address_value(), Ipv4Addr::new(192, 0, 2, 0));
    assert_eq!(entry.subnet_mask_value(), Ipv4Addr::new(255, 255, 255, 0));
    assert_eq!(entry.next_hop_value(), Ipv4Addr::new(198, 51, 100, 1));
    assert_eq!(entry.metric_value(), 3);
}

// ---------------------------------------------------------------------------
// RIPv2 simple-password authenticated response (RFC 2453 §4.1).
//
// The leading entry carries the authentication marker AFI 0xFFFF, the
// authentication type 0x0002 (simple password), and the 16-octet plaintext
// password right-padded with zeros. A normal route entry follows.
//
//   header     : 02 02 0000
//   auth entry : ffff                          AFI 0xFFFF (auth marker)
//                0002                          auth type 2 (simple password)
//                "ripsecret\0\0\0\0\0\0\0"     16 octets, zero-padded
//   route      : 0002 0000 c0000200 ffffff00 00000000 00000001
//
// The test-only password "ripsecret" is 9 octets ("ripsecret" =
// 72 69 70 73 65 63 72 65 74), padded with seven zero octets to 16.
// ---------------------------------------------------------------------------

const RIP_TEST_PASSWORD: &[u8] = b"ripsecret";

const GOLDEN_V2_SIMPLE_AUTH: &str = concat!(
    "02020000",                                 // header: Response, v2, reserved 0
    "ffff0002",                                 // auth entry: AFI 0xFFFF, type 2
    "72697073656372657400000000000000",         // "ripsecret" + 7 zero octets
    "00020000c0000200ffffff000000000000000001", // route 192.0.2.0/24 m1
);

fn build_v2_simple_auth() -> Rip {
    Rip::response()
        .version(RIP_VERSION_2)
        .auth(
            RipAuth::simple_password(RIP_TEST_PASSWORD),
            RIP_TEST_PASSWORD,
        )
        .entry(RipEntry::ipv2_route(
            Ipv4Addr::new(192, 0, 2, 0),
            Ipv4Addr::new(255, 255, 255, 0),
            1,
        ))
}

#[test]
fn rip_golden_v2_simple_password_auth() {
    let bytes = rip_bytes(build_v2_simple_auth());
    maybe_dump("V2_SIMPLE_AUTH", &bytes);
    assert_eq!(bytes, hex(GOLDEN_V2_SIMPLE_AUTH));

    // The decode-side verifier accepts the correct key and rejects a wrong one.
    assert_eq!(
        crafter::protocols::rip::verify(&bytes, RIP_TEST_PASSWORD),
        crafter::protocols::rip::RipAuthVerification::SimplePasswordOk
    );
    assert_eq!(
        crafter::protocols::rip::verify(&bytes, b"wrongkey"),
        crafter::protocols::rip::RipAuthVerification::SimplePasswordMismatch
    );

    let decoded = decode(&bytes).expect("decode RIPv2 simple-auth golden");
    assert_eq!(decoded.command(), RipCommand::Response);
    // The leading auth entry plus the one route entry are both present.
    assert_eq!(decoded.entries().len(), 2);
    assert!(decoded.entries()[0].is_auth_marker());
    let route = &decoded.entries()[1];
    assert_eq!(route.address_value(), Ipv4Addr::new(192, 0, 2, 0));
    assert_eq!(route.metric_value(), 1);
}

// ---------------------------------------------------------------------------
// RIPv2 Keyed-MD5 authenticated response (RFC 2082): the digest is auto-filled
// by compile() from the pinned key and sequence number.
//
// The leading entry is the keyed-digest header (AFI 0xFFFF, type 3, offset,
// key id, auth-data-length 16, sequence number, two reserved words); a route
// entry follows; the trailing block carries the 16-octet MD5 digest after the
// AFI 0xFFFF / trailer 0x0001 introduction.
//
// The expected 16-octet digest is pinned: it is the value compile() emits for
// this exact (message, key) pair. It was minted once via CRAFTER_RIP_GOLDEN_DUMP
// and is locked here so a change in the RFC 2082 construction fails the test.
// ---------------------------------------------------------------------------

const RIP_MD5_KEY: &[u8] = b"md5-test-key";
const RIP_MD5_KEY_ID: u8 = 7;
const RIP_MD5_SEQUENCE: u32 = 42;

// Pinned 16-octet Keyed-MD5 digest for the message built by
// `build_v2_md5_auth` under key `RIP_MD5_KEY`. Minted once; see comment above.
const GOLDEN_MD5_DIGEST: &str = "fe12d33d73e9648b451c4992cf15a226";

// Full keyed-MD5 message bytes, including the auto-filled trailing digest:
//   header     : 02020000
//   md5 header : ffff0003 00000710 0000002a 00000000 00000000
//                AFI 0xFFFF, type 3, offset 0, key id 0x07, auth-data-len 0x10
//                (16), sequence 0x2a (42), two reserved words
//   route      : 00020000 c0000200 ffffff00 00000000 00000001
//   trailer    : ffff0001 <16-octet MD5 digest>
const GOLDEN_V2_MD5_AUTH: &str = concat!(
    "02020000",
    "ffff0003000007100000002a0000000000000000",
    "00020000c0000200ffffff000000000000000001",
    "ffff0001",
    "fe12d33d73e9648b451c4992cf15a226",
);

fn build_v2_md5_auth() -> Rip {
    let mut auth = RipAuth::keyed_digest_with(RipDigestAlgorithm::KeyedMd5, RIP_MD5_KEY_ID);
    if let crafter::protocols::rip::RipAuthPayload::KeyedDigest(header) = &mut auth.payload {
        header.sequence.set_user(RIP_MD5_SEQUENCE);
    }
    Rip::response()
        .version(RIP_VERSION_2)
        .auth(auth, RIP_MD5_KEY)
        .entry(RipEntry::ipv2_route(
            Ipv4Addr::new(192, 0, 2, 0),
            Ipv4Addr::new(255, 255, 255, 0),
            1,
        ))
}

#[test]
fn rip_golden_v2_keyed_md5_auth() {
    let bytes = rip_bytes(build_v2_md5_auth());
    maybe_dump("V2_MD5_AUTH", &bytes);

    // The whole compiled message — including the auto-filled trailing digest —
    // is byte-exact against the pinned golden vector.
    assert_eq!(bytes, hex(GOLDEN_V2_MD5_AUTH));

    // The trailing 16-octet digest sits at the tail after the AFI 0xFFFF /
    // trailer 0x0001 introduction. Pin it against the minted golden digest.
    let digest = &bytes[bytes.len() - 16..];
    let digest_hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    if std::env::var_os("CRAFTER_RIP_GOLDEN_DUMP").is_some() {
        println!("GOLDEN MD5_DIGEST = \"{digest_hex}\"");
    }
    assert_eq!(
        digest_hex, GOLDEN_MD5_DIGEST,
        "auto-filled MD5 digest changed"
    );

    // The decode-side verifier accepts the auto-filled digest for the right key
    // and rejects a wrong key (RFC 2082 §3.2.1).
    assert_eq!(
        crafter::protocols::rip::verify(&bytes, RIP_MD5_KEY),
        crafter::protocols::rip::RipAuthVerification::DigestOk
    );
    assert_eq!(
        crafter::protocols::rip::verify(&bytes, b"not-the-key"),
        crafter::protocols::rip::RipAuthVerification::DigestMismatch
    );
}
