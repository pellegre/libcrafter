# NTP Wire Coverage

`crafter` treats Network Time Protocol as UDP packet bytes. It is not a clock,
not a time synchronization service, not an NTP daemon, and not an NTS key
exchange or authentication stack. The `Ntp` layer builds, compiles, decodes,
summarizes, and inspects NTPv4 and NTPv3/SNTP-shaped payloads inside the normal
`Packet` abstraction.

## Coverage At A Glance

| Area | State | Notes |
| --- | --- | --- |
| Fixed header | Supported | LI, version, mode, stratum, poll, precision, root delay, root dispersion, reference ID, and the four timestamps. |
| Timestamps | Supported as raw packet fields | The 64-bit timestamp fields preserve seconds and fractional halves; era and wall-clock interpretation stay with the caller. |
| Codepoints | Supported | Source-backed labels for LI, mode, stratum, reference IDs, Kiss-o'-Death codes, and extension field types. |
| Extension fields | Supported as raw-preserving envelopes | Unknown and NTS extension bodies are preserved; cryptographic verification is out of scope. |
| Legacy MAC | Supported as raw tail bytes | Key ID and digest bytes are inspectable and round-trip. |
| UDP dispatch | Supported | UDP/123 payloads decode as NTP only when the conservative shape gate accepts them; unrelated payloads remain `Raw`. |
| Fixtures and pcaps | Supported | Golden headers, malformed tails, summary/show output, Raw IPv4 pcaps, and Ethernet pcaps are checked in and validated offline. |
| Live behavior | Out of crate scope | Use offline construction, fixtures, dry-run plans, oracle/probe dry-runs, or provider-backed labs. |

## Fixed Header And Timestamps

The fixed NTP header is 48 octets. `crafter` exposes the first-octet fields as
typed values (`NtpLeapIndicator`, `NtpVersion`, and `NtpMode`) and keeps the
remaining scalar fields available through builder and accessor methods.

`root_delay` and `root_dispersion` use the NTP 16.16 short format through
`NtpShortFormat`. The reference, origin, receive, and transmit timestamps use
`NtpTimestamp`, which preserves the raw 64-bit wire value and exposes seconds
and fractional halves for inspection. All-zero timestamps remain valid packet
data; the crate does not infer whether a peer's clock is synchronized.

## Public API

NTP is exported through `crafter::prelude::*`:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> crafter::Result<()> {
    let packet = ntp_ipv4_client_request(
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(198, 51, 100, 20),
    );

    let bytes = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;

    println!("{}", decoded.summary());
    println!("{}", decoded.show());
    Ok(())
}
```

`compile()` fills UDP length/checksum and IP protocol fields when unset. The
NTP layer fills documentation-safe client defaults while preserving explicit
caller overrides, including unusual version, mode, stratum, timestamp,
extension, and MAC values.

## Extension Fields, NTS Bytes, And MAC Tails

NTP extension fields are modeled as raw-preserving packet envelopes. The public
helpers label known field types and keep unknown field types round-trippable:

```rust
use crafter::prelude::*;

let ntp = Ntp::client()
    .transmit_timestamp(NtpTimestamp::from_parts(0xecc0_0000, 0x1234_5678))
    .extension_field(NtpExtensionField::nts_unique_identifier([0x01, 0x02]))
    .extension_field(NtpExtensionField::nts_cookie([0xaa, 0xbb, 0xcc]))
    .extension_field(NtpExtensionField::unknown(0x2222, [0xde, 0xad]))
    .legacy_mac(NtpLegacyMac::from_key_id_and_digest(0x0102_0304, [0x55; 16]));

let bytes = Packet::from_layer(ntp).compile()?;
let decoded = Ntp::decode(bytes.as_bytes())?;

assert_eq!(decoded.extension_fields_value().len(), 3);
assert_eq!(decoded.legacy_mac_value().unwrap().digest().len(), 16);
# Ok::<(), crafter::CrafterError>(())
```

NTS support is deliberately packet-level. `NtpNtsUniqueIdentifierExtension`,
`NtpNtsCookieExtension`, `NtpNtsCookiePlaceholderExtension`, and
`NtpNtsAuthenticatorExtension` preserve NTS packet extension bytes and expose
typed views where the envelope shape is recognizable. They do not derive keys,
decrypt cookies, verify authenticators, maintain replay state, or decide
whether a packet is acceptable for a time source.

Legacy MAC tails are also preserved as packet bytes. The layer keeps the key ID
and digest material available through accessors and omits those secret-bearing
values from compact summaries. Four-octet crypto-NAK-shaped tails and common
20- or 24-octet legacy MAC tails round-trip without requiring cryptographic
validation.

## Decode And Raw Fallback

Direct parsing with `Ntp::decode` returns structured errors for truncated fixed
headers and malformed extension lengths. Registry dispatch is intentionally more
conservative: UDP/123 payloads that are too short or do not look like NTP stay
as `Raw`.

```rust
use crafter::prelude::*;

let ntp = Ntp::client()
    .transmit_timestamp(NtpTimestamp::from_parts(0xecc0_0000, 0x1234_5678))
    .extension_field(NtpExtensionField::nts_cookie([1, 2, 3]))
    .legacy_mac(NtpLegacyMac::from_key_id_and_digest(0x0102_0304, [0xaa; 16]));

let bytes = Packet::from_layer(ntp).compile()?;
let decoded = Ntp::decode(bytes.as_bytes())?;
assert_eq!(Packet::from_layer(decoded).compile()?.as_bytes(), bytes.as_bytes());
# Ok::<(), crafter::CrafterError>(())
```

## Fixtures And Offline Validation

The offline test corpus covers NTP without opening sockets:

- fixed-header golden vectors for NTPv4 client/server shapes and NTPv3/SNTP
  compatibility;
- decode vectors for IPv4/UDP and IPv6/UDP stacks;
- malformed fixtures for short headers, short extension headers, invalid
  extension lengths, truncated MAC tails, and ambiguous legacy MAC tails;
- NTS extension round trips and raw body preservation;
- summary and `show()` golden fixtures that keep MAC key and digest bytes out
  of compact inspection output;
- Raw IPv4 and Ethernet pcap fixtures that decode through the normal pcap
  fixture suite.

Useful focused checks:

```sh
cargo test -p crafter ntp_golden
cargo test -p crafter --test ntp_malformed
cargo test -p crafter fixture_suite_ntp
```

## Examples

Run the offline decode example:

```sh
cargo run -p crafter --example ntp_decode
```

Inspect dry-run IPv4 and IPv6 request plans:

```sh
cargo run -p crafter --example ntp_request_plan
```

Both examples use documentation addresses or deterministic bytes. They do not
open live sockets. Request planning uses `send_dry_run` with a fake interface
such as `dry-run0`, so the output is an inspectable send plan rather than live
traffic.

## Live Boundary

NTP live validation must be provider-backed and explicitly confirmed. Automated
tests and examples do not send live NTP traffic. A live oracle or probe run must
have all of the following:

- provider selection for a disposable endpoint or lab;
- an explicit live flag such as `--confirm-live-run`;
- NTP-specific confirmation such as `LIBCRAFTER_NTP_LIVE_CONFIRM=yes`;
- disposable endpoint/lab teardown and artifact collection.

Without those preconditions, NTP validation remains offline or dry-run only.
