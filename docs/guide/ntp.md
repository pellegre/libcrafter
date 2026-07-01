# NTP Wire Coverage

`crafter` treats Network Time Protocol as UDP packet bytes, not as a clock
synchronization service. The `Ntp` layer can build, compile, decode, summarize,
and inspect NTPv4 and NTPv3/SNTP-shaped payloads inside the normal `Packet`
abstraction.

## Coverage At A Glance

| Area | State | Notes |
| --- | --- | --- |
| Fixed header | Supported | LI, version, mode, stratum, poll, precision, root delay, root dispersion, reference ID, and the four timestamps. |
| Codepoints | Supported | Source-backed labels for LI, mode, stratum, reference IDs, Kiss-o'-Death codes, and extension field types. |
| Extension fields | Supported as raw-preserving envelopes | Unknown and NTS extension bodies are preserved; cryptographic verification is out of scope. |
| Legacy MAC | Supported as raw tail bytes | Key ID and digest bytes are inspectable and round-trip. |
| UDP dispatch | Supported | UDP/123 payloads decode as NTP only when the conservative shape gate accepts them; unrelated payloads remain `Raw`. |
| Live behavior | Out of crate scope | Use offline construction, fixtures, dry-run plans, oracle/probe dry-runs, or provider-backed labs. |

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
open live sockets.

## Live Boundary

NTP live validation must be provider-backed and explicitly confirmed. Automated
tests and examples do not send live NTP traffic. A live oracle or probe run must
have all of the following:

- provider selection such as Hetzner, QEMU, or VirtualBox;
- provider credentials where required, for example `HETZNER_API_TOKEN` or
  `HCLOUD_TOKEN`;
- an explicit live flag such as `--confirm-live-run`;
- NTP-specific confirmation such as `LIBCRAFTER_NTP_LIVE_CONFIRM=yes`;
- disposable endpoint/lab teardown and artifact collection.

Without those preconditions, NTP validation remains offline or dry-run only.
