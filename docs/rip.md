# RIP Wire Coverage

This page describes the Routing Information Protocol support in the `crafter`
crate: what the `Rip` layer builds and decodes for RIPv1/RIPv2 over UDP port
520, what the `Ripng` layer builds and decodes for RIPng over UDP port 521, how
RIPv2 authentication is constructed and verified, and how RIP rides the default
decode registry.

`crafter` treats each RIP or RIPng message as a packet layer. It builds,
compiles, decodes, summarizes, and shows like the other protocol layers. It is
not a distance-vector engine, a route table, a split-horizon implementation, or
a timer state machine. Convergence behavior belongs in a generated tool or in
the bundled examples; the crate surface is the wire primitive.

## Coverage At A Glance

| Area | State | Notes |
| --- | --- | --- |
| RIPv1 header and entries | Supported | 4-octet header (command, version, reserved) and fixed 20-octet route entries; reserved and version auto-fill unless explicitly set. |
| RIPv2 per-entry fields | Supported | Route tag, subnet mask, and next hop on each 20-octet entry. |
| Request sentinel | Supported | The whole-table request entry (AFI 0, metric 16). |
| 224.0.0.9 multicast response | Supported | Convenience builder for the RIPv2 multicast response group. |
| RIPv2 authentication | Supported | Simple password (RFC 2453) and keyed message digest — Keyed-MD5 (RFC 2082) and HMAC-SHA (RFC 4822); the digest auto-fills on `compile()` and a decode-side verification helper checks it. |
| Demand/triggered RIP | Supported | RFC 2091 Update-Request/Response/Acknowledge commands and the demand sequence number. |
| RIPng | Supported | RFC 2080 4-octet header and 20-octet route table entries (IPv6 prefix, route tag, prefix length, metric), the next-hop RTE (metric `0xFF`), and the whole-table request sentinel over `ff02::9`. |
| Registry dispatch | Supported | UDP/520 payloads decode as `Rip`; UDP/521 payloads decode as `Ripng`. Unrelated traffic on those ports falls through to `Raw`. |

## Public API

The core RIP and RIPng types are exported through `crafter::prelude::*`:

- `Rip` builds the IPv4 RIP message layer (versions 1 and 2).
- `RipEntry` builds a 20-octet route entry.
- `RipCommand` and `RipAddressFamily` carry the command and address-family
  codepoints, preserving unknown values as `Other(..)`.
- `Ripng` builds the IPv6 RIPng message layer and `RipngRte` builds a route
  table entry.
- Constants such as `RIP_UDP_PORT`, `RIP_V2_MULTICAST`, `RIP_METRIC_INFINITY`,
  `RIPNG_UDP_PORT`, `RIPNG_MULTICAST`, and `RIPNG_METRIC_INFINITY`.

The convenience builder functions, the authentication types, and the decode
entry points live in the `crafter::protocols::rip` module (and
`crafter::protocols::rip::ripng` for RIPng) rather than the prelude:

- `rip_v1_whole_table_request`, `rip_v2_whole_table_request`, and
  `rip_v2_multicast_response` build complete IPv4 RIP packets.
- `ripng_whole_table_request` builds a complete RIPng packet.
- `RipAuth`, `RipDigestAlgorithm`, `RipAuthVerification`, and
  `RipKeyedDigestHeader` build and inspect RIPv2 authentication.
- `crafter::protocols::rip::decode` and `crafter::protocols::rip::ripng::decode`
  parse a UDP payload directly; `Packet::decode_from_l3` dispatches through the
  registry.

Use the same packet shape as the rest of the crate: build a layer, wrap it in a
`Packet`, call `compile()`, and inspect `summary()` or `show()`.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> crafter::Result<()> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 1))
        .dst(Ipv4Addr::new(224, 0, 0, 9))
        / Udp::new().sport(520).dport(520)
        / Rip::response().with_entries([
            RipEntry::ipv2_route(
                Ipv4Addr::new(198, 51, 100, 0),
                Ipv4Addr::new(255, 255, 255, 0),
                1,
            ),
        ]);

    let bytes = packet.compile()?;
    println!("{}", packet.summary());
    println!("{}", bytes.hexdump());
    Ok(())
}
```

All examples use documentation address space (`192.0.2.0/24`,
`198.51.100.0/24`, `2001:db8::/32`). Send to real routers only in an explicitly
authorized lab session.

## RIPv1 And RIPv2 Construction

`Rip::request()` and `Rip::response()` create RIPv2 messages (set `.version(1)`
for RIPv1). Attach route entries with `.entry(...)` or `.with_entries(...)`.
`compile()` fills the reserved octets, version, and entry address families
unless the caller set them; any caller-set value — including one that is wrong
on purpose — survives untouched.

`RipEntry::ipv1_route(address, metric)` builds the RFC 1058 classful entry, and
`RipEntry::ipv2_route(address, mask, metric)` adds the RFC 2453 subnet mask. The
RIPv2 per-entry fields are set with chainable builders:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let entry = RipEntry::ipv2_route(
    Ipv4Addr::new(198, 51, 100, 0),
    Ipv4Addr::new(255, 255, 255, 0),
    2,
)
.with_route_tag(64500)
.with_next_hop(Ipv4Addr::new(192, 0, 2, 254));
```

The whole-table request uses the AFI-0 / metric-16 sentinel entry. The
convenience builders assemble the full IPv4/UDP/RIP packet for the common
request and multicast-response cases:

```rust
use crafter::prelude::*;
use crafter::protocols::rip::{
    rip_v1_whole_table_request, rip_v2_whole_table_request, rip_v2_multicast_response,
};
use std::net::Ipv4Addr;

let v1_req = rip_v1_whole_table_request(
    Ipv4Addr::new(192, 0, 2, 1),
    Ipv4Addr::new(255, 255, 255, 255),
);
let v2_req = rip_v2_whole_table_request(Ipv4Addr::new(192, 0, 2, 1));
let v2_resp = rip_v2_multicast_response(
    Ipv4Addr::new(192, 0, 2, 1),
    [RipEntry::ipv2_route(
        Ipv4Addr::new(198, 51, 100, 0),
        Ipv4Addr::new(255, 255, 255, 0),
        1,
    )],
);
```

`rip_v2_multicast_response` targets the RIPv2 multicast group `224.0.0.9`
(`RIP_V2_MULTICAST`) over UDP/520.

## RIPv2 Authentication

RIPv2 carries authentication in a leading AFI-`0xFFFF` entry. Attach it with
`Rip::auth(auth, key)`. `compute_md5_digest`/`compute_hmac_digest` run during
`compile()`, so the trailing digest block is filled automatically when the
caller did not pin a digest, and a caller-set digest is preserved.

```rust
use crafter::prelude::*;
use crafter::protocols::rip::{RipAuth, RipDigestAlgorithm};
use std::net::Ipv4Addr;

// Simple-password authentication (RFC 2453).
let simple = Rip::response()
    .with_entries([RipEntry::ipv2_route(
        Ipv4Addr::new(198, 51, 100, 0),
        Ipv4Addr::new(255, 255, 255, 0),
        1,
    )])
    .auth(RipAuth::simple_password(b"docs-only"), b"docs-only");

// Keyed message-digest authentication (RFC 2082 Keyed-MD5 / RFC 4822 HMAC-SHA).
let digest = Rip::response()
    .with_entries([RipEntry::ipv2_route(
        Ipv4Addr::new(198, 51, 100, 0),
        Ipv4Addr::new(255, 255, 255, 0),
        1,
    )])
    .auth(
        RipAuth::keyed_digest_with(RipDigestAlgorithm::KeyedMd5, 7),
        b"docs-only-key",
    );
```

`RipDigestAlgorithm` selects the digest: `KeyedMd5` (16 octets, RFC 2082),
`HmacSha1` (20 octets) and `HmacSha256` (32 octets, both RFC 4822). On the
decode side, `crafter::protocols::rip::auth::verify(message_bytes, key)` returns
a `RipAuthVerification` — `SimplePasswordOk`/`SimplePasswordMismatch`,
`DigestOk`/`DigestMismatch`, or `Unauthenticated` — so a tool can accept the
correct key and reject a wrong one. The decoded layer's authentication entry is
reachable through `auth_config()`.

```rust
use crafter::prelude::*;
use crafter::protocols::rip::auth::{verify, RipAuthVerification};

fn check(message_bytes: &[u8]) -> bool {
    matches!(
        verify(message_bytes, b"docs-only-key"),
        RipAuthVerification::DigestOk | RipAuthVerification::SimplePasswordOk
    )
}
```

## RIPng Construction

RIPng (RFC 2080) is a separate `Ripng` layer over IPv6 / UDP port 521, sent to
the all-RIP-routers multicast group `ff02::9` (`RIPNG_MULTICAST`). Each route
table entry is a `RipngRte`. `RipngRte::route(prefix, prefix_len, metric)` builds
a route RTE and `RipngRte::next_hop(address)` builds the next-hop RTE (metric
`0xFF`); `is_next_hop()` reports which is which.

```rust
use crafter::prelude::*;
use std::net::Ipv6Addr;

let response = Ipv6::new()
    .src("2001:db8::1".parse::<Ipv6Addr>().unwrap())
    .dst(RIPNG_MULTICAST)
    / Udp::new().sport(521).dport(521)
    / Ripng::response().with_rtes([
        RipngRte::next_hop("2001:db8::fe".parse::<Ipv6Addr>().unwrap()),
        RipngRte::route("2001:db8:1::".parse::<Ipv6Addr>().unwrap(), 48, 1),
        RipngRte::route("2001:db8:2::".parse::<Ipv6Addr>().unwrap(), 48, 2),
    ]);
```

The whole-table request uses the `::/0` metric-16 sentinel RTE; build the full
packet with `ripng_whole_table_request`:

```rust
use crafter::prelude::*;
use crafter::protocols::rip::ripng::ripng_whole_table_request;
use std::net::Ipv6Addr;

let request = ripng_whole_table_request("2001:db8::1".parse::<Ipv6Addr>().unwrap());
```

## Decode And Registry Dispatch

The built-in registry binds RIP to UDP port 520 and RIPng to UDP port 521. When
an IPv4 packet decodes to a UDP datagram on port 520, the payload is parsed as a
`Rip` layer; when an IPv6 packet decodes to a UDP datagram on port 521, the
payload is parsed as a `Ripng` layer. Each binding is guarded by a shape check,
so unrelated traffic on those ports remains a `Raw` payload.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn decode_rip() -> crafter::Result<()> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 1))
        .dst(Ipv4Addr::new(224, 0, 0, 9))
        / Udp::new().sport(520).dport(520)
        / Rip::response().with_entries([RipEntry::ipv2_route(
            Ipv4Addr::new(198, 51, 100, 0),
            Ipv4Addr::new(255, 255, 255, 0),
            1,
        )]);

    let bytes = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;

    for rip in decoded.layers::<Rip>() {
        println!("{}", rip.summary());
        for entry in rip.entries() {
            println!("  {} metric {}", entry.address_value(), entry.metric_value());
        }
    }

    Ok(())
}
```

To parse a UDP payload directly without a full L3 stack, call
`crafter::protocols::rip::decode(bytes)` or
`crafter::protocols::rip::ripng::decode(bytes)`. Unknown commands and address
families round-trip as preserved values, and a truncated header or a body whose
length is not a multiple of 20 returns a structured length error exposing
`context`, `required`, and `available` — never a panic. Use `summary()` for a
one-line description and `show()` for a full per-field dump.

## Offline And Live Surfaces

The offline path is the default. The bundled examples build documentation-safe
RIP and RIPng plans and print them without sending:

```sh
cargo run -p crafter --example rip_request
cargo run -p crafter --example rip_response
cargo run -p crafter --example rip_auth
cargo run -p crafter --example ripng_request
cargo run -p crafter --example ripng_response
```

A real wire run is opt-in: the examples gate sending behind an explicit `--send`
flag, and provider-backed validation runs dry-run first.

```sh
tools/probe/run --provider local-dry-run --dry-run --profile rip-smoke
tools/probe/run --provider qemu --dry-run --profile rip-smoke --seed 1
```

Live runs are intended for disposable provider-backed lab endpoints, not the
developer host. For the agent-facing live procedure and generated-tool guidance,
see [`.agents/docs/cookbook.md`](../.agents/docs/cookbook.md).

## Explicit Exclusions

The crate intentionally does not implement:

- A RIP routing engine, route table, distance-vector convergence, split-horizon,
  poison reverse, or RIP timer state machine.
- Automatic real-wire RIP exchange; live runs stay dry-run by default and require
  explicit confirmation and provider credentials.
- TCP-based or proprietary RIP variants beyond RFC 1058, 2453, 2082, 4822, 2080,
  and 2091.

Those are tools built on top of `crafter` packets. The crate stays focused on
constructing, decoding, preserving, and inspecting protocol-correct wire bytes.
