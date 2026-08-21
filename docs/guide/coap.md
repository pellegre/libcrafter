# CoAP wire coverage

`crafter` models CoAP as packet primitives: `Coap` is one RFC 7252 datagram
message and `CoapReliable` is one complete RFC 8323 reliable-transport frame.
Both compose with the normal `Packet` stack and preserve explicit caller
values, unknown codepoints, ordered options, tokens, payload-marker state, and
payload bytes. They do not implement a CoAP client, server, retransmission
engine, Observe subscription, block-transfer assembler, or TCP stream buffer.

The implementation is sourced from the repository's reviewed
[CoAP RFC manifest](../../.agents/docs/coap-rfc-manifest.md) and
[IANA snapshot](../../.agents/docs/coap-codepoints.md). In particular, it
covers RFC 7252 datagrams, CoRE Link Format, Observe, Block1/Block2 and BERT,
No-Response, PATCH/iPATCH, Hop-Limit, Echo and Request-Tag, Q-Block, extended
tokens, reliable framing and signaling, pairwise OSCORE, group communication
metadata, and provisional lossless Group OSCORE metadata. The exact admitted
source set and deferrals remain authoritative in the manifest.

## Build and decode a datagram

Import the standard prelude and compose `Coap` after UDP. `compile()` fills
unset IP/UDP/CoAP dependent fields; an explicitly supplied field is emitted
unchanged, including a deliberately malformed value.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> crafter::Result<()> {
    let packet = Ipv4::with_addresses(
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(198, 51, 100, 20),
    ) / Udp::new().sport(49_152).dport(COAP_PORT)
      / Coap::get()
          .confirmable()
          .message_id(0x1234)
          .token(CoapToken::from_bytes([0xaa, 0xbb]))
          .uri_path("status")
          .accept(CoapAccept::new(50));

    let bytes = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;
    let coap = decoded.layer::<Coap>().expect("typed CoAP layer");

    assert_eq!(coap.code_value(), CoapCode::get());
    assert_eq!(coap.message_id_value(), 0x1234);
    println!("{}", decoded.summary());
    println!("{}", decoded.show());
    Ok(())
}
```

`coap_ipv4_request`, `coap_ipv4_response`, `coap_ipv6_request`, and
`coap_ipv6_response` build common typed IP/UDP/CoAP stacks. The lower-level
`coap_request_udp` and `coap_response_udp` helpers return typed UDP layers for
callers that assemble the network envelope separately.

Use `decode_coap(bytes)` or `Coap::decode(bytes)` when a buffer is known to be
one CoAP datagram. Direct decode is strict and returns structured
`CrafterError` values for truncation or impossible grammar. Default UDP
registry dispatch is deliberately conservative: only structurally valid
cleartext candidates on UDP/5683 become `Coap`; wrong-port data, malformed
candidates, and secure UDP/5684 ciphertext remain an unchanged `Raw` layer.

## Options and extensions

`CoapOption` is the lossless base representation. Repeated and unknown options
retain their numeric values and bytes. Typed wrappers provide checked views and
builders for URI, conditional, representation, location, size, proxy,
No-Response, Hop-Limit, Echo, Request-Tag, Observe, Block, Q-Block, and OSCORE
options. `Coap::validate()` reports semantic inconsistencies without changing
or refusing to compile the message.

Resource discovery stays packet-local:

```rust
use crafter::prelude::*;

let request = coap_discovery_request().message_id(0x0102);
let links = CoapLinkFormat::new().link(
    CoapLink::new("/sensors/temp")
        .attribute(CoapLinkAttribute::resource_type("temperature-c")),
);
let response = coap_discovery_response(links)
    .acknowledgement()
    .message_id(0x0102);

assert_eq!(request.code_value(), CoapCode::get());
assert_eq!(response.code_value(), CoapCode::content());
# Ok::<(), crafter::CrafterError>(())
```

Observe values expose stateless serial ordering, including wraparound and the
ambiguous half range. Block1, Block2, BERT, Q-Block1, and Q-Block2 expose typed
NUM/M/SZX, size, and offset metadata plus opt-in validation. Follow-up timing,
burst scheduling, congestion control, retransmission, and body reassembly are
caller-owned workflows.

Tokens use `CoapToken`; canonical compilation selects the RFC 8974 direct,
Extended8, or Extended16 length form through `CoapTokenLength`. Direct decode
preserves explicit discriminator and extension bytes, including mismatched
metadata that is still structurally parseable.

## Reliable messages

`CoapReliable` encodes or decodes exactly one complete CoAP-over-TCP frame. It
supports the RFC 8323 length forms, extended tokens, ordinary messages, CSM,
Ping, Pong, Release, Abort, contextual signaling options, and BERT metadata.

```rust
use crafter::prelude::*;

let frame = CoapReliable::ping().token(CoapToken::from_bytes([0x42]));
let bytes = Packet::from_layer(frame).compile()?;
let (decoded, consumed) = decode_coap_reliable(bytes.as_bytes())?;

assert!(decoded.is_ping());
assert_eq!(consumed, bytes.len());
# Ok::<(), crafter::CrafterError>(())
```

The consumed length lets a caller advance its own stream buffer. Registry
dispatch types only a complete single cleartext frame on TCP/5683; partial or
concatenated frames and TCP/5684 ciphertext remain `Raw`. `crafter` does not
perform TCP stream reassembly, TLS, DTLS, or WebSocket framing.

## OSCORE transforms

Pairwise OSCORE is an explicit typed `Coap`-to-`Coap` transform. Construct an
immutable `OscoreContext`, then call `protect` with an
`OscoreProtectParams::request` or response binding. The peer calls `unprotect`
with the corresponding parameters. Successful operations return an ordinary
typed `Coap` value; authentication failure never returns partial plaintext.
Context diagnostics redact Master Secret, Master Salt, derived keys, and
Common IV data.

The API does not provision contexts, persist replay windows, manage sequence
state, or perform ACE/EDHOC. Group OSCORE currently exposes provisional opaque
wire metadata only; it intentionally has no protect/unprotect implementation
until final specification authority is available.

## Inspection and pcaps

`Packet::summary()`, `Packet::show()`, and compiled-byte `hexdump()` expose the
typed message, token and option counts, header values, payload length, and
bounded binary previews. OSCORE option data and context secrets use redacted
diagnostics. Classic pcap readers/writers and `PacketWire::pcap_file` or
`PacketWire::pcap_recorder` preserve CoAP through Raw IPv4, Raw IPv6, and
Ethernet link types; committed fixtures use documentation addresses and
deterministic timestamps.

## Validation

Use the tracked deterministic validation surfaces first:

```sh
tools/oracle/run offline --profile smoke --seed 1 --count 10
tools/oracle/run pcap --profile smoke --seed 1 --count 10
tools/probe/run --profile smoke --seed 1 --count 10 --out target/probe/plan
```

These commands do not select infrastructure or send packets. Any authorized use
of concrete interfaces, peers, radios, or targets is owned by external operator
tooling, which supplies runtime inputs and collects artifacts. libcrafter does
not provision machines, configure responders, manage credentials, or perform
remote cleanup.
