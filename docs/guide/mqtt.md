# MQTT Wire Coverage

This page describes MQTT packet-layer support in the `crafter` crate: what the
`Mqtt` layer builds and decodes today, how MQTT 3.1.1 and MQTT 5.0 are selected,
how properties and reason codes are represented, and where the offline/live
boundary sits.

`crafter` treats MQTT as a typed application layer over TCP. It builds,
compiles, decodes, summarizes, and shows like every other layer, slotting into
`/` composition, `compile()`, `decode_from_l3`, `summary()`, and `show()`. It is
not an MQTT broker, a client session implementation, a scanner, a fuzzer, or a
TLS implementation.

## Coverage at a glance

| Area | State | Notes |
| --- | --- | --- |
| Cleartext TCP port | Supported | TCP/1883 dispatches to MQTT when used as source or destination port. |
| MQTT over TLS | Preserved raw | TCP/8883 is TLS-wrapped traffic and is not decoded as cleartext MQTT. |
| MQTT 3.1.1 control packets | Supported | CONNECT, CONNACK, PUBLISH, PUBACK, PUBREC, PUBREL, PUBCOMP, SUBSCRIBE, SUBACK, UNSUBSCRIBE, UNSUBACK, PINGREQ, PINGRESP, DISCONNECT. |
| MQTT 5.0 control packets | Supported | `version(MQTT_5_PROTOCOL_LEVEL)` enables 5.0 body fields; AUTH is MQTT 5.0 only. |
| MQTT 5.0 properties | Supported | Typed `MqttProperty` values collected in `MqttProperties`; unknown property identifiers are rejected on decode because the identifier determines the wire type. |
| Remaining Length | Auto-filled | Filled from the encoded body on `compile()` unless `remaining_length()` set an explicit value. |
| Fixed-header flags | Auto-filled | Defaults follow each packet type; `flags()` preserves a caller-supplied nibble. |
| Stacked packets | Supported | Multiple MQTT control packets in one TCP payload decode as ordered `Mqtt` layers. |
| Truncated packets | Structured error / raw tail | Malformed buffers return typed errors; a complete packet followed by a partial tail keeps the tail as `Raw`. |
| Inspection | Supported | `summary()` gives one-line packet detail; `show()` includes fixed header and packet-specific fields. |

## Building packets

The MQTT layer is exported through `crafter::prelude::*` and through
`crafter::protocols::mqtt`. Constructors cover the baseline MQTT control packet
shapes:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

# fn main() -> crafter::Result<()> {
let packet = Ipv4::new()
    .src(Ipv4Addr::new(192, 0, 2, 10))
    .dst(Ipv4Addr::new(198, 51, 100, 20))
    .protocol(IPPROTO_TCP)
    / Tcp::new()
        .sport(49_194)
        .dport(MQTT_PORT)
        .seq(0x0102_0304)
        .ack(0x0506_0708)
        .ack_segment()
    / Mqtt::connect()
        .client_id("crafter-client")
        .keep_alive(30)
        .clean_session(true);

let bytes = packet.compile()?;
println!("{}", packet.summary());
# let _ = bytes;
# Ok(())
# }
```

Use `Mqtt::connect()`, `connack()`, `publish()`, `puback()`, `pubrec()`,
`pubrel()`, `pubcomp()`, `subscribe()`, `suback()`, `unsubscribe()`,
`unsuback()`, `pingreq()`, `pingresp()`, `disconnect()`, and `auth()` for typed
packets. Use `Mqtt::raw(packet_type, body)` when a tool needs an opaque body
under a known MQTT fixed-header type.

Common builder methods include:

- `client_id`, `keep_alive`, `clean_session`, `username`, `password`, `will`,
  `last_will`, `will_qos`, and `will_retain` for CONNECT.
- `topic`, `qos`, `dup`, `retain`, `payload`, and `packet_id` for PUBLISH.
- `subscribe_topic`, `subscribe_topic_options`, `topics`, and `packet_id` for
  SUBSCRIBE.
- `return_code`, `return_codes`, `reason_code`, `unsuback_reason_code`, and
  `unsuback_reason_codes` for acknowledgement and close packets.
- `flags` and `remaining_length` for deliberate fixed-header overrides.

`compile()` fills the fixed-header Remaining Length from the body, applies the
default fixed-header flags for each control packet type, fills TCP/IP lengths
and checksums through the enclosing layers, and preserves anything the caller
set explicitly, including intentionally malformed Remaining Length or flag
values.

## MQTT 5.0

MQTT 3.1.1 is the default for ordinary constructors. Select MQTT 5.0 with
`version(MQTT_5_PROTOCOL_LEVEL)` or `protocol_level(MQTT_5_PROTOCOL_LEVEL)` on a
CONNECT packet:

```rust
use crafter::prelude::*;

let connect_v5 = Mqtt::connect()
    .version(MQTT_5_PROTOCOL_LEVEL)
    .client_id("crafter-client")
    .connect_property(MqttProperty::SessionExpiryInterval(60))
    .connect_property(MqttProperty::ReceiveMaximum(10));

let publish_v5 = Mqtt::publish()
    .version(MQTT_5_PROTOCOL_LEVEL)
    .topic("crafter/demo/outbound")
    .qos(MQTT_PUBLISH_QOS_1)
    .packet_id(2)
    .content_type("text/plain")
    .user_property("example", "docs")
    .payload(b"hello from crafter".to_vec());
```

`MqttProperties` stores the property sequence with its MQTT property-length
prefix. It can hold typed `MqttProperty` values such as
`SessionExpiryInterval`, `ReceiveMaximum`, `ContentType`, `TopicAlias`,
`SubscriptionIdentifier`, `AuthenticationMethod`, `AuthenticationData`,
`ReasonString`, and repeated `UserProperty` pairs. Packet-specific helpers such
as `connect_property`, `publish_property`, `subscribe_property`,
`connack_property`, `disconnect_property`, `auth_property`, `ack_property`,
`suback_property`, `unsubscribe_property`, and `unsuback_property` append the
property to the matching packet body.

MQTT 5.0 acknowledgement packets can also carry reason codes and properties:

```rust
use crafter::prelude::*;

let disconnect = Mqtt::disconnect()
    .version(MQTT_5_PROTOCOL_LEVEL)
    .reason_code(MQTT_REASON_NORMAL_DISCONNECTION)
    .disconnect_property(MqttProperty::ReasonString("done".to_string()));
```

## Decoding

The default protocol registry dispatches cleartext MQTT from TCP port 1883.
Decoding through an IPv4 or IPv6 packet recovers typed TCP and MQTT layers:

```rust
use crafter::prelude::*;

# fn main() -> crafter::Result<()> {
# let packet = Ipv4::new()
#     .src("192.0.2.10".parse().unwrap())
#     .dst("198.51.100.20".parse().unwrap())
#     .protocol(IPPROTO_TCP)
#     / Tcp::new().sport(49_194).dport(MQTT_PORT)
#     / Mqtt::publish().topic("crafter/demo").payload(b"hi".to_vec());
# let bytes = packet.compile()?;
let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;
let mqtt = decoded.layer::<Mqtt>().expect("MQTT layer");

println!("{}", mqtt.summary());
println!("{}", decoded.show());
# Ok(())
# }
```

If a TCP segment carries multiple complete MQTT control packets, they decode as
multiple ordered MQTT layers:

```rust
use crafter::prelude::*;

# fn main() -> crafter::Result<()> {
let mut payload = Packet::from_layer(Mqtt::pingreq()).compile()?.into_bytes();
let pingresp = Packet::from_layer(Mqtt::pingresp()).compile()?;
payload.extend_from_slice(pingresp.as_bytes());

let decoded = Mqtt::decode_payload_with_default_version(
    &payload,
    MQTT_311_PROTOCOL_LEVEL,
)?;
let messages: Vec<_> = decoded.layers::<Mqtt>().collect();
assert_eq!(messages.len(), 2);
# Ok(())
# }
```

CONNECT carries its protocol level on the wire, so decode uses that value. Other
MQTT control packets do not carry a version marker; registry decode uses MQTT
3.1.1 as the default for non-CONNECT packets. For standalone MQTT 5.0 payloads,
call `Mqtt::decode_payload_with_default_version(bytes, MQTT_5_PROTOCOL_LEVEL)`
so property-bearing CONNACK, SUBACK, DISCONNECT, and similar packets are parsed
with the version-5 layout.

## Inspection

`summary()` reports the packet type and the most useful typed fields:

- CONNECT: client id, keep-alive, clean-session, will, username, password.
- PUBLISH: topic, QoS, DUP, RETAIN, and payload length.
- SUBSCRIBE and UNSUBSCRIBE: packet id and topic filters.
- ACK-like packets: packet id, return codes, or reason codes.

`show()` includes the fixed-header type, flags, Remaining Length, encoded body
length, and packet-specific fields such as CONNECT protocol level, PUBLISH
payload bytes, subscription options, and reason codes. Use `hexdump()` on the
compiled bytes when a generated tool needs byte-level audit output.

## Offline example

The bundled MQTT example builds a dry-run session plan by default using
documentation address space and no network side effects:

```console
cargo run -p crafter --example mqtt_session
cargo run -p crafter --example mqtt_session -- --v5
```

Both modes print CONNECT, SUBSCRIBE, PUBLISH, PINGREQ, and DISCONNECT packet
plans. The `--v5` flag selects MQTT 5.0 fields and properties. Live broker
traffic is opt-in with `--peer IP:PORT`; keep generated examples and tests on
the dry-run path unless an authorized operator explicitly provides a live peer.

For validation tooling, use the offline oracle and local dry-run probe paths
first:

```console
tools/oracle/run specs validate
tools/probe/run --profile mqtt-smoke --seed 1 --out target/probe/mqtt-plan
```

The MQTT 5.0 oracle cases for properties, reason codes, and AUTH are runnable
strict-byte cases today; no MQTT 5.0 oracle case is left as `contract_only`.
The reference backend contributes the IP/TCP/MQTT fixed-header framing and the
oracle materializes exact MQTT 5.0 bodies as bytes before normalizing them from
the TCP payload. Live broker exchange remains a dry-run-default probe or example
workflow: real traffic requires an explicit `--peer` or an externally executed
run with live confirmation and an authorized peer.

## Explicit exclusions

`crafter` does not implement broker state, client reconnect/session semantics,
topic matching, retained-message storage, TLS decryption, MQTT-over-WebSocket,
or application-level scanning. Those workflows belong in generated tools built
on top of the packet primitives.

TCP stream reassembly is also out of scope today. MQTT decode operates on the
bytes available in a single decoded TCP payload or on a standalone payload
passed to `Mqtt::decode_payload_with_default_version`.

## Standards implemented

The MQTT layer is source-backed by the local MQTT manifest and codepoint tables
under `.agents/docs/`. It implements the cleartext wire packet formats from:

- OASIS MQTT Version 3.1.1.
- OASIS MQTT Version 5.0.
