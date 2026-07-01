# NTP Packet-Layer Scope

NTP support in `crafter` is a packet primitive. It exists so generated tools can
build, decode, inspect, fixture, and validate NTP packet bytes carried by UDP
without introducing clock synchronization behavior.

## In Scope

- Build and decode NTP fixed header fields carried in UDP payloads.
- Preserve and inspect NTP timestamps as packet fields.
- Encode, decode, and round-trip extension fields, including unknown extension
  field types.
- Preserve NTS packet extension bodies as raw packet data.
- Preserve legacy MAC tails as raw packet data.
- Keep NTP traffic inside the existing `Packet` abstraction, including
  compile, decode, summary, and show behavior.

## Out of Scope

NTP support is not a clock implementation. It must not add:

- a clock discipline algorithm;
- a daemon;
- a pool client;
- a server;
- a peer association engine;
- NTS key exchange over TLS;
- Autokey cryptographic verification;
- time source selection;
- a replay cache; or
- scanner workflows.

Generated examples, fixtures, and defaults must stay offline or dry-run by
default. Any addresses shown in examples must use documentation address space
such as `192.0.2.0/24`, `198.51.100.0/24`, or `2001:db8::/32`; live NTP
validation belongs behind explicit provider-backed gates, not on the developer
machine.
