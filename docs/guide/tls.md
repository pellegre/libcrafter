# TLS Wire Coverage

This page describes TLS packet-layer support in the `crafter` crate. TLS slots
into the same `Packet` abstraction as other protocols: compose layers with `/`,
call `compile()`, decode through the normal packet entrypoints, and inspect with
`summary()`, `show()`, and hexdumps.

`crafter` is not a TLS endpoint stack. It does not implement a handshake state
machine, transcript hashing, certificate validation, key schedule, record
protection, decryption, or TCP stream reassembly. Encrypted bytes and unknown
codepoints remain packet bytes for generated tools to inspect, replay, mutate,
or preserve.

## Coverage At A Glance

| Area | State | Notes |
| --- | --- | --- |
| TLS-over-TCP ports | Supported | Common dispatch ports include 443, 853, 8883, and the documentation/testing port 4433. Non-TLS payloads on those ports fall back to `Raw`. |
| Record header | Supported | Content type, legacy record version, and length are typed. Length is auto-filled by `compile()` unless explicitly overridden. |
| Record bodies | Supported | Handshake, ChangeCipherSpec, alert, application data, and heartbeat helpers are available. Application data remains opaque bytes. |
| Stacked records | Supported | Multiple complete TLS records in one TCP payload decode as one `Tls` layer containing ordered records. |
| Handshake messages | Supported | Typed helpers cover ClientHello, ServerHello / HelloRetryRequest, EncryptedExtensions, Certificate, CertificateRequest, CertificateVerify, Finished, NewSessionTicket, KeyUpdate, and EndOfEarlyData. Unknown or encrypted handshake bodies are preserved. |
| Extensions | Supported | Common TLS 1.2 / TLS 1.3 extension bodies are typed where the packet grammar is source-backed; unknown extensions preserve type and bytes. |
| Codepoint labels | Supported | Versions, content types, alerts, handshake types, extension types, cipher suites, named groups, signature schemes, and related registries carry stable labels and status classification. |
| Decode errors | Supported | Truncated or internally inconsistent TLS buffers return structured errors rather than panics. |
| Inspection | Supported | `summary()` is concise; `show()` includes record, handshake, extension, and codepoint details. |
| Crypto and validation | Out of scope | No key exchange, MAC, AEAD, certificate trust, transcript validation, SNI policy, ALPN negotiation, or stream reassembly. |

## Packet Construction

Use TLS as a normal packet layer:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

# fn main() -> crafter::Result<()> {
let hello = TlsClientHello::new()
    .with_random([0x42; TLS_CLIENT_HELLO_RANDOM_LEN])
    .with_session_id([0x01, 0x02, 0x03, 0x04])
    .with_raw_cipher_suites([
        TLS_CIPHER_SUITE_AES_128_GCM_SHA256,
        TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256,
    ])
    .with_extensions(vec![
        TlsRawExtension::server_name(TlsServerNameList::from_host_name(
            "tls.example.test",
        )?)?,
        TlsRawExtension::alpn(TlsAlpnProtocols::h2_then_http_1_1())?,
        TlsRawExtension::supported_versions_client(vec![
            TlsVersion::tls_1_3(),
            TlsVersion::tls_1_2(),
        ])?,
    ]);

let record = TlsRecord::handshake_messages([
    TlsHandshake::from_client_hello(hello)?,
])?;

let packet = Ipv4::new()
    .src(Ipv4Addr::new(192, 0, 2, 10))
    .dst(Ipv4Addr::new(198, 51, 100, 20))
    .ipv4_protocol(Ipv4Protocol::Tcp)
    / Tcp::new().sport(49_171).dport(TLS_PORT_HTTPS).syn()
    / Tls::from_record(record);

let bytes = packet.compile()?;
println!("{}", packet.summary());
println!("{}", bytes.hexdump());
# Ok(())
# }
```

`Tls::from_record(record)` builds one-record payloads. Use
`Tls::from_records(records)` when a single TCP segment should contain multiple
TLS records. The layer remains inspectable before and after decode:

```rust
use crafter::prelude::*;

# fn main() -> crafter::Result<()> {
# let packet = Ipv4::new().ipv4_protocol(Ipv4Protocol::Tcp)
#     / Tcp::new().sport(49_171).dport(TLS_PORT_HTTPS).syn()
#     / Tls::from_record(TlsRecord::application_data([0xde, 0xad]));
# let bytes = packet.compile()?;
let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;
println!("{}", decoded.summary());
println!("{}", decoded.show());
# Ok(())
# }
```

## Compile Defaults And Overrides

`compile()` follows the crate-wide packet rule: it fills dependent fields the
caller did not set and preserves fields the caller did set, including malformed
values used for tests.

For TLS, compile fills:

- TLS record length from the encoded record body.
- TLS handshake message length from the encoded handshake body.
- TLS vector length prefixes for typed vectors such as session IDs, cipher-suite
  lists, extension lists, ALPN protocols, key shares, PSK identities, and
  certificate lists.
- Default legacy record and hello versions where the builder uses the TLS 1.2
  compatibility value expected by modern TLS records.
- Enclosing TCP/IP lengths, checksums, and protocol numbers through the normal
  `Packet` compilation path.

Explicit values survive:

- A record `declared_length` / `length` override is emitted as supplied.
- A handshake `declared_length` / `length` override is emitted as supplied.
- Raw codepoint constructors keep unknown, reserved, GREASE, private-use, and
  experimental values numeric and round-trippable.
- Opaque body helpers keep byte payloads unchanged.

This means generated tools can emit both protocol-correct ClientHello packets
and intentionally malformed record or handshake lengths when a controlled test
needs them.

## Records And Decode

The default protocol registry dispatches TLS from selected TCP ports. A decoded
packet keeps IPv4/IPv6, TCP, and TLS layers in order:

```rust
use crafter::prelude::*;

# fn main() -> crafter::Result<()> {
# let packet = Ipv4::new().ipv4_protocol(Ipv4Protocol::Tcp)
#     / Tcp::new().sport(49_171).dport(TLS_PORT_HTTPS)
#     / Tls::from_record(TlsRecord::alert(TlsAlert::decode_error().encode_to_vec()));
# let bytes = packet.compile()?;
let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;
let tls = decoded.layer::<Tls>().expect("TLS layer");
assert_eq!(tls.record_count(), 1);
# Ok(())
# }
```

Record bodies are decoded conservatively:

- `handshake` records decode complete handshake messages plus a raw tail when a
  complete message is followed by surplus bytes.
- `change_cipher_spec` records expose the ChangeCipherSpec byte when present.
- `alert` records preserve alert bytes and can be decoded as `TlsAlert`.
- `application_data` records stay opaque by design.
- `heartbeat` records expose the packet grammar without adding heartbeat
  protocol behavior.
- Unknown record content types preserve fragment bytes as opaque record bodies.

Malformed record headers, truncated declared lengths, malformed handshake
headers, and invalid vector lengths return structured errors with context. They
do not silently panic. If the TCP payload on a TLS-dispatch port is not a TLS
record at all, TCP decode preserves it as `Raw` so unrelated traffic is not
misclassified.

## Handshakes

Typed handshake helpers cover the source-backed packet grammar:

- `TlsClientHello` and `TlsServerHello`, including HelloRetryRequest detection
  through the standard retry random.
- `TlsEncryptedExtensions`.
- `TlsCertificate` for TLS 1.2 and TLS 1.3 certificate-list shapes.
- `TlsCertificateRequest` for TLS 1.2 and TLS 1.3 forms.
- `TlsCertificateVerify`, `TlsFinished`, `TlsNewSessionTicket`,
  `TlsKeyUpdate`, and `TlsEndOfEarlyData`.
- `TlsHandshake::raw(...)` / opaque bodies for unsupported, encrypted, or
  experimental handshake messages.

Handshake type labels include modern TLS values and preserve DTLS-only,
reserved, obsolete, and unknown values by numeric codepoint. `crafter` does not
decide whether a handshake sequence is legal for a TLS connection; it models
the bytes present in one packet payload.

## Extensions And Codepoints

`TlsRawExtension` is the common extension container: extension type plus body
bytes. Use typed constructors when available and raw extensions when a tool needs
an unknown or future extension.

Typed extension coverage includes:

- `server_name` SNI.
- `status_request` and `status_request_v2`.
- `certificate_authorities` and `oid_filters`.
- `supported_groups` and `ec_point_formats`.
- `signature_algorithms` and `signature_algorithms_cert`.
- `alpn`.
- `padding`.
- `supported_versions`.
- `cookie`.
- `record_size_limit`.
- `psk_key_exchange_modes`, `pre_shared_key`, and `key_share`.

Typed codepoint wrappers include `TlsVersion`, `TlsContentType`,
`TlsHandshakeType`, `TlsExtensionType`, `TlsCipherSuite`, `TlsNamedGroup`,
`TlsSignatureScheme`, `TlsAlertLevel`, `TlsAlertDescription`,
`TlsPskKeyExchangeMode`, and `TlsEcPointFormat`. They expose raw values,
labels, and status classification so generated tools can distinguish assigned
defaults from compatibility, GREASE, reserved, private-use, experimental, and
unknown values without losing the original bytes.

## Pcap Usage

TLS pcap workflows stay offline unless an operator explicitly chooses a live
provider-backed run. The bundled example reads a checked-in fixture through
`PacketWire`, applies a BPF filter, and iterates with `Sniffer`:

```console
cargo run -p crafter --example tls_pcap_read
```

Programmatic use is the same pattern:

```rust
use crafter::prelude::*;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let source = PacketWire::pcap_file("tls-fixture.pcap")
    .filter("tcp port 443")
    .open()?
    .source()?;

for record in Sniffer::new(source).no_timeout().collect_records()? {
    println!("{}", record.packet().summary());
}
# Ok(())
# }
```

Deterministic pcap fixtures under `crafter/tests/fixtures/pcaps/` cover RawIp
and Ethernet TLS records. Fixture-suite tests read them back, assert metadata,
preserve exact bytes, and verify TLS summaries.

## Offline Validation

Keep TLS validation offline by default:

- Golden byte fixtures cover ClientHello, ServerHello, HelloRetryRequest,
  alerts, ChangeCipherSpec, application data, unknown codepoints, and selected
  handshake and extension forms.
- Malformed corpora cover record, handshake, and extension truncation or length
  inconsistencies.
- Property tests cover TLS vector helpers and record round trips.
- Pcap tests cover deterministic read, write, BPF-filtered decode, metadata,
  summary, and byte-preservation behavior.
- Examples use documentation address space and dry-run send plans.

Useful local checks:

```console
cargo test -p crafter --test tls_vectors
cargo test -p crafter --test tls_records
cargo test -p crafter --test tls_properties
cargo test -p crafter --test tls_pcap
cargo run -p crafter --example tls_client_hello
cargo run -p crafter --example tls_pcap_read
```

## Live And Provider Safety

Live TLS packet work is not a default workflow. Generated tools should first
produce compiled bytes, `summary()`, `show()`, hexdumps, pcap artifacts, and
dry-run plans. If a real network observation is required, use a disposable
provider endpoint or lab session with explicit authorization, collect artifacts
under `target/`, and tear the endpoint down. Do not elevate the developer host
or aim crafted TLS traffic at arbitrary public services from local examples.

The TLS layer only provides packet primitives. Provider-backed probes can use
those primitives to observe a controlled service, but the crate itself remains
limited to building, decoding, preserving, and inspecting wire bytes.
