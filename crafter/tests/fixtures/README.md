# Packet Fixture Strategy

This directory holds offline fixtures for local tests. Fixtures must be safe to
run without root, live network access, cloud credentials, packet injection, or
host-specific interface state.

Local tests consume committed fixtures only. They must not silently regenerate
files in this tree.

## Categories

- `bytes/`: compact packet bytes used by decode, summary, field assertion, and
  compile/decode/compile tests. Use `.bin` for opaque bytes and `.hex` when
  line-oriented review is useful.
- `dot11/`: synthetic IEEE 802.11, radiotap, LLC/SNAP, EAPOL, and RSN-oriented
  hex fixtures. These are generated from documentation-space addresses and
  locally administered documentation MACs, not live captures.
- `pcaps/`: classic pcap files for supported offline link types. These exercise
  public pcap reader behavior, link type mapping, timestamps, record lengths,
  and packet decoding.
- `summaries/`: stable expected `summary()` output, or richer fixture output
  when a test needs `show()` or hexdump text.
- `malformed/`: line-oriented malformed input corpora with structured expected
  error categories.

## Test Ownership

The integration fixture catalog lives in
`crafter/tests/fixture_suite.rs`. When adding a valid fixture, update
`VALID_FIXTURES` and, if it closes a required coverage gap, update the
`coverage_for_case` mapping. The catalog entry records:

- `name`: lowercase dash-separated case name.
- `path`: path below this fixture directory.
- `contents`: checked-in bytes or checked-in hex text.
- `target`: public decode entrypoint, such as a link type, L3 protocol, raw
  decode, or DHCP option decoder.
- `expected_layers`: typed layers that must be present after decode.
- `preserve_exact_bytes`: whether decode/compile must preserve the fixture bytes.
- `summary_path`: optional expected summary fixture.

All files under `bytes/` must be listed in `VALID_FIXTURES`.
All packet hex files under `dot11/` must be listed in `DOT11_FIXTURES`.
All files under `pcaps/` must be listed in `PCAP_FIXTURES`.
The catalog tests fail if checked-in fixtures are missing from the catalogs or
if a required supported protocol family loses coverage.

UDP options fixtures use synthetic documentation-space packets whose UDP Length
field ends at the user payload and whose surplus area carries OCS plus option
bytes. Add these as `udp-options` catalog cases with an expected `UdpOptions`
layer, a stable summary fixture, and typed assertions for the option status and
decoded options.

The deterministic malformed packet corpus is consumed by
`crafter/tests/resilience.rs`. The malformed pcap corpus is consumed by
`crafter/tests/fixture_suite.rs`.

## Current Coverage Matrix

Valid byte fixtures cover:

- raw payload decode: `raw-hello-agents.hex`
- Ethernet unknown ethertype with raw payload:
  `ethernet-experimental-raw.bin`
- Ethernet ARP request and reply: `arp-who-has.bin`,
  `ethernet-arp-reply.hex`
- Ethernet nonstandard ARP (InfiniBand hardware type, IPv6 EtherType protocol
  type, variable-length raw addresses, unknown numeric opcode):
  `ethernet-arp-infiniband-ipv6-nonstandard.hex`
- Ethernet VLAN IPv4 UDP payload: `ethernet-vlan-ipv4-udp-raw.bin`
- Linux cooked ARP payload: `linux-sll-arp-who-has.hex`
- null loopback IPv4 and IPv6 payloads:
  `null-loopback-ipv4-udp-raw.hex`, `null-loopback-ipv6-raw.hex`
- IPv4 ICMP echo and ICMP error:
  `ipv4-icmp-echo-request.bin`,
  `ipv4-icmp-destination-unreachable.hex`
- IPv4 IGMP bootstrap and v2 compatibility fixtures:
  `ipv4-igmp-v1-query.hex`, `ipv4-igmp-v1-report.hex`,
  `ipv4-igmp-v2-query.hex`, `ipv4-igmp-v2-report.hex`,
  `ipv4-igmp-v2-leave.hex`
- IPv4 DSCP and ECN decode, including the differentiated-services octet split
  into DSCP EF and ECN CE:
  `ipv4-udp-dscp-ecn-raw.hex`
- IPv4 fragment fields without reassembly, including identification, reserved
  flag, Don't Fragment, More Fragments, and fragment offset:
  `ipv4-fragment-noninitial-raw.hex`
- IPv4 defragmentation vectors for complete out-of-order fragments, exact
  duplicate fragments, missing middle fragments, and conflicting overlaps:
  `ipv4-fragment-defrag-complete-*.hex`,
  `ipv4-fragment-defrag-duplicate-*.hex`,
  `ipv4-fragment-defrag-missing-*.hex`,
  `ipv4-fragment-defrag-overlap-*.hex`
- IPv4 options, including Record Route, Traceroute, Timestamp, and Router
  Alert:
  `ipv4-options-traceroute-udp-raw.hex`
- IPv4 TCP options:
  `ipv4-tcp-syn-options.hex`, `ipv4-tcp-syn-rich-options.hex` (MSS, Window
  Scale, SACK Permitted, Timestamp, RFC 5482 User Timeout, and a classified
  Generic option)
- IPv4 UDP DNS query and response:
  `ipv4-udp-dns-query-example-com.bin`,
  `ipv4-udp-dns-response-example-com.hex`
- IPv4 UDP DHCP message and DHCP option corpus:
  `ipv4-udp-dhcp-discover.hex`, `dhcp-offer-options.hex`
- IPv4 UDP options surplus decode:
  `ipv4-udp-options-known.hex`,
  `ipv4-udp-options-unknown-safe.hex`
- IPv6 ICMPv6 echo and ICMPv6 error:
  `ipv6-icmp-echo-request.bin`, `ipv6-icmpv6-time-exceeded.hex`
- IPv6 UDP, TCP, and fragment extension-header stacks:
  `ipv6-udp-raw.hex`, `ipv6-base-traffic-flow-udp-raw.hex` (base header
  Traffic Class DSCP/ECN, nonzero Flow Label, and Hop Limit),
  `ipv6-options-hop-destination-udp.hex` (Hop-by-Hop Router Alert, Jumbo
  Payload, unknown option preservation, Destination Options Home Address,
  padding, and terminal UDP payload),
  `ipv6-routing-generic-unknown-raw.hex` (generic unknown routing type with
  preserved type-specific data and raw payload), `ipv6-mobile-routing-raw.hex`
  (Mobile Type 2 routing fixed fields, home address, and raw payload),
  `ipv6-segment-routing-raw.hex` (Segment Routing Header Last Entry, Flags,
  Tag, Segment List, raw trailing data, and raw payload),
  `ipv6-tcp-raw.hex`,
  `ipv6-tcp-rich-options.hex` (MSS, Window Scale, SACK Permitted, Timestamp,
  RFC 5482 User Timeout, and a classified Generic option, with IPv6
  pseudo-header checksum), `ipv6-fragment-udp-raw.hex` (initial fragment that
  decodes the complete UDP header present in the first fragment),
  `ipv6-fragment-atomic-udp-raw.hex` (atomic fragment that decodes UDP), and
  `ipv6-fragment-non-initial-udp-raw.hex` (non-initial fragment bytes
  preserved as Raw without transport reassembly)
- IPv6 UDP options surplus decode:
  `ipv6-udp-options-unknown-unsafe.hex`,
  `ipv6-udp-options-frag.hex`

Summary fixtures cover representative raw, ARP, Linux cooked, IPv4 options,
IPv4 TCP options, IPv6 TCP options, IPv4 DNS response, IPv4 DHCP, UDP options,
IGMP v1 query/report and IGMPv2 query/report/leave packets, IPv6 option-header
stacks, and IPv6 fragment stacks.

Pcap fixtures cover:

- Ethernet link type with ARP request and reply records, plus a single-record
  nonstandard ARP frame (`ethernet-arp-nonstandard.pcap`) exercising variable
  address lengths and unknown codepoints.
- RawIp link type with IPv4 and IPv6 packets, including
  `raw-ipv4-igmp-bootstrap.pcap`: timestamped IGMP v1 query/report and
  IGMPv2 query/report/leave records using RFC 5737 source addresses, RFC 5771
  multicast documentation group addresses, and source-backed all-systems /
  all-routers destinations where applicable. They decode as IPv4/IGMP with no
  live capture data.
  `raw-ipv6-base-traffic-flow-udp-raw.pcap`: timestamp `20.000003`,
  DLT_RAW/RawIp, captured/original length 56, byte fixture
  `ipv6-base-traffic-flow-udp-raw.hex`, decoded as IPv6/UDP/Raw with Traffic
  Class `0xbb` (DSCP 46, ECN 3), Flow Label `0xabcde`, Hop Limit 37, UDP
  ports `54049 -> 1049`, a valid UDP checksum, and raw payload `base-v6!`.
  The RawIp pcap corpus also includes deterministic IP fragment transform
  fixtures: `raw-ipv4-ipfragment-generated.pcap` is byte-for-byte regenerated
  from `IpFragment`, and `raw-ipv6-fragment-oracle-reference.pcap` carries an
  oracle reference IPv6 fragment pair. Both are read back into `PacketRecord`s
  and reassembled through `IpDefrag`.
- LinuxSll link type with an ARP payload.
- NullLoopback link type with an IPv4 UDP payload.
- IEEE 802.11 link type with a synthetic WPA2-PSK CCMP conversation:
  `wpa2-psk-ccmp-unicast.pcap` contains a beacon, two EAPOL-Key handshake
  records, and one protected unicast data record. The fixture decrypts to an
  Ethernet-equivalent IPv4 raw payload through `WpaDecrypt` and uses only
  documentation-safe identifiers.

The checked-in pcap fixtures currently exercise link type mapping, timestamps,
record lengths, packet decoding, and IP fragment transform handoff for those
link types. They include RawIp IPv4 DSCP/ECN, RawIp IPv4/IPv6 fragment pcap,
and IEEE 802.11 WPA decryptor coverage. IPv4 options, Timestamp, and Router
Alert coverage still live in byte and summary fixtures unless a matching pcap
fixture is added.

Malformed packet fixtures cover short or inconsistent Ethernet, VLAN, ARP,
Linux cooked, null loopback, IPv4, IPv4 options, IPv6 extension headers, UDP,
TCP, TCP options, ICMP, ICMPv6, DNS, DHCP, and DHCP option inputs. The random
resilience tests remain broad panic guards; named malformed fixtures provide the
deterministic regression coverage.

Malformed IPv4 option cases include below-minimum option lengths, option
payload overruns, route-option length and pointer errors, malformed Timestamp
data, and Router Alert bad-length handling.

Malformed IGMP bootstrap fixtures cover empty and short IGMP payloads,
inconsistent IPv4 wrapper length, surplus bytes preserved as Raw, and unknown
IGMP type payload preservation.

Malformed pcap fixtures cover unknown magic, unsupported major version, zero
snapshot length, partial record headers, captured length greater than snaplen,
and truncated record bodies.

## Naming Conventions

Use lowercase, dash-separated names that describe the protocol stack and case:

```text
<stack>-<case>.<kind>
```

Examples:

```text
ipv4-icmp-echo-request.bin
ethernet-vlan-ipv4-udp-raw.bin
ipv4-tcp-syn-options.hex
ipv6-fragment-udp-raw.summary.txt
```

Prefer stable, deterministic packets. Do not include wall-clock timestamps,
random identifiers, real account data, or host-specific interface addresses
unless the test explicitly documents and normalizes them.

## Malformed Decode Corpus

`malformed/core-decode-corpus.hex` uses one case per non-comment line:

```text
name|target|expected-kind|expected-context-or-field|hex
```

Supported `target` values are defined by the resilience test runner and include
packet decode targets such as `ethernet`, `linux-sll`, `null-loopback`, `ipv4`,
and `ipv6`, plus focused decoders such as `ipv4-options`, `tcp-options`,
`dhcp`, `dhcp-options`, and `dns-name`.

Supported `expected-kind` values currently map to structured `CrafterError`
variants:

- `buffer-too-short`: assert the stable error context.
- `invalid-field-value`: assert the stable field name.

The tests assert the enum variant and context or field, not full display
strings. Keep case names lowercase and dash-separated, and keep hex payloads
minimal enough to make the failing field obvious.

`malformed/pcap-corpus.hex` uses:

```text
name|expected-kind|hex
```

Supported pcap `expected-kind` values are `invalid-header` and
`invalid-record`, matching `PcapError` categories.

## Pcap Fixtures

Pcap fixtures are classic pcap files with deterministic timestamps. The current
catalog asserts exact `PcapTimestamp` values, timestamp precision, captured and
original lengths, record bytes, pcap link type, crate link type, and decoded
packet fields.

Use microsecond precision unless the fixture is specifically exercising another
precision. A pcap should normally contain one conversation or one behavior under
test. Do not commit captures from personal networks unless they have been
sanitized and reduced to deterministic fixture data.

IP fragmentation pcaps in this tree must stay deterministic RawIp fixtures built
from documentation address space, such as `192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`, or `2001:db8::/32`. Provider-backed live
fragment artifacts belong under ignored `target/oracle/ip-fragment-*` or
`target/lab/ip-fragment-*` directories; only sanitized summaries that omit
credentials, public host addresses, live captures, and cloud resource IDs may be
promoted into tracked docs or `.agents/context/`.

## Oracle Promotion

Oracle-generated packet behavior coverage is produced by executable specs and
written below `target/oracle/`. Keep backend-specific reference logic inside
`tools/oracle/`; crate tests and fixtures must not import or name those
backends directly.

Useful oracle commands:

```sh
tools/oracle/run offline --profile smoke --seed 1 --count 10
tools/oracle/run pcap --profile smoke --seed 1 --count 10
```

Before promoting oracle output into this tree:

- Regenerate with explicit `--seed`, and use `--index` for a single failing or
  interesting case when needed.
- Review the artifact under `target/oracle/`; do not make tests depend on that
  directory being present.
- Copy only synthetic, generic bytes or metadata into
  `crafter/tests/fixtures/`.
- Add or update the appropriate Rust catalog entry and coverage mapping.
- Add a summary fixture only when stable human-readable output is part of the
  intended regression check.
- Run the focused fixture test and the full validation preflight before review.

## Regeneration

Fixture regeneration must be explicit. Any wire endpoint or reference
regeneration tool should write into a temporary artifact directory first so
changes can be reviewed before fixtures are copied into this tree.

Pull request CI may run deterministic oracle validation, but it must not rewrite
checked-in fixtures. CI should use `tools/oracle/run` rather than importing
reference backends from tests directly.
