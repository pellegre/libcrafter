# RIP / RIPng Codepoint Authority Table

Compact, code-facing authority for the `crafter` RIP (IPv4, RFC 1058 / RFC 2453)
and RIPng (IPv6, RFC 2080) layers. This table is the single source the Rust
constants modules (`crafter/src/protocols/rip/constants.rs`,
`crafter/src/protocols/rip/registry.rs`,
`crafter/src/protocols/rip/ripng/constants.rs`) and the oracle YAML specs copy
**verbatim**. Names are SCREAMING_SNAKE_CASE so they transfer unchanged into Rust
constants.

Every value here is derived from and **must** match
[`rip-manifest.md`](rip-manifest.md). The manifest carries the full RFC/IANA
evidence and the RTE byte diagrams; this file is the condensed contract. On any
disagreement, this table is corrected to the manifest, never the reverse.

Row format: `NAME = value  # RFC`.

## Transport and fixed protocol constants (RFC 1058 §3.1, RFC 2453 §4)

```
RIP_UDP_PORT = 520  # RFC 1058 §3.1 / IANA service registry
RIP_HEADER_LEN = 4  # RFC 1058 §3.1 / RFC 2453 §4 (command + version + 2-octet reserved)
RIP_ENTRY_LEN = 20  # RFC 1058 §3.1 / RFC 2453 §4
RIP_MAX_ENTRIES = 25  # RFC 2453 §4 (generation guideline; decode does not reject more)
RIP_METRIC_INFINITY = 16  # RFC 1058 §3.1 (unreachable)
RIP_VERSION_1 = 1  # RFC 1058 §3.1
RIP_VERSION_2 = 2  # RFC 2453 §4
RIP_V2_MULTICAST = 224.0.0.9  # RFC 2453 §3.5 (IPv4 all-RIP-routers)
```

The third/fourth header octets are "must be zero" (reserved) in RFC 1058 and
remain reserved/unused in RFC 2453 §4. `compile()` fills them as zero unless the
caller set them. The 25-entry maximum is a *generation* guideline; decode still
parses messages carrying more than 25 entries (spec edge case).

## Command numbers (RFC 1058 §3.1, RFC 2091 §3.2)

```
RIP_COMMAND_REQUEST = 1  # RFC 1058 §3.1 / RFC 2453 §4
RIP_COMMAND_RESPONSE = 2  # RFC 1058 §3.1 / RFC 2453 §4
RIP_COMMAND_UPDATE_REQUEST = 9  # RFC 2091 §3.2 (demand RIP)
RIP_COMMAND_UPDATE_RESPONSE = 10  # RFC 2091 §3.2 (demand RIP)
RIP_COMMAND_UPDATE_ACK = 11  # RFC 2091 §3.2 (demand RIP)
```

Commands 1 (Request) and 2 (Response) are the RIPv1/RIPv2 core; commands 9-11
are the demand/triggered RIP extension. Preserve-only command codes (round-trip
verbatim, never the active surface):

```
RIP_COMMAND_TRACEON = 3  # RFC 1058 §3.1 (obsolete)
RIP_COMMAND_TRACEOFF = 4  # RFC 1058 §3.1 (obsolete)
RIP_COMMAND_SUN_RESERVED = 5  # RFC 1058 §3.1 (Sun Microsystems, reserved)
```

Commands 6-8 are historical triggered-RIP codes kept reserved. Unknown command
values are preserved as raw/typed data, never rejected (spec edge case).

## Address Family Identifiers — AFI (IANA "Address Family Numbers", RFC 2453 §4.1)

The 2-octet AFI begins each RIP route entry.

```
RIP_AFI_IP = 2  # IANA Address Family Numbers (IP) / RFC 1058 §3.1
RIP_AFI_AUTH = 0xFFFF  # RFC 2453 §4.1 (RIPv2 authentication-entry marker)
```

A RIPv1/RIPv2 route entry carries AFI **2** for IP. When the first entry's AFI is
the reserved value **0xFFFF**, the entry is a RIPv2 authentication entry rather
than a route (RFC 2453 §4.1; RFC 4822 §3). RIPng does **not** use an AFI field in
its RTE. Unknown address-family identifiers round-trip as preserved values, never
rejected (spec edge case).

## Authentication types (RFC 2453 §4.1, RFC 2082 §3, RFC 4822 §3)

The authentication entry (AFI 0xFFFF) carries a 2-octet authentication type in
the slot that a route entry uses for the route tag.

```
RIP_AUTH_TYPE_SIMPLE = 2  # RFC 2453 §4.1 (simple password, 16 plaintext octets)
RIP_AUTH_TYPE_KEYED_DIGEST = 3  # RFC 2082 §3, obsoleted by RFC 4822 §3 (keyed message digest)
RIP_AUTH_TRAILER_MARKER = 0x0001  # RFC 2082 §3 / RFC 4822 §3 (trailing-digest entry marker)
```

- **Type 2 (simple password)**: the remaining 16 octets hold a plaintext
  password (RFC 2453 §4.1).
- **Type 3 (keyed message digest)**: the authentication entry carries the digest
  offset, key ID, authentication-data length, and sequence number; the digest
  itself rides in a **trailing** AFI-0xFFFF entry (marker `0x0001`) at the given
  offset (RFC 2082 §3 / RFC 4822 §3). The digest is auto-computed on `compile()`
  when the caller did not set it and preserved untouched when the caller did.

Type 1 historically marked the entry as carrying an IP route and is kept
reserved. Unknown authentication types round-trip as preserved values, never
rejected (spec edge case).

### Keyed-digest algorithms (RFC 2082 §3, RFC 4822 §3)

RFC 4822 generalizes the digest algorithm; the wire layout of the authentication
and trailing-digest entries is shared. The algorithm is inferred on decode from
the authentication-data length octet (16 → Keyed-MD5, 20 → HMAC-SHA-1,
32 → HMAC-SHA-256).

```
RIP_DIGEST_LEN_KEYED_MD5 = 16  # RFC 2082 §3 (Keyed-MD5)
RIP_DIGEST_LEN_HMAC_SHA1 = 20  # RFC 4822 §3 (HMAC-SHA-1)
RIP_DIGEST_LEN_HMAC_SHA256 = 32  # RFC 4822 §3 (HMAC-SHA-256)
```

## RIPng (RFC 2080)

RIPng runs over a different UDP port, uses an IPv6 multicast group, and carries a
single-octet metric. RIPng RTEs have no AFI field.

```
RIPNG_UDP_PORT = 521  # RFC 2080 §2
RIPNG_HEADER_LEN = 4  # RFC 2080 §2 (command + version + 2-octet reserved)
RIPNG_RTE_LEN = 20  # RFC 2080 §2.1
RIPNG_METRIC_INFINITY = 16  # RFC 2080 §2.1 (unreachable)
RIPNG_NEXT_HOP_METRIC = 0xFF  # RFC 2080 §2.1.1 (marks a next-hop RTE)
RIPNG_VERSION_1 = 1  # RFC 2080 §2
RIPNG_COMMAND_REQUEST = 1  # RFC 2080 §2.1
RIPNG_COMMAND_RESPONSE = 2  # RFC 2080 §2.1
RIPNG_MULTICAST = ff02::9  # RFC 2080 §2 (IPv6 link-local all-RIP-routers)
```

The RIPng next-hop RTE is signalled by **metric = 0xFF** (RFC 2080 §2.1.1); the
16-octet field then carries the next-hop IPv6 address, the route tag must be
zero, the prefix length must be zero, and the next hop applies to the following
RTEs. RIPng reuses the RIP command numbers (1 Request, 2 Response).
