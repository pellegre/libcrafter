# BGP-4 Codepoint Authority Table

Compact, code-facing authority for the `crafter` BGP-4 layer. This table is the
single source the Rust constants module (`crafter/src/protocols/bgp/constants.rs`)
and the oracle YAML specs copy **verbatim**. Names are SCREAMING_SNAKE_CASE so
they transfer unchanged into Rust constants.

Every value here is derived from and **must** match
[`bgp-manifest.md`](bgp-manifest.md). The manifest carries the full RFC/IANA
evidence; this file is the condensed contract. On any disagreement, this table
is corrected to the manifest, never the reverse.

Row format: `NAME = value  # RFC`.

## Fixed protocol constants (RFC 4271 §4.1, §4.2)

```
BGP_PORT = 179  # RFC 4271 §1 / IANA service registry
BGP_VERSION = 4  # RFC 4271 §4.2
BGP_MARKER_LEN = 16  # RFC 4271 §4.1
BGP_HEADER_LEN = 19  # RFC 4271 §4.1
BGP_MAX_MESSAGE_LEN = 4096  # RFC 4271 §4.1
AS_TRANS = 23456  # RFC 6793 §9
BGP_MIN_OPEN_LEN = 29  # RFC 4271 §4.2
BGP_MIN_UPDATE_LEN = 23  # RFC 4271 §4.3
BGP_MIN_NOTIFICATION_LEN = 21  # RFC 4271 §4.5
BGP_KEEPALIVE_LEN = 19  # RFC 4271 §4.4
```

## Message types (IANA `bgp-parameters-1`)

```
MSG_TYPE_OPEN = 1  # RFC 4271
MSG_TYPE_UPDATE = 2  # RFC 4271
MSG_TYPE_NOTIFICATION = 3  # RFC 4271
MSG_TYPE_KEEPALIVE = 4  # RFC 4271
MSG_TYPE_ROUTE_REFRESH = 5  # RFC 2918
```

## OPEN optional parameter types (IANA `bgp-parameters-11`)

```
OPT_PARAM_AUTHENTICATION = 1  # RFC 4271 / RFC 5492 (deprecated)
OPT_PARAM_CAPABILITIES = 2  # RFC 5492
OPT_PARAM_EXTENDED_LENGTH = 255  # RFC 9072
```

Capabilities optional parameter (type 2) carries
`<Capability Code(1), Capability Length(1), Capability Value(variable)>` triples
(RFC 5492 §4). In scope: parameter type 2 only.

## Capability codes (IANA `capability-codes-2`)

```
CAP_MULTIPROTOCOL = 1  # RFC 2858 (obsoleted by RFC 4760)
CAP_ROUTE_REFRESH = 2  # RFC 2918
CAP_GRACEFUL_RESTART = 64  # RFC 4724
CAP_FOUR_OCTET_AS = 65  # RFC 6793
CAP_ADD_PATH = 69  # RFC 7911
CAP_ENHANCED_ROUTE_REFRESH = 70  # RFC 7313 (preserve only)
CAP_ROUTE_REFRESH_OLD = 128  # RFC 8810 (prestandard, deprecated; preserve only)
```

- The standardized Route-Refresh capability is `CAP_ROUTE_REFRESH = 2`
  (RFC 2918); `CAP_ROUTE_REFRESH_OLD = 128` is the prestandard variant
  (RFC 8810). The crate advertises 2 and preserves 128 verbatim if received.
- MP-BGP capability (code 1) value is 4 octets: `AFI(2) | Reserved(1) | SAFI(1)`
  (RFC 4760 §8).
- Unknown capability codes MUST round-trip verbatim (RFC 5492 §5).

## Path attribute type codes (IANA `bgp-parameters-2`)

```
ATTR_ORIGIN = 1  # RFC 4271
ATTR_AS_PATH = 2  # RFC 4271
ATTR_NEXT_HOP = 3  # RFC 4271
ATTR_MULTI_EXIT_DISC = 4  # RFC 4271
ATTR_LOCAL_PREF = 5  # RFC 4271
ATTR_ATOMIC_AGGREGATE = 6  # RFC 4271
ATTR_AGGREGATOR = 7  # RFC 4271
ATTR_COMMUNITIES = 8  # RFC 1997
ATTR_ORIGINATOR_ID = 9  # RFC 4456 (preserve only)
ATTR_CLUSTER_LIST = 10  # RFC 4456 (preserve only)
ATTR_MP_REACH_NLRI = 14  # RFC 4760
ATTR_MP_UNREACH_NLRI = 15  # RFC 4760
ATTR_EXTENDED_COMMUNITIES = 16  # RFC 4360
ATTR_AS4_PATH = 17  # RFC 6793
ATTR_AS4_AGGREGATOR = 18  # RFC 6793
ATTR_LARGE_COMMUNITY = 32  # RFC 8092
```

### Attribute flags octet (RFC 4271 §4.3)

High-order bits of the Flags octet; framing is
`Flags(1) | Type Code(1) | Length(1 or 2) | Value(Length)`.

```
ATTR_FLAG_OPTIONAL = 0x80  # RFC 4271 §4.3 (1 = optional, 0 = well-known)
ATTR_FLAG_TRANSITIVE = 0x40  # RFC 4271 §4.3 (1 = transitive; well-known MUST be 1)
ATTR_FLAG_PARTIAL = 0x20  # RFC 4271 §4.3 (1 = partial, 0 = complete)
ATTR_FLAG_EXTENDED_LEN = 0x10  # RFC 4271 §4.3 (1 = 2-octet length, 0 = 1-octet)
```

Well-known flag defaults per in-scope attribute (Optional/Transitive/Partial/
Extended-Length bits; Partial = 0 and Extended-Length = 0 by default):

```
ATTR_ORIGIN_FLAGS = 0x40  # well-known mandatory (transitive)
ATTR_AS_PATH_FLAGS = 0x40  # well-known mandatory (transitive)
ATTR_NEXT_HOP_FLAGS = 0x40  # well-known mandatory (transitive)
ATTR_MULTI_EXIT_DISC_FLAGS = 0x80  # optional non-transitive
ATTR_LOCAL_PREF_FLAGS = 0x40  # well-known discretionary (transitive)
ATTR_ATOMIC_AGGREGATE_FLAGS = 0x40  # well-known discretionary (transitive)
ATTR_AGGREGATOR_FLAGS = 0xC0  # optional transitive
ATTR_COMMUNITIES_FLAGS = 0xC0  # optional transitive
ATTR_MP_REACH_NLRI_FLAGS = 0x80  # optional non-transitive (RFC 4760 §3)
ATTR_MP_UNREACH_NLRI_FLAGS = 0x80  # optional non-transitive (RFC 4760 §4)
ATTR_EXTENDED_COMMUNITIES_FLAGS = 0xC0  # optional transitive
ATTR_AS4_PATH_FLAGS = 0xC0  # optional transitive (RFC 6793 §3)
ATTR_AS4_AGGREGATOR_FLAGS = 0xC0  # optional transitive (RFC 6793 §3)
ATTR_LARGE_COMMUNITY_FLAGS = 0xC0  # optional transitive
```

The builder selects extended length (sets `ATTR_FLAG_EXTENDED_LEN`)
automatically when a value exceeds 255 octets unless the caller overrides.

### ORIGIN values (attribute type 1, RFC 4271 §5.1.1)

```
ORIGIN_IGP = 0  # RFC 4271 §5.1.1
ORIGIN_EGP = 1  # RFC 4271 §5.1.1
ORIGIN_INCOMPLETE = 2  # RFC 4271 §5.1.1
```

### AS_PATH segment types (attribute type 2, RFC 4271 §5.1.2)

```
AS_PATH_SEG_AS_SET = 1  # RFC 4271 §4.3
AS_PATH_SEG_AS_SEQUENCE = 2  # RFC 4271 §4.3
AS_PATH_SEG_AS_CONFED_SEQUENCE = 3  # RFC 5065
AS_PATH_SEG_AS_CONFED_SET = 4  # RFC 5065
```

### Well-known COMMUNITIES (attribute type 8, RFC 1997)

```
COMMUNITY_NO_EXPORT = 0xFFFFFF01  # RFC 1997
COMMUNITY_NO_ADVERTISE = 0xFFFFFF02  # RFC 1997
COMMUNITY_NO_EXPORT_SUBCONFED = 0xFFFFFF03  # RFC 1997
```

## NOTIFICATION error codes (IANA `bgp-parameters-3`, RFC 4271 §6)

```
NOTIFY_MESSAGE_HEADER_ERROR = 1  # RFC 4271
NOTIFY_OPEN_MESSAGE_ERROR = 2  # RFC 4271
NOTIFY_UPDATE_MESSAGE_ERROR = 3  # RFC 4271
NOTIFY_HOLD_TIMER_EXPIRED = 4  # RFC 4271
NOTIFY_FSM_ERROR = 5  # RFC 4271
NOTIFY_CEASE = 6  # RFC 4271
NOTIFY_ROUTE_REFRESH_MESSAGE_ERROR = 7  # RFC 7313
NOTIFY_SEND_HOLD_TIMER_EXPIRED = 8  # RFC 9687
NOTIFY_LOSS_OF_LSDB_SYNC = 9  # RFC 9815
```

### Message Header Error subcodes (error code 1, IANA `bgp-parameters-5`, RFC 4271 §6.1)

```
MSG_HEADER_ERR_CONNECTION_NOT_SYNCHRONIZED = 1  # RFC 4271
MSG_HEADER_ERR_BAD_MESSAGE_LENGTH = 2  # RFC 4271
MSG_HEADER_ERR_BAD_MESSAGE_TYPE = 3  # RFC 4271
```

### OPEN Message Error subcodes (error code 2, IANA `bgp-parameters-6`, RFC 4271 §6.2)

```
OPEN_ERR_UNSUPPORTED_VERSION_NUMBER = 1  # RFC 4271
OPEN_ERR_BAD_PEER_AS = 2  # RFC 4271
OPEN_ERR_BAD_BGP_IDENTIFIER = 3  # RFC 4271
OPEN_ERR_UNSUPPORTED_OPTIONAL_PARAMETER = 4  # RFC 4271
OPEN_ERR_UNACCEPTABLE_HOLD_TIME = 6  # RFC 4271
OPEN_ERR_UNSUPPORTED_CAPABILITY = 7  # RFC 5492
OPEN_ERR_ROLE_MISMATCH = 11  # RFC 9234
```

### UPDATE Message Error subcodes (error code 3, IANA `bgp-parameters-7`, RFC 4271 §6.3)

```
UPDATE_ERR_MALFORMED_ATTRIBUTE_LIST = 1  # RFC 4271
UPDATE_ERR_UNRECOGNIZED_WELL_KNOWN_ATTRIBUTE = 2  # RFC 4271
UPDATE_ERR_MISSING_WELL_KNOWN_ATTRIBUTE = 3  # RFC 4271
UPDATE_ERR_ATTRIBUTE_FLAGS_ERROR = 4  # RFC 4271
UPDATE_ERR_ATTRIBUTE_LENGTH_ERROR = 5  # RFC 4271
UPDATE_ERR_INVALID_ORIGIN_ATTRIBUTE = 6  # RFC 4271
UPDATE_ERR_INVALID_NEXT_HOP_ATTRIBUTE = 8  # RFC 4271
UPDATE_ERR_OPTIONAL_ATTRIBUTE_ERROR = 9  # RFC 4271
UPDATE_ERR_INVALID_NETWORK_FIELD = 10  # RFC 4271
UPDATE_ERR_MALFORMED_AS_PATH = 11  # RFC 4271
```

### Finite State Machine Error subcodes (error code 5, IANA `bgp-finite-state-machine-error-subcodes`)

```
FSM_ERR_UNSPECIFIED = 0  # RFC 6608
FSM_ERR_UNEXPECTED_MESSAGE_IN_OPENSENT = 1  # RFC 6608
FSM_ERR_UNEXPECTED_MESSAGE_IN_OPENCONFIRM = 2  # RFC 6608
FSM_ERR_UNEXPECTED_MESSAGE_IN_ESTABLISHED = 3  # RFC 6608
```

### Cease subcodes (error code 6, IANA `bgp-parameters-8`)

```
CEASE_MAX_PREFIXES_REACHED = 1  # RFC 4486
CEASE_ADMINISTRATIVE_SHUTDOWN = 2  # RFC 4486 (RFC 9003)
CEASE_PEER_DECONFIGURED = 3  # RFC 4486
CEASE_ADMINISTRATIVE_RESET = 4  # RFC 4486 (RFC 9003)
CEASE_CONNECTION_REJECTED = 5  # RFC 4486
CEASE_OTHER_CONFIGURATION_CHANGE = 6  # RFC 4486
CEASE_CONNECTION_COLLISION_RESOLUTION = 7  # RFC 4486
CEASE_OUT_OF_RESOURCES = 8  # RFC 4486
CEASE_HARD_RESET = 9  # RFC 8538
CEASE_BFD_DOWN = 10  # RFC 9384
```

### ROUTE-REFRESH Message Error subcodes (error code 7, IANA `route-refresh-error-subcodes`)

```
ROUTE_REFRESH_ERR_INVALID_MESSAGE_LENGTH = 1  # RFC 7313
```

## ROUTE-REFRESH message subtypes (type 5 body, RFC 2918 / RFC 7313)

Body is `AFI(2) | Subtype/Reserved(1) | SAFI(1)` (RFC 2918 §3).

```
ROUTE_REFRESH_SUBTYPE_NORMAL = 0  # RFC 2918 (also RFC 5291)
ROUTE_REFRESH_SUBTYPE_BORR = 1  # RFC 7313
ROUTE_REFRESH_SUBTYPE_EORR = 2  # RFC 7313
```

## AFI values (IANA `address-family-numbers-2`)

```
AFI_IPV4 = 1  # IANA Address Family Numbers
AFI_IPV6 = 2  # IANA Address Family Numbers
```

## SAFI values (IANA `safi-namespace-2`)

```
SAFI_UNICAST = 1  # RFC 4760
SAFI_MULTICAST = 2  # RFC 4760
```

In-scope combinations: `<AFI_IPV4, SAFI_UNICAST>` and
`<AFI_IPV6, SAFI_UNICAST>` (RFC 4760; IPv6 usage per RFC 2545).
