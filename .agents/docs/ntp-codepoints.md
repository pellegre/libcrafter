# NTP Codepoint Authority Table

This document is the code-facing authority for NTP constants, registry labels,
fixture values, oracle specs, summaries, and examples. It is derived from
`.agents/docs/ntp-rfc-manifest.md` and `.agents/docs/ntp-wire-grammar.md`; on
disagreement, return to the manifest sources and current IANA registries before
changing packet behavior.

Review date: 2026-07-01.

## Sources

- RFC 5905, Sections 7.3 and 7.4, for fixed-header LI, version, mode, stratum,
  reference ID, and Kiss-o'-Death packet meaning.
- RFC 7821 for the UDP Checksum Complement extension field body.
- RFC 7822 for NTP Extension Field framing and unknown extension handling.
- RFC 8915 for NTS packet extension field types carried inside NTPv4 packets.
- RFC 9748 for current NTP registry cleanup, historical reservations, private
  ranges, and registration-policy changes.
- IANA "Network Time Protocol (NTP) Parameters", created 2010-03-25 and last
  updated 2026-01-07 when reviewed:
  `https://www.iana.org/assignments/ntp-parameters/ntp-parameters.xhtml`.
- IANA "Network Time Security (NTS)", last updated 2026-06-02 when reviewed:
  `https://www.iana.org/assignments/nts/nts.xhtml`. This is context for
  NTS-KE registries only; NTP packet extension field types are in the IANA NTP
  Parameters registry.
- IANA "Service Name and Transport Protocol Port Number Registry", `ntp` rows
  for TCP/123 and UDP/123, last updated 2026-06-17 when reviewed.

## Global Preservation Policy

`crafter` is a packet primitive. Registry labels improve inspection, but they
are not parser gates by themselves. Unknown but structurally valid values must
be preserved byte-for-byte and shown with stable fallback labels.

Fallback labels:

```
LI fallback: no unknown numeric values; reserved or alarm values keep labels
Version fallback: version-<n>
Mode fallback: mode-<n>
Stratum fallback: stratum-<n>
Reference ID fallback: refid-0xXXXXXXXX
Kiss-o'-Death fallback: kod-0xXXXXXXXX
Extension Field Type fallback: extension-field-0xNNNN
NTS extension body fallback: nts-extension-0xNNNN
Service fallback: port-<n>/<proto>
```

Reserved, private-use, historic, duplicated, and future values are still
structurally valid when their enclosing wire grammar is valid. Builders must
preserve explicit caller values even when the value would be unusual or
malformed for a live NTP peer. Defaults may emit only the source-backed values
selected by later implementation steps.

## Service Port Constants

These are transport service constants, not live-send permission. UDP/123 is the
only default NTP application decode binding planned for the packet layer.
TCP/123 is recorded as an IANA service-registry fact only; it does not authorize
a TCP NTP stream parser.

```
NTP_SERVICE_NAME = "ntp"  # IANA service registry
NTP_UDP_PORT = 123  # IANA ntp/udp; RFC 5905
NTP_TCP_PORT = 123  # IANA ntp/tcp registry fact only
```

Unknown or non-default ports remain UDP or TCP layer values. They are not named
NTP service defaults, but explicitly supplied values must not be rewritten.

## Leap Indicator Values

The Leap Indicator is the high two bits of the first fixed-header octet. All
two-bit values are defined by RFC 5905 Section 7.3 and must be preserved.

```
NTP_LI_NO_WARNING = 0  # no warning
NTP_LI_LAST_MINUTE_61_SECONDS = 1  # last minute has 61 seconds
NTP_LI_LAST_MINUTE_59_SECONDS = 2  # last minute has 59 seconds
NTP_LI_ALARM_UNSYNCHRONIZED = 3  # alarm condition / clock unsynchronized
```

Unknown-value policy: there are no values outside the two-bit LI space during
wire parsing. Display must still avoid treating `3` as malformed; show it with
the stable alarm/unsynchronized label and preserve it byte-for-byte.

## Version Handling

The Version Number is the middle three bits of the first fixed-header octet.
RFC 5905 defines version 4 as the current NTP version. Older NTP/SNTP-shaped
packets and future values are structurally valid packet data when the rest of
the packet shape is valid.

```
NTP_VERSION_CURRENT = 4  # RFC 5905 NTPv4
```

Known display labels:

| Value | Label | Policy |
| ---: | --- | --- |
| 0 | `version-0` | Preserve. Do not emit as a default. |
| 1 | `ntp-v1` | Preserve for legacy-shaped packets. |
| 2 | `ntp-v2` | Preserve for legacy-shaped packets. |
| 3 | `ntp-v3` | Preserve for NTPv3/SNTP-compatible packets. |
| 4 | `ntp-v4` | Default version for constructed NTP packets. |
| 5-7 | `version-<n>` | Preserve as future or unknown values. |

Unknown-value policy: preserve every three-bit version value. Do not fail
decode or raw-fallback solely because the version is not 4.

## Mode Values

The Mode field is the low three bits of the first fixed-header octet. RFC 5905
Section 7.3 defines the full three-bit mode space.

```
NTP_MODE_RESERVED = 0
NTP_MODE_SYMMETRIC_ACTIVE = 1
NTP_MODE_SYMMETRIC_PASSIVE = 2
NTP_MODE_CLIENT = 3
NTP_MODE_SERVER = 4
NTP_MODE_BROADCAST = 5
NTP_MODE_CONTROL = 6
NTP_MODE_PRIVATE = 7
```

Unknown-value policy: there are no values outside the three-bit mode space
during wire parsing. Reserved and private-use mode values must be preserved and
shown with stable labels, not rejected.

## Stratum Ranges

Stratum is an unsigned fixed-header octet. It is inspectable packet data, not a
parser gate.

| Value | Label | Source-backed meaning |
| ---: | --- | --- |
| 0 | `unspecified-or-invalid` | KoD or otherwise unspecified/invalid stratum. |
| 1 | `primary` | Primary server or reference clock. |
| 2-15 | `secondary` | Secondary server via NTP. |
| 16 | `unsynchronized` | Unsynchronized. |
| 17-255 | `reserved` | Reserved by RFC 5905. |

Unknown-value policy: every `u8` stratum is structurally valid packet data.
Preserve and display unhandled values as `stratum-<n>` with the range label
when applicable.

## NTP Reference Identifier Codes

The Reference ID field is always four octets. Interpretation is stratum
dependent. For stratum 1, IANA "NTP Reference Identifier Codes" supplies the
current reference-clock labels. RFC 9748 says reference ID registry entries are
up to four ASCII uppercase letters or digits padded on the right with zero
octets; IDs beginning with uppercase `X` are reserved for private or
experimental use and IANA cannot assign them.

IANA entries reviewed on 2026-07-01:

| ID | Label |
| --- | --- |
| `GOES` | Geosynchronous Orbit Environment Satellite |
| `GPS` | Global Position System |
| `GAL` | Galileo Positioning System |
| `PPS` | Generic pulse-per-second |
| `IRIG` | Inter-Range Instrumentation Group |
| `WWVB` | LF Radio WWVB Ft. Collins, CO 60 kHz |
| `DCF` | LF Radio DCF77 Mainflingen, DE 77.5 kHz |
| `HBG` | LF Radio HBG Prangins, HB 75 kHz |
| `MSF` | LF Radio MSF Anthorn, UK 60 kHz |
| `JJY` | LF Radio JJY Fukushima, JP 40 kHz, Saga, JP 60 kHz |
| `LORC` | MF Radio LORAN C station, 100 kHz |
| `TDF` | MF Radio Allouis, FR 162 kHz |
| `CHU` | HF Radio CHU Ottawa, Ontario |
| `WWV` | HF Radio WWV Ft. Collins, CO |
| `WWVH` | HF Radio WWVH Kauai, HI |
| `NIST` | NIST telephone modem |
| `ACTS` | NIST telephone modem |
| `USNO` | USNO telephone modem |
| `PTB` | European telephone modem |
| `DFM` | UTC(DFM) |

Secondary-server Reference IDs are not values from this IANA table: for IPv4
they can carry the server IPv4 address, and for IPv6 they can carry the first
four octets of the MD5 hash of the IPv6 address. The packet layer must not try
to infer or validate the lower-layer address from those bytes.

Unknown-value policy: preserve all four raw bytes. If the stratum implies a
reference-clock ID and the bytes do not match a known IANA row, display
`refid-0xXXXXXXXX`; if the first non-padding byte is `X`, include a
private-or-experimental label without rejecting the packet.

## Kiss-o'-Death Reference Identifiers

For stratum 0 packets, the Reference ID carries a Kiss-o'-Death code. IANA "NTP
Kiss-o'-Death Codes" supplies current labels, and RFC 8915 adds `NTSN`.
RFC 9748 applies the same uppercase letter/digit, zero-padding, and
uppercase-`X` private/experimental reservation policy used by reference-clock
IDs.

IANA entries reviewed on 2026-07-01:

| Code | Meaning |
| --- | --- |
| `ACST` | The association belongs to a unicast server |
| `AUTH` | Server authentication failed |
| `AUTO` | Autokey sequence failed |
| `BCST` | The association belongs to a broadcast server |
| `CRYP` | Cryptographic authentication or identification failed |
| `DENY` | Access denied by remote server |
| `DROP` | Lost peer in symmetric mode |
| `RSTR` | Access denied due to local policy |
| `INIT` | The association has not yet synchronized for the first time |
| `MCST` | The association belongs to a dynamically discovered server |
| `NKEY` | No key found or not trusted |
| `NTSN` | Network Time Security negative acknowledgment |
| `RATE` | Rate exceeded |
| `RMOT` | Alteration of association from a remote host running ntpdc |
| `STEP` | Step change in system time before resynchronization |

Unknown-value policy: preserve all four raw bytes. Unregistered codes display
as `kod-0xXXXXXXXX`; uppercase-`X` codes additionally show
private-or-experimental. Do not implement KoD client behavior such as
demobilizing associations or changing polling intervals in this crate.

## NTP Extension Field Types

NTP Extension Field Types are unsigned 16-bit values in the RFC 7822 extension
field envelope. RFC 9748 is the current registry-correction source. It changes
the registration policy to Specification Required, marks historically erroneous
Autokey values as reserved, records the duplicate `0x0204` assignment, and
reserves `0xF000..=0xFFFF` for private or experimental use.

Extension Field type classes for packet-layer labeling:

| Range or pattern | Class | Policy |
| --- | --- | --- |
| `0x0000` | Crypto-NAK | Preserve and label; model as raw extension/tail data only. |
| `0x0001..=0x7FFF` | Request, NTS, checksum, or other extension | Label known IANA rows; preserve unknown rows. |
| `0x8000..=0xBFFF` | Response-style Autokey space | Label known IANA rows; preserve raw data; no Autokey workflow. |
| `0xC000..=0xEFFF` | Error-response-style Autokey space | Label known IANA rows; preserve raw data; no Autokey workflow. |
| `0xF000..=0xFFFF` | Private or Experimental Use | Preserve and display as private/experimental. |

Current IANA rows reviewed on 2026-07-01:

| Type | Label | Source |
| --- | --- | --- |
| `0x0000` | Crypto-NAK; authentication failure | RFC 5905 |
| `0x0002` | Reserved for historic reasons | RFC 9748 |
| `0x0102` | Reserved for historic reasons | RFC 9748 |
| `0x0104` | Unique Identifier | RFC 8915 Section 5.3 |
| `0x010A` | Network Correction | draft RFC-ietf-ntp-over-ptp-08 |
| `0x0200` | No-Operation Request | RFC 5906 |
| `0x0201` | Association Message Request | RFC 5906 |
| `0x0202` | Certificate Message Request | RFC 5906 |
| `0x0203` | Cookie Message Request | RFC 5906 |
| `0x0204` | Autokey Message Request | RFC 5906 |
| `0x0204` | NTS Cookie | RFC 8915 Section 5.4 |
| `0x0205` | Leapseconds Message Request | RFC 5906 |
| `0x0206` | Sign Message Request | RFC 5906 |
| `0x0207` | IFF Identity Message Request | RFC 5906 |
| `0x0208` | GQ Identity Message Request | RFC 5906 |
| `0x0209` | MV Identity Message Request | RFC 5906 |
| `0x0302` | Reserved for historic reasons | RFC 9748 |
| `0x0304` | NTS Cookie Placeholder | RFC 8915 Section 5.5 |
| `0x0402` | Reserved for historic reasons | RFC 9748 |
| `0x0404` | NTS Authenticator and Encrypted Extension Fields | RFC 8915 Section 5.6 |
| `0x0502` | Reserved for historic reasons | RFC 9748 |
| `0x0602` | Reserved for historic reasons | RFC 9748 |
| `0x0702` | Reserved for historic reasons | RFC 9748 |
| `0x0802` | Reserved for historic reasons | RFC 9748 |
| `0x0902` | Reserved for historic reasons | RFC 9748 |
| `0x2005` | UDP Checksum Complement | RFC 7821 |
| `0x8002` | Reserved for historic reasons | RFC 9748 |
| `0x8102` | Reserved for historic reasons | RFC 9748 |
| `0x8200` | No-Operation Response | RFC 5906 |
| `0x8201` | Association Message Response | RFC 5906 |
| `0x8202` | Certificate Message Response | RFC 5906 |
| `0x8203` | Cookie Message Response | RFC 5906 |
| `0x8204` | Autokey Message Response | RFC 5906 |
| `0x8205` | Leapseconds Message Response | RFC 5906 |
| `0x8206` | Sign Message Response | RFC 5906 |
| `0x8207` | IFF Identity Message Response | RFC 5906 |
| `0x8208` | GQ Identity Message Response | RFC 5906 |
| `0x8209` | MV Identity Message Response | RFC 5906 |
| `0x8302` | Reserved for historic reasons | RFC 9748 |
| `0x8402` | Reserved for historic reasons | RFC 9748 |
| `0x8502` | Reserved for historic reasons | RFC 9748 |
| `0x8602` | Reserved for historic reasons | RFC 9748 |
| `0x8702` | Reserved for historic reasons | RFC 9748 |
| `0x8802` | Reserved for historic reasons | RFC 9748 |
| `0x8902` | Reserved for historic reasons | RFC 9748 |
| `0xC002` | Reserved for historic reasons | RFC 9748 |
| `0xC102` | Reserved for historic reasons | RFC 9748 |
| `0xC200` | No-Operation Error Response | RFC 5906 |
| `0xC201` | Association Message Error Response | RFC 5906 |
| `0xC202` | Certificate Message Error Response | RFC 5906 |
| `0xC203` | Cookie Message Error Response | RFC 5906 |
| `0xC204` | Autokey Message Error Response | RFC 5906 |
| `0xC205` | Leapseconds Message Error Response | RFC 5906 |
| `0xC206` | Sign Message Error Response | RFC 5906 |
| `0xC207` | IFF Identity Message Error Response | RFC 5906 |
| `0xC208` | GQ Identity Message Error Response | RFC 5906 |
| `0xC209` | MV Identity Message Error Response | RFC 5906 |
| `0xC302` | Reserved for historic reasons | RFC 9748 |
| `0xC402` | Reserved for historic reasons | RFC 9748 |
| `0xC502` | Reserved for historic reasons | RFC 9748 |
| `0xC602` | Reserved for historic reasons | RFC 9748 |
| `0xC702` | Reserved for historic reasons | RFC 9748 |
| `0xC802` | Reserved for historic reasons | RFC 9748 |
| `0xC902` | Reserved for historic reasons | RFC 9748 |
| `0xF000-0xFFFF` | Reserved for Private or Experimental Use | RFC 9748 |

Unknown-value policy: preserve the 16-bit field type and the full extension
field bytes whenever length and alignment rules are structurally valid. Display
unassigned values as `extension-field-0xNNNN`, with a private/experimental
suffix for `0xF000..=0xFFFF`. Reserved-for-historic values are labels, not
decode failures.

## NTS Extension Field Types

NTS packet extension fields use the normal NTP Extension Field envelope. The
NTS-KE record-type, next-protocol, error-code, and warning-code registries are
not NTP packet extension field registries and must not add crate-level NTS-KE
workflow behavior.

```
NTP_EXT_UNIQUE_IDENTIFIER = 0x0104  # RFC 8915 Section 5.3
NTP_EXT_NTS_COOKIE = 0x0204  # RFC 8915 Section 5.4; duplicates Autokey request
NTP_EXT_NTS_COOKIE_PLACEHOLDER = 0x0304  # RFC 8915 Section 5.5
NTP_EXT_NTS_AUTHENTICATOR = 0x0404  # RFC 8915 Section 5.6
```

Unknown-value policy: preserve NTS extension bodies as raw bytes. Do not
implement NTS-KE, AEAD encryption/decryption, cookie construction, replay-cache
decisions, or authentication decisions. When a known NTS type carries a body
that a later helper does not understand, display `nts-extension-0xNNNN` plus
the known type label and preserve the bytes.

## UDP Checksum Complement Extension

The UDP Checksum Complement extension field type is assigned in the NTP
Extension Field Types registry and defined by RFC 7821. It affects the UDP
checksum relationship, but checksum calculation remains the UDP layer's job.

```
NTP_EXT_UDP_CHECKSUM_COMPLEMENT = 0x2005
```

Unknown-value policy: only `0x2005` receives the checksum-complement label.
Other structurally valid field types remain raw-preserving extension fields
with the fallback label described above.

