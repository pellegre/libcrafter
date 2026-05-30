# UDP RFC Manifest

This manifest records the UDP behavior that `crafter` models for RFC-backed
compile, decode, display, fixture, and oracle work. It is intentionally narrow:
`crafter` stays a packet primitive, separates UDP from TCP, and exposes UDP
options as typed packet data rather than as an application workflow.

## Source Set

- RFC 768 defines UDP's base header, UDP Length, checksum pseudo-header, and
  protocol number 17.
- RFC 1122 requires hosts to implement UDP checksum generation and validation,
  to default UDP checksum generation on, and to discard datagrams with invalid
  nonzero checksums in normal stack operation.
- RFC 8200 defines the IPv6 pseudo-header checksum inputs and makes the UDP
  checksum mandatory for IPv6 by default.
- RFC 6935 and RFC 6936 define the narrow IPv6 zero-checksum exception for
  explicitly enabled tunnel use. `crafter` should inspect this condition
  distinctly from normal IPv4 zero-checksum UDP.
- RFC 1071 defines the Internet checksum algorithm. RFC 1141 and RFC 1624 cover
  incremental checksum update behavior that appears around NAT and middlebox
  edits.
- RFC 9868 updates RFC 768 by placing UDP options in the UDP surplus area after
  UDP user data and before the end of the IP transport payload.
- The IANA UDP Option Kind Numbers registry is the authority for current UDP
  option kind assignments. It was created 2025-03-25 and last updated
  2025-10-08 when this manifest was written.

## UDP Core Header

UDP is an 8-octet transport header followed by UDP user data:

| Field | Size | Source-backed behavior |
| --- | ---: | --- |
| Source Port | 16 bits | Optional in RFC 768; zero means unused. |
| Destination Port | 16 bits | Identifies the receiving process in the destination address context. |
| UDP Length | 16 bits | Length in octets of UDP header plus UDP user data. Minimum value is 8. |
| UDP Checksum | 16 bits | One's-complement checksum over the IP pseudo-header, UDP header, and UDP user data, with zero padding for odd byte counts. |

`crafter` compile should fill UDP Length and checksum when they are unset and
preserve explicit user-provided values, including deliberately malformed values
that fit the field. Decode should keep malformed packets inspectable with
structured status rather than panicking.

## Checksum Scope

For IPv4 UDP, RFC 768 allows a transmitted checksum field of zero to mean that
the sender did not generate a UDP checksum. If the computed checksum value is
zero, the transmitted field is all ones (`0xffff`), because zero has the
special no-checksum meaning.

RFC 1122 requires UDP checksum support and requires default checksum generation.
A received nonzero checksum that does not validate is a datagram error for an
operating-system UDP stack. In `crafter`, offline decode must remain
inspectable: an invalid checksum is represented in checksum status instead of
silently dropping the decoded packet.

For IPv6 UDP, RFC 8200 makes the checksum non-optional by default and requires
receivers to discard UDP packets whose checksum field is zero. RFC 6935 and
RFC 6936 allow zero UDP checksums only for explicitly enabled tunnel protocols
and port sets, with path and integrity constraints. `crafter` should therefore
distinguish at least these cases:

| Case | Decode status intent |
| --- | --- |
| IPv4 checksum field is zero | No UDP checksum was transmitted. |
| IPv4 or IPv6 checksum is nonzero and validates | Checksum valid. |
| IPv4 or IPv6 checksum is nonzero and fails | Checksum invalid, packet remains inspectable. |
| IPv6 checksum field is zero | IPv6 zero-checksum condition, not normal UDP unless an explicit exception model applies. |

The UDP checksum covers only the UDP header and UDP user data, plus the
addressing pseudo-header. It does not cover the RFC 9868 surplus option area.

## UDP Length And Surplus Area

RFC 9868 uses the difference between UDP Length and the enclosing IP transport
payload length to define an option trailer:

```text
IP transport payload = UDP header || UDP user data || surplus area
UDP Length           = len(UDP header || UDP user data)
surplus area         = IP transport payload bytes after UDP Length
```

Valid option-aware decoding requires `8 <= UDP Length <= IP transport payload
length`. If UDP Length equals the IP transport payload length, there is no
surplus area and UDP behaves like pre-options UDP. If UDP Length is smaller,
the bytes after UDP Length are the UDP surplus area. The surplus area can begin
at any valid byte offset; it does not need 16-bit or 32-bit alignment.

Application decoders consume only UDP user data:

```text
udp_user_data = ip_transport_payload[8..UDP Length]
udp_options   = ip_transport_payload[UDP Length..]
```

DNS, DHCP, and any other application decoder must never receive the surplus
area as application payload.

## UDP Surplus Area Structure

The surplus area begins with optional zero alignment bytes so that the Option
Checksum (OCS) starts on the first 2-byte boundary relative to the start of the
IP datagram. Alignment bytes before OCS must be zero; otherwise, all UDP
options are ignored and the surplus area is discarded for option processing.

OCS is a 16-bit Internet checksum over the surplus area, including the surplus
area length as a 16-bit value. OCS protects the option area that the UDP
checksum intentionally excludes. If the UDP checksum is nonzero, OCS must be
nonzero. If the UDP checksum is zero, OCS may be zero to indicate that OCS is
unused. On OCS validation failure, UDP user data is still delivered by default
when the UDP checksum is otherwise acceptable, but options are ignored.

After OCS, UDP options are interpreted in order. EOL and NOP are one-byte
options. Every other option uses:

```text
Kind: 1 byte
Length: 1 byte, total option length including Kind and Length
```

When Length is 255, the option uses the extended format:

```text
Kind: 1 byte
Length: 255
Extended Length: 16 bits, total option length
```

Option lengths smaller than the fixed minimum for that option, or lengths that
run past the surplus area, make the option area malformed.

## IANA UDP Option Kind Numbers

This table follows the IANA UDP Option Kind Numbers registry and RFC 9868. Kind
values 0 through 7 are must-support for implementations that support UDP
Options. `crafter` can recognize and preserve FRAG, but FRAG fragmentation and
reassembly are out of scope for this work.

| Kind | Length | Name | Scope for `crafter` |
| ---: | --- | --- | --- |
| 0 | implicit 1 | End of Options List (EOL) | Parse, build, stop option processing, require zero-fill after EOL on transmit. |
| 1 | implicit 1 | No Operation (NOP) | Parse and build as alignment padding; more than seven consecutive NOPs is notable. |
| 2 | 6 | Additional Payload Checksum (APC) | Parse and build CRC32c over UDP user data only; report validation status. |
| 3 | 10 or 12 | Fragmentation (FRAG) | Recognize and preserve or report unsupported. FRAG fragmentation, reassembly, fragment caches, timers, and delivery of FRAG data are out of scope. |
| 4 | 4 | Maximum Datagram Size (MDS) | Parse and build a 16-bit size hint. |
| 5 | 5 | Maximum Reassembled Datagram Size (MRDS) | Parse and build a 16-bit size plus 8-bit segment count. |
| 6 | 6 | Echo Request (REQ) | Parse and build a 32-bit token. No automatic RES generation. |
| 7 | 6 | Echo Response (RES) | Parse and build a 32-bit token supplied by the application. |
| 8 | 10 | Timestamp (TIME) | Parse and build 32-bit TSval and 32-bit TSecr values; zero values carry request/response meaning. |
| 9 | varies | Reserved for Authentication (AUTH) | Preserve as reserved SAFE option unless a future authenticated option model is added. |
| 10-126 | varies | Unassigned SAFE | Preserve unknown SAFE options and ignore for application delivery. |
| 127 | varies, minimum 4 | RFC 3692-style experiments (EXP) | Parse and build a 16-bit UDP ExID plus experiment bytes; extended length is allowed. |
| 128-191 | reserved | Reserved SAFE | Preserve as reserved SAFE option. |
| 192 | varies | Reserved for UNSAFE Compression (UCMP) | Treat as reserved UNSAFE; unsupported UNSAFE terminates option processing. |
| 193 | varies | Reserved for UNSAFE Encryption (UENC) | Treat as reserved UNSAFE; unsupported UNSAFE terminates option processing. |
| 194-253 | unassigned | Unassigned UNSAFE | Preserve enough to inspect; unsupported UNSAFE terminates option processing. |
| 254 | varies, minimum 4 | RFC 3692-style UNSAFE experiments (UEXP) | Parse and build a 16-bit UDP ExID plus experiment bytes; unsupported UNSAFE rules still apply. |
| 255 | reserved | Reserved UNSAFE | Preserve enough to inspect; unsupported UNSAFE terminates option processing. |

## Option Behavior Notes

EOL marks the end of options before the end of the surplus area. Bytes after
EOL are zero-fill; if a receiver checks them and finds nonzero bytes, the
option area is discarded while UDP user data is still delivered by default.

NOP is a one-byte alignment placeholder. It is not reported to the application.

APC is a CRC32c in network byte order over conventional UDP user data only. It
does not cover the pseudo-header, UDP header, or surplus area. An incorrect or
unrecognized APC length is reported as APC failure while the SAFE-option
default still delivers UDP user data unless configured otherwise.

MDS, MRDS, REQ, RES, and TIME have the fixed lengths shown in the IANA table.
EXP and UEXP carry a 16-bit UDP ExID followed by arbitrary experiment-defined
content; they may use the extended length format when required.

SAFE options use kind values 0 through 191 and are designed not to change UDP
user data semantics if ignored. Unknown SAFE options are preserved for
inspection and ignored for application delivery. UNSAFE options use kind values
192 through 255 and may change the user data meaning. RFC 9868 requires UNSAFE
options to be used only with UDP fragments; because `crafter` does not implement
UDP fragmentation/reassembly in this scope, unsupported UNSAFE options terminate
option processing and are surfaced as inspectable option status.

## Explicit Exclusion

FRAG support is limited to recognizing malformed and well-formed FRAG option
encodings with lengths 10 and 12. FRAG is out of scope for packet generation
that performs fragmentation, reassembly, fragment cache management, fragment
expiration, or delivery of FRAG-contained data as UDP user data.
