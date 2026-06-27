# SSDP Codepoint Authority Table

This document is the code-facing authority for SSDP constants, named helpers,
registry labels, fixture values, oracle specs, and examples. It is derived from
`.agents/docs/ssdp-source-manifest.md` and `.agents/docs/ssdp-wire-grammar.md`;
on disagreement, return to the manifest sources and update this handoff rather
than relying on memory.

SSDP-specific assignments come from OCF / UPnP Forum, "UPnP Device
Architecture 2.0" discovery clause 1 and Annex A, with UPnP Device
Architecture 1.1 and its Annex A used as compatibility evidence. UDP service
and multicast assignments are cross-checked against IANA registries. HTTP RFCs
and IANA HTTP registries are only support evidence for generic syntax and
registered generic values; absence from an HTTP registry is not a rejection rule
for a UPnP-defined SSDP value.

## Sources

- OCF / UPnP Forum, "UPnP Device Architecture 2.0",
  `https://openconnectivity.org/upnp-specs/UPnP-arch-DeviceArchitecture-v2.0-20200417.pdf`
- UPnP Forum, "UPnP Device Architecture 1.1",
  `https://upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1.pdf`
- UPnP Forum, "UPnP Device Architecture 1.1 Annex A - IPv6",
  `https://upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1-AnnexA.pdf`
- IANA Service Name and Transport Protocol Port Number Registry,
  `https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=ssdp`
- IANA IPv4 Multicast Address Space Registry,
  `https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml`
- IANA IPv6 Multicast Address Space Registry,
  `https://www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xhtml`
- IANA HTTP Method Registry,
  `https://www.iana.org/assignments/http-methods/http-methods.xhtml`
- IANA HTTP Field Name Registry,
  `https://www.iana.org/assignments/http-fields/http-fields.xhtml`
- IANA HTTP Status Code Registry,
  `https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml`
- RFC 9110, RFC 9112, RFC 3986, RFC 4291, RFC 5771, and RFC 2774 as classified
  by `.agents/docs/ssdp-source-manifest.md`.

## UDP Service And Multicast Values

These are the only default transport and multicast constants admitted for SSDP
packet helpers. `crafter` remains a packet primitive; these values do not imply
membership management, scanning, retry behavior, or live transmission defaults.

```
SSDP_SERVICE_NAME = "ssdp"  # IANA service registry
SSDP_UDP_PORT = 1900  # IANA ssdp/udp; UPnP discovery address and port
SSDP_IPV4_MULTICAST = "239.255.255.250"  # UPnP discovery; IANA scoped SSDP relative address
SSDP_IPV4_MULTICAST_HOST = "239.255.255.250:1900"  # UPnP discovery HOST value
SSDP_IPV6_MULTICAST_PATTERN = "ff0x::c"  # IANA IPv6 SSDP variable-scope assignment
SSDP_IPV6_LINK_LOCAL_MULTICAST = "ff02::c"  # IANA IPv6 SSDP; UPnP Annex A link scope
SSDP_IPV6_SITE_LOCAL_MULTICAST = "ff05::c"  # UPnP Annex A site scope
SSDP_IPV6_LINK_LOCAL_HOST = "[ff02::c]:1900"  # UPnP Annex A example HOST value
SSDP_IPV6_SITE_LOCAL_HOST = "[ff05::c]:1900"  # UPnP Annex A site-scope HOST value
```

Clarifications:

- `ssdp/tcp` port `1900` is registered by IANA, but this SSDP packet layer only
  admits the UDP service binding. Do not add TCP decode or send behavior from
  this table.
- `SEARCHPORT.UPNP.ORG` advertises a unicast M-SEARCH response UDP port in the
  range `49152..=65535` when port `1900` is unavailable. It is a header value,
  not another IANA SSDP service assignment.
- `TCPPORT.UPNP.ORG` is a UPnP Device Architecture 2.0 search-request header
  for TCP replies on `49152..=65535`. It is source-backed as a header name, but
  it is not a UDP service value and must not create a default TCP SSDP surface.
- IANA also assigns `FF0X:0:0:0:0:0:0:C` to SSDP. UDA 2.0 Annex A uses `X`
  values `2` and `5` for Link-Local and Site-Local scope. UDA 1.1 main text
  mentioned `ff0e::c` global scope, but later Annex A and UDA 2.0 say not to
  send Global scoped multicast messages; treat global-scope SSDP multicast as
  obsolete or ambiguous for helpers.
- Unknown or unusual SSDP-related ports and multicast groups can still be
  carried by the UDP/IP layers when the caller sets them explicitly; they are
  not named SSDP defaults.

## Start-Line Methods And Status

UPnP discovery admits three SSDP start-line families. RFC 9112 supplies the
generic request-line and status-line shape, while UPnP fixes the SSDP names.

```
SSDP_METHOD_NOTIFY = "NOTIFY"  # UPnP discovery notification request
SSDP_METHOD_M_SEARCH = "M-SEARCH"  # UPnP discovery search request
SSDP_HTTP_VERSION = "HTTP/1.1"  # UPnP SSDP start-line token
SSDP_STATUS_OK = 200  # UPnP search response; IANA/RFC 9110 status code
SSDP_REASON_OK = "OK"  # UPnP search response; IANA/RFC 9110 reason label
```

Clarifications:

- The IANA HTTP Method Registry does not assign `NOTIFY` or `M-SEARCH` as HTTP
  methods. They are still UPnP-defined SSDP methods.
- IANA's registered HTTP `SEARCH` method is not `M-SEARCH` and is not an SSDP
  alias.
- `HTTP/1.1 200 OK` is the only UPnP discovery response line admitted as a
  named status helper. Other structurally valid HTTP status codes and reason
  phrases are preserved as explicit or decoded values, not rejected merely
  because they are not SSDP discovery defaults.
- Search-request errors are handled operationally by silent discard in UPnP
  discovery; do not add SSDP error-response status helpers from generic HTTP.

## Notification And Target Values

These values are header-field values, not independent transports.

```
SSDP_NTS_ALIVE = "ssdp:alive"  # NOTIFY availability advertisement
SSDP_NTS_BYEBYE = "ssdp:byebye"  # NOTIFY withdrawal advertisement
SSDP_NTS_UPDATE = "ssdp:update"  # NOTIFY update advertisement
SSDP_MAN_DISCOVER = "\"ssdp:discover\""  # M-SEARCH MAN value, including quotes
SSDP_ST_ALL = "ssdp:all"  # M-SEARCH search target for all devices and services
SSDP_TARGET_ROOTDEVICE = "upnp:rootdevice"  # NT/ST root-device target
```

Source-backed dynamic target families:

- `uuid:device-UUID` for a device UUID target.
- `urn:schemas-upnp-org:device:deviceType:ver` for a UPnP Forum device type.
- `urn:schemas-upnp-org:service:serviceType:ver` for a UPnP Forum service type.
- `urn:domain-name:device:deviceType:ver` for a vendor device type.
- `urn:domain-name:service:serviceType:ver` for a vendor service type.
- `uuid:device-UUID::upnp:rootdevice` and `uuid:device-UUID::<target>` as USN
  composite identifiers for advertisements and responses.

Clarifications:

- `ssdp:all` is an `ST` search target, not an `NT` notification type.
- `upnp:event` and `upnp:propchange` belong to UPnP eventing examples, not SSDP
  discovery helpers, even though those messages can also use `NOTIFY`.
- Vendor and working-committee URNs are source-backed patterns. The packet
  layer must preserve unknown URI values and should not require a catalog of
  all device and service type names.

## Header Names

Header names are case-insensitive for lookup, but decoding and serialization
must preserve spelling, ordering, duplicates, and unknown extension fields.
UPnP defines SSDP use of the header fields below; generic HTTP field registry
status is only support evidence.

### Advertisement Headers

```
SSDP_HEADER_HOST = "HOST"
SSDP_HEADER_CACHE_CONTROL = "CACHE-CONTROL"
SSDP_HEADER_LOCATION = "LOCATION"
SSDP_HEADER_NT = "NT"
SSDP_HEADER_NTS = "NTS"
SSDP_HEADER_SERVER = "SERVER"
SSDP_HEADER_USN = "USN"
SSDP_HEADER_BOOTID = "BOOTID.UPNP.ORG"
SSDP_HEADER_CONFIGID = "CONFIGID.UPNP.ORG"
SSDP_HEADER_SEARCHPORT = "SEARCHPORT.UPNP.ORG"
SSDP_HEADER_NEXTBOOTID = "NEXTBOOTID.UPNP.ORG"
SSDP_HEADER_SECURELOCATION = "SECURELOCATION.UPNP.ORG"
```

Notes:

- `NEXTBOOTID.UPNP.ORG` is required only for `ssdp:update` messages.
- `SECURELOCATION.UPNP.ORG` is UDA 2.0 source-backed and required only when
  Device Protection is implemented; the packet layer should preserve it without
  implementing Device Protection.
- `BOOTID.UPNP.ORG` and `NEXTBOOTID.UPNP.ORG` values are non-negative 31-bit
  decimal integers in UPnP. `CONFIGID.UPNP.ORG` values above `16777215` are
  reserved for future UPnP Technical Committee assignment.
- `CACHE-CONTROL` uses the `max-age=` directive for SSDP advertisements and
  responses. Other directives are not named helpers; preserve caller-supplied
  values and decoded values for inspection.

### Search Request Headers

```
SSDP_HEADER_MAN = "MAN"
SSDP_HEADER_MX = "MX"
SSDP_HEADER_ST = "ST"
SSDP_HEADER_USER_AGENT = "USER-AGENT"
SSDP_HEADER_TCPPORT = "TCPPORT.UPNP.ORG"
SSDP_HEADER_CPFN = "CPFN.UPNP.ORG"
SSDP_HEADER_CPUUID = "CPUUID.UPNP.ORG"
```

Notes:

- `MAN` is an extension-style header whose SSDP search value is exactly
  `"ssdp:discover"` including double quotes.
- `MX` is a decimal second count. UPnP operational behavior treats values
  greater than `5` specially, but the packet layer preserves explicit values.
- `CPFN.UPNP.ORG`, `CPUUID.UPNP.ORG`, and `TCPPORT.UPNP.ORG` are UDA 2.0
  source-backed search-request headers. They are not present in the UDA 1.1
  search examples; treat them as versioned helpers and preserve them generally.

### Search Response Headers

```
SSDP_HEADER_DATE = "DATE"
SSDP_HEADER_EXT = "EXT"
```

Search responses also use `CACHE-CONTROL`, `LOCATION`, `SERVER`, `ST`, `USN`,
`BOOTID.UPNP.ORG`, `CONFIGID.UPNP.ORG`, `SEARCHPORT.UPNP.ORG`, and
`SECURELOCATION.UPNP.ORG` as listed above. `EXT` is an empty field retained for
UPnP 1.0 compatibility; do not invent a value when serializing an unset one.

### IPv6 Extension Headers

```
SSDP_HEADER_OPT = "OPT"
SSDP_HEADER_NLS_SUFFIX = "NLS"
```

UPnP Annex A uses RFC 2774-style extension syntax for IPv6 compatibility. The
wire field for NLS is namespace-prefixed, for example:

```
OPT: "http://schemas.upnp.org/upnp/1/0/"; ns=01
01-NLS: same value as BOOTID field value
```

Do not treat `01` as a fixed codepoint. Preserve any structurally valid
namespace-prefixed `*-NLS` field as an extension header. RFC 2774 is historical
context only; do not implement generic HTTP extension processing from this
table.

### Vendor And Unknown Headers

UPnP allows vendor or working-committee SSDP header field names of the form
`token "." domain-name`. Unknown header names, unknown values, duplicate header
instances, obsolete-but-structurally-valid extension headers, and non-canonical
casing are preserved. A later helper may assign semantics only after a public
source admits the specific field.

## Reserved, Obsolete, Ambiguous, And Excluded Values

- Unknown SSDP methods, status codes, reason phrases, headers, extension
  values, and bodies are preserved when the enclosing message is structurally
  valid.
- Draft-only SSDP material from expired Internet-Drafts is historical or
  ambiguous. Do not add named helpers for draft-only methods, headers, status
  labels, ports, or multicast values unless a later source-scope step admits
  them.
- `ff0e::c` global-scope SSDP multicast is obsolete or ambiguous for helper
  generation because UDA 2.0 Annex A prohibits Global scoped multicast
  messages.
- Eventing-only values such as `upnp:event`, `upnp:propchange`, `SVCID`, `SEQ`,
  `LVL`, `CONTENT-LENGTH`, `CONTENT-TYPE`, and multicast eventing destinations
  such as `[ff0x::130]:7900` are not SSDP discovery codepoints.
- Generic HTTP methods, HTTP status codes, and HTTP field names are not SSDP
  discovery assignments unless UPnP discovery text uses them for SSDP. Preserve
  structurally valid unknowns; do not silently normalize them into named SSDP
  helpers.
