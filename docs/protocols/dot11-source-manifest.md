# Dot11 Source Manifest

This manifest records the authoritative sources for phase 1 through phase 1.5
IEEE 802.11 support. Later implementation steps should update this file before
adding wire behavior that is not covered here.

Implementation code, packet dissectors, packet generators, blog posts, and
third-party examples are not protocol authority for this work. When sources
conflict, the applicable IEEE standard or registry entry wins over explanatory
material.

## IEEE 802.11 MAC and RSN

Source:

- IEEE Std 802.11-2024, `IEEE Standard for Information Technology--
  Telecommunications and Information Exchange between Systems Local and
  Metropolitan Area Networks--Specific Requirements Part 11: Wireless LAN
  Medium Access Control (MAC) and Physical Layer (PHY) Specifications`.
  https://standards.ieee.org/ieee/802.11/10548/
- IEEE 802.11 working group standards list and publication status.
  http://www.ieee802.org/11/

Governs:

- IEEE 802.11 MAC header layout, frame-control field layout, protocol version,
  type and subtype values, To DS, From DS, More Fragments, Retry, Power
  Management, More Data, Protected Frame, and +HTC/Order bits.
- Duration/ID, Address 1 through Address 4, Sequence Control, fragment number,
  sequence number, QoS Control, and HT Control presence rules.
- QoS Control field layout for QoS data subtypes: TID in bits 0 through 3,
  EOSP in bit 4, ACK policy in bits 5 through 6, A-MSDU Present in bit 7, and
  the context-dependent TXOP/queue-size octet in bits 8 through 15.
- Management, control, and data frame type/subtype codepoints and subtype
  minimum header lengths.
- Management fixed fields and tagged parameters/elements used by selected
  beacon, probe, association, authentication, disassociation, and deauth frames.
- RSN information element syntax, including element ID, version, group data
  cipher suite, pairwise cipher suite list, AKM suite list, RSN capabilities,
  PMKID list, and group management cipher suite.
- RSN cipher suite selectors and AKM suite selectors, including the OUI plus
  one-octet suite type shape.
- RSNA EAPOL-Key descriptor fields needed for phase 1.5 parsing: descriptor
  type, Key Information, key length, replay counter, nonce, EAPOL-Key IV, key
  RSC, key ID, key MIC, key data length, and key data bytes.

Known ambiguity or deferred behavior:

- This phase supports packet construction, decoding, inspection, pcap storage,
  and decrypt-ready metadata boundaries only. WPA/WPA2/WPA3 plaintext recovery,
  password cracking, association state machines, scanning, channel hopping, and
  autonomous live capture are out of scope.
- Protected data frame bodies decode as `Raw` until a later explicit decrypt
  primitive exists. The Protected Frame bit remains visible.
- Fragment reassembly, A-MSDU reassembly, mesh-specific address semantics,
  multi-link operation, EHT/802.11be-specific fields, and newer amendment-only
  features are deferred unless a later source-manifest update narrows the
  implemented subset.
- `protected` is the preferred public term for the IEEE 802.11 protected-frame
  bit. Older names such as WEP are too narrow for new APIs.
- FCS generation/validation is not required for phase 1. FCS presence must stay
  observable when a capture source exposes it through radiotap metadata.

## Radiotap

Sources:

- Radiotap introduction and header rules. https://www.radiotap.org/
- Radiotap defined fields registry. https://www.radiotap.org/fields/defined
- Radiotap Flags field. https://www.radiotap.org/fields/Flags.html
- Radiotap Channel field. https://www.radiotap.org/fields/Channel.html
- Radiotap RX flags field. https://www.radiotap.org/fields/RX%20flags.html
- Radiotap TX flags field. https://www.radiotap.org/fields/TX%20flags.html
- Linux mac80211 packet injection documentation for monitor-mode injection
  behavior. https://www.kernel.org/doc/html/latest/networking/mac80211-injection.html

Governs:

- Radiotap base header fields: version, pad, length, and little-endian present
  bitmap words.
- Extended present bitmap chaining through bit 31 of each present word.
- Field ordering by present-bit number, little-endian encoding, implicit field
  lengths, and natural alignment padding.
- Selected typed fields for phase 1: TSFT, Flags, Rate, Channel, Antenna
  signal, Antenna, RX flags, and TX flags.
- FCS metadata: radiotap Flags bit `0x10` means the frame includes FCS, and
  radiotap Flags bit `0x40` means the frame failed the FCS check.
- Monitor-mode injection packet shape on Linux: radiotap header followed by
  IEEE 802.11 header followed by payload.
- mac80211 injection handling for selected radiotap fields such as Flags,
  TX flags, Rate, MCS, data retries, and VHT, while unknown or unused fields may
  be skipped by the kernel.

Known ambiguity or deferred behavior:

- Radiotap field lengths are implicit. Unknown fields cannot be decoded safely
  without field definitions, so decoders should preserve the radiotap header
  bytes and skip to `it_len` for unrecognized present bits.
- Decoding must not reject, strip, or mutate the 802.11 payload solely because
  FCS-present or failed-FCS metadata is present.
- Radiotap must not invent channel, signal, rate, FCS, antenna, retry, or
  similar metadata during compile when the caller did not set those fields.
- Vendor namespace, radiotap namespace, TLV fields, HE, EHT, S1G, and full
  MCS/VHT/HE/EHT typed support are deferred unless explicitly added to this
  manifest.
- Automated tests must not require monitor mode or Wi-Fi hardware. Live
  injection is manual and safety-gated.

## IEEE 802.2 LLC

Sources:

- IEEE/ISO/IEC 8802-2-1998, `Information technology --
  Telecommunications and information exchange between systems -- Local and
  metropolitan area networks -- Specific requirements -- Part 2: Logical Link
  Control`. https://standards.ieee.org/ieee/8802-2/2349/
- IEEE 802 Numbers registry, Logical Link Control numbers.
  https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml

Governs:

- LLC PDU structure and the DSAP, SSAP, and Control fields.
- Type 1 unnumbered information service used with SNAP encapsulation.
- LSAP/SAP registry values where a later implementation needs non-SNAP LLC
  dispatch.

Known ambiguity or deferred behavior:

- Phase 1 implements the SNAP-bearing LLC shape needed for IEEE 802.11 data
  payload dispatch. Full LLC class 1, class 2, class 3, XID, TEST, and non-SNAP
  protocol dispatch are deferred.
- Non-SNAP DSAP/SSAP/control combinations should preserve their body as `Raw`
  unless a later manifest update defines a typed decoder.

## RFC 1042 SNAP

Source:

- RFC 1042, `Standard for the transmission of IP datagrams over IEEE 802
  networks`. https://www.rfc-editor.org/rfc/rfc1042
- RFC 9542, `IANA Considerations and IETF Protocol and Documentation Usage for
  IEEE 802 Parameters`. https://www.rfc-editor.org/rfc/rfc9542.html

Governs:

- SNAP over LLC with DSAP `0xaa`, SSAP `0xaa`, Control `0x03`, three-octet OUI,
  and two-octet protocol identifier.
- RFC 1042 all-zero OUI (`00-00-00`) followed by an EtherType for IP and ARP
  over IEEE 802 networks.
- The eight-octet LLC plus SNAP overhead: DSAP, SSAP, Control, OUI, and
  EtherType.
- RFC 9542 general OUI-based protocol identifier shape and the all-zero OUI
  plus EtherType form for SNAP.

Known ambiguity or deferred behavior:

- RFC 1042 specifically covers IP and ARP over IEEE 802 networks. IPv6 and
  EAPOL use the same explicit LLC/SNAP EtherType bridge in this project, but
  their EtherType values are governed by IEEE/IANA registries and IEEE 802.1X,
  not by RFC 1042 itself.
- `Dot11 / Ipv4`, `Dot11 / Ipv6`, `Dot11 / Arp`, and `Dot11 / Eapol` must not
  infer LLC/SNAP implicitly. The stack must carry `LlcSnap` explicitly.
- Non-zero OUIs, unknown OUIs, and unknown protocol identifiers should preserve
  payload bytes unless a later source-manifest entry defines typed dispatch.

## IEEE 802.1X EAPOL

Sources:

- IEEE Std 802.1X-2020, `Port-Based Network Access Control`.
  https://standards.ieee.org/ieee/802.1X/7345/
- IEEE 802.1 working group 802.1X page.
  https://1.ieee802.org/security/802-1x/
- IANA IEEE 802 Numbers EtherTypes registry.
  https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml

Governs:

- EAPOL base header fields: protocol version, packet type, and packet body
  length.
- EAPOL packet types needed for phase 1.5: EAP-Packet, EAPOL-Start,
  EAPOL-Logoff, EAPOL-Key, and unknown packet-type preservation.
- The IEEE 802.1X EtherType `0x888e` for EAPOL carriage through LLC/SNAP.
- Relationship between IEEE 802.1X EAPOL and EAP as a carried authentication
  protocol.

Known ambiguity or deferred behavior:

- Phase 1.5 parses EAPOL and RSN EAPOL-Key enough to inspect handshakes and
  preserve bytes. It does not implement a supplicant, authenticator, key
  negotiation, MACsec MKA workflow, or decrypt operation.
- Unknown EAPOL packet types should produce a typed EAPOL layer plus `Raw` body
  preservation where the base header length is valid.
- EAP method parsing is deferred except for preserving EAP-Packet bytes.

## EtherTypes

Sources:

- IANA IEEE 802 Numbers EtherTypes registry.
  https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
- RFC 9542, especially the EtherType and SNAP/OUI guidance.
  https://www.rfc-editor.org/rfc/rfc9542.html
- IEEE Registration Authority EtherType process.
  https://standards.ieee.org/products-programs/regauth/ethertype/

Governs:

- IPv4 EtherType `0x0800`.
- ARP EtherType `0x0806`.
- IPv6 EtherType `0x86dd`.
- EAPOL EtherType `0x888e`.
- IEEE 802.11 pre-authentication EtherType `0x88c7` is noted but not in scope
  for phase 1.5.
- Local experimental EtherTypes `0x88b5` and `0x88b6` are reserved for local
  experimental use but must not be emitted by defaults.
- OUI Extended EtherType `0x88b7` is noted but not in scope for initial
  LLC/SNAP dispatch.

Known ambiguity or deferred behavior:

- IANA notes that the IEEE 802 Numbers EtherTypes list is informational for
  assignments controlled by the IEEE Registration Authority. Values used here
  should be treated as registry-backed constants, and additions should cite the
  IEEE RA or current registry entry.
- Unknown EtherTypes carried by LLC/SNAP should decode as `Raw` after the
  typed `LlcSnap` layer.

## OUIs and Suite Selectors

Sources:

- IEEE Registration Authority FAQs and public listing guidance.
  https://standards.ieee.org/faqs/regauth/
- IEEE RA public assignment listings.
  https://regauth.standards.ieee.org/
- RFC 9542 OUI, CID, documentation, and OUI-based parameter guidance.
  https://www.rfc-editor.org/rfc/rfc9542.html
- IEEE Std 802.11-2024 for RSN cipher and AKM suite selector meanings.
  https://standards.ieee.org/ieee/802.11/10548/

Governs:

- EUI-48/MAC address assignment terminology and OUI public listing source.
- OUI shape as a 24-bit identifier used in SNAP protocol identifiers and RSN
  suite selectors.
- RSN cipher and AKM suite selector shape: three-octet OUI plus one-octet
  suite type.
- Documentation-oriented OUI and protocol number guidance from RFC 9542 where
  tests or examples need non-real identifiers.

Known ambiguity or deferred behavior:

- The all-zero OUI has a special SNAP meaning when followed by an EtherType; it
  must not be treated as an ordinary assigned organization in that context.
- No real vendor OUIs are required for tests. Synthetic fixtures should use
  documentation-safe addresses and standard OUIs only where a protocol requires
  them.
- Vendor-specific RSN suites and vendor-specific management elements should be
  preserved but not interpreted until a source-manifest update names the
  governing source.

## libpcap LINKTYPE and DLT Values

Sources:

- tcpdump/libpcap link-layer header type registry.
  https://www.tcpdump.org/linktypes.html
- libpcap `pcap/dlt.h` source for DLT constants.
  https://raw.githubusercontent.com/the-tcpdump-group/libpcap/master/pcap/dlt.h

Governs:

- Bare IEEE 802.11 pcap link type: `LINKTYPE_IEEE802_11` / `DLT_IEEE802_11`
  value `105`.
- Radiotap-wrapped IEEE 802.11 pcap link type:
  `LINKTYPE_IEEE802_11_RADIOTAP` / `DLT_IEEE802_11_RADIO` value `127`.
- The captured byte shape associated with those link types: bare IEEE 802.11
  MAC frame for value `105`, and radiotap header followed by IEEE 802.11 MAC
  frame for value `127`.

Known ambiguity or deferred behavior:

- Other 802.11-related link types, including Prism, AVS, PPI, and vendor radio
  headers, are out of scope for phase 1.5.
- Classic pcap support is in scope. Full pcapng interface metadata support is
  not in scope for this plan.
- On some systems live `pcap_datalink()`/`pcap_set_datalink()` support depends
  on driver and monitor-mode configuration; automated tests must use offline
  pcap fixtures and dry-run send planning instead of hardware.

## Implementation Guardrails From These Sources

- Decode the outer valid layer first. If the next encapsulation is unknown but
  the enclosing layer is valid, preserve the unknown bytes as `Raw`.
- Return structured truncation errors when a declared radiotap length, IEEE
  802.11 header length, tagged-parameter length, LLC/SNAP header length, EAPOL
  body length, RSN IE length, or RSN EAPOL-Key data length exceeds available
  bytes.
- Preserve user-overridden fields on compile, including deliberately unusual or
  malformed values, unless the requested shape cannot be encoded at all.
- Keep offline validation first: byte fixtures, pcap round trips, oracle-backed
  decoding comparisons, malformed-buffer tests, and dry-run live planning do
  not require a Wi-Fi dongle, root privileges, monitor mode, provider
  credentials, or real network identifiers.
