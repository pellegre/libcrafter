# NTP RFC Manifest

Review date: 2026-07-01.

This manifest is the evidence gate for Network Time Protocol packet support in
`crafter`. Later NTP code, tests, docs, oracle specs, probe expectations,
fixtures, summaries, and examples must cite this manifest before relying on a
wire fact, and must also cite the exact RFC section, IANA registry row,
Datatracker relationship, or RFC Editor erratum that supplies the fact.

NTP remains a packet primitive in this repository. These sources may define
bytes, fields, codepoints, extension field payloads, and registry relationships;
they do not authorize adding a clock synchronization service, daemon, pool
client, NTS-KE workflow, Autokey verifier, scanner, or live traffic default.

## Source Classes

- `core wire behavior`: current normative source for the fixed NTP packet
  header, packet field semantics, extension framing, MAC placement, or packet
  parse behavior.
- `registry authority`: official authority for assigned NTP, NTS, service-port,
  RFC status, update, obsolescence, or errata records.
- `packet-data extension`: source for an optional NTP extension field body or
  optional packet tail that must be preserved byte-exactly when structurally
  valid.
- `operational guidance`: source that informs safe examples, dry-run defaults,
  external qualification, or deployment risk, but is not by itself a packet grammar
  authority for this crate.
- `obsolete context`: source superseded by newer NTP authority and usable only
  to understand legacy SNTP/NTP-shaped packets or fixture context.
- `blocked`: source or behavior that must not be implemented in `crafter`
  unless a later source-backed scope step explicitly admits it.

## Selected Sources

| Class | Source | Use in this project | Downstream gate |
| --- | --- | --- | --- |
| core wire behavior | RFC 5905, "Network Time Protocol Version 4: Protocol and Algorithms Specification", `https://www.rfc-editor.org/rfc/rfc5905.html` | Primary NTPv4 fixed-header packet format, field names, first-octet LI/VN/mode packing, timestamps, strata, reference IDs, Kiss-o'-Death packet shape, UDP transport baseline, and extension-field starting point. | Packet structs, constants, fixed-header decode/encode, summaries, and NTPv3/SNTP-compatible preservation must cite the exact section used. Apply current updates and verified errata before freezing behavior. |
| core wire behavior | RFC 7822, "Network Time Protocol Version 4 (NTPv4) Extension Fields", `https://www.rfc-editor.org/rfc/rfc7822.html` | Updates RFC 5905 extension-field handling, including extension-field placement relative to optional MAC data, minimum lengths, alignment, unknown field handling, and MAC relationship rules. | Extension-field parsing, raw preservation, shape gates, and malformed-tail errors must cite RFC 7822 before relying on extension length, padding, or unknown-field behavior. |
| core wire behavior | RFC 8573, "Message Authentication Code for the Network Time Protocol", `https://www.rfc-editor.org/rfc/rfc8573.html` | Current MAC behavior source for NTP authentication material and MD5 deprecation context. `crafter` may preserve MAC bytes and expose packet structure, but does not compute or verify NTP MACs. | Legacy MAC tail modeling must cite this source for MAC behavior and must not imply cryptographic verification support. |
| registry authority | RFC 9748, "Updating the NTP Registries", `https://www.rfc-editor.org/rfc/rfc9748.html` | Current registry-correction source. It updates RFCs 5905, 5906, 7821, 7822, and 8573 and corrects NTP/NTS registry assignments. | Registry labels, reserved ranges, duplicate historical assignments, NTS extension-field assignments, private/experimental ranges, and codepoint tests must prefer RFC 9748 plus current IANA rows over older tables. |
| packet-data extension | RFC 7821, "UDP Checksum Complement in the Network Time Protocol (NTP)", `https://www.rfc-editor.org/rfc/rfc7821.html` | Source for the UDP Checksum Complement extension field and its packet data. | Any checksum-complement helper must cite RFC 7821 and RFC 9748's current registry assignment. UDP checksum calculation remains in the UDP layer. |
| packet-data extension | RFC 8915, "Network Time Security for the Network Time Protocol", `https://www.rfc-editor.org/rfc/rfc8915.html` | Source for NTS extension fields carried inside NTPv4 packet data, including Unique Identifier, NTS Cookie, NTS Cookie Placeholder, NTS Authenticator and Encrypted Extension Fields, and NTS NAK Kiss-o'-Death context. | NTS packet extension wrappers may preserve and label raw bytes. They must not implement NTS-KE, AEAD encryption/decryption, key export, cookie construction, replay cache, or authentication decisions. |
| operational guidance | RFC 8633, "Network Time Protocol Best Current Practices", `https://www.rfc-editor.org/rfc/rfc8633.html` | Operational and security guidance for NTP deployments, examples, probe dry-runs, live-gate wording, and non-amplifying behavior. | Use only for safe validation and documentation policy. Do not derive packet grammar, registry assignments, or default live behavior from this BCP alone. |
| obsolete context | RFC 4330, "Simple Network Time Protocol (SNTP) Version 4 for IPv4, IPv6 and OSI", `https://www.rfc-editor.org/rfc/rfc4330.html` | Obsolete SNTP context for legacy SNTP-shaped packets and compatibility notes. Datatracker marks it obsoleted by RFC 5905. | Do not prefer RFC 4330 over RFC 5905 for new behavior. Use it only to explain legacy fixture shapes while preserving RFC 5905-compatible bytes. |
| registry authority | IANA "Network Time Protocol (NTP) Parameters", `https://www.iana.org/assignments/ntp-parameters/ntp-parameters.xhtml` | Current registry authority for NTP Reference Identifier Codes, NTP Kiss-o'-Death Codes, and NTP Extension Field Types. The registry was last updated 2026-01-07 when reviewed. | Constants, labels, unknown-value policy, and extension type tables must cite exact IANA rows and RFC 9748 where registry corrections matter. Unknown valid values remain preservable. |
| registry authority | IANA "Network Time Security (NTS)", `https://www.iana.org/assignments/nts/nts.xhtml` | Current registry authority for NTS-KE record types, NTS next protocols, NTS error codes, and NTS warning codes. The registry was last updated 2026-06-02 when reviewed. | NTS packet support in `crafter` is limited to NTPv4 extension field packet data. NTS-KE record registries are context unless a later source-backed step scopes a generated tool outside the crate. |
| registry authority | IANA "Service Name and Transport Protocol Port Number Registry", `https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=ntp` | Authority for the `ntp` service name and port 123 assignments for TCP and UDP. The registry was last updated 2026-06-17 when reviewed. | UDP/123 decode bindings and service-port constants must cite the exact `ntp 123 udp` row. TCP/123 is a service registry fact, not authority to add a TCP NTP stream protocol here. |
| registry authority | IETF Datatracker RFC metadata pages, including `https://datatracker.ietf.org/doc/rfc5905/`, `https://datatracker.ietf.org/doc/rfc7821/`, `https://datatracker.ietf.org/doc/rfc7822/`, `https://datatracker.ietf.org/doc/rfc8573/`, `https://datatracker.ietf.org/doc/rfc8915/`, `https://datatracker.ietf.org/doc/rfc9748/`, `https://datatracker.ietf.org/doc/rfc8633/`, `https://datatracker.ietf.org/doc/rfc4330/`, `https://datatracker.ietf.org/doc/rfc9109/`, and `https://datatracker.ietf.org/doc/rfc9769/` | Official RFC status, stream, publication date, update, and obsolescence relationships. On review, Datatracker lists RFC 5905 as updated by RFCs 8573, 9109, 7822, 9748, and 9769, and as obsoleting RFCs 4330 and 1305. | Before relying on any RFC fact, check Datatracker for current updates/obsoletes. Later steps must record when a current update is in scope, operational-only, or blocked by packet-layer scope. |
| registry authority | RFC Editor errata pages, including `https://errata.rfc-editor.org/search/?rfc_number=5905&presentation=records`, `https://errata.rfc-editor.org/search/?rfc_number=7821&presentation=records`, `https://errata.rfc-editor.org/search/?rfc_number=7822&presentation=records`, `https://errata.rfc-editor.org/search/?rfc_number=8573&presentation=records`, `https://errata.rfc-editor.org/search/?rfc_number=8915&presentation=records`, `https://errata.rfc-editor.org/search/?rfc_number=9748&presentation=records`, `https://errata.rfc-editor.org/search/?rfc_number=8633&presentation=records`, `https://errata.rfc-editor.org/search/?rfc_number=4330&presentation=records`, `https://errata.rfc-editor.org/search/?rfc_number=9109&presentation=records`, and `https://errata.rfc-editor.org/search/?rfc_number=9769&presentation=records` | Official errata authority for RFC corrections. RFC 5905 errata are material to packet work, especially verified Errata 3627 for extension fields without MACs and verified Errata 4504 for leap-indicator wording. | Any subtle field, extension, algorithm-text, or compatibility rule must check relevant errata. Errata may correct a source but do not expand project scope. |
| operational guidance | RFC 9109, "Network Time Protocol Version 4: Port Randomization", `https://www.rfc-editor.org/rfc/rfc9109.html` | Current RFC 5905 update for source-port behavior and off-path attack mitigation. | Examples and generated helpers must not imply that client-originated NTP packets should use UDP source port 123 unless the chosen mode requires it. This does not add a live client workflow to the crate. |
| operational guidance | RFC 9769, "NTP Interleaved Modes", `https://www.rfc-editor.org/rfc/rfc9769.html` | Current RFC 5905 update for interleaved operational modes and timestamp field semantics. It does not define a new header format or new extension fields. | Preserve timestamp fields byte-exactly. Do not implement interleaved association state, negotiation, or time synchronization logic in `crafter` without a later explicit scope change. |
| blocked | RFC 5906, "Network Time Protocol Version 4: Autokey Specification", `https://www.rfc-editor.org/rfc/rfc5906.html` | Historical source behind Autokey-related extension field registry entries, now registry-corrected by RFC 9748. | Autokey cryptographic verification, certificate handling, identity schemes, and protocol workflow are out of scope. Raw-preserving labels for registry-listed Autokey field types must cite IANA and RFC 9748 first. |

## Authority Order

1. Use RFC 5905, as updated by current Datatracker relationships and relevant
   verified errata, for the fixed NTP packet header and base NTPv4 packet
   grammar.
2. Use RFC 7822 for extension-field framing, lengths, alignment, MAC
   relationship rules, and unknown extension behavior.
3. Use RFC 8573 for MAC behavior only to the extent needed to model and
   preserve packet tail bytes; do not implement MAC computation or validation.
4. Use RFC 8915 and RFC 7821 for packet-data extension bodies after RFC 7822
   has established extension framing.
5. Use RFC 9748 plus current IANA registries for assigned values and registry
   corrections. Prefer current IANA rows over stale tables in older RFC text.
6. Use IANA service-name and port registry rows for `ntp` port constants and
   UDP/123 decode bindings.
7. Use Datatracker metadata and RFC Editor errata before freezing any RFC fact.
8. Use RFC 8633, RFC 9109, and RFC 9769 only for safety, examples, dry-run
   expectations, or field-preservation context unless a later source-backed
   scope document explicitly admits more behavior.
9. Use RFC 4330 only as obsolete SNTP context. Do not prefer it over current
   NTPv4 sources.

## Errata And Update Review

- RFC 5905 currently has verified, reported, held-for-update, and rejected
  errata records. Packet-layer work must account for verified Errata 3627
  before implementing extension fields without MACs, and verified Errata 4504
  before documenting leap-indicator meaning. Other RFC 5905 errata largely
  affect algorithms or reference code, but later steps must re-check the exact
  section before depending on it.
- RFC 7822 updates the extension-field text that began in RFC 5905 and is
  updated by RFC 9748 for registry matters. Treat RFC 7822 as the extension
  framing source unless a later erratum or update says otherwise.
- RFC 9748 updates RFCs 5905, 5906, 7821, 7822, and 8573 for registry cleanup.
  Any codepoint table frozen before checking RFC 9748 is incomplete.
- RFC 8915 defines NTS extension fields for NTPv4 packets, but the NTS-KE
  protocol, TLS exchange, key export, AEAD operations, cookie generation, and
  replay protection are outside the crate packet primitive.
- RFC 9109 updates RFC 5905 for port randomization. This affects examples and
  helpers that choose ports, but does not change the NTP payload grammar.
- RFC 9769 updates RFC 5905 for interleaved modes. It affects operational
  timestamp interpretation, but does not change the fixed header layout.
- RFC 4330 is obsolete context. Its errata may explain legacy SNTP examples,
  but it is not a current authority for new packet behavior.

## Blocked Until Later Evidence

- Do not decode every UDP/123 payload as NTP. A later grammar step must define
  a conservative shape gate; too-short or non-NTP-shaped payloads must remain
  `Raw`.
- Do not reject unknown but structurally valid versions, modes, strata,
  reference IDs, Kiss-o'-Death codes, extension field types, NTS bodies, MAC
  bytes, or tail bytes solely because they are absent from an enum.
- Do not implement NTP clock discipline, server selection, association state,
  pool behavior, replay cache, NTS-KE, AEAD encryption/decryption, Autokey
  cryptographic verification, or live sender defaults in the crate.
- Do not add live NTP validation from the developer machine. Any later live
  work must be externally executed, explicitly confirmed, and documented through
  the repository live-gate policy.
- Do not rely on packet captures, vendor behavior, pool-server observations,
  Stack Overflow answers, expired drafts, or implementation source as authority
  for wire facts unless a later source-backed step records them as
  non-normative fixture context.
