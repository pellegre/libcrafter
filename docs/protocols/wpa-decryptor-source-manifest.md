# WPA Decryptor Source Manifest

This manifest records the protocol sources and current crate inventory for the
first passive WPA decryptor transform. It uses only synthetic identifiers in
examples and does not define any live capture workflow.

## Source Authority

| Topic | Primary authority | Implementation note |
| --- | --- | --- |
| IEEE 802.11 MAC frame layout, address roles, protected frame bit, management tagged parameters, RSN information elements, RSNA key hierarchy, four-way handshake, and CCMP protected data | IEEE Std 802.11-2020, including the MAC and RSNA security material inherited from IEEE 802.11i | Use this as the authority for Dot11 frame interpretation, BSSID/station roles, RSN suite selectors, PTK/GTK context, replay counters, packet numbers, CCMP AAD/nonce inputs, and WPA2-PSK CCMP-128 behavior. |
| EAP and EAPOL carriage | IEEE Std 802.1X-2020 for EAPOL LAN encapsulation; RFC 3748 for the Extensible Authentication Protocol model | The decryptor observes EAPOL-Key records carried by LLC/SNAP EtherType `0x888e`; it does not implement an authenticator, supplicant, or EAP method. |
| EAPOL-Key message classification | IEEE Std 802.11-2020 RSNA EAPOL-Key descriptor definitions | Existing crate classification is a passive shape classifier only. The transform still needs state validation against addresses, replay counters, nonces, and MIC verification. |
| Passphrase-to-PMK derivation | IEEE Std 802.11-2020 for WPA/WPA2-Personal parameters; RFC 8018 for the PBKDF2 primitive | First scope is PBKDF2-HMAC-SHA1 with SSID bytes as the salt and the IEEE-specified iteration/output parameters. SSIDs are bytes, not guaranteed UTF-8 strings. |
| PTK expansion and EAPOL MIC verification | IEEE Std 802.11-2020 RSNA key hierarchy and EAPOL-Key descriptor-version rules | The transform must derive key material only after it has both MAC addresses, both nonces, configured credentials, and enough EAPOL bytes to verify a MIC with the MIC field zeroed. |
| Encrypted EAPOL-Key data unwrap | IEEE Std 802.11-2020 encrypted key data rules; RFC 3394 for the AES Key Wrap primitive where the RSNA descriptor uses AES key wrap | First scope can record GTK/key-data presence, but pairwise unicast CCMP decryption must not depend on group-key support. |
| AES block cipher and CCM mode | FIPS 197 for AES; NIST SP 800-38C for CCM; IEEE Std 802.11-2020 for the CCMP profile, header, packet number, AAD, nonce, and MIC layout | Use RustCrypto primitives behind a WPA module boundary. CCMP authentication failure is a decrypt failure state, not a panic or successful packet. |

The source-backed first implementation scope is passive WPA2-PSK with
CCMP-128-protected unicast data frames. The transform may learn beacon/probe
RSN information, station/BSSID relationships, EAPOL-Key handshake state, and
protected data metadata from a monitor-mode packet stream. It must not actively
send traffic, force handshakes, change channels, or crack passwords.

WPA3/SAE, enterprise authentication, TKIP decryption, WEP, GCMP, CCMP-256,
active deauthentication, AP/supplicant behavior, channel management, password
cracking, fragmentation/reassembly, and TCP/application reconstruction are
explicitly out of scope for this first pass.

## Implementation Inventory

| Planned primitive | Existing crate surface | Missing helper or type |
| --- | --- | --- |
| Stream transform contract | `crafter/src/wire/transform.rs` defines `PacketTransform`, which can keep state and emit zero, one, or many `PacketRecord` values. | `crafter/src/wire/wpa/transform.rs` with `WpaDecrypt` and diagnostics counters. |
| Packet record metadata | `crafter/src/wire/record.rs` preserves packet, origin, backend, interface, pcap timestamp, captured bytes, link type, transform trace, and initial `WifiMetadata`. | WPA-specific metadata nested under Wi-Fi metadata: cipher, AKM, BSSID/station session, handshake status, key kind, packet number, and decrypt reason. |
| Dot11 metadata pre-pass | `crafter/src/wire/dot11_metadata.rs` annotates Radiotap/Dot11 records with SSID, BSSID, transmitter, receiver, channel, signal, Dot11 frame kind, protected status, and initial decrypt state. | RSN-aware enrichment from management tags and CCMP key-id/PN extraction from protected bodies. |
| Dot11 MAC frame access | `crafter/src/protocols/link/dot11.rs` exposes frame type/subtype, address-role helpers, protected bit, QoS control, tagged parameters, RSN tag parsing, and encrypted protected body preservation as `Raw` plus `encrypted_body_len`. | CCMP header parser, CCMP AAD/nonce input builder, role-specific plaintext source/destination mapper, and helper access to protected body bytes for transforms. |
| RSN information elements | `crafter/src/protocols/rsn.rs` exposes RSN version, cipher suite selectors, AKM suite selectors, capabilities, PMKIDs, group management cipher, decode, encode, and known labels including `RSN_CIPHER_SUITE_CCMP_128` and `RSN_AKM_SUITE_PSK`. | Supported-network classifier that reduces RSN information to WPA2-PSK CCMP-128, unsupported cipher/AKM reasons, and configured SSID matching state. |
| EAPOL and EAPOL-Key | `crafter/src/protocols/eapol.rs` exposes EAPOL headers, EAPOL-Key descriptor fields, key information flags, nonce, MIC, replay counter, key data, and passive RSN four-way handshake message classification. | MIC-zeroed EAPOL serialization, descriptor-version policy, replay validation, PTK key slice selection, and EAPOL state-machine integration keyed by BSSID/station. |
| LLC/SNAP plaintext decode | `crafter/src/protocols/link/llc.rs` decodes RFC 1042 SNAP payloads through the EtherType registry and preserves non-SNAP data as `Raw`. | A reusable internal helper for WPA to decode decrypted plaintext bytes into `LlcSnap` plus higher layers or `Raw`, and optional Ethernet-equivalent packet construction for downstream IP/TCP transforms. |
| WPA credential material | No dedicated WPA module exists yet. | `WpaNetwork` with SSID bytes, passphrase or pre-derived PMK, validation for WPA passphrase length/encoding rules, and a PMK cache keyed by SSID bytes. |
| WPA crypto | No PBKDF2, PTK PRF, EAPOL MIC verification, AES key unwrap, or CCMP decrypt helper exists in the crate. | Isolated `crafter/src/wire/wpa/crypto.rs` and `ccmp.rs` using audited RustCrypto crates, deterministic test vectors, and structured errors. |
| WPA state machines | No WPA session state exists yet. | `ConfiguredNetwork`, `ObservedBss`, `PairwiseSession`, and optional `GroupKeyState`, keyed by BSSID and station, tolerant of duplicate and out-of-order EAPOL records. |
| Offline validation | `crafter/tests/public_api.rs` already covers Dot11, LLC/SNAP, EAPOL-Key, RSN, radiotap, and public re-exports. | Synthetic WPA2-PSK CCMP fixtures, crypto vector tests, state-machine tests, pcap-backed transform tests, and wrong-passphrase failure tests. |

## Initial Behavior Contract

The decryptor should run after `Dot11Metadata` in a sniffer transform chain, but
it must also tolerate records without prior Wi-Fi metadata by inspecting the
packet layers directly. It observes management and EAPOL records to update
state and emits no decrypted record for handshake-only inputs unless configured
to pass originals through.

For protected data records, the transform should emit a new `PacketRecord` only
when the configured WPA2-PSK material, observed handshake state, and supported
CCMP key state authenticate the payload. The emitted record must preserve useful
capture metadata, append a `wpa-decrypt` transform trace, and carry Wi-Fi/WPA
metadata that identifies the synthetic network context such as SSID bytes,
BSSID, station, cipher, packet number, key kind, and decrypt state.

If a frame is unconfigured, unsupported, incomplete, waiting for key material,
or fails MIC/CCMP authentication, the transform must expose that reason through
metadata or diagnostics and must not emit falsely decrypted packets.
