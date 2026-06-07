# IEEE 802.11 Fixture Corpus

These fixtures are synthetic, deterministic hex fixtures for offline tests.
They contain no live captures, real network identifiers, provider data, public
IP addresses, or host-specific interface details.

MAC addresses use locally administered documentation values matching
`02:00:5e:10:*:*`. The beacon SSID strings `crafter`, `rsn-fixture`, and
`libcrafter-wpa` are synthetic fixture markers, not network names. IP payloads
use documentation address space. EAPOL-Key fixtures exercise typed phase 1.5
parsing and the WPA decryptor fixture; other unsupported EAPOL and RSN bytes
remain raw-preserved until their later plan steps.
