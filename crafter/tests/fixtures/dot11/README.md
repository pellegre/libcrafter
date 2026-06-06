# IEEE 802.11 Fixture Corpus

These fixtures are synthetic, deterministic hex fixtures for offline tests.
They contain no live captures, real network identifiers, provider data, public
IP addresses, or host-specific interface details.

MAC addresses use locally administered documentation values in the
`02:00:5e:10:00:00/40` range. IP payloads use documentation address space.
EAPOL and RSN bytes are intentionally raw in this phase because typed EAPOL and
RSN parsing is added by later plan steps.
