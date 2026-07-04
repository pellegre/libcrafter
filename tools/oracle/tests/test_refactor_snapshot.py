"""Behavior-lock snapshot test for the oracle plan generator.

This is the keystone safety net for the protocol-plugin refactor. The generator
(``tools/oracle/engine/generator.py``) is pure Python and runs offline without
Scapy: ``generate_plans(...)`` returns ``list[PacketPlan]``. For every profile the
loaded specs expose, this test pins a deterministic SHA-256 digest over the
generated packet plans (each plan reduced to its ``stack`` list and its ``fields``,
serialized with recursively sorted keys). Any later refactor step that alters the
generated plans for a fixed seed/count will flip a digest and fail here, proving a
behavior change.

The test is generation-only and imports no backend, so it runs on a bare
interpreter without Scapy. Profiles that cannot generate for structural reasons
are pinned through a ``"<error: ...>"`` placeholder so behavior stays pinned
rather than silently skipped; with the current specs every profile generates
cleanly.
"""

from __future__ import annotations

import hashlib
import json
import unittest

from tools.oracle.engine.generator import generate_plans
from tools.oracle.engine.spec_loader import load_oracle_specs


# Fixed generation coordinates: every profile is generated with this seed and
# count so the digests below are reproducible.
SEED = 12345
COUNT = 20


# Pinned per-profile digests, computed once from the current generator. These are
# the behavior lock: a digest mismatch means generated plans changed for a fixed
# seed/count, which the refactor must never do (move code, do not rewrite it). If
# a profile is intentionally added or removed, update the keys; never edit a value
# to silence a real generation change.
EXPECTED_DIGESTS = {
    "ah": "0768ce61aa59771235ae10522037c01a3b6599ac89c5c022a98dc82aa8ff88b7",
    "bgp-smoke": "784b998c5d5377eb34330d1a52d3ab075f1462e5f43f7db83f563128329310be",
    "boundary": "8b2dc26ca848a75b4792f6aaa106a2411500d4121136d67eb9ae1fc72ae51191",
    "ci": "d9f1e66a5af2024722b2e67faf8d2ab37a4fb12a7cfa63f8328ee132341c0647",
    "dhcpv6-smoke": "08f26866d079baf38c023a4b54841aeaaf3d80109d82879ed7233ae50836b9b9",
    "dot11-pcap": "a183c962ba2b3e2eb4ac38956a2cbbc72c4ec9d08ffdc270272398bd46848d75",
    "dot11-smoke": "9696816eadcb781664f6a34dc13fa91873f3049eff55a532b3d2c5c3445be67b",
    "eapol-smoke": "930ecfad701ecb5c8e91ea764c3080d0a3be6c105bcfad42854159c1847f6c8c",
    "esp": "cc8a0fff10fbba05a681f67e51b9b67e01befefe9e9b0ad4c54b00af42f72956",
    "fragmentation-smoke": "49e0b5ea1769743e5f256892f2423a82ea7fef87455a8a7dde39d1d3c785dc9b",
    "fuzz": "2a9ac0561e6cf77e17ca9246f528477ed678dcf5c50743502860c77f3621d4eb",
    "igmp-boundary": "83803ecc96ff6fdcf7803daf7b2fd98dc021dd059b16ba5b407c3d082d160cfa",
    "igmp-ci": "1f2620765214c58feee161f18316bbd0b2382c03f93a072100543ac1f6bb7744",
    "igmp-live-dry-run": "f98b56cbc3a900c6dda0e28841f7614434eb33102e66e2c873f9b50e2f2e0007",
    "igmp-smoke": "f3905fb935b48acb82ce8cb72efb6b83eea6caaaa559fdfbf44d87181eb1f590",
    "ikev2": "e5746a33412a690ae1197351af92b545618cf210fa34b00b33df4dc636006519",
    "ip-fragment-smoke": "a05c44538fd7f5b7bfd5da6c5eeea295042eabb5ad643a5011495261cb1b6ba5",
    "ipsec-smoke": "68f511d01f2ceae16267da0d2c9b0b04e9f0f6a9b4b3f910fac806453dd5545f",
    "ipv4-enrichment": "ca5d8ac931ec41f6a5509cf13672b0b25aaf427548c60962eb50968fe2714e41",
    "ipv6-enrichment": "2f1cecaffd46d9ef912e0b67bea0570c2b7af464d9dc7bafe9716034df244f8a",
    "mdns-boundary": "80251f402bfeefab3051ed63fcc3d6de04a04effac03c55a566e6aa1c4aa4f38",
    "mdns-ci": "9cce8e8d6f801e676b5a239229d507b0ea9b444471b34834097ff00c3fb596fe",
    "mdns-live-dry-run": "7bb158b5826ed55185bbaa0bcf07c1c19ac689f5bf55c31b99e7b9c07f9e8b74",
    "mdns-pcap": "d5de224edbab9443de2abc5e44d1b2e3aad6dde7ec089ab4b868c2dc9cd246a2",
    "mdns-smoke": "bdd84613df846ef83448cf9469619d709ce28acb0a38bc983a59f7c169d8c8a5",
    "ntp-ci": "720dc3617b5ef6e4fcbc5e62c43fe564686b30202caac0a683dd97de505a6de4",
    "ntp-live-dry-run": "9ed37a2586969dc5566db0fdcdb30111e945d443bec6ea897d4f2f7286df8a69",
    "ntp-smoke": "7c5845a3510f54a9bf13a361c546825f6d4ddd404ab9bb27ef112a4e8a91a1a4",
    "ospf-smoke": "7f829d6e9bf0e5773466cb7b11cf7b3853fd0dcc81284d6aa980490d8ead16bb",
    "quic-ci": "65c3781050a3cae2cc6d4f7ebd01f7e7fa6a9262ad2c087fa472b2f78fb92d3b",
    "quic-smoke": "582a7f7069e1eecd3f1863c3bd13df4302511cf772be97f1be3372da0d8a3b52",
    "radiotap-smoke": "45e1edc2ee939bcf00a1d0dd15d9f66a1a0f3c428888d716f7e0088da30070a5",
    "rip-smoke": "5dfd7ad4bc2428075418fa0de787a1df377c09d8223f6892a80cb964cbdec092",
    "rsn-smoke": "ca1936202ca6d35350cd610a7cfdbbd84483a0399c7292b6a5dca652a49acdcc",
    "sctp-boundary": "88e6939c47c47bb25740a57187fde6371ee90aa32a26ec9d6b6583e4abade7e8",
    "sctp-pcap": "b1b37ab51e7f2879c028d916e6930abaa8722e6133f45d8ca899a2ec46475bf2",
    "sctp-smoke": "555bd9318cd98e4bcae2766d1e72fde7552d5c13a45652c23f98bf04081ed1f8",
    "smoke": "b84ad6040c4cce3e08b4644709e078cbdb084613141974846a7ca9fe67fce5e4",
    "snmp-boundary": "7bf311a663168514940265d49ec6f6cea43c3c0e63f50161a9c2ab1b707e4b47",
    "snmp-ci": "30bfb539dfafb9a93fc5058bc3e8a3b9f6d829db379c1dbb793b57a972a0ced1",
    "snmp-live-dry-run": "fdc15150796dd3d99461552c7f7fce01a932b9e01004b7ba74b8dd344c4f53bb",
    "snmp-smoke": "df44044299c8b5e06ac0e638af03613e6f70aeb893b2ba2ab1cc16c999e08a0f",
    "ssdp-boundary": "dbf600bf5b7221535a0a72e621c0932d38cf5d07a418a727f05b63c98218c1c7",
    "ssdp-ci": "ffb7d7467f3694d0e673aaea9882eac6cb07bf26ca5b429dee2f5f940152aa83",
    "ssdp-live-dry-run": "a8a90223bffed471ebe917ecfdb280678da1a2a433c58db75b8eeb6a8598da4b",
    "ssdp-pcap": "30ab8853901e704d8cdbd59e376c37a97c620ffaa6f7c862696b844376e7796b",
    "ssdp-smoke": "3017a77d537e41d2675a5e3d8b5a980a4f4522c39215b7a2c4c55877b7ba7613",
    "tcp-header": "e62e918200aacb46fdfcd5cde318bf412739f1c64bfbfae5b35034bbde69380c",
    "tcp-options": "c4a438c51f9ba728dffc3ffa1dd0ab15479d8fd80dfef6fadf5f3b42a8f31487",
    "tcp-smoke": "10ece5bd042f42c31f2a14f66afc10b8ffa4f287ee559dcf50d9e146c58bff46",
    "tls": "cf646c38cce4b0b82f4cccf25a616e00f57e0839d99db73dcb24b64ffeddc0e8",
    "tls-ci": "6128bac2de55f1ee677113be4a8a83196af8f92c77980d8fc2cae237e0c45602",
    "tls-smoke": "805b66cdd8920822479b48d102d44c70c0fab3e638c90a7f07105db32786b712",
    "wild": "79e45efe1cfba2d6b1b0c542b1d808c22d78323172dd6be5230684d74871f52e",
}


def _canonical_plan(plan) -> dict:
    """Order-stable reduction of one ``PacketPlan`` to stack + fields.

    ``json.dumps(..., sort_keys=True)`` recursively sorts every mapping key during
    serialization, so the digest is independent of dict insertion order.
    """

    return {"stack": list(plan.stack), "fields": plan.fields}


def _profile_digest(profile: str) -> str:
    """Digest the generated plans for ``profile`` at the fixed seed and count.

    Structural generation failures are pinned through a ``"<error: ...>"``
    placeholder so the digest still locks behavior deterministically instead of
    silently skipping the profile.
    """

    try:
        plans = generate_plans(seed=SEED, profile=profile, count=COUNT)
    except Exception as exc:  # noqa: BLE001 - pin structural failures too
        payload = f"<error: {type(exc).__name__}: {exc}>"
    else:
        payload = [_canonical_plan(plan) for plan in plans]
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class GeneratorSnapshotTest(unittest.TestCase):
    """Pin generated packet-plan digests across every spec-declared profile."""

    def test_profile_set_matches_pinned_snapshot(self) -> None:
        specs = load_oracle_specs()
        self.assertEqual(
            sorted(specs.profiles),
            sorted(EXPECTED_DIGESTS),
            "the set of spec profiles drifted from the pinned snapshot; "
            "regenerate the EXPECTED_DIGESTS keys only when a profile is "
            "intentionally added or removed",
        )

    def test_generated_plans_match_pinned_digests(self) -> None:
        specs = load_oracle_specs()
        for profile in sorted(specs.profiles):
            with self.subTest(profile=profile):
                expected = EXPECTED_DIGESTS.get(profile)
                self.assertIsNotNone(
                    expected,
                    f"profile {profile!r} has no pinned digest",
                )
                self.assertEqual(
                    _profile_digest(profile),
                    expected,
                    f"generated plans for profile {profile!r} changed; the "
                    "refactor must not alter generator output for a fixed "
                    "seed/count",
                )


if __name__ == "__main__":
    unittest.main()
