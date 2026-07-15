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
    "boundary": "416c7b4c8cadaccd8b576740a4a947903e53a6d2f851f03b8d176f314f0f5eb3",
    "ci": "235b5fb216f7a6b696a8f2603900286996abf00b3a5aa2d248b5c1ce44c7a613",
    "coap-ci": "e1d26a3a8dab051be494f67f6fb6c6db4c5a92e813b6e686e31ef69bf0a21ac5",
    "coap-live-dry-run": "9bfeb208945971209f6e9da531b82bd40c7f9ad49816ad1d4a79384f2bb6d4f9",
    "coap-smoke": "08215d5dac98b0abb6b3b15e3f7a2ff2907ab97b16c8d1e03b1ca7ec796ae5bc",
    "dhcpv6-smoke": "08f26866d079baf38c023a4b54841aeaaf3d80109d82879ed7233ae50836b9b9",
    "dot11-pcap": "28e0d99a6f6fda12d5ef37570bb42aad50ebb0537dd260bb8d5f40806cacc611",
    "dot11-smoke": "11300500eb2a93252ed76758d31d50663970172ab3702bd9585d7f6302af9d34",
    "eapol-smoke": "dfa2996751c70d0606847f21d388a45d1e73be1cc52fb9cff3fda8ea0cf96850",
    "esp": "cc8a0fff10fbba05a681f67e51b9b67e01befefe9e9b0ad4c54b00af42f72956",
    "fragmentation-smoke": "f1e1304cc91325db78bf7ec24085e185dd33284177637f67403d17772942e215",
    "fuzz": "7bd8f5f7076da218e60fa61d93651d4876e0cc585a9e19e743c66b777e8fe1c2",
    "igmp-boundary": "ad4baf706380aeaad473e8197f9561af3d258024eec4506a67c836a83ce2ac1f",
    "igmp-ci": "eb31439534c000f2f5fea03f221584f3121acdaf7aef5ef21639009df7c8365a",
    "igmp-live-dry-run": "1111f5c5ee07dd901f6475c0937dcca70cc94025d03efe0496f6c04de668f11a",
    "igmp-smoke": "4cd9ecb93cc74381826fa7a4725f45be1517291232d242c531f6e51098586f18",
    "ikev2": "e5746a33412a690ae1197351af92b545618cf210fa34b00b33df4dc636006519",
    "ip-fragment-smoke": "707d5794bf1ede0159ffbabf94e64b5fe7e3327b6ce4a28866600b4c414ed0aa",
    "ipsec-smoke": "68f511d01f2ceae16267da0d2c9b0b04e9f0f6a9b4b3f910fac806453dd5545f",
    "ipv4-enrichment": "ca5d8ac931ec41f6a5509cf13672b0b25aaf427548c60962eb50968fe2714e41",
    "ipv6-enrichment": "2f1cecaffd46d9ef912e0b67bea0570c2b7af464d9dc7bafe9716034df244f8a",
    "mdns-boundary": "11629d6298b64e4987191ea2ad6af2662496da3cced5fdb723e5fd55c347a2b9",
    "mdns-ci": "d82201246209ceed4932aef5dcce79a9f427834984db1b851f1976da325008c3",
    "mdns-live-dry-run": "def8bb2686d5d6519c77cd80b6609b0551f8b94de6d743cf4aab4e29797fee47",
    "mdns-pcap": "8171ef044b30156ad5d1df00501673afccb9433459e74346acd403151a7cc4c0",
    "mdns-smoke": "1998e96128b8a9c8b4154c999280bd22cfd8a9d5523310d18daa52f024ef3747",
    "ntp-ci": "720dc3617b5ef6e4fcbc5e62c43fe564686b30202caac0a683dd97de505a6de4",
    "ntp-live-dry-run": "9ed37a2586969dc5566db0fdcdb30111e945d443bec6ea897d4f2f7286df8a69",
    "ntp-smoke": "7c5845a3510f54a9bf13a361c546825f6d4ddd404ab9bb27ef112a4e8a91a1a4",
    "ospf-smoke": "7f829d6e9bf0e5773466cb7b11cf7b3853fd0dcc81284d6aa980490d8ead16bb",
    "quic-ci": "798f8e39a1ede7a9cb09368246b089163f627f812a6701eb13bac40cb3e85cf8",
    "quic-smoke": "cf3ca1b1ee63770baafbf012c63f2e06b7cf365ff8b0f0d4ea8fb8d2e8040143",
    "radiotap-smoke": "04b01f150d61aeef051f05254efe1ce45e63ad12ee923d3f8a3a4cb3dbebb45d",
    "rip-smoke": "5dfd7ad4bc2428075418fa0de787a1df377c09d8223f6892a80cb964cbdec092",
    "rsn-smoke": "de2116740bbe768010cffff20e49027167a1e5dc46a5017e0a7ff5cc99dd4867",
    "sctp-boundary": "88e6939c47c47bb25740a57187fde6371ee90aa32a26ec9d6b6583e4abade7e8",
    "sctp-pcap": "b1b37ab51e7f2879c028d916e6930abaa8722e6133f45d8ca899a2ec46475bf2",
    "sctp-smoke": "555bd9318cd98e4bcae2766d1e72fde7552d5c13a45652c23f98bf04081ed1f8",
    "smoke": "1f77708846ecb83ec213f5fb985a10d65a1c14a20270c4188b3e88b5a4a1c5aa",
    "snmp-boundary": "7bf311a663168514940265d49ec6f6cea43c3c0e63f50161a9c2ab1b707e4b47",
    "snmp-ci": "30bfb539dfafb9a93fc5058bc3e8a3b9f6d829db379c1dbb793b57a972a0ced1",
    "snmp-live-dry-run": "fdc15150796dd3d99461552c7f7fce01a932b9e01004b7ba74b8dd344c4f53bb",
    "snmp-smoke": "df44044299c8b5e06ac0e638af03613e6f70aeb893b2ba2ab1cc16c999e08a0f",
    "ssdp-boundary": "7741635660d02dce9839cca59cb2aa07499d62b78c8252bc2aa8f9a756d182e4",
    "ssdp-ci": "ef784998598d4ce38b06df06cae6fb0d962681c8fed889599240b5a03393f92a",
    "ssdp-live-dry-run": "c2a14c88cc7c3da08fcc70ff9edf7529b0bb926c8de9e7ee19a2a82c0c6806fd",
    "ssdp-pcap": "7b08774cb33d81e476cb9115e2f807b36428fbc2dc50f2fc43fd31603c28a9d7",
    "ssdp-smoke": "bd4f054d2fbea5f8118b95a7b6a07ef205721c25e9bc62a827146d77b7921600",
    "tcp-header": "e62e918200aacb46fdfcd5cde318bf412739f1c64bfbfae5b35034bbde69380c",
    "tcp-options": "c4a438c51f9ba728dffc3ffa1dd0ab15479d8fd80dfef6fadf5f3b42a8f31487",
    "tcp-smoke": "10ece5bd042f42c31f2a14f66afc10b8ffa4f287ee559dcf50d9e146c58bff46",
    "tls": "cf646c38cce4b0b82f4cccf25a616e00f57e0839d99db73dcb24b64ffeddc0e8",
    "tls-ci": "6128bac2de55f1ee677113be4a8a83196af8f92c77980d8fc2cae237e0c45602",
    "tls-smoke": "805b66cdd8920822479b48d102d44c70c0fab3e638c90a7f07105db32786b712",
    "wild": "8e9e75248003d3b8a9b559fdd7464eb8b880cf2ac50806651979043183d8f048",
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
