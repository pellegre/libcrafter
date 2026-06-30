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
    "boundary": "939e83ff8aa946671769259e31ea1beff395c3f1f5948bbcf643679f24d3aa09",
    "ci": "40335cdf27e83bb1bb1fdced4fad39e4bde5e6fcd7b6fffd13baf8bb316d8bcb",
    "dhcpv6-smoke": "08f26866d079baf38c023a4b54841aeaaf3d80109d82879ed7233ae50836b9b9",
    "dot11-pcap": "a183c962ba2b3e2eb4ac38956a2cbbc72c4ec9d08ffdc270272398bd46848d75",
    "dot11-smoke": "9696816eadcb781664f6a34dc13fa91873f3049eff55a532b3d2c5c3445be67b",
    "eapol-smoke": "930ecfad701ecb5c8e91ea764c3080d0a3be6c105bcfad42854159c1847f6c8c",
    "esp": "cc8a0fff10fbba05a681f67e51b9b67e01befefe9e9b0ad4c54b00af42f72956",
    "fragmentation-smoke": "49e0b5ea1769743e5f256892f2423a82ea7fef87455a8a7dde39d1d3c785dc9b",
    "fuzz": "0e5994a715fecaf546e491bbebd901215c02a8742c216f22ddc1dc7fdac47bf4",
    "igmp-boundary": "fbfe953904645866a26f37f920cc915fd599710864ac7584aaedbc4c4d7523e8",
    "igmp-ci": "d07f3bad2b1e582aace53db2d4e7cd7a5bd85dfc4fc7149fbb48315de54ded77",
    "igmp-live-dry-run": "7f8ca5ddb5eff8d008143fa195c4fdf31d9692aee4266b2522aeb3b24e0ffb34",
    "igmp-smoke": "e18c74080c384c4f737b4f7455c49c20a1cac4e4211bd2a4fe59717cec493739",
    "ikev2": "e5746a33412a690ae1197351af92b545618cf210fa34b00b33df4dc636006519",
    "ip-fragment-smoke": "a05c44538fd7f5b7bfd5da6c5eeea295042eabb5ad643a5011495261cb1b6ba5",
    "ipsec-smoke": "68f511d01f2ceae16267da0d2c9b0b04e9f0f6a9b4b3f910fac806453dd5545f",
    "ipv4-enrichment": "ca5d8ac931ec41f6a5509cf13672b0b25aaf427548c60962eb50968fe2714e41",
    "ipv6-enrichment": "2f1cecaffd46d9ef912e0b67bea0570c2b7af464d9dc7bafe9716034df244f8a",
    "mdns-boundary": "14272c12f481b7ea6610cbb23f8e0f805919ef2e95a42d2660ff0e4e728020f1",
    "mdns-ci": "01376db2355d1fa801b26af23e36687a5e595ad1749591cf480448327c09255b",
    "mdns-live-dry-run": "7388a0eccc921fb024bf9d7273678792310c499e8f1a2f927d6f3dcc60786272",
    "mdns-pcap": "6c337a6b05166065d7ef0a24cdcd286259440eceda4114b518d91dfb996cae95",
    "mdns-smoke": "6198ec85aa72fd4d7cf779f2e4c65f585bdae9023b6ac7e429d64a0cab40725f",
    "ospf-smoke": "7f829d6e9bf0e5773466cb7b11cf7b3853fd0dcc81284d6aa980490d8ead16bb",
    "quic-ci": "55befea4d1ff89b95083f043d81ceceaf8297966f7c592fc4df59f101b32cc40",
    "quic-smoke": "21b2dd50385257e515b30884cc9146e5f2c7084acb31604a01486d7fb6bdf036",
    "radiotap-smoke": "45e1edc2ee939bcf00a1d0dd15d9f66a1a0f3c428888d716f7e0088da30070a5",
    "rip-smoke": "5dfd7ad4bc2428075418fa0de787a1df377c09d8223f6892a80cb964cbdec092",
    "rsn-smoke": "ca1936202ca6d35350cd610a7cfdbbd84483a0399c7292b6a5dca652a49acdcc",
    "smoke": "b84ad6040c4cce3e08b4644709e078cbdb084613141974846a7ca9fe67fce5e4",
    "snmp-boundary": "7bf311a663168514940265d49ec6f6cea43c3c0e63f50161a9c2ab1b707e4b47",
    "snmp-ci": "30bfb539dfafb9a93fc5058bc3e8a3b9f6d829db379c1dbb793b57a972a0ced1",
    "snmp-live-dry-run": "fdc15150796dd3d99461552c7f7fce01a932b9e01004b7ba74b8dd344c4f53bb",
    "snmp-smoke": "df44044299c8b5e06ac0e638af03613e6f70aeb893b2ba2ab1cc16c999e08a0f",
    "ssdp-boundary": "a899fb417d5f1243e69b1a8864e464334e4bc06c1cef540c09e6a832050cd6d1",
    "ssdp-ci": "41b2fb4217d926d16281b37a4c50b39219c0c25b0af6a737ad2005b6a372d9dc",
    "ssdp-live-dry-run": "f8cb701dadd3112df18b57b93aec96a23e279b0d548d238d6f973a54ef0d52f0",
    "ssdp-pcap": "cd39a2a697bee5ce74ba5a55a7a4e658b879f82650ac59d09bfe2646d1024868",
    "ssdp-smoke": "a5c26b0aac633fa0a8d7b69aa50e15dea2394b90a086da93108bd8e5a55410b8",
    "tcp-header": "e62e918200aacb46fdfcd5cde318bf412739f1c64bfbfae5b35034bbde69380c",
    "tcp-options": "c4a438c51f9ba728dffc3ffa1dd0ab15479d8fd80dfef6fadf5f3b42a8f31487",
    "tcp-smoke": "10ece5bd042f42c31f2a14f66afc10b8ffa4f287ee559dcf50d9e146c58bff46",
    "wild": "cf7366998528de74b2a0cf845223e445e74ec3b165e2a56e3d7bc5696ec23036",
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
