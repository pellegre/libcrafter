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
    "boundary": "b6cd01c580cee128fb0d5f264cadcde006f5fbc066f47a5cafb5352ed1208bfc",
    "ci": "e7b9cc9f2eeab2b86bb2f2bd1c041a99b6ef59aac42ec80a3d26c965722d31d3",
    "dot11-pcap": "a183c962ba2b3e2eb4ac38956a2cbbc72c4ec9d08ffdc270272398bd46848d75",
    "dot11-smoke": "9696816eadcb781664f6a34dc13fa91873f3049eff55a532b3d2c5c3445be67b",
    "eapol-smoke": "930ecfad701ecb5c8e91ea764c3080d0a3be6c105bcfad42854159c1847f6c8c",
    "esp": "cc8a0fff10fbba05a681f67e51b9b67e01befefe9e9b0ad4c54b00af42f72956",
    "fragmentation-smoke": "49e0b5ea1769743e5f256892f2423a82ea7fef87455a8a7dde39d1d3c785dc9b",
    "fuzz": "0a3ab123c1dbdd3210d4dade7025d3c56824dec0213a608ec38c9b4cabb4092b",
    "igmp-boundary": "1efef4615edf5376bc337b26d74e678066398c14d27a12359674bbda97de7564",
    "igmp-ci": "d905d5de79f0a0cd4921cca07cb75a502fb4fbece7f28f459f0641dff795afc5",
    "igmp-live-dry-run": "52a997480fe501cedcea8a98fd1be3bb04481ded4e8bce5a9b710b7e8d5d8b1f",
    "igmp-smoke": "da473e2b680092c40b7edd198bb171843e442ca41cac4c9cabc760e06c521add",
    "ikev2": "e5746a33412a690ae1197351af92b545618cf210fa34b00b33df4dc636006519",
    "ip-fragment-smoke": "a05c44538fd7f5b7bfd5da6c5eeea295042eabb5ad643a5011495261cb1b6ba5",
    "ipsec-smoke": "68f511d01f2ceae16267da0d2c9b0b04e9f0f6a9b4b3f910fac806453dd5545f",
    "ipv4-enrichment": "ca5d8ac931ec41f6a5509cf13672b0b25aaf427548c60962eb50968fe2714e41",
    "ipv6-enrichment": "2f1cecaffd46d9ef912e0b67bea0570c2b7af464d9dc7bafe9716034df244f8a",
    "ospf-smoke": "7f829d6e9bf0e5773466cb7b11cf7b3853fd0dcc81284d6aa980490d8ead16bb",
    "radiotap-smoke": "45e1edc2ee939bcf00a1d0dd15d9f66a1a0f3c428888d716f7e0088da30070a5",
    "rip-smoke": "5dfd7ad4bc2428075418fa0de787a1df377c09d8223f6892a80cb964cbdec092",
    "rsn-smoke": "ca1936202ca6d35350cd610a7cfdbbd84483a0399c7292b6a5dca652a49acdcc",
    "smoke": "b72d0ae54db1efec2b44ce7303ad3e9fffafba678e48b850aed4e27bc8a410a4",
    "tcp-header": "e62e918200aacb46fdfcd5cde318bf412739f1c64bfbfae5b35034bbde69380c",
    "tcp-options": "c4a438c51f9ba728dffc3ffa1dd0ab15479d8fd80dfef6fadf5f3b42a8f31487",
    "tcp-smoke": "10ece5bd042f42c31f2a14f66afc10b8ffa4f287ee559dcf50d9e146c58bff46",
    "wild": "f741d09b1aba80d4f51b04f338e1a5c43fe759b787130f66b59b179b4df5537b",
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
