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
    "boundary": "39b66e31733e220fb657bf53c92d0906e30420f6521347656624f5eaaff9abf7",
    "ci": "c37779f1c21ecfa4c248fa1bc098859ed3a632b69bd5465bc5ddac3e5b9f83a8",
    "dot11-pcap": "a183c962ba2b3e2eb4ac38956a2cbbc72c4ec9d08ffdc270272398bd46848d75",
    "dot11-smoke": "9696816eadcb781664f6a34dc13fa91873f3049eff55a532b3d2c5c3445be67b",
    "eapol-smoke": "930ecfad701ecb5c8e91ea764c3080d0a3be6c105bcfad42854159c1847f6c8c",
    "esp": "cc8a0fff10fbba05a681f67e51b9b67e01befefe9e9b0ad4c54b00af42f72956",
    "fragmentation-smoke": "49e0b5ea1769743e5f256892f2423a82ea7fef87455a8a7dde39d1d3c785dc9b",
    "fuzz": "e37705a4fceda1c93c7a4012edb581520ba30dfc665225e3d9950283bd41caa4",
    "igmp-boundary": "feb7022878b1d93d32652bb340413300ab76714de3aaf5a85622fc5768f73cef",
    "igmp-ci": "74ab1417bb652931c4a4919a0b4bb3d884abb6cf9b023777c10caef63bf25d3b",
    "igmp-live-dry-run": "02aa24b00e837d0ece6f7af8f1980e0a7529bdb6f92cebab1e7055c41e9f2c77",
    "igmp-smoke": "5a47659287fbc81e8f0920515c9d4e64f976461f099e97259c9ff8b506c815ba",
    "ikev2": "e5746a33412a690ae1197351af92b545618cf210fa34b00b33df4dc636006519",
    "ip-fragment-smoke": "a05c44538fd7f5b7bfd5da6c5eeea295042eabb5ad643a5011495261cb1b6ba5",
    "ipsec-smoke": "68f511d01f2ceae16267da0d2c9b0b04e9f0f6a9b4b3f910fac806453dd5545f",
    "ipv4-enrichment": "ca5d8ac931ec41f6a5509cf13672b0b25aaf427548c60962eb50968fe2714e41",
    "ipv6-enrichment": "2f1cecaffd46d9ef912e0b67bea0570c2b7af464d9dc7bafe9716034df244f8a",
    "ospf-smoke": "7f829d6e9bf0e5773466cb7b11cf7b3853fd0dcc81284d6aa980490d8ead16bb",
    "radiotap-smoke": "45e1edc2ee939bcf00a1d0dd15d9f66a1a0f3c428888d716f7e0088da30070a5",
    "rip-smoke": "5dfd7ad4bc2428075418fa0de787a1df377c09d8223f6892a80cb964cbdec092",
    "rsn-smoke": "ca1936202ca6d35350cd610a7cfdbbd84483a0399c7292b6a5dca652a49acdcc",
    "smoke": "0412ac1b889006cbba3926e9da68ae308a73f8cfa1bb0a218a7247985b2091ea",
    "snmp-boundary": "0eaca1de19d8bc3c17b7446f90df090c6656bd348ae0b0e928665969ed1ec61f",
    "snmp-ci": "e5fbdd1e3a20bf2d10346e394b1609c977e0bfa03db2c96e1092f9762c4583d8",
    "snmp-live-dry-run": "859559c89d8d5f913a990b863502f8f6f6ad18dfc39668e876b0d8733beb54df",
    "snmp-smoke": "fbfe4b97af872987cb532c3144b95abb0bd0ad32eb119c1bbf83ae2066e286d2",
    "tcp-header": "e62e918200aacb46fdfcd5cde318bf412739f1c64bfbfae5b35034bbde69380c",
    "tcp-options": "c4a438c51f9ba728dffc3ffa1dd0ab15479d8fd80dfef6fadf5f3b42a8f31487",
    "tcp-smoke": "10ece5bd042f42c31f2a14f66afc10b8ffa4f287ee559dcf50d9e146c58bff46",
    "wild": "d5ede06275bf295a61d66ad02ec40e84493ed84eec43e12a74109fe15ca6f75a",
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
