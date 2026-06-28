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
    "boundary": "2499beab90b35b0abe1afdf4024df2e53b09fa3902f98c0bb5836c6f20776a6b",
    "ci": "d60a3a8cf8035af15560fff17850b15ad7edc94851b6072d4f8e3e8b316e0392",
    "dhcpv6-smoke": "08f26866d079baf38c023a4b54841aeaaf3d80109d82879ed7233ae50836b9b9",
    "dot11-pcap": "a183c962ba2b3e2eb4ac38956a2cbbc72c4ec9d08ffdc270272398bd46848d75",
    "dot11-smoke": "9696816eadcb781664f6a34dc13fa91873f3049eff55a532b3d2c5c3445be67b",
    "eapol-smoke": "930ecfad701ecb5c8e91ea764c3080d0a3be6c105bcfad42854159c1847f6c8c",
    "esp": "cc8a0fff10fbba05a681f67e51b9b67e01befefe9e9b0ad4c54b00af42f72956",
    "fragmentation-smoke": "49e0b5ea1769743e5f256892f2423a82ea7fef87455a8a7dde39d1d3c785dc9b",
    "fuzz": "51821c4b09639e471c0470c5c34c692422e127fedc7fb1cd0149793e500ed4e8",
    "igmp-boundary": "2427b9611b1581d7cca39bed3fef395d130ab8aa1bb8024249443b3eba592d66",
    "igmp-ci": "1d115243a9d5b10ad2d0ed732c22aad19ceaa1369fcae37678175e2e24d45b47",
    "igmp-live-dry-run": "1f0336e9681c078b0f85846ff581f3c5f8b44a99ed1c46786104958befa4dc71",
    "igmp-smoke": "34d3e8f4e3af44bb838d5feb5ba10f28825fb7bfdf057110f73a9352a30b605e",
    "ikev2": "e5746a33412a690ae1197351af92b545618cf210fa34b00b33df4dc636006519",
    "ip-fragment-smoke": "a05c44538fd7f5b7bfd5da6c5eeea295042eabb5ad643a5011495261cb1b6ba5",
    "ipsec-smoke": "68f511d01f2ceae16267da0d2c9b0b04e9f0f6a9b4b3f910fac806453dd5545f",
    "ipv4-enrichment": "ca5d8ac931ec41f6a5509cf13672b0b25aaf427548c60962eb50968fe2714e41",
    "ipv6-enrichment": "2f1cecaffd46d9ef912e0b67bea0570c2b7af464d9dc7bafe9716034df244f8a",
    "ospf-smoke": "7f829d6e9bf0e5773466cb7b11cf7b3853fd0dcc81284d6aa980490d8ead16bb",
    "quic-ci": "3fe045b12b79c698ddf1e6dcd64566417164ebcbcf4248604315c982eb43bd73",
    "quic-smoke": "e511f7185124b4a54f956e48909662f2c89ec08acaedd55fb8f78ce04e74a94d",
    "radiotap-smoke": "45e1edc2ee939bcf00a1d0dd15d9f66a1a0f3c428888d716f7e0088da30070a5",
    "rip-smoke": "5dfd7ad4bc2428075418fa0de787a1df377c09d8223f6892a80cb964cbdec092",
    "rsn-smoke": "ca1936202ca6d35350cd610a7cfdbbd84483a0399c7292b6a5dca652a49acdcc",
    "smoke": "f066b37b2ed0cbe7ad52fc19441d9e753dd36f4ef04bc7e4dc744a67dd5a2dbd",
    "snmp-boundary": "7bf311a663168514940265d49ec6f6cea43c3c0e63f50161a9c2ab1b707e4b47",
    "snmp-ci": "30bfb539dfafb9a93fc5058bc3e8a3b9f6d829db379c1dbb793b57a972a0ced1",
    "snmp-live-dry-run": "fdc15150796dd3d99461552c7f7fce01a932b9e01004b7ba74b8dd344c4f53bb",
    "snmp-smoke": "df44044299c8b5e06ac0e638af03613e6f70aeb893b2ba2ab1cc16c999e08a0f",
    "ssdp-boundary": "8f3d20d3220af6bfa439feb87a2270c18b773c0a5fdb5be0b4ae07431aee5000",
    "ssdp-ci": "8c90b1d2f08a6a6d3872f38c58b2a5f5132e98570776d7c9cb9a1ac58a36567d",
    "ssdp-live-dry-run": "2c3ec021e50a1e82728ca6384459b594ef8fd5e4ceb44686b33a199bd4656578",
    "ssdp-pcap": "f5db4e8ad10d5729b8bd073d30a089eaeb8d2f4ec7aa862c2f6c69533208241f",
    "ssdp-smoke": "cae69338336f2e249eb28cd2271fac35f55526f0ede6a2864b22cb58e2ba1a19",
    "tcp-header": "e62e918200aacb46fdfcd5cde318bf412739f1c64bfbfae5b35034bbde69380c",
    "tcp-options": "c4a438c51f9ba728dffc3ffa1dd0ab15479d8fd80dfef6fadf5f3b42a8f31487",
    "tcp-smoke": "10ece5bd042f42c31f2a14f66afc10b8ffa4f287ee559dcf50d9e146c58bff46",
    "wild": "d1519fd947e638effe996b9dcc4db58eb41bdd0bd44a2aef2d16b401b39627df",
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
