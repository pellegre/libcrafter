"""Behavior-lock snapshot test for the Scapy encode backend.

This is the backend-stage companion to ``test_refactor_snapshot.py``. Where the
generator snapshot pins the offline ``PacketPlan`` output, this test pins the
encoded *bytes* the Scapy backend produces, so the backend-migration steps prove
they move encode code without changing any wire output.

The bare unittest interpreter used for the offline gate has no Scapy installed,
so every Scapy-dependent assertion must skip cleanly. We mirror the plain-import
guard used by ``test_scapy_backend.py`` (``_scapy_available``): a bare
``import scapy`` rather than the backend ``import_scapy()`` bootstrap, so a
missing Scapy skips the test instead of triggering the re-exec/bootstrap path.

When Scapy *is* available, for each representative profile the test generates a
fixed corpus with ``generate_plans`` (seed/count below), encodes every plan with
``encode_packet_plans``, computes a SHA-256 digest over the concatenated encoded
bytes in order, and asserts it equals the pinned value in ``_EXPECTED``. The
pinned values can only be computed in a Scapy-enabled environment, so they are
filled in during the backend-migration steps (compute once, then hardcode); a
profile with no pin yet is skipped with a named reason so the gap is visible and
gets filled rather than silently dropped. There is no print or self-updating
logic, and no pinned profile's assertion is ever weakened.
"""

from __future__ import annotations

import hashlib
import unittest

from tools.oracle.engine.generator import generate_plans
from tools.oracle.engine.spec_loader import load_oracle_specs


def _scapy_available() -> bool:
    """Return True only when Scapy imports cleanly.

    The guard does a plain ``import`` rather than going through
    ``import_scapy()`` so a missing Scapy skips the test cleanly instead of
    triggering the backend's bootstrap/re-exec path.
    """

    try:
        import scapy  # type: ignore[import-untyped]  # noqa: F401
    except Exception:  # pragma: no cover - environment dependent
        return False
    return True


_HAS_SCAPY = _scapy_available()


# Fixed generation coordinates, matching the generator snapshot so the corpora
# line up: every profile is generated with this seed and count.
SEED = 12345
COUNT = 20


# Candidate profiles to lock encoded bytes for. ``smoke`` is required; the rest
# are exercised only when present in the loaded specs (intersected at runtime).
# These span Scapy materialization paths (per-layer build, raw-bytes stack
# encoders, IPsec, RIP) so the snapshot guards multiple backends.
CANDIDATE_PROFILES = (
    "smoke",
    "tcp-smoke",
    "bgp-smoke",
    "ospf-smoke",
    "rip-smoke",
    "igmp-smoke",
    "ipsec-smoke",
    "dot11-smoke",
)


# Pinned per-profile digests over the concatenated encoded-vector bytes. These
# can only be computed with Scapy installed, so they are filled in during the
# backend-migration steps (compute once, then hardcode); never edit a value to
# silence a real encode change. Under a Scapy-enabled run a profile missing from
# this mapping is skipped with a named reason (see below) so the gap is visible
# and gets pinned, rather than being silently dropped or fabricated here.
_EXPECTED: dict[str, str] = {}


def _selected_profiles() -> list[str]:
    """Representative profiles present in the loaded specs, order-stable."""

    available = set(load_oracle_specs().profiles)
    return [profile for profile in CANDIDATE_PROFILES if profile in available]


def _encode_digest(profile: str) -> str:
    """Digest the concatenated encoded bytes for ``profile``'s fixed corpus."""

    from tools.oracle.engine.backends.scapy.packets import encode_packet_plans

    plans = generate_plans(seed=SEED, profile=profile, count=COUNT, backend="scapy")
    digest = hashlib.sha256()
    for vector in encode_packet_plans(plans):
        digest.update(vector.to_bytes())
    return digest.hexdigest()


@unittest.skipUnless(_HAS_SCAPY, "scapy backend unavailable")
class ScapyEncodeSnapshotTest(unittest.TestCase):
    """Pin encoded packet bytes per representative profile when Scapy is here."""

    def test_smoke_profile_is_present(self) -> None:
        self.assertIn(
            "smoke",
            _selected_profiles(),
            "the required 'smoke' profile is missing from the loaded specs",
        )

    def test_encoded_bytes_match_pinned_digests(self) -> None:
        for profile in _selected_profiles():
            with self.subTest(profile=profile):
                expected = _EXPECTED.get(profile)
                if expected is None:
                    # No pin yet for this profile: skip with a named reason
                    # during the backend-migration steps, where the digest is
                    # computed once under Scapy and hardcoded into _EXPECTED.
                    # Skipping keeps the gap visible without fabricating a value
                    # or weakening any already-pinned profile's assertion.
                    self.skipTest(
                        f"no pinned encode digest for profile {profile!r}; "
                        "compute it under Scapy and add it to _EXPECTED"
                    )
                self.assertEqual(
                    _encode_digest(profile),
                    expected,
                    f"encoded bytes for profile {profile!r} changed; the "
                    "refactor must not alter Scapy encode output for a fixed "
                    "seed/count",
                )


if __name__ == "__main__":
    unittest.main()
