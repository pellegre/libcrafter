"""Unit coverage for the RIP oracle path: specs, plan generation, backends.

These tests guard the offline RIP oracle path end-to-end inside the engine the
way ``test_dhcp_oracle.py`` does for DHCP, without provisioning anything:

  * the RIP layer and feature specs load and declare the ``rip`` layer,
    the command/version matrix, the route-entry surface, and the AFI 0xFFFF
    authentication surface;
  * the ``rip-smoke`` profile generates the IPv4-root ``ipv4 / udp / rip`` stack
    deterministically for the layer-spec coverage cases (``rip-v1-request``,
    ``rip-v2-response``, ``rip-v2-auth``);
  * both backends agree on command / version / entry-count for the
    ``rip-v2-response`` strict-byte case, and both normalize the ``rip-auth``
    simple-password authentication type as 2.

The libcrafter-shaped truth is the canonical packet plan: its RIP field names
mirror the libcrafter ``Rip``/``RipEntry`` accessors (command, version,
reserved, entries with address_family / route_tag / address / subnet_mask /
next_hop / metric, and an auth sub-object), per
``tools/oracle/specs/layers/rip.yaml``. The Scapy reference backend must
reproduce that model from the same plan. Scapy assertions skip cleanly when the
backend is unavailable, matching ``test_dhcp_oracle.py`` and
``test_scapy_backend.py`` — the bare ``python3 -m unittest`` interpreter does
not have Scapy installed (the oracle CLI bootstraps it through ``uv``).
"""

from __future__ import annotations

import unittest
from collections.abc import Mapping, Sequence

from tools.oracle.engine.generator import generate_plans
from tools.oracle.engine.model import PacketPlan
from tools.oracle.engine.spec_loader import (
    FeatureSpec,
    LayerSpec,
    load_oracle_specs,
)


# The IPv4-root RIP stack the rip-smoke profile selects for the RIP layer-spec
# coverage cases.
_RIP_STACK = ["ipv4", "udp", "rip"]

# Fixed seed keeps generation deterministic and offline.
_SEED = 53

# RIP rides on IPv4 (20 octets) + UDP (8 octets); the RIP message begins at
# offset 28 and its first octet is the command.
_RIP_MESSAGE_OFFSET = 28

# AFI 0xFFFF marks a RIPv2 authentication entry; simple password is auth type 2.
_RIP_AFI_AUTH = 0xFFFF
_RIP_AUTH_TYPE_SIMPLE_PASSWORD = 2

# Pinned test-only documentation secret (matches features/rip-auth.yaml). It is
# a documentation test vector with no operational meaning.
_RIP_SIMPLE_PASSWORD = "rip-doc-secret"


def _require_scapy_backend():
    """Import the Scapy materialize/decode backend or skip when unavailable.

    The acceptance command runs ``python3 -m unittest`` on the bare interpreter,
    where Scapy is not installed; the oracle CLI only bootstraps Scapy through
    ``uv``. Skip cleanly there so the RIP protocol contract stays backend-owned
    rather than failing for a missing optional dependency, matching how the
    other backend tests guard their imports.
    """

    try:
        from tools.oracle.engine.backends.scapy import normalize, packets
    except Exception as exc:  # pragma: no cover - exercised only without Scapy.
        raise unittest.SkipTest(f"Scapy backend unavailable: {exc}")

    try:
        from tools.oracle.engine.backends.scapy.bootstrap import import_scapy

        import_scapy()
    except Exception as exc:  # pragma: no cover - exercised only without Scapy.
        raise unittest.SkipTest(f"Scapy is not importable: {exc}")

    return packets, normalize


def _rip_plan(*, command: object, version: int, entries: list, auth=None) -> PacketPlan:
    """Build the canonical libcrafter-shaped RIP packet plan.

    The RIP field block mirrors the libcrafter accessor names (command, version,
    reserved, entries, auth), so the plan itself is the libcrafter-shaped model
    the Scapy reference backend must reproduce. This mirrors the ``_rip_plan``
    helper in ``test_scapy_backend.py``.
    """

    rip_fields: dict = {"command": command, "version": version, "entries": entries}
    if auth is not None:
        rip_fields["auth"] = auth
    return PacketPlan(
        stack=list(_RIP_STACK),
        fields={
            "ipv4": {
                "src": "192.0.2.1",
                "dst": "224.0.0.9",
                "ttl": 1,
                "flags": "none",
                "identification": 1,
                "protocol": "udp",
            },
            "udp": {"src_port": 520, "dst_port": 520},
            "rip": rip_fields,
        },
        profile="rip-smoke",
        seed=_SEED,
        index=0,
        direction="reference_to_libcrafter",
        family="ipv4",
        feature_tags=["baseline", "ipv4", "udp", "rip"],
        case="rip-v2-response",
        strict_bytes=True,
        metadata={
            "root": "l3:ipv4",
            "root_decoder": "l3:ipv4",
            "stack_name": "ipv4_udp_rip",
        },
    )


def _scapy_rip_model(packets, normalize, plan: PacketPlan) -> Mapping[str, object]:
    """Materialize a RIP plan with Scapy and return the normalized rip layer."""

    vector = packets.encode_packet_plan(plan)
    decoded = normalize.decode_bytes(
        vector.to_bytes(), root="l3:ipv4", source_hex=vector.raw_hex
    )
    assert "rip" in decoded.layers, "scapy decode must surface a rip layer"
    rip = decoded.fields["rip"]
    assert isinstance(rip, Mapping)
    return rip


class RipSpecLoadingTest(unittest.TestCase):
    """The RIP layer and feature specs load and declare the RIP surface.

    These checks are backend-neutral (no Scapy import), so they always run.
    """

    def setUp(self) -> None:
        self.specs = load_oracle_specs()

    def test_rip_layer_spec_declares_header_and_entry_fields(self) -> None:
        layer = self.specs.layers.get("rip")
        self.assertIsInstance(layer, LayerSpec)
        assert layer is not None
        self.assertEqual(layer.name, "rip")
        # RIP parents UDP and carries the header + route-entry field surface
        # whose names mirror the libcrafter accessors.
        self.assertIn("udp", layer.parents)
        field_names = {field.name for field in layer.fields}
        for expected in (
            "command",
            "version",
            "reserved",
            "address_family",
            "route_tag",
            "address",
            "subnet_mask",
            "next_hop",
            "metric",
        ):
            self.assertIn(expected, field_names)
        self.assertIn("scapy", layer.backend_support)
        self.assertIn("libcrafter", layer.backend_support)

    def test_rip_feature_specs_are_registered(self) -> None:
        for name, expected_case in (
            ("rip_header", "rip-header-v2-response"),
            ("rip_entries", "rip-entries-v2-route"),
            ("rip_auth", "rip-auth-simple-password"),
        ):
            with self.subTest(feature=name):
                feature = self.specs.features.get(name)
                self.assertIsInstance(feature, FeatureSpec)
                assert feature is not None
                self.assertEqual(feature.layers, ("rip",))
                self.assertIn(expected_case, feature.coverage_cases)
                self.assertIn("scapy", feature.backend_support)
                self.assertIn("libcrafter", feature.backend_support)

    def test_scapy_backend_advertises_rip_feature_materialization(self) -> None:
        from tools.oracle.engine.backends.scapy import packets

        for name in ("rip_header", "rip_entries", "rip_auth", "ripng_rtes"):
            with self.subTest(feature=name):
                self.assertIn(name, packets._SUPPORTED_FEATURES)

    def test_rip_smoke_profile_is_registered(self) -> None:
        self.assertIn("rip-smoke", self.specs.profiles)


class RipSmokePlanGenerationTest(unittest.TestCase):
    """The ``rip-smoke`` profile generates the IPv4-root RIP stack.

    Generation is backend-neutral and seeded, so these checks always run and
    stay deterministic without touching any backend.
    """

    def _rip_smoke_plans(self, case: str) -> Sequence[PacketPlan]:
        return generate_plans(
            seed=_SEED,
            profile="rip-smoke",
            count=6,
            backend="scapy",
            case=case,
        )

    def test_rip_smoke_selects_ipv4_root_rip_stack(self) -> None:
        for case in ("rip-v1-request", "rip-v2-response", "rip-v2-auth"):
            with self.subTest(case=case):
                plans = self._rip_smoke_plans(case)
                self.assertTrue(
                    plans,
                    msg=f"expected rip-smoke plans for case {case!r}",
                )
                for plan in plans:
                    self.assertEqual(list(plan.stack), _RIP_STACK)
                    self.assertEqual(plan.case, case)
                    self.assertEqual(
                        plan.metadata.get(
                            "root_decoder", plan.metadata.get("root")
                        ),
                        "l3:ipv4",
                    )

    def test_rip_smoke_generation_is_deterministic(self) -> None:
        first = self._rip_smoke_plans("rip-v2-response")
        second = self._rip_smoke_plans("rip-v2-response")
        self.assertEqual(
            [plan.to_dict() for plan in first],
            [plan.to_dict() for plan in second],
        )


class RipV2ResponseBackendAgreementTest(unittest.TestCase):
    """Both backends agree on command/version/entry-count for rip-v2-response.

    The canonical libcrafter-shaped plan carries the RIPv2 response header and a
    single route entry; the Scapy reference backend must materialize and decode
    that same plan to a normalized ``rip`` layer with the same command, version,
    and entry count (byte_policy: strict_bytes). Scapy assertions skip cleanly
    when the backend is unavailable.
    """

    def _v2_response_plan(self) -> PacketPlan:
        return _rip_plan(
            command="response",
            version=2,
            entries=[
                {
                    "address_family": 2,
                    "route_tag": 7,
                    "address": "198.51.100.0",
                    "subnet_mask": "255.255.255.0",
                    "next_hop": "192.0.2.2",
                    "metric": 1,
                }
            ],
        )

    def test_libcrafter_model_carries_v2_response_header_and_entry(self) -> None:
        # The plan is the libcrafter-shaped model; assert its header/entry shape
        # directly so the agreement target is pinned even without Scapy.
        rip = self._v2_response_plan().fields["rip"]
        self.assertEqual(rip["command"], "response")
        self.assertEqual(rip["version"], 2)
        self.assertEqual(len(rip["entries"]), 1)
        self.assertEqual(rip["entries"][0]["address_family"], 2)

    def test_both_backends_agree_on_command_version_entry_count(self) -> None:
        packets, normalize = _require_scapy_backend()

        plan = self._v2_response_plan()
        reference = _scapy_rip_model(packets, normalize, plan)

        # The libcrafter-shaped truth: a RIPv2 response (command 2) carrying one
        # route entry. The Scapy reference backend must agree on all three.
        self.assertEqual(reference["command"], 2)
        self.assertEqual(reference["version"], 2)
        self.assertEqual(len(reference["entries"]), len(plan.fields["rip"]["entries"]))
        self.assertEqual(len(reference["entries"]), 1)


class RipAuthSimplePasswordTest(unittest.TestCase):
    """Both backends normalize the simple-password auth type as 2.

    The ``rip-auth`` simple-password case carries a leading AFI 0xFFFF
    authentication entry with authentication type 2 (RFC 2453 §4.1). The
    canonical plan declares ``auth.type == 2`` and the Scapy reference backend
    must normalize the decoded auth sub-object's ``auth_type`` as 2.
    """

    def _simple_password_plan(self) -> PacketPlan:
        return _rip_plan(
            command="response",
            version=2,
            entries=[{"address_family": 2, "address": "198.51.100.1", "metric": 1}],
            auth={"type": _RIP_AUTH_TYPE_SIMPLE_PASSWORD, "simple_password": _RIP_SIMPLE_PASSWORD},
        )

    def test_libcrafter_model_declares_auth_type_two(self) -> None:
        rip = self._simple_password_plan().fields["rip"]
        self.assertEqual(rip["auth"]["type"], _RIP_AUTH_TYPE_SIMPLE_PASSWORD)

    def test_both_backends_normalize_auth_type_as_two(self) -> None:
        packets, normalize = _require_scapy_backend()

        plan = self._simple_password_plan()
        reference = _scapy_rip_model(packets, normalize, plan)

        self.assertIn("auth", reference)
        auth = reference["auth"]
        self.assertIsInstance(auth, Mapping)
        # The AFI 0xFFFF authentication entry surfaces under "auth", and its
        # normalized type matches the libcrafter-shaped plan's auth type (2).
        self.assertEqual(auth["address_family"], _RIP_AFI_AUTH)
        self.assertEqual(auth["auth_type"], _RIP_AUTH_TYPE_SIMPLE_PASSWORD)
        self.assertEqual(
            auth["auth_type"], plan.fields["rip"]["auth"]["type"]
        )


if __name__ == "__main__":
    unittest.main()
