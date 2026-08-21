"""Unit coverage for SCTP offline oracle smoke generation and suite wiring.

The full offline Scapy run is covered by the Step 105 acceptance command. These
tests keep the bare ``python3 -m unittest`` gate non-vacuous by pinning the
seeded plan matrix and the specs-suite command matrix without requiring Scapy,
Rust builds, external execution, or live traffic.
"""

from __future__ import annotations

import unittest
from collections.abc import Mapping

from tools.oracle.engine import cli
from tools.oracle.engine.cli import _derive_suite_seed, _suite_offline_cases
from tools.oracle.engine.generator import generate_plans
from tools.oracle.engine.model import PacketPlan


_SEED = 9260
_SCTP_SMOKE_CASES = {
    "sctp-native-ipv4-data",
    "sctp-native-ipv6-data",
    "sctp-udp-encap-data",
}
_SCTP_SMOKE_STACKS = {
    ("ipv4", "sctp"),
    ("ipv4", "udp", "sctp"),
    ("ipv6", "sctp"),
    ("ipv6", "udp", "sctp"),
}
_SUITE_DIRECTIONS = {"backend_to_libcrafter", "libcrafter_to_backend"}


def _smoke_plans(direction: str = "backend_to_libcrafter") -> list[PacketPlan]:
    return generate_plans(
        seed=_SEED,
        profile="sctp-smoke",
        count=10,
        backend="scapy",
        family="sctp",
        direction=direction,
    )


def _layer_fields(plan: PacketPlan, layer: str) -> Mapping[str, object]:
    fields = plan.fields.get(layer)
    assert isinstance(fields, Mapping), f"{plan.case} plan has no {layer} fields"
    return fields


class SctpSmokePlanGenerationTest(unittest.TestCase):
    """The ``sctp-smoke`` profile deterministically covers the offline matrix."""

    def test_sctp_smoke_covers_native_and_udp_encapsulated_stacks(self) -> None:
        for direction in sorted(_SUITE_DIRECTIONS):
            with self.subTest(direction=direction):
                plans = _smoke_plans(direction)

                self.assertEqual(len(plans), 10)
                self.assertEqual({plan.direction for plan in plans}, {direction})
                self.assertEqual({plan.case for plan in plans}, _SCTP_SMOKE_CASES)
                self.assertEqual({tuple(plan.stack) for plan in plans}, _SCTP_SMOKE_STACKS)
                self.assertEqual(
                    {plan.metadata.get("feature") for plan in plans},
                    {"sctp_core"},
                )
                self.assertTrue(all(plan.strict_bytes for plan in plans))

    def test_sctp_smoke_uses_protocol_correct_native_and_udp_encapsulation(self) -> None:
        for plan in _smoke_plans():
            with self.subTest(index=plan.index, stack=plan.stack, case=plan.case):
                sctp = _layer_fields(plan, "sctp")
                self.assertEqual(sctp.get("chunks"), ["data"])

                if tuple(plan.stack) == ("ipv4", "sctp"):
                    ipv4 = _layer_fields(plan, "ipv4")
                    self.assertEqual(ipv4.get("protocol"), "sctp")
                    self.assertEqual(plan.metadata.get("root_decoder"), "l3:ipv4")
                    self.assertNotIn("udp", plan.fields)
                elif tuple(plan.stack) == ("ipv6", "sctp"):
                    ipv6 = _layer_fields(plan, "ipv6")
                    self.assertEqual(ipv6.get("next_header"), "sctp")
                    self.assertEqual(plan.metadata.get("root_decoder"), "l3:ipv6")
                    self.assertNotIn("udp", plan.fields)
                elif tuple(plan.stack) == ("ipv4", "udp", "sctp"):
                    ipv4 = _layer_fields(plan, "ipv4")
                    udp = _layer_fields(plan, "udp")
                    self.assertEqual(ipv4.get("protocol"), "udp")
                    self.assertEqual(udp.get("src_port"), 9899)
                    self.assertEqual(udp.get("dst_port"), 9899)
                elif tuple(plan.stack) == ("ipv6", "udp", "sctp"):
                    ipv6 = _layer_fields(plan, "ipv6")
                    udp = _layer_fields(plan, "udp")
                    self.assertEqual(ipv6.get("next_header"), "udp")
                    self.assertEqual(udp.get("src_port"), 9899)
                    self.assertEqual(udp.get("dst_port"), 9899)
                else:  # pragma: no cover - guarded by the matrix assertion.
                    self.fail(f"unexpected SCTP smoke stack: {plan.stack!r}")

    def test_sctp_smoke_generation_is_deterministic(self) -> None:
        first = [plan.to_dict() for plan in _smoke_plans()]
        second = [plan.to_dict() for plan in _smoke_plans()]
        self.assertEqual(first, second)


class SctpOfflineSuiteEmitterTest(unittest.TestCase):
    """The specs suite exposes runnable SCTP cases in both offline directions."""

    def test_sctp_smoke_cases_are_runnable_in_both_offline_directions(self) -> None:
        entries = _suite_offline_cases("sctp_core")
        runnable = {
            (entry["case"], entry["direction"])
            for entry in entries
            if entry.get("contract_only") is not True
        }

        for case in _SCTP_SMOKE_CASES:
            for direction in _SUITE_DIRECTIONS:
                with self.subTest(case=case, direction=direction):
                    self.assertIn((case, direction), runnable)

    def test_sctp_contract_only_cases_are_reported_but_not_runnable(self) -> None:
        entries = _suite_offline_cases("sctp_core")
        contract_cases = {
            entry["case"]
            for entry in entries
            if entry.get("contract_only") is True
        }
        runnable_cases = {
            entry["case"]
            for entry in entries
            if entry.get("contract_only") is not True
        }

        for case in (
            "sctp-pcap-native-ipv4",
            "sctp-pcap-native-ipv6",
            "sctp-pcap-udp-encap",
            "sctp-udp-encap-raw-reject",
        ):
            with self.subTest(case=case):
                self.assertIn(case, contract_cases)
                self.assertNotIn(case, runnable_cases)

    def test_sctp_suite_seed_derivation_is_deterministic_per_direction(self) -> None:
        first = _derive_suite_seed(
            2701, "sctp", "sctp-native-ipv4-data", "backend_to_libcrafter"
        )
        second = _derive_suite_seed(
            2701, "sctp", "sctp-native-ipv4-data", "backend_to_libcrafter"
        )
        other = _derive_suite_seed(
            2701, "sctp", "sctp-native-ipv4-data", "libcrafter_to_backend"
        )

        self.assertEqual(first, second)
        self.assertNotEqual(first, other)
        self.assertTrue(0 <= first < 1_000_000)


class SctpPcapCanonicalizationTest(unittest.TestCase):
    """Pcap records use libcrafter display names but compare layer contracts."""

    def test_libcrafter_sctp_layer_name_canonicalizes(self) -> None:
        report = {
            "metadata": {
                "records": [
                    {
                        "layers": ["ipv6", "udp", "Sctp"],
                        "raw_hex": "60000000000000840000",
                    }
                ]
            }
        }

        records = cli._pcap_records(report)

        self.assertEqual(records[0]["layers"], ["ipv6", "udp", "sctp"])
        self.assertEqual(records[0]["raw_hex"], "60000000000000840000")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
