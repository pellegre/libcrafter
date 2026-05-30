"""Unit coverage for the oracle spec loader and the ICMPv4 live matrix.

These tests load the full oracle spec set through the public loader and assert
that the data-driven ICMPv4 live coverage matrix recorded under
``tools/oracle/specs/features/icmpv4-live.yaml`` is present and internally
consistent. The matrix is the source of truth for which ICMPv4 live cases are
eligible for provider-backed exchange and which are explicitly skipped with a
stable reason, so it must round-trip through the validated loader.
"""

from __future__ import annotations

import unittest
from collections.abc import Mapping, Sequence

from tools.oracle.engine.spec_loader import (
    FeatureSpec,
    SpecValidationError,
    load_oracle_specs,
)


REPRESENTATIONS = {"typed", "raw_compatible"}
SUPPORT_VALUES = {"supported", "unsupported"}


def _matrix_entries(value: object) -> Sequence[Mapping[str, object]]:
    assert isinstance(value, list), "live matrix sections must be lists"
    entries: list[Mapping[str, object]] = []
    for entry in value:
        assert isinstance(entry, Mapping), "matrix entries must be objects"
        entries.append(entry)
    return entries


class SpecLoaderTest(unittest.TestCase):
    def setUp(self) -> None:
        self.specs = load_oracle_specs()

    def test_full_spec_set_loads_without_error(self) -> None:
        # A clean load is the baseline contract; a failure here means a spec file
        # no longer validates.
        self.assertGreater(len(self.specs.features), 0)
        self.assertIn("icmpv4_errors", self.specs.features)

    def test_icmpv4_live_feature_is_registered(self) -> None:
        feature = self.specs.features.get("icmpv4_live")
        self.assertIsInstance(feature, FeatureSpec)
        assert feature is not None
        self.assertEqual(feature.layers, ("ipv4", "icmp"))
        self.assertIn("live_exchange", feature.directions)
        self.assertTrue(feature.strict_bytes)
        self.assertFalse(feature.malformed)
        self.assertIn("scapy", feature.backend_support)
        self.assertIn("libcrafter", feature.backend_support)

    def test_live_matrix_entries_are_well_formed(self) -> None:
        feature = self.specs.features["icmpv4_live"]
        entries = _matrix_entries(feature.raw["live_matrix"])
        self.assertGreater(len(entries), 0)

        seen_behaviors: set[str] = set()
        for entry in entries:
            behavior = entry.get("behavior")
            self.assertIsInstance(behavior, str)
            assert isinstance(behavior, str)
            self.assertNotIn(behavior, seen_behaviors, f"duplicate behavior {behavior}")
            seen_behaviors.add(behavior)

            self.assertIsInstance(entry.get("coverage_case"), str)

            directions = entry.get("directions")
            self.assertIsInstance(directions, list)
            assert isinstance(directions, list)
            self.assertIn("live_exchange", directions)

            self.assertIn(entry.get("representation"), REPRESENTATIONS)

            support = entry.get("scapy_support")
            self.assertIn(support, SUPPORT_VALUES)

            # Eligible (supported) live cases carry the sentinel skip reason; a
            # skipped case must record a non-sentinel stable reason so the gap is
            # never silent.
            skip_reason = entry.get("skip_reason")
            self.assertIsInstance(skip_reason, str)
            if support == "supported":
                self.assertEqual(skip_reason, "none")
            else:
                self.assertNotEqual(skip_reason, "none")

    def test_live_matrix_cases_are_declared_in_coverage_cases(self) -> None:
        feature = self.specs.features["icmpv4_live"]
        declared = set(feature.coverage_cases)
        for entry in _matrix_entries(feature.raw["live_matrix"]):
            case = entry["coverage_case"]
            assert isinstance(case, str)
            self.assertIn(
                case,
                declared,
                f"live matrix case {case} missing from coverage_cases",
            )

    def test_live_matrix_covers_the_required_icmp_families(self) -> None:
        feature = self.specs.features["icmpv4_live"]
        behaviors = {
            entry["behavior"]
            for entry in _matrix_entries(feature.raw["live_matrix"])
        }
        required = {
            "echo_request",
            "echo_reply",
            "destination_unreachable",
            "frag_needed_next_hop_mtu",
            "time_exceeded",
            "parameter_problem",
            "redirect",
            "source_quench",
            "timestamp",
            "information",
            "address_mask",
            "router_solicitation",
            "router_advertisement",
            "rfc4884_extension_mpls",
            "rfc4884_extension_framing",
            "rfc5837_interface_info_extension",
            "extended_echo_request",
            "legacy_raw_compatible_types",
        }
        missing = required - behaviors
        self.assertEqual(missing, set(), f"missing live behaviors: {sorted(missing)}")

    def test_unsupported_matrix_records_stable_skip_reasons(self) -> None:
        feature = self.specs.features["icmpv4_live"]
        entries = _matrix_entries(feature.raw["unsupported_matrix"])
        self.assertGreater(len(entries), 0)
        for entry in entries:
            self.assertEqual(entry.get("scapy_support"), "unsupported")
            skip_reason = entry.get("skip_reason")
            self.assertIsInstance(skip_reason, str)
            assert isinstance(skip_reason, str)
            self.assertNotEqual(skip_reason.strip(), "")
            self.assertNotEqual(skip_reason, "none")

    def test_missing_spec_root_raises(self) -> None:
        with self.assertRaises(SpecValidationError):
            load_oracle_specs("/nonexistent/oracle/spec/root")


if __name__ == "__main__":
    unittest.main()
