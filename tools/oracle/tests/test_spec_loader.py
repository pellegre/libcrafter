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

from tools.oracle.engine.generator import case_byte_policy_index
from tools.oracle.engine.spec_loader import (
    FeatureSpec,
    SpecValidationError,
    load_oracle_specs,
)


REPRESENTATIONS = {"typed", "raw_compatible"}
SUPPORT_VALUES = {"supported", "unsupported"}
DOT11_RADIOTAP_STRUCTURED_ERROR_TEST = (
    "crafter/tests/resilience.rs::"
    "malformed_dot11_and_radiotap_corpus_errors_carry_structured_fields"
)
MALFORMED_CORPUS_FIXTURE = "crafter/tests/fixtures/malformed/core-decode-corpus.hex"


def _matrix_entries(value: object) -> Sequence[Mapping[str, object]]:
    assert isinstance(value, list), "live matrix sections must be lists"
    entries: list[Mapping[str, object]] = []
    for entry in value:
        assert isinstance(entry, Mapping), "matrix entries must be objects"
        entries.append(entry)
    return entries


def _supported_cases_by_name(feature: FeatureSpec) -> dict[str, Mapping[str, object]]:
    raw_cases = feature.raw.get("supported_cases")
    assert isinstance(raw_cases, list), "supported_cases must be a list"
    cases: dict[str, Mapping[str, object]] = {}
    for raw_case in raw_cases:
        assert isinstance(raw_case, Mapping), "supported_cases entries must be objects"
        name = raw_case.get("name")
        assert isinstance(name, str), "supported_cases entries must have names"
        cases[name] = raw_case
    return cases


def _structured_error_cases(feature: FeatureSpec) -> Sequence[Mapping[str, object]]:
    raw_cases = feature.raw.get("structured_error_cases")
    assert isinstance(raw_cases, list), "structured_error_cases must be a list"
    cases: list[Mapping[str, object]] = []
    for raw_case in raw_cases:
        assert isinstance(raw_case, Mapping), "structured_error_cases entries must be objects"
        cases.append(raw_case)
    return cases


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

    def test_dot11_structured_error_policy_is_preserved(self) -> None:
        self._assert_structured_error_policy(
            feature_name="dot11_basic",
            aggregate_case="malformed-dot11-truncated-header",
            expected_decode_target="link:dot11",
            expected_rows={
                "short-dot11-frame-control",
                "truncated-dot11-data-header",
                "truncated-dot11-qos-control",
                "truncated-dot11-address-four",
                "truncated-dot11-tagged-parameter",
            },
        )

    def test_radiotap_structured_error_policy_is_preserved(self) -> None:
        self._assert_structured_error_policy(
            feature_name="radiotap_basic",
            aggregate_case="malformed-radiotap-truncated-header",
            expected_decode_target="link:radiotap",
            expected_rows={
                "short-radiotap-header",
                "invalid-radiotap-length-below-base",
                "radiotap-length-overrun",
                "unterminated-radiotap-present-bitmap",
                "truncated-radiotap-channel-field",
            },
        )

    def _assert_structured_error_policy(
        self,
        *,
        feature_name: str,
        aggregate_case: str,
        expected_decode_target: str,
        expected_rows: set[str],
    ) -> None:
        feature = self.specs.features[feature_name]
        supported_case = _supported_cases_by_name(feature)[aggregate_case]

        self.assertEqual(supported_case["byte_policy"], "structured_error")
        self.assertEqual(supported_case["offline_byte_comparison"], "excluded")
        self.assertEqual(
            supported_case["generator_policy"],
            {
                "strict_byte_comparison": "excluded",
                "reason": "structured_error",
            },
        )
        self.assertEqual(
            supported_case["crate_test_coverage"],
            {
                "test": DOT11_RADIOTAP_STRUCTURED_ERROR_TEST,
                "fixture": MALFORMED_CORPUS_FIXTURE,
            },
        )
        self.assertEqual(case_byte_policy_index().get(aggregate_case), "structured_error")

        rows = _structured_error_cases(feature)
        self.assertEqual({row["name"] for row in rows}, expected_rows)
        for row in rows:
            with self.subTest(feature=feature_name, row=row["name"]):
                self.assertEqual(row["coverage_case"], aggregate_case)
                self.assertEqual(row["decode_target"], expected_decode_target)
                self.assertEqual(row["crate_test"], DOT11_RADIOTAP_STRUCTURED_ERROR_TEST)
                self.assertEqual(row["fixture"], MALFORMED_CORPUS_FIXTURE)
                expected_error = row["expected_error"]
                self.assertIsInstance(expected_error, Mapping)
                assert isinstance(expected_error, Mapping)
                self.assertEqual(expected_error["kind"], "buffer-too-short")
                self.assertIsInstance(expected_error["context"], str)
                self.assertIsInstance(expected_error["required"], int)
                self.assertIsInstance(expected_error["available"], int)
                self.assertGreater(expected_error["required"], expected_error["available"])

    def test_missing_spec_root_raises(self) -> None:
        with self.assertRaises(SpecValidationError):
            load_oracle_specs("/nonexistent/oracle/spec/root")


if __name__ == "__main__":
    unittest.main()
