"""Unit coverage for the data-driven DNS offline oracle suite.

Step 27 adds a reproducible offline suite that forces every offline-eligible DNS
case in each direction its feature spec declares. The selection is data-driven:
the generator honors each ``supported_cases`` entry's ``directions`` and
``byte_policy``, and ``tools/oracle/run specs suite`` enumerates the same matrix
with deterministic seeds and artifact paths.

These checks read the executable specs only (no Scapy and no libcrafter build),
so they run under bare ``python3 -m unittest`` alongside the existing oracle
tests.
"""

from __future__ import annotations

import unittest

from tools.oracle.engine.cli import _derive_suite_seed, _suite_offline_cases
from tools.oracle.engine.generator import PacketGenerator, generate_plans, load_stack_grammar


def _dns_supported_cases() -> list[dict]:
    grammar = load_stack_grammar()
    return list(grammar["features"]["dns_behavior"]["supported_cases"])


class SupportedCaseDirectionFilterTest(unittest.TestCase):
    """The generator must honor each case's declared directions and policy."""

    def setUp(self) -> None:
        self.generator = PacketGenerator(seed=1, profile="ci")

    def test_reference_only_case_excluded_from_libcrafter_direction(self) -> None:
        for case in ("dns-compressed-names", "dns-name-compressed", "dns-name-records-compressed"):
            with self.subTest(case=case):
                self.assertTrue(
                    self.generator._case_supported_in_direction(case, "reference_to_libcrafter")
                )
                self.assertFalse(
                    self.generator._case_supported_in_direction(case, "libcrafter_to_reference")
                )

    def test_libcrafter_only_case_excluded_from_reference_direction(self) -> None:
        case = "crafter-dns-name-uncompressed"
        self.assertTrue(
            self.generator._case_supported_in_direction(case, "libcrafter_to_reference")
        )
        self.assertFalse(
            self.generator._case_supported_in_direction(case, "reference_to_libcrafter")
        )

    def test_both_direction_case_allowed_in_both_directions(self) -> None:
        case = "dns-record-txt"
        self.assertTrue(
            self.generator._case_supported_in_direction(case, "reference_to_libcrafter")
        )
        self.assertTrue(
            self.generator._case_supported_in_direction(case, "libcrafter_to_reference")
        )

    def test_structured_error_cases_excluded_from_offline_directions(self) -> None:
        excluded = [
            case["name"]
            for case in _dns_supported_cases()
            if case.get("byte_policy") == "structured_error"
        ]
        self.assertTrue(excluded, "expected at least one structured_error case in the spec")
        for case in excluded:
            with self.subTest(case=case):
                self.assertFalse(
                    self.generator._case_supported_in_direction(case, "reference_to_libcrafter")
                )
                self.assertFalse(
                    self.generator._case_supported_in_direction(case, "libcrafter_to_reference")
                )

    def test_undeclared_case_keeps_prior_behavior(self) -> None:
        # A case with no supported_cases entry is unaffected by the filter.
        self.assertTrue(
            self.generator._case_supported_in_direction("ipv4-udp", "libcrafter_to_reference")
        )


class GeneratedBatchDirectionTest(unittest.TestCase):
    """A libcrafter_to_reference DNS batch must be materializable by libcrafter."""

    def test_no_raw_or_questionless_dns_plans_in_libcrafter_direction(self) -> None:
        plans = generate_plans(
            seed=2702,
            profile="ci",
            backend="scapy",
            count=50,
            family="dns",
            direction="libcrafter_to_reference",
        )
        for plan in plans:
            dns = plan.fields.get("dns")
            if not isinstance(dns, dict):
                continue
            with self.subTest(case=plan.case):
                # The libcrafter materializer rejects the Scapy-owned raw bytes
                # path and requires a questions field; neither must appear in the
                # libcrafter_to_reference direction.
                self.assertNotIn("dns_raw", dns, f"{plan.case} emitted a raw spec")
                self.assertIn(
                    "questions",
                    dns,
                    f"{plan.case} is missing questions for libcrafter materialization",
                )

    def test_compressed_cases_present_in_reference_direction(self) -> None:
        plans = generate_plans(
            seed=2701,
            profile="ci",
            backend="scapy",
            count=80,
            family="dns",
            direction="reference_to_libcrafter",
        )
        cases = {plan.case for plan in plans}
        # The reference direction is where the compressed/normalized cases live.
        self.assertIn("dns-compressed-names", cases)


class OfflineSuiteEmitterTest(unittest.TestCase):
    """The specs suite emitter must mirror the spec's direction matrix."""

    def test_emitter_covers_every_offline_eligible_direction(self) -> None:
        entries = _suite_offline_cases("dns_behavior")
        emitted = {(entry["case"], entry["direction"]) for entry in entries}

        expected: set[tuple[str, str]] = set()
        for case in _dns_supported_cases():
            if case.get("byte_policy") == "structured_error":
                continue
            directions = case.get("directions", [])
            for direction in ("reference_to_libcrafter", "libcrafter_to_reference"):
                if direction in directions or "roundtrip" in directions:
                    expected.add((case["name"], direction))

        self.assertEqual(emitted, expected)

    def test_emitter_excludes_compressed_cases_from_libcrafter_direction(self) -> None:
        entries = _suite_offline_cases("dns_behavior")
        emitted = {(entry["case"], entry["direction"]) for entry in entries}
        self.assertIn(("dns-compressed-names", "reference_to_libcrafter"), emitted)
        self.assertNotIn(("dns-compressed-names", "libcrafter_to_reference"), emitted)

    def test_emitter_excludes_structured_error_cases(self) -> None:
        entries = _suite_offline_cases("dns_behavior")
        emitted_cases = {entry["case"] for entry in entries}
        for case in _dns_supported_cases():
            if case.get("byte_policy") == "structured_error":
                self.assertNotIn(case["name"], emitted_cases)

    def test_derived_seed_is_deterministic_and_bounded(self) -> None:
        first = _derive_suite_seed(2701, "dns", "dns-query", "reference_to_libcrafter")
        second = _derive_suite_seed(2701, "dns", "dns-query", "reference_to_libcrafter")
        other = _derive_suite_seed(2701, "dns", "dns-query", "libcrafter_to_reference")
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)
        self.assertTrue(0 <= first < 1_000_000)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
