"""Compatibility coverage for oracle direction name aliases."""

from __future__ import annotations

import unittest

from tools.oracle.engine.corpus import packet_plan_from_object
from tools.oracle.engine import cli
from tools.oracle.engine.directions import normalize_direction
from tools.oracle.engine.generator import generate_plans
from tools.oracle.engine.live import live_execution_directions


class DirectionAliasTest(unittest.TestCase):
    def test_legacy_reference_direction_names_normalize(self) -> None:
        self.assertEqual(
            normalize_direction("reference_to_libcrafter"),
            "backend_to_libcrafter",
        )
        self.assertEqual(
            normalize_direction("libcrafter_to_reference"),
            "libcrafter_to_backend",
        )
        self.assertEqual(
            normalize_direction("scapy_to_libcrafter"),
            "backend_to_libcrafter",
        )
        self.assertEqual(
            normalize_direction("libcrafter_to_scapy"),
            "libcrafter_to_backend",
        )

    def test_generator_emits_canonical_direction_for_legacy_input(self) -> None:
        plans = generate_plans(
            seed=1,
            profile="smoke",
            count=1,
            direction="reference_to_libcrafter",
        )
        self.assertEqual(plans[0].direction, "backend_to_libcrafter")

    def test_corpus_plan_parser_canonicalizes_legacy_direction(self) -> None:
        plan = packet_plan_from_object(
            {
                "stack": ["ipv4", "udp", "payload"],
                "fields": {},
                "profile": "smoke",
                "seed": 1,
                "index": 0,
                "direction": "libcrafter_to_reference",
            }
        )
        self.assertEqual(plan.direction, "libcrafter_to_backend")

    def test_live_and_pcap_helpers_accept_legacy_directions(self) -> None:
        self.assertEqual(
            live_execution_directions("reference_to_libcrafter"),
            ["backend_to_libcrafter"],
        )
        self.assertEqual(
            cli._pcap_execution_directions("libcrafter_to_reference"),
            ["libcrafter_to_backend"],
        )


if __name__ == "__main__":
    unittest.main()
