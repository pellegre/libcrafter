"""Deterministic probe catalog and plan-contract coverage."""

from __future__ import annotations

import hashlib
import json
import re
import unittest

from tools.probe.engine import cases, planning
from tools.probe.engine.model import ProbeRunRequest
from tools.probe.engine.protocols import registered_plugins


_SUBSTRATE_TERMS = re.compile(
    r"(?:hetzner|qemu|virtualbox|appliance|target[_ -]?service|"
    r"tools/(?:lab|endpoint|appliance)|lab-session|\bprovider\b|\blab\b)",
    re.IGNORECASE,
)

# Pins the complete ordered plan contract at a fixed seed. Per-case assertions
# below explain structural failures; this digest catches any unreviewed field or
# value drift across all protocol plans.
_CATALOG_DIGEST_SEED_17 = (
    "cfaa61f9776bfd27d454c2c2da7f0806af3e3c495003d597c428971acc6fd8f3"
)


def _substrate_hits(value: object, path: str = "$") -> list[str]:
    hits: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}"
            if _SUBSTRATE_TERMS.search(str(key)):
                hits.append(child)
            hits.extend(_substrate_hits(item, child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            hits.extend(_substrate_hits(item, f"{path}[{index}]"))
    elif isinstance(value, str) and _SUBSTRATE_TERMS.search(value):
        hits.append(path)
    return hits


class CatalogPlanTest(unittest.TestCase):
    def test_catalog_is_unique_and_plugin_owned(self) -> None:
        names = cases.known_case_names()
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(set(names), set(cases.PROBE_CASE_BY_NAME))

        owners: dict[str, list[str]] = {}
        for plugin in registered_plugins():
            for case in plugin.cases:
                owners.setdefault(case.name, []).append(plugin.name)
        self.assertEqual(set(owners), set(names))
        self.assertTrue(all(len(case_owners) == 1 for case_owners in owners.values()))

    def test_every_case_has_a_deterministic_substrate_free_plan(self) -> None:
        request = ProbeRunRequest(profile="all", seed=17, count=1)
        for sequence, case in enumerate(cases.PROBE_CASES):
            with self.subTest(case=case.name):
                first = planning.probe_plan_for_case(
                    request=request, case=case, sequence=sequence
                )
                second = planning.probe_plan_for_case(
                    request=request, case=case, sequence=sequence
                )
                self.assertEqual(first, second)
                self.assertEqual(first["case"], case.name)
                self.assertEqual(first["sequence"], sequence)
                self.assertEqual(first["stimulus"], case.stimulus)
                self.assertEqual(first["expected_response"], case.expected_response)
                self.assertEqual(_substrate_hits(first), [])

    def test_complete_plan_contract_matches_reviewed_snapshot(self) -> None:
        request = ProbeRunRequest(profile="all", seed=17, count=1)
        plans = [
            planning.probe_plan_for_case(
                request=request,
                case=case,
                sequence=sequence,
            )
            for sequence, case in enumerate(cases.PROBE_CASES)
        ]
        canonical = json.dumps(
            plans,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        self.assertEqual(
            hashlib.sha256(canonical).hexdigest(),
            _CATALOG_DIGEST_SEED_17,
        )

    def test_planned_selection_is_repeatable(self) -> None:
        selected = cases.profile_selected_cases("smoke", [])
        first = planning.planned_cases(selected, seed=9, count=20)
        second = planning.planned_cases(selected, seed=9, count=20)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 20)


if __name__ == "__main__":
    unittest.main()
