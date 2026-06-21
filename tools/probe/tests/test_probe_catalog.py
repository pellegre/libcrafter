"""Unit coverage for the probe case catalog and lookup helpers."""

from __future__ import annotations

import unittest

from tools.probe.engine import cases, cli
from tools.probe.engine.model import EndpointRole, ProbeCase


class ProbeCatalogTest(unittest.TestCase):
    def test_known_case_names_are_sorted_and_complete(self) -> None:
        names = cases.known_case_names()

        self.assertEqual(names, tuple(sorted(names)))
        self.assertEqual(set(names), {case.name for case in cases.PROBE_CASES})
        self.assertEqual(len(names), len(set(names)))
        for expected in (
            "icmp-echo",
            "tcp-syn-open",
            "tcp-syn-closed",
            "dns-query",
            "ttl-expired",
            "arp-resolution",
        ):
            self.assertIn(expected, names)

    def test_case_by_name_returns_catalog_entry(self) -> None:
        case = cases.case_by_name("dns-query")

        self.assertIsInstance(case, ProbeCase)
        self.assertEqual(case.name, "dns-query")
        self.assertIs(case, cases.PROBE_CASE_BY_NAME["dns-query"])

    def test_case_by_name_unknown_lists_available_cases(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            cases.case_by_name("not-a-case")

        message = str(ctx.exception)
        self.assertIn("not-a-case", message)
        for name in cases.known_case_names():
            self.assertIn(name, message)

    def test_case_name_filters_deduplicates_and_preserves_order(self) -> None:
        parsed = cases.case_name_filters(
            ["dns-query, icmp-echo", "dns-query", " tcp-syn-open ", ""]
        )

        self.assertEqual(parsed, ["dns-query", "icmp-echo", "tcp-syn-open"])

    def test_case_name_filters_empty_input(self) -> None:
        self.assertEqual(cases.case_name_filters(None), [])
        self.assertEqual(cases.case_name_filters([]), [])
        self.assertEqual(cases.case_name_filters(["", "  "]), [])

    def test_selected_cases_without_names_returns_full_catalog(self) -> None:
        selected = cases.selected_cases([])

        self.assertEqual(
            [case.name for case in selected],
            [case.name for case in cases.PROBE_CASES],
        )

    def test_selected_cases_preserves_requested_order(self) -> None:
        selected = cases.selected_cases(["dns-query", "icmp-echo"])

        self.assertEqual(
            [case.name for case in selected],
            ["dns-query", "icmp-echo"],
        )

    def test_selected_cases_unknown_name_raises_with_available_list(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            cases.selected_cases(["dns-query", "ghost-case"])

        message = str(ctx.exception)
        self.assertIn("ghost-case", message)
        for name in cases.known_case_names():
            self.assertIn(name, message)

    def test_endpoint_roles_serialize_to_stable_json_objects(self) -> None:
        self.assertTrue(cases.ENDPOINT_ROLES)
        for role in cases.ENDPOINT_ROLES:
            self.assertIsInstance(role, EndpointRole)
            payload = role.to_dict()
            self.assertEqual(
                set(payload),
                {"role", "responsibilities", "capabilities", "metadata"},
            )
            self.assertEqual(payload["role"], role.role)
            self.assertIsInstance(payload["responsibilities"], list)
            self.assertIsInstance(payload["capabilities"], list)
            self.assertIsInstance(payload["metadata"], dict)

        roles = [role.role for role in cases.ENDPOINT_ROLES]
        self.assertEqual(roles, ["stimulus", "target", "router"])
        self.assertEqual(len(roles), len(set(roles)))

    def test_cli_reexports_catalog_for_backward_compatibility(self) -> None:
        self.assertIs(cli._PROBE_CASES, cases.PROBE_CASES)
        self.assertIs(cli._PROBE_CASE_BY_NAME, cases.PROBE_CASE_BY_NAME)
        self.assertIs(cli._ENDPOINT_ROLES, cases.ENDPOINT_ROLES)
        self.assertIs(cli._selected_cases, cases.selected_cases)
        self.assertIs(cli._case_name_filters, cases.case_name_filters)

    def test_igmp_profile_cases_are_focused_and_ordered(self) -> None:
        self.assertEqual(
            cases.IGMP_PROFILE_CASE_NAMES,
            (
                "igmp-membership-query-observation",
                "igmp-v2-membership-report-emission",
                "igmp-v2-leave-group-emission",
                "igmp-v3-source-list-report",
            ),
        )

        selected = cases.profile_selected_cases("igmp", [])
        self.assertEqual(
            [case.name for case in selected],
            list(cases.IGMP_PROFILE_CASE_NAMES),
        )
        self.assertEqual(cases.profile_default_count("igmp"), len(selected))

    def test_igmp_cases_carry_multicast_peer_capabilities(self) -> None:
        for case in cases.IGMP_PROBE_CASES:
            with self.subTest(case=case.name):
                self.assertIn(case.name, cases.PROBE_CASE_BY_NAME)
                self.assertEqual(case.metadata["protocol"], "igmp")
                self.assertEqual(case.metadata["suite"], "behavior")
                self.assertEqual(case.metadata["layer"], "network")
                self.assertIs(case.metadata["ipv4_only"], True)
                self.assertIs(case.metadata["planned_only"], True)
                self.assertEqual(
                    case.required_capabilities,
                    ["ipv4_multicast", "igmp_peer"],
                )


if __name__ == "__main__":
    unittest.main()
