"""Offline unit coverage for SCTP probe registration and dry-run plans."""

from __future__ import annotations

import ipaddress
import tempfile
import unittest
from pathlib import Path

from tools.probe.engine import capabilities
from tools.probe.engine import cases as probe_cases
from tools.probe.engine import planning
from tools.probe.engine.lab import probe_capabilities_from_lab_capabilities
from tools.probe.engine.model import ProbeRunRequest
from tools.probe.engine.protocols import PROTOCOL_REGISTRY
from tools.probe.engine.protocols import sctp as sctp_protocol
from tools.probe.testing import probe_acceptance


SCTP_CASE_NAMES = tuple(case.name for case in sctp_protocol.SCTP_PROBE_CASES)


def _request(**overrides: object) -> ProbeRunRequest:
    base = {
        "provider": "local-dry-run",
        "profile": sctp_protocol.SCTP_SMOKE_PROFILE,
        "seed": 9262,
        "count": len(SCTP_CASE_NAMES),
        "case_names": [],
        "dry_run": True,
    }
    base.update(overrides)
    return ProbeRunRequest(**base)  # type: ignore[arg-type]


def _sctp_plan(case_name: str, *, seed: int = 9262, sequence: int = 0) -> dict:
    case = probe_cases.PROBE_CASE_BY_NAME[case_name]
    return planning.probe_plan_for_case(
        request=_request(seed=seed),
        case=case,
        sequence=sequence,
    )


class SctpProbeRegistrationTest(unittest.TestCase):
    def test_sctp_plugin_registers_cases_and_hooks(self) -> None:
        plugin = PROTOCOL_REGISTRY.require("sctp")

        self.assertEqual(tuple(case.name for case in plugin.cases), SCTP_CASE_NAMES)
        self.assertEqual(plugin.planned_only_cases, frozenset(SCTP_CASE_NAMES))
        self.assertEqual(plugin.stimulus_endpoint_cases, frozenset())
        self.assertIs(plugin.failure_reasons, sctp_protocol.sctp_failure_reasons)
        self.assertIs(plugin.lab_capabilities, sctp_protocol.sctp_lab_capabilities)
        self.assertEqual(
            plugin.profile_counts[sctp_protocol.SCTP_SMOKE_PROFILE],
            {name: 1 for name in SCTP_CASE_NAMES},
        )

    def test_sctp_cases_are_catalog_entries_with_expected_metadata(self) -> None:
        for case in sctp_protocol.SCTP_PROBE_CASES:
            with self.subTest(case=case.name):
                self.assertIs(probe_cases.PROBE_CASE_BY_NAME[case.name], case)
                self.assertEqual(case.metadata["protocol"], "sctp")
                self.assertEqual(case.metadata["service"], "sctp-controlled-peer")
                self.assertIs(case.metadata["planned_only"], True)
                self.assertIs(case.metadata["live_capable"], True)
                self.assertEqual(case.required_capabilities, ["sctp_controlled_peer"])

    def test_sctp_smoke_profile_membership_is_ordered(self) -> None:
        self.assertIn(sctp_protocol.SCTP_SMOKE_PROFILE, probe_cases.known_profiles())
        self.assertEqual(
            probe_cases.profile_case_names(sctp_protocol.SCTP_SMOKE_PROFILE),
            SCTP_CASE_NAMES,
        )
        self.assertEqual(
            probe_cases.profile_default_count(sctp_protocol.SCTP_SMOKE_PROFILE),
            len(SCTP_CASE_NAMES),
        )


class SctpProbePlanDispatchTest(unittest.TestCase):
    def test_plan_builders_are_registered_with_identity(self) -> None:
        for case_name in SCTP_CASE_NAMES:
            with self.subTest(case=case_name):
                self.assertIn(case_name, planning.PLAN_BUILDERS)
                self.assertIs(
                    planning.PLAN_BUILDERS[case_name],
                    planning._sctp_probe_plan,
                )
                self.assertIn(case_name, planning.PLANNED_ONLY_REGISTERED_CASES)

    def test_native_data_plan_carries_sctp_wire_intent(self) -> None:
        plan = _sctp_plan("sctp-native-data-exchange")

        self.assertEqual(plan["case"], "sctp-native-data-exchange")
        self.assertIs(plan["planned_only"], True)
        self.assertIs(plan["live_capable"], True)
        self.assertEqual(plan["protocol"], "sctp")
        self.assertEqual(plan["transport"], "sctp")
        self.assertEqual(plan["packet"]["stack"], ["ipv4", "sctp"])
        self.assertEqual(plan["packet"]["layers"]["ipv4"]["protocol"], "sctp")
        self.assertEqual(plan["packet"]["layers"]["sctp"]["chunks"], ["data"])
        self.assertEqual(plan["target_service"]["kind"], "sctp-controlled-peer")
        self.assertEqual(plan["target_service"]["behavior"], "data")
        self.assertIn("sctp and src host", plan["capture_filter"])
        self.assertEqual(plan["sctp"]["validation"]["expected_decode"], "sctp")
        self.assertTrue(plan["wire_requirements"]["dry_run_only_until_adapter"])
        self.assertEqual(
            plan["stimulus_driver"]["adapter_module"],
            "tools/probe/adapters/src/sctp.rs",
        )

    def test_udp_encap_plan_uses_rfc6951_port(self) -> None:
        plan = _sctp_plan("sctp-udp-encap-data-exchange", sequence=2)

        self.assertEqual(plan["transport"], "udp+sctp")
        self.assertEqual(plan["packet"]["stack"], ["ipv4", "udp", "sctp"])
        self.assertEqual(plan["packet"]["layers"]["ipv4"]["protocol"], "udp")
        self.assertEqual(plan["packet"]["layers"]["udp"]["src_port"], 9899)
        self.assertEqual(plan["packet"]["layers"]["udp"]["dst_port"], 9899)
        self.assertIn("udp and src host", plan["capture_filter"])
        self.assertEqual(plan["target_service"]["port"], 9899)

    def test_init_and_abort_plans_record_chunk_intent(self) -> None:
        init = _sctp_plan("sctp-init-handshake-plan", sequence=1)
        abort = _sctp_plan("sctp-abort-error-observation", sequence=3)

        self.assertEqual(init["packet"]["layers"]["sctp"]["chunks"], ["init"])
        self.assertEqual(init["sctp"]["validation"]["message_kind"], "init")
        self.assertEqual(abort["packet"]["layers"]["sctp"]["chunks"], ["abort"])
        self.assertEqual(abort["sctp"]["validation"]["message_kind"], "abort")

    def test_sctp_plans_are_deterministic_and_documentation_scoped(self) -> None:
        documentation = ipaddress.ip_network("198.51.100.0/24")

        for sequence, case_name in enumerate(SCTP_CASE_NAMES):
            with self.subTest(case=case_name):
                first = _sctp_plan(case_name, seed=9901, sequence=sequence)
                second = _sctp_plan(case_name, seed=9901, sequence=sequence)

                self.assertEqual(first, second)
                self.assertEqual(first["documentation_prefixes"], ["198.51.100.0/24"])
                self.assertIn(ipaddress.ip_address(first["source_ipv4"]), documentation)
                self.assertIn(ipaddress.ip_address(first["destination_ipv4"]), documentation)
                self.assertNotIn("payload_hex", first)
                self.assertNotIn("packet_hex", first)


class SctpProbeCapabilityTest(unittest.TestCase):
    def test_provider_without_sctp_peer_skips_with_stable_reason(self) -> None:
        case = probe_cases.PROBE_CASE_BY_NAME["sctp-native-data-exchange"]
        provider_capabilities = probe_capabilities_from_lab_capabilities(
            "sctp-less-lab",
            {
                "provider": "sctp-less-lab",
                "ipv4_unicast": True,
                "controlled_services": True,
                "sctp_controlled_peer": False,
            },
            dry_run=False,
        )

        missing = capabilities.missing_capabilities(case, provider_capabilities)

        self.assertEqual(missing, ["sctp_controlled_peer"])
        self.assertEqual(
            capabilities.skip_reason_for_missing_capability(case, missing[0]),
            capabilities.SKIP_REQUIRES_SCTP_CONTROLLED_PEER,
        )

    def test_local_dry_run_grants_sctp_planning_capability(self) -> None:
        provider_capabilities = probe_capabilities_from_lab_capabilities(
            "local-dry-run",
            {
                "provider": "local-dry-run",
                "dry_run": True,
                "ipv4_unicast": True,
                "controlled_services": True,
                "sctp_controlled_peer": False,
            },
            dry_run=True,
        )

        self.assertIs(provider_capabilities["sctp_controlled_peer"], True)
        self.assertIn("sctp_controlled_peer", provider_capabilities["capability_names"])
        self.assertEqual(
            provider_capabilities["capability_sources"]["sctp_controlled_peer"],
            ["ipv4_unicast", "controlled_services", "sctp_controlled_peer"],
        )


class SctpProbeAcceptanceTest(unittest.TestCase):
    def test_native_data_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "sctp-native-data-exchange",
                out_dir=Path(temp_dir) / "harness",
                provider="local-dry-run",
                profile=sctp_protocol.SCTP_SMOKE_PROFILE,
                seed=9263,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            self.assertEqual(outcome.report.get("provider"), "local-dry-run")
            request_plans = [
                plan
                for plan in outcome.request.get("probe_plans", [])
                if plan.get("case") == "sctp-native-data-exchange"
            ]
            self.assertTrue(request_plans, "request emitted no SCTP native data plan")
            self.assertEqual(request_plans[0]["packet"]["stack"], ["ipv4", "sctp"])
            self.assertTrue(request_plans[0]["planned_only"])

            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "sctp-native-data-exchange"
            ]
            self.assertTrue(results, "endpoint emitted no SCTP result")
            metadata = results[0].get("metadata", {})
            self.assertEqual(results[0].get("status"), "planned")
            self.assertTrue(metadata.get("dry_run"))
            self.assertTrue(metadata.get("planned_only"))
            self.assertEqual(metadata.get("validation", {}).get("expected_decode"), "sctp")
            self.assertEqual(
                metadata.get("target_service", {}).get("kind"),
                "sctp-controlled-peer",
            )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
