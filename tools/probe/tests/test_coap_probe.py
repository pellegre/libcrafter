"""Deterministic CoAP probe catalog, plan, rewrite, and skip-policy coverage."""

from __future__ import annotations

import ipaddress
import unittest
from unittest.mock import patch

from tools.probe.engine import cases as probe_cases
from tools.probe.engine import planning
from tools.probe.engine import target_services
from tools.probe.engine.model import ProbeRunRequest
from tools.probe.engine.protocols import (
    PROTOCOL_REGISTRY,
    missing_live_environment_confirmations,
)
from tools.probe.engine.protocols import coap as coap_protocol


COAP_CASE_NAMES = tuple(case.name for case in coap_protocol.COAP_PROBE_CASES)
COAP_LIVE_CASES = (
    "coap-unicast-get-content",
    "coap-empty-ack-separate-response",
    "coap-reset",
    "coap-observe-notification",
    "coap-block1-transfer",
    "coap-block2-transfer",
    "coap-echo-request-tag",
)
COAP_OFFLINE_CASES = tuple(name for name in COAP_CASE_NAMES if name not in COAP_LIVE_CASES)


def _request(**overrides: object) -> ProbeRunRequest:
    values = {
        "provider": "local-dry-run",
        "profile": coap_protocol.COAP_SMOKE_PROFILE,
        "seed": 5683,
        "count": len(COAP_CASE_NAMES),
        "case_names": [],
        "dry_run": True,
    }
    values.update(overrides)
    return ProbeRunRequest(**values)  # type: ignore[arg-type]


def _plan(case_name: str, *, seed: int = 5683, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed),
        case=probe_cases.PROBE_CASE_BY_NAME[case_name],
        sequence=sequence,
    )


class CoapProbeCatalogTest(unittest.TestCase):
    def test_plugin_registration_promotes_only_admitted_udp_cases(self) -> None:
        plugin = PROTOCOL_REGISTRY.require("coap")

        self.assertEqual(tuple(case.name for case in plugin.cases), COAP_CASE_NAMES)
        self.assertEqual(plugin.planned_only_cases, frozenset(COAP_OFFLINE_CASES))
        self.assertEqual(plugin.stimulus_endpoint_cases, frozenset(COAP_LIVE_CASES))
        self.assertEqual(
            plugin.profile_counts[coap_protocol.COAP_SMOKE_PROFILE],
            {name: 1 for name in COAP_CASE_NAMES},
        )
        self.assertIs(plugin.target_service, coap_protocol.coap_target_service_contribution)
        self.assertIs(plugin.rewrite_endpoint_addresses, coap_protocol.coap_rewrite_endpoint_addresses)
        self.assertIs(plugin.failure_reasons, coap_protocol.coap_failure_reasons)
        self.assertIs(plugin.lab_capabilities, coap_protocol.coap_lab_capabilities)
        self.assertIs(
            plugin.live_environment_confirmations,
            coap_protocol.missing_live_environment_confirmations,
        )

    def test_catalog_marks_live_capability_explicitly(self) -> None:
        for case in coap_protocol.COAP_PROBE_CASES:
            with self.subTest(case=case.name):
                self.assertIs(probe_cases.PROBE_CASE_BY_NAME[case.name], case)
                self.assertEqual(case.metadata["protocol"], "coap")
                self.assertIs(
                    case.metadata["planned_only"],
                    case.name in COAP_OFFLINE_CASES,
                )
                self.assertEqual(
                    case.metadata["appliance_runtime_profile"],
                    coap_protocol.COAP_APPLIANCE_PROFILE,
                )
                if case.name in COAP_LIVE_CASES:
                    self.assertIs(case.metadata["live_capable"], True)
                    self.assertEqual(case.required_capabilities, ["udp_service"])
                else:
                    self.assertIs(case.metadata["live_capable"], False)
                    self.assertIs(case.metadata["offline_only"], True)
                    self.assertEqual(case.required_capabilities, [])

    def test_coap_smoke_profile_is_ordered_and_complete(self) -> None:
        self.assertEqual(
            probe_cases.profile_case_names("coap-smoke"),
            COAP_CASE_NAMES,
        )
        self.assertEqual(
            probe_cases.profile_default_count("coap-smoke"),
            len(COAP_CASE_NAMES),
        )
        self.assertEqual(
            [case.name for case in probe_cases.profile_selected_cases("coap-smoke", [])],
            list(COAP_CASE_NAMES),
        )


class CoapProbePlanTest(unittest.TestCase):
    def test_builders_are_registered_with_identity(self) -> None:
        for case_name in COAP_CASE_NAMES:
            with self.subTest(case=case_name):
                self.assertIs(
                    planning.PLAN_BUILDERS[case_name],
                    planning._coap_probe_plan,
                )
                if case_name in COAP_OFFLINE_CASES:
                    self.assertIn(case_name, planning.PLANNED_ONLY_REGISTERED_CASES)
                else:
                    self.assertNotIn(case_name, planning.PLANNED_ONLY_REGISTERED_CASES)

    def test_plans_are_deterministic_documentation_safe_and_bounded(self) -> None:
        network = ipaddress.ip_network(coap_protocol.COAP_DOCUMENTATION_IPV4_PREFIX)
        for sequence, case_name in enumerate(COAP_CASE_NAMES):
            with self.subTest(case=case_name):
                first = _plan(case_name, seed=7252, sequence=sequence)
                second = _plan(case_name, seed=7252, sequence=sequence)
                self.assertEqual(first, second)
                if case_name in COAP_OFFLINE_CASES:
                    self.assertTrue(first["planned_only"])
                else:
                    self.assertNotIn("planned_only", first)
                self.assertEqual(first["protocol"], "coap")
                self.assertEqual(len(bytes.fromhex(first["payload_hex"])), first["payload_length"])
                self.assertIn(ipaddress.ip_address(first["source_ipv4"]), network)
                self.assertIn(ipaddress.ip_address(first["target_ipv4"]), network)
                self.assertTrue(first["exchange"]["bounded"])
                self.assertLessEqual(first["exchange"]["send_count"], 10)
                self.assertLessEqual(first["exchange"]["workload_timeout_seconds"], 30)
                self.assertLessEqual(first["exchange"]["capture_timeout_seconds"], 60)
                self.assertLessEqual(first["exchange"]["capture_max_bytes"], 16 * 1024 * 1024)
                self.assertEqual(
                    first["wire_requirements"]["appliance_runtime_profile"],
                    "lan-raw",
                )
                self.assertIs(
                    first["wire_requirements"]["dry_run_only_until_adapter"],
                    case_name in COAP_OFFLINE_CASES,
                )
                self.assertIs(
                    first["wire_requirements"]["stimulus_adapter_ready"],
                    case_name in COAP_LIVE_CASES,
                )

    def test_get_and_multi_response_plans_have_typed_decode_contracts(self) -> None:
        get = _plan("coap-unicast-get-content")
        separate = _plan("coap-empty-ack-separate-response", sequence=1)

        self.assertEqual(get["packet"]["coap"]["layer"], "Coap")
        self.assertEqual(get["packet"]["coap"]["code"], "0.01 GET")
        self.assertEqual(get["expected_coap"]["code"], "2.05 Content")
        self.assertEqual(get["validation"]["expected_decode"], "Coap")
        self.assertEqual(get["target_service"]["kind"], coap_protocol.COAP_SERVICE_KIND)
        self.assertTrue(get["target_service"]["controlled_responder"])
        self.assertTrue(get["live_capable"])

        self.assertEqual(separate["exchange"]["response_count"], 2)
        self.assertEqual(
            [model["code"] for model in separate["exchange"]["response_models"]],
            ["0.00 Empty", "2.05 Content"],
        )
        self.assertEqual(
            [model["type"] for model in separate["exchange"]["response_models"]],
            ["acknowledgement", "confirmable"],
        )

    def test_reset_observe_block_and_modern_option_plans_are_typed(self) -> None:
        reset = _plan("coap-reset", sequence=2)
        observe = _plan("coap-observe-notification", sequence=3)
        block1 = _plan("coap-block1-transfer", sequence=4)
        block2 = _plan("coap-block2-transfer", sequence=5)
        echo = _plan("coap-echo-request-tag", sequence=6)
        qblock = _plan("coap-qblock-planning", sequence=7)

        self.assertEqual(reset["expected_coap"]["type"], "reset")
        self.assertEqual(reset["expected_coap"]["code"], "0.00 Empty")
        self.assertEqual(observe["coap"]["options"][0]["number"], 6)
        self.assertEqual(observe["expected_coap"]["options"][0]["number"], 6)
        self.assertIn(27, [option["number"] for option in block1["coap"]["options"]])
        self.assertIn(23, [option["number"] for option in block2["expected_coap"]["options"]])
        self.assertEqual(
            [option["number"] for option in echo["coap"]["options"][-2:]],
            [252, 292],
        )
        self.assertIn(31, [option["number"] for option in qblock["coap"]["options"]])
        self.assertFalse(qblock["live_capable"])
        self.assertEqual(qblock["target_service"]["kind"], "none")

    def test_reliable_malformed_and_oscore_cases_fail_closed(self) -> None:
        csm = _plan("coap-reliable-csm", sequence=8)
        ping = _plan("coap-reliable-ping", sequence=9)
        malformed = _plan("coap-malformed-raw-fallback", sequence=10)
        oscore = _plan("coap-oscore-vector-exchange", sequence=11)

        self.assertEqual(csm["payload_hex"], "30e1220480")
        self.assertEqual(csm["coap"]["layer"], "CoapReliable")
        self.assertEqual(ping["payload_hex"], "01e2")
        self.assertEqual(ping["expected_payload_hex"], "01e3")
        self.assertFalse(csm["live_capable"])
        self.assertFalse(ping["live_capable"])

        self.assertEqual(malformed["validation"]["registry_layer"], "Raw")
        self.assertEqual(malformed["validation"]["raw_hex"], malformed["payload_hex"])
        self.assertEqual(malformed["validation"]["direct_decode_error"]["required"], 4)
        self.assertEqual(malformed["validation"]["direct_decode_error"]["available"], 3)

        self.assertEqual(
            oscore["payload_hex"],
            "44025d1f00003974396c6f63616c686f7374620914ff612f1092f1776f1c1668b3825e",
        )
        self.assertEqual(
            oscore["expected_payload_hex"],
            "64445d1f0000397490ffdbaad1e9a7e7b2a813d3c31524378303cdafae119106",
        )
        self.assertFalse(oscore["coap"]["secrets_in_plan"])
        self.assertIn(
            "controlled_oscore_context_not_configured",
            oscore["skip_reasons"]["live_promotion"],
        )


class CoapProbeTargetServiceAndRewriteTest(unittest.TestCase):
    def test_target_service_is_workload_readiness_not_provider_capability(self) -> None:
        plans = [_plan(name, sequence=index) for index, name in enumerate(COAP_CASE_NAMES)]
        contribution = coap_protocol.coap_target_service_contribution(plans, dry_run=True)

        self.assertFalse(contribution["starts_services"])
        self.assertEqual(len(contribution["services"]), 1)
        service = contribution["services"][0]
        self.assertEqual(service["query_count"], len(COAP_LIVE_CASES))
        self.assertEqual(service["cases"], list(COAP_LIVE_CASES))
        self.assertEqual(service["workload_readiness"], "required")
        self.assertFalse(service["supports"]["reliable_transport"])
        self.assertFalse(service["supports"]["oscore_context"])
        self.assertEqual(coap_protocol.coap_lab_capabilities({"provider": "qemu"}), {})

    def test_controlled_responder_script_is_bounded_deterministic_and_artifact_producing(self) -> None:
        plans = [_plan(name, sequence=index) for index, name in enumerate(COAP_LIVE_CASES)]
        first = target_services.target_service_setup_script(
            artifact_root="/tmp/probe-target",
            bind_ipv4="10.77.0.20",
            open_ports=[],
            closed_ports=[],
            dns_plans=[],
            coap_plans=plans,
        )
        second = target_services.target_service_setup_script(
            artifact_root="/tmp/probe-target",
            bind_ipv4="10.77.0.20",
            open_ports=[],
            closed_ports=[],
            dns_plans=[],
            coap_plans=plans,
        )

        self.assertEqual(first, second)
        self.assertIn('check_udp_port_free "$coap_bind_ipv4" 5683', first)
        self.assertIn("max_requests = min(10", first)
        self.assertIn("deadline = time.monotonic() + 60.0", first)
        self.assertIn("coap-responder.jsonl", first)
        self.assertIn("response_payloads_hex", first)

    def test_live_rewrite_updates_every_address_and_filter(self) -> None:
        rewritten = coap_protocol.coap_rewrite_endpoint_addresses(
            _plan("coap-unicast-get-content"),
            source_ipv4="10.77.0.10",
            target_ipv4="10.77.0.20",
            rewrite_source="lab_session",
        )
        source_port = rewritten["source_port"]

        self.assertEqual(rewritten["source_ipv4"], "10.77.0.10")
        self.assertEqual(rewritten["destination_ipv4"], "10.77.0.20")
        self.assertEqual(rewritten["target_ipv4"], "10.77.0.20")
        self.assertEqual(rewritten["packet"]["ipv4"]["src"], "10.77.0.10")
        self.assertEqual(rewritten["packet"]["ipv4"]["dst"], "10.77.0.20")
        self.assertEqual(rewritten["expected_response_packet"]["ipv4"]["src"], "10.77.0.20")
        self.assertEqual(rewritten["expected_response_packet"]["ipv4"]["dst"], "10.77.0.10")
        self.assertEqual(rewritten["target_service"]["bind_ipv4"], "10.77.0.20")
        self.assertEqual(
            rewritten["capture_filter"],
            f"udp and src host 10.77.0.20 and dst host 10.77.0.10 and src port 5683 and dst port {source_port}",
        )

    def test_offline_rewrite_is_stably_skipped(self) -> None:
        original = _plan("coap-malformed-raw-fallback", sequence=10)
        rewritten = coap_protocol.coap_rewrite_endpoint_addresses(
            original,
            source_ipv4="10.77.0.10",
            target_ipv4="10.77.0.20",
            rewrite_source="lab_session",
        )

        self.assertEqual(rewritten["source_ipv4"], original["source_ipv4"])
        self.assertEqual(
            rewritten["skip_reasons"]["address_rewrite"],
            ["offline_or_planned_only"],
        )
        self.assertEqual(rewritten["live_address_rewrite"]["status"], "skipped")
        self.assertEqual(rewritten["live_address_rewrite"]["reason"], "offline_or_planned_only")


class CoapProbeSkipPolicyTest(unittest.TestCase):
    def test_live_cases_require_both_confirmation_gates_and_have_adapter(self) -> None:
        for case_name in COAP_LIVE_CASES:
            with self.subTest(case=case_name):
                plan = _plan(case_name)
                self.assertTrue(plan["wire_requirements"]["live_requires_provider"])
                self.assertTrue(plan["wire_requirements"]["live_requires_confirm_live_run"])
                self.assertTrue(plan["wire_requirements"]["live_requires_coap_confirmation"])
                self.assertEqual(
                    plan["wire_requirements"]["coap_confirmation_environment"],
                    "LIBCRAFTER_COAP_LIVE_CONFIRM",
                )
                self.assertEqual(plan["skip_reasons"]["live_promotion"], [])
                self.assertEqual(plan["stimulus_driver"]["state"], "ready")
                self.assertFalse(plan["stimulus_driver"]["planned_only"])
                self.assertEqual(
                    plan["skip_reasons"]["capability"],
                    [
                        "requires_lan_raw_appliance",
                        "requires_ipv4_unicast",
                        "requires_controlled_service",
                        "requires_controlled_coap_responder",
                    ],
                )

    def test_coap_environment_confirmation_is_checked_before_live_provider_work(self) -> None:
        plan = _plan("coap-unicast-get-content")
        with patch.dict("os.environ", {}, clear=True):
            missing = coap_protocol.missing_live_environment_confirmation(plan)
            batch_missing = missing_live_environment_confirmations([plan])
        self.assertEqual(
            missing,
            {
                "environment": "LIBCRAFTER_COAP_LIVE_CONFIRM",
                "expected": "yes",
                "present": False,
            },
        )
        self.assertEqual(
            batch_missing,
            [
                {
                    "case": "coap-unicast-get-content",
                    "environment": "LIBCRAFTER_COAP_LIVE_CONFIRM",
                    "expected": "yes",
                    "present": False,
                }
            ],
        )
        with patch.dict(
            "os.environ",
            {"LIBCRAFTER_COAP_LIVE_CONFIRM": "yes"},
            clear=True,
        ):
            self.assertIsNone(coap_protocol.missing_live_environment_confirmation(plan))

    def test_offline_cases_never_acquire_live_capability_from_name(self) -> None:
        for case_name in COAP_OFFLINE_CASES:
            with self.subTest(case=case_name):
                plan = _plan(case_name)
                self.assertFalse(plan["live_capable"])
                self.assertTrue(plan["wire_requirements"]["offline_only"])
                self.assertFalse(plan["wire_requirements"]["requires_live_network"])
                self.assertFalse(plan["wire_requirements"]["live_requires_provider"])
                self.assertEqual(plan["target_service"]["kind"], "none")
                self.assertEqual(plan["skip_reasons"]["capability"], [])


if __name__ == "__main__":
    unittest.main()
