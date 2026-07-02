"""Offline unit coverage for NTP probe registration and dry-run plans."""

from __future__ import annotations

import ipaddress
import unittest

from tools.probe.engine import cases as probe_cases
from tools.probe.engine import planning
from tools.probe.engine.lab import probe_capabilities_from_lab_capabilities
from tools.probe.engine.model import ProbeRunRequest
from tools.probe.engine.protocols import PROTOCOL_REGISTRY
from tools.probe.engine.protocols import ntp as ntp_protocol


NTP_CASE_NAMES = tuple(case.name for case in ntp_protocol.NTP_PROBE_CASES)
NTP_LIVE_CASES = (
    "ntp-client-server-exchange",
    "ntp-kod-response",
    "ntp-extension-preservation",
    "ntp-nts-extension-plan",
)
NTP_OFFLINE_CASES = ("ntp-malformed-observation",)


def _request(**overrides: object) -> ProbeRunRequest:
    base = {
        "provider": "local-dry-run",
        "profile": ntp_protocol.NTP_SMOKE_PROFILE,
        "seed": 5906,
        "count": len(NTP_CASE_NAMES),
        "case_names": [],
        "dry_run": True,
    }
    base.update(overrides)
    return ProbeRunRequest(**base)  # type: ignore[arg-type]


def _ntp_plan(case_name: str, *, seed: int = 5906, sequence: int = 0) -> dict:
    case = probe_cases.PROBE_CASE_BY_NAME[case_name]
    return planning.probe_plan_for_case(
        request=_request(seed=seed),
        case=case,
        sequence=sequence,
    )


class NtpProbeRegistrationTest(unittest.TestCase):
    def test_ntp_plugin_registers_cases_and_hooks(self) -> None:
        plugin = PROTOCOL_REGISTRY.require("ntp")

        self.assertEqual(tuple(case.name for case in plugin.cases), NTP_CASE_NAMES)
        self.assertEqual(plugin.planned_only_cases, frozenset(NTP_CASE_NAMES))
        self.assertEqual(plugin.stimulus_endpoint_cases, frozenset(NTP_LIVE_CASES))
        self.assertIs(plugin.target_service, ntp_protocol.ntp_target_service_contribution)
        self.assertIs(plugin.rewrite_endpoint_addresses, ntp_protocol.ntp_rewrite_endpoint_addresses)
        self.assertIs(plugin.failure_reasons, ntp_protocol.ntp_failure_reasons)
        self.assertIs(plugin.lab_capabilities, ntp_protocol.ntp_lab_capabilities)

    def test_ntp_cases_are_catalog_entries_with_expected_capabilities(self) -> None:
        for case in ntp_protocol.NTP_PROBE_CASES:
            with self.subTest(case=case.name):
                self.assertIs(probe_cases.PROBE_CASE_BY_NAME[case.name], case)
                self.assertEqual(case.metadata["protocol"], "ntp")
                self.assertEqual(case.metadata["transport"], "udp")
                self.assertEqual(
                    case.metadata["service"],
                    ntp_protocol.NTP_SERVICE_KIND,
                )
                self.assertEqual(case.metadata["udp_port"], ntp_protocol.NTP_PORT)
                self.assertIs(case.metadata["planned_only"], True)
                if case.name in NTP_LIVE_CASES:
                    self.assertIs(case.metadata["live_capable"], True)
                    self.assertEqual(
                        case.required_capabilities,
                        ["ntp_controlled_responder", "privileged_udp_port"],
                    )
                else:
                    self.assertIs(case.metadata["offline_only"], True)
                    self.assertEqual(case.required_capabilities, ["ntp_offline_plan"])

    def test_ntp_smoke_profile_membership_is_ordered(self) -> None:
        self.assertEqual(
            probe_cases.profile_case_names(ntp_protocol.NTP_SMOKE_PROFILE),
            NTP_CASE_NAMES,
        )
        self.assertEqual(
            probe_cases.profile_default_count(ntp_protocol.NTP_SMOKE_PROFILE),
            len(NTP_CASE_NAMES),
        )
        self.assertEqual(
            [case.name for case in probe_cases.profile_selected_cases("ntp-smoke", [])],
            list(NTP_CASE_NAMES),
        )


class NtpProbePlanDispatchTest(unittest.TestCase):
    def test_plan_builders_are_registered_with_identity(self) -> None:
        for case_name in NTP_CASE_NAMES:
            with self.subTest(case=case_name):
                self.assertIn(case_name, planning.PLAN_BUILDERS)
                self.assertIs(
                    planning.PLAN_BUILDERS[case_name],
                    planning._ntp_probe_plan,
                )
                self.assertIn(case_name, planning.PLANNED_ONLY_REGISTERED_CASES)

    def test_client_server_plan_carries_wire_shape_and_target_service(self) -> None:
        plan = _ntp_plan("ntp-client-server-exchange")

        self.assertEqual(plan["case"], "ntp-client-server-exchange")
        self.assertIs(plan["planned_only"], True)
        self.assertIs(plan["live_capable"], True)
        self.assertEqual(plan["protocol"], "ntp")
        self.assertEqual(plan["transport"], "udp")
        self.assertEqual(plan["destination_port"], ntp_protocol.NTP_PORT)
        self.assertGreaterEqual(plan["source_port"], 49152)
        self.assertLess(plan["source_port"], 65536)
        self.assertEqual(plan["payload_length"], ntp_protocol.NTP_FIXED_HEADER_LEN)
        self.assertEqual(plan["expected_payload_length"], ntp_protocol.NTP_FIXED_HEADER_LEN)
        self.assertEqual(plan["payload_hex"], plan["udp_payload_hex"])
        self.assertEqual(len(bytes.fromhex(plan["payload_hex"])), plan["payload_length"])
        self.assertEqual(plan["packet"]["stack"], ["ipv4", "udp", "ntp"])
        self.assertEqual(plan["expected_response_packet"]["stack"], ["ipv4", "udp", "ntp"])
        self.assertEqual(plan["ntp"]["mode"], "client")
        self.assertEqual(plan["ntp"]["first_octet"], 0x23)
        self.assertEqual(plan["expected_ntp"]["mode"], "server")
        self.assertEqual(plan["expected_ntp"]["first_octet"], 0x24)
        self.assertEqual(plan["expected_ntp"]["reference_id"], "GPS\\0")
        self.assertEqual(
            plan["target_service"]["kind"],
            ntp_protocol.NTP_SERVICE_KIND,
        )
        self.assertEqual(plan["target_service"]["behavior"], "server_response")
        self.assertEqual(
            plan["target_service"]["response_payload_hex"],
            plan["expected_payload_hex"],
        )
        self.assertEqual(
            plan["stimulus_driver"]["adapter_module"],
            ntp_protocol.NTP_ADAPTER_MODULE,
        )
        self.assertEqual(plan["validation"]["expected_decode"], "ntp")
        self.assertEqual(
            plan["documentation_prefixes"],
            [ntp_protocol.NTP_DOCUMENTATION_IPV4_PREFIX],
        )
        documentation = ipaddress.ip_network(ntp_protocol.NTP_DOCUMENTATION_IPV4_PREFIX)
        for key in ("source_ipv4", "destination_ipv4", "target_ipv4"):
            with self.subTest(key=key):
                self.assertIn(ipaddress.ip_address(plan[key]), documentation)

    def test_kod_extension_and_nts_plans_record_ntp_specific_behavior(self) -> None:
        kod = _ntp_plan("ntp-kod-response", sequence=1)
        extension = _ntp_plan("ntp-extension-preservation", sequence=2)
        nts = _ntp_plan("ntp-nts-extension-plan", sequence=3)

        self.assertEqual(kod["target_service"]["behavior"], "kiss_o_death")
        self.assertEqual(kod["expected_ntp"]["stratum"], 0)
        self.assertEqual(kod["expected_ntp"]["reference_id"], "RATE")
        self.assertEqual(kod["validation"]["behavior"], "kiss_o_death")

        self.assertEqual(extension["target_service"]["behavior"], "preserve_extension_field")
        self.assertEqual(extension["payload_length"], ntp_protocol.NTP_FIXED_HEADER_LEN + 28)
        self.assertEqual(extension["ntp"]["extension_fields"][0]["field_type_hex"], "0x2222")
        self.assertTrue(extension["ntp"]["extension_fields"][0]["preserve_raw"])
        self.assertEqual(
            extension["expected_ntp"]["extension_fields"],
            extension["ntp"]["extension_fields"],
        )

        self.assertEqual(nts["target_service"]["behavior"], "preserve_nts_packet_extensions")
        self.assertEqual(nts["payload_length"], ntp_protocol.NTP_FIXED_HEADER_LEN + 84)
        self.assertEqual(
            [field["label"] for field in nts["ntp"]["extension_fields"]],
            [
                "unique-identifier",
                "nts-cookie",
                "nts-authenticator-and-encrypted-extension-fields",
            ],
        )
        self.assertEqual(
            nts["expected_ntp"]["extension_fields"],
            nts["ntp"]["extension_fields"],
        )

    def test_malformed_plan_is_offline_decode_evidence(self) -> None:
        plan = _ntp_plan("ntp-malformed-observation", sequence=4)

        self.assertIs(plan["live_capable"], False)
        self.assertEqual(plan["payload_length"], 12)
        self.assertTrue(plan["wire_requirements"]["offline_only"])
        self.assertFalse(plan["wire_requirements"]["requires_live_network"])
        self.assertEqual(plan["target_service"]["kind"], "none")
        self.assertEqual(plan["validation"]["expected_decode"], "structured_error")
        self.assertEqual(plan["validation"]["error_context"], "ntp.fixed_header")
        self.assertEqual(plan["validation"]["required"], ntp_protocol.NTP_FIXED_HEADER_LEN)
        self.assertEqual(plan["validation"]["available"], plan["payload_length"])
        self.assertEqual(plan["expected_ntp"]["message_kind"], "structured_error")
        self.assertEqual(plan["expected_ntp"]["context"], "ntp.fixed_header")
        self.assertEqual(plan["expected_ntp"]["required"], ntp_protocol.NTP_FIXED_HEADER_LEN)
        self.assertEqual(plan["expected_ntp"]["available"], plan["payload_length"])

    def test_plans_are_deterministic(self) -> None:
        for sequence, case_name in enumerate(NTP_CASE_NAMES):
            with self.subTest(case=case_name):
                first = _ntp_plan(case_name, seed=9901, sequence=sequence)
                second = _ntp_plan(case_name, seed=9901, sequence=sequence)

                self.assertEqual(first, second)
                self.assertEqual(first["payload_hex"], first["udp_payload_hex"])
                self.assertEqual(
                    len(bytes.fromhex(first["payload_hex"])),
                    first["payload_length"],
                )
                self.assertEqual(
                    len(bytes.fromhex(first["expected_payload_hex"])),
                    first["expected_payload_length"],
                )


class NtpProbeTargetServiceTest(unittest.TestCase):
    def test_target_service_contribution_is_dry_run_metadata(self) -> None:
        plans = [
            _ntp_plan(case_name, sequence=sequence)
            for sequence, case_name in enumerate(NTP_CASE_NAMES)
        ]

        contribution = ntp_protocol.ntp_target_service_contribution(
            plans,
            dry_run=True,
        )

        self.assertFalse(contribution["starts_services"])
        self.assertEqual(len(contribution["services"]), 1)
        service = contribution["services"][0]
        self.assertEqual(service["name"], ntp_protocol.NTP_SERVICE_KIND)
        self.assertEqual(service["protocol"], "udp")
        self.assertEqual(service["port"], ntp_protocol.NTP_PORT)
        self.assertEqual(service["runtime"], ntp_protocol.NTP_RUNTIME)
        self.assertTrue(service["deterministic"])
        self.assertTrue(service["planned_only"])
        self.assertTrue(service["live_requires_provider"])
        self.assertEqual(service["query_count"], len(NTP_LIVE_CASES))
        self.assertEqual(service["cases"], list(NTP_LIVE_CASES))
        self.assertTrue(service["supports"]["client_server_exchange"])
        self.assertTrue(service["supports"]["kiss_o_death_response"])
        self.assertTrue(service["supports"]["extension_preservation"])
        self.assertTrue(service["supports"]["nts_packet_extensions"])
        self.assertFalse(service["supports"]["time_synchronization"])
        self.assertFalse(service["supports"]["nts_key_exchange"])


class NtpProbeFailureReasonTest(unittest.TestCase):
    def test_live_cases_record_stable_failure_reasons(self) -> None:
        expected_failures = [
            "timeout",
            "wrong_peer",
            "wrong_payload",
            "wrong_flags",
            "decode_failed",
            "target_setup_failed",
        ]

        for case_name in NTP_LIVE_CASES:
            with self.subTest(case=case_name):
                plan = _ntp_plan(case_name)

                self.assertEqual(
                    ntp_protocol.ntp_failure_reasons(case_name),
                    expected_failures,
                )
                self.assertEqual(plan["skip_reasons"]["failure"], expected_failures)
                self.assertEqual(
                    plan["skip_reasons"]["capability"],
                    ["requires_controlled_ntp_responder", "requires_privileged_port"],
                )

    def test_offline_case_records_decode_failure_reasons(self) -> None:
        plan = _ntp_plan("ntp-malformed-observation", sequence=4)

        self.assertEqual(
            ntp_protocol.ntp_failure_reasons("ntp-malformed-observation"),
            ["decode_failed", "wrong_payload"],
        )
        self.assertEqual(
            plan["skip_reasons"]["failure"],
            ["decode_failed", "wrong_payload"],
        )
        self.assertEqual(
            plan["skip_reasons"]["capability"],
            ["offline_plan_unavailable"],
        )


class NtpProbeCapabilityTest(unittest.TestCase):
    def test_lab_capabilities_derive_ntp_peer_bits(self) -> None:
        substrate = {
            "provider": "qemu",
            "dry_run": True,
            "ipv4_unicast": True,
            "controlled_services": True,
            "live_packet_exchange": True,
        }
        derived = probe_capabilities_from_lab_capabilities(
            "qemu",
            substrate,
            dry_run=True,
        )

        self.assertIs(derived["ntp_offline_plan"], True)
        self.assertIs(derived["ntp_controlled_responder"], True)
        for case_name in NTP_CASE_NAMES:
            with self.subTest(case=case_name):
                case = probe_cases.PROBE_CASE_BY_NAME[case_name]
                self.assertEqual(
                    [name for name in case.required_capabilities if not derived.get(name)],
                    [],
                )

    def test_ntp_controlled_responder_can_be_denied_independently(self) -> None:
        substrate = {
            "provider": "ntp-less-lab",
            "dry_run": True,
            "ipv4_unicast": True,
            "controlled_services": True,
            "ntp_controlled_responder": False,
            "live_packet_exchange": True,
        }
        derived = probe_capabilities_from_lab_capabilities(
            "ntp-less-lab",
            substrate,
            dry_run=True,
        )
        case = probe_cases.PROBE_CASE_BY_NAME["ntp-client-server-exchange"]

        self.assertIs(derived["ntp_controlled_responder"], False)
        self.assertEqual(
            [name for name in case.required_capabilities if not derived.get(name)],
            ["ntp_controlled_responder"],
        )


class NtpProbeAddressRewriteTest(unittest.TestCase):
    def test_live_rewrite_uses_lab_hosts_and_preserves_ntp_metadata(self) -> None:
        rewritten = ntp_protocol.ntp_rewrite_endpoint_addresses(
            _ntp_plan("ntp-client-server-exchange"),
            source_ipv4="10.77.0.10",
            target_ipv4="10.77.0.20",
            rewrite_source="lab_session",
        )
        source_port = rewritten["source_port"]

        self.assertEqual(rewritten["source_ipv4"], "10.77.0.10")
        self.assertEqual(rewritten["destination_ipv4"], "10.77.0.20")
        self.assertEqual(rewritten["target_ipv4"], "10.77.0.20")
        self.assertEqual(rewritten["expected_reply_source_ipv4"], "10.77.0.20")
        self.assertEqual(rewritten["expected_reply_destination_ipv4"], "10.77.0.10")
        self.assertEqual(
            rewritten["capture_filter"],
            (
                "udp and src host 10.77.0.20 and dst host 10.77.0.10 "
                f"and src port 123 and dst port {source_port}"
            ),
        )
        self.assertEqual(rewritten["validation"]["source_ipv4"], "10.77.0.20")
        self.assertEqual(rewritten["validation"]["destination_ipv4"], "10.77.0.10")
        self.assertEqual(rewritten["packet"]["ipv4"]["src"], "10.77.0.10")
        self.assertEqual(rewritten["packet"]["ipv4"]["dst"], "10.77.0.20")
        self.assertEqual(
            rewritten["expected_response_packet"]["ipv4"]["src"],
            "10.77.0.20",
        )
        self.assertEqual(
            rewritten["expected_response_packet"]["ipv4"]["dst"],
            "10.77.0.10",
        )
        self.assertEqual(rewritten["target_service"]["bind_ipv4"], "10.77.0.20")
        self.assertEqual(rewritten["target_service"]["source_ipv4"], "10.77.0.10")
        self.assertEqual(
            rewritten["live_address_rewrite"],
            {
                "source": "lab_session",
                "stimulus_ipv4": "10.77.0.10",
                "target_ipv4": "10.77.0.20",
            },
        )

    def test_offline_rewrite_is_skipped_with_reason(self) -> None:
        original = _ntp_plan("ntp-malformed-observation", sequence=4)
        rewritten = ntp_protocol.ntp_rewrite_endpoint_addresses(
            original,
            source_ipv4="10.77.0.10",
            target_ipv4="10.77.0.20",
            rewrite_source="lab_session",
        )

        self.assertEqual(rewritten["source_ipv4"], original["source_ipv4"])
        self.assertEqual(rewritten["destination_ipv4"], original["destination_ipv4"])
        self.assertEqual(rewritten["target_ipv4"], original["target_ipv4"])
        self.assertEqual(rewritten["skip_reasons"]["address_rewrite"], ["offline_only"])
        self.assertEqual(
            rewritten["live_address_rewrite"],
            {
                "source": "lab_session",
                "status": "skipped",
                "reason": "offline_only",
                "stimulus_ipv4": "10.77.0.10",
                "target_ipv4": "10.77.0.20",
            },
        )


if __name__ == "__main__":
    unittest.main()
