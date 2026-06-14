"""Unit coverage for probe provider capability policy and skip reasons."""

from __future__ import annotations

import unittest

from tools.probe.engine import capabilities, cases, cli
from tools.probe.engine.lab import (
    PROBE_CAPABILITY_NAMES,
    probe_capabilities_from_lab_capabilities,
)
from tools.probe.engine.model import ProbeRunRequest


_LINK_LAYER_SUBSTRATE = {
    "provider": "qemu",
    "ipv4_unicast": True,
    "controlled_services": True,
    "controlled_router": False,
    "link_layer_send": True,
    "link_layer_capture": True,
    "broadcast": True,
    "provider_mac_known": True,
    "live_packet_exchange": True,
}

_L3_ONLY_SUBSTRATE = {
    "provider": "hetzner",
    "ipv4_unicast": True,
    "controlled_services": True,
    "controlled_router": False,
    "link_layer_send": False,
    "link_layer_capture": False,
    "broadcast": False,
    "provider_mac_known": False,
    "live_packet_exchange": True,
}


def _request(**overrides: object) -> ProbeRunRequest:
    base = {
        "provider": "qemu",
        "profile": "smoke",
        "seed": 3,
        "count": 6,
        "case_names": [],
        "dry_run": True,
    }
    base.update(overrides)
    return ProbeRunRequest(**base)  # type: ignore[arg-type]


class ProbeCapabilityDerivationTest(unittest.TestCase):
    def test_new_capability_names_are_registered(self) -> None:
        for name in (
            "dhcp_service",
            "udp_service",
            "udp_large_payload",
            "udp_ipv4_zero_checksum",
            "udp_options_surplus",
            "privileged_udp_port",
            "link_layer_arp",
            "provider_mac",
            "repeated_response",
            "bgp_peer",
            "ipsec_esp",
            "ipsec_ah",
            "ikev2",
        ):
            self.assertIn(name, PROBE_CAPABILITY_NAMES)

    def test_link_layer_substrate_grants_dhcp_and_arp_capabilities(self) -> None:
        derived = probe_capabilities_from_lab_capabilities(
            "qemu",
            _LINK_LAYER_SUBSTRATE,
            dry_run=True,
        )

        for name in (
            "dns_service",
            "dhcp_service",
            "udp_service",
            "udp_large_payload",
            "udp_ipv4_zero_checksum",
            "udp_options_surplus",
            "privileged_udp_port",
            "arp_resolution",
            "link_layer_arp",
            "provider_mac",
            "repeated_response",
            "bgp_peer",
            # An IPSec-capable peer rides the controlled-services substrate.
            "ipsec_esp",
            "ipsec_ah",
            "ikev2",
        ):
            self.assertIs(derived[name], True, name)

    def test_l3_only_substrate_skips_link_layer_capabilities(self) -> None:
        derived = probe_capabilities_from_lab_capabilities(
            "hetzner",
            _L3_ONLY_SUBSTRATE,
            dry_run=True,
        )

        # DNS and UDP service behavior need only IPv4 unicast plus controlled
        # services, so they remain available.
        for granted in (
            "dns_service",
            "udp_service",
            "udp_large_payload",
            "udp_ipv4_zero_checksum",
            "udp_options_surplus",
            "privileged_udp_port",
            "repeated_response",
            "bgp_peer",
            # IPSec rides IPv4 unicast + a controlled peer, not the link layer,
            # so an L3-only-but-controlled substrate still grants it.
            "ipsec_esp",
            "ipsec_ah",
            "ikev2",
        ):
            self.assertIs(derived[granted], True, granted)

        # DHCP and ARP need a link-layer substrate, broadcast, and provider MAC.
        for denied in (
            "dhcp_service",
            "arp_resolution",
            "link_layer_arp",
            "provider_mac",
            "broadcast",
        ):
            self.assertIs(derived[denied], False, denied)

    def test_provider_mac_required_for_link_layer_arp(self) -> None:
        substrate = dict(_LINK_LAYER_SUBSTRATE)
        substrate["provider_mac_known"] = False
        derived = probe_capabilities_from_lab_capabilities(
            "qemu",
            substrate,
            dry_run=True,
        )

        self.assertIs(derived["arp_resolution"], True)
        self.assertIs(derived["link_layer_arp"], False)
        self.assertIs(derived["provider_mac"], False)

    def test_advertised_small_udp_payload_limit_disables_large_echo(self) -> None:
        substrate = dict(_LINK_LAYER_SUBSTRATE)
        substrate["udp_safe_payload_size"] = 1199

        derived = probe_capabilities_from_lab_capabilities(
            "qemu",
            substrate,
            dry_run=True,
        )

        self.assertIs(derived["udp_service"], True)
        self.assertIs(derived["udp_large_payload"], False)
        self.assertEqual(derived["udp_safe_payload_size"], 1199)

    def test_explicit_udp_zero_checksum_denial_disables_that_case(self) -> None:
        substrate = dict(_LINK_LAYER_SUBSTRATE)
        substrate["udp_ipv4_zero_checksum"] = False

        derived = probe_capabilities_from_lab_capabilities(
            "qemu",
            substrate,
            dry_run=True,
        )

        self.assertIs(derived["udp_service"], True)
        self.assertIs(derived["udp_ipv4_zero_checksum"], False)

    def test_explicit_udp_options_surplus_denial_disables_that_case(self) -> None:
        substrate = dict(_LINK_LAYER_SUBSTRATE)
        substrate["udp_options_surplus"] = False

        derived = probe_capabilities_from_lab_capabilities(
            "qemu",
            substrate,
            dry_run=True,
        )

        self.assertIs(derived["udp_service"], True)
        self.assertIs(derived["udp_options_surplus"], False)

    def test_ipsec_capabilities_denied_without_controlled_service(self) -> None:
        # An IPSec peer needs a controlled service to host the SA / IKE
        # responder; a bare substrate without one denies every IPSec capability.
        substrate = dict(_L3_ONLY_SUBSTRATE)
        substrate["controlled_services"] = False

        derived = probe_capabilities_from_lab_capabilities(
            "bare-l3",
            substrate,
            dry_run=True,
        )

        for denied in ("bgp_peer", "ipsec_esp", "ipsec_ah", "ikev2"):
            self.assertIs(derived[denied], False, denied)

    def test_explicit_bgp_peer_denial_disables_bgp_only(self) -> None:
        substrate = dict(_LINK_LAYER_SUBSTRATE)
        substrate["bgp_peer"] = False

        derived = probe_capabilities_from_lab_capabilities(
            "qemu",
            substrate,
            dry_run=True,
        )

        self.assertIs(derived["bgp_peer"], False)
        self.assertIs(derived["dns_service"], True)

    def test_explicit_ipsec_peer_denial_disables_esp_and_ah(self) -> None:
        # A controlled substrate that cannot configure the xfrm/strongSwan SA can
        # deny the peer explicitly; ESP/AH are denied while IKEv2 (which only
        # needs the IKE responder) is unaffected.
        substrate = dict(_LINK_LAYER_SUBSTRATE)
        substrate["ipsec_peer"] = False

        derived = probe_capabilities_from_lab_capabilities(
            "qemu",
            substrate,
            dry_run=True,
        )

        self.assertIs(derived["ipsec_esp"], False)
        self.assertIs(derived["ipsec_ah"], False)
        self.assertIs(derived["ikev2"], True)

    def test_explicit_ikev2_responder_denial_disables_ikev2_only(self) -> None:
        substrate = dict(_LINK_LAYER_SUBSTRATE)
        substrate["ikev2_responder"] = False

        derived = probe_capabilities_from_lab_capabilities(
            "qemu",
            substrate,
            dry_run=True,
        )

        self.assertIs(derived["ikev2"], False)
        self.assertIs(derived["ipsec_esp"], True)
        self.assertIs(derived["ipsec_ah"], True)


class ProbeMissingCapabilityTest(unittest.TestCase):
    def test_missing_capabilities_reports_required_but_ungranted(self) -> None:
        case = cases.PROBE_CASE_BY_NAME["arp-resolution"]
        derived = probe_capabilities_from_lab_capabilities(
            "hetzner",
            _L3_ONLY_SUBSTRATE,
            dry_run=True,
        )

        missing = capabilities.missing_capabilities(case, derived)
        self.assertEqual(missing, list(case.required_capabilities))

    def test_missing_capabilities_empty_when_all_granted(self) -> None:
        case = cases.PROBE_CASE_BY_NAME["arp-resolution"]
        derived = probe_capabilities_from_lab_capabilities(
            "qemu",
            _LINK_LAYER_SUBSTRATE,
            dry_run=True,
        )

        self.assertEqual(capabilities.missing_capabilities(case, derived), [])

    def test_dns_query_supported_on_l3_only_substrate(self) -> None:
        case = cases.PROBE_CASE_BY_NAME["dns-query"]
        derived = probe_capabilities_from_lab_capabilities(
            "hetzner",
            _L3_ONLY_SUBSTRATE,
            dry_run=True,
        )

        self.assertEqual(capabilities.missing_capabilities(case, derived), [])

    def test_udp_echo_large_skips_when_payload_limit_is_too_small(self) -> None:
        case = cases.PROBE_CASE_BY_NAME["udp-echo-large"]
        substrate = dict(_LINK_LAYER_SUBSTRATE)
        substrate["udp_safe_payload_size"] = 1199
        derived = probe_capabilities_from_lab_capabilities(
            "qemu",
            substrate,
            dry_run=True,
        )

        self.assertEqual(
            capabilities.missing_capabilities(case, derived),
            ["udp_large_payload"],
        )
        self.assertEqual(
            capabilities.skip_reason_for_missing_capability(case, "udp_large_payload"),
            capabilities.SKIP_CAPABILITY_UNAVAILABLE,
        )

    def test_udp_zero_checksum_skips_when_provider_denies_capability(self) -> None:
        case = cases.PROBE_CASE_BY_NAME["udp-zero-checksum-ipv4"]
        substrate = dict(_LINK_LAYER_SUBSTRATE)
        substrate["udp_ipv4_zero_checksum"] = False
        derived = probe_capabilities_from_lab_capabilities(
            "qemu",
            substrate,
            dry_run=True,
        )

        self.assertEqual(
            capabilities.missing_capabilities(case, derived),
            ["udp_ipv4_zero_checksum"],
        )
        self.assertEqual(
            capabilities.skip_reason_for_missing_capability(
                case,
                "udp_ipv4_zero_checksum",
            ),
            capabilities.SKIP_CAPABILITY_UNAVAILABLE,
        )

    def test_udp_options_surplus_skips_when_provider_denies_capability(self) -> None:
        case = cases.PROBE_CASE_BY_NAME["udp-options-surplus-echo"]
        substrate = dict(_LINK_LAYER_SUBSTRATE)
        substrate["udp_options_surplus"] = False
        derived = probe_capabilities_from_lab_capabilities(
            "qemu",
            substrate,
            dry_run=True,
        )

        self.assertEqual(
            capabilities.missing_capabilities(case, derived),
            ["udp_options_surplus"],
        )
        self.assertEqual(
            capabilities.skip_reason_for_missing_capability(
                case,
                "udp_options_surplus",
            ),
            capabilities.SKIP_CAPABILITY_UNAVAILABLE,
        )


class ProbeSkipReasonTest(unittest.TestCase):
    def test_controlled_router_maps_to_stable_reason(self) -> None:
        case = cases.PROBE_CASE_BY_NAME["ttl-expired"]
        self.assertEqual(
            capabilities.skip_reason_for_missing_capability(case, "controlled_router"),
            capabilities.SKIP_REQUIRES_CONTROLLED_ROUTER,
        )

    def test_link_layer_capabilities_map_to_link_layer_reason(self) -> None:
        case = cases.PROBE_CASE_BY_NAME["arp-resolution"]
        for capability in (
            "arp_resolution",
            "link_layer_arp",
            "link_layer_send",
            "link_layer_capture",
        ):
            self.assertEqual(
                capabilities.skip_reason_for_missing_capability(case, capability),
                capabilities.SKIP_REQUIRES_LINK_LAYER,
                capability,
            )

    def test_new_capabilities_map_to_distinct_stable_reasons(self) -> None:
        case = cases.PROBE_CASE_BY_NAME["arp-resolution"]
        self.assertEqual(
            capabilities.skip_reason_for_missing_capability(case, "broadcast"),
            capabilities.SKIP_REQUIRES_BROADCAST,
        )
        self.assertEqual(
            capabilities.skip_reason_for_missing_capability(case, "provider_mac"),
            capabilities.SKIP_REQUIRES_PROVIDER_MAC,
        )
        self.assertEqual(
            capabilities.skip_reason_for_missing_capability(
                case, "privileged_udp_port"
            ),
            capabilities.SKIP_REQUIRES_PRIVILEGED_PORT,
        )
        self.assertEqual(
            capabilities.skip_reason_for_missing_capability(
                case, "controlled_services"
            ),
            capabilities.SKIP_REQUIRES_CONTROLLED_SERVICE,
        )

    def test_ipsec_capabilities_map_to_stable_peer_reasons(self) -> None:
        esp_case = cases.PROBE_CASE_BY_NAME["esp-transport-echo"]
        ah_case = cases.PROBE_CASE_BY_NAME["ah-transport-verify"]
        ikev2_case = cases.PROBE_CASE_BY_NAME["ikev2-sa-init"]
        self.assertEqual(
            capabilities.skip_reason_for_missing_capability(esp_case, "ipsec_esp"),
            capabilities.SKIP_REQUIRES_IPSEC_PEER,
        )
        self.assertEqual(
            capabilities.skip_reason_for_missing_capability(ah_case, "ipsec_ah"),
            capabilities.SKIP_REQUIRES_IPSEC_PEER,
        )
        self.assertEqual(
            capabilities.skip_reason_for_missing_capability(ikev2_case, "ikev2"),
            capabilities.SKIP_REQUIRES_IKEV2_RESPONDER,
        )

    def test_bgp_peer_maps_to_stable_reason(self) -> None:
        case = cases.PROBE_CASE_BY_NAME["bgp-session-smoke"]
        self.assertEqual(
            capabilities.skip_reason_for_missing_capability(case, "bgp_peer"),
            capabilities.SKIP_REQUIRES_BGP_PEER,
        )

    def test_unknown_capability_falls_back_to_unavailable(self) -> None:
        case = cases.PROBE_CASE_BY_NAME["icmp-echo"]
        self.assertEqual(
            capabilities.skip_reason_for_missing_capability(case, "icmp_echo"),
            capabilities.SKIP_CAPABILITY_UNAVAILABLE,
        )


class ProbeCapabilitySkipResultTest(unittest.TestCase):
    def test_capability_skip_result_none_when_supported(self) -> None:
        case = cases.PROBE_CASE_BY_NAME["dns-query"]
        derived = probe_capabilities_from_lab_capabilities(
            "hetzner",
            _L3_ONLY_SUBSTRATE,
            dry_run=True,
        )
        result = capabilities.capability_skip_result(
            request=_request(provider="hetzner"),
            case=case,
            sequence=0,
            probe_plan={"case": case.name, "sequence": 0},
            dry_run=True,
            provider_capabilities=derived,
        )
        self.assertIsNone(result)

    def test_capability_skip_result_builds_skip_and_result(self) -> None:
        case = cases.PROBE_CASE_BY_NAME["arp-resolution"]
        derived = probe_capabilities_from_lab_capabilities(
            "hetzner",
            _L3_ONLY_SUBSTRATE,
            dry_run=True,
        )
        outcome = capabilities.capability_skip_result(
            request=_request(provider="hetzner"),
            case=case,
            sequence=2,
            probe_plan={"case": case.name, "sequence": 2},
            dry_run=True,
            provider_capabilities=derived,
        )
        assert outcome is not None
        skip, result = outcome

        self.assertEqual(skip.case, "arp-resolution")
        self.assertEqual(skip.sequence, 2)
        self.assertEqual(skip.reason, capabilities.SKIP_REQUIRES_LINK_LAYER)
        self.assertEqual(skip.capability, "arp_resolution")
        self.assertEqual(
            skip.metadata["missing_capabilities"],
            list(case.required_capabilities),
        )
        self.assertEqual(result.status, "skipped")
        self.assertIs(result.skip, skip)
        self.assertEqual(result.endpoint_role, "stimulus")

    def test_capability_skip_state_collects_skipped_sequences(self) -> None:
        request = _request(provider="hetzner")
        selected = cases.selected_cases(request.case_names)
        planned = cli._planned_cases(
            selected,
            seed=request.seed,
            count=len(selected),
        )
        probe_plans = [
            {"case": case.name, "sequence": sequence}
            for sequence, case in enumerate(planned)
        ]
        derived = probe_capabilities_from_lab_capabilities(
            "hetzner",
            _L3_ONLY_SUBSTRATE,
            dry_run=True,
        )

        results, skips, counts, sequences = capabilities.capability_skip_state(
            request=request,
            planned_cases=planned,
            probe_plans=probe_plans,
            dry_run=True,
            provider_capabilities=derived,
        )

        self.assertEqual(len(results), len(skips))
        self.assertEqual(sequences, {skip.sequence for skip in skips})
        self.assertEqual(sum(counts.values()), len(skips))
        for skip in skips:
            self.assertIn(skip.reason, counts)
        # ARP and controlled-router cases must skip on an L3-only provider.
        skipped_cases = {skip.case for skip in skips}
        self.assertIn("arp-resolution", skipped_cases)
        self.assertIn("ttl-expired", skipped_cases)
        # DNS service behavior must not skip on an L3-only provider.
        self.assertNotIn("dns-query", skipped_cases)


class ProbeCapabilityBackwardCompatTest(unittest.TestCase):
    def test_cli_reexports_capability_helpers(self) -> None:
        self.assertIs(cli._missing_capabilities, capabilities.missing_capabilities)
        self.assertIs(
            cli._skip_reason_for_missing_capability,
            capabilities.skip_reason_for_missing_capability,
        )
        self.assertIs(cli._capability_skip_result, capabilities.capability_skip_result)
        self.assertIs(cli._capability_skip_state, capabilities.capability_skip_state)
        self.assertIs(cli._primary_endpoint_role, capabilities.primary_endpoint_role)
        self.assertIs(
            cli._probe_capabilities_for_request,
            capabilities.probe_capabilities_for_request,
        )

    def test_cli_reexports_skip_reason_constants(self) -> None:
        self.assertEqual(
            cli.SKIP_CAPABILITY_UNAVAILABLE,
            capabilities.SKIP_CAPABILITY_UNAVAILABLE,
        )
        self.assertEqual(
            cli.SKIP_CONFIRMATION_REQUIRED,
            capabilities.SKIP_CONFIRMATION_REQUIRED,
        )
        self.assertEqual(
            cli.SKIP_REQUIRES_CONTROLLED_ROUTER,
            capabilities.SKIP_REQUIRES_CONTROLLED_ROUTER,
        )
        self.assertEqual(
            cli.SKIP_REQUIRES_LINK_LAYER,
            capabilities.SKIP_REQUIRES_LINK_LAYER,
        )
        self.assertEqual(
            cli.SKIP_REQUIRES_BGP_PEER,
            capabilities.SKIP_REQUIRES_BGP_PEER,
        )


if __name__ == "__main__":
    unittest.main()
