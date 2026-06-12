"""Generator coverage for the extended ICMP common-field model.

These tests assert that the seeded generator samples ICMP rest-of-header and
type-specific body fields (gateway, pointer, next-hop MTU, timestamps, address
mask, router-discovery fields, and raw-compatible extension bytes) for the
``icmpv4_live`` coverage cases, driven by the feature's live matrix rather than
by backend-specific special cases. They also guard that plain echo cases stay
free of body fields and that generation remains deterministic.
"""

from __future__ import annotations

import unittest

from tools.oracle.engine.generator import case_byte_policy_index, generate_plans
from tools.oracle.engine.model import PacketPlan


_BACKEND = "scapy"
_ROOT = "l2:ipv4"
_FEATURE = "icmpv4_live"
_PROFILE = "smoke"
_SEED = 21
_DIRECTION = "live_exchange"


def _icmp_for_case(case: str) -> dict[str, object]:
    plan = _plan_for_case(case)
    icmp = plan.fields.get("icmp")
    assert isinstance(icmp, dict), f"plan for {case} has no icmp layer"
    return icmp


def _plan_for_case(case: str) -> PacketPlan:
    plans = generate_plans(
        seed=_SEED,
        profile=_PROFILE,
        count=1,
        backend=_BACKEND,
        root=_ROOT,
        feature=_FEATURE,
        case=case,
        direction=_DIRECTION,
    )
    assert len(plans) == 1
    return plans[0]


class IcmpCommonFieldGenerationTest(unittest.TestCase):
    def test_echo_case_carries_no_rest_of_header_body(self) -> None:
        icmp = _icmp_for_case("ipv4-icmp")
        self.assertEqual(icmp["type"], "echo_request")
        # The plain echo query must not gain rest-of-header or type-specific body
        # fields; those belong only to the behaviors that exercise them.
        for body_field in (
            "rest_of_header",
            "gateway",
            "pointer",
            "next_hop_mtu",
            "originate_timestamp",
            "address_mask",
            "router_addresses",
            "extension_bytes",
            "embedded_header",
        ):
            self.assertNotIn(body_field, icmp)

    def test_redirect_lists_gateway(self) -> None:
        icmp = _icmp_for_case("icmpv4-redirect")
        self.assertEqual(icmp["type"], "redirect")
        self.assertEqual(icmp["gateway"], "192.0.2.1")

    def test_parameter_problem_lists_pointer(self) -> None:
        icmp = _icmp_for_case("icmpv4-parameter-problem")
        self.assertEqual(icmp["type"], "parameter_problem")
        self.assertEqual(icmp["pointer"], 20)

    def test_frag_needed_lists_next_hop_mtu_and_code(self) -> None:
        icmp = _icmp_for_case("icmpv4-frag-needed-next-hop-mtu")
        self.assertEqual(icmp["type"], "destination_unreachable")
        self.assertEqual(icmp["code"], 4)
        self.assertEqual(icmp["next_hop_mtu"], 1280)

    def test_destination_unreachable_lists_representative_code(self) -> None:
        icmp = _icmp_for_case("icmpv4-destination-unreachable")
        self.assertEqual(icmp["type"], "destination_unreachable")
        # The code is one of the matrix-named representative codes (0-3).
        self.assertIn(icmp["code"], {0, 1, 2, 3})

    def test_timestamp_lists_three_timestamp_values(self) -> None:
        icmp = _icmp_for_case("icmpv4-timestamp")
        self.assertIn(icmp["type"], {"timestamp", "timestamp_reply"})
        for field_name in (
            "originate_timestamp",
            "receive_timestamp",
            "transmit_timestamp",
        ):
            self.assertIn(field_name, icmp)
            value = icmp[field_name]
            self.assertIsInstance(value, int)
            self.assertGreaterEqual(value, 0)
            self.assertLess(value, 1 << 32)

    def test_address_mask_lists_mask(self) -> None:
        icmp = _icmp_for_case("icmpv4-address-mask")
        self.assertIn(icmp["type"], {"address_mask_request", "address_mask_reply"})
        self.assertEqual(icmp["address_mask"], "255.255.255.0")

    def test_router_advertisement_lists_router_discovery_fields(self) -> None:
        icmp = _icmp_for_case("icmpv4-router-advertisement")
        self.assertEqual(icmp["type"], "router_advertisement")
        self.assertEqual(icmp["router_address_entry_size"], 2)
        self.assertEqual(icmp["router_lifetime"], 1800)
        addresses = icmp["router_addresses"]
        self.assertIsInstance(addresses, list)
        self.assertEqual(len(addresses), 2)

    def test_router_solicitation_lists_reserved_rest_of_header(self) -> None:
        icmp = _icmp_for_case("icmpv4-router-solicitation")
        self.assertEqual(icmp["type"], "router_solicitation")
        self.assertEqual(icmp["rest_of_header"], {"hex": "00000000"})

    def test_mpls_extension_lists_raw_compatible_extension_bytes(self) -> None:
        icmp = _icmp_for_case("icmpv4-extensions-mpls")
        self.assertEqual(icmp["type"], "destination_unreachable")
        embedded = icmp["embedded_header"]
        self.assertIsInstance(embedded, dict)
        bytes.fromhex(embedded["hex"])
        extension = icmp["extension_bytes"]
        self.assertIsInstance(extension, dict)
        self.assertIn("hex", extension)
        # Deterministic, even-length hex string both backends can parse.
        hex_bytes = extension["hex"]
        self.assertIsInstance(hex_bytes, str)
        self.assertEqual(len(hex_bytes) % 2, 0)
        bytes.fromhex(hex_bytes)

    def test_generic_extension_framing_lists_extension_bytes(self) -> None:
        icmp = _icmp_for_case("crafter-icmpv4-errors-extensions")
        self.assertEqual(icmp["type"], "destination_unreachable")
        self.assertIn("extension_bytes", icmp)
        bytes.fromhex(icmp["extension_bytes"]["hex"])

    def test_extended_echo_lists_rest_of_header_and_extension_bytes(self) -> None:
        icmp = _icmp_for_case("icmpv4-extended-echo-request")
        self.assertIn(icmp["type"], {"extended_echo_request", "extended_echo_reply"})
        self.assertIn("rest_of_header", icmp)
        self.assertIn("extension_bytes", icmp)

    def test_legacy_type_lists_raw_rest_of_header(self) -> None:
        icmp = _icmp_for_case("crafter-icmpv4-legacy-types")
        self.assertIn(
            icmp["type"],
            {
                "source_quench",
                "traceroute",
                "mobile_host_redirect",
                "domain_name_request",
                "photuris",
            },
        )
        self.assertEqual(icmp["rest_of_header"], {"hex": "00000000"})


class IcmpCommonFieldDeterminismTest(unittest.TestCase):
    def test_same_coordinates_produce_identical_icmp_fields(self) -> None:
        first = _icmp_for_case("icmpv4-timestamp")
        second = _icmp_for_case("icmpv4-timestamp")
        self.assertEqual(first, second)

    def test_no_malformed_plans_in_live_matrix(self) -> None:
        # The live matrix is well-formed only: generated ICMP live plans must not
        # be flagged malformed or non-strict.
        plans = generate_plans(
            seed=_SEED,
            profile=_PROFILE,
            count=12,
            backend=_BACKEND,
            root=_ROOT,
            feature=_FEATURE,
            direction=_DIRECTION,
        )
        for plan in plans:
            self.assertFalse(plan.metadata.get("malformed"), plan.case)
            self.assertNotIn("malformed", plan.feature_tags, plan.case)
            self.assertNotIn("non_strict_reencode", plan.feature_tags, plan.case)


class Ipv6EnrichmentProfileTest(unittest.TestCase):
    def test_first_twenty_cover_focused_ipv6_enrichment_cases(self) -> None:
        plans = generate_plans(
            seed=1,
            profile="ipv6-enrichment",
            count=20,
            backend=_BACKEND,
            root="l3:ipv6",
        )
        cases = {plan.case for plan in plans}

        self.assertEqual(len(plans), 20)
        self.assertTrue(
            {
                "ipv6-boundary-fields",
                "ipv6-unknown-next-header-raw",
                "ipv6-hop-by-hop-options",
                "ipv6-destination-options",
                "ipv6-option-metadata",
                "ipv6-fragment-udp",
                "ipv6-routing-generic",
                "ipv6-mobile-routing",
                "ipv6-segment-routing-udp",
                "ipv6-extension-chain-tcp-raw",
                "ipv6-routing-icmpv6",
            }.issubset(cases)
        )
        for plan in plans:
            with self.subTest(case=plan.case):
                self.assertEqual(plan.metadata["root"], "l3:ipv6")
                self.assertIn(plan.metadata.get("feature"), {None, "ipv6_fragment_routing"})
                self.assertNotIn("live", plan.feature_tags)
                self.assertNotIn("pcap", plan.feature_tags)
                self.assertNotIn("malformed", plan.feature_tags)

    def test_malformed_ipv6_extension_case_is_declared_but_not_sampled(self) -> None:
        policies = case_byte_policy_index()
        self.assertEqual(policies.get("malformed-ipv6-extensions"), "structured_error")

        plans = generate_plans(
            seed=1,
            profile="ipv6-enrichment",
            count=20,
            backend=_BACKEND,
            root="l3:ipv6",
        )
        self.assertNotIn("malformed-ipv6-extensions", {plan.case for plan in plans})


class BgpSmokeProfileTest(unittest.TestCase):
    def test_first_twenty_cover_only_bgp_message_cases(self) -> None:
        plans = generate_plans(
            seed=1,
            profile="bgp-smoke",
            count=20,
            backend=_BACKEND,
        )

        self.assertEqual(len(plans), 20)
        self.assertTrue({plan.case for plan in plans})
        for plan in plans:
            with self.subTest(case=plan.case, stack=plan.stack):
                self.assertEqual(plan.family, "bgp")
                self.assertTrue(plan.case.startswith("bgp-"))
                self.assertIn("bgp", plan.stack)
                self.assertNotIn("pcap", plan.feature_tags)
                self.assertNotIn("live", plan.feature_tags)
                self.assertNotIn("malformed", plan.feature_tags)

                bgp = plan.fields.get("bgp")
                self.assertIsInstance(bgp, dict)
                self.assertIn("message_type", bgp)
                self.assertEqual(bgp.get("marker"), {"hex": "ff" * 16})
                self.assertEqual(plan.fields.get("tcp", {}).get("dst_port"), 179)
                self.assertEqual(plan.fields.get("payload"), {"hex": "", "length": 0})
                if bgp.get("message_type") != "keepalive":
                    self.assertIn("body", bgp)


if __name__ == "__main__":
    unittest.main()
