"""Unit coverage for DHCPv6 oracle generator selection and field sampling."""

from __future__ import annotations

import unittest
from collections.abc import Mapping, Sequence
from random import Random

from tools.oracle.engine.generator import generate_plans
from tools.oracle.engine.model import PacketPlan
from tools.oracle.engine.protocols import dhcpv6 as dhcpv6_sampler
from tools.oracle.engine.sampling import _SKIP_FIELD, _SamplingContext


_DHCPV6_STACKS = {
    ("ethernet", "ipv6", "udp", "dhcpv6"),
    ("ipv6", "udp", "dhcpv6"),
}
_DHCPV6_OFFLINE_CASES = {
    "dhcpv6-solicit",
    "dhcpv6-request",
    "dhcpv6-reply",
    "dhcpv6-information-request",
    "dhcpv6-information-reply",
    "dhcpv6-relay-forward",
    "dhcpv6-relay-reply",
    "dhcpv6-ia-na-iaaddr",
    "dhcpv6-ia-pd-iaprefix",
    "dhcpv6-unknown-option",
    "dhcpv6-option-matrix",
}


def _require_scapy_backend():
    try:
        from tools.oracle.engine.backends.scapy.packets import encode_packet_plan
        from tools.oracle.engine.backends.scapy.normalize import decode_vector
    except Exception as exc:  # pragma: no cover - exercised only without Scapy.
        raise unittest.SkipTest(f"Scapy backend unavailable: {exc}")

    try:
        from tools.oracle.engine.backends.scapy.bootstrap import import_scapy

        import_scapy()
    except Exception as exc:  # pragma: no cover - exercised only without Scapy.
        raise unittest.SkipTest(f"Scapy is not importable: {exc}")

    return encode_packet_plan, decode_vector


def _plans_for_case(case: str, count: int = 4) -> list[PacketPlan]:
    return generate_plans(
        seed=9915,
        profile="smoke",
        count=count,
        backend="scapy",
        case=case,
    )


def _first_plan(case: str) -> PacketPlan:
    plans = _plans_for_case(case, count=1)
    assert len(plans) == 1
    return plans[0]


def _dhcpv6_fields(plan: PacketPlan) -> Mapping[str, object]:
    dhcpv6 = plan.fields.get("dhcpv6")
    assert isinstance(dhcpv6, Mapping), f"plan for {plan.case} has no dhcpv6 fields"
    return dhcpv6


def _udp_fields(plan: PacketPlan) -> Mapping[str, object]:
    udp = plan.fields.get("udp")
    assert isinstance(udp, Mapping), f"plan for {plan.case} has no udp fields"
    return udp


def _option_names(dhcpv6: Mapping[str, object]) -> list[str]:
    options = dhcpv6.get("options")
    assert isinstance(options, Sequence)
    output: list[str] = []
    for option in options:
        assert isinstance(option, Mapping)
        name = option.get("name")
        assert isinstance(name, str)
        output.append(name)
    return output


def _option_codes(dhcpv6: Mapping[str, object]) -> list[int]:
    options = dhcpv6.get("options")
    assert isinstance(options, Sequence)
    codes: list[int] = []
    for option in options:
        assert isinstance(option, Mapping)
        code = option.get("code")
        assert isinstance(code, int)
        codes.append(code)
    return codes


class Dhcpv6GeneratorSelectionTest(unittest.TestCase):
    def test_dhcpv6_solicit_selects_registered_dhcpv6_stacks(self) -> None:
        plans = _plans_for_case("dhcpv6-solicit")
        self.assertEqual(len(plans), 4)
        for plan in plans:
            self.assertIn(tuple(plan.stack), _DHCPV6_STACKS)
            self.assertEqual(plan.case, "dhcpv6-solicit")
            self.assertIn("dhcpv6", plan.feature_tags)

    def test_dhcpv6_solicit_uses_client_ports_and_options(self) -> None:
        plan = _first_plan("dhcpv6-solicit")
        udp = _udp_fields(plan)
        dhcpv6 = _dhcpv6_fields(plan)

        self.assertEqual(udp.get("src_port"), 546)
        self.assertEqual(udp.get("dst_port"), 547)
        self.assertEqual(dhcpv6.get("message_type"), "solicit")
        self.assertIn("transaction_id", dhcpv6)
        self.assertEqual(_option_names(dhcpv6), ["client_id", "oro", "elapsed_time"])
        self.assertEqual(plan.fields["ipv6"].get("dst"), "ff02::1:2")
        if "ethernet" in plan.fields:
            self.assertEqual(plan.fields["ethernet"].get("dst"), "33:33:00:01:00:02")

    def test_dhcpv6_reply_uses_server_ports_and_status(self) -> None:
        plan = _first_plan("dhcpv6-reply")
        udp = _udp_fields(plan)
        dhcpv6 = _dhcpv6_fields(plan)

        self.assertEqual(udp.get("src_port"), 547)
        self.assertEqual(udp.get("dst_port"), 546)
        self.assertEqual(dhcpv6.get("message_type"), "reply")
        self.assertEqual(_option_names(dhcpv6), ["client_id", "server_id", "status_code"])

    def test_dhcpv6_relay_forward_uses_relay_fields_and_ports(self) -> None:
        plan = _first_plan("dhcpv6-relay-forward")
        udp = _udp_fields(plan)
        dhcpv6 = _dhcpv6_fields(plan)

        self.assertEqual(udp.get("src_port"), 547)
        self.assertEqual(udp.get("dst_port"), 547)
        self.assertEqual(dhcpv6.get("message_type"), "relay_forward")
        self.assertNotIn("transaction_id", dhcpv6)
        self.assertEqual(dhcpv6.get("hop_count"), 1)
        self.assertEqual(dhcpv6.get("link_address"), "2001:db8:100::")
        self.assertEqual(_option_names(dhcpv6), ["interface_id", "relay_msg"])
        self.assertEqual(plan.fields["ipv6"].get("dst"), "ff05::1:3")

    def test_sampled_relay_message_type_uses_relay_shape(self) -> None:
        ctx = _SamplingContext(
            rng=Random(12345),
            profile="ci",
            feature_weights={},
            stack=["ipv6", "udp", "dhcpv6"],
            payload_min=0,
            payload_max=0,
            feature="ah_integrity",
            case="ah-hmac-tunnel-inner-ip",
        )
        current_fields = {"message_type": "relay_forward"}

        self.assertIs(
            dhcpv6_sampler._sample(
                ctx,
                "transaction_id",
                "deterministic",
                field_spec={},
                current_fields=current_fields,
            ),
            _SKIP_FIELD,
        )
        self.assertEqual(
            dhcpv6_sampler._sample(
                ctx,
                "hop_count",
                "one",
                field_spec={},
                current_fields=current_fields,
            ),
            1,
        )
        self.assertEqual(
            dhcpv6_sampler._sample(
                ctx,
                "link_address",
                "documentation_ipv6",
                field_spec={},
                current_fields=current_fields,
            ),
            "2001:db8:100::",
        )
        options = dhcpv6_sampler._sample(
            ctx,
            "options",
            "client_id",
            field_spec={},
            current_fields=current_fields,
        )

        self.assertIsInstance(options, Sequence)
        self.assertEqual(
            [option["name"] for option in options if isinstance(option, Mapping)],
            ["interface_id", "relay_msg"],
        )
        fields = {
            "udp": {"src_port": 546, "dst_port": 547},
            "dhcpv6": dict(current_fields),
        }

        dhcpv6_sampler._post_sample(
            fields,
            stack=["ipv6", "udp", "dhcpv6"],
            case="ah-hmac-tunnel-inner-ip",
        )

        self.assertEqual(fields["udp"], {"src_port": 547, "dst_port": 547})

    def test_dhcpv6_identity_association_cases_are_nested(self) -> None:
        plan = _first_plan("dhcpv6-ia-pd-iaprefix")
        dhcpv6 = _dhcpv6_fields(plan)
        options = dhcpv6.get("options")
        assert isinstance(options, Sequence)
        ia_pd = next(
            option
            for option in options
            if isinstance(option, Mapping) and option.get("name") == "ia_pd"
        )
        assert isinstance(ia_pd, Mapping)
        nested = ia_pd.get("options")
        assert isinstance(nested, Sequence)
        self.assertEqual(
            [option.get("name") for option in nested if isinstance(option, Mapping)],
            ["ia_prefix"],
        )

    def test_dhcpv6_generation_is_deterministic(self) -> None:
        first = [plan.to_dict() for plan in _plans_for_case("dhcpv6-option-matrix")]
        second = [plan.to_dict() for plan in _plans_for_case("dhcpv6-option-matrix")]
        self.assertEqual(first, second)

    def test_dhcpv6_smoke_profile_covers_offline_matrix(self) -> None:
        plans = generate_plans(
            seed=9915,
            profile="dhcpv6-smoke",
            count=20,
            backend="scapy",
        )
        self.assertTrue(plans)
        self.assertTrue({plan.case for plan in plans} <= _DHCPV6_OFFLINE_CASES)
        self.assertEqual({plan.case for plan in plans}, _DHCPV6_OFFLINE_CASES)
        self.assertTrue({tuple(plan.stack) for plan in plans} <= _DHCPV6_STACKS)
        self.assertEqual(
            {plan.metadata.get("feature") for plan in plans},
            {"dhcpv6_behavior"},
        )

    def test_dhcpv6_smoke_reference_direction_covers_offline_matrix(self) -> None:
        plans = generate_plans(
            seed=9916,
            profile="dhcpv6-smoke",
            count=12,
            backend="scapy",
            direction="reference_to_libcrafter",
        )
        self.assertEqual({plan.case for plan in plans}, _DHCPV6_OFFLINE_CASES)

    def test_dhcpv6_smoke_short_pcap_batch_uses_raw_and_ethernet_roots(self) -> None:
        plans = generate_plans(
            seed=9915,
            profile="dhcpv6-smoke",
            count=10,
            backend="scapy",
        )
        roots = {plan.metadata.get("root_decoder") for plan in plans}
        self.assertEqual(roots, {"link:ethernet", "l3:ipv6"})


class ScapyDhcpv6MaterializationTest(unittest.TestCase):
    def _decoded_for_case(self, case: str):
        encode_packet_plan, decode_vector = _require_scapy_backend()
        plan = _first_plan(case)
        vector = encode_packet_plan(plan)
        return plan, vector, decode_vector(vector)

    def test_scapy_materializes_solicit(self) -> None:
        plan, vector, decoded = self._decoded_for_case("dhcpv6-solicit")

        self.assertEqual(vector.metadata.get("scapy_stack")[-1], "DHCP6")
        self.assertEqual(decoded.layers, list(plan.stack))
        dhcpv6 = decoded.fields.get("dhcpv6")
        self.assertIsInstance(dhcpv6, Mapping)
        self.assertEqual(dhcpv6.get("message_type"), 1)
        self.assertIn("transaction_id", dhcpv6)
        self.assertEqual(_option_codes(dhcpv6), [1, 6, 8])

    def test_scapy_materializes_relay_forward(self) -> None:
        _plan, _vector, decoded = self._decoded_for_case("dhcpv6-relay-forward")
        dhcpv6 = decoded.fields.get("dhcpv6")

        self.assertIsInstance(dhcpv6, Mapping)
        self.assertEqual(dhcpv6.get("message_type"), 12)
        self.assertEqual(dhcpv6.get("hop_count"), 1)
        self.assertEqual(dhcpv6.get("link_address"), "2001:db8:100::")
        self.assertEqual(_option_codes(dhcpv6), [18, 9])

    def test_scapy_materializes_ia_na(self) -> None:
        _plan, _vector, decoded = self._decoded_for_case("dhcpv6-ia-na-iaaddr")
        dhcpv6 = decoded.fields.get("dhcpv6")

        self.assertIsInstance(dhcpv6, Mapping)
        self.assertIn(3, _option_codes(dhcpv6))

    def test_scapy_materializes_ia_pd(self) -> None:
        _plan, _vector, decoded = self._decoded_for_case("dhcpv6-ia-pd-iaprefix")
        dhcpv6 = decoded.fields.get("dhcpv6")

        self.assertIsInstance(dhcpv6, Mapping)
        self.assertIn(25, _option_codes(dhcpv6))

    def test_scapy_materializes_unknown_options(self) -> None:
        _plan, _vector, decoded = self._decoded_for_case("dhcpv6-unknown-option")
        dhcpv6 = decoded.fields.get("dhcpv6")

        self.assertIsInstance(dhcpv6, Mapping)
        self.assertIn(65000, _option_codes(dhcpv6))


if __name__ == "__main__":
    unittest.main()
