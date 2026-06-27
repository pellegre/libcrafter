"""Behavior-lock snapshot for the live-path endpoint address rewrite.

The probe live path rewrites every generated plan onto the lab endpoint
addresses through the big per-protocol if/elif in
:func:`tools.probe.engine.cli._probe_plan_with_endpoint_addresses` (plus the
IPv6/link-local :func:`tools.probe.engine.cli._ndp_plan_with_endpoint_addresses`
branch). Given a fixed, documentation-range endpoint-address context this
rewrite is deterministic and JSON-able. The plan-JSON snapshot
(``test_probe_plan_snapshot.py``) covers plan *generation*; this module pins a
deterministic SHA-256 digest of the *rewritten* plan JSON for every case in
``cli._STIMULUS_ENDPOINT_CASES`` so the later refactor steps that relocate the
per-protocol rewrite branches into plugins prove byte-identical behavior.

The fixture is documentation-only and deterministic: the stimulus/target
endpoint IPv4 addresses live in ``192.0.2.0/24``, the endpoint MACs are
documentation-style locally-administered addresses, and the IPv6/link-local
addresses the NDP branch derives come from those MACs. The expected digests were
computed once from the current engine and hardcoded below; there is
intentionally no print or self-updating logic.

The suite is offline and deterministic: pure Python planning + rewrite, no
uv, cargo, or network.
"""

from __future__ import annotations

import hashlib
import json
import unittest

from tools.probe.engine import cli
from tools.probe.engine.cases import PROBE_CASE_BY_NAME
from tools.probe.engine.model import ProbeRunRequest
from tools.probe.engine.planning import probe_plans_for_cases


# Fixed, documentation-range endpoint-address context. The IPv4 addresses are in
# the documentation range ``192.0.2.0/24``; the MACs are locally-administered
# (``02:..``) documentation-style addresses the NDP branch derives EUI-64
# link-local IPv6 addresses from. The seed pins the base plan generation.
STIMULUS_IPV4 = "192.0.2.10"
TARGET_IPV4 = "192.0.2.20"
STIMULUS_MAC = "02:00:5e:00:53:10"
TARGET_MAC = "02:00:5e:00:53:20"
TARGET_INTERFACE = "eth1"
REWRITE_SEED = 4242
REWRITE_SOURCE = "lab_session"


# Per-case digest of the rewritten plan dict, keyed by case name. Every case in
# ``cli._STIMULUS_ENDPOINT_CASES`` is individually pinned here. Recompute
# deliberately (never auto-update) if and only if an intentional behavior change
# is being made.
REWRITE_DIGESTS: dict[str, str] = {
    "arp-alias-address-reply": "13a422c90aec56cf61e88d0bd27334721af084958c6eeef7eca999691f77834b",
    "arp-basic-who-has": "f05e7726246d30fa8b352d5a1dc3db41e3a6160ade4e6530b507101ae3fb03c7",
    "arp-broadcast-filtered-capture": "636ae27a3e8b6b7e2fc62405ce944678c2802824edf4b4297323f29f86a0ea4e",
    "arp-cache-flush-reply": "11ef9ba8a75bf4a99c6aa46a22732cf4fcd724ace1fa9eb2c4431f2976a82176",
    "arp-mac-validation": "7adf75da8638b8fa214c39d5bb0820082117854f25bf701ab7ad95b296d31ede",
    "arp-padding-reply": "b8e6613f3dc2f85c8845fd146e6e31237935b3562caf59c5ac0c15c6cfeaec40",
    "arp-repeat-two-replies": "c2e81ba5ee729fcf461d15f38dd46e16e4f7dfb6556ce38e08ab51a50c879fbc",
    "arp-source-address-preserved": "39a4ba6f4f8f4c7a24366a98caf554c9380704b62c12a41fc0706ac62efc05bf",
    "arp-spa-variation": "a9512b94c8c2fa87074ad7bdac690e4e01c63cf84845a088a47457dd9bbce3c1",
    "arp-unicast-request-reply": "a1c7c6e2b394c4abb9d7db374fc3064fc12fa8f19ffcf47f1917f28fbcd116f0",
    "dhcpv4-client-identifier": "e7be8db4d9ba3a534a678b3a67e1766420061b3ff021349645c11b752ffb0703",
    "dhcpv4-discover-offer": "92df7e75a2152d2778986f0dad3b9004d64d8e70649cdd57d241cd335d52f787",
    "dhcpv4-hostname": "6fa2d462e4ddd9c2c1d537badf6f163e4c2638193f37162abc54c39a8bd705b0",
    "dhcpv4-inform-ack": "1cdff0c314fc8440ecb39efd33d7aad5728644662601a98bb414dd45a69bed59",
    "dhcpv4-lease-time": "2d499cce67c62d3c81fe13fa9b6a8a2330c49d5387ee7b6874e823ba92296211",
    "dhcpv4-parameter-request-list": "83ba4a9de126369e651dba26da1ed11893de9d396225b1317485fd5910d4c481",
    "dhcpv4-rapid-repeat": "092cddc1927f309129790ca8b3bf6aa0cd9eef1ed5e23a3b8f70eea551a8322f",
    "dhcpv4-renewal-unicast-ack": "afa495c963104f42d36f4c391bd0cad2b9cb444887db11418cd4cb634e603477",
    "dhcpv4-request-ack": "0b49c0484c35489cf0b57a55876960f15bff122fee65a1b343576cb048939207",
    "dhcpv4-request-nak": "f2d05d8b0ef61719843d83bb39477575d7ee8dab37d73befd464683ce2f59386",
    "dns-a-success": "186201269324720d875d7e977babf0a79eed7119c525a541607de8c6f6b37e8c",
    "dns-aaaa-success": "7ec53a7f7c205fada468c6dddc61184d9a0d624e1405d15e2cce5692da61a080",
    "dns-cname-chain": "07bcd0d2de34b12e37eee19cb9183dfa198d711f2c2ea02c48acf703415fad55",
    "dns-edns-opt": "d912e5555a1015586e8d401559fa9d37f29d254268835e83f14100e87959d5dd",
    "dns-mx-answer": "703c155af4359783e72a3c59329d122173836b77b3e98de80e2647d117ebb2ac",
    "dns-nodata": "96edb783f33bd770c988552ac9bd2f1461dd3fa8ea13219a92a1794c2f9fd9f4",
    "dns-nxdomain": "dd4bd459ccc995c041701a7b3fea7470f0d6101a483224d2c5d31fd1129839c4",
    "dns-query": "ac7983fb5116f2707206496e382af058d16d59d1e56e4e0e91048b86e977dd78",
    "dns-repeat-transaction": "97aa60bee672a23e14d564b6e141b9e9d0168befbcccb19ca0171d6c393fe6ff",
    "dns-srv-answer": "ee403727917ae8fe902d7e667dd98eea0461a722acdb9bb2b8efce6b8606e384",
    "dns-txt-answer": "1b23be37362e3e8f8598b84a6e9d7f489b20edb13369e641058fba6cc5a48ead",
    "icmp-echo": "bfab9d15f362f498422b7e275c741f6cbcd1ed52e8e84f3b6c875e67c29c064c",
    "ndp-duplicate-address-detection": "dbe3201e1cbf7c2a8fa98d98549fdf7417128fc1d79d4741732dd60c831d89f9",
    "ndp-neighbor-solicitation": "370a344dc0fe7b07254594a2415c6f00b4d27734da865a637e7ef196cfd3ce4d",
    "ndp-router-solicitation": "16ea7b10442d032555bea4d2efa11dc43177f9587bdb65fe1e418e36eb5664a4",
    "ospf-hello-exchange": "9bf3e1d497c8e2404e80c95a0cf58f52cc93a8f68f784302d273a5818610bbb9",
    "quic-initial-udp-observation": "333992d27b0cdca999480fad5358234724aaf8d277dbba4f654c7cf7ddfa781d",
    "snmp-get-response": "4105476f8a7d1da56f01073a02f72a18f304ae25909249a4d73a81cfd7e01ed4",
    "snmp-getbulk-response": "0207340c1e09e1bc71c30e23becdde9098904e30ff58206b5b5559179934b755",
    "snmp-notification-trap": "86a24d2f0a6d83fde84fa17c0a6ad6f70e1f8006bac836cbaf2ea5e3fdf0a0d0",
    "snmpv3-engine-discovery-report": "bfde17a3d36b9ed3c5a7e76ed984c42c018f122935d8e6946e65ca427fe9063a",
    "tcp-syn-closed": "9732ff1fed6789850825ccc582b1c6dc7dd2c978f2a29d4833e4fff2bf85f93b",
    "tcp-syn-open": "4d1d4aeecfc025cff25e6bc5ffe6b55854e8d3b763128554e73d03683fd3b0a0",
    "tcp-syn-options": "458186f9cf6827c9b7595092d66c3caf5929df27039cd0ee8388e4f05e885bc2",
    "ttl-expired": "e687bec9ed0649db33ab140084c0c954ae8a5636ddcbc23bed541fb1f786fb91",
    "udp-closed-port-icmp": "f7d41bd23ba83e563baa3c222b99c175ead8d2617acc59318e99989c00ba388c",
    "udp-echo-binary": "209af25593738a4bb62612bf999bb6ad1356f17aeaadd9c60eae5e6330536455",
    "udp-echo-empty": "5cc86db0654fad938694d9002a345bff4bfdb1c53c61bc4aa62f94a4e0f1e9ca",
    "udp-echo-large": "b3b5bb0c885fd89829425b0b108b60654d95e021d154bbd19e1655b77d801dbf",
    "udp-echo-short": "ce6d49e9b28ab095e62ece59aa95a365f3e61084a8182080f349ee9bccfc060a",
    "udp-length-boundary-echo": "5dffbc3d00f2a26e85da3daa0f8691a898d9895b86d5c9aff4d1e28638736d7e",
    "udp-multi-shot-order": "ee86b9dd241377644b6ffbc8d1cb9a441366b632141e6a8376c077a8264ffa98",
    "udp-options-surplus-echo": "3f736b8efede9d0c251006cd171aa1c92f80f4548cc8e0b7b822b530c9d715f3",
    "udp-source-port-reflection": "fcd3cf1939b853b68283805c81a0a494c3cfa1612644ad1356335ed88a7c3542",
    "udp-zero-checksum-ipv4": "6ac7fefff050e94aa7cbfd724dc57f93e0ffc831998f44675b5ad8f2eb2db16f",
}


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _base_plan(case_name: str) -> object:
    """Generate the deterministic pre-rewrite plan dict for one case."""

    case = PROBE_CASE_BY_NAME[case_name]
    request = ProbeRunRequest(
        provider="qemu",
        profile="behavior",
        seed=REWRITE_SEED,
        count=1,
        dry_run=True,
    )
    return probe_plans_for_cases(request, [case])[0]


def _rewritten_plan(case_name: str) -> object:
    """Rewrite one case's base plan onto the fixed lab endpoint addresses."""

    return cli._probe_plan_with_endpoint_addresses(
        _base_plan(case_name),
        source_ipv4=STIMULUS_IPV4,
        target_ipv4=TARGET_IPV4,
        source_mac=STIMULUS_MAC,
        target_mac=TARGET_MAC,
        target_interface=TARGET_INTERFACE,
        rewrite_source=REWRITE_SOURCE,
    )


class ProbeRewriteSnapshotTest(unittest.TestCase):
    """Pin the rewritten plan JSON for every stimulus-endpoint case."""

    def test_rewrite_digests_are_locked(self) -> None:
        for case_name in sorted(cli._STIMULUS_ENDPOINT_CASES):
            with self.subTest(case=case_name):
                self.assertIn(
                    case_name,
                    REWRITE_DIGESTS,
                    f"no pinned rewrite digest for case {case_name!r}",
                )
                self.assertEqual(
                    _digest(_rewritten_plan(case_name)),
                    REWRITE_DIGESTS[case_name],
                    f"rewritten plan JSON changed for case {case_name!r}",
                )


class ProbeRewriteSnapshotCoverageGuardTest(unittest.TestCase):
    """Fail loudly when a stimulus-endpoint case is added/removed undigested."""

    def test_rewritten_case_set_matches_pinned_keys(self) -> None:
        self.assertEqual(
            set(cli._STIMULUS_ENDPOINT_CASES),
            set(REWRITE_DIGESTS),
            "cli._STIMULUS_ENDPOINT_CASES and REWRITE_DIGESTS keys diverged; "
            "add or remove the rewrite digest to match.",
        )


if __name__ == "__main__":
    unittest.main()
