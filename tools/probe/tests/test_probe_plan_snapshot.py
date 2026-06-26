"""Behavior-lock snapshot for emitted probe plan JSON.

This is the keystone safety net for the probe plugin refactor. The plan dicts
produced by :func:`tools.probe.engine.planning.probe_plan_for_case` (via
``probe_plans_for_cases``) are the cross-language wire contract consumed by the
Rust adapter under ``tools/probe/adapters/``. This module pins a deterministic
SHA-256 digest of that emitted JSON for:

* every engine-exposed profile (read off ``cases``, never hardcoded), across a
  small fixed set of seeds and a fixed planned count; and
* every individual case in ``PROBE_CASES`` at a fixed seed/sequence.

Every later refactor step must keep these digests byte-identical, proving it
changed no observable behavior. A guard test asserts that the set of cases and
profiles still exactly matches the pinned digest keys, so adding or removing a
case (or profile) fails loudly here rather than silently going undigested.

The suite is offline and deterministic: pure Python planning, no uv,
cargo, or network. The expected digests were computed once from the current
engine and hardcoded below; there is intentionally no print or self-updating
logic.
"""

from __future__ import annotations

import hashlib
import json
import unittest

from tools.probe.engine.cases import (
    PROBE_CASES,
    PROBE_CASE_BY_NAME,
    known_profiles,
    profile_selected_cases,
)
from tools.probe.engine.model import ProbeRunRequest
from tools.probe.engine.planning import planned_cases, probe_plans_for_cases


# Fixed snapshot inputs. These pin the planning seeds, the per-profile planned
# count, and the per-case seed/sequence used to generate the digests below.
SNAPSHOT_SEEDS: tuple[int, ...] = (1, 7, 12345)
SNAPSHOT_PROFILE_COUNT = 12
PER_CASE_SEED = 4242


# Per-(profile, seed) digest of the ordered list of emitted plan dicts. Keys are
# ``"<profile>:<seed>"``. Recompute deliberately (never auto-update) if and only
# if an intentional behavior change is being made.
PROFILE_PLAN_DIGESTS: dict[str, str] = {
    "behavior:1": "78f010dc3696ef6a5b9e36a5150dcaa11206a6494e3cbf11c789bc5b3227f8da",
    "behavior:7": "94393d241f611570467c930d0c83aa460a4b21456992bab051206fc81b609207",
    "behavior:12345": "ff8891926d4a0d980d70954602f77ed80b570450814e264c2453e580b6512c57",
    "bgp-smoke:1": "b84b465fefcfe30d1ff58f9c4343cfb823cb602e3c1d4f25e3041b7c1892be42",
    "bgp-smoke:7": "0ed21e7c89b1c6286a148550cff345e316a767ebf1457bfb2470f363d0349b09",
    "bgp-smoke:12345": "dfda4140bd99676d41c44a29e55228b48eabd6dc5883530aac7f346268c40cad",
    "igmp:1": "1aac31bcbe02c1230a1f9d32435aa646975830d199763dabe6d36ae61dc8b9ff",
    "igmp:7": "7864449e11c2354f0ba4865938b82c3d4bed0c396804ee895eda304a2b500ba0",
    "igmp:12345": "f51fbec327253accf4e453779126ecaa7f97993ec4a9a08dd2b84cff4739f202",
    "ipsec:1": "5eafe68409799da7a908e15072f1f42555e8c0e1668f04243741d0dec17fd600",
    "ipsec:7": "184b21689ac93d9dc79c92f5593b71c5c55e9cdc2b90d221cb79eb179accd687",
    "ipsec:12345": "2a9ce0da6a9387487bc9c72e164251559175fec8c335eaa10299301a0aa12062",
    "mqtt-smoke:1": "fefee9866071f67342b446c0d4fd9385fcc97e7752c62941a258171135b933be",
    "mqtt-smoke:7": "bf4907795247cf08c83521daf2c9e6b8b5a2f6e34879b6f0189e5c1102ade30c",
    "mqtt-smoke:12345": "5247c938ea319d92a403383c19d8a0050ed76f2c14c5006522dc0ebe5633d888",
    "ospf-smoke:1": "e102a929bb6296c0172a7e9ddd8db161aabba7e5c390edec9ada931aabcc3ab4",
    "ospf-smoke:7": "c0adcbf467a43743d413aec17423c37ae5442826435c84367dbae9cacd2e1025",
    "ospf-smoke:12345": "1c65414e4d63f27f33f9b00c47ade7af96e72a468b51677d33e2dfe0001f5646",
    "quic-smoke:1": "dc6fdb0a0d2fb9b2ad52cba0f9e0700bd356c27072c23b0dd15fdc18cc89e8c7",
    "quic-smoke:7": "49595d06f963e164f21edad9dee3cd3580b5fb51f988657ff1f93873236958bb",
    "quic-smoke:12345": "cbc5a6a6cc0edc5fc93db53dbd8cb80171a86bf7a24c6495498df080d8d0b556",
    "rip-smoke:1": "c47612480e42b8d425be82d6915e8a4d3e88c2049c9660dc5e36b0ceb7f83898",
    "rip-smoke:7": "775c38236cf78b4a1979d23dcbe51876aaf20717c8af6221ec0df81d354ea5e4",
    "rip-smoke:12345": "63f47505202021c685c88d86d4393ad7f5aa85baf465a192084398f971cc514c",
    "smoke:1": "518adc8cbac4ad4bc800c1b5da0a99cc075589b4775368fe0143529b1c5ca2d9",
    "smoke:7": "c15f30a7aac321ca1601c53bcafb10902dd912962ee88dc550640c0dfe4a5416",
    "smoke:12345": "40007ee4950ce5b4b129fe3d2d0d7e355e645fbb351457ca2efb5b0d347795be",
    "snmp-smoke:1": "870689b697d5b5044c29cb9bc632d76a812550e1c82e84cbead9fd37f3e0cd30",
    "snmp-smoke:7": "34520c5c156e2e1b3583926db0fbbff2b4c2357b3525428e0f36fd0952af2c7f",
    "snmp-smoke:12345": "3277df0d37f6573333b620c6ddad46ef674e50c7f8e3db677b710a6f843ccf20",
    "tcp-smoke:1": "401b7f4dbbba35981d80ae64bb610812c2839d2157aae1227c622da4b8302387",
    "tcp-smoke:7": "0a8c417754f0bc6c251cabdd219e4d0cb118de0b5dc97017eebc921e962317f9",
    "tcp-smoke:12345": "cbaab7d6eb6ad35e860311c01c03039369292652e1e3676cb455b9ad6b3d5487",
}


# Per-case digest of the single emitted plan dict at the fixed per-case
# seed/sequence. Every case in ``PROBE_CASES`` is individually pinned here.
CASE_PLAN_DIGESTS: dict[str, str] = {
    "icmp-echo": "9ec4b56944ed98e799782668975df2e8e72d8a33a34d2f611b18e3002aa361d1",
    "tcp-syn-open": "c628bbe320b4f05021ffcbe584d0dd334b09f752dc943d2b2258bc4bbe1973b7",
    "tcp-syn-closed": "87a3df56d338abad6cef4a9a6aca1d9fee9374b5cc13fe7ddd9cc1684d82b3a3",
    "tcp-syn-options": "cb855b218c5be192c125e7414b19ffe74d59983b99b0a5fe7e60343c4a2c876d",
    "dns-query": "e408a9242bef1ad92a02249f89339c295f9c39eb14abff92d38731b83934d083",
    "ttl-expired": "dcbb08eeb5e6331e363615e6c70462ab32ee615e4fc7fb092f0eb33594707485",
    "arp-resolution": "639050f41c1982ebb71b1009cd0f36a2a1b6e2901a872095afc388f9c67b38ae",
    "dns-a-success": "4deffc2bd5c34b67481ae6f636c25dff5dfa4a7fc88f4455d9c3b9effe54b05f",
    "dns-aaaa-success": "fb6e80bc9c7c2c214540e16295a0ba67b270735e16906e5a62fec8ea8249a57f",
    "dns-cname-chain": "20fc894f82daf651b1b4a1acb20e630a9ab7e2ca839d8f5944c2e1462b51dcf4",
    "dns-nxdomain": "6b40a9212d6f143ddabf775dfce5105f9c9b931723bfb6961351fe5ea7930c99",
    "dns-nodata": "bf1bafc4b4abd6adf905f305053f670ae9946b41a05a8e367c66d8e0073d398f",
    "dns-txt-answer": "3bcd7af77fec54755c7c6d67189492eab7ac34bce7fb18f164a3105f1ef780ad",
    "dns-mx-answer": "7ccfef14e8f22de3fd358a08c7b48944994ea20dfe7a6c21f977d78d41fd9e09",
    "dns-srv-answer": "ac152a54dad5a89933ec9447ccfb1d6ba65710f6079481fa05d27b9bb827943f",
    "dns-edns-opt": "7676d6756f33b9c5b701280dfeaffdb6fd1814ee405b37a13834249b20a115df",
    "dns-repeat-transaction": "00b4f46bc9a79af82d490bd4724b857c76f14c5b888ac8cc02ef1dae88f89b24",
    "dhcp-discover-offer": "0c48ee6c444e788e0b4f09e6a2a87f269aa6280e42e11d431df2653c40d7a599",
    "dhcp-request-ack": "22fc552aa71ae6206bb3f6af04f3184ad56bc0f00ae2a0d7243e98df1344a89d",
    "dhcp-client-identifier": "ec425316f163bb18f53ff5cb9eefa01b64f2f1566360e44c4d9549888164da8b",
    "dhcp-hostname": "54fb5fd9c072c70e747fbdd79dfb3001adae3741670c6880cb3294e31e4818a2",
    "dhcp-parameter-request-list": "a470d1c9c5ebeb91f3b5425b7dc52d8cc29d1581e7cbf1ba0ac5ad793aa77e3c",
    "dhcp-lease-time": "815d9cb616ed8ca848d7d6284639d63c5bf526f65d0cd648c63d31a51f2c362e",
    "dhcp-renewal-unicast-ack": "23ba2f9f8b547eacdf6ceacb827cfd9477d0e50b9b627fa7721a3af4be9a6ca6",
    "dhcp-inform-ack": "91213c087b2cbae3a1a521394f50a2c3f75e7ba055f0b7cc571426964567ff07",
    "dhcp-request-nak": "50ebd3bd6f99756e979663ac0b159cad1ebe3cc876eab051d608813b08121deb",
    "dhcp-rapid-repeat": "3d9a85e9b0cc296014a6925e4b3f71aca62cabc5d2a535194ea3617be0da3446",
    "arp-basic-who-has": "9e8d200ecc0b03b5878cbe0297f85dd84ec51e5a02bfa06c0d78ea0c4c907469",
    "arp-repeat-two-replies": "567097b639846dfce90edead28e5fbf549c21aea239962d43c663a554140b59b",
    "arp-source-address-preserved": "c7eefb8dfd13f10338dbd7bdcc2a0c0c12fe830920c37f7b04a6a1ee4eecbaad",
    "arp-alias-address-reply": "cd1058383465fcee4419ee3e71d0038f914f83158817aa5e0ef6c409e8ede4bb",
    "arp-unicast-request-reply": "3836f0d67a980d9fc9530585cb10174402b26e3eab56ea3623af8f0ba1e1bf98",
    "arp-padding-reply": "24e2cc696f9faf9e2d74b2f0bc620a5f2357c4a7893c510554504b8b4cc4903f",
    "arp-cache-flush-reply": "91f5180e38cc558b589263c4fa366d3f6a94e4fd736d4f342d86be1924265544",
    "arp-mac-validation": "fdabe7ee35b304bd7dfec1151f24e7cfd1f558de46a5fe50f652f2dde74f0f0d",
    "arp-spa-variation": "9411410d7460dfa4520b5b614a4cc931cc179aad3708230f0038d92801958498",
    "arp-broadcast-filtered-capture": "e59555f501cb0069e448382b3feeadc7aaca9e42b8a1e9cf0a1ce950fd20c9fc",
    "ndp-neighbor-solicitation": "f3251259775c90b0f5c895977b457564f0abee89085e1633caef2648f6315aaa",
    "ndp-router-solicitation": "118cdb334a8e6b8323189fcdb8d4bece919045d286ebfec33b1b94cb90040c85",
    "ndp-duplicate-address-detection": "a15b5a2f5979adb433e535108856328d6456ffa41c5417612a869ec72f29ebc3",
    "udp-echo-empty": "77aadf7f0509eb02f7e7ade3ed8575d6de18acdd5bad39c5009c7f5ade8dba5b",
    "udp-echo-short": "1d9b12c1835a5f7c640a845d699ec63c1aebe6270b08a90d33a8ea2f51d61dbd",
    "udp-echo-binary": "421c983d1056a58fe43910408b755171dae310cbffba8a7fd617f220f43947c3",
    "udp-echo-large": "42ea5a108e1ff0129ac873cda9336177cadc19fe594329eabebe587e2a40cdb0",
    "udp-source-port-reflection": "9e63c552da5ce3fb7b9742516295f13914ad82a1838551cd54041b0a13aae7d2",
    "udp-multi-shot-order": "ca14681e652a80bf27b790b5a7977f701bab729dab04caa636016a55aa4ea78f",
    "udp-closed-port-icmp": "e3caf56aab52481da9858edfca7f7eac5b377fcac59cbcdc7d1b030d17d9f005",
    "udp-zero-checksum-ipv4": "d64b3ec9cdf94283d9b7cad1c17441d33ebe7d430f69e0902157053fff99b05c",
    "udp-options-surplus-echo": "0ca6258a73f102f2f6f749bd28edb711bd076d9bda8983575e4407728e0115ad",
    "udp-length-boundary-echo": "7d2163ad127baa9988fa23d25727743adf70f6181a1c26a1a041e5ffc29773d9",
    "ospf-hello-exchange": "328a8bcbef396feecafb0758c183997525ec6dc2572f9ccabc95c5a89b884f0f",
    "ospf-dd-exchange": "af6e49246005e4372a15c96f5c706326f519d9ddeb237738ecc9947e2718307d",
    "bgp-session-smoke": "9d6c347df4c6b86103672553fca72c757617da177dbd792cd1ec8e644c6a891b",
    "rip-update-v2": "febf11fc439b31f488768a0b023dfdd0a17167dc4dea1c3be59b1aa96cb3b046",
    "ripng-update": "11565c245deff44d013a589fc6bc48cd736b2fc1ccdb4afdfc96ce42f77db86d",
    "mqtt-connect-connack": "1020c708710a8de1c0aa0ac04646a576e59410e3b9a7fecc329ffee34591b143",
    "mqtt-v5-connect-connack": "d8d3445d5d89849df402ae1909eff8c9d6dcb728206555c7173a1997fb7e58ea",
    "mqtt-subscribe-suback": "13a4fa04b76735ddea64954086276569ab26d1918a685383a465e8c123b99590",
    "mqtt-publish-puback": "10123d137b01949891f7d7efff2566189e963a3cbb58ea70e3909b1403ff7d39",
    "snmp-get-response": "396e23b564a24ac3bd69a15c93c8b8aaa318f9d732c5ff6596cafe879a7b7a41",
    "snmp-getbulk-response": "f5e779620660b822f6d8951ff53632ead396e0a5a81e331a502bfa0dc1efbf08",
    "snmp-notification-trap": "80e4ccdf84390f22c2141f76ed8ddf39d3badf2ea85da3f860940925e15da87f",
    "snmpv3-engine-discovery-report": "42fa43a77fee81819b230109b1b1b1daf765047bd1f24c63b747f6da04b9bdf4",
    "igmp-membership-query-observation": "ea704a25f05be3e1379b71b710389e637283e071b34d4c6989ec9827d52560c5",
    "igmp-v2-membership-report-emission": "51a1985a38e255360c8a301739be58eff5259b120594aef010f9ecadd389d23b",
    "igmp-v2-leave-group-emission": "8810922568b05ad5d3c60bc6898ed2eec20a28613e6bf1fbc231d5a0124b8d48",
    "igmp-v3-source-list-report": "c52e1b71af3adc27f795c736f019ad15e60d7c3d186a8259e9f5e0277b86dd21",
    "esp-transport-echo": "c8066bb34835f40bccbdfd4f9be4625440b34e8a1af590bab1e0e8af100a2a92",
    "esp-tunnel-echo": "982ef30418b05851f42da88d28d167e3f3b2f692993afde04146219796c51296",
    "ah-transport-verify": "b9c42a15caea17c29f53759034586520f11873cdfe97125e64ebce1eac8973c5",
    "ikev2-sa-init": "0c375af8619b2b4564928107c310dad77b7c69227972e057b8c18f91bdbb391a",
    "quic-initial-udp-observation": "71c7ff8db7fd00774b1a479aebb7e4992b98da0d80f9bb8efc67fd49afae72bc",
    "quic-version-negotiation-observation": "e9382e4f00e501edad1a60ca375b63278ab62cc805e6300aa5d6a5fc6ef3b32f",
    "quic-retry-observation": "85b66a8c8098fcf17843ef46aca54aa6b980d01471637b3fcfbea9b298beda35",
    "quic-stateless-reset-observation": "5bf10cffff720854b6a7c60159e54a362799827f5b856b0914f7b6954c0aff95",
    "quic-protected-flow-plan": "9dc5f5bf554376f93ace6227591c61d49d6317b096604f6648efca949a5cbcfd",
}


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _profile_plans(profile: str, seed: int) -> list[object]:
    """Generate the deterministic ordered plan list for a profile and seed."""

    selected = profile_selected_cases(profile, [])
    request = ProbeRunRequest(
        provider="qemu",
        profile=profile,
        seed=seed,
        count=SNAPSHOT_PROFILE_COUNT,
        dry_run=True,
    )
    planned = planned_cases(selected, seed=seed, count=SNAPSHOT_PROFILE_COUNT)
    return probe_plans_for_cases(request, planned)


def _case_plan(case_name: str) -> object:
    """Generate the deterministic single plan dict for one case."""

    case = PROBE_CASE_BY_NAME[case_name]
    request = ProbeRunRequest(
        provider="qemu",
        profile="behavior",
        seed=PER_CASE_SEED,
        count=1,
        dry_run=True,
    )
    return probe_plans_for_cases(request, [case])[0]


class ProbePlanProfileSnapshotTest(unittest.TestCase):
    """Pin the emitted plan JSON for every profile across seeds."""

    def test_profile_plan_digests_are_locked(self) -> None:
        for profile in known_profiles():
            for seed in SNAPSHOT_SEEDS:
                key = f"{profile}:{seed}"
                with self.subTest(profile=profile, seed=seed):
                    self.assertIn(
                        key,
                        PROFILE_PLAN_DIGESTS,
                        f"no pinned digest for profile/seed {key!r}",
                    )
                    self.assertEqual(
                        _digest(_profile_plans(profile, seed)),
                        PROFILE_PLAN_DIGESTS[key],
                        f"emitted plan JSON changed for {key!r}",
                    )


class ProbePlanCaseSnapshotTest(unittest.TestCase):
    """Pin the emitted plan JSON for every individual probe case."""

    def test_case_plan_digests_are_locked(self) -> None:
        for case in PROBE_CASES:
            with self.subTest(case=case.name):
                self.assertIn(
                    case.name,
                    CASE_PLAN_DIGESTS,
                    f"no pinned digest for case {case.name!r}",
                )
                self.assertEqual(
                    _digest(_case_plan(case.name)),
                    CASE_PLAN_DIGESTS[case.name],
                    f"emitted plan JSON changed for case {case.name!r}",
                )


class ProbePlanSnapshotCoverageGuardTest(unittest.TestCase):
    """Fail loudly when a case or profile is added/removed without a digest."""

    def test_every_case_has_exactly_one_pinned_digest(self) -> None:
        case_names = {case.name for case in PROBE_CASES}
        self.assertEqual(
            case_names,
            set(CASE_PLAN_DIGESTS),
            "PROBE_CASES and CASE_PLAN_DIGESTS keys diverged; "
            "add or remove the case digest to match.",
        )

    def test_every_profile_has_a_pinned_digest_for_each_seed(self) -> None:
        expected_keys = {
            f"{profile}:{seed}"
            for profile in known_profiles()
            for seed in SNAPSHOT_SEEDS
        }
        self.assertEqual(
            expected_keys,
            set(PROFILE_PLAN_DIGESTS),
            "known profiles/seeds and PROFILE_PLAN_DIGESTS keys diverged; "
            "add or remove the profile digest to match.",
        )


if __name__ == "__main__":
    unittest.main()
