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
    "behavior:1": "eb4cc5e4a3a9379577da10d879aa6d26e0e8e47a45a9332320773f7aec997c42",
    "behavior:7": "3e6e170757b9998716fba4e92f893cd7236d1ea4b1e66c64d16f79a430879fbd",
    "behavior:12345": "ff8891926d4a0d980d70954602f77ed80b570450814e264c2453e580b6512c57",
    "bgp-smoke:1": "b84b465fefcfe30d1ff58f9c4343cfb823cb602e3c1d4f25e3041b7c1892be42",
    "bgp-smoke:7": "0ed21e7c89b1c6286a148550cff345e316a767ebf1457bfb2470f363d0349b09",
    "bgp-smoke:12345": "dfda4140bd99676d41c44a29e55228b48eabd6dc5883530aac7f346268c40cad",
    "dhcpv6-advanced:1": "4bf33fd3f5ad38ce023e17cbb8e3bf38a3a3a8a7a8e486188a7c81dd5f1c1f03",
    "dhcpv6-advanced:7": "c7ebbd730066b5b437ceb627e82d6065555ff433d317c60c2341089027e89dce",
    "dhcpv6-advanced:12345": "31345efa98ecf0609a22814524f8f62a2714a6a03b448b30bf974b5148dcd449",
    "dhcpv6-relay:1": "64d9585dc601a303f1ff98118456b44c85b529ce33bc1b5b2b2683dfc5461aef",
    "dhcpv6-relay:7": "37a5e0073b6dbfcdd3698979999cc3a4c14cf31611d7ad03f1861ae80a13dc8e",
    "dhcpv6-relay:12345": "955cc6924add34502a10e304cefbe8306e58123650e51d01d93a1106a3137186",
    "dhcpv6-smoke:1": "ff20b0ce4f196200a62f0b3b77f26d829116d81ab7c7b0a3943dcea9f8554f02",
    "dhcpv6-smoke:7": "4a20f9b5efde72923ac0cff4f38aac4e4ef8edea63f68ea0e800afd0864dbecf",
    "dhcpv6-smoke:12345": "67d2f85f4acb464e0f284a1c73ed046b2e2554e66b4f9f1df10577eba6f0e7ab",
    "igmp:1": "1aac31bcbe02c1230a1f9d32435aa646975830d199763dabe6d36ae61dc8b9ff",
    "igmp:7": "7864449e11c2354f0ba4865938b82c3d4bed0c396804ee895eda304a2b500ba0",
    "igmp:12345": "f51fbec327253accf4e453779126ecaa7f97993ec4a9a08dd2b84cff4739f202",
    "ipsec:1": "5eafe68409799da7a908e15072f1f42555e8c0e1668f04243741d0dec17fd600",
    "ipsec:7": "184b21689ac93d9dc79c92f5593b71c5c55e9cdc2b90d221cb79eb179accd687",
    "ipsec:12345": "2a9ce0da6a9387487bc9c72e164251559175fec8c335eaa10299301a0aa12062",
    "mdns-smoke:1": "f89b9abfa13108331fe45a4a6edb064b2850bb31669cee3c080a27a7e674e458",
    "mdns-smoke:7": "c65e1f07ec7fa0d75dccce69d347c56d508d74c7f4b1a874314c65526268d194",
    "mdns-smoke:12345": "e7413afaed40411ee32d32cf35e94446114c838d9b876373ab894f40021a2438",
    "mqtt-smoke:1": "fefee9866071f67342b446c0d4fd9385fcc97e7752c62941a258171135b933be",
    "mqtt-smoke:7": "bf4907795247cf08c83521daf2c9e6b8b5a2f6e34879b6f0189e5c1102ade30c",
    "mqtt-smoke:12345": "5247c938ea319d92a403383c19d8a0050ed76f2c14c5006522dc0ebe5633d888",
    "ntp-smoke:1": "c3310eda4c9752a9d93ce7d17a853c23e9edb89f961c0268c24da7be4634f810",
    "ntp-smoke:7": "a801a82cec3fd6b1568d99b6417c9dc7519d2e504be71ffae5be091248706eff",
    "ntp-smoke:12345": "b2df99e2340bfaff0b2c85e3b1a5a6852fb85d88f45c6ec40089e54afb0f5273",
    "ospf-smoke:1": "e102a929bb6296c0172a7e9ddd8db161aabba7e5c390edec9ada931aabcc3ab4",
    "ospf-smoke:7": "c0adcbf467a43743d413aec17423c37ae5442826435c84367dbae9cacd2e1025",
    "ospf-smoke:12345": "1c65414e4d63f27f33f9b00c47ade7af96e72a468b51677d33e2dfe0001f5646",
    "quic-smoke:1": "ab2299cd6550864b4cdadea5c187bef584dc856412bc4fea854b984f435e35d3",
    "quic-smoke:7": "eedd7b257dc4a7809d3b9289337affd1eae6970933e9ed60bf0d4a9c9eae4a6a",
    "quic-smoke:12345": "3f57c0b5c63e6df74dcfb62266fcf654f0b6da3f811996c2155ccb8df0bc8969",
    "rip-smoke:1": "c47612480e42b8d425be82d6915e8a4d3e88c2049c9660dc5e36b0ceb7f83898",
    "rip-smoke:7": "775c38236cf78b4a1979d23dcbe51876aaf20717c8af6221ec0df81d354ea5e4",
    "rip-smoke:12345": "63f47505202021c685c88d86d4393ad7f5aa85baf465a192084398f971cc514c",
    "sctp-smoke:1": "0094b75abb30d276aeea1a2f9b2741793e4e39eafbcc6aefa009791cadd9f2f0",
    "sctp-smoke:7": "4d7d0d980b216188a24a030772c7728ffd6fd8555594d57e5bf5c6143dc58be1",
    "sctp-smoke:12345": "f2cfdb256a2f4f5073e1f063da138bebd121474d9a1fb4d485898263b0e4d13d",
    "smoke:1": "518adc8cbac4ad4bc800c1b5da0a99cc075589b4775368fe0143529b1c5ca2d9",
    "smoke:7": "c15f30a7aac321ca1601c53bcafb10902dd912962ee88dc550640c0dfe4a5416",
    "smoke:12345": "40007ee4950ce5b4b129fe3d2d0d7e355e645fbb351457ca2efb5b0d347795be",
    "snmp-smoke:1": "870689b697d5b5044c29cb9bc632d76a812550e1c82e84cbead9fd37f3e0cd30",
    "snmp-smoke:7": "34520c5c156e2e1b3583926db0fbbff2b4c2357b3525428e0f36fd0952af2c7f",
    "snmp-smoke:12345": "3277df0d37f6573333b620c6ddad46ef674e50c7f8e3db677b710a6f843ccf20",
    "ssdp-smoke:1": "d9e9f4c36c2106225433b83bc779c9d7346425dbbc051857f0b8dd3d1fffef62",
    "ssdp-smoke:7": "1c9f1bc2102686658c0ac1b24a5a136b6902527e5c526f7236310e482d2a3596",
    "ssdp-smoke:12345": "0c434fba5928e068c90f832489190b66cf1b9cf4dc07c121c2805c0b83e25b9a",
    "tcp-smoke:1": "401b7f4dbbba35981d80ae64bb610812c2839d2157aae1227c622da4b8302387",
    "tcp-smoke:7": "0a8c417754f0bc6c251cabdd219e4d0cb118de0b5dc97017eebc921e962317f9",
    "tcp-smoke:12345": "cbaab7d6eb6ad35e860311c01c03039369292652e1e3676cb455b9ad6b3d5487",
    "tls-smoke:1": "eb509125148b2f8bba0ac2c6f0837ecd48bd983492b3b75ab99a205eaa2935cd",
    "tls-smoke:7": "615b388bf5598e80fa595bac529e2c929d147d49577eefee86563f3af835be2b",
    "tls-smoke:12345": "de34529af862b688c2e5d47feb58744462a2df8fb6346524741c9b1b7bf264c4",
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
    "dhcpv4-discover-offer": "985137b44da37485f0b21ddfe62ba6a6611198d08d338bc23085c9411c277428",
    "dhcpv4-request-ack": "b31315456cbbbe71e04453943bcdcf711756077a050b2216f4f48ebbb85e76c3",
    "dhcpv4-client-identifier": "4fedfe93c4fd420b15709b7edebc5132c8005ddc418268f2d221016eb56cabb4",
    "dhcpv4-hostname": "92ee8bdd3d83d670f072062efdd777538e04f51df57ac962839c98d53b7b4d4e",
    "dhcpv4-parameter-request-list": "0ba8618741d9d95f1cfa7a2098a1081b033867aff88f947d31eb3057a4b86dde",
    "dhcpv4-lease-time": "8cf5bca1b2b5b25d0c1cb517fc8c34eea9606c216382a758bf8b7c2bfa1f4fa6",
    "dhcpv4-renewal-unicast-ack": "0385c82172c8feca26aaaa6a59f4a3b2e112bf5a81a043bcc847a27d428dcb5a",
    "dhcpv4-inform-ack": "f1b72f5b45d917b443c02eeb65e7abb2e5ce71d9c1a9acd7f0fe3a04800b1fda",
    "dhcpv4-request-nak": "bc8004218bb231b8ae591bd218b60780a24ff429d4abbf12760ec4d2f2814ed0",
    "dhcpv4-rapid-repeat": "994810fc8e20a053044c3eead71937c19443e9d3eb0600f9e6e4e294519fbb07",
    "dhcpv6-information-request-reply": "7127f06f8225ecec81ba59c9a828bcb0b83cf50daaed663d431f859da1f32de1",
    "dhcpv6-solicit-advertise": "f94655c506ba1c2de42d0c11f23c346b25625ace40909160dbb6fbcd0d0ef1e3",
    "dhcpv6-request-reply-ia-na": "e9020d1b2baf428f595462a46ec1adf30ad7f5c96e730e0cc868b141be1be5d6",
    "dhcpv6-prefix-delegation": "e191a488f6f8cdaab799820d9ca05b78d439e76cea231db26955690918f19506",
    "dhcpv6-rapid-commit": "6f1ddf1d1e9f3a06d9efc9df57da67f4df305b51054ecfec4cca113e798b48e4",
    "dhcpv6-relay-forward-reply": "6ded5f8e8a60d38d7b5c3aad816c66f4eba92a4d2910b7017f05ffc88f6492d6",
    "dhcpv6-reconfigure-observation": "045c613307bb8673c93cbe048c2d40eb389091e4de251fe8f78dc9ee283e53b6",
    "dhcpv6-leasequery-plan": "edf718a8d859785010fe2b4908e14f40de1a01490230a5565fa1abc905b03e00",
    "dhcpv6-bulk-leasequery-plan": "e23fd2a8f4c5f0efd7dd423dc831b8614588bcb4f535eb44ae906617766e1888",
    "dhcpv6-active-leasequery-plan": "bee077f1e8d909054c9c1889ec7e14a6c6e030242e1f00fcaa9dca6c6fb17279",
    "dhcpv6-unknown-option-preservation": "7d3929788dbf8c985dc97193fa906f8da3d2c1a44a536e922b83e92574479255",
    "dhcpv6-repeated-transaction-id": "079c004d55ec64e3dab219869f2b4dbd9785e4b43f8770399a4d7061d43f0890",
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
    "sctp-native-data-exchange": "547eb0653caf2aaad44cc4e3e9eebd39c312746bd89daa75c296705d0a03117a",
    "sctp-init-handshake-plan": "01e773fd01d64ba23744e4ac06904a1ead17582d6150b6926e5b3be98f70ab73",
    "sctp-udp-encap-data-exchange": "8399eaba00403307c34edd8e637c731b51cf1b3cc8b017195b4136c8372c65fb",
    "sctp-abort-error-observation": "ff0f7db2c9c7818570361d0b4f75c98a300e50d19a34522dc97b064deb11728f",
    "ssdp-ipv4-search-exchange": "f03f241b9e271517cfe515c31bec1cd82a5bc5059242a6b7c09d92838f4bba6e",
    "ssdp-ipv6-search-exchange": "8f5e05bbb8ed8d4a8e2c3ef9ca5c3ed51127b51fe38fa5bd372cce9bf6b0cd02",
    "ssdp-notify-capture": "6fff5bf7c853ebbcb93f530177be329995113b5197b8f951ffeb082bb1b0a3f2",
    "ssdp-raw-fallback": "7f1baec55d9c23bec61fee38b9067f5e4cd140c7a8c355fc58db835052ea3239",
    "ssdp-malformed-observation": "376320c3699bf020a87ad9844e05986b2ecb67a72acee0ead6ce98352b72fa24",
    "ntp-client-server-exchange": "1957ecd34419f106da476be470c0f9753510696900f181e06a584766e5f3b985",
    "ntp-kod-response": "1f5c5534106e1f79f47aa2e488f1aa069eb0ffb82b7029fba2c1a8614b7a1643",
    "ntp-extension-preservation": "137efdef30d3f471472e3cce97752162db249a69a0d14b561647f308900a4d7c",
    "ntp-nts-extension-plan": "95226770083b4c90b6d150b872cc96637be439b2900dafb57e4de28acda07fc6",
    "ntp-malformed-observation": "8170798760296f666ef2be53abf5f8d84938463bf5e4dabff2bb596022e037c9",
    "igmp-membership-query-observation": "ea704a25f05be3e1379b71b710389e637283e071b34d4c6989ec9827d52560c5",
    "igmp-v2-membership-report-emission": "51a1985a38e255360c8a301739be58eff5259b120594aef010f9ecadd389d23b",
    "igmp-v2-leave-group-emission": "8810922568b05ad5d3c60bc6898ed2eec20a28613e6bf1fbc231d5a0124b8d48",
    "igmp-v3-source-list-report": "c52e1b71af3adc27f795c736f019ad15e60d7c3d186a8259e9f5e0277b86dd21",
    "esp-transport-echo": "c8066bb34835f40bccbdfd4f9be4625440b34e8a1af590bab1e0e8af100a2a92",
    "esp-tunnel-echo": "982ef30418b05851f42da88d28d167e3f3b2f692993afde04146219796c51296",
    "ah-transport-verify": "b9c42a15caea17c29f53759034586520f11873cdfe97125e64ebce1eac8973c5",
    "ikev2-sa-init": "0c375af8619b2b4564928107c310dad77b7c69227972e057b8c18f91bdbb391a",
    "mdns-ipv4-multicast-browse": "2288f5b615f1dc7af310e8ca0597f7cb3c69008c5492a99fe1df2707cf67cc6c",
    "mdns-ipv6-multicast-browse": "8f1fc07b1bdeb40c380a4c0bd797167eecd97c137c0b3de1f21ce9ca7ac0b0f6",
    "mdns-qu-unicast-response": "ed00a5bb166653cdb18e9a4154dcaa362d48a9dd81e579a061bb134d31326ccd",
    "mdns-service-resolve": "4ea391fa5bc3ca1300d7852341d0255e69b38c714e61847101f9e5674b8d6c7b",
    "mdns-announcement": "ce1c4bf0cf66963baa174eb708a4e23fbb9f4a698c1cf27502ef4157eb02920f",
    "mdns-goodbye": "2febab07b902221c23889915eff68de6540983049d045bec5385a3eb5121dcaa",
    "mdns-known-answer-suppression": "4c825528ef39d5586ce78197543e58fa902a707d9af368b63d025fcfd0c056df",
    "mdns-cache-flush-response": "39ff56a404ee5b8dc40326b534b3fd77735563c0482c64056016948f21699f28",
    "mdns-subtype-browse": "2a352cbf42de2ad2945dc3d4c8160862e1f0377cce6b1fc390bfead60a1851e0",
    "mdns-bonjour-txt": "f668089c566f1d91e8e75b9415b3fd518fe0790f7c47344917ea0ca0aa71116f",
    "quic-initial-udp-observation": "09c6faa4ebf0215d6eeb414316cf4d80cff11424a8c8af5eb2a494583ae507d5",
    "quic-version-negotiation-observation": "f3d7a5585baf7d6f21be30efc86f34e92dbb5ef301b61d4ffb2f690ef418b869",
    "quic-retry-observation": "478ef1f516deb35b264a2bcd11a60c19378dc9bee9e135f36127f8da0c65bcaa",
    "quic-stateless-reset-observation": "4b4b0816258c1141a218f16662adc8a8947785af6fc66b7d3549209d2d86e420",
    "quic-protected-flow-plan": "c70dcba163775324dfc429af4646af00920a2da410ab5b81392b1dead862fe2e",
    "tls-clienthello-observation": "b622d6e570830106f0cf0d2156c5f3d78a2ad024d67e80ba9167ec7b06b7092b",
    "tls-alert-observation": "8aef39240c6a3ffdc1bbe166022b79da97457671db62106f232ae2de37713a3d",
    "tls-application-data-capture": "bc23ea47eb3ae37ff1d9eab81c595257c7e4899928b46c44d516d57443bf17ed",
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
