"""Skip-vs-failure policy coverage for the behavioral probe suite.

These tests pin the report metadata that keeps provider *skips* distinct from
real *failures*. A behavioral case that the provider can support but that builds
the wrong packet, returns an undecodable response, or fails validation must
surface as ``failed`` and be fixed in libcrafter or the probe infrastructure --
it is never relabeled as a skip. The metadata split asserted here
(``executed`` / ``passed`` / ``failed`` / ``skipped_by_capability`` /
``skipped_by_confirmation``) is what lets a reader tell those apart.

The full-suite assertions prove the documented provider policy: a Hetzner
dry-run skips every DHCP and ARP behavioral case for stable capability reasons
(it has no link-layer substrate), while a QEMU dry-run plans all forty.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.probe.engine import capabilities, cases, cli
from tools.probe.engine.model import ProbeRunRequest, ProbeSkip


def _dry_run_report_for(provider: str, *, seed: int = 9, count: int = 40):
    request = ProbeRunRequest(
        provider=provider,
        profile="behavior",
        seed=seed,
        count=count,
        case_names=[],
        dry_run=True,
    )
    selected = cli._profile_selected_cases(request.profile, request.case_names)
    planned = cli._planned_cases(selected, seed=request.seed, count=request.count)
    probe_plans = cli._probe_plans_for_cases(request, planned)
    with tempfile.TemporaryDirectory() as tmp:
        report_path = Path(tmp) / "report.json"
        return cli._dry_run_report(
            request=request,
            selected_cases=selected,
            planned_cases=planned,
            probe_plans=probe_plans,
            report_path=report_path,
        )


def _behavior_cases_by_protocol(protocol: str) -> set[str]:
    return {
        case.name
        for case in cases.profile_selected_cases("behavior", [])
        if case.metadata.get("protocol") == protocol
    }


class SkipClassificationTest(unittest.TestCase):
    def test_confirmation_reason_classified_as_confirmation_skip(self) -> None:
        self.assertEqual(
            capabilities.skip_class_for_reason(
                capabilities.SKIP_CONFIRMATION_REQUIRED
            ),
            "skipped_by_confirmation",
        )

    def test_capability_reasons_classified_as_capability_skip(self) -> None:
        for reason in (
            capabilities.SKIP_CAPABILITY_UNAVAILABLE,
            capabilities.SKIP_REQUIRES_LINK_LAYER,
            capabilities.SKIP_REQUIRES_BROADCAST,
            capabilities.SKIP_REQUIRES_PROVIDER_MAC,
            capabilities.SKIP_REQUIRES_PRIVILEGED_PORT,
            capabilities.SKIP_REQUIRES_CONTROLLED_SERVICE,
            capabilities.SKIP_REQUIRES_CONTROLLED_ROUTER,
        ):
            with self.subTest(reason=reason):
                self.assertEqual(
                    capabilities.skip_class_for_reason(reason),
                    "skipped_by_capability",
                )

    def test_skip_class_counts_partitions_every_skip(self) -> None:
        skips = [
            ProbeSkip(case="a", sequence=0, reason=capabilities.SKIP_REQUIRES_LINK_LAYER),
            ProbeSkip(
                case="b",
                sequence=1,
                reason=capabilities.SKIP_CAPABILITY_UNAVAILABLE,
            ),
            ProbeSkip(
                case="c",
                sequence=2,
                reason=capabilities.SKIP_CONFIRMATION_REQUIRED,
            ),
        ]
        counts = capabilities.skip_class_counts(skips)
        self.assertEqual(counts["skipped_by_capability"], 2)
        self.assertEqual(counts["skipped_by_confirmation"], 1)
        # Every skip must land in exactly one bucket.
        self.assertEqual(
            counts["skipped_by_capability"] + counts["skipped_by_confirmation"],
            len(skips),
        )

    def test_empty_skip_list_has_zero_counts(self) -> None:
        counts = capabilities.skip_class_counts([])
        self.assertEqual(
            counts,
            {"skipped_by_capability": 0, "skipped_by_confirmation": 0},
        )

    def test_cli_reexports_skip_class_counts(self) -> None:
        self.assertIs(cli._skip_class_counts, capabilities.skip_class_counts)


class DryRunSkipMetadataTest(unittest.TestCase):
    def test_report_metadata_separates_outcome_classes(self) -> None:
        report = _dry_run_report_for("qemu")
        metadata = report.metadata
        for key in (
            "executed",
            "passed",
            "failed",
            "skipped_by_capability",
            "skipped_by_confirmation",
        ):
            self.assertIn(key, metadata, f"metadata missing {key!r}")

    def test_skip_class_counts_reconcile_with_skip_total(self) -> None:
        for provider in ("hetzner", "qemu"):
            with self.subTest(provider=provider):
                metadata = _dry_run_report_for(provider).metadata
                self.assertEqual(
                    metadata["skipped_by_capability"]
                    + metadata["skipped_by_confirmation"],
                    metadata["skipped_count"],
                )

    def test_dry_run_executes_nothing(self) -> None:
        # A dry run plans cases but never sends, so there are no real outcomes
        # to confuse with skips.
        metadata = _dry_run_report_for("qemu").metadata
        self.assertEqual(metadata["executed"], 0)
        self.assertEqual(metadata["passed"], 0)
        self.assertEqual(metadata["failed"], 0)


class HetznerSkipsQemuPlansTest(unittest.TestCase):
    def test_hetzner_skips_dhcp_and_arp_for_capability_reasons(self) -> None:
        report = _dry_run_report_for("hetzner")
        skipped = {skip.case for skip in report.skips}
        dhcp = _behavior_cases_by_protocol("dhcp")
        arp = _behavior_cases_by_protocol("arp")
        self.assertTrue(dhcp, "behavior suite defines DHCP cases")
        self.assertTrue(arp, "behavior suite defines ARP cases")
        # Every DHCP and ARP behavioral case skips on the L3-only provider.
        self.assertTrue(dhcp <= skipped)
        self.assertTrue(arp <= skipped)
        # The skips are capability skips with stable reasons, not failures and
        # not confirmation skips.
        self.assertEqual(report.metadata["failed"], 0)
        self.assertEqual(report.metadata["skipped_by_confirmation"], 0)
        self.assertEqual(report.metadata["skipped_by_capability"], len(dhcp) + len(arp))
        for skip in report.skips:
            with self.subTest(case=skip.case):
                self.assertEqual(
                    capabilities.skip_class_for_reason(skip.reason),
                    "skipped_by_capability",
                )

    def test_hetzner_still_plans_dns_and_udp_cases(self) -> None:
        report = _dry_run_report_for("hetzner")
        skipped = {skip.case for skip in report.skips}
        dns = _behavior_cases_by_protocol("dns")
        udp = _behavior_cases_by_protocol("udp")
        # DNS and UDP unicast cases are supported on Hetzner; none of them skip.
        self.assertTrue(dns.isdisjoint(skipped))
        self.assertTrue(udp.isdisjoint(skipped))

    def test_qemu_plans_every_behavioral_case(self) -> None:
        report = _dry_run_report_for("qemu")
        self.assertEqual(report.metadata["planned_count"], 40)
        self.assertEqual(report.metadata["skipped_count"], 0)
        self.assertEqual(report.metadata["skipped_by_capability"], 0)
        self.assertEqual(report.metadata["skipped_by_confirmation"], 0)
        self.assertEqual(report.skips, [])
        # The DHCP and ARP cases Hetzner skips are planned on QEMU.
        planned = {case.name for case in report.cases}
        self.assertTrue(_behavior_cases_by_protocol("dhcp") <= planned)
        self.assertTrue(_behavior_cases_by_protocol("arp") <= planned)


if __name__ == "__main__":
    unittest.main()
