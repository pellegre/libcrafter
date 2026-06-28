"""Plan-only coverage for endpoint smoke appliance paths."""

from __future__ import annotations

import contextlib
import io
import unittest

from tools.endpoint.smoke import (
    live_docker_lan_icmp,
    live_docker_private_packet_exchange,
    live_docker_wan_dns,
    live_virtualbox_network_ping,
)


class EndpointSmokePlanTest(unittest.TestCase):
    def test_docker_lan_plan_uses_endpoint_container_appliance(self) -> None:
        output = _plan_output(live_docker_lan_icmp)

        self.assertIn("appliance profile: lan-raw", output)
        self.assertIn("appliance substrate: docker-endpoint-container", output)
        self.assertIn("endpoint container is appliance: true", output)
        self.assertIn("nested Docker: false", output)
        self.assertIn("Docker execution supported: false", output)
        self.assertIn("endpoint-appliance-sync", output)
        self.assertIn("tools/endpoint/run exec", output)
        self.assertNotIn(" upload ", output)
        self.assertNotIn(" chmod ", output)

    def test_docker_wan_plan_uses_wan_profile_without_nested_docker(self) -> None:
        output = _plan_output(live_docker_wan_dns)

        self.assertIn("appliance profile: wan-raw", output)
        self.assertIn("appliance substrate: docker-endpoint-container", output)
        self.assertIn("nested Docker: false", output)
        self.assertIn("endpoint-appliance-sync", output)
        self.assertNotIn(" upload ", output)
        self.assertNotIn(" chmod ", output)

    def test_docker_private_plan_has_appliance_metadata_for_both_roles(self) -> None:
        output = _plan_output(live_docker_private_packet_exchange)

        self.assertIn("receiver appliance runtime:", output)
        self.assertIn("sender appliance runtime:", output)
        self.assertEqual(output.count("appliance profile: lan-raw"), 2)
        self.assertEqual(output.count("appliance substrate: docker-endpoint-container"), 2)
        self.assertIn("<receiver_endpoint_appliance_workspace>", output)
        self.assertIn("<sender_endpoint_appliance_workspace>", output)
        self.assertNotIn(" upload ", output)
        self.assertNotIn(" chmod ", output)

    def test_virtualbox_plan_uses_endpoint_appliance_run(self) -> None:
        output = _plan_output(live_virtualbox_network_ping)

        self.assertIn("appliance profile: lan-raw", output)
        self.assertIn("appliance substrate: ssh-docker-host", output)
        self.assertIn("nested Docker: false", output)
        self.assertIn("Docker execution supported: true", output)
        self.assertIn("tools/endpoint/run appliance deploy", output)
        self.assertIn("tools/endpoint/run appliance run", output)
        self.assertNotIn(" upload ", output)
        self.assertNotIn(" chmod ", output)


def _plan_output(module: object) -> str:
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        exit_code = module.main(["--plan-only"])  # type: ignore[attr-defined]
    if exit_code != 0:
        raise AssertionError(f"plan returned {exit_code}")
    return stdout.getvalue()


if __name__ == "__main__":
    unittest.main()
