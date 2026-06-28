"""Coverage for the appliance image context and base runtime defaults."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


APPLIANCE_ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = APPLIANCE_ROOT / "Dockerfile"
ENTRYPOINT = APPLIANCE_ROOT / "image" / "entrypoint.sh"


class ApplianceImageContextTest(unittest.TestCase):
    def test_dockerfile_and_entrypoint_exist(self) -> None:
        self.assertTrue(DOCKERFILE.is_file())
        self.assertTrue(ENTRYPOINT.is_file())

    def test_dockerfile_references_entrypoint(self) -> None:
        dockerfile = DOCKERFILE.read_text(encoding="utf-8")

        self.assertIn(
            "COPY image/entrypoint.sh /usr/local/bin/libcrafter-appliance-entrypoint",
            dockerfile,
        )
        self.assertIn(
            'ENTRYPOINT ["/usr/local/bin/libcrafter-appliance-entrypoint"]',
            dockerfile,
        )

    def test_base_image_includes_expected_userland(self) -> None:
        dockerfile = DOCKERFILE.read_text(encoding="utf-8")

        for package in (
            "build-essential",
            "clang",
            "iproute2",
            "iputils-ping",
            "iw",
            "libpcap-dev",
            "pkg-config",
            "python3",
            "python3-pip",
            "tcpdump",
        ):
            with self.subTest(package=package):
                self.assertRegex(dockerfile, rf"\b{re.escape(package)}\b")

    def test_entrypoint_runs_commands_from_workdir(self) -> None:
        entrypoint = ENTRYPOINT.read_text(encoding="utf-8")

        self.assertIn('workdir="${LIBCRAFTER_APPLIANCE_WORKDIR:-/work}"', entrypoint)
        self.assertIn('cd "${workdir}"', entrypoint)
        self.assertIn('exec "$@"', entrypoint)

    def test_docker_socket_is_not_required_by_image_defaults(self) -> None:
        defaults = self._image_defaults_text().lower()

        self.assertNotIn("docker.sock", defaults)
        self.assertNotIn("/var/run/docker", defaults)
        self.assertNotIn("docker socket", defaults)

    def test_privileged_mode_is_not_a_tracked_default(self) -> None:
        defaults = self._image_defaults_text().lower()

        self.assertNotIn("--privileged", defaults)
        self.assertNotIn("privileged: true", defaults)

    def _image_defaults_text(self) -> str:
        return "\n".join(
            path.read_text(encoding="utf-8") for path in (DOCKERFILE, ENTRYPOINT)
        )


if __name__ == "__main__":
    unittest.main()
