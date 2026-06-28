"""Coverage for appliance image metadata helpers."""

from __future__ import annotations

import json
import unittest

from tools.appliance.engine import image


class ApplianceImageMetadataTest(unittest.TestCase):
    def test_default_tag(self) -> None:
        self.assertEqual(
            image.requested_appliance_image({}),
            "libcrafter/appliance:local",
        )
        self.assertEqual(
            image.appliance_image_metadata(env={})["tag"],
            "libcrafter/appliance:local",
        )
        self.assertTrue(image.appliance_image_metadata(env={})["uses_default"])

    def test_environment_override(self) -> None:
        env = {image.LIBCRAFTER_APPLIANCE_IMAGE: "registry.example/appliance:test"}

        self.assertEqual(
            image.requested_appliance_image(env),
            "registry.example/appliance:test",
        )
        metadata = image.appliance_image_metadata(env=env)
        self.assertEqual(metadata["tag"], "registry.example/appliance:test")
        self.assertFalse(metadata["uses_default"])

    def test_digest_is_stable_and_covers_expected_files(self) -> None:
        first = image.appliance_image_context_digest()
        second = image.appliance_image_context_digest()

        self.assertEqual(first, second)
        self.assertEqual(len(first), 64)
        int(first, 16)
        self.assertEqual(
            image.appliance_image_metadata(env={})["context_files"],
            ["Dockerfile", "image/entrypoint.sh"],
        )

    def test_inspect_and_build_argv(self) -> None:
        tag = "registry.example/appliance:test"
        digest = image.appliance_image_context_digest()

        self.assertEqual(
            image.appliance_image_inspect_argv(tag, docker_command="podman"),
            ["podman", "image", "inspect", tag],
        )
        self.assertEqual(
            image.appliance_image_build_argv(tag, docker_command="podman"),
            [
                "podman",
                "build",
                "-t",
                tag,
                "--label",
                f"{image.APPLIANCE_IMAGE_CONTEXT_LABEL}={digest}",
                "-f",
                str(image.appliance_image_dockerfile_path()),
                str(image.appliance_image_context_dir()),
            ],
        )

    def test_metadata_json_shape(self) -> None:
        env = {image.LIBCRAFTER_APPLIANCE_IMAGE: "example/appliance:ci"}
        metadata = image.appliance_image_metadata(env=env, docker_command="podman")

        self.assertEqual(
            set(metadata),
            {
                "build_argv",
                "context_digest",
                "context_dir",
                "context_files",
                "context_label",
                "default",
                "dockerfile_path",
                "env",
                "inspect_argv",
                "tag",
                "uses_default",
            },
        )
        self.assertEqual(metadata["env"], image.LIBCRAFTER_APPLIANCE_IMAGE)
        self.assertEqual(metadata["default"], image.DEFAULT_APPLIANCE_IMAGE)
        self.assertEqual(metadata["context_label"], image.APPLIANCE_IMAGE_CONTEXT_LABEL)
        self.assertEqual(metadata["inspect_argv"][0], "podman")
        self.assertEqual(metadata["build_argv"][0], "podman")
        self.assertEqual(json.loads(json.dumps(metadata, sort_keys=True)), metadata)


if __name__ == "__main__":
    unittest.main()
