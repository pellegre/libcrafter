"""Coverage for appliance image CLI commands."""

from __future__ import annotations

import io
import json
import os
import unittest
from collections.abc import Sequence
from contextlib import redirect_stdout
from unittest.mock import patch

from tools.appliance.engine import cli, image


class RecordingRunner:
    def __init__(self, returncode: int = 0) -> None:
        self.returncode = returncode
        self.calls: list[list[str]] = []

    def __call__(self, argv: Sequence[str]) -> int:
        self.calls.append(list(argv))
        return self.returncode


class ApplianceImageCliTest(unittest.TestCase):
    def test_image_plan_json_prints_metadata_without_running_docker(self) -> None:
        runner = RecordingRunner()
        stdout = io.StringIO()

        with patch.dict(os.environ, {}, clear=True):
            with redirect_stdout(stdout):
                exit_code = cli.main(["image", "plan", "--json"], command_runner=runner)

        self.assertEqual(exit_code, 0)
        self.assertEqual(runner.calls, [])
        payload = json.loads(stdout.getvalue())
        self.assertEqual(
            payload,
            {
                "image_tag": image.DEFAULT_APPLIANCE_IMAGE,
                "context_digest": image.appliance_image_context_digest(),
                "dockerfile_path": str(image.appliance_image_dockerfile_path()),
                "context_path": str(image.appliance_image_context_dir()),
                "inspect_argv": image.appliance_image_inspect_argv(
                    image.DEFAULT_APPLIANCE_IMAGE
                ),
                "build_argv": image.appliance_image_build_argv(
                    image.DEFAULT_APPLIANCE_IMAGE
                ),
            },
        )

    def test_image_inspect_runs_docker_inspect_argv(self) -> None:
        runner = RecordingRunner(returncode=7)

        with patch.dict(os.environ, {}, clear=True):
            exit_code = cli.main(["image", "inspect"], command_runner=runner)

        self.assertEqual(exit_code, 7)
        self.assertEqual(
            runner.calls,
            [image.appliance_image_inspect_argv(image.DEFAULT_APPLIANCE_IMAGE)],
        )

    def test_image_build_runs_docker_build_argv(self) -> None:
        runner = RecordingRunner(returncode=11)

        with patch.dict(os.environ, {}, clear=True):
            exit_code = cli.main(["image", "build"], command_runner=runner)

        self.assertEqual(exit_code, 11)
        self.assertEqual(
            runner.calls,
            [image.appliance_image_build_argv(image.DEFAULT_APPLIANCE_IMAGE)],
        )


if __name__ == "__main__":
    unittest.main()
