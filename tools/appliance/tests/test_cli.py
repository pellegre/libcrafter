"""Smoke coverage for the appliance CLI scaffold."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from tools.appliance.engine import cli


class ApplianceCliTest(unittest.TestCase):
    def test_help_prints_usage_and_info_command(self) -> None:
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            with self.assertRaises(SystemExit) as raised:
                cli.main(["--help"])

        self.assertEqual(raised.exception.code, 0)
        output = stdout.getvalue()
        self.assertIn("usage: appliance", output)
        self.assertIn("info", output)

    def test_info_prints_deterministic_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "repo"
            root.mkdir()
            stdout = io.StringIO()

            with patch.dict(os.environ, {"LIBCRAFTER_REPO_ROOT": str(root)}):
                with redirect_stdout(stdout):
                    exit_code = cli.main(["info"])

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            json.loads(stdout.getvalue()),
            {
                "ok": True,
                "package": "appliance",
                "repo_root": str(root.resolve()),
            },
        )


if __name__ == "__main__":
    unittest.main()
