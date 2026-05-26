"""Coverage for provider command execution helpers."""

from __future__ import annotations

import sys
import unittest

from tools.wire.engine.process import run_command


class RunCommandTest(unittest.TestCase):
    def test_allows_empty_non_command_arguments(self) -> None:
        result = run_command(
            [
                sys.executable,
                "-c",
                "import sys; print(sys.argv[1] == '')",
                "",
            ]
        )

        self.assertTrue(result.ok)
        self.assertEqual(result.stdout.strip(), "True")

    def test_rejects_empty_command_argument(self) -> None:
        with self.assertRaisesRegex(ValueError, "command"):
            run_command([""])


if __name__ == "__main__":
    unittest.main()
