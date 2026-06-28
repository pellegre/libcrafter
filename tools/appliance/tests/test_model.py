"""Coverage for appliance JSON model helpers."""

from __future__ import annotations

import math
import tempfile
import unittest
from pathlib import Path

from tools.appliance.engine import model


class ApplianceModelTest(unittest.TestCase):
    def test_dumps_json_orders_keys_deterministically(self) -> None:
        self.assertEqual(
            model.dumps_json({"zeta": 1, "alpha": {"delta": 4, "beta": 2}}),
            (
                "{\n"
                '  "alpha": {\n'
                '    "beta": 2,\n'
                '    "delta": 4\n'
                "  },\n"
                '  "zeta": 1\n'
                "}\n"
            ),
        )

    def test_rejects_non_string_object_keys(self) -> None:
        with self.assertRaisesRegex(TypeError, "JSON object keys must be strings"):
            model.dumps_json({1: "bad"})

        with self.assertRaisesRegex(ValueError, "metadata keys must be strings"):
            model.json_object({1: "bad"}, "metadata")

    def test_rejects_non_finite_floats(self) -> None:
        for value in (math.nan, math.inf, -math.inf):
            with self.subTest(value=value):
                with self.assertRaisesRegex(TypeError, "non-finite float"):
                    model.dumps_json({"value": value})

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "bad.json"
            path.write_text('{"value": NaN}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "non-finite float"):
                model.read_json(path)

    def test_absolute_path_validation(self) -> None:
        self.assertEqual(model.absolute_path("/tmp/appliance.json", "path"), "/tmp/appliance.json")
        self.assertEqual(model.optional_absolute_path(None, "path"), None)
        self.assertEqual(
            model.optional_absolute_path(Path("/tmp/appliance.json"), "path"),
            "/tmp/appliance.json",
        )

        with self.assertRaisesRegex(ValueError, "path must be an absolute path"):
            model.absolute_path("relative/appliance.json", "path")

        with self.assertRaisesRegex(ValueError, "path must be an absolute path"):
            model.optional_absolute_path("relative/appliance.json", "path")


if __name__ == "__main__":
    unittest.main()
