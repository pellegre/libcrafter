"""VirtualBox appliance group helper coverage."""

from __future__ import annotations

import unittest

from tools.endpoint.engine.providers.virtualbox.constants import (
    VBOX_DEFAULT_APPLIANCE_GROUP,
)
from tools.endpoint.engine.providers.virtualbox.groups import (
    default_group_metadata,
    modifyvm_groups_command,
    normalize_group_path,
    normalize_group_paths,
    parse_showvminfo_groups,
    showvminfo_has_group,
)


class VirtualBoxGroupHelpersTest(unittest.TestCase):
    def test_default_group_value_and_metadata(self) -> None:
        self.assertEqual(VBOX_DEFAULT_APPLIANCE_GROUP, "/libcrafter/appliances")
        self.assertEqual(default_group_metadata(), ["/libcrafter/appliances"])
        self.assertEqual(normalize_group_paths(), ("/libcrafter/appliances",))

    def test_valid_group_paths_are_normalized_for_metadata(self) -> None:
        self.assertEqual(
            normalize_group_path("/libcrafter/appliances"),
            "/libcrafter/appliances",
        )
        self.assertEqual(
            normalize_group_paths(("/libcrafter/appliances", "/libcrafter/fixtures")),
            ("/libcrafter/appliances", "/libcrafter/fixtures"),
        )

    def test_invalid_group_paths_are_rejected(self) -> None:
        invalid_values = (
            "",
            "libcrafter/appliances",
            "/",
            "/libcrafter/",
            "/libcrafter//appliances",
            " /libcrafter/appliances",
            "/libcrafter/appliances ",
        )
        for value in invalid_values:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    normalize_group_path(value)

    def test_modifyvm_group_command_shape(self) -> None:
        self.assertEqual(
            modifyvm_groups_command("wire-virtualbox-lan-test"),
            [
                "VBoxManage",
                "modifyvm",
                "wire-virtualbox-lan-test",
                "--groups",
                "/libcrafter/appliances",
            ],
        )
        self.assertEqual(
            modifyvm_groups_command(
                "wire-virtualbox-lan-test",
                ("/libcrafter/appliances", "/libcrafter/fixtures"),
            ),
            [
                "VBoxManage",
                "modifyvm",
                "wire-virtualbox-lan-test",
                "--groups",
                "/libcrafter/appliances,/libcrafter/fixtures",
            ],
        )

    def test_showvminfo_group_parsing_missing_group_line(self) -> None:
        stdout = 'name="wire-virtualbox-lan-test"\nVMState="running"\n'

        self.assertEqual(parse_showvminfo_groups(stdout), ())
        self.assertFalse(showvminfo_has_group(stdout))

    def test_showvminfo_group_parsing_single_group(self) -> None:
        stdout = 'name="wire-virtualbox-lan-test"\ngroups="/libcrafter/appliances"\n'

        self.assertEqual(parse_showvminfo_groups(stdout), ("/libcrafter/appliances",))
        self.assertTrue(showvminfo_has_group(stdout))

    def test_showvminfo_group_parsing_multi_group(self) -> None:
        stdout = (
            'name="wire-virtualbox-lan-test"\n'
            'groups="/manual,/libcrafter/appliances,/libcrafter/fixtures"\n'
        )

        self.assertEqual(
            parse_showvminfo_groups(stdout),
            ("/manual", "/libcrafter/appliances", "/libcrafter/fixtures"),
        )
        self.assertTrue(showvminfo_has_group(stdout))
        self.assertFalse(showvminfo_has_group(stdout, "/libcrafter/missing"))


if __name__ == "__main__":
    unittest.main()
