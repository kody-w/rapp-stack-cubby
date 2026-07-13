from __future__ import annotations

import json
import unittest

from rapp_stack_cubby.dependencies import validate_dependency_inputs

from ._support import REPOSITORY_ROOT


class DependencyLockTests(unittest.TestCase):
    def test_exact_target_dependency_license_hash_and_sbom_inputs(self):
        result = validate_dependency_inputs(REPOSITORY_ROOT)
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(result.package_count, 3)
        lock = json.loads(
            (REPOSITORY_ROOT / "DEPENDENCY_LOCK.json").read_text()
        )
        cryptography = next(
            item
            for item in lock["packages"]
            if item["name"] == "cryptography"
        )
        self.assertEqual(cryptography["version"], "49.0.0")
        self.assertIn("macosx_11_0_arm64", cryptography["wheel"]["filename"])
        self.assertEqual(len(cryptography["wheel"]["sha256"]), 64)
        self.assertEqual(
            cryptography["license_expression"],
            "Apache-2.0 OR BSD-3-Clause",
        )


if __name__ == "__main__":
    unittest.main()
