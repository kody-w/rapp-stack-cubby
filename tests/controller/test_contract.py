from __future__ import annotations

import ast
import json
import unittest
from pathlib import Path

from rapp_stack_cubby.catalog import (
    CONTROLLER_AGENT_RELATIVE,
    build_controller_catalog,
    inspect_controller_source,
)

from ._support import ControllerEnvironment, REPOSITORY_ROOT, decoded


class ControllerContractTests(unittest.TestCase):
    def test_one_native_single_file_controller_is_the_only_top_level_agent(self):
        directory = REPOSITORY_ROOT / CONTROLLER_AGENT_RELATIVE.parent
        paths = sorted(directory.glob("*_agent.py"))

        self.assertEqual(paths, [REPOSITORY_ROOT / CONTROLLER_AGENT_RELATIVE])
        source = paths[0].read_text(encoding="utf-8")
        tree = ast.parse(source)
        classes = [node for node in tree.body if isinstance(node, ast.ClassDef)]
        self.assertEqual(len(classes), 1)
        self.assertEqual(
            [ast.unparse(base) for base in classes[0].bases],
            ["BasicAgent"],
        )
        self.assertIsNotNone(ast.get_docstring(tree))
        inspected = inspect_controller_source(paths[0])
        self.assertEqual(
            inspected["manifest"]["name"], "RappStackCubbyController"
        )

    def test_controller_catalog_matches_source_and_complete_action_set(self):
        catalog = build_controller_catalog(REPOSITORY_ROOT)
        frozen = json.loads(
            (
                REPOSITORY_ROOT
                / "cubbies/kody-w/catalog/controller-catalog.json"
            ).read_text(encoding="utf-8")
        )

        self.assertEqual(catalog, frozen)
        self.assertEqual(
            catalog["actions"],
            [
                "inspect",
                "verify",
                "adopt_install",
                "hatch_repo",
                "list",
                "status",
                "start",
                "stop",
                "archive",
                "unarchive",
                "purge",
                "rotate_keys",
                "chat",
                "self_test",
                "pack",
                "export",
            ],
        )

    def test_every_action_returns_json_and_pending_artifacts_are_truthful(self):
        with ControllerEnvironment(mutations=False) as environment:
            for action in build_controller_catalog(REPOSITORY_ROOT)["actions"]:
                with self.subTest(action=action):
                    result = decoded(environment.agent, action=action)
                    self.assertEqual(result["action"], action)
                    self.assertIsInstance(result["ok"], bool)
            for action in ("pack", "export"):
                result = decoded(environment.agent, action=action)
                self.assertEqual(result["status"], "pending")
                self.assertFalse(result["implemented"])
                self.assertFalse(result["artifact_created"])

    def test_read_only_inspection_works_without_home_or_controller_root(self):
        with ControllerEnvironment(mutations=False) as environment:
            with unittest.mock.patch.dict(
                "os.environ",
                {
                    "HOME": "",
                    "RAPP_STACK_CONTROLLER_DATA_DIR": "",
                },
                clear=False,
            ):
                inspect_result = decoded(environment.agent, action="inspect")
                list_result = decoded(environment.agent, action="list")

        self.assertTrue(inspect_result["ok"])
        self.assertFalse(inspect_result["controller_data_configured"])
        self.assertEqual(list_result["twins"], [])


if __name__ == "__main__":
    unittest.main()
