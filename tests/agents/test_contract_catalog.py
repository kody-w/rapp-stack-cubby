from __future__ import annotations

import ast
import json
import tempfile
import unittest
from pathlib import Path

from rapp_stack_cubby.catalog import (
    AGENTS_RELATIVE,
    CatalogValidationError,
    build_agent_catalog,
    build_implementation_matrix,
    inspect_agent_source,
    validate_catalogs,
)
from rapp_stack_cubby.agents.source_scan import scan_agent_sources
from rapp_stack_cubby.constants import (
    EXPECTED_ACTUAL_AGENT_COUNT,
    EXPECTED_CAPABILITY_COUNT,
    EXPECTED_SELECTED_CAPABILITY_COUNT,
)

from ._support import AGENTS_DIRECTORY, AgentEnvironment, REPOSITORY_ROOT


class AgentContractCatalogTests(unittest.TestCase):
    def test_every_agent_satisfies_ast_and_source_contract(self) -> None:
        paths = sorted(AGENTS_DIRECTORY.glob("*_agent.py"))
        self.assertEqual(len(paths), EXPECTED_ACTUAL_AGENT_COUNT)

        for path in paths:
            with self.subTest(path=path.name):
                inspected = inspect_agent_source(path)
                manifest = inspected["manifest"]
                self.assertEqual(manifest["schema"], "rapp-agent/1.0")
                self.assertEqual(
                    inspected["metadata"]["parameters"]["properties"]["action"][
                        "enum"
                    ],
                    manifest["actions"],
                )
                tree = ast.parse(path.read_text(encoding="utf-8"))
                classes = [
                    node for node in tree.body if isinstance(node, ast.ClassDef)
                ]
                self.assertEqual(len(classes), 1)
                perform = next(
                    node
                    for node in classes[0].body
                    if isinstance(node, ast.FunctionDef)
                    and node.name == "perform"
                )
                self.assertIsNotNone(perform.args.kwarg)

    def test_source_contract_rejects_every_non_exact_perform_shape(self) -> None:
        source = '''\
"""Synthetic strict source."""

from basic_agent import BasicAgent

__manifest__ = {
    "schema": "rapp-agent/1.0",
    "name": "Exact",
    "version": "1.0.0",
    "description": "Exercise the exact perform ABI.",
    "actions": ["run"],
    "capability_ids": [],
    "mutability": "read_only",
    "enabled_by_default": False,
    "provenance": "generated_local",
    "dependencies": ["python-stdlib", "BasicAgent"],
}

class Exact(BasicAgent):
    name = "Exact"
    metadata = {
        "name": "Exact",
        "description": "Exercise the exact perform ABI.",
        "parameters": {
            "type": "object",
            "properties": {"action": {"type": "string", "enum": ["run"]}},
            "required": ["action"],
            "additionalProperties": False,
        },
    }

    def perform(self: object, **kwargs: object) -> str:
        return str(kwargs)
'''
        variants = {
            "async": "async def perform(self, **kwargs)",
            "positional_only": "def perform(self, /, **kwargs)",
            "required_arg": "def perform(self, value, **kwargs)",
            "required_keyword": "def perform(self, *, value, **kwargs)",
            "optional_arg": "def perform(self, value=None, **kwargs)",
            "decorated": "@staticmethod\n    def perform(self, **kwargs)",
        }
        valid_definition = (
            "def perform(self: object, **kwargs: object) -> str"
        )
        with tempfile.TemporaryDirectory(
            prefix=".test-agent-abi-", dir=REPOSITORY_ROOT
        ) as temporary:
            path = Path(temporary) / "exact_agent.py"
            path.write_text(source, encoding="utf-8")
            inspected = inspect_agent_source(path)
            self.assertEqual(inspected["tool_name"], "Exact")
            for label, definition in variants.items():
                with self.subTest(label=label):
                    path.write_text(
                        source.replace(valid_definition, definition),
                        encoding="utf-8",
                    )
                    with self.assertRaises(CatalogValidationError):
                        inspect_agent_source(path)

    def test_catalog_is_deterministic_and_hashes_are_current(self) -> None:
        expected = build_agent_catalog(REPOSITORY_ROOT)
        path = (
            REPOSITORY_ROOT
            / "cubbies/kody-w/rapplications/rapp-stack/twin/catalog/"
            "agent-catalog.json"
        )
        actual = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(actual, expected)
        self.assertEqual(
            actual["agent_abi"],
            {
                "decorated": False,
                "signature": "def perform(self, **kwargs)",
                "synchronous": True,
            },
        )
        self.assertEqual(actual["agent_count"], EXPECTED_ACTUAL_AGENT_COUNT)
        self.assertEqual(
            [item["path"] for item in actual["agents"]],
            sorted(item["path"] for item in actual["agents"]),
        )
        self.assertTrue(
            all(
                item["path"].startswith(AGENTS_RELATIVE.as_posix() + "/")
                for item in actual["agents"]
            )
        )

    def test_implementation_matrix_covers_every_capability_truthfully(self) -> None:
        catalog = build_agent_catalog(REPOSITORY_ROOT)
        expected = build_implementation_matrix(REPOSITORY_ROOT, catalog)
        path = (
            REPOSITORY_ROOT
            / "cubbies/kody-w/rapplications/rapp-stack/twin/catalog/"
            "implementation-matrix.json"
        )
        actual = json.loads(path.read_text(encoding="utf-8"))
        counts = actual["aggregates"]

        self.assertEqual(actual, expected)
        self.assertEqual(counts["capability_count"], EXPECTED_CAPABILITY_COUNT)
        self.assertEqual(
            counts["selected_count"], EXPECTED_SELECTED_CAPABILITY_COUNT
        )
        self.assertEqual(counts["selected_unmapped_count"], 0)
        self.assertEqual(sum(counts["counts_by_implementation_state"].values()), 113)
        future = {
            record["owner"]["name"]
            for record in actual["capabilities"]
            if record["implementation_state"] == "future_owned"
        }
        self.assertLessEqual(future, set(actual["future_task_ids"]))
        self.assertFalse(validate_catalogs(REPOSITORY_ROOT))

        replay = next(
            item
            for item in actual["capabilities"]
            if item["capability_id"] == "chat.replay-idempotency"
        )
        self.assertEqual(replay["owner"]["kind"], "runtime")
        twin = next(
            item
            for item in catalog["agents"]
            if item["tool_name"] == "TwinChat"
        )
        self.assertEqual(twin["capability_ids"], [])
        self.assertEqual(twin["mutability"], "read_only")

    def test_reverse_agent_capability_ownership_is_enforced(self) -> None:
        catalog = build_agent_catalog(REPOSITORY_ROOT)
        twin = next(
            item
            for item in catalog["agents"]
            if item["tool_name"] == "TwinChat"
        )
        twin["capability_ids"].append("chat.replay-idempotency")
        with self.assertRaises(CatalogValidationError):
            build_implementation_matrix(REPOSITORY_ROOT, catalog)

    def test_real_registry_loads_all_agents_in_deterministic_order(self) -> None:
        with AgentEnvironment() as environment:
            snapshot = environment.snapshot
            assert snapshot is not None
            self.assertEqual(len(snapshot), EXPECTED_ACTUAL_AGENT_COUNT)
            self.assertEqual(snapshot.names, tuple(sorted(snapshot.names)))
            self.assertEqual(len(set(snapshot.names)), len(snapshot.names))
            self.assertTrue(snapshot.load_report.ok)

    def test_agent_source_privacy_and_execution_scan_passes(self) -> None:
        result = scan_agent_sources(REPOSITORY_ROOT)

        self.assertTrue(result.ok, result.findings)
        self.assertEqual(result.scanned_file_count, EXPECTED_ACTUAL_AGENT_COUNT)


if __name__ == "__main__":
    unittest.main()
