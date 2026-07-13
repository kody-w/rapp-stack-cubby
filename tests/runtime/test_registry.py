from __future__ import annotations

import hashlib
import os
import subprocess
import unittest
from unittest.mock import patch

from rapp_stack_cubby.runtime.registry import (
    AgentRegistry,
    RegistryConfigurationError,
    RegistryLoadError,
)
from rapp_stack_cubby.runtime.storage import LocalStorage

from ._support import ECHO_AGENT, RuntimeFixture

STRICT_AGENT = '''\
"""Strict synthetic actual agent."""

import json

from basic_agent import BasicAgent

__manifest__ = {
    "schema": "rapp-agent/1.0",
    "name": "StrictEcho",
    "version": "1.0.0",
    "description": "Echo one bounded synthetic value.",
    "actions": ["run"],
    "capability_ids": [],
    "mutability": "read_only",
    "enabled_by_default": False,
    "provenance": "generated_local",
    "dependencies": ["python-stdlib", "BasicAgent"],
}

class StrictEcho(BasicAgent):
    name = "StrictEcho"
    metadata = {
        "name": "StrictEcho",
        "description": "Echo one bounded synthetic value.",
        "parameters": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["run"]},
            },
            "required": ["action"],
            "additionalProperties": False,
        },
    }

    def perform(self, **kwargs):
        return json.dumps({"ok": kwargs.get("action") == "run"})
'''


class RegistryTests(unittest.TestCase):
    def test_loads_valid_agent_with_structured_report(self) -> None:
        with RuntimeFixture() as fixture:
            fixture.write_agent("echo_agent.py", ECHO_AGENT)
            snapshot = self._registry(fixture).load()

            self.assertEqual(snapshot.names, ("echo",))
            self.assertEqual(snapshot["echo"].perform(text="yes"), "echo:yes")
            self.assertTrue(snapshot.load_report.ok)
            self.assertEqual(snapshot.load_report.loaded_agent_count, 1)
            self.assertTrue(snapshot.load_report.as_dict()["ok"])

    def test_all_three_audited_import_shims_work(self) -> None:
        sources = {
            "one_agent.py": ECHO_AGENT.replace(
                "from basic_agent", "from agents.basic_agent"
            ),
            "storage_agent.py": """\
from agents.basic_agent import BasicAgent
from utils.azure_file_storage import AzureFileStorageManager

class StorageAgent(BasicAgent):
    name = "storage"
    metadata = {
        "name": "storage",
        "description": "Store text.",
        "parameters": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    }
    def __init__(self):
        self.manager = AzureFileStorageManager()
        super().__init__()
    def perform(self, text="", **kwargs):
        self.manager.write_file("shim/value.txt", text)
        return self.manager.read_file("shim/value.txt")
""",
        }
        with RuntimeFixture() as fixture:
            for name, source in sources.items():
                fixture.write_agent(name, source)
            snapshot = self._registry(fixture).load()

            self.assertEqual(snapshot.names, ("echo", "storage"))
            self.assertEqual(snapshot["storage"].perform(text="safe"), "safe")
            shims = {
                shim
                for record in snapshot.report.records
                for shim in record.shims_used
            }
            self.assertIn("agents.basic_agent", shims)
            self.assertIn("utils.azure_file_storage", shims)

    def test_order_is_deterministic_by_file_class_and_tool(self) -> None:
        with RuntimeFixture() as fixture:
            fixture.write_agent(
                "zeta_agent.py",
                ECHO_AGENT.replace('"echo"', '"zeta"').replace(
                    "EchoAgent", "ZetaAgent"
                ),
            )
            fixture.write_agent("alpha_agent.py", ECHO_AGENT)
            snapshot = self._registry(fixture).load()

            self.assertEqual(snapshot.names, ("echo", "zeta"))
            self.assertEqual(
                [record.file_name for record in snapshot.report.records],
                ["alpha_agent.py", "zeta_agent.py"],
            )

    def test_duplicate_tool_name_rejects_entire_refresh(self) -> None:
        with RuntimeFixture() as fixture:
            fixture.write_agent("one_agent.py", ECHO_AGENT)
            fixture.write_agent(
                "two_agent.py", ECHO_AGENT.replace("EchoAgent", "SecondAgent")
            )

            with self.assertRaises(RegistryLoadError) as raised:
                self._registry(fixture).load()

            self.assertIn(
                "duplicate_tool_name",
                {
                    record.error_code
                    for record in raised.exception.report.records
                },
            )

    def test_symlink_candidate_is_rejected(self) -> None:
        with RuntimeFixture() as fixture:
            target = fixture.root / "target.py"
            target.write_text(ECHO_AGENT, encoding="utf-8")
            (fixture.agents / "linked_agent.py").symlink_to(target)

            with self.assertRaises(RegistryLoadError) as raised:
                self._registry(fixture).load()

            self.assertEqual(
                raised.exception.report.records[0].error_code, "symlink"
            )

    def test_unsafe_file_name_and_traversing_directory_are_rejected(self) -> None:
        with RuntimeFixture() as fixture:
            fixture.write_agent("-bad_agent.py", ECHO_AGENT)
            with self.assertRaises(RegistryLoadError) as raised:
                self._registry(fixture).load()
            self.assertEqual(
                raised.exception.report.records[0].error_code,
                "unsafe_file_name",
            )

            traversing = fixture.root / "agents" / ".." / "agents"
            with self.assertRaises(RegistryConfigurationError):
                AgentRegistry(traversing, storage=LocalStorage(fixture.data))

    def test_oversized_source_is_rejected_before_import(self) -> None:
        with RuntimeFixture() as fixture:
            fixture.write_agent("large_agent.py", ECHO_AGENT + ("#" * 100))
            registry = AgentRegistry(
                fixture.agents,
                storage=LocalStorage(fixture.data),
                max_agent_bytes=64,
                compatibility_mode=True,
            )

            with self.assertRaises(RegistryLoadError) as raised:
                registry.load()

            self.assertEqual(
                raised.exception.report.records[0].error_code,
                "oversized_file",
            )

    def test_invalid_metadata_is_rejected(self) -> None:
        with RuntimeFixture() as fixture:
            fixture.write_agent(
                "bad_agent.py",
                ECHO_AGENT.replace('"description": "Echo supplied text."', '"description": ""'),
            )

            with self.assertRaises(RegistryLoadError) as raised:
                self._registry(fixture).load()

            self.assertEqual(
                raised.exception.report.records[0].error_code,
                "invalid_agent_metadata",
            )

    def test_non_basic_agent_class_is_rejected(self) -> None:
        with RuntimeFixture() as fixture:
            fixture.write_agent(
                "fake_agent.py",
                "class FakeAgent:\n"
                "    def perform(self, **kwargs):\n"
                "        return kwargs\n",
            )

            with self.assertRaises(RegistryLoadError) as raised:
                self._registry(fixture).load()

            self.assertEqual(
                raised.exception.report.records[0].error_code,
                "non_basic_agent_class",
            )

    def test_missing_dependency_is_reported_without_auto_install(self) -> None:
        with RuntimeFixture() as fixture:
            fixture.write_agent(
                "missing_agent.py",
                "import package_that_does_not_exist_4a39\n" + ECHO_AGENT,
            )
            with patch.object(subprocess, "run") as run:
                with self.assertRaises(RegistryLoadError) as raised:
                    self._registry(fixture).load()

            run.assert_not_called()
            record = raised.exception.report.records[0]
            self.assertEqual(record.error_code, "missing_dependency")
            self.assertEqual(record.detail, "package_that_does_not_exist_4a39")

    def test_constructor_failure_is_reported(self) -> None:
        with RuntimeFixture() as fixture:
            fixture.write_agent(
                "broken_agent.py",
                ECHO_AGENT.replace(
                    "    def perform",
                    "    def __init__(self):\n"
                    "        raise RuntimeError('private detail')\n"
                    "    def perform",
                ),
            )

            with self.assertRaises(RegistryLoadError) as raised:
                self._registry(fixture).load()

            record = raised.exception.report.records[0]
            self.assertEqual(record.error_code, "constructor_error")
            self.assertNotIn("private detail", str(raised.exception))

    def test_refresh_loads_changed_local_bytes(self) -> None:
        with RuntimeFixture() as fixture:
            path = fixture.write_agent("echo_agent.py", ECHO_AGENT)
            registry = self._registry(fixture)
            first = registry.load()
            path.write_text(
                ECHO_AGENT.replace("echo:{text}", "changed:{text}"),
                encoding="utf-8",
            )
            second = registry.refresh()

            self.assertEqual(first["echo"].perform(text="x"), "echo:x")
            self.assertEqual(second["echo"].perform(text="x"), "changed:x")

    def test_production_mode_rejects_compatibility_fixture(self) -> None:
        with RuntimeFixture() as fixture:
            fixture.write_agent("echo_agent.py", ECHO_AGENT)
            with self.assertRaises(RegistryLoadError) as raised:
                AgentRegistry(
                    fixture.agents,
                    storage=LocalStorage(fixture.data),
                ).load()
            self.assertEqual(
                raised.exception.report.records[0].error_code,
                "invalid_agent_contract",
            )

    def test_production_mode_enforces_complete_actual_agent_abi(self) -> None:
        with RuntimeFixture() as fixture:
            fixture.write_agent("strict_echo_agent.py", STRICT_AGENT)
            snapshot = AgentRegistry(
                fixture.agents,
                storage=LocalStorage(fixture.data),
            ).load()
            self.assertEqual(snapshot.names, ("StrictEcho",))

        invalid_sources = {
            "second_manifest": STRICT_AGENT.replace(
                "\nclass StrictEcho",
                "\n__manifest__ = dict(__manifest__)\n\nclass StrictEcho",
            ),
            "second_class": STRICT_AGENT
            + "\nclass Extra:\n    pass\n",
            "missing_perform": STRICT_AGENT.replace(
                "    def perform(self, **kwargs):",
                "    def execute(self, **kwargs):",
            ),
            "async_perform": STRICT_AGENT.replace(
                "    def perform(self, **kwargs):",
                "    async def perform(self, **kwargs):",
            ),
            "positional_only": STRICT_AGENT.replace(
                "    def perform(self, **kwargs):",
                "    def perform(self, /, **kwargs):",
            ),
            "required_arg": STRICT_AGENT.replace(
                "    def perform(self, **kwargs):",
                "    def perform(self, value, **kwargs):",
            ),
            "optional_arg": STRICT_AGENT.replace(
                "    def perform(self, **kwargs):",
                "    def perform(self, value=None, **kwargs):",
            ),
            "decorated": STRICT_AGENT.replace(
                "    def perform(self, **kwargs):",
                "    @staticmethod\n    def perform(self, **kwargs):",
            ),
            "forbidden_import": STRICT_AGENT.replace(
                "import json", "import json\nimport socket"
            ),
            "action_mismatch": STRICT_AGENT.replace(
                '"enum": ["run"]', '"enum": ["other"]'
            ),
        }
        for label, source in invalid_sources.items():
            with self.subTest(label=label), RuntimeFixture() as fixture:
                fixture.write_agent("strict_echo_agent.py", source)
                with self.assertRaises(RegistryLoadError) as raised:
                    AgentRegistry(
                        fixture.agents,
                        storage=LocalStorage(fixture.data),
                    ).load()
                self.assertEqual(
                    raised.exception.report.records[0].error_code,
                    "invalid_agent_contract",
                )

    def test_runtime_signature_check_rejects_static_check_drift(self) -> None:
        source = STRICT_AGENT.replace(
            "    def perform(self, **kwargs):",
            "    def perform(self, optional=None, **kwargs):",
        )
        digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
        with RuntimeFixture() as fixture:
            fixture.write_agent("strict_echo_agent.py", source)
            with patch(
                "rapp_stack_cubby.runtime.registry.inspect_agent_source",
                return_value={"sha256": digest},
            ):
                with self.assertRaises(RegistryLoadError) as raised:
                    AgentRegistry(
                        fixture.agents,
                        storage=LocalStorage(fixture.data),
                    ).load()
        self.assertEqual(
            raised.exception.report.records[0].error_code,
            "invalid_agent_contract",
        )

    @staticmethod
    def _registry(fixture: RuntimeFixture) -> AgentRegistry:
        return AgentRegistry(
            fixture.agents,
            storage=LocalStorage(fixture.data),
            compatibility_mode=True,
        )


if __name__ == "__main__":
    unittest.main()
