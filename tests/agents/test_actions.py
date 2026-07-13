from __future__ import annotations

import json
import os
import time
import unittest
from unittest.mock import patch

from ._support import AgentEnvironment, decoded


class AgentActionTests(unittest.TestCase):
    def test_imessage_reads_only_explicit_redacted_status(self) -> None:
        with AgentEnvironment() as environment:
            status_path = environment.data / "imessage-status.json"
            status_path.write_text(
                json.dumps(
                    {
                        "controller_ready": True,
                        "dropped": 0,
                        "failed": 0,
                        "heartbeat_at": time.time(),
                        "imsg_version": "0.12.3",
                        "lifecycle": "running",
                        "pending": 0,
                        "processed": 1,
                        "read_ready": True,
                        "ready": True,
                        "restart_count": 0,
                        "send_ready": True,
                        "transport_ready": True,
                    }
                ),
                encoding="utf-8",
            )
            os.chmod(status_path, 0o600)
            with patch.dict(
                os.environ,
                {"RAPP_STACK_IMESSAGE_STATUS": str(status_path)},
                clear=False,
            ):
                result = decoded(
                    environment.snapshot["IMessage"], action="status"
                )
            self.assertTrue(result["configured"])
            self.assertTrue(result["ready"])
            self.assertTrue(result["controller_ready"])
            self.assertTrue(result["transport_ready"])
            self.assertTrue(result["send_ready"])

    def test_every_declared_action_returns_json_for_valid_fixture(self) -> None:
        with AgentEnvironment(writes=True) as environment:
            agents = environment.snapshot
            assert agents is not None

            factory_render = decoded(
                agents["AgentFactory"],
                action="render",
                name="Synthetic",
                description="A synthetic test agent.",
                parameters=[
                    {
                        "name": "text",
                        "type": "string",
                        "description": "Synthetic text.",
                        "required": True,
                    }
                ],
            )
            self.assertTrue(factory_render["ok"])
            self.assertTrue(
                decoded(agents["AgentFactory"], action="list")["ok"]
            )
            created = decoded(
                agents["AgentFactory"],
                action="create",
                name="Synthetic",
                description="A synthetic test agent.",
                parameters=[],
            )
            self.assertEqual(created["status"], "created")
            deleted = decoded(
                agents["AgentFactory"],
                action="delete",
                name="Synthetic",
                expected_digest=created["sha256"],
            )
            self.assertEqual(deleted["status"], "deleted")

            cubby_fixtures = {
                "inspect": {},
                "list": {"resource": "anatomy", "limit": 2},
                "show": {"resource": "cubby"},
                "query": {"query": "RAPP", "limit": 2},
                "render": {
                    "slug": "synthetic",
                    "display_name": "Synthetic Cubby",
                    "description": "A synthetic public cubby.",
                    "created_at": "2026-01-01T00:00:00Z",
                },
                "pack": {},
                "import": {},
                "stream": {},
            }
            for action, fixture in cubby_fixtures.items():
                with self.subTest(agent="Cubby", action=action):
                    decoded(agents["Cubby"], action=action, **fixture)

            for target in (
                "local",
                "pages",
                "azure-functions",
                "dataverse",
                "m365-copilot-studio",
            ):
                for action in ("inspect", "render"):
                    with self.subTest(
                        agent="Deployment", action=action, target=target
                    ):
                        result = decoded(
                            agents["Deployment"], action=action, target=target
                        )
                        self.assertFalse(result["execution_performed"])

            remembered = decoded(
                agents["Memory"],
                action="remember",
                content="The synthetic preference is concise output.",
                tags=["preference"],
                importance=5,
                timestamp="2026-01-01T00:00:00Z",
            )
            memory_id = remembered["memory"]["id"]
            for action, fixture in {
                "recall": {"memory_id": memory_id},
                "list": {"limit": 5},
                "context": {"query": "concise"},
                "forget": {"memory_id": memory_id},
            }.items():
                with self.subTest(agent="Memory", action=action):
                    decoded(agents["Memory"], action=action, **fixture)

            minted = decoded(
                agents["Rappid"],
                action="mint",
                owner="example",
                slug="sample",
                birth={"kind": "synthetic", "name": "Sample"},
            )
            rappid = minted["rappid"]
            rappid_fixtures = {
                "canonicalize": {
                    "birth": {
                        "name": "Sample",
                        "signature": "excluded",
                    }
                },
                "validate": {"rappid": rappid},
                "parse": {"rappid": rappid},
                "door": {"rappid": rappid, "door": "local"},
            }
            for action, fixture in rappid_fixtures.items():
                with self.subTest(agent="Rappid", action=action):
                    decoded(agents["Rappid"], action=action, **fixture)

            rapplication_fixtures = {
                "inspect": {},
                "status": {},
                "coverage": {},
                "render": {
                    "name": "synthetic-app",
                    "description": "A synthetic rapplication template.",
                    "version": "1.0.0",
                },
                "pack": {},
                "hatch": {},
                "lifecycle": {},
            }
            for action, fixture in rapplication_fixtures.items():
                with self.subTest(agent="Rapplication", action=action):
                    decoded(agents["Rapplication"], action=action, **fixture)

            registry_fixtures = {
                "list": {"limit": 2},
                "search": {"query": "memory", "limit": 2},
                "inspect": {"name": "Memory"},
                "capability": {"capability_id": "memory.", "limit": 5},
            }
            for action, fixture in registry_fixtures.items():
                with self.subTest(agent="Registry", action=action):
                    decoded(agents["Registry"], action=action, **fixture)

            security_fixtures = {
                "boundary": {},
                "provenance": {},
                "unresolved": {},
                "scan": {
                    "subtree": (
                        "cubbies/kody-w/rapplications/rapp-stack/twin/agents"
                    ),
                    "max_files": 20,
                },
                "verify": {},
            }
            for action, fixture in security_fixtures.items():
                with self.subTest(agent="Security", action=action):
                    decoded(agents["Security"], action=action, **fixture)

            for action in (
                "run",
                "artifact",
                "catalog",
                "agents",
                "mappings",
                "isolation",
                "routes",
            ):
                with self.subTest(agent="SelfTest", action=action):
                    result = decoded(agents["SelfTest"], action=action)
                    self.assertTrue(result["passed"], result)

            stack_fixtures = {
                "overview": {},
                "capability": {"query": "memory", "limit": 2},
                "path": {"query": "local", "limit": 2},
                "repo": {"repo_name": "RAR", "limit": 2},
                "collision": {"query": "skill", "limit": 2},
                "gaps": {"query": "runtime", "limit": 2},
                "coverage": {},
            }
            for action, fixture in stack_fixtures.items():
                with self.subTest(agent="StackMap", action=action):
                    decoded(agents["StackMap"], action=action, **fixture)

    def test_every_agent_json_encodes_invalid_action(self) -> None:
        with AgentEnvironment() as environment:
            agents = environment.snapshot
            assert agents is not None
            for name, agent in agents.items():
                with self.subTest(agent=name):
                    result = decoded(agent, action="unsupported")
                    self.assertFalse(result["ok"])
                    self.assertEqual(
                        result["error"]["code"], "invalid_action"
                    )

    def test_mutation_defaults_disabled(self) -> None:
        with AgentEnvironment() as environment:
            agents = environment.snapshot
            assert agents is not None
            memory = decoded(
                agents["Memory"],
                action="remember",
                content="Synthetic local fact.",
                timestamp="2026-01-01T00:00:00Z",
            )
            self.assertEqual(memory["status"], "disabled")
            factory = decoded(
                agents["AgentFactory"],
                action="create",
                name="Synthetic",
                description="Synthetic generated agent.",
                parameters=[],
            )
            self.assertEqual(factory["status"], "disabled")

            with patch.dict(
                os.environ,
                {"RAPP_STACK_GENERATED_AGENTS_DIR": str(environment.generated)},
                clear=False,
            ):
                self.assertFalse((environment.generated / "synthetic_agent.py").exists())


if __name__ == "__main__":
    unittest.main()
