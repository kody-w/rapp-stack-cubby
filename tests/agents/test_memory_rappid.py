from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from ._support import AgentEnvironment, decoded


class MemoryAgentTests(unittest.TestCase):
    def test_principal_isolation_secret_rejection_and_context_bounds(self) -> None:
        with AgentEnvironment(writes=True, principal="principal-a") as environment:
            agents = environment.snapshot
            assert agents is not None
            memory = agents["Memory"]
            first = decoded(
                memory,
                action="remember",
                content="Prefer concise synthetic summaries.",
                tags=["preference"],
                importance=5,
                timestamp="2026-01-01T00:00:00Z",
            )
            self.assertEqual(first["status"], "stored")
            decoded(
                memory,
                action="remember",
                content="This low-priority synthetic detail should stay out.",
                tags=["misc"],
                importance=1,
                timestamp="2026-01-01T00:00:01Z",
            )

            with patch.dict(
                os.environ,
                {"RAPP_STACK_PRINCIPAL": "principal-b"},
                clear=False,
            ):
                other = decoded(memory, action="list")
                self.assertEqual(other["total_count"], 0)
                self.assertIsNone(memory.system_context())

            own = decoded(memory, action="list")
            self.assertEqual(own["total_count"], 2)
            context = memory.system_context()
            self.assertIsInstance(context, str)
            assert context is not None
            self.assertIn("concise synthetic summaries", context)
            self.assertNotIn("low-priority synthetic detail", context)
            self.assertLessEqual(len(context), 1200)

            rejected = decoded(
                memory,
                action="remember",
                content="password = synthetic-value",
                timestamp="2026-01-01T00:00:02Z",
            )
            self.assertFalse(rejected["ok"])
            self.assertEqual(rejected["error"]["code"], "secret_rejected")
            self.assertNotIn("synthetic-value", str(rejected))

            oversized = decoded(
                memory,
                action="remember",
                content="x" * 2001,
                timestamp="2026-01-01T00:00:03Z",
            )
            self.assertFalse(oversized["ok"])

    def test_stable_ids_and_forget_are_deterministic(self) -> None:
        with AgentEnvironment(writes=True) as environment:
            memory = environment.snapshot["Memory"]
            fixture = {
                "action": "remember",
                "content": "Stable synthetic fact.",
                "tags": ["context"],
                "importance": 4,
                "timestamp": "2026-01-01T00:00:00Z",
            }
            first = decoded(memory, **fixture)
            second = decoded(memory, **fixture)
            self.assertEqual(first["memory"]["id"], second["memory"]["id"])
            self.assertEqual(second["status"], "already_present")

            forgotten = decoded(
                memory,
                action="forget",
                memory_id=first["memory"]["id"],
            )
            self.assertEqual(forgotten["status"], "deleted")
            recalled = decoded(
                memory,
                action="recall",
                memory_id=first["memory"]["id"],
            )
            self.assertEqual(recalled["count"], 0)


class RappidAgentTests(unittest.TestCase):
    VECTOR = (
        "rappid:@example/sample:"
        "280cbe5df87f88ed24d52eff2b64ffd190b9083ef37ce389f0efeab660087016"
    )

    def test_deterministic_vector_and_self_referential_exclusion(self) -> None:
        with AgentEnvironment() as environment:
            agent = environment.snapshot["Rappid"]
            birth = {"kind": "synthetic", "name": "Sample"}
            first = decoded(
                agent,
                action="mint",
                owner="example",
                slug="sample",
                birth=birth,
            )
            second = decoded(
                agent,
                action="mint",
                owner="example",
                slug="sample",
                birth={
                    **birth,
                    "rappid": "legacy-read-only",
                    "signature": "excluded",
                    "transport": {"kind": "excluded"},
                },
            )
            self.assertEqual(first["rappid"], self.VECTOR)
            self.assertEqual(second["rappid"], self.VECTOR)
            self.assertEqual(first["canonical_birth"], second["canonical_birth"])

    def test_legacy_parse_invalid_forms_and_door_derivation(self) -> None:
        with AgentEnvironment() as environment:
            agent = environment.snapshot["Rappid"]
            legacy = decoded(
                agent, action="parse", rappid="rappid:" + ("a" * 32)
            )
            self.assertEqual(legacy["format"], "legacy_hex")
            self.assertFalse(legacy["canonical"])
            self.assertNotIn("rappid", legacy)

            invalid = decoded(agent, action="validate", rappid="not-an-id")
            self.assertFalse(invalid["valid"])
            malformed = decoded(agent, action="parse", rappid="not-an-id")
            self.assertFalse(malformed["ok"])

            first = decoded(
                agent, action="door", rappid=self.VECTOR, door="local"
            )
            second = decoded(
                agent, action="door", rappid=self.VECTOR, door="local"
            )
            self.assertEqual(first["rappid"], second["rappid"])
            self.assertRegex(
                first["rappid"],
                r"^rappid:@example/sample-local:[0-9a-f]{64}$",
            )


if __name__ == "__main__":
    unittest.main()
