from __future__ import annotations

import json
import os
import unittest
from unittest.mock import patch

from rapp_stack_cubby.protocols.replay import ReplayJournal

from ._support import AgentEnvironment, decoded


class TwinChatAgentTests(unittest.TestCase):
    def test_actions_report_only_public_ids_and_counts(self):
        with AgentEnvironment() as environment:
            state = environment.data / "twin-chat"
            state.mkdir(mode=0o700)
            pairing = {
                "schema": "rapp-twin-chat-pairing/1.0",
                "twin_rappid": "rappid:@kody-w/synthetic-agent-twin:" + "1" * 64,
                "controller_rappid": (
                    "rappid:@kody-w/rapp-stack-cubby-controller:" + "2" * 64
                ),
                "controller_key_id": "2" * 64,
                "controller_public_jwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "synthetic-public-only",
                    "y": "synthetic-public-only",
                },
                "child_key_id": "3" * 64,
                "child_public_jwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "synthetic-public-only",
                    "y": "synthetic-public-only",
                },
                "generation": 1,
                "key_epoch": 1,
                "paired_at": "2026-07-12T00:00:00Z",
            }
            (state / "pairing.json").write_text(
                json.dumps(pairing, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            replay_path = state / "replay.sqlite3"
            ReplayJournal(replay_path)
            variables = {
                "RAPP_STACK_TWIN_CHAT_STATE_DIR": str(state),
                "RAPP_STACK_TWIN_CHAT_REPLAY_DB": str(replay_path),
            }
            with patch.dict(os.environ, variables, clear=False):
                agent = environment.snapshot["TwinChat"]
                self.assertEqual(
                    agent.perform.__globals__["__manifest__"][
                        "capability_ids"
                    ],
                    [],
                )
                results = {
                    action: decoded(agent, action=action)
                    for action in ("status", "identity", "journal", "vector")
                }

        self.assertTrue(all(result["ok"] for result in results.values()))
        self.assertEqual(results["journal"]["counts"]["total"], 0)
        self.assertTrue(results["journal"]["values_redacted"])
        self.assertTrue(results["vector"]["synthetic"])
        self.assertTrue(results["vector"]["matched"])
        self.assertEqual(results["identity"]["key_epoch"], 1)
        rendered = json.dumps(results, sort_keys=True)
        self.assertNotIn("nonce", rendered)
        self.assertNotIn("user_input", rendered)
        self.assertNotIn("private.pem", rendered)


if __name__ == "__main__":
    unittest.main()
