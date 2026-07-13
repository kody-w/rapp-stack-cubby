from __future__ import annotations

import os
import stat
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from rapp_stack_cubby.runtime.config import SignedIngressConfig
from rapp_stack_cubby.runtime.orchestrator import Orchestrator
from rapp_stack_cubby.runtime.provider import (
    ProviderResponse,
    ProviderTransportError,
    ScriptedProvider,
    ToolCall,
)
from rapp_stack_cubby.runtime.registry import AgentRegistry
from rapp_stack_cubby.runtime.server import RuntimeServer
from rapp_stack_cubby.runtime.storage import LocalStorage

from ._support import (
    ControllerEnvironment,
    CONTROLLER_DIRECTORY,
    IDENTITY_HASH,
    RAPPID,
    REPOSITORY_ROOT,
    decoded,
)

INTERNAL_AGENTS = (
    REPOSITORY_ROOT
    / "cubbies/kody-w/rapplications/rapp-stack/twin/agents"
)
SOUL = (
    REPOSITORY_ROOT
    / "cubbies/kody-w/rapplications/rapp-stack/twin/soul.md"
)


class LiveControllerChatTests(unittest.TestCase):
    def test_chat_session_mapping_and_conversational_self_test_use_only_chat(self):
        with ControllerEnvironment() as environment:
            twin = environment.create_twin()
            child_data = twin / "workspace/data"
            root = environment.controller_data
            state = environment.globals["_load_state"](twin)
            controller, pairing = environment.globals[
                "_ensure_twin_transport"
            ](root, twin, state)
            state = dict(state)
            state["transport"] = environment.globals["_transport_state"](
                pairing
            )
            environment.globals["_write_state"](twin, state)
            provider = ScriptedProvider(
                [
                    ProviderResponse(content="local reply"),
                    ProviderResponse(
                        tool_calls=(
                            ToolCall(
                                id="self-test-call",
                                name="SelfTest",
                                arguments='{"action":"run"}',
                            ),
                        )
                    ),
                    ProviderResponse(content="self test passed"),
                    ProviderResponse(content="no tool proof"),
                    ProviderResponse(
                        tool_calls=(
                            ToolCall(
                                id="timeout-self-test-call",
                                name="SelfTest",
                                arguments='{"action":"run"}',
                            ),
                        )
                    ),
                    ProviderResponse(content="timeout recovered"),
                    ProviderTransportError("synthetic terminal rejection"),
                ]
            )
            registry = AgentRegistry(
                INTERNAL_AGENTS,
                storage=LocalStorage(child_data),
            )
            orchestrator = Orchestrator(
                soul_path=SOUL,
                registry=registry,
                provider=provider,
                model="scripted-controller-test",
                signed_ingress=SignedIngressConfig(
                    twin_rappid=RAPPID,
                    child_private_key_path=(
                        twin / "workspace/data/twin-chat/private.pem"
                    ),
                    paired_controller_public_jwk_path=(
                        twin
                        / "workspace/data/twin-chat/controller-public.jwk"
                    ),
                    paired_controller_rappid=controller["rappid"],
                    replay_db_path=(
                        twin / "workspace/data/twin-chat/replay.sqlite3"
                    ),
                    key_epoch=pairing["key_epoch"],
                ),
                signed_only=True,
            )
            server = RuntimeServer(
                orchestrator,
                host="127.0.0.1",
                port=0,
                instance_id="controller-child-instance",
            )
            server.start()
            plain_request = urllib.request.Request(
                server.url + "/chat",
                data=b'{"user_input":"direct plaintext child call"}',
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as rejected_plain:
                urllib.request.urlopen(plain_request, timeout=2.0)
            self.assertEqual(rejected_plain.exception.code, 400)
            self.assertEqual(provider.requests, ())
            process = {
                "pid": os.getpid(),
                "pgid": os.getpgid(os.getpid()),
                "port": server.port,
                "started_at": "2026-07-12T00:00:00Z",
                "start_identity": "c" * 64,
                "instance_id": "controller-child-instance",
                "command_sha256": "a" * 64,
                "model": "scripted-controller-test",
                "provider_timeout": 30.0,
                "signed_only": True,
            }
            state = environment.globals["_load_state"](twin)
            state = dict(state)
            state["runtime_status"] = "running"
            state["process"] = process
            environment.globals["_write_state"](twin, state)
            child_environment = {
                "RAPP_STACK_ROOT": str(REPOSITORY_ROOT),
                "RAPP_STACK_DATA_DIR": str(child_data),
                "RAPP_STACK_GENERATED_AGENTS_DIR": str(
                    environment.root / "generated"
                ),
                "RAPP_STACK_PRINCIPAL": "controller-test-principal",
            }
            (environment.root / "generated").mkdir(mode=0o700)
            try:
                with patch.dict(
                    os.environ, child_environment, clear=False
                ), patch.dict(
                    environment.globals,
                    {
                        "_leader_identity_matches": lambda process: True,
                        "_health_matches": lambda process: True,
                    },
                ):
                    health_status, health = server.health_payload()
                    self.assertEqual(health_status, 200)
                    self.assertTrue(health["signed_only"])
                    chat = decoded(
                        environment.agent,
                        action="chat",
                        rappid=RAPPID,
                        idempotency_key="live-chat",
                        message="hello child",
                        audience="local-owner",
                    )
                    self_test = decoded(
                        environment.agent,
                        action="self_test",
                        rappid=RAPPID,
                        idempotency_key="live-self-test",
                        audience="self-test-owner",
                    )
                    rejected = decoded(
                        environment.agent,
                        action="self_test",
                        rappid=RAPPID,
                        idempotency_key="live-self-test-no-proof",
                        audience="self-test-no-proof",
                    )
                    original_http = environment.globals["_http_json"]
                    timeout_wires = []

                    def lose_first_response(
                        port,
                        method,
                        path,
                        payload=None,
                        timeout=35,
                    ):
                        timeout_wires.append(payload["user_input"])
                        response = original_http(
                            port,
                            method,
                            path,
                            payload,
                            timeout,
                        )
                        if len(timeout_wires) == 1:
                            raise RuntimeError("http_unavailable")
                        return response

                    with patch.dict(
                        environment.globals,
                        {"_http_json": lose_first_response},
                    ):
                        ambiguous = decoded(
                            environment.agent,
                            action="chat",
                            rappid=RAPPID,
                            idempotency_key="live-timeout-restart",
                            message="survive lost response",
                            audience="timeout-owner",
                        )

                    restarted_data = environment.root / "restarted-registry"
                    restarted_data.mkdir(mode=0o700)
                    restarted = AgentRegistry(
                        CONTROLLER_DIRECTORY,
                        storage=LocalStorage(restarted_data),
                    ).load()["RappStackCubbyController"]
                    restarted_globals = restarted.perform.__globals__
                    with patch.dict(
                        restarted_globals,
                        {
                            "_leader_identity_matches": lambda process: True,
                            "_health_matches": lambda process: True,
                            "_http_json": lose_first_response,
                        },
                    ):
                        with patch.dict(
                            restarted_globals,
                            {
                                "_transport_require_fresh": (
                                    lambda value: (_ for _ in ()).throw(
                                        AssertionError(
                                            "retrieval checked freshness"
                                        )
                                    )
                                )
                            },
                        ):
                            recovered = decoded(
                                restarted,
                                action="chat",
                                rappid=RAPPID,
                                idempotency_key="live-timeout-restart",
                                message="survive lost response",
                                audience="timeout-owner",
                            )
                            completed_replay = decoded(
                                restarted,
                                action="chat",
                                rappid=RAPPID,
                                idempotency_key="live-timeout-restart",
                                message="survive lost response",
                                audience="timeout-owner",
                            )
                        terminal = decoded(
                            restarted,
                            action="chat",
                            rappid=RAPPID,
                            idempotency_key="live-terminal-rejection",
                            message="produce terminal rejection",
                            audience="rejection-owner",
                        )
                        terminal_replay = decoded(
                            restarted,
                            action="chat",
                            rappid=RAPPID,
                            idempotency_key="live-terminal-rejection",
                            message="produce terminal rejection",
                            audience="rejection-owner",
                        )
                        conflict = decoded(
                            restarted,
                            action="chat",
                            rappid=RAPPID,
                            idempotency_key="live-timeout-restart",
                            message="different request",
                            audience="timeout-owner",
                        )
            finally:
                server.shutdown()

            session_files = list(
                (
                    environment.controller_data
                    / "sessions"
                    / IDENTITY_HASH
                ).glob("*.json")
            )
            session_modes = [
                stat.S_IMODE(path.stat().st_mode) for path in session_files
            ]

        self.assertTrue(chat["ok"])
        self.assertEqual(chat["child"]["response"], "local reply")
        self.assertFalse(chat["local_owner_direct"])
        self.assertTrue(chat["signed_twin_chat"])
        self.assertTrue(self_test["passed"])
        self.assertIn("[SelfTest] completed", self_test["child"]["agent_logs"])
        self.assertFalse(rejected["ok"])
        self.assertEqual(rejected["error"]["code"], "self_test_failed")
        self.assertFalse(ambiguous["ok"])
        self.assertEqual(ambiguous["error"]["code"], "http_unavailable")
        self.assertTrue(recovered["ok"])
        self.assertEqual(
            recovered["child"]["agent_logs"], "[SelfTest] completed"
        )
        self.assertEqual(recovered, completed_replay)
        self.assertEqual(len(timeout_wires), 3)
        self.assertEqual(timeout_wires[0], timeout_wires[1])
        self.assertNotEqual(timeout_wires[1], timeout_wires[2])
        self.assertFalse(terminal["ok"])
        self.assertEqual(terminal["error"]["code"], "child_rejected")
        self.assertEqual(terminal, terminal_replay)
        self.assertFalse(conflict["ok"])
        self.assertEqual(conflict["error"]["code"], "idempotency_conflict")
        self.assertEqual(len(provider.requests), 7)
        self.assertEqual(len(session_files), 4)
        self.assertTrue(all(mode == 0o600 for mode in session_modes))


if __name__ == "__main__":
    unittest.main()
