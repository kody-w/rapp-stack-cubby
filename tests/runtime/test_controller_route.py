from __future__ import annotations

import hashlib
import io
import json
import os
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from rapp_stack_cubby.cli import main
from rapp_stack_cubby.runtime.orchestrator import (
    Orchestrator,
    RequestValidationError,
    build_controller_chat_request,
)
from rapp_stack_cubby.runtime.provider import ProviderResponse, ScriptedProvider
from rapp_stack_cubby.runtime.registry import AgentRegistry
from rapp_stack_cubby.runtime.storage import LocalStorage

from tests.controller._support import (
    CONTROLLER_DIRECTORY,
    ControllerEnvironment,
    RAPPID,
    REPOSITORY_ROOT,
)
from ._support import RuntimeFixture


class _Response:
    status = 200

    def __init__(self, payload: dict):
        self._raw = json.dumps(payload).encode("utf-8")

    def read(self, maximum: int) -> bytes:
        return self._raw[:maximum]

    def close(self) -> None:
        return None


class ControllerRouteTests(unittest.TestCase):
    def test_exact_route_bypasses_provider_and_returns_content_free_proof(self):
        with ControllerEnvironment(mutations=False) as environment:
            provider = ScriptedProvider([])
            registry = AgentRegistry(
                CONTROLLER_DIRECTORY,
                storage=LocalStorage(environment.registry_data),
            )
            orchestrator = Orchestrator(
                soul_path=REPOSITORY_ROOT / "cubbies/kody-w/soul.md",
                registry=registry,
                provider=provider,
                model="explicit-controller-model",
                controller_route_enabled=True,
            )
            request = build_controller_chat_request(
                "inspect", {}, "inspect-route"
            )
            result = orchestrator.chat(request)

        decoded = json.loads(result["response"])
        self.assertTrue(decoded["ok"])
        self.assertEqual(provider.remaining, 0)
        self.assertEqual(
            result["model"], "deterministic-controller-route/1.0"
        )
        self.assertNotIn("result", result["result_proof"])
        self.assertEqual(
            result["result_proof"]["result_sha256"],
            hashlib.sha256(result["response"].encode()).hexdigest(),
        )

    def test_reserved_route_is_explicit_and_other_chat_stays_normal(self):
        with ControllerEnvironment(mutations=False) as environment:
            provider = ScriptedProvider(
                [ProviderResponse(content="ordinary response")]
            )
            registry = AgentRegistry(
                CONTROLLER_DIRECTORY,
                storage=LocalStorage(environment.registry_data),
            )
            disabled = Orchestrator(
                soul_path=REPOSITORY_ROOT / "cubbies/kody-w/soul.md",
                registry=registry,
                provider=provider,
                model="explicit-controller-model",
            )
            route = build_controller_chat_request(
                "inspect", {}, "disabled-route"
            )
            with self.assertRaises(RequestValidationError):
                disabled.chat(route)
            ordinary = disabled.chat({"user_input": "ordinary"})
        self.assertEqual(ordinary["response"], "ordinary response")

    def test_verified_terminal_child_rejection_is_returned_not_redispatched(self):
        with ControllerEnvironment(mutations=False) as environment:
            registry = AgentRegistry(
                CONTROLLER_DIRECTORY,
                storage=LocalStorage(environment.registry_data),
            )
            orchestrator = Orchestrator(
                soul_path=REPOSITORY_ROOT / "cubbies/kody-w/soul.md",
                registry=registry,
                provider=ScriptedProvider([]),
                model="explicit-controller-model",
                controller_route_enabled=True,
            )
            terminal = {
                "action": "chat",
                "agent": "RappStackCubbyController",
                "ok": False,
                "terminal": True,
                "signed_twin_chat": True,
                "signed_twin_chat_verified": True,
                "signed_twin_chat_status": "rejected",
                "instance_rappid": RAPPID,
                "key_epoch": 1,
                "error": {
                    "code": "child_rejected",
                    "message": "The signed child returned a terminal rejection.",
                },
            }
            terminal_text = json.dumps(
                terminal, sort_keys=True, separators=(",", ":")
            )
            request = build_controller_chat_request(
                "chat",
                {"rappid": RAPPID, "message": "synthetic"},
                "terminal-route",
            )
            with patch.object(
                orchestrator,
                "_execute_tool",
                return_value=(
                    terminal_text,
                    ("[RappStackCubbyController] completed",),
                ),
            ) as execute:
                first = orchestrator.chat(request)
                second = orchestrator.chat(request)

        self.assertEqual(first["response"], terminal_text)
        self.assertEqual(second["response"], terminal_text)
        self.assertEqual(execute.call_count, 2)

    def test_controller_cli_sends_only_post_chat(self):
        observed = {}

        def urlopen(request, timeout):
            observed["method"] = request.get_method()
            observed["url"] = request.full_url
            observed["timeout"] = timeout
            body = json.loads(request.data.decode("utf-8"))
            observed["body"] = body
            request_hash = hashlib.sha256(
                body["user_input"].encode("utf-8")
            ).hexdigest()
            controller_result = {"action": "status", "ok": True}
            result = json.dumps(
                controller_result,
                sort_keys=True,
                separators=(",", ":"),
            )
            result_sha256 = hashlib.sha256(result.encode()).hexdigest()
            return _Response(
                {
                    "response": result,
                    "controller_result": controller_result,
                    "session_id": "controller-" + request_hash[:32],
                    "agent_logs": "[RappStackCubbyController] completed",
                    "voice_mode": False,
                    "model": "deterministic-controller-route/1.0",
                    "requested_model": "explicit-controller-model",
                    "result_proof": {
                        "schema": "rapp-controller-result-proof/1.0",
                        "algorithm": "sha256",
                        "tool": "RappStackCubbyController",
                        "action": "status",
                        "request_sha256": request_hash,
                        "result_sha256": result_sha256,
                        "controller_result_sha256": result_sha256,
                        "child_response_sha256": result_sha256,
                        "signed_twin_chat_verified": False,
                        "signed_twin_chat_status": "not_applicable",
                        "instance_rappid": None,
                        "key_epoch": None,
                        "status": "ok",
                    },
                }
            )

        output = io.StringIO()
        with RuntimeFixture() as fixture:
            token = fixture.root / "token"
            token.write_bytes(b"\x51" * 32)
            os.chmod(token, 0o600)
            with patch(
                "urllib.request.urlopen", side_effect=urlopen
            ), redirect_stdout(output):
                status = main(
                    [
                        "controller",
                        "--url",
                        "http://127.0.0.1:7071/chat",
                        "--auth-token-file",
                        str(token),
                        "--idempotency-key",
                        "cli-status",
                        "status",
                        "--rappid",
                        RAPPID,
                    ]
                )
        self.assertEqual(status, 0)
        self.assertEqual(observed["method"], "POST")
        self.assertEqual(observed["url"], "http://127.0.0.1:7071/chat")
        self.assertEqual(set(observed["body"]), {"user_input"})
        self.assertIn("RAPP_CONTROLLER_ROUTE/1.0\n", observed["body"]["user_input"])


if __name__ == "__main__":
    unittest.main()
