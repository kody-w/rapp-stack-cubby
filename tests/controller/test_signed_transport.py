from __future__ import annotations

import json
import os
import stat
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ._support import (
    ControllerEnvironment,
    IDENTITY_HASH,
    RAPPID,
    REPOSITORY_ROOT,
    decoded,
)


class ControllerSignedTransportTests(unittest.TestCase):
    def _running_twin(self, environment):
        process = {
            "pid": os.getpid(),
            "pgid": os.getpgid(os.getpid()),
            "port": 43219,
            "started_at": "2026-07-12T00:00:00Z",
            "instance_id": "synthetic-signed-child",
            "command_sha256": "a" * 64,
        }
        return environment.create_twin(
            runtime_status="running",
            process=process,
        )

    def test_chat_uses_only_signed_wrapper_in_post_chat_and_has_no_fallback(self):
        with ControllerEnvironment() as environment:
            self._running_twin(environment)
            calls = []

            def unsigned_response(port, method, path, payload=None, timeout=15):
                calls.append((method, path, payload))
                return {
                    "response": "unsigned child response",
                    "session_id": "untrusted",
                    "agent_logs": "",
                }

            with patch.dict(
                environment.globals,
                {
                    "_health_matches": lambda process: True,
                    "_http_json": unsigned_response,
                },
            ):
                result = decoded(
                    environment.agent,
                    action="chat",
                    rappid=RAPPID,
                    idempotency_key="signed-wrapper-only",
                    message="synthetic controller input",
                    audience="signed-test",
                )
            session_directory = (
                environment.controller_data
                / "sessions"
                / IDENTITY_HASH
            )
            sessions = (
                list(session_directory.glob("*.json"))
                if session_directory.exists()
                else []
            )

        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "response_invalid")
        self.assertEqual(len(calls), 1)
        method, path, outer = calls[0]
        self.assertEqual((method, path), ("POST", "/chat"))
        self.assertEqual(set(outer), {"user_input"})
        wrapper = json.loads(outer["user_input"])
        self.assertEqual(wrapper["schema"], "rapp-commons-event/1.0")
        self.assertEqual(wrapper["body"]["schema"], "rapp-twin-chat/1.0")
        self.assertEqual(wrapper["body"]["payload"]["user_input"], "synthetic controller input")
        self.assertEqual(sessions, [])

    def test_controller_source_has_no_alternate_agent_route_or_perform_shortcut(self):
        with ControllerEnvironment() as environment:
            source = (
                REPOSITORY_ROOT
                / "cubbies/kody-w/agents/rapp_stack_cubby_agent.py"
            ).read_text(encoding="utf-8")

        self.assertNotIn("/api/agent", source)
        self.assertNotIn("direct_perform", source)
        self.assertEqual(source.count('"/chat"'), 2)

    def test_chat_requires_idempotency_key_before_any_child_call(self):
        with ControllerEnvironment() as environment:
            self._running_twin(environment)
            with patch.dict(
                environment.globals,
                {
                    "_health_matches": lambda process: True,
                    "_http_json": lambda *args, **kwargs: (_ for _ in ()).throw(
                        AssertionError("child called")
                    ),
                },
            ):
                results = [
                    decoded(
                        environment.agent,
                        action="chat",
                        rappid=RAPPID,
                        message="missing key",
                    ),
                    decoded(
                        environment.agent,
                        action="self_test",
                        rappid=RAPPID,
                    ),
                ]
        for result in results:
            self.assertFalse(result["ok"])
            self.assertEqual(
                result["error"]["code"], "idempotency_key_required"
            )

    def test_verified_rejection_is_terminal_and_exactly_replayed(self):
        with ControllerEnvironment() as environment:
            twin = self._running_twin(environment)
            root = environment.controller_data
            state = environment.globals["_load_state"](twin)
            _controller, pairing = environment.globals[
                "_ensure_twin_transport"
            ](root, twin, state)
            child_key = environment.globals["_transport_load_private"](
                twin / "workspace/data/twin-chat/private.pem"
            )
            calls = []

            def reject(port, method, path, payload=None, timeout=35):
                calls.append((payload["user_input"], timeout))
                wrapper = json.loads(payload["user_input"])
                inner = wrapper["body"]
                response = {
                    "schema": "rapp-twin-chat-response/1.0",
                    "from_rappid": RAPPID,
                    "to_rappid": wrapper["from"],
                    "utc": environment.globals["_utc_now"](),
                    "request_nonce": inner["nonce"],
                    "request_digest": environment.globals["hashlib"].sha256(
                        environment.globals["_transport_canonical_bytes"](
                            inner
                        )
                    ).hexdigest(),
                    "key_epoch": pairing["key_epoch"],
                    "status": "rejected",
                    "payload": {
                        "error": {
                            "code": "synthetic_terminal",
                            "message": "Synthetic terminal rejection.",
                        }
                    },
                    "key_id": pairing["child_key_id"],
                }
                response["sig"] = environment.globals["_transport_sign"](
                    response, child_key
                )
                return {
                    "response": environment.globals[
                        "_transport_canonical_bytes"
                    ](response).decode("utf-8")
                }

            with patch.dict(
                environment.globals,
                {
                    "_health_matches": lambda process: True,
                    "_http_json": reject,
                },
            ):
                first = decoded(
                    environment.agent,
                    action="chat",
                    rappid=RAPPID,
                    idempotency_key="terminal-rejection",
                    message="reject exactly once",
                    audience="terminal-owner",
                )
                replay = decoded(
                    environment.agent,
                    action="chat",
                    rappid=RAPPID,
                    idempotency_key="terminal-rejection",
                    message="reject exactly once",
                    audience="terminal-owner",
                )
                conflict = decoded(
                    environment.agent,
                    action="chat",
                    rappid=RAPPID,
                    idempotency_key="terminal-rejection",
                    message="different request",
                    audience="terminal-owner",
                )
            transaction = json.loads(
                environment.globals["_transaction_path"](
                    root, "terminal-rejection"
                ).read_text(encoding="utf-8")
            )
            transaction_mode = stat.S_IMODE(
                environment.globals["_transaction_path"](
                    root, "terminal-rejection"
                ).stat().st_mode
            )

        self.assertFalse(first["ok"])
        self.assertEqual(first["error"]["code"], "child_rejected")
        self.assertEqual(first, replay)
        self.assertFalse(conflict["ok"])
        self.assertEqual(conflict["error"]["code"], "idempotency_conflict")
        self.assertEqual(len(calls), 1)
        self.assertGreater(calls[0][1], 30.0)
        self.assertEqual(transaction["phase"], "completed")
        self.assertEqual(
            transaction["signed_request"]["state"], "response_verified"
        )
        self.assertEqual(transaction["signed_request"]["key_epoch"], 1)
        self.assertEqual(transaction["signed_request"]["generation"], 1)
        self.assertEqual(transaction["signed_response"]["status"], "rejected")
        self.assertEqual(transaction_mode, 0o600)

    def test_single_file_crypto_rejects_sec1_and_high_s(self):
        with ControllerEnvironment() as environment:
            sec1 = environment.root / "sec1.pem"
            sec1.write_bytes(
                ec.generate_private_key(ec.SECP256R1()).private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )
            sec1.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError, "state_invalid"):
                environment.globals["_transport_load_private"](sec1)

            key = ec.generate_private_key(ec.SECP256R1())
            jwk = environment.globals["_transport_public_jwk"](key)
            value = {"schema": "synthetic", "value": 1}
            value["sig"] = environment.globals["_transport_sign"](
                value, key
            )
            raw = environment.globals["_transport_b64decode"](
                value["sig"], 64
            )
            order = environment.globals["_P256_ORDER"]
            s = int.from_bytes(raw[32:], "big")
            high = dict(value)
            high["sig"] = environment.globals["_transport_b64encode"](
                raw[:32] + (order - s).to_bytes(32, "big")
            )
            with self.assertRaisesRegex(RuntimeError, "response_invalid"):
                environment.globals["_transport_verify"](high, jwk)


if __name__ == "__main__":
    unittest.main()
