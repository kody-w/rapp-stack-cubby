from __future__ import annotations

import http.server
import hashlib
import json
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from rapp_stack_cubby.imessage.bridge import (
    IMessageBridge,
    IMessageBridgeError,
    LoopbackGlobalChatRunner,
    build_routing_instruction,
    validate_global_chat_response,
)
from rapp_stack_cubby.imessage.cli import OwnerChatBinding
from rapp_stack_cubby.imessage.rpc import ImsgRpcAmbiguous
from rapp_stack_cubby.imessage.state import IMessageState
from rapp_stack_cubby.runtime.orchestrator import Orchestrator
from rapp_stack_cubby.runtime.provider import ScriptedProvider
from rapp_stack_cubby.runtime.registry import AgentRegistry
from rapp_stack_cubby.runtime.server import RuntimeServer
from rapp_stack_cubby.runtime.storage import LocalStorage
from rapp_stack_cubby.runtime.auth import (
    AUTH_CHALLENGE_HEADER,
    AUTH_PROOF_HEADER,
    auth_challenge_proof,
    decode_auth_value,
)
from tests.controller._support import (
    CONTROLLER_DIRECTORY,
    ControllerEnvironment,
)

from ._support import (
    FakeSupervisor,
    WorkDirectory,
    global_response,
    global_response_for_call,
    make_config,
    owner_event,
)


class IMessageBridgeTests(unittest.TestCase):
    def test_live_authenticated_route_proves_signed_child_to_bridge(self) -> None:
        with ControllerEnvironment(mutations=False) as environment:
            registry = AgentRegistry(
                CONTROLLER_DIRECTORY,
                storage=LocalStorage(environment.registry_data),
            )
            orchestrator = Orchestrator(
                soul_path=(
                    Path(__file__).resolve().parents[2]
                    / "cubbies/kody-w/soul.md"
                ),
                registry=registry,
                provider=ScriptedProvider([]),
                model="deterministic-route",
                controller_route_enabled=True,
            )
            with WorkDirectory() as root:
                config = make_config(root)
                token = config.controller_auth_token_file.read_bytes()
                server = RuntimeServer(
                    orchestrator,
                    port=0,
                    instance_id="global-controller",
                    auth_token=token,
                )
                server.start()
                config_value = config.to_dict()
                config_value["global_controller_url"] = (
                    f"http://127.0.0.1:{server.port}/chat"
                )
                config = type(config).from_dict(config_value)
                config.write(overwrite=True)
                controller_result = {
                    "action": "chat",
                    "agent": "RappStackCubbyController",
                    "child": {"response": "live signed child response"},
                    "instance_rappid": config.target_rappid,
                    "key_epoch": 3,
                    "ok": True,
                    "rappid": config.target_rappid,
                    "signed_twin_chat": True,
                    "signed_twin_chat_status": "verified",
                    "signed_twin_chat_verified": True,
                }
                result_text = json.dumps(
                    controller_result,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                state = IMessageState(config)
                supervisor = FakeSupervisor()
                bridge = IMessageBridge(
                    config,
                    state=state,
                    supervisor=supervisor,
                )
                try:
                    with patch.object(
                        orchestrator,
                        "_execute_tool",
                        return_value=(
                            result_text,
                            ("[RappStackCubbyController] completed",),
                        ),
                    ):
                        self.assertEqual(
                            bridge.process_message(owner_event(900)),
                            "replied",
                        )
                    self.assertEqual(
                        supervisor.requests[0][1]["text"],
                        "live signed child response",
                    )
                    self.assertEqual(len(orchestrator.provider.requests), 0)
                finally:
                    server.shutdown()
                    state.close()

    def test_pinned_v0123_notification_projects_known_fields_end_to_end(self) -> None:
        fixture = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "fixtures"
                / "imsg-v0.12.3-message-notification.json"
            ).read_text(encoding="utf-8")
        )
        with WorkDirectory() as root:
            config = make_config(
                root,
                account_id="E:synthetic-owner@invalid.example",
                owner_chat_ids=[
                    "42",
                    "iMessage;-;synthetic-owner-handle",
                ],
                stale_after_seconds=86400.0,
            )
            state = IMessageState(config)
            bridge = IMessageBridge(
                config,
                state=state,
                chat_runner=lambda *args: global_response_for_call(
                    "synthetic fixture response", args[3]
                ),
                supervisor=FakeSupervisor(),
            )
            bridge._subscription = 7
            fixture["params"]["future_additive"] = {"safe": True}
            fixture["params"]["message"]["future_additive"] = ["ignored"]
            bridge._on_notification(fixture["method"], fixture["params"])
            deadline = time.monotonic() + 2
            while (
                state.counts()["inbox_processed"] != 1
                and time.monotonic() < deadline
            ):
                time.sleep(0.01)
            self.assertEqual(state.counts()["inbox_processed"], 1)
            self.assertEqual(
                bridge.supervisor.requests[0][1]["text"],
                "synthetic fixture response",
            )
            malformed = dict(fixture["params"]["message"])
            malformed.update(
                {
                    "attachments": "wrong-type",
                    "guid": "synthetic-malformed-guid",
                    "id": 315,
                }
            )
            self.assertEqual(bridge.process_message(malformed), "invalid_event")
            mismatched = dict(fixture["params"]["message"])
            mismatched.update(
                {
                    "account_id": "E:other@invalid.example",
                    "guid": "synthetic-account-mismatch-guid",
                    "id": 316,
                }
            )
            self.assertEqual(
                bridge.process_message(mismatched),
                "owner_mismatch",
            )
            bridge.stop()
            state.close()

    def test_owner_turn_routes_global_controller_and_sends_exact_chat(self) -> None:
        with WorkDirectory() as root:
            config = make_config(root)
            state = IMessageState(config)
            calls: list[tuple[str, str, dict[str, object]]] = []

            def chat(prompt, history, session_id, context):
                self.assertEqual(history, [])
                calls.append((prompt, session_id, dict(context)))
                return global_response_for_call(
                    "synthetic child response",
                    context,
                    session_id="global-session",
                )

            supervisor = FakeSupervisor()
            bridge = IMessageBridge(
                config,
                state=state,
                chat_runner=chat,
                supervisor=supervisor,
            )
            self.assertEqual(bridge.process_message(owner_event(1)), "replied")
            self.assertEqual(calls[0][0], "synthetic owner turn")
            self.assertEqual(calls[0][1], "")
            self.assertTrue(calls[0][2]["audience"].startswith("imessage-owner-"))
            method, params, _timeout = supervisor.requests[0]
            self.assertEqual(method, "send")
            self.assertEqual(params["chat_id"], "synthetic-owner-chat")
            self.assertEqual(params["service"], "imessage")
            self.assertEqual(params["text"], "synthetic child response")
            self.assertEqual(state.get_global_session(), "global-session")
            bridge.process_message(owner_event(2, text="second turn"))
            self.assertEqual(calls[1][1], "global-session")
            state.close()

    def test_owner_policy_rejects_before_model(self) -> None:
        with WorkDirectory() as root:
            config = make_config(root)
            state = IMessageState(config)
            model_calls = 0

            def chat(*args):
                nonlocal model_calls
                model_calls += 1
                return global_response_for_call(
                    "synthetic child response",
                    args[3],
                )

            bridge = IMessageBridge(
                config,
                state=state,
                chat_runner=chat,
                supervisor=FakeSupervisor(),
            )
            cases = (
                ("group_not_allowed", {"is_group": True}),
                ("non_imessage", {"service": "sms"}),
                ("attachments_not_allowed", {"attachments": [{"name": "x"}]}),
                ("reactions_not_allowed", {"reactions": ["liked"]}),
                ("unknown_chat", {"chat_id": "other-chat"}),
                ("owner_mismatch", {"sender": "other-handle"}),
                ("invalid_event", {"is_from_me": "yes"}),
            )
            for rowid, (outcome, override) in enumerate(cases, 10):
                with self.subTest(outcome=outcome):
                    self.assertEqual(
                        bridge.process_message(owner_event(rowid, **override)),
                        outcome,
                    )
            self.assertEqual(model_calls, 0)
            self.assertEqual(bridge.supervisor.requests, [])
            state.close()

    def test_from_me_non_echo_and_same_text_remote_are_admitted(self) -> None:
        with WorkDirectory() as root:
            config = make_config(root)
            state = IMessageState(config)
            bridge = IMessageBridge(
                config,
                state=state,
                chat_runner=lambda *args: global_response_for_call(
                    "same text", args[3]
                ),
                supervisor=FakeSupervisor(),
            )
            self.assertEqual(bridge.process_message(owner_event(1)), "replied")
            remote = owner_event(
                2,
                guid="different-guid",
                text="same text",
                is_from_me=False,
            )
            self.assertEqual(bridge.process_message(remote), "replied")
            echo = owner_event(
                3,
                guid="synthetic-outbound-guid",
                text="same text",
            )
            self.assertEqual(bridge.process_message(echo), "outbound_echo")
            state.close()

    def test_missing_controller_evidence_is_retryable_and_never_sends(self) -> None:
        with WorkDirectory() as root:
            config = make_config(root)
            state = IMessageState(config)
            supervisor = FakeSupervisor()
            bridge = IMessageBridge(
                config,
                state=state,
                chat_runner=lambda *args: {
                    **global_response_for_call(
                        "synthetic child response", args[3]
                    ),
                    "controller_result": {"ok": True},
                },
                supervisor=supervisor,
            )
            self.assertEqual(bridge.process_message(owner_event(1)), "controller_failed")
            self.assertEqual(supervisor.requests, [])
            self.assertEqual(state.counts()["inbox_retryable"], 1)
            state.close()

    def test_proof_tamper_and_forged_log_marker_are_rejected(self) -> None:
        valid = global_response()
        cases = []
        tampered_response = json.loads(json.dumps(valid))
        tampered_response["response"] = "tampered"
        cases.append(tampered_response)
        tampered_result = json.loads(json.dumps(valid))
        tampered_result["controller_result"]["child"]["response"] = "tampered"
        cases.append(tampered_result)
        forged_marker = json.loads(json.dumps(valid))
        forged_marker["controller_result"] = {"ok": True}
        cases.append(forged_marker)
        false_ok = json.loads(json.dumps(valid))
        false_ok["controller_result"]["ok"] = False
        cases.append(false_ok)
        for value in cases:
            with self.subTest(value=value["response"]):
                with self.assertRaises(Exception):
                    validate_global_chat_response(
                        value,
                        max_response_chars=4096,
                        expected_request_sha256="a" * 64,
                        expected_instance_rappid=valid["result_proof"][
                            "instance_rappid"
                        ],
                    )

    def test_terminal_signed_rejection_is_never_sent_as_success(self) -> None:
        with WorkDirectory() as root:
            config = make_config(root)
            rejection = {
                "action": "chat",
                "agent": "RappStackCubbyController",
                "error": {
                    "code": "child_rejected",
                    "message": "Synthetic signed rejection.",
                },
                "instance_rappid": config.target_rappid,
                "key_epoch": 2,
                "ok": False,
                "signed_twin_chat": True,
                "signed_twin_chat_status": "rejected",
                "signed_twin_chat_verified": True,
                "terminal": True,
            }

            def chat(prompt, history, session_id, context):
                canonical = json.dumps(
                    rejection,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                result = global_response_for_call(canonical, context)
                result["response"] = canonical
                result["controller_result"] = rejection
                digest = hashlib.sha256(canonical.encode()).hexdigest()
                proof = result["result_proof"]
                proof["result_sha256"] = digest
                proof["controller_result_sha256"] = digest
                proof["child_response_sha256"] = digest
                proof["instance_rappid"] = config.target_rappid
                proof["key_epoch"] = 2
                proof["signed_twin_chat_status"] = "rejected"
                proof["status"] = "rejected"
                return result

            state = IMessageState(config)
            supervisor = FakeSupervisor()
            bridge = IMessageBridge(
                config,
                state=state,
                chat_runner=chat,
                supervisor=supervisor,
            )
            self.assertEqual(
                bridge.process_message(owner_event(701)),
                "controller_rejected",
            )
            self.assertEqual(supervisor.requests, [])
            state.close()

    def test_staged_crash_recovery_avoids_second_model_call(self) -> None:
        with WorkDirectory() as root:
            config = make_config(root)
            state = IMessageState(config)
            prepared_bridge = IMessageBridge(
                config,
                state=state,
                chat_runner=lambda *args: (_ for _ in ()).throw(
                    AssertionError("model must not run")
                ),
                supervisor=FakeSupervisor(),
            )
            prepared = prepared_bridge._prepare_message(owner_event(1))
            event = state.claim_event(
                prepared["rowid"],
                prepared["guid"],
                prepared_bridge._private_payload(prepared),
            )
            state.stage_controller_result(
                event,
                conversation_hmac=state.owner_session_key(),
                target_hmac=prepared["target_hmac"],
                target_kind=prepared["target_kind"],
                user_text=prepared["text"],
                response_text="already staged",
                global_session_id="global-session",
            )
            self.assertEqual(prepared_bridge._process_claim(event), "replied")
            self.assertEqual(
                prepared_bridge.supervisor.requests[0][1]["text"],
                "already staged",
            )
            state.close()

    def test_ambiguous_send_is_unknown_and_never_resent(self) -> None:
        with WorkDirectory() as root:
            config = make_config(root)
            state = IMessageState(config)
            supervisor = FakeSupervisor(ImsgRpcAmbiguous("unknown"))
            bridge = IMessageBridge(
                config,
                state=state,
                chat_runner=lambda *args: global_response_for_call(
                    "synthetic child response", args[3]
                ),
                supervisor=supervisor,
            )
            event = owner_event(1)
            self.assertEqual(bridge.process_message(event), "send_unknown")
            self.assertEqual(bridge.process_message(event), "duplicate")
            self.assertEqual(len(supervisor.requests), 1)
            self.assertEqual(state.counts()["outbox_unknown"], 1)
            state.close()

    def test_ok_without_guid_recovers_one_shot_echo_without_feedback(self) -> None:
        fixtures = Path(__file__).resolve().parents[1] / "fixtures"
        send_envelope = json.loads(
            (fixtures / "imsg-v0.12.3-send-ok-no-guid.json").read_text(
                encoding="utf-8"
            )
        )
        catalog = json.loads(
            (fixtures / "imsg-v0.12.3-rpc-chats-list.json").read_text(
                encoding="utf-8"
            )
        )
        notification = json.loads(
            (fixtures / "imsg-v0.12.3-message-notification.json").read_text(
                encoding="utf-8"
            )
        )

        class CatalogClient:
            def request(self, method, params=None, timeout=None):
                self_method = method
                if self_method != "chats.list":
                    raise AssertionError(self_method)
                return catalog

        with WorkDirectory() as root:
            config = make_config(
                root,
                account_id="E:synthetic-owner@invalid.example",
                owner_chat_ids=["42", "iMessage;-;synthetic-owner-handle"],
                stale_after_seconds=86400.0,
            )
            state = IMessageState(config)
            model_calls: list[str] = []

            def chat(prompt, history, session_id, context):
                model_calls.append(prompt)
                return global_response_for_call(
                    "synthetic fixture response",
                    context,
                )

            supervisor = FakeSupervisor(send_envelope["result"])
            bridge = IMessageBridge(
                config,
                state=state,
                chat_runner=chat,
                supervisor=supervisor,
            )
            bridge._refresh_chat_catalog(CatalogClient())
            first = dict(notification["params"]["message"])
            self.assertNotIn("account_id", first)
            self.assertEqual(bridge.process_message(first), "send_unknown")
            self.assertEqual(bridge.process_message(first), "duplicate")
            self.assertEqual(len(supervisor.requests), 1)

            echo = dict(first)
            echo.update(
                {
                    "guid": "synthetic-no-guid-send-echo",
                    "id": 315,
                    "text": "synthetic fixture response",
                }
            )
            self.assertEqual(
                bridge.process_message(echo),
                "ambiguous_outbound_echo",
            )
            self.assertEqual(model_calls, ["synthetic pinned payload turn"])

            remote = dict(echo)
            remote.update(
                {
                    "guid": "synthetic-remote-same-text",
                    "id": 316,
                    "is_from_me": False,
                }
            )
            self.assertEqual(bridge.process_message(remote), "send_unknown")
            self.assertEqual(
                model_calls,
                [
                    "synthetic pinned payload turn",
                    "synthetic fixture response",
                ],
            )
            second_echo = dict(echo)
            second_echo.update(
                {
                    "guid": "synthetic-second-no-guid-send-echo",
                    "id": 317,
                }
            )
            self.assertEqual(
                bridge.process_message(second_echo),
                "ambiguous_outbound_echo",
            )
            self.assertEqual(len(model_calls), 2)
            self.assertEqual(len(supervisor.requests), 2)
            self.assertEqual(state.counts()["outbox_unknown"], 2)
            bridge.stop()
            state.close()

    def test_live_shape_uses_private_catalog_account_and_rejects_rebind(self) -> None:
        fixtures = Path(__file__).resolve().parents[1] / "fixtures"
        catalog = json.loads(
            (fixtures / "imsg-v0.12.3-rpc-chats-list.json").read_text(
                encoding="utf-8"
            )
        )
        notification = json.loads(
            (fixtures / "imsg-v0.12.3-message-notification.json").read_text(
                encoding="utf-8"
            )
        )

        class Client:
            def __init__(self, chats):
                self.chats = chats

            def request(self, method, params=None, timeout=None):
                if method == "chats.list":
                    return self.chats
                if method == "watch.subscribe":
                    return {"subscription": 7}
                raise AssertionError(method)

        bindings = [
            OwnerChatBinding(
                ("42", "iMessage;-;synthetic-owner-handle"),
                "E:synthetic-owner@invalid.example",
            ),
            OwnerChatBinding(
                ("42", "iMessage;-;synthetic-owner-handle"),
                "E:changed@invalid.example",
            ),
        ]

        def discover(*args, **kwargs):
            return bindings.pop(0)

        with WorkDirectory() as root:
            config = make_config(
                root,
                account_id="E:synthetic-owner@invalid.example",
                owner_chat_ids=["42", "iMessage;-;synthetic-owner-handle"],
                stale_after_seconds=86400.0,
            )
            state = IMessageState(config)
            bridge = IMessageBridge(
                config,
                state=state,
                chat_runner=lambda *args: global_response_for_call(
                    "catalog-bound response", args[3]
                ),
                supervisor=FakeSupervisor(),
                binding_discoverer=discover,
            )
            bridge._started = True
            bridge._on_ready(Client(catalog))
            message = dict(notification["params"]["message"])
            self.assertNotIn("account_id", message)
            self.assertEqual(bridge.process_message(message), "replied")

            with self.assertRaises(IMessageBridgeError):
                bridge._on_ready(Client(catalog))
            changed = dict(message)
            changed.update({"guid": "synthetic-after-rebind", "id": 318})
            self.assertEqual(
                bridge.process_message(changed),
                "owner_binding_unverified",
            )
            bridge.stop()
            state.close()

    def test_watch_errors_require_exact_acknowledged_subscription(self) -> None:
        with WorkDirectory() as root:
            config = make_config(root)
            state = IMessageState(config)
            supervisor = FakeSupervisor()
            bridge = IMessageBridge(
                config,
                state=state,
                supervisor=supervisor,
            )
            bridge._subscription = 7
            bridge._on_notification("error", {"subscription": 8})
            bridge._on_notification("error", {})
            self.assertEqual(supervisor.restart_count, 0)
            bridge._on_notification("error", {"subscription": 7})
            self.assertEqual(supervisor.restart_count, 1)
            bridge.stop()
            state.close()

    def test_timeout_restart_reuses_exact_persisted_controller_route(self) -> None:
        class AmbiguousReplayRunner:
            def __init__(self) -> None:
                self.calls: list[tuple[str, str]] = []
                self.controller_executions = 0
                self.cached: dict[str, object] | None = None

            def __call__(self, prompt, history, session_id, context):
                self.calls.append(
                    (
                        context["idempotency_key"],
                        context["route_request"],
                    )
                )
                if self.cached is None:
                    self.controller_executions += 1
                    self.cached = global_response_for_call(
                        "idempotent response", context
                    )
                    raise TimeoutError("ambiguous global timeout")
                return self.cached

        with WorkDirectory() as root:
            config = make_config(root)
            runner = AmbiguousReplayRunner()
            first_state = IMessageState(config)
            first = IMessageBridge(
                config,
                state=first_state,
                chat_runner=runner,
                supervisor=FakeSupervisor(),
            )
            event = owner_event(501)
            self.assertEqual(
                first.process_message(event),
                "controller_failed",
            )
            event_digest = first_state.event_digest_for_guid(event["guid"])
            first.stop()
            first_state.close()

            recovered = IMessageState(config)
            recovered.recover_after_restart()
            with recovered._transaction():
                recovered._db.execute(
                    "UPDATE inbox SET next_retry=0 WHERE event_digest=?",
                    (event_digest,),
                )
            second = IMessageBridge(
                config,
                state=recovered,
                chat_runner=runner,
                supervisor=FakeSupervisor(),
            )
            self.assertEqual(
                second._process_claim(event_digest),
                "replied",
            )
            self.assertEqual(runner.controller_executions, 1)
            self.assertEqual(len(runner.calls), 2)
            self.assertEqual(runner.calls[0], runner.calls[1])
            self.assertTrue(runner.calls[0][0].startswith("imessage-"))
            second.stop()
            recovered.close()

    def test_send_result_target_or_service_mismatch_is_terminal_unknown(self) -> None:
        for result in (
            {
                "ok": True,
                "guid": "synthetic-outbound",
                "service": "SMS",
            },
            {
                "ok": True,
                "guid": "synthetic-outbound",
                "chat_id": "different-chat",
            },
        ):
            with self.subTest(result=result), WorkDirectory() as root:
                config = make_config(root)
                state = IMessageState(config)
                supervisor = FakeSupervisor(result)
                bridge = IMessageBridge(
                    config,
                    state=state,
                    chat_runner=lambda *args: global_response_for_call(
                        "send target proof", args[3]
                    ),
                    supervisor=supervisor,
                )
                event = owner_event(601)
                self.assertEqual(
                    bridge.process_message(event),
                    "send_unknown",
                )
                self.assertEqual(bridge.process_message(event), "duplicate")
                self.assertEqual(len(supervisor.requests), 1)
                state.close()

    def test_supervisor_exhaustion_exits_and_releases_writer_lease(self) -> None:
        class TerminalSupervisor:
            is_ready = False
            restart_count = 8
            last_error = "restart_limit"
            terminal = False

            def start(self):
                self.terminal = True

            def stop(self):
                return None

        with WorkDirectory() as root:
            config = make_config(root)
            state = IMessageState(config)
            bridge = IMessageBridge(
                config,
                state=state,
                supervisor=TerminalSupervisor(),
                transport_verifier=lambda *args, **kwargs: {"ok": True},
            )
            with patch(
                "rapp_stack_cubby.imessage.cli.discover_owner_binding",
                return_value=OwnerChatBinding(
                    tuple(config.owner_chat_ids),
                    config.account_id,
                ),
            ), self.assertRaises(IMessageBridgeError):
                bridge.run_forever()
            self.assertEqual(state.read_status()["lifecycle"], "failed")
            self.assertTrue(state.acquire_lease("replacement"))
            state.release_lease("replacement")
            state.close()

    def test_routing_instruction_contains_structured_exact_arguments(self) -> None:
        message = "synthetic message\nwith unicode λ"
        instruction = build_routing_instruction(
            message,
            target_rappid=(
                "rappid:@sample-owner/sample-twin:"
                "0000000000000000000000000000000000000000000000000000000000000000"
            ),
            audience="imessage-owner-0000",
            max_chars=10000,
        )
        route = json.loads(instruction.splitlines()[-1])
        self.assertEqual(route["arguments"]["message"], message)
        self.assertEqual(route["action"], "chat")
        self.assertEqual(route["tool"], "RappStackCubbyController")
        self.assertEqual(route["schema"], "rapp-controller-route/1.0")
        self.assertEqual(
            instruction.splitlines()[0], "RAPP_CONTROLLER_ROUTE/1.0"
        )

    def test_loopback_runner_sets_host_and_validates_evidence(self) -> None:
        captured: dict[str, object] = {}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                challenge = decode_auth_value(
                    self.headers[AUTH_CHALLENGE_HEADER]
                )
                body = json.dumps(
                    {
                        "ready": True,
                        "status": "ok",
                        "version": "synthetic",
                    }
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header(
                    AUTH_PROOF_HEADER,
                    auth_challenge_proof(b"\x42" * 32, challenge),
                )
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                length = int(self.headers["Content-Length"])
                captured["host"] = self.headers["Host"]
                captured["authorization"] = self.headers["Authorization"]
                captured["path"] = self.path
                captured["request"] = json.loads(self.rfile.read(length))
                body = json.dumps(
                    global_response(
                        request_sha256=hashlib.sha256(
                            captured["request"]["user_input"].encode()
                        ).hexdigest()
                    )
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with WorkDirectory() as root:
                config = make_config(
                    root,
                    global_controller_url=(
                        f"http://127.0.0.1:{server.server_address[1]}/chat"
                    ),
                )
                result = LoopbackGlobalChatRunner(config)(
                    "synthetic owner turn",
                    [],
                    "",
                    {
                        "audience": "imessage-owner-0000",
                        "idempotency_key": "imessage-test-route",
                    },
                )
                self.assertEqual(result["response"], "synthetic child response")
                self.assertEqual(captured["path"], "/chat")
                self.assertEqual(
                    captured["host"], f"127.0.0.1:{server.server_address[1]}"
                )
                self.assertTrue(
                    captured["authorization"].startswith("Bearer ")
                )
                self.assertIn(
                    "RAPP_CONTROLLER_ROUTE/1.0",
                    captured["request"]["user_input"],
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_rogue_port_without_token_never_receives_owner_content(self) -> None:
        observed = {"posts": 0}

        class RogueHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'{"ready":true,"status":"ok","version":"rogue"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header(AUTH_PROOF_HEADER, "A" * 43)
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                observed["posts"] += 1
                observed["body"] = self.rfile.read(
                    int(self.headers["Content-Length"])
                )
                self.send_response(500)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, format, *args):
                return

        server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0),
            RogueHandler,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with WorkDirectory() as root:
                config = make_config(
                    root,
                    global_controller_url=(
                        f"http://127.0.0.1:{server.server_address[1]}/chat"
                    ),
                )
                with self.assertRaises(Exception):
                    LoopbackGlobalChatRunner(config)(
                        "owner content sentinel",
                        [],
                        "",
                        {
                            "audience": "imessage-owner-0000",
                            "idempotency_key": "rogue-route",
                        },
                    )
                self.assertEqual(observed["posts"], 0)
                self.assertNotIn("body", observed)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
