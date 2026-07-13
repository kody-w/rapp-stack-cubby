from __future__ import annotations

import json
import os
import signal
import unittest
from unittest.mock import Mock, patch

from ._support import (
    ControllerEnvironment,
    IDENTITY_HASH,
    RAPPID,
    decoded,
)


class ControllerProcessTests(unittest.TestCase):
    def test_start_requires_explicit_model_before_process_creation(self):
        with ControllerEnvironment() as environment:
            environment.create_twin()
            result = decoded(
                environment.agent,
                action="start",
                rappid=RAPPID,
                idempotency_key="missing-model",
            )
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "model_invalid")

    def test_live_start_requires_safe_explicit_provider_token_file(self):
        with ControllerEnvironment() as environment:
            environment.create_twin()
            missing = decoded(
                environment.agent,
                action="start",
                rappid=RAPPID,
                model="synthetic-test-model",
                idempotency_key="missing-provider-auth",
            )
            token = environment.create_provider_token()
            os.chmod(token, 0o644)
            unsafe_mode = decoded(
                environment.agent,
                action="start",
                rappid=RAPPID,
                model="synthetic-test-model",
                github_token_file=str(token),
                idempotency_key="unsafe-provider-auth",
            )
            os.chmod(token, 0o600)
            linked = environment.root / "linked-provider-token.json"
            linked.symlink_to(token)
            symlinked = decoded(
                environment.agent,
                action="start",
                rappid=RAPPID,
                model="synthetic-test-model",
                github_token_file=str(linked),
                idempotency_key="linked-provider-auth",
            )

        self.assertEqual(
            missing["error"]["code"], "provider_auth_invalid"
        )
        self.assertEqual(
            unsafe_mode["error"]["code"], "provider_auth_invalid"
        )
        self.assertEqual(
            symlinked["error"]["code"], "provider_auth_invalid"
        )

    def test_start_uses_fixed_python_argv_new_group_and_redacted_environment(self):
        fake_child = Mock()
        fake_child.pid = 54321
        fake_child.poll.return_value = None
        popen = Mock(return_value=fake_child)
        with ControllerEnvironment() as environment:
            environment.create_twin()
            provider_token = environment.create_provider_token()
            status_path = environment.root / "imessage-status.json"
            status_path.write_text("{}\n", encoding="utf-8")
            os.chmod(status_path, 0o600)
            with patch.dict(
                os.environ,
                {
                    "GITHUB_TOKEN": "must-not-be-copied",
                    "RAPP_STACK_IMESSAGE_CONFIG": "must-not-be-copied",
                    "RAPP_STACK_IMESSAGE_STATUS": str(status_path),
                },
                clear=False,
            ), patch.object(
                environment.globals["subprocess"],
                "Popen",
                popen,
            ), patch.dict(
                environment.globals,
                {
                    "_validate_python": (
                        lambda: "/opt/homebrew/bin/python3.11"
                    ),
                    "_preflight_model": (
                        lambda python, source, model, token_file: model
                    ),
                    "_process_start_identity": lambda pid: "c" * 64,
                    "_wait_health": lambda port, instance, timeout: True,
                },
            ), patch.object(
                environment.globals["os"], "getpgid", side_effect=lambda pid: pid
            ):
                result = decoded(
                    environment.agent,
                    action="start",
                    rappid=RAPPID,
                    model="synthetic-test-model",
                    github_token_file=str(provider_token),
                    port=43210,
                    idempotency_key="start-process",
                )

            state = json.loads(
                (
                    environment.controller_data
                    / "twins/active"
                    / IDENTITY_HASH
                    / "state.json"
                ).read_text(encoding="utf-8")
            )
            receipt_bytes = b"".join(
                path.read_bytes()
                for path in (
                    environment.controller_data / "receipts"
                ).glob("*.json")
            )
            controller_bytes = b"".join(
                path.read_bytes()
                for path in environment.controller_data.rglob("*")
                if path.is_file()
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "running")
        argv = popen.call_args.args[0]
        self.assertEqual(argv[0], "/opt/homebrew/bin/python3.11")
        self.assertEqual(argv[1:4], ["-m", "rapp_stack_cubby", "serve"])
        self.assertIn("--instance-id", argv)
        self.assertIn("--root", argv)
        self.assertIn("--principal", argv)
        self.assertIn("--generated-agents-dir", argv)
        self.assertIn("--allow-agent-writes", argv)
        self.assertIn("--signed-only", argv)
        self.assertEqual(
            argv[argv.index("--model") + 1], "synthetic-test-model"
        )
        self.assertEqual(
            argv[argv.index("--github-token-file") + 1],
            str(provider_token),
        )
        self.assertIn("--twin-rappid", argv)
        self.assertIn("--child-private-key", argv)
        self.assertIn("--paired-controller-public-jwk", argv)
        self.assertIn("--paired-controller-rappid", argv)
        self.assertIn("--replay-db", argv)
        self.assertEqual(
            argv[argv.index("--signed-ingress-key-epoch") + 1], "1"
        )
        self.assertEqual(
            argv[argv.index("--provider-timeout") + 1], "30.0"
        )
        self.assertIs(popen.call_args.kwargs["shell"], False)
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertNotIn(
            "GITHUB_TOKEN", popen.call_args.kwargs["env"]
        )
        self.assertNotIn(
            "RAPP_STACK_IMESSAGE_CONFIG",
            popen.call_args.kwargs["env"],
        )
        self.assertEqual(
            popen.call_args.kwargs["env"]["RAPP_STACK_IMESSAGE_STATUS"],
            str(status_path),
        )
        self.assertEqual(state["process"]["command_sha256"], result["command_sha256"])
        self.assertNotIn("command", state["process"])
        serialized_state = json.dumps(state)
        self.assertNotIn(str(provider_token), serialized_state)
        self.assertNotIn("synthetic-controller-access", serialized_state)
        self.assertNotIn(str(provider_token).encode(), receipt_bytes)
        self.assertNotIn(b"synthetic-controller-access", receipt_bytes)
        self.assertNotIn(str(provider_token).encode(), controller_bytes)
        self.assertNotIn(b"synthetic-controller-access", controller_bytes)

    def test_failed_health_terminates_exact_spawn_and_preserves_stopped_workspace(self):
        fake_child = Mock()
        fake_child.pid = 54322
        popen = Mock(return_value=fake_child)
        terminate = Mock()
        with ControllerEnvironment() as environment:
            environment.create_twin()
            provider_token = environment.create_provider_token()
            observed_starting = {}

            def fail_health(port, instance, timeout):
                del port, instance, timeout
                state = json.loads(
                    (
                        environment.controller_data
                        / "twins/active"
                        / IDENTITY_HASH
                        / "state.json"
                    ).read_text(encoding="utf-8")
                )
                observed_starting.update(state)
                return False

            with patch.object(
                environment.globals["subprocess"],
                "Popen",
                popen,
            ), patch.dict(
                environment.globals,
                {
                    "_validate_python": (
                        lambda: "/opt/homebrew/bin/python3.11"
                    ),
                    "_preflight_model": (
                        lambda python, source, model, token_file: model
                    ),
                    "_process_start_identity": lambda pid: "c" * 64,
                    "_wait_health": fail_health,
                    "_terminate_spawned": terminate,
                },
            ):
                result = decoded(
                    environment.agent,
                    action="start",
                    rappid=RAPPID,
                    model="synthetic-test-model",
                    github_token_file=str(provider_token),
                    port=43211,
                    idempotency_key="start-health-failure",
                )
            state_path = (
                environment.controller_data
                / "twins/active"
                / IDENTITY_HASH
                / "state.json"
            )
            state = json.loads(state_path.read_text(encoding="utf-8"))

        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "health_failed")
        terminate.assert_called_once_with(fake_child, fake_child.pid)
        self.assertEqual(state["runtime_status"], "stopped")
        self.assertIsNone(state["process"])
        self.assertEqual(observed_starting["runtime_status"], "starting")
        self.assertEqual(observed_starting["process"]["pid"], 54322)
        self.assertEqual(
            observed_starting["process"]["start_identity"], "c" * 64
        )

    def test_stop_escalates_only_the_recorded_process_group(self):
        process = {
            "pid": 60001,
            "pgid": 60001,
            "port": 43212,
            "instance_id": "expected-instance",
        }
        with ControllerEnvironment() as environment:
            killpg = Mock()
            with patch.object(
                environment.globals["os"], "killpg", killpg
            ), patch.dict(
                environment.globals,
                {
                    "_process_group": lambda value: 60001,
                    "_health_probe": lambda port: {
                        "instance_id": "expected-instance"
                    },
                    "_wait_process_exit": Mock(
                        side_effect=[False, True]
                    ),
                    "_wait_group_exit": lambda pgid, timeout: True,
                },
            ):
                escalated = environment.globals["_terminate_recorded"](
                    process
                )

        self.assertTrue(escalated)
        self.assertEqual(
            killpg.call_args_list,
            [
                unittest.mock.call(60001, signal.SIGTERM),
                unittest.mock.call(60001, signal.SIGKILL),
            ],
        )

    def test_pid_or_port_reuse_with_wrong_instance_is_never_signalled(self):
        process = {
            "pid": 60002,
            "pgid": 60002,
            "port": 43213,
            "instance_id": "expected-instance",
        }
        with ControllerEnvironment() as environment:
            killpg = Mock()
            with patch.object(
                environment.globals["os"], "killpg", killpg
            ), patch.dict(
                environment.globals,
                {
                    "_process_group": lambda value: 60002,
                    "_health_probe": lambda port: {
                        "instance_id": "different-instance"
                    },
                },
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "process_identity_mismatch"
                ):
                    environment.globals["_terminate_recorded"](process)

        killpg.assert_not_called()

    def test_pid_reuse_with_wrong_start_identity_is_never_signalled(self):
        process = {
            "pid": 60003,
            "pgid": 60003,
            "port": 43214,
            "instance_id": "expected-instance",
            "start_identity": "a" * 64,
        }
        with ControllerEnvironment() as environment:
            killpg = Mock()
            with patch.object(
                environment.globals["os"], "getpgid", return_value=60003
            ), patch.object(
                environment.globals["os"], "killpg", killpg
            ), patch.dict(
                environment.globals,
                {"_process_start_identity": lambda pid: "b" * 64},
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "process_identity_mismatch"
                ):
                    environment.globals["_terminate_recorded"](process)
        killpg.assert_not_called()

    def test_dead_leader_does_not_hide_live_recorded_process_group(self):
        process = {
            "pid": 60004,
            "pgid": 60004,
            "port": 43215,
            "instance_id": "expected-instance",
            "start_identity": "a" * 64,
        }
        with ControllerEnvironment() as environment:
            killpg = Mock()
            with patch.object(
                environment.globals["os"],
                "getpgid",
                side_effect=ProcessLookupError,
            ), patch.object(
                environment.globals["os"], "killpg", killpg
            ), patch.dict(
                environment.globals,
                {
                    "_group_alive": Mock(side_effect=[True, True]),
                    "_command_owns_group": lambda record: True,
                    "_health_probe": lambda port: {
                        "instance_id": "expected-instance"
                    },
                    "_wait_process_exit": lambda pid, timeout: True,
                    "_wait_group_exit": lambda pgid, timeout: True,
                },
            ):
                escalated = environment.globals["_terminate_recorded"](
                    process
                )
        self.assertTrue(escalated)
        self.assertEqual(
            killpg.call_args_list,
            [
                unittest.mock.call(60004, signal.SIGTERM),
                unittest.mock.call(60004, signal.SIGKILL),
            ],
        )

    def test_source_contains_no_name_based_process_kill(self):
        with ControllerEnvironment() as environment:
            source = environment.agent.perform.__globals__
            code = environment.agent.perform.__code__

        self.assertNotIn("pkill", code.co_names)
        self.assertNotIn("killall", code.co_names)
        self.assertIn("_stop", source["RappStackCubbyController"].__dict__)


if __name__ == "__main__":
    unittest.main()
