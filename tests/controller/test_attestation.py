from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from rapp_stack_cubby.runtime.config import SignedIngressConfig
from rapp_stack_cubby.runtime.orchestrator import Orchestrator
from rapp_stack_cubby.runtime.provider import (
    ATTESTATION_MODEL,
    AttestationProvider,
)
from rapp_stack_cubby.runtime.registry import AgentRegistry
from rapp_stack_cubby.runtime.server import RuntimeServer
from rapp_stack_cubby.runtime.storage import LocalStorage

from ._support import ControllerEnvironment, RAPPID, REPOSITORY_ROOT, decoded

INTERNAL_AGENTS = (
    REPOSITORY_ROOT
    / "cubbies/kody-w/rapplications/rapp-stack/twin/agents"
)
SOUL = (
    REPOSITORY_ROOT
    / "cubbies/kody-w/rapplications/rapp-stack/twin/soul.md"
)


class OfflineAttestationTests(unittest.TestCase):
    def test_attestation_child_diagnostics_are_unbuffered(self):
        with ControllerEnvironment() as environment:
            twin = environment.create_twin()
            state = dict(environment.globals["_load_state"](twin))
            state["attestation_mode"] = "offline-self-test"
            child_environment = environment.globals["_child_environment"](
                twin,
                state,
            )

        self.assertEqual(child_environment["PYTHONUNBUFFERED"], "1")

    def test_real_signed_loopback_self_test_is_content_free(self):
        with ControllerEnvironment() as environment:
            twin = environment.create_twin()
            state = environment.globals["_load_state"](twin)
            controller, pairing = environment.globals[
                "_ensure_twin_transport"
            ](environment.controller_data, twin, state)
            state = dict(state)
            state["transport"] = environment.globals["_transport_state"](
                pairing
            )
            state["selected_model"] = ATTESTATION_MODEL
            state["attestation_mode"] = "offline-self-test"
            environment.globals["_write_state"](twin, state)

            provider = AttestationProvider()
            orchestrator = Orchestrator(
                soul_path=SOUL,
                registry=AgentRegistry(
                    INTERNAL_AGENTS,
                    storage=LocalStorage(twin / "workspace/data"),
                ),
                provider=provider,
                model=ATTESTATION_MODEL,
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
                port=0,
                instance_id="offline-attestation-child",
            )
            server.start()
            process = {
                "pid": os.getpid(),
                "pgid": os.getpgid(os.getpid()),
                "port": server.port,
                "started_at": "2026-07-13T00:00:00Z",
                "start_identity": "c" * 64,
                "instance_id": "offline-attestation-child",
                "command_sha256": "a" * 64,
                "model": ATTESTATION_MODEL,
                "attestation_mode": "offline-self-test",
                "provider_timeout": 30.0,
                "signed_only": True,
            }
            state = environment.globals["_load_state"](twin)
            state = dict(state)
            state["runtime_status"] = "running"
            state["process"] = process
            environment.globals["_write_state"](twin, state)
            generated = environment.root / "generated"
            generated.mkdir(mode=0o700)
            try:
                with patch.dict(
                    os.environ,
                    {
                        "RAPP_STACK_ROOT": str(REPOSITORY_ROOT),
                        "RAPP_STACK_DATA_DIR": str(
                            twin / "workspace/data"
                        ),
                        "RAPP_STACK_GENERATED_AGENTS_DIR": str(generated),
                        "RAPP_STACK_PRINCIPAL": "attestation-test",
                    },
                    clear=False,
                ), patch.dict(
                    environment.globals,
                    {
                        "_leader_identity_matches": lambda process: True,
                        "_health_matches": lambda process: True,
                    },
                ):
                    result = decoded(
                        environment.agent,
                        action="self_test",
                        rappid=RAPPID,
                        idempotency_key="offline-attestation",
                    )
            finally:
                server.shutdown()

        self.assertTrue(result["ok"], result)
        self.assertTrue(result["passed"])
        self.assertEqual(result["child"]["response"], "")
        self.assertEqual(len(provider.requests), 2)
        self.assertEqual(
            provider.requests[0].model,
            ATTESTATION_MODEL,
        )

    def test_attestation_start_skips_live_model_preflight(self):
        child = unittest.mock.Mock(pid=65000)
        child.poll.return_value = None
        with ControllerEnvironment() as environment:
            environment.create_twin()
            with patch.object(
                environment.globals["subprocess"],
                "Popen",
                return_value=child,
            ) as popen, patch.object(
                environment.globals["os"],
                "getpgid",
                return_value=65000,
            ), patch.dict(
                environment.globals,
                {
                    "_validate_python": lambda selected=None: (
                        "/opt/homebrew/bin/python3.11"
                    ),
                    "_preflight_model": unittest.mock.Mock(
                        side_effect=AssertionError("live preflight called")
                    ),
                    "_process_start_identity": lambda pid: "d" * 64,
                    "_wait_health": lambda port, instance, timeout: True,
                },
            ):
                result = decoded(
                    environment.agent,
                    action="start",
                    rappid=RAPPID,
                    model=ATTESTATION_MODEL,
                    attestation_mode="offline-self-test",
                    idempotency_key="attestation-start",
                )
        self.assertTrue(result["ok"], result)
        argv = popen.call_args.args[0]
        self.assertEqual(
            argv[argv.index("--attestation-mode") + 1],
            "offline-self-test",
        )
        self.assertIn("--signed-only", argv)
