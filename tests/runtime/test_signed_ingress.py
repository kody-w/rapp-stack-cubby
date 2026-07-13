from __future__ import annotations

import json
import os
import sqlite3
import unittest
from unittest.mock import patch

from rapp_stack_cubby.protocols import (
    canonical_json_text,
    create_transport_keypair,
    load_private_key,
    request_digest,
    sign_request,
    verify_response,
)
from rapp_stack_cubby.protocols.replay import ReplayJournal
from rapp_stack_cubby.runtime.config import (
    RuntimeConfig,
    RuntimeConfigurationError,
    SignedIngressConfig,
)
from rapp_stack_cubby.runtime.orchestrator import (
    Orchestrator,
    OrchestratorProviderError,
    RequestValidationError,
)
from rapp_stack_cubby.runtime.provider import (
    ProviderResponse,
    ProviderTransportError,
    ScriptedProvider,
)
from rapp_stack_cubby.runtime.registry import AgentRegistry
from rapp_stack_cubby.runtime.storage import LocalStorage

from ._support import RuntimeFixture


class SignedIngressRuntimeTests(unittest.TestCase):
    def _runtime(
        self, fixture, responses, *, signed_only=False, key_epoch=1
    ):
        os.chmod(fixture.data, 0o700)
        transport = fixture.data / "twin-chat"
        controller = create_transport_keypair(
            transport / "controller/private.pem",
            transport / "controller/public.jwk",
        )
        child = create_transport_keypair(
            transport / "child/private.pem",
            transport / "child/public.jwk",
        )
        controller_rappid = (
            "rappid:@kody-w/rapp-stack-cubby-controller:"
            + controller.key_id
        )
        twin_rappid = (
            "rappid:@kody-w/synthetic-runtime-twin:" + "1" * 64
        )
        provider = ScriptedProvider(responses)
        orchestrator = Orchestrator(
            soul_path=fixture.soul,
            registry=AgentRegistry(
                fixture.agents,
                storage=LocalStorage(fixture.data),
                compatibility_mode=True,
            ),
            provider=provider,
            model="synthetic-provider",
            signed_ingress=SignedIngressConfig(
                twin_rappid=twin_rappid,
                child_private_key_path=child.private_key_path,
                paired_controller_public_jwk_path=controller.public_jwk_path,
                paired_controller_rappid=controller_rappid,
                replay_db_path=transport / "replay.sqlite3",
                key_epoch=key_epoch,
            ),
            signed_only=signed_only,
        )
        return (
            orchestrator,
            provider,
            controller,
            child,
            controller_rappid,
            twin_rappid,
        )

    def test_runtime_config_requires_complete_contained_private_ingress_paths(self):
        with RuntimeFixture() as fixture:
            os.chmod(fixture.data, 0o700)
            controller = create_transport_keypair(
                fixture.data / "transport/controller-private.pem",
                fixture.data / "transport/controller-public.jwk",
            )
            child = create_transport_keypair(
                fixture.data / "transport/child-private.pem",
                fixture.data / "transport/child-public.jwk",
            )
            controller_rappid = (
                "rappid:@kody-w/rapp-stack-cubby-controller:"
                + controller.key_id
            )
            twin_rappid = (
                "rappid:@kody-w/synthetic-runtime-twin:" + "1" * 64
            )
            config = RuntimeConfig(
                soul_path=fixture.soul,
                agent_directories=(fixture.agents,),
                data_root=fixture.data,
                instance_id="signed-config",
                root=fixture.root,
                principal="signed-principal",
                model="synthetic-provider",
                twin_rappid=twin_rappid,
                child_private_key_path=child.private_key_path,
                paired_controller_public_jwk_path=controller.public_jwk_path,
                paired_controller_rappid=controller_rappid,
                replay_db_path=fixture.data / "transport/replay.sqlite3",
                signed_ingress_key_epoch=7,
                signed_only=True,
            )
            self.assertEqual(config.signed_ingress.twin_rappid, twin_rappid)
            self.assertEqual(config.signed_ingress.key_epoch, 7)
            self.assertTrue(config.signed_only)
            with self.assertRaises(RuntimeConfigurationError):
                RuntimeConfig(
                    soul_path=fixture.soul,
                    agent_directories=(fixture.agents,),
                    data_root=fixture.data,
                    instance_id="incomplete-signed-config",
                    root=fixture.root,
                    principal="signed-principal",
                    model="synthetic-provider",
                    twin_rappid=twin_rappid,
                )
            with self.assertRaises(RuntimeConfigurationError):
                RuntimeConfig(
                    soul_path=fixture.soul,
                    agent_directories=(fixture.agents,),
                    data_root=fixture.data,
                    instance_id="signed-only-without-ingress",
                    root=fixture.root,
                    principal="signed-principal",
                    model="synthetic-provider",
                    signed_only=True,
                )

    def test_signed_only_rejects_plain_chat_before_provider(self):
        with RuntimeFixture() as fixture:
            orchestrator, provider, *_unused = self._runtime(
                fixture, [], signed_only=True
            )
            with self.assertRaisesRegex(
                RequestValidationError, "signed_only"
            ):
                orchestrator.chat({"user_input": "plain owner route"})
            with self.assertRaisesRegex(
                RequestValidationError, "signed_only"
            ):
                orchestrator.chat(
                    {"user_input": '{"schema":"unrelated/1.0"}'}
                )
            self.assertEqual(provider.requests, ())

    def test_signed_request_verifies_before_provider_and_replays_exact_response(self):
        with RuntimeFixture() as fixture:
            (
                orchestrator,
                provider,
                controller,
                child,
                controller_rappid,
                twin_rappid,
            ) = self._runtime(
                fixture,
                [ProviderResponse(content="synthetic signed reply")],
            )
            request = sign_request(
                private_key=load_private_key(controller.private_key_path),
                public_jwk=controller.public_jwk,
                from_rappid=controller_rappid,
                to_rappid=twin_rappid,
                payload={"user_input": "inner trusted input"},
                facets=("runtime-test",),
            )
            outer = orchestrator.chat(
                {"user_input": canonical_json_text(request)}
            )
            signed = verify_response(
                outer["response"],
                paired_child_public_jwk=child.public_jwk,
                expected_child_rappid=twin_rappid,
                expected_controller_rappid=controller_rappid,
                expected_request_nonce=request["body"]["nonce"],
                expected_request_digest=request_digest(request["body"]),
            )
            duplicate = orchestrator.chat(
                {"user_input": canonical_json_text(request)}
            )

            self.assertEqual(
                signed["payload"]["response"], "synthetic signed reply"
            )
            self.assertEqual(duplicate["response"], outer["response"])
            self.assertEqual(len(provider.requests), 1)
            self.assertEqual(
                provider.requests[0].messages[-1]["content"],
                "inner trusted input",
            )
            with patch(
                "rapp_stack_cubby.runtime.orchestrator.validate_freshness",
                side_effect=AssertionError("completed replay checked freshness"),
            ):
                replay_after_window = orchestrator.chat(
                    {"user_input": canonical_json_text(request)}
                )
            self.assertEqual(
                replay_after_window["response"], outer["response"]
            )

    def test_bad_signature_and_malformed_claim_never_reach_provider(self):
        with RuntimeFixture() as fixture:
            (
                orchestrator,
                provider,
                controller,
                _child,
                controller_rappid,
                twin_rappid,
            ) = self._runtime(
                fixture,
                [ProviderResponse(content="must not run")],
            )
            request = sign_request(
                private_key=load_private_key(controller.private_key_path),
                public_jwk=controller.public_jwk,
                from_rappid=controller_rappid,
                to_rappid=twin_rappid,
                payload={"user_input": "synthetic"},
            )
            request["sig"] = "A" * 86
            with self.assertRaises(RequestValidationError):
                orchestrator.chat(
                    {"user_input": canonical_json_text(request)}
                )
            with self.assertRaises(RequestValidationError):
                orchestrator.chat(
                    {
                        "user_input": (
                            '{"schema":"rapp-twin-chat/1.0",'
                            '"user_input":"malformed claim"}'
                        )
                    }
                )
            self.assertEqual(provider.requests, ())

    def test_escaped_duplicate_deep_and_noncanonical_claims_fail_closed(self):
        with RuntimeFixture() as fixture:
            (
                orchestrator,
                provider,
                controller,
                _child,
                controller_rappid,
                twin_rappid,
            ) = self._runtime(
                fixture,
                [ProviderResponse(content="must not run")],
            )
            request = sign_request(
                private_key=load_private_key(
                    controller.private_key_path
                ),
                public_jwk=controller.public_jwk,
                from_rappid=controller_rappid,
                to_rappid=twin_rappid,
                payload={"user_input": "synthetic"},
            )
            claims = (
                '{"schema":"rapp-commons-\\u0065vent/1.0",',
                '\ufeff{"schema":"rapp-commons-event/1.0"}',
                (
                    '{"schema":"rapp-commons-\\u0065vent/1.0",'
                    '"schema":"unrelated/1.0"}'
                ),
                (
                    '{"schema":"rapp-twin-chat/1.0","value":'
                    + "[" * 18
                    + "0"
                    + "]" * 18
                    + "}"
                ),
                json.dumps(request, ensure_ascii=False, indent=2),
            )
            for claim in claims:
                with self.subTest(claim=claim[:80]):
                    with self.assertRaises(RequestValidationError):
                        orchestrator.chat({"user_input": claim})
            self.assertEqual(provider.requests, ())

    def test_unknown_json_is_plain_text_and_local_chat_remains_available(self):
        with RuntimeFixture() as fixture:
            (
                orchestrator,
                provider,
                _controller,
                _child,
                _controller_rappid,
                _twin_rappid,
            ) = self._runtime(
                fixture,
                [
                    ProviderResponse(content="plain reply"),
                    ProviderResponse(content="json reply"),
                ],
            )
            plain = orchestrator.chat({"user_input": "plain local owner"})
            unknown = orchestrator.chat(
                {"user_input": '{"schema":"unrelated/1.0","value":1}'}
            )
            self.assertEqual(plain["response"], "plain reply")
            self.assertEqual(unknown["response"], "json reply")
            self.assertEqual(len(provider.requests), 2)

    def test_provider_failure_is_terminal_signed_rejection_and_not_retried(self):
        with RuntimeFixture() as fixture:
            (
                orchestrator,
                provider,
                controller,
                child,
                controller_rappid,
                twin_rappid,
            ) = self._runtime(
                fixture,
                [ProviderTransportError("synthetic provider failure")],
            )
            request = sign_request(
                private_key=load_private_key(controller.private_key_path),
                public_jwk=controller.public_jwk,
                from_rappid=controller_rappid,
                to_rappid=twin_rappid,
                payload={"user_input": "synthetic failure"},
            )
            encoded = canonical_json_text(request)
            first = orchestrator.chat({"user_input": encoded})
            second = orchestrator.chat({"user_input": encoded})
            signed = verify_response(
                first["response"],
                paired_child_public_jwk=child.public_jwk,
                expected_child_rappid=twin_rappid,
                expected_controller_rappid=controller_rappid,
                expected_request_nonce=request["body"]["nonce"],
                expected_request_digest=request_digest(request["body"]),
            )

            self.assertEqual(signed["status"], "rejected")
            self.assertEqual(
                signed["payload"]["error"]["code"],
                "child_dispatch_failed",
            )
            self.assertEqual(second["response"], first["response"])
            self.assertEqual(len(provider.requests), 1)

    def test_stale_new_dispatch_becomes_retrievable_signed_terminal(self):
        with RuntimeFixture() as fixture:
            (
                orchestrator,
                provider,
                controller,
                child,
                controller_rappid,
                twin_rappid,
            ) = self._runtime(fixture, [])
            request = sign_request(
                private_key=load_private_key(
                    controller.private_key_path
                ),
                public_jwk=controller.public_jwk,
                from_rappid=controller_rappid,
                to_rappid=twin_rappid,
                payload={"user_input": "stale new request"},
                utc="2000-01-01T00:00:00Z",
            )
            encoded = canonical_json_text(request)
            first = orchestrator.chat({"user_input": encoded})
            replay = orchestrator.chat({"user_input": encoded})
            signed = verify_response(
                first["response"],
                paired_child_public_jwk=child.public_jwk,
                expected_child_rappid=twin_rappid,
                expected_controller_rappid=controller_rappid,
                expected_request_nonce=request["body"]["nonce"],
                expected_request_digest=request_digest(request["body"]),
                enforce_freshness=False,
            )
            self.assertEqual(signed["status"], "rejected")
            self.assertEqual(
                signed["payload"]["error"]["code"], "request_stale"
            )
            self.assertEqual(replay["response"], first["response"])
            self.assertEqual(provider.requests, ())

    def test_oversized_signed_response_and_logs_become_terminal_rejections(self):
        for field in ("response", "agent_logs"):
            with self.subTest(field=field), RuntimeFixture() as fixture:
                (
                    orchestrator,
                    provider,
                    controller,
                    child,
                    controller_rappid,
                    twin_rappid,
                ) = self._runtime(
                    fixture,
                    [ProviderResponse(content="unused")],
                )
                request = sign_request(
                    private_key=load_private_key(
                        controller.private_key_path
                    ),
                    public_jwk=controller.public_jwk,
                    from_rappid=controller_rappid,
                    to_rappid=twin_rappid,
                    payload={"user_input": "bounded response test"},
                )
                result = {
                    "response": "ok",
                    "session_id": "bounded-session",
                    "agent_logs": "",
                    "voice_mode": False,
                    "model": "synthetic-provider",
                    "requested_model": "synthetic-provider",
                }
                result[field] = "x" * (1024 * 1024 + 1)
                encoded = canonical_json_text(request)
                with patch.object(
                    orchestrator,
                    "_execute_chat",
                    return_value=result,
                ) as execute:
                    first = orchestrator.chat({"user_input": encoded})
                    second = orchestrator.chat({"user_input": encoded})
                signed = verify_response(
                    first["response"],
                    paired_child_public_jwk=child.public_jwk,
                    expected_child_rappid=twin_rappid,
                    expected_controller_rappid=controller_rappid,
                    expected_request_nonce=request["body"]["nonce"],
                    expected_request_digest=request_digest(request["body"]),
                )
                self.assertEqual(signed["status"], "rejected")
                self.assertEqual(second["response"], first["response"])
                self.assertEqual(execute.call_count, 1)
                counts = orchestrator._signed_ingress.journal.counts()
                self.assertEqual(counts["processing"], 0)
                self.assertEqual(counts["rejected"], 1)
                self.assertEqual(provider.requests, ())

    def test_signing_failure_is_durable_and_retry_recovers_without_dispatch(self):
        with RuntimeFixture() as fixture:
            (
                orchestrator,
                provider,
                controller,
                child,
                controller_rappid,
                twin_rappid,
            ) = self._runtime(
                fixture,
                [ProviderResponse(content="dispatch happened once")],
            )
            request = sign_request(
                private_key=load_private_key(controller.private_key_path),
                public_jwk=controller.public_jwk,
                from_rappid=controller_rappid,
                to_rappid=twin_rappid,
                payload={"user_input": "recover terminal signing failure"},
            )
            encoded = canonical_json_text(request)
            with patch(
                "rapp_stack_cubby.runtime.orchestrator."
                "_SignedIngressRuntime.sign",
                side_effect=ValueError("synthetic signing failure"),
            ):
                with self.assertRaises(OrchestratorProviderError):
                    orchestrator.chat({"user_input": encoded})

            counts = orchestrator._signed_ingress.journal.counts()
            self.assertEqual(counts["processing"], 0)
            self.assertEqual(counts["failed"], 1)
            recovered = orchestrator.chat({"user_input": encoded})
            signed = verify_response(
                recovered["response"],
                paired_child_public_jwk=child.public_jwk,
                expected_child_rappid=twin_rappid,
                expected_controller_rappid=controller_rappid,
                expected_request_nonce=request["body"]["nonce"],
                expected_request_digest=request_digest(request["body"]),
            )
            self.assertEqual(signed["status"], "rejected")
            self.assertEqual(len(provider.requests), 1)
            final = orchestrator._signed_ingress.journal.counts()
            self.assertEqual(final["failed"], 0)
            self.assertEqual(final["rejected"], 1)

    def test_old_epoch_is_rejected_even_with_empty_replay_database(self):
        with RuntimeFixture() as fixture:
            (
                orchestrator,
                provider,
                controller,
                child,
                controller_rappid,
                twin_rappid,
            ) = self._runtime(
                fixture,
                [ProviderResponse(content="current epoch reply")],
                key_epoch=2,
            )
            key = load_private_key(controller.private_key_path)
            captured = sign_request(
                private_key=key,
                public_jwk=controller.public_jwk,
                from_rappid=controller_rappid,
                to_rappid=twin_rappid,
                payload={"user_input": "captured before rotation"},
                key_epoch=1,
            )
            with self.assertRaises(RequestValidationError):
                orchestrator.chat(
                    {"user_input": canonical_json_text(captured)}
                )
            current = sign_request(
                private_key=key,
                public_jwk=controller.public_jwk,
                from_rappid=controller_rappid,
                to_rappid=twin_rappid,
                payload={"user_input": "current epoch"},
                key_epoch=2,
            )
            outer = orchestrator.chat(
                {"user_input": canonical_json_text(current)}
            )
            verified = verify_response(
                outer["response"],
                paired_child_public_jwk=child.public_jwk,
                expected_child_rappid=twin_rappid,
                expected_controller_rappid=controller_rappid,
                expected_request_nonce=current["body"]["nonce"],
                expected_request_digest=request_digest(current["body"]),
                expected_key_epoch=2,
            )
            self.assertEqual(verified["key_epoch"], 2)
            self.assertEqual(len(provider.requests), 1)

    def test_crash_before_dispatch_reclaims_but_after_marker_rejects(self):
        for dispatched in (False, True):
            with self.subTest(dispatched=dispatched), RuntimeFixture() as fixture:
                (
                    orchestrator,
                    provider,
                    controller,
                    child,
                    controller_rappid,
                    twin_rappid,
                ) = self._runtime(
                    fixture,
                    (
                        [ProviderResponse(content="reclaimed reply")]
                        if not dispatched
                        else []
                    ),
                )
                request = sign_request(
                    private_key=load_private_key(
                        controller.private_key_path
                    ),
                    public_jwk=controller.public_jwk,
                    from_rappid=controller_rappid,
                    to_rappid=twin_rappid,
                    payload={"user_input": "crash boundary"},
                )
                encoded = canonical_json_text(request)
                ingress = orchestrator._signed_ingress
                verified_request = ingress.verify(encoded)
                key = (
                    verified_request.sender_rappid,
                    verified_request.key_id,
                    verified_request.nonce,
                )
                ingress.journal.claim(*key, verified_request.digest)
                if dispatched:
                    ingress.journal.mark_dispatched(
                        *key, verified_request.digest
                    )
                with sqlite3.connect(
                    ingress.config.replay_db_path
                ) as connection:
                    connection.execute(
                        """
                        UPDATE twin_chat_replay
                        SET lease_deadline = '2000-01-01T00:00:00Z'
                        """
                    )
                ingress.journal = ReplayJournal(
                    ingress.config.replay_db_path,
                    key_epoch=1,
                    owner_id="restarted-runtime-owner",
                )
                outer = orchestrator.chat({"user_input": encoded})
                signed = verify_response(
                    outer["response"],
                    paired_child_public_jwk=child.public_jwk,
                    expected_child_rappid=twin_rappid,
                    expected_controller_rappid=controller_rappid,
                    expected_request_nonce=request["body"]["nonce"],
                    expected_request_digest=request_digest(request["body"]),
                )
                if dispatched:
                    self.assertEqual(signed["status"], "rejected")
                    self.assertEqual(
                        signed["payload"]["error"]["code"],
                        "dispatch_ambiguous",
                    )
                    self.assertEqual(provider.requests, ())
                else:
                    self.assertEqual(signed["status"], "ok")
                    self.assertEqual(len(provider.requests), 1)


if __name__ == "__main__":
    unittest.main()
