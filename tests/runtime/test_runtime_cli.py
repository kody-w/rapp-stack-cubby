from __future__ import annotations

import io
import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from rapp_stack_cubby.cli import build_parser, main
from rapp_stack_cubby.constants import EXPECTED_ACTUAL_AGENT_COUNT
from rapp_stack_cubby.runtime.app import RuntimeApp
from rapp_stack_cubby.runtime.orchestrator import Orchestrator
from rapp_stack_cubby.runtime.provider import (
    ProviderAuthenticationError,
    ProviderEndpointDriftError,
    ProviderEntitlementError,
    ProviderResponse,
    ScriptedProvider,
    ToolCall,
    ProviderTokenCompatibilityError,
    ProviderTransportError,
    ProviderUnsupportedModelError,
)
from rapp_stack_cubby.runtime.provider import ProviderModel
from rapp_stack_cubby.runtime.registry import AgentRegistry
from rapp_stack_cubby.runtime.server import RuntimeServer
from rapp_stack_cubby.runtime.storage import LocalStorage

from ._support import ECHO_AGENT, REPOSITORY_ROOT, RuntimeFixture


class RuntimeCliTests(unittest.TestCase):
    def test_serve_requires_explicit_runtime_paths(self) -> None:
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                build_parser().parse_args(["serve"])

    def test_serve_requires_explicit_model_root_and_principal(self) -> None:
        with RuntimeFixture() as fixture, redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                build_parser().parse_args(
                    [
                        "serve",
                        "--soul",
                        str(fixture.soul),
                        "--agents-dir",
                        str(fixture.agents),
                        "--data-dir",
                        str(fixture.data),
                        "--instance-id",
                        "missing-context",
                    ]
                )

    def test_serve_rejects_non_loopback_host(self) -> None:
        with RuntimeFixture() as fixture:
            errors = io.StringIO()
            with redirect_stderr(errors):
                status = main(
                    [
                        "serve",
                        "--soul",
                        str(fixture.soul),
                        "--agents-dir",
                        str(fixture.agents),
                        "--data-dir",
                        str(fixture.data),
                        "--instance-id",
                        "cli-test-instance",
                        "--root",
                        str(fixture.root),
                        "--principal",
                        "cli-principal",
                        "--model",
                        "test-model",
                        "--host",
                        "0.0.0.0",
                    ]
                )

            self.assertEqual(status, 2)
            self.assertIn("loopback", errors.getvalue())

    def test_serve_prints_only_selected_loopback_url(self) -> None:
        class FakeApp:
            url = "http://127.0.0.1:43210"

            def __init__(self, config):
                self.config = config
                self.shutdown_called = False

            def serve_forever(self):
                return None

            def shutdown(self):
                self.shutdown_called = True

        with RuntimeFixture() as fixture:
            output = io.StringIO()
            with patch(
                "rapp_stack_cubby.runtime.app.RuntimeApp",
                FakeApp,
            ), redirect_stdout(output):
                status = main(
                    [
                        "serve",
                        "--soul",
                        str(fixture.soul),
                        "--agents-dir",
                        str(fixture.agents),
                        "--data-dir",
                        str(fixture.data),
                        "--instance-id",
                        "cli-test-instance",
                        "--root",
                        str(fixture.root),
                        "--principal",
                        "cli-principal",
                        "--model",
                        "test-model",
                        "--port",
                        "0",
                    ]
                )

            self.assertEqual(status, 0)
            self.assertEqual(output.getvalue().strip(), FakeApp.url)
            self.assertNotIn("@", output.getvalue())

    def test_health_queries_local_server_with_timeout(self) -> None:
        with RuntimeFixture() as fixture:
            fixture.write_agent("echo_agent.py", ECHO_AGENT)
            registry = AgentRegistry(
                fixture.agents,
                storage=LocalStorage(fixture.data),
                compatibility_mode=True,
            )
            orchestrator = Orchestrator(
                soul_path=fixture.soul,
                registry=registry,
                provider=ScriptedProvider([ProviderResponse(content="ok")]),
                model="model",
            )
            server = RuntimeServer(
                orchestrator,
                port=0,
                instance_id="health-test-instance",
            )
            server.start()
            try:
                output = io.StringIO()
                with redirect_stdout(output):
                    status = main(
                        [
                            "health",
                            "--url",
                            server.health_url,
                            "--timeout",
                            "2",
                        ]
                    )
            finally:
                server.shutdown()

            self.assertEqual(status, 0)
            self.assertEqual(json.loads(output.getvalue())["status"], "ok")

    def test_health_rejects_remote_or_credentialed_urls_without_network(self) -> None:
        for url in (
            "https://127.0.0.1:7071/health",
            "http://example.com/health",
            "http://user:password@127.0.0.1/health",
            "http://127.0.0.1/chat",
        ):
            with self.subTest(url=url):
                errors = io.StringIO()
                with patch(
                    "rapp_stack_cubby.cli.urllib.request.urlopen"
                ) as urlopen, redirect_stderr(errors):
                    status = main(["health", url])
                self.assertEqual(status, 2)
                urlopen.assert_not_called()

    def test_models_alias_lists_and_validates_without_credentials(self) -> None:
        catalog = (
            ProviderModel(
                id="chat-model",
                name="Chat Model",
                vendor="Synthetic",
                preview=False,
                tool_calls=True,
            ),
        )

        class FakeProvider:
            def __init__(self, *, model, timeout, github_token_file=None):
                self.model = model
                self.timeout = timeout
                self.github_token_file = github_token_file

            def list_models(self):
                return catalog

            def validate_model(self, model, *, models):
                self.asserted = (model, models)
                return models[0]

        output = io.StringIO()
        with patch(
            "rapp_stack_cubby.runtime.provider.CopilotProvider",
            FakeProvider,
        ), redirect_stdout(output):
            status = main(
                [
                    "provider-preflight",
                    "--model",
                    "chat-model",
                    "--github-token-file",
                    "/private/provider-token.json",
                    "--json",
                ]
            )

        payload = json.loads(output.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(payload["selected_model"], "chat-model")
        self.assertEqual(payload["chat_completion_model_count"], 1)
        self.assertNotIn("token", output.getvalue().casefold())

    def test_provider_smoke_outputs_shape_without_content_or_path(self) -> None:
        catalog = (
            ProviderModel(
                id="chat-model",
                name="Chat Model",
                vendor="Synthetic",
                preview=False,
                tool_calls=True,
            ),
        )

        class FakeProvider:
            def __init__(
                self,
                *,
                model,
                timeout,
                github_token_file,
            ):
                self.model = model
                self.responses = [
                    ProviderResponse(
                        content="",
                        tool_calls=(
                            ToolCall(
                                "synthetic-call",
                                "rapp_provider_probe",
                                '{"value":"synthetic"}',
                            ),
                        ),
                        model=model,
                        finish_reason="tool_calls",
                    ),
                    ProviderResponse(
                        content="synthetic completion body",
                        model=model,
                        finish_reason="stop",
                    ),
                ]

            def list_models(self):
                return catalog

            def validate_model(self, model, *, models):
                return models[0]

            def complete(self, messages, *, tools, timeout):
                return self.responses.pop(0)

        output = io.StringIO()
        with patch(
            "rapp_stack_cubby.runtime.provider.CopilotProvider",
            FakeProvider,
        ), redirect_stdout(output):
            status = main(
                [
                    "provider-smoke",
                    "--model",
                    "chat-model",
                    "--github-token-file",
                    "/private/provider-token.json",
                    "--json",
                ]
            )

        payload = json.loads(output.getvalue())
        self.assertEqual(status, 0)
        self.assertTrue(payload["success"])
        self.assertEqual(payload["response_shape"]["initial_tool_calls"], 1)
        self.assertNotIn("synthetic completion body", output.getvalue())
        self.assertNotIn("/private", output.getvalue())

    def test_preflight_reports_stable_content_free_failure_categories(self):
        failures = (
            (
                ProviderAuthenticationError("missing"),
                "auth_missing",
            ),
            (
                ProviderTokenCompatibilityError(),
                "incompatible_gho",
            ),
            (
                ProviderEntitlementError(),
                "no_copilot_entitlement",
            ),
            (
                ProviderEndpointDriftError("drift"),
                "endpoint_drift",
            ),
            (
                ProviderUnsupportedModelError("unsupported"),
                "unsupported_model",
            ),
            (
                ProviderTransportError("transport"),
                "transport",
            ),
        )
        for failure, expected in failures:
            with self.subTest(status=expected):
                class FailingProvider:
                    def __init__(self, *, model, timeout):
                        pass

                    def list_models(self):
                        raise failure

                output = io.StringIO()
                with patch(
                    "rapp_stack_cubby.runtime.provider.CopilotProvider",
                    FailingProvider,
                ), redirect_stdout(output):
                    status = main(
                        [
                            "provider-preflight",
                            "--model",
                            "chat-model",
                            "--json",
                        ]
                    )
                payload = json.loads(output.getvalue())
                self.assertEqual(status, 2)
                self.assertEqual(payload["status"], expected)
                self.assertFalse(payload["authenticated"])
                self.assertNotIn("detail", payload)

    def test_documented_serve_loads_all_actual_agents_from_config(self) -> None:
        actual_agents = (
            REPOSITORY_ROOT
            / "cubbies/kody-w/rapplications/rapp-stack/twin/agents"
        )
        soul = (
            REPOSITORY_ROOT
            / "cubbies/kody-w/rapplications/rapp-stack/twin/soul.md"
        )
        context_keys = tuple(
            key
            for key in os.environ
            if key.startswith("RAPP_STACK_")
        )
        before = {key: os.environ[key] for key in context_keys}

        class DocumentedServeApp(RuntimeApp):
            loaded_names = ()

            def __init__(self, config):
                super().__init__(
                    config,
                    provider=ScriptedProvider(
                        [ProviderResponse(content="unused")]
                    ),
                )
                type(self).loaded_names = self.startup_snapshot.names

            def serve_forever(self):
                return None

        with RuntimeFixture() as fixture:
            generated = fixture.root / "generated"
            generated.mkdir(mode=0o700)
            output = io.StringIO()
            with patch(
                "rapp_stack_cubby.runtime.app.RuntimeApp",
                DocumentedServeApp,
            ), redirect_stdout(output):
                status = main(
                    [
                        "serve",
                        "--soul",
                        str(soul),
                        "--agents-dir",
                        str(actual_agents),
                        "--data-dir",
                        str(fixture.data),
                        "--instance-id",
                        "all-agents-live-load",
                        "--root",
                        str(REPOSITORY_ROOT),
                        "--principal",
                        "serve-test-principal",
                        "--generated-agents-dir",
                        str(generated),
                        "--allow-agent-writes",
                        "--model",
                        "synthetic-test-model",
                        "--port",
                        "0",
                    ]
                )

        self.assertEqual(status, 0)
        self.assertEqual(
            len(DocumentedServeApp.loaded_names),
            EXPECTED_ACTUAL_AGENT_COUNT,
        )
        self.assertEqual(
            {
                key: value
                for key, value in os.environ.items()
                if key.startswith("RAPP_STACK_")
            },
            before,
        )


if __name__ == "__main__":
    unittest.main()
