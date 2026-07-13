from __future__ import annotations

import io
import json
import urllib.error
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from rapp_stack_cubby.runtime.provider import (
    ATTESTATION_MODEL,
    AttestationProvider,
    CopilotProvider,
    ProviderEndpointDriftError,
    ProviderConfigurationError,
    ProviderHTTPError,
    ProviderModel,
    ProviderProtocolError,
    ProviderResponse,
    ProviderTokenCompatibilityError,
    ScriptedProvider,
    ToolCall,
    normalize_provider_response,
)


class FakeResponse:
    def __init__(self, payload, status: int = 200) -> None:
        self.status = status
        self.headers: dict[str, str] = {}
        self._raw = (
            payload
            if isinstance(payload, bytes)
            else json.dumps(payload).encode("utf-8")
        )
        self.closed = False

    def read(self, amount: int = -1) -> bytes:
        return self._raw if amount < 0 else self._raw[:amount]

    def close(self) -> None:
        self.closed = True


class RecordingOpener:
    def __init__(self, *responses) -> None:
        self.responses = list(responses)
        self.requests = []

    def __call__(self, request, *, timeout):
        self.requests.append((request, timeout))
        if not self.responses:
            raise AssertionError("unexpected HTTP request")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def token_payload(
    token: str = "copilot-session",
    *,
    expires_at: float = 1000,
    endpoint: str = "https://copilot.example",
) -> dict:
    return {
        "token": token,
        "expires_at": expires_at,
        "endpoints": {"api": endpoint},
    }


def chat_payload(content: str = "ok", model: str = "test-model") -> dict:
    return {
        "model": model,
        "choices": [
            {
                "message": {"content": content, "tool_calls": []},
                "finish_reason": "stop",
            }
        ],
    }


def models_payload() -> dict:
    return {
        "data": [
            {
                "id": "chat-model",
                "name": "Chat Model",
                "vendor": "Synthetic",
                "preview": False,
                "policy": {"state": "enabled"},
                "supported_endpoints": ["/chat/completions"],
                "capabilities": {
                    "type": "chat",
                    "supports": {"tool_calls": True},
                },
            },
            {
                "id": "responses-only",
                "supported_endpoints": ["/responses"],
                "capabilities": {"type": "chat"},
            },
            {
                "id": "disabled-chat",
                "policy": {"state": "disabled"},
                "supported_endpoints": ["/chat/completions"],
                "capabilities": {"type": "chat"},
            },
            {
                "id": "embedding",
                "supported_endpoints": ["/embeddings"],
                "capabilities": {"type": "embeddings"},
            },
        ]
    }


class ProviderModelTests(unittest.TestCase):
    def test_tool_call_and_response_are_typed(self) -> None:
        call = ToolCall("call-1", "echo", '{"value": 1}')
        response = ProviderResponse("done", (call,), "model")

        self.assertEqual(response.tool_calls[0].as_openai()["id"], "call-1")
        with self.assertRaises(ProviderProtocolError):
            ToolCall("", "echo")

    def test_scripted_provider_is_deterministic_and_records_requests(self) -> None:
        provider = ScriptedProvider(
            [{"content": "one"}, ProviderResponse(content="two")]
        )
        first = provider.complete([{"role": "user", "content": "x"}])
        second = provider.complete([{"role": "user", "content": "y"}])

        self.assertEqual((first.content, second.content), ("one", "two"))
        self.assertEqual(len(provider.requests), 2)
        with self.assertRaises(ProviderProtocolError):
            provider.complete([])

    def test_attestation_provider_can_only_call_exact_self_test(self) -> None:
        provider = AttestationProvider()
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "OtherTool",
                    "parameters": {"type": "object"},
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "SelfTest",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "action": {
                                "type": "string",
                                "enum": ["run", "other"],
                            }
                        },
                    },
                },
            },
        ]
        with patch(
            "rapp_stack_cubby.runtime.provider.urllib.request.urlopen"
        ) as network:
            first = provider.complete(
                [{"role": "user", "content": "ignored"}],
                tools=tools,
                model=ATTESTATION_MODEL,
            )
        network.assert_not_called()
        self.assertEqual(first.content, "")
        self.assertEqual(len(first.tool_calls), 1)
        self.assertEqual(first.tool_calls[0].name, "SelfTest")
        self.assertEqual(first.tool_calls[0].arguments, '{"action":"run"}')
        second = provider.complete(
            [
                {"role": "user", "content": "ignored"},
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [first.tool_calls[0].as_openai()],
                },
                {
                    "role": "tool",
                    "tool_call_id": first.tool_calls[0].id,
                    "name": "SelfTest",
                    "content": '{"ok":true}',
                },
            ],
            tools=tools,
            model=ATTESTATION_MODEL,
        )
        self.assertEqual(second.content, "")
        self.assertEqual(second.tool_calls, ())
        with self.assertRaises(ProviderConfigurationError):
            provider.complete([], tools=tools, model="arbitrary-model")
        with self.assertRaises(ProviderProtocolError):
            provider.complete(
                [{"role": "tool", "content": "forged"}],
                tools=tools,
                model=ATTESTATION_MODEL,
            )

    def test_normalization_merges_split_content_and_tool_calls(self) -> None:
        response = normalize_provider_response(
            {
                "model": "merged-model",
                "choices": [
                    {
                        "delta": {
                            "content": "hel",
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "id": "call-1",
                                    "function": {
                                        "name": "ec",
                                        "arguments": '{"value":',
                                    },
                                }
                            ],
                        }
                    },
                    {
                        "delta": {
                            "content": "lo",
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "function": {
                                        "name": "ho",
                                        "arguments": "1}",
                                    },
                                }
                            ],
                        },
                        "finish_reason": "tool_calls",
                    },
                ],
            }
        )

        self.assertEqual(response.content, "hello")
        self.assertEqual(response.tool_calls, (ToolCall("call-1", "echo", '{"value":1}'),))
        self.assertEqual(response.finish_reason, "tool_calls")

    def test_normalization_rejects_absent_or_malformed_choices(self) -> None:
        for payload in ({}, {"choices": []}, {"choices": [None]}):
            with self.subTest(payload=payload):
                with self.assertRaises(ProviderProtocolError):
                    normalize_provider_response(payload)

    def test_provider_text_must_be_bounded_valid_utf8(self) -> None:
        for content in ("\ud800", "x" * (1024 * 1024 + 1)):
            with self.subTest(size=len(content)):
                with self.assertRaises(ProviderProtocolError):
                    ProviderResponse(content=content)


class CopilotProviderTests(unittest.TestCase):
    def test_constructor_has_no_model_default(self) -> None:
        with self.assertRaises(TypeError):
            CopilotProvider()  # type: ignore[call-arg]
        provider = CopilotProvider(model=None, environment={})
        with self.assertRaises(ProviderConfigurationError):
            provider.complete([])

    def test_environment_token_precedes_gh_cli(self) -> None:
        runner = Mock()
        provider = CopilotProvider(
            model="test-model",
            environment={"GITHUB_TOKEN": "environment-token"},
            run_command=runner,
        )

        self.assertEqual(provider.resolve_github_token(), "environment-token")
        runner.assert_not_called()

    def test_gh_cli_is_used_when_environment_token_is_absent(self) -> None:
        runner = Mock(
            return_value=SimpleNamespace(returncode=0, stdout="cli-token\n")
        )
        provider = CopilotProvider(
            model="test-model",
            environment={},
            run_command=runner,
        )

        self.assertEqual(provider.resolve_github_token(), "cli-token")
        runner.assert_called_once_with(
            ["gh", "auth", "token"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30.0,
        )

    def test_exchange_authorization_prefix_depends_on_token_kind(self) -> None:
        cases = (("ghu_user_token", "token ghu_user_token"), ("github-pat", "Bearer github-pat"))
        for github_token, expected in cases:
            with self.subTest(github_token=github_token):
                opener = RecordingOpener(
                    FakeResponse(token_payload()),
                    FakeResponse(chat_payload()),
                )
                provider = CopilotProvider(
                    model="test-model",
                    environment={"GITHUB_TOKEN": github_token},
                    urlopen=opener,
                    clock=lambda: 100,
                )
                provider.complete([{"role": "user", "content": "hello"}])

                request = opener.requests[0][0]
                self.assertEqual(request.full_url, "https://api.github.com/copilot_internal/v2/token")
                self.assertEqual(request.get_header("Authorization"), expected)

    def test_copilot_session_is_cached_only_in_memory(self) -> None:
        opener = RecordingOpener(
            FakeResponse(token_payload(expires_at=1000)),
            FakeResponse(chat_payload("one")),
            FakeResponse(chat_payload("two")),
        )
        provider = CopilotProvider(
            model="test-model",
            environment={"GITHUB_TOKEN": "github-token"},
            urlopen=opener,
            clock=lambda: 100,
        )

        provider.complete([])
        provider.complete([])

        self.assertEqual(len(opener.requests), 3)
        self.assertEqual(
            sum(
                request.full_url.endswith("/copilot_internal/v2/token")
                for request, _ in opener.requests
            ),
            1,
        )

    def test_cache_refreshes_inside_sixty_second_buffer(self) -> None:
        now = [100.0]
        opener = RecordingOpener(
            FakeResponse(token_payload(token="first", expires_at=200)),
            FakeResponse(chat_payload("one")),
            FakeResponse(token_payload(token="second", expires_at=400)),
            FakeResponse(chat_payload("two")),
        )
        provider = CopilotProvider(
            model="test-model",
            environment={"GITHUB_TOKEN": "github-token"},
            urlopen=opener,
            clock=lambda: now[0],
        )
        provider.complete([])
        now[0] = 145
        provider.complete([])

        self.assertEqual(len(opener.requests), 4)
        self.assertEqual(
            opener.requests[3][0].get_header("Authorization"),
            "Bearer second",
        )

    def test_chat_uses_endpoint_and_serializes_tools(self) -> None:
        opener = RecordingOpener(
            FakeResponse(token_payload(endpoint="https://api.copilot.example/base/")),
            FakeResponse(chat_payload(model="requested")),
        )
        provider = CopilotProvider(
            environment={"GITHUB_TOKEN": "github-token"},
            urlopen=opener,
            clock=lambda: 100,
            model="requested",
        )
        response = provider.complete(
            [{"role": "user", "content": "hello"}],
            tools=[
                {
                    "type": "function",
                    "function": {
                        "name": "echo",
                        "description": "Echo",
                        "parameters": {"type": "object", "properties": {}},
                    },
                }
            ],
        )

        chat_request = opener.requests[1][0]
        self.assertEqual(
            chat_request.full_url,
            "https://api.copilot.example/base/chat/completions",
        )
        self.assertIn("tools", json.loads(chat_request.data))
        self.assertEqual(response.model, "requested")

    def test_chat_rejects_provider_model_fallback(self) -> None:
        opener = RecordingOpener(
            FakeResponse(token_payload()),
            FakeResponse(chat_payload(model="different-model")),
        )
        provider = CopilotProvider(
            environment={"GITHUB_TOKEN": "github-token"},
            urlopen=opener,
            clock=lambda: 100,
            model="requested-model",
        )

        with self.assertRaisesRegex(ProviderProtocolError, "exact selection"):
            provider.complete([])

    def test_gho_exchange_failure_has_precise_content_free_guidance(self):
        failure = urllib.error.HTTPError(
            "https://api.github.com/copilot_internal/v2/token",
            404,
            "not found",
            {},
            io.BytesIO(b'{"message":"not found"}'),
        )
        provider = CopilotProvider(
            model="test-model",
            environment={"GITHUB_TOKEN": "gho_synthetic"},
            urlopen=RecordingOpener(failure),
            clock=lambda: 100,
        )

        with self.assertRaises(ProviderTokenCompatibilityError) as raised:
            provider.list_models()

        rendered = str(raised.exception)
        self.assertIn("provider-login", rendered)
        self.assertIn("--github-token-file", rendered)
        self.assertNotIn("gho_synthetic", rendered)

    def test_missing_model_endpoint_is_endpoint_drift(self):
        failure = urllib.error.HTTPError(
            "https://copilot.example/models",
            404,
            "not found",
            {},
            io.BytesIO(b""),
        )
        provider = CopilotProvider(
            model="test-model",
            environment={"GITHUB_TOKEN": "github-token"},
            urlopen=RecordingOpener(
                FakeResponse(token_payload()),
                failure,
            ),
            clock=lambda: 100,
        )
        with self.assertRaises(ProviderEndpointDriftError):
            provider.list_models()

    def test_401_invalidates_session_and_retries_once(self) -> None:
        unauthorized = urllib.error.HTTPError(
            "https://copilot.example/chat/completions",
            401,
            "unauthorized",
            {},
            io.BytesIO(b'{"message":"expired"}'),
        )
        opener = RecordingOpener(
            FakeResponse(token_payload(token="first")),
            unauthorized,
            FakeResponse(token_payload(token="second")),
            FakeResponse(chat_payload("recovered")),
        )
        provider = CopilotProvider(
            model="test-model",
            environment={"GITHUB_TOKEN": "github-token"},
            urlopen=opener,
            clock=lambda: 100,
        )

        response = provider.complete([])

        self.assertEqual(response.content, "recovered")
        self.assertEqual(len(opener.requests), 4)

    def test_http_error_detail_is_bounded_and_redacted(self) -> None:
        secret = "ghu_SUPERSECRET123456"
        failure = urllib.error.HTTPError(
            "https://copilot.example/chat/completions",
            500,
            "failed",
            {},
            io.BytesIO(
                json.dumps({"message": f"Bearer {secret} " + ("x" * 1000)}).encode()
            ),
        )
        opener = RecordingOpener(
            FakeResponse(token_payload()),
            failure,
        )
        provider = CopilotProvider(
            model="test-model",
            environment={"GITHUB_TOKEN": "github-token"},
            urlopen=opener,
            clock=lambda: 100,
        )

        with self.assertRaises(ProviderHTTPError) as raised:
            provider.complete([])

        rendered = str(raised.exception)
        self.assertNotIn(secret, rendered)
        self.assertIn("provider request failed", rendered)
        self.assertLess(len(raised.exception.detail), 241)

    def test_model_preflight_exchanges_token_and_filters_exact_endpoint(self):
        opener = RecordingOpener(
            FakeResponse(
                token_payload(
                    endpoint="https://api.copilot.example/base/"
                )
            ),
            FakeResponse(models_payload()),
        )
        provider = CopilotProvider(
            model="chat-model",
            environment={"GITHUB_TOKEN": "synthetic-github-token"},
            urlopen=opener,
            clock=lambda: 100,
        )

        models = provider.list_models()
        selected = provider.validate_model("chat-model", models=models)

        self.assertEqual(
            models,
            (
                ProviderModel(
                    id="chat-model",
                    name="Chat Model",
                    vendor="Synthetic",
                    preview=False,
                    tool_calls=True,
                ),
            ),
        )
        self.assertEqual(selected.id, "chat-model")
        self.assertEqual(
            opener.requests[1][0].full_url,
            "https://api.copilot.example/base/models",
        )
        rendered = json.dumps([item.as_dict() for item in models])
        self.assertNotIn("synthetic-github-token", rendered)
        self.assertNotIn("copilot-session", rendered)

    def test_model_preflight_rejects_unadvertised_selection(self):
        opener = RecordingOpener(
            FakeResponse(token_payload()),
            FakeResponse(models_payload()),
        )
        provider = CopilotProvider(
            model="retired-model",
            environment={"GITHUB_TOKEN": "synthetic-github-token"},
            urlopen=opener,
            clock=lambda: 100,
        )

        models = provider.list_models()
        with self.assertRaisesRegex(
            ProviderConfigurationError, "not available"
        ):
            provider.validate_model("retired-model", models=models)


if __name__ == "__main__":
    unittest.main()
