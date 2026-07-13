from __future__ import annotations

import uuid
import unittest

from rapp_stack_cubby.runtime.orchestrator import (
    MAX_TOOL_ROUNDS,
    Orchestrator,
    OrchestratorProviderError,
    RequestValidationError,
)
from rapp_stack_cubby.runtime.provider import (
    ProviderHTTPError,
    ProviderResponse,
    ScriptedProvider,
    ToolCall,
)
from rapp_stack_cubby.runtime.registry import AgentRegistry
from rapp_stack_cubby.runtime.storage import LocalStorage

from ._support import RuntimeFixture


AGENTS = """\
from basic_agent import BasicAgent

EMPTY = {"type": "object", "properties": {}, "required": []}

class EchoAgent(BasicAgent):
    name = "echo"
    metadata = {
        "name": "echo",
        "description": "Echo text.",
        "parameters": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": [],
        },
    }
    def perform(self, text="", **kwargs):
        return f"echo:{text}"

class UpperAgent(BasicAgent):
    name = "upper"
    metadata = {
        "name": "upper",
        "description": "Uppercase text.",
        "parameters": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": [],
        },
    }
    def perform(self, text="", **kwargs):
        return text.upper()

class BoomAgent(BasicAgent):
    name = "boom"
    metadata = {
        "name": "boom",
        "description": "Raise a test error.",
        "parameters": EMPTY,
    }
    def perform(self, **kwargs):
        raise RuntimeError("message and private args must not be logged")

class ContextAgent(BasicAgent):
    name = "context"
    metadata = {
        "name": "context",
        "description": "Provide context.",
        "parameters": EMPTY,
    }
    def perform(self, **kwargs):
        return "unused"
    def system_context(self):
        return "Context supplied by an agent."

class InvalidTextAgent(BasicAgent):
    name = "invalid_text"
    metadata = {
        "name": "invalid_text",
        "description": "Return invalid or oversized synthetic text.",
        "parameters": {
            "type": "object",
            "properties": {"mode": {"type": "string"}},
            "required": [],
        },
    }
    def perform(self, mode="", **kwargs):
        if mode == "surrogate":
            return chr(0xD800)
        return "x" * (1024 * 1024 + 1)

class CoroutineReturnAgent(BasicAgent):
    name = "coroutine_return"
    metadata = {
        "name": "coroutine_return",
        "description": "Return a synthetic coroutine.",
        "parameters": EMPTY,
    }
    def perform(self, **kwargs):
        async def result():
            return "must not be awaited"
        return result()
"""


class OrchestratorTests(unittest.TestCase):
    def test_no_tool_response_has_exact_shape_and_uuid4(self) -> None:
        with RuntimeFixture() as fixture:
            provider = ScriptedProvider(
                [ProviderResponse(content="hello", model="actual-model")]
            )
            orchestrator = self._orchestrator(fixture, provider)

            result = orchestrator.chat({"user_input": "hi"})

            self.assertEqual(
                set(result),
                {
                    "response",
                    "session_id",
                    "agent_logs",
                    "voice_mode",
                    "model",
                    "requested_model",
                },
            )
            self.assertNotIn("assistant_response", result)
            self.assertEqual(result["response"], "hello")
            self.assertEqual(result["model"], "actual-model")
            self.assertEqual(result["requested_model"], "requested-model")
            self.assertEqual(uuid.UUID(result["session_id"]).version, 4)

    def test_provided_safe_session_is_preserved(self) -> None:
        with RuntimeFixture() as fixture:
            orchestrator = self._orchestrator(
                fixture,
                ScriptedProvider([ProviderResponse(content="ok")]),
            )

            result = orchestrator.chat(
                {"user_input": "hi", "session_id": "session-123"}
            )

            self.assertEqual(result["session_id"], "session-123")

    def test_one_tool_is_executed_and_returned_to_provider(self) -> None:
        with RuntimeFixture() as fixture:
            provider = ScriptedProvider(
                [
                    ProviderResponse(
                        tool_calls=(ToolCall("call-1", "echo", '{"text":"yes"}'),)
                    ),
                    ProviderResponse(content="finished"),
                ]
            )
            result = self._orchestrator(fixture, provider).chat(
                {"user_input": "echo"}
            )

            self.assertEqual(result["response"], "finished")
            self.assertEqual(result["agent_logs"], "[echo] completed")
            tool_messages = [
                message
                for message in provider.requests[1].messages
                if message["role"] == "tool"
            ]
            self.assertEqual(tool_messages[0]["content"], "echo:yes")
            self.assertEqual(tool_messages[0]["tool_call_id"], "call-1")

    def test_multiple_tools_execute_in_provider_order(self) -> None:
        with RuntimeFixture() as fixture:
            provider = ScriptedProvider(
                [
                    ProviderResponse(
                        tool_calls=(
                            ToolCall("one", "echo", '{"text":"a"}'),
                            ToolCall("two", "upper", '{"text":"b"}'),
                        )
                    ),
                    ProviderResponse(content="done"),
                ]
            )
            result = self._orchestrator(fixture, provider).chat(
                {"user_input": "both"}
            )

            self.assertEqual(
                result["agent_logs"], "[echo] completed\n[upper] completed"
            )
            contents = [
                message["content"]
                for message in provider.requests[1].messages
                if message["role"] == "tool"
            ]
            self.assertEqual(contents, ["echo:a", "B"])

    def test_malformed_and_non_object_arguments_become_empty_objects(self) -> None:
        cases = (
            ("not-json", "malformed arguments"),
            ("[1,2]", "non-object arguments"),
        )
        for arguments, expected_log in cases:
            with self.subTest(arguments=arguments), RuntimeFixture() as fixture:
                provider = ScriptedProvider(
                    [
                        ProviderResponse(
                            tool_calls=(ToolCall("one", "echo", arguments),)
                        ),
                        ProviderResponse(content="done"),
                    ]
                )
                result = self._orchestrator(fixture, provider).chat(
                    {"user_input": "run"}
                )

                self.assertIn(expected_log, result["agent_logs"])
                tool = next(
                    message
                    for message in provider.requests[1].messages
                    if message["role"] == "tool"
                )
                self.assertEqual(tool["content"], "echo:")

    def test_missing_and_raising_tools_become_tool_results(self) -> None:
        calls = (
            ToolCall("missing", "absent", "{}"),
            ToolCall("raising", "boom", "{}"),
        )
        with RuntimeFixture() as fixture:
            provider = ScriptedProvider(
                [
                    ProviderResponse(tool_calls=calls),
                    ProviderResponse(content="handled"),
                ]
            )
            result = self._orchestrator(fixture, provider).chat(
                {"user_input": "run"}
            )

            tool_results = [
                message["content"]
                for message in provider.requests[1].messages
                if message["role"] == "tool"
            ]
            self.assertIn("not registered", tool_results[0])
            self.assertIn("raised RuntimeError", tool_results[1])
            self.assertNotIn("private args", result["agent_logs"])

    def test_invalid_or_oversized_agent_text_is_bounded_before_provider(self):
        for mode in ("surrogate", "oversized"):
            with self.subTest(mode=mode), RuntimeFixture() as fixture:
                provider = ScriptedProvider(
                    [
                        ProviderResponse(
                            tool_calls=(
                                ToolCall(
                                    "invalid",
                                    "invalid_text",
                                    f'{{"mode":"{mode}"}}',
                                ),
                            )
                        ),
                        ProviderResponse(content="handled safely"),
                    ]
                )
                result = self._orchestrator(fixture, provider).chat(
                    {"user_input": "run invalid output"}
                )
                tool = next(
                    message
                    for message in provider.requests[1].messages
                    if message["role"] == "tool"
                )
                if mode == "surrogate":
                    self.assertLess(len(tool["content"]), 200)
                    self.assertIn(
                        "raised AgentOutputError", tool["content"]
                    )
                else:
                    self.assertLessEqual(
                        len(tool["content"].encode("utf-8")),
                        1024 * 1024,
                    )
                    self.assertTrue(tool["content"].endswith("…"))
                self.assertEqual(result["response"], "handled safely")

    def test_coroutine_tool_result_fails_closed_without_awaiting(self) -> None:
        with RuntimeFixture() as fixture:
            provider = ScriptedProvider(
                [
                    ProviderResponse(
                        tool_calls=(
                            ToolCall("awaitable", "coroutine_return", "{}"),
                        )
                    ),
                    ProviderResponse(content="handled safely"),
                ]
            )
            result = self._orchestrator(fixture, provider).chat(
                {"user_input": "return a coroutine"}
            )
            tool = next(
                message
                for message in provider.requests[1].messages
                if message["role"] == "tool"
            )
            self.assertEqual(
                tool["content"],
                "ERROR: tool 'coroutine_return' raised AgentOutputError.",
            )
            self.assertEqual(
                result["agent_logs"],
                "[coroutine_return] failed (AgentOutputError)",
            )

    def test_soul_and_agent_context_are_in_system_message(self) -> None:
        with RuntimeFixture() as fixture:
            provider = ScriptedProvider([ProviderResponse(content="ok")])
            self._orchestrator(fixture, provider).chat({"user_input": "hi"})

            system = provider.requests[0].messages[0]
            self.assertEqual(system["role"], "system")
            self.assertIn("You are a test assistant.", system["content"])
            self.assertIn("Context supplied by an agent.", system["content"])

    def test_history_is_strictly_validated(self) -> None:
        invalid_histories = (
            "not-an-array",
            [None],
            [{"role": "system", "content": "unsafe"}],
            [{"role": "user", "content": 3}],
            [{"role": "user", "content": "ok", "extra": True}],
        )
        with RuntimeFixture() as fixture:
            orchestrator = self._orchestrator(
                fixture,
                ScriptedProvider([ProviderResponse(content="unused")] * 5),
            )
            for history in invalid_histories:
                with self.subTest(history=history):
                    with self.assertRaises(RequestValidationError):
                        orchestrator.chat(
                            {
                                "user_input": "hi",
                                "conversation_history": history,
                            }
                        )

    def test_valid_user_assistant_and_tool_history_is_forwarded(self) -> None:
        with RuntimeFixture() as fixture:
            provider = ScriptedProvider([ProviderResponse(content="ok")])
            history = [
                {"role": "user", "content": "one"},
                {"role": "assistant", "content": "two"},
                {"role": "tool", "content": "three"},
            ]
            self._orchestrator(fixture, provider).chat(
                {"user_input": "four", "conversation_history": history}
            )

            self.assertEqual(
                list(provider.requests[0].messages[1:4]),
                history,
            )

    def test_unknown_request_fields_and_bad_sessions_are_rejected(self) -> None:
        with RuntimeFixture() as fixture:
            orchestrator = self._orchestrator(
                fixture,
                ScriptedProvider([ProviderResponse(content="unused")] * 2),
            )
            with self.assertRaises(RequestValidationError):
                orchestrator.chat({"user_input": "hi", "model": "other"})
            with self.assertRaises(RequestValidationError):
                orchestrator.chat({"user_input": "hi", "session_id": "../bad"})

    def test_three_tool_rounds_are_followed_by_tool_less_completion(self) -> None:
        responses = [
            ProviderResponse(
                tool_calls=(ToolCall(f"call-{index}", "echo", "{}"),)
            )
            for index in range(MAX_TOOL_ROUNDS)
        ]
        responses.append(ProviderResponse(content="final"))
        with RuntimeFixture() as fixture:
            provider = ScriptedProvider(responses)
            result = self._orchestrator(fixture, provider).chat(
                {"user_input": "loop"}
            )

            self.assertEqual(result["response"], "final")
            self.assertEqual(len(provider.requests), MAX_TOOL_ROUNDS + 1)
            self.assertTrue(provider.requests[0].tools)
            self.assertEqual(provider.requests[-1].tools, ())
            self.assertIn("round limit reached", result["agent_logs"])

    def test_voice_delimiter_is_split_without_legacy_response_field(self) -> None:
        with RuntimeFixture() as fixture:
            provider = ScriptedProvider(
                [ProviderResponse(content="Formatted |||VOICE||| Spoken")]
            )
            orchestrator = self._orchestrator(
                fixture, provider, voice_mode=True
            )
            result = orchestrator.chat({"user_input": "voice"})

            self.assertEqual(result["response"], "Formatted")
            self.assertTrue(result["voice_mode"])
            self.assertNotIn("assistant_response", result)
            self.assertIn("|||VOICE|||", provider.requests[0].messages[0]["content"])

    def test_provider_errors_are_translated_to_typed_failure(self) -> None:
        with RuntimeFixture() as fixture:
            provider = ScriptedProvider([ProviderHTTPError(500, "failure")])
            orchestrator = self._orchestrator(fixture, provider)

            with self.assertRaises(OrchestratorProviderError) as raised:
                orchestrator.chat({"user_input": "hi"})

            self.assertNotIn("failure", str(raised.exception))

    def test_soul_and_agents_are_loaded_fresh_per_request(self) -> None:
        with RuntimeFixture() as fixture:
            path = fixture.write_agent("all_agent.py", AGENTS)
            provider = ScriptedProvider(
                [ProviderResponse(content="one"), ProviderResponse(content="two")]
            )
            registry = AgentRegistry(
                fixture.agents,
                storage=LocalStorage(fixture.data),
                compatibility_mode=True,
            )
            orchestrator = Orchestrator(
                soul_path=fixture.soul,
                registry=registry,
                provider=provider,
                model="requested-model",
            )
            orchestrator.chat({"user_input": "first"})
            fixture.soul.write_text("A changed soul.\n", encoding="utf-8")
            path.write_text(
                AGENTS.replace("Echo text.", "Changed description."),
                encoding="utf-8",
            )
            orchestrator.chat({"user_input": "second"})

            self.assertIn(
                "A changed soul.", provider.requests[1].messages[0]["content"]
            )
            descriptions = [
                tool["function"]["description"]
                for tool in provider.requests[1].tools
            ]
            self.assertIn("Changed description.", descriptions)

    @staticmethod
    def _orchestrator(
        fixture: RuntimeFixture,
        provider: ScriptedProvider,
        *,
        voice_mode: bool = False,
    ) -> Orchestrator:
        fixture.write_agent("all_agent.py", AGENTS)
        registry = AgentRegistry(
            fixture.agents,
            storage=LocalStorage(fixture.data),
            compatibility_mode=True,
        )
        return Orchestrator(
            soul_path=fixture.soul,
            registry=registry,
            provider=provider,
            model="requested-model",
            voice_mode=voice_mode,
        )


if __name__ == "__main__":
    unittest.main()
