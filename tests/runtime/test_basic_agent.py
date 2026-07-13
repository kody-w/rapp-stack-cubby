from __future__ import annotations

import unittest

from rapp_stack_cubby.runtime.basic_agent import (
    AgentExecutionError,
    AgentValidationError,
    BasicAgent,
    validate_agent,
    validate_agent_name,
    validate_metadata,
)


def metadata(name: str = "echo") -> dict:
    return {
        "name": name,
        "description": "Echo a value.",
        "parameters": {
            "type": "object",
            "properties": {"value": {"type": "string"}},
            "required": ["value"],
        },
    }


class BasicAgentTests(unittest.TestCase):
    def test_compatible_constructor_and_tool_schema(self) -> None:
        agent = BasicAgent("echo", metadata())
        tool = agent.to_tool()

        self.assertEqual(tool["type"], "function")
        self.assertEqual(tool["function"]["name"], "echo")
        self.assertEqual(tool["function"]["parameters"]["type"], "object")

    def test_tool_schema_is_an_isolated_copy(self) -> None:
        agent = BasicAgent("echo", metadata())
        tool = agent.to_tool()
        tool["function"]["parameters"]["properties"].clear()

        self.assertIn("value", agent.metadata["parameters"]["properties"])

    def test_name_validation_is_informative(self) -> None:
        for value in ("", "has space", "x" * 65, "../escape", None):
            with self.subTest(value=value):
                with self.assertRaises(AgentValidationError):
                    validate_agent_name(value)

    def test_metadata_requires_description_and_object_parameters(self) -> None:
        with self.assertRaisesRegex(AgentValidationError, "description"):
            validate_metadata({"parameters": {"type": "object"}})
        with self.assertRaisesRegex(AgentValidationError, "type must be 'object'"):
            validate_metadata(
                {
                    "description": "bad",
                    "parameters": {"type": "array"},
                }
            )

    def test_required_parameters_must_exist_in_properties(self) -> None:
        invalid = metadata()
        invalid["parameters"]["required"] = ["missing"]

        with self.assertRaisesRegex(AgentValidationError, "missing"):
            validate_metadata(invalid, agent_name="echo")

    def test_base_perform_raises_typed_error(self) -> None:
        with self.assertRaises(AgentExecutionError):
            BasicAgent("echo", metadata()).perform(value="x")

    def test_validate_agent_rejects_non_basic_object(self) -> None:
        class Lookalike:
            name = "echo"
            metadata = metadata()

            def perform(self, **kwargs):
                return kwargs

        with self.assertRaisesRegex(AgentValidationError, "inherit"):
            validate_agent(Lookalike())

    def test_default_system_context_is_optional(self) -> None:
        self.assertIsNone(BasicAgent("echo", metadata()).system_context())


if __name__ == "__main__":
    unittest.main()
