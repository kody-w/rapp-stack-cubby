"""Stable BasicAgent ABI and schema validation."""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Mapping
from typing import Any

_TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_MAX_DESCRIPTION_LENGTH = 4096
_MAX_METADATA_BYTES = 256 * 1024


class AgentError(Exception):
    """Base class for agent ABI failures."""


class AgentValidationError(AgentError, ValueError):
    """Raised when an agent does not satisfy the BasicAgent ABI."""


class AgentExecutionError(AgentError, RuntimeError):
    """Raised when an agent cannot be executed safely."""


def validate_agent_name(name: object) -> str:
    """Validate and return an OpenAI-compatible function name."""

    if not isinstance(name, str):
        raise AgentValidationError("agent name must be a string")
    if not _TOOL_NAME_RE.fullmatch(name):
        raise AgentValidationError(
            "agent name must contain 1-64 ASCII letters, digits, '_' or '-'"
        )
    return name


def validate_parameters_schema(parameters: object) -> dict[str, Any]:
    """Validate the supported object-shaped function parameter schema."""

    if not isinstance(parameters, Mapping):
        raise AgentValidationError("metadata.parameters must be an object")
    normalized = copy.deepcopy(dict(parameters))
    if normalized.get("type") != "object":
        raise AgentValidationError("metadata.parameters.type must be 'object'")

    properties = normalized.get("properties", {})
    if not isinstance(properties, Mapping):
        raise AgentValidationError("metadata.parameters.properties must be an object")
    if not all(isinstance(key, str) and key for key in properties):
        raise AgentValidationError(
            "metadata.parameters.properties keys must be non-empty strings"
        )
    normalized["properties"] = copy.deepcopy(dict(properties))

    required = normalized.get("required", [])
    if not isinstance(required, list) or not all(
        isinstance(item, str) and item for item in required
    ):
        raise AgentValidationError(
            "metadata.parameters.required must be an array of non-empty strings"
        )
    if len(set(required)) != len(required):
        raise AgentValidationError(
            "metadata.parameters.required must not contain duplicates"
        )
    unknown_required = sorted(set(required) - set(properties))
    if unknown_required:
        raise AgentValidationError(
            "metadata.parameters.required names missing from properties: "
            + ", ".join(unknown_required)
        )
    normalized["required"] = list(required)
    _validate_json_value(normalized, "metadata.parameters")
    return normalized


def validate_metadata(
    metadata: object, *, agent_name: str | None = None
) -> dict[str, Any]:
    """Validate and return an isolated copy of agent metadata."""

    if not isinstance(metadata, Mapping):
        raise AgentValidationError("agent metadata must be an object")
    normalized = copy.deepcopy(dict(metadata))

    description = normalized.get("description")
    if not isinstance(description, str) or not description.strip():
        raise AgentValidationError(
            "metadata.description must be a non-empty string"
        )
    if len(description) > _MAX_DESCRIPTION_LENGTH:
        raise AgentValidationError(
            f"metadata.description exceeds {_MAX_DESCRIPTION_LENGTH} characters"
        )

    declared_name = normalized.get("name")
    if declared_name is not None:
        validate_agent_name(declared_name)
        if agent_name is not None and declared_name != agent_name:
            raise AgentValidationError(
                "metadata.name must match the agent name"
            )

    normalized["parameters"] = validate_parameters_schema(
        normalized.get(
            "parameters",
            {"type": "object", "properties": {}, "required": []},
        )
    )
    _validate_json_value(normalized, "agent metadata")
    encoded = json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(encoded) > _MAX_METADATA_BYTES:
        raise AgentValidationError(
            f"agent metadata exceeds {_MAX_METADATA_BYTES} bytes"
        )
    return normalized


def validate_agent(agent: object) -> "BasicAgent":
    """Validate an instantiated BasicAgent and return it."""

    if not isinstance(agent, BasicAgent):
        raise AgentValidationError("agent class must inherit from BasicAgent")
    name = validate_agent_name(getattr(agent, "name", None))
    metadata = validate_metadata(getattr(agent, "metadata", None), agent_name=name)
    if not callable(getattr(agent, "perform", None)):
        raise AgentValidationError("agent.perform must be callable")
    context = getattr(agent, "system_context", None)
    if context is not None and not callable(context):
        raise AgentValidationError("agent.system_context must be callable")
    agent.name = name
    agent.metadata = metadata
    return agent


class BasicAgent:
    """Frozen compatibility surface for independently loaded RAPP agents."""

    name = "BasicAgent"
    metadata: Mapping[str, Any] = {
        "name": "BasicAgent",
        "description": "Base agent; override this implementation.",
        "parameters": {"type": "object", "properties": {}, "required": []},
    }

    def __init__(
        self,
        name: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        selected_name = name if name is not None else getattr(self, "name", None)
        selected_metadata = (
            metadata if metadata is not None else getattr(self, "metadata", None)
        )
        self.name = validate_agent_name(selected_name)
        self.metadata = validate_metadata(
            selected_metadata,
            agent_name=self.name,
        )

    def perform(self, **kwargs: Any) -> Any:
        """Perform the agent operation."""

        raise AgentExecutionError(
            f"agent {self.name!r} does not implement perform(**kwargs)"
        )

    def system_context(self) -> str | None:
        """Return optional context to append to the system prompt."""

        return None

    def to_tool(self) -> dict[str, Any]:
        """Return a validated OpenAI function-tool declaration."""

        validate_agent(self)
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.metadata["description"],
                "parameters": copy.deepcopy(self.metadata["parameters"]),
            },
        }


def _validate_json_value(value: object, label: str) -> None:
    try:
        json.dumps(value, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise AgentValidationError(f"{label} must contain only JSON values") from error
