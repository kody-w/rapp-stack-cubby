from __future__ import annotations

import tempfile
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class RuntimeFixture:
    def __init__(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(
            prefix=".test-runtime-",
            dir=REPOSITORY_ROOT,
        )
        self.root = Path(self._temporary.name)
        self.agents = self.root / "agents"
        self.data = self.root / "data"
        self.soul = self.root / "soul.md"
        self.agents.mkdir()
        self.data.mkdir()
        self.soul.write_text("You are a test assistant.\n", encoding="utf-8")

    def write_agent(self, name: str, source: str) -> Path:
        path = self.agents / name
        path.write_text(source, encoding="utf-8")
        return path

    def cleanup(self) -> None:
        self._temporary.cleanup()

    def __enter__(self) -> "RuntimeFixture":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.cleanup()


ECHO_AGENT = """\
from basic_agent import BasicAgent

class EchoAgent(BasicAgent):
    name = "echo"
    metadata = {
        "name": "echo",
        "description": "Echo supplied text.",
        "parameters": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    }

    def perform(self, text="", **kwargs):
        return f"echo:{text}"
"""

STRICT_ECHO_AGENT = '''\
"""Strict synthetic actual agent."""

from basic_agent import BasicAgent

__manifest__ = {
    "schema": "rapp-agent/1.0",
    "name": "StrictEcho",
    "version": "1.0.0",
    "description": "Echo one bounded synthetic value.",
    "actions": ["run"],
    "capability_ids": [],
    "mutability": "read_only",
    "enabled_by_default": False,
    "provenance": "generated_local",
    "dependencies": ["python-stdlib", "BasicAgent"],
}

class StrictEcho(BasicAgent):
    name = "StrictEcho"
    metadata = {
        "name": "StrictEcho",
        "description": "Echo one bounded synthetic value.",
        "parameters": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["run"]},
                "text": {"type": "string"},
            },
            "required": ["action"],
            "additionalProperties": False,
        },
    }

    def perform(self, **kwargs):
        return "echo:" + kwargs.get("text", "")
'''
