from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from rapp_stack_cubby.runtime.registry import AgentRegistry
from rapp_stack_cubby.runtime.storage import LocalStorage

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
AGENTS_DIRECTORY = (
    REPOSITORY_ROOT
    / "cubbies"
    / "kody-w"
    / "rapplications"
    / "rapp-stack"
    / "twin"
    / "agents"
)


class AgentEnvironment:
    def __init__(self, *, writes: bool = False, principal: str = "principal-a"):
        self._temporary = tempfile.TemporaryDirectory(
            prefix=".test-agents-",
            dir=REPOSITORY_ROOT,
        )
        self.root = Path(self._temporary.name)
        self.data = self.root / "data"
        self.generated = self.root / "generated"
        self.data.mkdir(mode=0o700)
        self.generated.mkdir(mode=0o700)
        environment = {
            "RAPP_STACK_ROOT": str(REPOSITORY_ROOT),
            "RAPP_STACK_DATA_DIR": str(self.data),
            "RAPP_STACK_GENERATED_AGENTS_DIR": str(self.generated),
            "RAPP_STACK_PRINCIPAL": principal,
        }
        if writes:
            environment["RAPP_STACK_ALLOW_AGENT_WRITES"] = "1"
        else:
            environment["RAPP_STACK_ALLOW_AGENT_WRITES"] = ""
        self._environment = patch.dict(os.environ, environment, clear=False)
        self.snapshot = None

    def __enter__(self) -> "AgentEnvironment":
        self._environment.start()
        self.snapshot = AgentRegistry(
            AGENTS_DIRECTORY,
            storage=LocalStorage(self.data),
        ).load()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self._environment.stop()
        self._temporary.cleanup()


def decoded(agent, **kwargs):
    result = agent.perform(**kwargs)
    if not isinstance(result, str):
        raise AssertionError("perform must return a JSON string")
    value = json.loads(result)
    if not isinstance(value, dict):
        raise AssertionError("perform result must decode to an object")
    return value
