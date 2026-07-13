from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from rapp_stack_cubby.runtime.registry import AgentRegistry
from rapp_stack_cubby.runtime.storage import LocalStorage

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CONTROLLER_DIRECTORY = REPOSITORY_ROOT / "cubbies/kody-w/agents"
RAPPID = (
    "rappid:@kody-w/controller-test:"
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)
PRODUCT_RAPPID = (
    "rappid:@kody-w/controller-product:"
    "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
)
IDENTITY_HASH = RAPPID.rsplit(":", 1)[1]


class ControllerEnvironment:
    def __init__(self, *, mutations: bool = True) -> None:
        self._temporary = tempfile.TemporaryDirectory(
            prefix=".test-controller-",
            dir=REPOSITORY_ROOT,
        )
        self.root = Path(self._temporary.name)
        self.controller_data = self.root / "controller"
        self.registry_data = self.root / "registry"
        self.registry_data.mkdir(mode=0o700)
        environment = {
            "RAPP_STACK_CONTROLLER_DATA_DIR": str(self.controller_data),
            "RAPP_STACK_ALLOW_CONTROLLER_MUTATIONS": "1" if mutations else "",
            "RAPP_STACK_ALLOW_DEVELOPMENT_HATCH": "1",
            "RAPP_STACK_PYTHON": "/opt/homebrew/bin/python3.11",
            "RAPP_STACK_MODEL": "synthetic-test-model",
        }
        self._environment = patch.dict(os.environ, environment, clear=False)
        self.agent = None
        self.globals = None

    def __enter__(self) -> "ControllerEnvironment":
        self._environment.start()
        snapshot = AgentRegistry(
            CONTROLLER_DIRECTORY,
            storage=LocalStorage(self.registry_data),
        ).load()
        self.agent = snapshot["RappStackCubbyController"]
        self.globals = self.agent.perform.__globals__
        return self

    def initialize(self) -> Path:
        assert self.globals is not None
        return self.globals["_initialize_layout"]()

    def create_twin(
        self,
        *,
        location: str = "active",
        runtime_status: str = "stopped",
        process: dict | None = None,
    ) -> Path:
        root = self.initialize()
        twin = root / "twins" / location / IDENTITY_HASH
        twin.mkdir(mode=0o700)
        workspace = twin / "workspace"
        for path in (
            twin / "source",
            workspace,
            workspace / "agents",
            workspace / "data",
            workspace / "generated-agents",
            workspace / "logs",
        ):
            path.mkdir(mode=0o700, exist_ok=True)
        (workspace / "soul.md").write_text("test soul\n", encoding="utf-8")
        os.chmod(workspace / "soul.md", 0o600)
        state = {
            "schema": "rapp-controller-twin-state/1.0",
            "rappid": RAPPID,
            "instance_rappid": RAPPID,
            "product_rappid": PRODUCT_RAPPID,
            "identity_hash": IDENTITY_HASH,
            "lifecycle_state": location,
            "runtime_status": runtime_status,
            "repository_url": "https://github.com/kody-w/rapp-stack-cubby.git",
            "source_commit": "a" * 40,
            "source_tree_digest": self.globals["_tree_digest"]([]),
            "release_manifest_sha256": None,
            "hatch_profile": "development_non_release",
            "selected_model": None,
            "attestation_mode": None,
            "signed_only": True,
            "created_at": "2026-07-12T00:00:00Z",
            "updated_at": "2026-07-12T00:00:00Z",
            "process": process,
        }
        (twin / "state.json").write_text(
            json.dumps(state, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.chmod(twin / "state.json", 0o600)
        return twin

    def create_provider_token(self) -> Path:
        path = self.root / "provider-token.json"
        path.write_text(
            json.dumps({"access_token": "synthetic-controller-access"})
            + "\n",
            encoding="utf-8",
        )
        os.chmod(path, 0o600)
        return path

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self._environment.stop()
        self._temporary.cleanup()


def decoded(agent, **kwargs):
    value = agent.perform(**kwargs)
    if not isinstance(value, str):
        raise AssertionError("controller actions must return JSON strings")
    result = json.loads(value)
    if not isinstance(result, dict):
        raise AssertionError("controller action result must be an object")
    return result
