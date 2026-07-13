"""Composition root for the isolated runtime."""

from __future__ import annotations

import os
import threading
from typing import Any

from .config import (
    RuntimeConfig,
    RuntimeConfigurationError,
    validate_python_version,
)
from .orchestrator import Orchestrator
from .provider import (
    AttestationProvider,
    CopilotProvider,
    Provider,
    ScriptedProvider,
)
from .registry import AgentRegistry, RegistrySnapshot
from .server import RuntimeServer
from .storage import LocalStorage

_AGENT_ENVIRONMENT_KEYS = (
    "RAPP_STACK_ROOT",
    "RAPP_STACK_DATA_DIR",
    "RAPP_STACK_PRINCIPAL",
    "RAPP_STACK_GENERATED_AGENTS_DIR",
    "RAPP_STACK_ALLOW_AGENT_WRITES",
    "RAPP_STACK_IMESSAGE_CONFIG",
    "RAPP_STACK_IMESSAGE_STATUS",
    "RAPP_STACK_TWIN_CHAT_STATE_DIR",
    "RAPP_STACK_TWIN_CHAT_REPLAY_DB",
)
_MISSING = object()
_PROCESS_CONTEXT_GUARD = threading.Lock()


class RuntimeApp:
    """Wire validated configuration into storage, registry, provider, and HTTP."""

    def __init__(
        self,
        config: RuntimeConfig,
        *,
        provider: Provider | None = None,
    ) -> None:
        if not isinstance(config, RuntimeConfig):
            raise TypeError("config must be a RuntimeConfig")
        validate_python_version()
        self.config = config
        self._agent_context = _ProcessAgentContext(config)
        self._closed = False
        self._agent_context.activate()
        try:
            self.storage = LocalStorage(config.data_root)
            self.registry = AgentRegistry(
                config.agent_directories,
                storage=self.storage,
            )
            if provider is None:
                if config.attestation_mode is not None:
                    self.provider = AttestationProvider()
                elif config.controller_route_enabled:
                    self.provider = ScriptedProvider([])
                else:
                    live_provider = CopilotProvider(
                        model=config.model,
                        timeout=config.provider_timeout,
                        github_token_file=config.github_token_file,
                    )
                    live_provider.validate_model(config.model)
                    self.provider = live_provider
            else:
                self.provider = provider
            self.orchestrator = Orchestrator(
                soul_path=config.soul_path,
                registry=self.registry,
                provider=self.provider,
                model=config.model,
                provider_timeout=config.provider_timeout,
                voice_mode=config.voice_mode,
                signed_ingress=config.signed_ingress,
                signed_only=config.signed_only,
                controller_route_enabled=config.controller_route_enabled,
            )
            self.startup_snapshot = self.validate_startup()
            self.server = RuntimeServer(
                self.orchestrator,
                host=config.host,
                port=config.port,
                request_timeout=config.request_timeout,
                instance_id=config.instance_id,
                auth_token=(
                    None
                    if config.auth_token_file is None
                    else _read_runtime_auth_token(config.auth_token_file)
                ),
            )
        except BaseException:
            self._agent_context.restore()
            raise

    @property
    def url(self) -> str:
        return self.server.url

    @property
    def health_url(self) -> str:
        return self.server.health_url

    def validate_startup(self) -> RegistrySnapshot:
        """Fail before binding if the soul or trusted agent set is invalid."""

        self.orchestrator.load_soul()
        snapshot = self.registry.load()
        if self.config.controller_route_enabled:
            from ..controller import (
                ControllerLoadoutError,
                verify_controller_loadout,
            )

            loadout = self.config.controller_loadout_root
            if loadout is None:
                raise RuntimeConfigurationError(
                    "controller loadout root is required"
                )
            try:
                verify_controller_loadout(loadout)
            except ControllerLoadoutError as error:
                raise RuntimeConfigurationError(
                    "controller loadout verification failed"
                ) from error
            if (
                self.config.agent_directories
                != (loadout / "agents",)
                or snapshot.names != ("RappStackCubbyController",)
            ):
                raise RuntimeConfigurationError(
                    "controller route requires the verified controller-only loadout"
                )
        return snapshot

    def serve_forever(self) -> None:
        self.server.serve_forever()

    def start(self) -> threading.Thread:
        return self.server.start_in_thread()

    def shutdown(self, timeout: float = 5.0) -> None:
        if self._closed:
            return
        try:
            self.server.shutdown(timeout)
        finally:
            self._closed = True
            self._agent_context.restore()

    close = shutdown

    def __enter__(self) -> "RuntimeApp":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.shutdown()


IsolatedRuntimeApp = RuntimeApp


def _read_runtime_auth_token(path: os.PathLike[str]) -> bytes:
    from .auth import read_auth_token

    return read_auth_token(path)


class _ProcessAgentContext:
    """Install one explicit process-global agent context for app lifetime."""

    def __init__(self, config: RuntimeConfig) -> None:
        self._config = config
        self._previous: dict[str, str | object] = {}
        self._active = False

    def activate(self) -> None:
        if not _PROCESS_CONTEXT_GUARD.acquire(blocking=False):
            raise RuntimeConfigurationError(
                "the runtime requires one dedicated process per agent context"
            )
        try:
            values: dict[str, str | None] = {
                "RAPP_STACK_ROOT": str(self._config.root),
                "RAPP_STACK_DATA_DIR": str(self._config.data_root),
                "RAPP_STACK_PRINCIPAL": self._config.principal,
                "RAPP_STACK_GENERATED_AGENTS_DIR": (
                    None
                    if self._config.generated_agents_dir is None
                    else str(self._config.generated_agents_dir)
                ),
                "RAPP_STACK_ALLOW_AGENT_WRITES": (
                    "1" if self._config.allow_agent_writes else None
                ),
                "RAPP_STACK_IMESSAGE_CONFIG": None,
                "RAPP_STACK_IMESSAGE_STATUS": (
                    None
                    if self._config.imessage_status_path is None
                    else str(self._config.imessage_status_path)
                ),
                "RAPP_STACK_TWIN_CHAT_STATE_DIR": None,
                "RAPP_STACK_TWIN_CHAT_REPLAY_DB": None,
            }
            if self._config.signed_ingress is not None:
                replay = self._config.signed_ingress.replay_db_path
                values["RAPP_STACK_TWIN_CHAT_STATE_DIR"] = str(replay.parent)
                values["RAPP_STACK_TWIN_CHAT_REPLAY_DB"] = str(replay)
            for key in _AGENT_ENVIRONMENT_KEYS:
                self._previous[key] = os.environ.get(key, _MISSING)
                value = values[key]
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
            self._active = True
        except BaseException:
            _PROCESS_CONTEXT_GUARD.release()
            raise

    def restore(self) -> None:
        if not self._active:
            return
        try:
            for key in _AGENT_ENVIRONMENT_KEYS:
                previous = self._previous.get(key, _MISSING)
                if previous is _MISSING:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = str(previous)
        finally:
            self._active = False
            _PROCESS_CONTEXT_GUARD.release()
