"""Deterministic loading of trusted, explicitly configured local agents."""

from __future__ import annotations

import ast
import hashlib
import inspect
import os
import re
import sys
import threading
import types
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final

from ..catalog import (
    CatalogValidationError,
    inspect_agent_source,
    inspect_controller_source,
)
from .basic_agent import (
    AgentValidationError,
    BasicAgent,
    validate_agent,
)
from .storage import (
    AzureFileStorageManager,
    LocalStorage,
    configured_storage_manager,
    safe_json_loads,
)

DEFAULT_MAX_AGENT_BYTES: Final = 1024 * 1024
_AGENT_FILE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*_agent\.py$")
_DEPENDENCY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")
_IMPORT_LOCK = threading.RLock()
_SHIM_NAMES = (
    "agents",
    "agents.basic_agent",
    "basic_agent",
    "utils",
    "utils.azure_file_storage",
)


class RegistryError(Exception):
    """Base class for registry failures."""


class RegistryConfigurationError(RegistryError, ValueError):
    """Raised when trusted registry roots are not explicit and valid."""


class RegistryLoadError(RegistryError):
    """Raised when one or more candidate agent files are rejected."""

    def __init__(self, report: "RegistryLoadReport") -> None:
        self.report = report
        codes = sorted({record.error_code for record in report.records if record.error_code})
        detail = ", ".join(codes) if codes else "unknown_error"
        super().__init__(f"agent registry load failed ({detail})")


@dataclass(frozen=True, slots=True)
class AgentLoadRecord:
    """One auditable candidate-file result."""

    directory_index: int
    file_name: str
    status: str
    agent_names: tuple[str, ...] = ()
    shims_used: tuple[str, ...] = ()
    error_code: str | None = None
    error_type: str | None = None
    detail: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "directory_index": self.directory_index,
            "file": self.file_name,
            "status": self.status,
            "agent_names": list(self.agent_names),
            "shims_used": list(self.shims_used),
            "error_code": self.error_code,
            "error_type": self.error_type,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class RegistryLoadReport:
    """Structured evidence for one complete registry refresh."""

    directory_count: int
    records: tuple[AgentLoadRecord, ...]

    @property
    def ok(self) -> bool:
        return all(record.status == "loaded" for record in self.records)

    @property
    def candidate_count(self) -> int:
        return len(self.records)

    @property
    def loaded_file_count(self) -> int:
        return sum(record.status == "loaded" for record in self.records)

    @property
    def loaded_agent_count(self) -> int:
        return sum(len(record.agent_names) for record in self.records)

    @property
    def error_count(self) -> int:
        return sum(record.status == "rejected" for record in self.records)

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "directory_count": self.directory_count,
            "candidate_count": self.candidate_count,
            "loaded_file_count": self.loaded_file_count,
            "loaded_agent_count": self.loaded_agent_count,
            "error_count": self.error_count,
            "records": [record.as_dict() for record in self.records],
        }


class RegistrySnapshot(Mapping[str, BasicAgent]):
    """Immutable agents and report from one deterministic load."""

    def __init__(
        self,
        agents: Mapping[str, BasicAgent],
        load_report: RegistryLoadReport,
    ) -> None:
        ordered = {name: agents[name] for name in sorted(agents)}
        self._agents = MappingProxyType(ordered)
        self.load_report = load_report

    @property
    def report(self) -> RegistryLoadReport:
        return self.load_report

    @property
    def agents(self) -> Mapping[str, BasicAgent]:
        return self._agents

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(self._agents)

    @property
    def tools(self) -> tuple[dict[str, Any], ...]:
        return tuple(agent.to_tool() for agent in self._agents.values())

    def __getitem__(self, name: str) -> BasicAgent:
        return self._agents[name]

    def __iter__(self) -> Iterator[str]:
        return iter(self._agents)

    def __len__(self) -> int:
        return len(self._agents)


class AgentRegistry:
    """Loads top-level ``*_agent.py`` files from fixed local directories."""

    def __init__(
        self,
        directories: str
        | os.PathLike[str]
        | Iterable[str | os.PathLike[str]],
        *,
        storage: LocalStorage | None = None,
        data_root: str | os.PathLike[str] | None = None,
        max_agent_bytes: int = DEFAULT_MAX_AGENT_BYTES,
        compatibility_mode: bool = False,
    ) -> None:
        if isinstance(directories, (str, os.PathLike)):
            supplied_directories = (Path(directories),)
        else:
            supplied_directories = tuple(Path(item) for item in directories)
        if not supplied_directories:
            raise RegistryConfigurationError(
                "at least one explicit agents directory is required"
            )
        if not isinstance(max_agent_bytes, int) or isinstance(max_agent_bytes, bool):
            raise RegistryConfigurationError("max_agent_bytes must be an integer")
        if max_agent_bytes < 1:
            raise RegistryConfigurationError("max_agent_bytes must be positive")
        if not isinstance(compatibility_mode, bool):
            raise RegistryConfigurationError(
                "compatibility_mode must be boolean"
            )
        if storage is not None and data_root is not None:
            raise RegistryConfigurationError(
                "provide storage or data_root, not both"
            )
        if storage is None:
            if data_root is None:
                raise RegistryConfigurationError(
                    "an explicit storage instance or data_root is required"
                )
            storage = LocalStorage(data_root)

        directories_resolved: list[Path] = []
        for directory in supplied_directories:
            if ".." in directory.parts:
                raise RegistryConfigurationError(
                    "agents directory must not contain traversal"
                )
            if directory.is_symlink():
                raise RegistryConfigurationError(
                    "agents directory must not be a symbolic link"
                )
            try:
                resolved = directory.resolve(strict=True)
            except OSError as error:
                raise RegistryConfigurationError(
                    "configured agents directory does not exist"
                ) from error
            if not resolved.is_dir():
                raise RegistryConfigurationError(
                    "configured agents path must be a directory"
                )
            if resolved in directories_resolved:
                raise RegistryConfigurationError(
                    "configured agents directories must be unique"
                )
            directories_resolved.append(resolved)

        self._directories = tuple(directories_resolved)
        self._storage = storage
        self._max_agent_bytes = max_agent_bytes
        self._compatibility_mode = compatibility_mode

    @property
    def directories(self) -> tuple[Path, ...]:
        return self._directories

    @property
    def storage(self) -> LocalStorage:
        return self._storage

    def load(self) -> RegistrySnapshot:
        """Load a fresh snapshot, rejecting the entire refresh on any error."""

        records: list[AgentLoadRecord] = []
        loaded: dict[str, BasicAgent] = {}
        owners: dict[str, str] = {}

        with _IMPORT_LOCK:
            for directory_index, directory in enumerate(self._directories):
                candidates, discovery_records = self._discover(
                    directory_index, directory
                )
                records.extend(discovery_records)
                for candidate in candidates:
                    record, agents = self._load_file(
                        directory_index,
                        candidate,
                    )
                    if record.status == "loaded":
                        duplicates = [
                            agent.name for agent in agents if agent.name in loaded
                        ]
                        if duplicates:
                            duplicate = sorted(duplicates)[0]
                            record = AgentLoadRecord(
                                directory_index=directory_index,
                                file_name=candidate.name,
                                status="rejected",
                                shims_used=record.shims_used,
                                error_code="duplicate_tool_name",
                                detail=(
                                    f"tool {duplicate!r} is already declared by "
                                    f"{owners[duplicate]}"
                                ),
                            )
                        else:
                            for agent in agents:
                                loaded[agent.name] = agent
                                owners[agent.name] = candidate.name
                    records.append(record)

        report = RegistryLoadReport(
            directory_count=len(self._directories),
            records=tuple(records),
        )
        if not report.ok:
            raise RegistryLoadError(report)
        return RegistrySnapshot(loaded, report)

    refresh = load
    snapshot = load

    def _discover(
        self, directory_index: int, directory: Path
    ) -> tuple[list[Path], list[AgentLoadRecord]]:
        try:
            entries = sorted(directory.iterdir(), key=lambda path: path.name)
        except OSError as error:
            return [], [
                AgentLoadRecord(
                    directory_index=directory_index,
                    file_name="<directory>",
                    status="rejected",
                    error_code="directory_read_error",
                    error_type=type(error).__name__,
                )
            ]

        candidates: list[Path] = []
        records: list[AgentLoadRecord] = []
        for entry in entries:
            if not entry.name.endswith("_agent.py"):
                continue
            if not _AGENT_FILE_RE.fullmatch(entry.name):
                records.append(
                    AgentLoadRecord(
                        directory_index=directory_index,
                        file_name=entry.name,
                        status="rejected",
                        error_code="unsafe_file_name",
                    )
                )
                continue
            if entry.is_symlink():
                records.append(
                    AgentLoadRecord(
                        directory_index=directory_index,
                        file_name=entry.name,
                        status="rejected",
                        error_code="symlink",
                    )
                )
                continue
            if not entry.is_file():
                records.append(
                    AgentLoadRecord(
                        directory_index=directory_index,
                        file_name=entry.name,
                        status="rejected",
                        error_code="not_regular_file",
                    )
                )
                continue
            try:
                if entry.parent.resolve(strict=True) != directory:
                    raise OSError
                size = entry.stat(follow_symlinks=False).st_size
            except OSError:
                records.append(
                    AgentLoadRecord(
                        directory_index=directory_index,
                        file_name=entry.name,
                        status="rejected",
                        error_code="file_stat_error",
                    )
                )
                continue
            if size > self._max_agent_bytes:
                records.append(
                    AgentLoadRecord(
                        directory_index=directory_index,
                        file_name=entry.name,
                        status="rejected",
                        error_code="oversized_file",
                        detail=f"limit is {self._max_agent_bytes} bytes",
                    )
                )
                continue
            candidates.append(entry)
        return candidates, records

    def _load_file(
        self, directory_index: int, path: Path
    ) -> tuple[AgentLoadRecord, tuple[BasicAgent, ...]]:
        try:
            source = self._read_source(path)
        except RegistryError as error:
            return (
                AgentLoadRecord(
                    directory_index,
                    path.name,
                    "rejected",
                    error_code="file_read_error",
                    error_type=type(error).__name__,
                ),
                (),
            )

        try:
            tree = ast.parse(source, filename=path.name)
        except SyntaxError as error:
            return (
                AgentLoadRecord(
                    directory_index,
                    path.name,
                    "rejected",
                    error_code="syntax_error",
                    error_type=type(error).__name__,
                    detail=f"line {error.lineno or 0}",
                ),
                (),
            )
        if not self._compatibility_mode:
            try:
                inspected = (
                    inspect_controller_source(path)
                    if path.name == "rapp_stack_cubby_agent.py"
                    else inspect_agent_source(path)
                )
            except (CatalogValidationError, OSError, UnicodeError) as error:
                return (
                    AgentLoadRecord(
                        directory_index,
                        path.name,
                        "rejected",
                        error_code="invalid_agent_contract",
                        error_type=type(error).__name__,
                    ),
                    (),
                )
            source_digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
            if inspected.get("sha256") != source_digest:
                return (
                    AgentLoadRecord(
                        directory_index,
                        path.name,
                        "rejected",
                        error_code="agent_changed_during_load",
                    ),
                    (),
                )
        shims_used = _detect_shims(tree)
        module_name = "_rapp_stack_cubby_agent_" + hashlib.sha256(
            f"{directory_index}:{path.name}".encode("utf-8")
        ).hexdigest()[:20]
        module = types.ModuleType(module_name)
        module.__file__ = path.name
        module.__package__ = ""

        try:
            code = compile(tree, path.name, "exec", dont_inherit=True)
            with self._installed_shims():
                sys.modules[module_name] = module
                try:
                    exec(code, module.__dict__)
                finally:
                    sys.modules.pop(module_name, None)
        except ModuleNotFoundError as error:
            dependency = _safe_dependency_name(error.name)
            return (
                AgentLoadRecord(
                    directory_index,
                    path.name,
                    "rejected",
                    shims_used=shims_used,
                    error_code="missing_dependency",
                    error_type=type(error).__name__,
                    detail=dependency,
                ),
                (),
            )
        except ImportError as error:
            return (
                AgentLoadRecord(
                    directory_index,
                    path.name,
                    "rejected",
                    shims_used=shims_used,
                    error_code="import_error",
                    error_type=type(error).__name__,
                ),
                (),
            )
        except SystemExit as error:
            return (
                AgentLoadRecord(
                    directory_index,
                    path.name,
                    "rejected",
                    shims_used=shims_used,
                    error_code="module_execution_error",
                    error_type=type(error).__name__,
                ),
                (),
            )
        except Exception as error:
            return (
                AgentLoadRecord(
                    directory_index,
                    path.name,
                    "rejected",
                    shims_used=shims_used,
                    error_code="module_execution_error",
                    error_type=type(error).__name__,
                ),
                (),
            )

        classes = [
            value
            for _, value in sorted(module.__dict__.items())
            if inspect.isclass(value) and value.__module__ == module_name
        ]
        invalid_classes = [
            value.__name__
            for value in classes
            if value.__name__.endswith("Agent")
            and not issubclass(value, BasicAgent)
        ]
        if invalid_classes:
            return (
                AgentLoadRecord(
                    directory_index,
                    path.name,
                    "rejected",
                    shims_used=shims_used,
                    error_code="non_basic_agent_class",
                    detail=", ".join(sorted(invalid_classes)),
                ),
                (),
            )
        agent_classes = [
            value
            for value in classes
            if issubclass(value, BasicAgent) and value is not BasicAgent
        ]
        if not agent_classes:
            return (
                AgentLoadRecord(
                    directory_index,
                    path.name,
                    "rejected",
                    shims_used=shims_used,
                    error_code="missing_agent_class",
                ),
                (),
            )
        if not self._compatibility_mode and len(agent_classes) != 1:
            return (
                AgentLoadRecord(
                    directory_index,
                    path.name,
                    "rejected",
                    shims_used=shims_used,
                    error_code="invalid_agent_contract",
                ),
                (),
            )
        if not self._compatibility_mode:
            try:
                _validate_runtime_perform_signature(agent_classes[0])
            except (TypeError, ValueError):
                return (
                    AgentLoadRecord(
                        directory_index,
                        path.name,
                        "rejected",
                        shims_used=shims_used,
                        error_code="invalid_agent_contract",
                    ),
                    (),
                )

        agents: list[BasicAgent] = []
        for agent_class in sorted(agent_classes, key=lambda item: item.__name__):
            try:
                agent = agent_class()
            except ModuleNotFoundError as error:
                return (
                    AgentLoadRecord(
                        directory_index,
                        path.name,
                        "rejected",
                        shims_used=shims_used,
                        error_code="missing_dependency",
                        error_type=type(error).__name__,
                        detail=_safe_dependency_name(error.name),
                    ),
                    (),
                )
            except AgentValidationError as error:
                return (
                    AgentLoadRecord(
                        directory_index,
                        path.name,
                        "rejected",
                        shims_used=shims_used,
                        error_code="invalid_agent_metadata",
                        error_type=type(error).__name__,
                        detail=str(error),
                    ),
                    (),
                )
            except SystemExit as error:
                return (
                    AgentLoadRecord(
                        directory_index,
                        path.name,
                        "rejected",
                        shims_used=shims_used,
                        error_code="constructor_error",
                        error_type=type(error).__name__,
                        detail=agent_class.__name__,
                    ),
                    (),
                )
            except Exception as error:
                return (
                    AgentLoadRecord(
                        directory_index,
                        path.name,
                        "rejected",
                        shims_used=shims_used,
                        error_code="constructor_error",
                        error_type=type(error).__name__,
                        detail=agent_class.__name__,
                    ),
                    (),
                )
            try:
                validate_agent(agent)
                agent.to_tool()
            except AgentValidationError as error:
                return (
                    AgentLoadRecord(
                        directory_index,
                        path.name,
                        "rejected",
                        shims_used=shims_used,
                        error_code="invalid_agent_metadata",
                        error_type=type(error).__name__,
                        detail=str(error),
                    ),
                    (),
                )
            agents.append(agent)

        names = [agent.name for agent in agents]
        if len(set(names)) != len(names):
            return (
                AgentLoadRecord(
                    directory_index,
                    path.name,
                    "rejected",
                    shims_used=shims_used,
                    error_code="duplicate_tool_name",
                ),
                (),
            )
        return (
            AgentLoadRecord(
                directory_index,
                path.name,
                "loaded",
                agent_names=tuple(sorted(names)),
                shims_used=shims_used,
            ),
            tuple(sorted(agents, key=lambda agent: agent.name)),
        )

    def _read_source(self, path: Path) -> str:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            raise RegistryError("agent source cannot be opened") from error
        try:
            stat_result = os.fstat(descriptor)
            if stat_result.st_size > self._max_agent_bytes:
                raise RegistryError("agent source exceeds the size limit")
            chunks: list[bytes] = []
            remaining = self._max_agent_bytes + 1
            while remaining:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > self._max_agent_bytes:
                raise RegistryError("agent source exceeds the size limit")
        except OSError as error:
            raise RegistryError("agent source cannot be read") from error
        finally:
            os.close(descriptor)
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise RegistryError("agent source must be UTF-8") from error

    def _installed_shims(self) -> "_ShimContext":
        storage_class = configured_storage_manager(self._storage)
        basic_module = types.ModuleType("basic_agent")
        basic_module.BasicAgent = BasicAgent

        agents_package = types.ModuleType("agents")
        agents_package.__path__ = []
        agents_basic_module = types.ModuleType("agents.basic_agent")
        agents_basic_module.BasicAgent = BasicAgent
        agents_package.basic_agent = agents_basic_module

        utils_package = types.ModuleType("utils")
        utils_package.__path__ = []
        storage_module = types.ModuleType("utils.azure_file_storage")
        storage_module.AzureFileStorageManager = storage_class
        storage_module.LocalStorageManager = storage_class
        storage_module.safe_json_loads = safe_json_loads
        utils_package.azure_file_storage = storage_module

        return _ShimContext(
            {
                "basic_agent": basic_module,
                "agents": agents_package,
                "agents.basic_agent": agents_basic_module,
                "utils": utils_package,
                "utils.azure_file_storage": storage_module,
            }
        )


class _ShimContext:
    def __init__(self, replacements: Mapping[str, types.ModuleType]) -> None:
        self._replacements = replacements
        self._previous: dict[str, types.ModuleType] = {}
        self._missing: set[str] = set()

    def __enter__(self) -> None:
        for name in _SHIM_NAMES:
            if name in sys.modules:
                self._previous[name] = sys.modules[name]
            else:
                self._missing.add(name)
            sys.modules[name] = self._replacements[name]

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        for name in reversed(_SHIM_NAMES):
            if name in self._missing:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = self._previous[name]


def load_agents(
    directories: str
    | os.PathLike[str]
    | Iterable[str | os.PathLike[str]],
    *,
    storage: LocalStorage | None = None,
    data_root: str | os.PathLike[str] | None = None,
    max_agent_bytes: int = DEFAULT_MAX_AGENT_BYTES,
    compatibility_mode: bool = False,
) -> RegistrySnapshot:
    """Convenience entry point for a one-shot deterministic refresh."""

    return AgentRegistry(
        directories,
        storage=storage,
        data_root=data_root,
        max_agent_bytes=max_agent_bytes,
        compatibility_mode=compatibility_mode,
    ).load()


def _detect_shims(tree: ast.AST) -> tuple[str, ...]:
    used: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in _SHIM_NAMES:
                    used.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module in _SHIM_NAMES:
                used.add(node.module)
    return tuple(sorted(used))


def _safe_dependency_name(name: str | None) -> str:
    if isinstance(name, str) and _DEPENDENCY_RE.fullmatch(name):
        return name
    return "<unavailable>"


def _validate_runtime_perform_signature(
    agent_class: type[BasicAgent],
) -> None:
    method = vars(agent_class).get("perform")
    if not inspect.isfunction(method) or inspect.iscoroutinefunction(method):
        raise TypeError("perform must be a synchronous instance method")
    parameters = tuple(
        inspect.signature(method, follow_wrapped=False).parameters.values()
    )
    if (
        len(parameters) != 2
        or parameters[0].name != "self"
        or parameters[0].kind is not inspect.Parameter.POSITIONAL_OR_KEYWORD
        or parameters[0].default is not inspect.Parameter.empty
        or parameters[1].name != "kwargs"
        or parameters[1].kind is not inspect.Parameter.VAR_KEYWORD
    ):
        raise TypeError(
            "perform must have exactly the signature (self, **kwargs)"
        )


AgentRegistrySnapshot = RegistrySnapshot
LoadReport = RegistryLoadReport
