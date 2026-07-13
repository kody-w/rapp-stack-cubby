"""Deterministic builders and validators for the local actual-agent catalogs."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final

from .constants import (
    AGENT_CATALOG_SCHEMA,
    CONTROLLER_CATALOG_SCHEMA,
    EXPECTED_ACTUAL_AGENT_COUNT,
    EXPECTED_CAPABILITY_COUNT,
    EXPECTED_SELECTED_CAPABILITY_COUNT,
    IMPLEMENTATION_MATRIX_SCHEMA,
)

AGENTS_RELATIVE: Final = Path(
    "cubbies/kody-w/rapplications/rapp-stack/twin/agents"
)
CATALOG_RELATIVE: Final = Path(
    "cubbies/kody-w/rapplications/rapp-stack/twin/catalog/agent-catalog.json"
)
IMPLEMENTATION_MATRIX_RELATIVE: Final = Path(
    "cubbies/kody-w/rapplications/rapp-stack/twin/catalog/"
    "implementation-matrix.json"
)
CAPABILITY_MATRIX_RELATIVE: Final = Path("CAPABILITY_MATRIX.json")
CONTROLLER_AGENT_RELATIVE: Final = Path(
    "cubbies/kody-w/agents/rapp_stack_cubby_agent.py"
)
CONTROLLER_CATALOG_RELATIVE: Final = Path(
    "cubbies/kody-w/catalog/controller-catalog.json"
)

_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_AGENT_NAME_RE = re.compile(r"^[A-Z][A-Za-z0-9]{0,63}$")
_ACTION_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_CAPABILITY_RE = re.compile(
    r"^[a-z][a-z0-9-]*\.[a-z0-9][a-z0-9.-]*$"
)
_ABSOLUTE_LOCAL_PATH_RE = re.compile(
    r"(?:/(?:Users|home)/[^/\s]+/|[A-Za-z]:\\Users\\[^\\\s]+\\)"
)
_REQUIRED_MANIFEST_KEYS = frozenset(
    {
        "schema",
        "name",
        "version",
        "description",
        "actions",
        "capability_ids",
        "mutability",
        "enabled_by_default",
        "provenance",
        "dependencies",
    }
)
_BASIC_AGENT_IMPORTS = frozenset({"agents.basic_agent", "basic_agent"})
_STORAGE_SHIM_IMPORT = "utils.azure_file_storage"
_AGENT_PROVENANCE = frozenset({"original_new", "generated_local"})
_AGENT_MUTABILITY = frozenset(
    {
        "read_only",
        "guarded_generated_files",
        "guarded_local_state",
        "guarded_local_lifecycle",
    }
)
_CONTROLLER_ALLOWED_EXTERNAL_ROOTS = frozenset({"cryptography"})
_FORBIDDEN_IMPORT_ROOTS = frozenset(
    {
        "aiohttp",
        "ftplib",
        "httpx",
        "pip",
        "requests",
        "socket",
        "subprocess",
        "urllib3",
    }
)
_FORBIDDEN_CALLS = frozenset(
    {
        "__import__",
        "eval",
        "exec",
        "os.popen",
        "os.system",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.run",
    }
)
_FUTURE_TASKS = frozenset(
    {
        "release-attestation",
    }
)
_PAGES_OWNERS = frozenset({"static-handoff"})
_PACKAGING_OWNERS = frozenset(
    {
        "artifact-build",
        "dependency-fetch",
        "hatch",
        "indexes",
        "provenance",
        "publication-scan",
        "source-manifest",
        "verification",
    }
)
_RUNTIME_OWNERS = frozenset(
    {
        "agent-registry/load",
        "basic-agent/abi",
        "isolated-runtime/chat",
        "isolated-runtime/clean-room",
        "isolated-runtime/no-dynamic-code",
        "imessage-bridge/ingest",
        "imessage-bridge/owner-only",
        "imessage-bridge/trust",
        "imessage-state/echo-suppression",
        "imessage-state/outbox-recovery",
        "local-storage/isolation",
        "orchestrator/tool-call-loop",
        "server-config/loopback",
        "signed-ingress/replay-journal",
        "signed-ingress/signed-response",
        "signed-ingress/twin-chat",
    }
)
_EXACT_PERFORM_ABI: Final = {
    "decorated": False,
    "signature": "def perform(self, **kwargs)",
    "synchronous": True,
}


class CatalogValidationError(ValueError):
    """Raised when generated catalog data does not match its source."""


def canonical_json_bytes(value: Any) -> bytes:
    """Return the repository's deterministic JSON representation."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_file(path: Path) -> str:
    """Hash one regular, non-symlink file."""

    if path.is_symlink() or not path.is_file():
        raise CatalogValidationError(f"{path.name}: expected a regular file")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inspect_agent_source(path: Path) -> dict[str, Any]:
    """Extract and validate one portable actual-agent contract without import."""

    if path.is_symlink() or not path.is_file():
        raise CatalogValidationError(f"{path.name}: agent must be a regular file")
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise CatalogValidationError(
            f"{path.name}: agent source is not readable UTF-8"
        ) from error
    if _ABSOLUTE_LOCAL_PATH_RE.search(source):
        raise CatalogValidationError(
            f"{path.name}: absolute local paths are forbidden"
        )
    try:
        tree = ast.parse(source, filename=path.name)
    except SyntaxError as error:
        raise CatalogValidationError(
            f"{path.name}: syntax error at line {error.lineno or 0}"
        ) from error
    if ast.get_docstring(tree) is None:
        raise CatalogValidationError(
            f"{path.name}: top-level docstring is required"
        )

    manifest_nodes = [
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "__manifest__"
            for target in node.targets
        )
    ]
    if len(manifest_nodes) != 1:
        raise CatalogValidationError(
            f"{path.name}: exactly one __manifest__ is required"
        )
    try:
        manifest = ast.literal_eval(manifest_nodes[0].value)
    except (TypeError, ValueError) as error:
        raise CatalogValidationError(
            f"{path.name}: __manifest__ must be a literal object"
        ) from error
    _validate_manifest(path.name, manifest)

    classes = [node for node in tree.body if isinstance(node, ast.ClassDef)]
    agent_classes = [
        node
        for node in classes
        if any(_ast_name(base) == "BasicAgent" for base in node.bases)
    ]
    if len(classes) != 1 or len(agent_classes) != 1:
        raise CatalogValidationError(
            f"{path.name}: exactly one BasicAgent subclass is required"
        )
    agent_class = agent_classes[0]
    if agent_class.name != manifest["name"]:
        raise CatalogValidationError(
            f"{path.name}: class and manifest names must match"
        )
    class_values = _class_literal_assignments(agent_class)
    if class_values.get("name") != manifest["name"]:
        raise CatalogValidationError(
            f"{path.name}: native class name metadata is invalid"
        )
    metadata = class_values.get("metadata")
    if not isinstance(metadata, dict):
        raise CatalogValidationError(
            f"{path.name}: literal native metadata is required"
        )
    _validate_metadata(path.name, metadata, manifest)

    _validate_exact_perform(path.name, agent_class)

    imports = _validate_imports(path.name, tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call_name = _ast_name(node.func)
        if call_name in _FORBIDDEN_CALLS:
            raise CatalogValidationError(
                f"{path.name}: forbidden call {call_name}"
            )
        for keyword in node.keywords:
            if (
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
            ):
                raise CatalogValidationError(
                    f"{path.name}: shell execution is forbidden"
                )

    return {
        "manifest": manifest,
        "metadata": metadata,
        "tool_name": class_values["name"],
        "imports": imports,
        "sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
    }


def build_agent_catalog(root: str | Path) -> dict[str, Any]:
    """Build the frozen catalog from actual source files in deterministic order."""

    repository = Path(root).resolve(strict=True)
    agents_directory = _contained_directory(repository, AGENTS_RELATIVE)
    records: list[dict[str, Any]] = []
    for path in sorted(agents_directory.glob("*_agent.py"), key=lambda item: item.name):
        inspected = inspect_agent_source(path)
        manifest = inspected["manifest"]
        records.append(
            {
                "path": path.relative_to(repository).as_posix(),
                "tool_name": inspected["tool_name"],
                "manifest_name": manifest["name"],
                "manifest_version": manifest["version"],
                "sha256": inspected["sha256"],
                "description": manifest["description"],
                "actions": list(manifest["actions"]),
                "capability_ids": list(manifest["capability_ids"]),
                "mutability": manifest["mutability"],
                "enabled_by_default": manifest["enabled_by_default"],
                "provenance": manifest["provenance"],
                "dependencies": list(manifest["dependencies"]),
            }
        )
    records.sort(key=lambda item: item["path"])
    mutability_counts = Counter(record["mutability"] for record in records)
    capability_count = sum(len(record["capability_ids"]) for record in records)
    return {
        "schema": AGENT_CATALOG_SCHEMA,
        "agent_abi": dict(_EXACT_PERFORM_ABI),
        "agent_count": len(records),
        "agents": records,
        "aggregates": {
            "capability_assignment_count": capability_count,
            "enabled_by_default_count": sum(
                record["enabled_by_default"] for record in records
            ),
            "counts_by_mutability": dict(sorted(mutability_counts.items())),
        },
        "determinism": {
            "encoding": "UTF-8",
            "agent_order": "path",
            "key_order": "lexicographic",
            "indent_spaces": 2,
            "trailing_newline": True,
        },
    }


def inspect_controller_source(path: Path) -> dict[str, Any]:
    """Validate the sole streamable controller without executing it."""

    if path.is_symlink() or not path.is_file():
        raise CatalogValidationError(
            "controller agent must be a regular file"
        )
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise CatalogValidationError(
            "controller agent must be readable UTF-8"
        ) from error
    if _ABSOLUTE_LOCAL_PATH_RE.search(source):
        raise CatalogValidationError(
            "controller agent contains an absolute local path"
        )
    try:
        tree = ast.parse(source, filename=path.name)
    except SyntaxError as error:
        raise CatalogValidationError(
            f"controller agent syntax error at line {error.lineno or 0}"
        ) from error
    if ast.get_docstring(tree) is None:
        raise CatalogValidationError(
            "controller agent top-level docstring is required"
        )
    manifest_nodes = [
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "__manifest__"
            for target in node.targets
        )
    ]
    if len(manifest_nodes) != 1:
        raise CatalogValidationError(
            "controller agent requires exactly one native manifest"
        )
    try:
        manifest = ast.literal_eval(manifest_nodes[0].value)
    except (TypeError, ValueError) as error:
        raise CatalogValidationError(
            "controller manifest must be a literal object"
        ) from error
    _validate_manifest(path.name, manifest)
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef)]
    agent_classes = [
        node
        for node in classes
        if any(_ast_name(base) == "BasicAgent" for base in node.bases)
    ]
    if len(classes) != 1 or len(agent_classes) != 1:
        raise CatalogValidationError(
            "controller requires exactly one BasicAgent subclass"
        )
    agent_class = agent_classes[0]
    if agent_class.name != manifest["name"]:
        raise CatalogValidationError(
            "controller class and manifest names must match"
        )
    class_values = _class_literal_assignments(agent_class)
    if class_values.get("name") != manifest["name"]:
        raise CatalogValidationError(
            "controller native class name metadata is invalid"
        )
    metadata = class_values.get("metadata")
    if not isinstance(metadata, dict):
        raise CatalogValidationError(
            "controller requires literal native metadata"
        )
    _validate_metadata(path.name, metadata, manifest)
    _validate_exact_perform(path.name, agent_class)
    imports: list[str] = []
    basic_imported = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            modules = [node.module or ""]
        else:
            continue
        for module in modules:
            imports.append(module)
            if module in _BASIC_AGENT_IMPORTS:
                basic_imported = True
            elif (
                module.split(".", 1)[0] not in sys.stdlib_module_names
                and module.split(".", 1)[0]
                not in _CONTROLLER_ALLOWED_EXTERNAL_ROOTS
            ):
                raise CatalogValidationError(
                    f"controller has non-stdlib import {module}"
                )
    if not basic_imported:
        raise CatalogValidationError(
            "controller BasicAgent compatibility import is required"
        )
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call_name = _ast_name(node.func)
        if call_name in {
            "__import__",
            "eval",
            "exec",
            "os.popen",
            "os.system",
            "subprocess.call",
        }:
            raise CatalogValidationError(
                f"controller has forbidden call {call_name}"
            )
        if call_name in {"subprocess.Popen", "subprocess.run"}:
            shell_values = [
                keyword.value
                for keyword in node.keywords
                if keyword.arg == "shell"
            ]
            if (
                len(shell_values) != 1
                or not isinstance(shell_values[0], ast.Constant)
                or shell_values[0].value is not False
            ):
                raise CatalogValidationError(
                    "controller subprocess calls must declare shell=False"
                )
    return {
        "manifest": manifest,
        "metadata": metadata,
        "tool_name": class_values["name"],
        "imports": sorted(set(imports)),
        "sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
    }


def build_controller_catalog(root: str | Path) -> dict[str, Any]:
    """Build deterministic metadata for the only top-level controller."""

    repository = Path(root).resolve(strict=True)
    directory = _contained_directory(
        repository, CONTROLLER_AGENT_RELATIVE.parent
    )
    candidates = sorted(
        directory.glob("*_agent.py"), key=lambda item: item.name
    )
    if candidates != [repository / CONTROLLER_AGENT_RELATIVE]:
        raise CatalogValidationError(
            "exactly one top-level streamable controller agent is required"
        )
    inspected = inspect_controller_source(candidates[0])
    manifest = inspected["manifest"]
    return {
        "schema": CONTROLLER_CATALOG_SCHEMA,
        "name": inspected["tool_name"],
        "source": {
            "path": CONTROLLER_AGENT_RELATIVE.as_posix(),
            "sha256": inspected["sha256"],
        },
        "actions": list(manifest["actions"]),
        "capability_ids": list(manifest["capability_ids"]),
        "mutability": manifest["mutability"],
        "dependencies": list(manifest["dependencies"]),
        "only_streamable_agent": True,
        "determinism": {
            "encoding": "UTF-8",
            "key_order": "lexicographic",
            "indent_spaces": 2,
            "trailing_newline": True,
        },
    }


def _validate_exact_perform(file_name: str, agent_class: ast.ClassDef) -> None:
    methods = [
        node
        for node in agent_class.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "perform"
    ]
    if len(methods) != 1:
        raise CatalogValidationError(
            f"{file_name}: exactly one perform method is required"
        )
    method = methods[0]
    arguments = method.args
    if (
        not isinstance(method, ast.FunctionDef)
        or method.decorator_list
        or arguments.posonlyargs
        or len(arguments.args) != 1
        or arguments.args[0].arg != "self"
        or arguments.vararg is not None
        or arguments.kwonlyargs
        or arguments.kw_defaults
        or arguments.defaults
        or arguments.kwarg is None
        or arguments.kwarg.arg != "kwargs"
    ):
        raise CatalogValidationError(
            f"{file_name}: perform must be exactly synchronous "
            "def perform(self, **kwargs) without decorators"
        )


def build_implementation_matrix(
    root: str | Path, catalog: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """Map every audited capability to an implemented, runtime, future, or excluded owner."""

    repository = Path(root).resolve(strict=True)
    if catalog is None:
        catalog = build_agent_catalog(repository)
    capability_matrix = _read_json_object(
        repository / CAPABILITY_MATRIX_RELATIVE
    )
    capabilities = capability_matrix.get("capabilities")
    if not isinstance(capabilities, list):
        raise CatalogValidationError(
            "CAPABILITY_MATRIX.json capabilities must be an array"
        )
    catalog_by_name = {
        item["tool_name"]: item
        for item in catalog.get("agents", [])
        if isinstance(item, dict) and isinstance(item.get("tool_name"), str)
    }
    controller_catalog = build_controller_catalog(repository)
    catalog_by_name[controller_catalog["name"]] = {
        "tool_name": controller_catalog["name"],
        "actions": controller_catalog["actions"],
        "capability_ids": controller_catalog["capability_ids"],
    }
    capabilities_by_id = {
        item.get("id"): item
        for item in capabilities
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    internal_records = {
        item["tool_name"]: item
        for item in catalog.get("agents", [])
        if isinstance(item, dict) and isinstance(item.get("tool_name"), str)
    }
    for name, record in internal_records.items():
        for capability_id in record.get("capability_ids", []):
            capability = capabilities_by_id.get(capability_id)
            pointer = (
                capability.get("selected_implementation")
                if isinstance(capability, dict)
                else None
            )
            prefix = f"agent:{name}/"
            action = (
                pointer[len(prefix) :]
                if isinstance(pointer, str) and pointer.startswith(prefix)
                else None
            )
            if action not in record.get("actions", []):
                raise CatalogValidationError(
                    f"{name}: capability {capability_id} does not point back "
                    "to an available agent action"
                )

    records: list[dict[str, Any]] = []
    state_counts: Counter[str] = Counter()
    selected_count = 0
    unmapped = 0
    for capability in capabilities:
        if not isinstance(capability, dict):
            raise CatalogValidationError("capability entries must be objects")
        capability_id = capability.get("id")
        if not isinstance(capability_id, str) or not capability_id:
            raise CatalogValidationError("capability id must be non-empty text")
        selected = capability.get("selected_for_cubby") is True
        pointer = capability.get("selected_implementation")
        owner, state, claim = _owner_for(
            capability_id,
            selected,
            pointer,
            catalog_by_name,
        )
        if selected:
            selected_count += 1
            if owner is None:
                unmapped += 1
        state_counts[state] += 1
        records.append(
            {
                "capability_id": capability_id,
                "plane": capability.get("plane"),
                "capability_status": capability.get("status"),
                "selected": selected,
                "implementation_state": state,
                "owner": owner,
                "claim": claim,
            }
        )
    records.sort(key=lambda item: item["capability_id"])
    return {
        "schema": IMPLEMENTATION_MATRIX_SCHEMA,
        "capabilities": records,
        "aggregates": {
            "capability_count": len(records),
            "selected_count": selected_count,
            "selected_unmapped_count": unmapped,
            "counts_by_implementation_state": {
                key: state_counts.get(key, 0)
                for key in (
                    "implemented_now",
                    "runtime_implemented",
                    "future_owned",
                    "reference_only",
                    "excluded",
                )
            },
        },
        "future_task_ids": sorted(_FUTURE_TASKS),
        "source": {
            "agent_catalog_schema": catalog.get("schema"),
            "capability_matrix": CAPABILITY_MATRIX_RELATIVE.as_posix(),
            "capability_matrix_sha256": sha256_file(
                repository / CAPABILITY_MATRIX_RELATIVE
            ),
        },
        "truth_rule": (
            "implemented_now names only the available focused action; "
            "runtime_implemented remains unattested; future_owned is not implemented; "
            "Pages implementation is static and unreleased; reference_only and "
            "excluded never claim local implementation."
        ),
        "determinism": {
            "encoding": "UTF-8",
            "capability_order": "capability_id",
            "key_order": "lexicographic",
            "indent_spaces": 2,
            "trailing_newline": True,
        },
    }


def validate_catalogs(root: str | Path) -> tuple[str, ...]:
    """Return deterministic validation errors for both generated catalog files."""

    repository = Path(root).resolve(strict=True)
    errors: list[str] = []
    try:
        expected_catalog = build_agent_catalog(repository)
    except (CatalogValidationError, OSError, UnicodeError) as error:
        return (str(error),)
    try:
        actual_catalog = _read_json_object(repository / CATALOG_RELATIVE)
    except (CatalogValidationError, OSError, UnicodeError) as error:
        errors.append(str(error))
        actual_catalog = {}
    if actual_catalog != expected_catalog:
        errors.append("agent-catalog.json does not match actual agent sources")
    if expected_catalog["agent_count"] != EXPECTED_ACTUAL_AGENT_COUNT:
        errors.append(
            f"actual agent count must be {EXPECTED_ACTUAL_AGENT_COUNT}"
        )
    try:
        expected_controller = build_controller_catalog(repository)
        actual_controller = _read_json_object(
            repository / CONTROLLER_CATALOG_RELATIVE
        )
    except (CatalogValidationError, OSError, UnicodeError) as error:
        errors.append(str(error))
        expected_controller = {}
        actual_controller = {}
    if actual_controller != expected_controller:
        errors.append(
            "controller-catalog.json does not match controller source"
        )

    try:
        expected_matrix = build_implementation_matrix(
            repository, expected_catalog
        )
        actual_matrix = _read_json_object(
            repository / IMPLEMENTATION_MATRIX_RELATIVE
        )
    except (CatalogValidationError, OSError, UnicodeError) as error:
        errors.append(str(error))
        return tuple(errors)
    if actual_matrix != expected_matrix:
        errors.append(
            "implementation-matrix.json does not match capability ownership"
        )
    aggregates = expected_matrix["aggregates"]
    if aggregates["capability_count"] != EXPECTED_CAPABILITY_COUNT:
        errors.append(
            f"implementation matrix must cover {EXPECTED_CAPABILITY_COUNT} capabilities"
        )
    if aggregates["selected_count"] != EXPECTED_SELECTED_CAPABILITY_COUNT:
        errors.append(
            "implementation matrix selected count must be "
            f"{EXPECTED_SELECTED_CAPABILITY_COUNT}"
        )
    if aggregates["selected_unmapped_count"] != 0:
        errors.append("every selected capability must have an explicit owner")
    return tuple(errors)


def write_catalogs(root: str | Path) -> tuple[Path, Path, Path]:
    """Regenerate all catalogs with canonical indentation and LF newline."""

    repository = Path(root).resolve(strict=True)
    catalog = build_agent_catalog(repository)
    matrix = build_implementation_matrix(repository, catalog)
    controller = build_controller_catalog(repository)
    catalog_path = repository / CATALOG_RELATIVE
    matrix_path = repository / IMPLEMENTATION_MATRIX_RELATIVE
    controller_path = repository / CONTROLLER_CATALOG_RELATIVE
    catalog_path.parent.mkdir(parents=True, exist_ok=True)
    controller_path.parent.mkdir(parents=True, exist_ok=True)
    _write_json(catalog_path, catalog)
    _write_json(matrix_path, matrix)
    _write_json(controller_path, controller)
    return catalog_path, matrix_path, controller_path


def _owner_for(
    capability_id: str,
    selected: bool,
    pointer: object,
    catalog_by_name: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, str] | None, str, str]:
    if not selected:
        if pointer in {"excluded", "excluded_from_v1_runtime"}:
            return (
                {"kind": "excluded", "name": str(pointer)},
                "excluded",
                "Excluded from the selected local profile.",
            )
        return (
            {"kind": "reference", "name": str(pointer or "reference_only")},
            "reference_only",
            "Audited reference only; no local implementation is claimed.",
        )
    if not isinstance(pointer, str) or ":" not in pointer:
        return None, "future_owned", "Selected capability has no valid owner."
    kind, value = pointer.split(":", 1)
    if kind == "agent":
        if "/" not in value:
            return None, "future_owned", "Selected agent owner is malformed."
        name, action = value.split("/", 1)
        catalog_record = catalog_by_name.get(name)
        if (
            catalog_record is None
            or action not in catalog_record.get("actions", [])
            or capability_id not in catalog_record.get("capability_ids", [])
        ):
            return None, "future_owned", "Selected agent owner is unavailable."
        if name == "RappStackCubbyController":
            claim = (
                "The guarded local controller action is available now; "
                "release packaging, iMessage, publication, and "
                "conformance remain unclaimed."
            )
        else:
            claim = (
                "The focused agent action is available now; this is not an "
                "artifact, deployment, lifecycle, or conformance claim."
            )
        return (
            {"kind": "agent", "name": name, "action": action},
            "implemented_now",
            claim,
        )
    if kind == "runtime":
        if value not in _RUNTIME_OWNERS:
            return None, "future_owned", "Selected runtime owner is unknown."
        name, action = value.split("/", 1)
        return (
            {"kind": "runtime", "name": name, "action": action},
            "runtime_implemented",
            "The local runtime component exists but remains unattested.",
        )
    if kind == "packaging":
        if value not in _PACKAGING_OWNERS:
            return None, "future_owned", "Selected packaging owner is unknown."
        return (
            {"kind": "packaging", "name": value},
            "implemented_now",
            (
                "The deterministic local packaging or hatch component is "
                "tested; public release and final-commit attestation remain "
                "unclaimed."
            ),
        )
    if kind == "pages":
        if value not in _PAGES_OWNERS:
            return None, "future_owned", "Selected Pages owner is unknown."
        return (
            {"kind": "pages", "name": value},
            "implemented_now",
            (
                "The dependency-free static Pages handoff and checker are "
                "implemented locally; live deployment and release remain unclaimed."
            ),
        )
    if kind == "future":
        if value not in _FUTURE_TASKS:
            return None, "future_owned", "Selected future task is unknown."
        return (
            {"kind": "future", "name": value},
            "future_owned",
            "Explicit future ownership; no implementation is claimed.",
        )
    return None, "future_owned", "Selected capability owner kind is invalid."


def _validate_manifest(file_name: str, manifest: object) -> None:
    if not isinstance(manifest, dict):
        raise CatalogValidationError(
            f"{file_name}: __manifest__ must be an object"
        )
    missing = sorted(_REQUIRED_MANIFEST_KEYS - manifest.keys())
    if missing:
        raise CatalogValidationError(
            f"{file_name}: manifest missing {', '.join(missing)}"
        )
    extra = sorted(set(manifest) - _REQUIRED_MANIFEST_KEYS)
    if extra:
        raise CatalogValidationError(
            f"{file_name}: manifest has unsupported fields {', '.join(extra)}"
        )
    if manifest.get("schema") != "rapp-agent/1.0":
        raise CatalogValidationError(
            f"{file_name}: manifest schema must be rapp-agent/1.0"
        )
    name = manifest.get("name")
    version = manifest.get("version")
    if not isinstance(name, str) or not _AGENT_NAME_RE.fullmatch(name):
        raise CatalogValidationError(
            f"{file_name}: manifest name must be short PascalCase text"
        )
    if not isinstance(version, str) or not _VERSION_RE.fullmatch(version):
        raise CatalogValidationError(
            f"{file_name}: manifest version must be semantic x.y.z"
        )
    description = manifest.get("description")
    if (
        not isinstance(description, str)
        or not description
        or len(description) > 240
    ):
        raise CatalogValidationError(
            f"{file_name}: manifest description must contain 1-240 characters"
        )
    if manifest.get("mutability") not in _AGENT_MUTABILITY:
        raise CatalogValidationError(
            f"{file_name}: manifest mutability is invalid"
        )
    if manifest.get("provenance") not in _AGENT_PROVENANCE:
        raise CatalogValidationError(
            f"{file_name}: manifest provenance is invalid"
        )
    if not isinstance(manifest.get("enabled_by_default"), bool):
        raise CatalogValidationError(
            f"{file_name}: enabled_by_default must be boolean"
        )
    for key in ("actions", "capability_ids", "dependencies"):
        values = manifest.get(key)
        if (
            not isinstance(values, list)
            or not all(isinstance(item, str) and item for item in values)
            or len(values) != len(set(values))
        ):
            raise CatalogValidationError(
                f"{file_name}: manifest {key} must be a unique string array"
            )
    if not manifest["actions"]:
        raise CatalogValidationError(
            f"{file_name}: manifest actions must not be empty"
        )
    if not all(_ACTION_RE.fullmatch(item) for item in manifest["actions"]):
        raise CatalogValidationError(
            f"{file_name}: manifest actions are invalid"
        )
    if not all(
        _CAPABILITY_RE.fullmatch(item)
        for item in manifest["capability_ids"]
    ):
        raise CatalogValidationError(
            f"{file_name}: manifest capability_ids are invalid"
        )
    if manifest["capability_ids"] != sorted(manifest["capability_ids"]):
        raise CatalogValidationError(
            f"{file_name}: capability_ids must be sorted"
        )


def _validate_metadata(
    file_name: str,
    metadata: Mapping[str, Any],
    manifest: Mapping[str, Any],
) -> None:
    if metadata.get("name") != manifest["name"]:
        raise CatalogValidationError(
            f"{file_name}: metadata name must match manifest"
        )
    if not isinstance(metadata.get("description"), str) or not metadata[
        "description"
    ]:
        raise CatalogValidationError(
            f"{file_name}: metadata description is required"
        )
    parameters = metadata.get("parameters")
    properties = (
        parameters.get("properties")
        if isinstance(parameters, dict)
        else None
    )
    action_schema = (
        properties.get("action") if isinstance(properties, dict) else None
    )
    actions = action_schema.get("enum") if isinstance(action_schema, dict) else None
    if actions != manifest["actions"]:
        raise CatalogValidationError(
            f"{file_name}: metadata action enum must match manifest actions"
        )
    if (
        parameters.get("type") != "object"
        or "action" not in parameters.get("required", [])
    ):
        raise CatalogValidationError(
            f"{file_name}: metadata must require an object action"
        )


def _validate_imports(file_name: str, tree: ast.AST) -> list[str]:
    imports: list[str] = []
    basic_imported = False
    storage_imported = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            modules = [node.module or ""]
        else:
            continue
        for module in modules:
            imports.append(module)
            root = module.split(".", 1)[0]
            if root in _FORBIDDEN_IMPORT_ROOTS:
                raise CatalogValidationError(
                    f"{file_name}: forbidden import {module}"
                )
            if module in _BASIC_AGENT_IMPORTS:
                basic_imported = True
                continue
            if module == _STORAGE_SHIM_IMPORT:
                storage_imported = True
                continue
            if root not in sys.stdlib_module_names:
                raise CatalogValidationError(
                    f"{file_name}: non-stdlib import {module}"
                )
    if not basic_imported:
        raise CatalogValidationError(
            f"{file_name}: BasicAgent compatibility import is required"
        )
    if storage_imported and file_name != "memory_agent.py":
        raise CatalogValidationError(
            f"{file_name}: storage shim is restricted to Memory"
        )
    return sorted(set(imports))


def _class_literal_assignments(node: ast.ClassDef) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for item in node.body:
        if not isinstance(item, ast.Assign) or len(item.targets) != 1:
            continue
        target = item.targets[0]
        if not isinstance(target, ast.Name) or target.id not in {"name", "metadata"}:
            continue
        try:
            values[target.id] = ast.literal_eval(item.value)
        except (TypeError, ValueError):
            continue
    return values


def _ast_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _ast_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _contained_directory(root: Path, relative: Path) -> Path:
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise CatalogValidationError(
                f"{relative.as_posix()}: symbolic links are forbidden"
            )
    resolved = current.resolve(strict=True)
    if root not in resolved.parents or not resolved.is_dir():
        raise CatalogValidationError(
            f"{relative.as_posix()}: expected a contained directory"
        )
    return resolved


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CatalogValidationError(
            f"{path.name}: cannot read valid JSON"
        ) from error
    if not isinstance(value, dict):
        raise CatalogValidationError(f"{path.name}: top level must be an object")
    return value


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    rendered = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        indent=2,
    )
    path.write_text(rendered + "\n", encoding="utf-8", newline="\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Build or validate catalogs from the command line."""

    arguments = _parser().parse_args(argv)
    if arguments.write:
        write_catalogs(arguments.root)
        return 0
    errors = validate_catalogs(arguments.root)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
