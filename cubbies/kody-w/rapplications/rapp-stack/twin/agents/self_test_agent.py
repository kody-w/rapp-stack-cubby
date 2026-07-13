"""Deterministic in-process structural checks for the local agent closure."""

import ast
import hashlib
import json
import os
import stat
from pathlib import Path

from agents.basic_agent import BasicAgent


__manifest__ = {
    "schema": "rapp-agent/1.0",
    "name": "SelfTest",
    "version": "1.0.0",
    "description": "Check artifact presence, catalog integrity, mappings, isolation, and routes.",
    "actions": [
        "run",
        "artifact",
        "catalog",
        "agents",
        "mappings",
        "isolation",
        "routes",
    ],
    "capability_ids": [],
    "mutability": "read_only",
    "enabled_by_default": True,
    "provenance": "original_new",
    "dependencies": ["python-stdlib", "BasicAgent"],
}

_AGENTS = "cubbies/kody-w/rapplications/rapp-stack/twin/agents"
_SOUL = "cubbies/kody-w/rapplications/rapp-stack/twin/soul.md"
_CATALOG = (
    "cubbies/kody-w/rapplications/rapp-stack/twin/catalog/agent-catalog.json"
)
_MATRIX = (
    "cubbies/kody-w/rapplications/rapp-stack/twin/catalog/"
    "implementation-matrix.json"
)
_LOCK = "STACK_LOCK.json"
_RUNTIME = "src/rapp_stack_cubby/runtime"
_MAX_FILE_BYTES = 1024 * 1024


def _json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _response(action, *, ok=True, **values):
    payload = {"agent": "SelfTest", "action": action, "ok": ok}
    payload.update(values)
    return _json(payload)


def _safe_directory(variable):
    raw = os.environ.get(variable)
    if not raw:
        raise ValueError(f"{variable} is required")
    candidate = Path(raw)
    if not candidate.is_absolute():
        raise ValueError(f"{variable} must be absolute")
    current = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"{variable} must not contain symbolic links")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"{variable} must be a directory")
    return resolved


def _contained(root, relative_text, *, directory=False):
    relative = Path(relative_text)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("relative path is invalid")
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("path must not contain symbolic links")
    resolved = current.resolve(strict=True)
    if root not in resolved.parents:
        raise ValueError("path escapes root")
    if directory and not resolved.is_dir():
        raise ValueError("path must be a directory")
    if not directory and not resolved.is_file():
        raise ValueError("path must be a file")
    return resolved


def _read_json(root, relative):
    path = _contained(root, relative)
    if path.stat().st_size > _MAX_FILE_BYTES:
        raise ValueError("JSON file exceeds read bound")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JSON document must be an object")
    return value


def _manifest(tree):
    assignments = [
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "__manifest__"
            for target in node.targets
        )
    ]
    if len(assignments) != 1:
        raise ValueError("agent must declare one manifest")
    value = ast.literal_eval(assignments[0].value)
    if not isinstance(value, dict):
        raise ValueError("agent manifest must be an object")
    return value


def _agent_structure(path):
    if path.is_symlink() or path.stat().st_size > _MAX_FILE_BYTES:
        return False, None
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=path.name)
    manifest = _manifest(tree)
    classes = [
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and any(
            isinstance(base, ast.Name) and base.id == "BasicAgent"
            for base in node.bases
        )
    ]
    methods = [
        node
        for class_node in classes
        for node in class_node.body
        if isinstance(node, ast.FunctionDef) and node.name == "perform"
    ]
    valid = (
        ast.get_docstring(tree) is not None
        and len(classes) == 1
        and len(methods) == 1
        and methods[0].args.kwarg is not None
        and manifest.get("schema") == "rapp-agent/1.0"
        and manifest.get("name") == classes[0].name
    )
    return valid, manifest


class SelfTest(BasicAgent):
    """Perform no subprocess, network, import, or mutation during checks."""

    name = "SelfTest"
    metadata = {
        "name": "SelfTest",
        "description": "Run deterministic in-process agent-closure checks.",
        "parameters": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": [
                        "run",
                        "artifact",
                        "catalog",
                        "agents",
                        "mappings",
                        "isolation",
                        "routes",
                    ],
                }
            },
            "required": ["action"],
            "additionalProperties": False,
        },
    }

    def perform(self, **kwargs):
        action = kwargs.get("action")
        if action not in __manifest__["actions"]:
            return _response(
                str(action or ""),
                ok=False,
                error={"code": "invalid_action", "message": "Unsupported action."},
            )
        try:
            root = _safe_directory("RAPP_STACK_ROOT")
            data = _safe_directory("RAPP_STACK_DATA_DIR")
            checks = {
                "artifact": self._artifact(root),
                "catalog": self._catalog(root),
                "agents": self._agents(root),
                "mappings": self._mappings(root),
                "isolation": self._isolation(root, data),
                "routes": self._routes(root),
            }
            selected = checks if action == "run" else {action: checks[action]}
            passed = all(
                all(group.values()) for group in selected.values()
            )
            return _response(
                action,
                passed=passed,
                checks=selected,
                deterministic=True,
                subprocess_used=False,
                network_used=False,
            )
        except Exception:
            return _response(
                action,
                ok=False,
                passed=False,
                error={
                    "code": "self_test_unavailable",
                    "message": "The contained self-test could not complete.",
                },
            )

    def _artifact(self, root):
        return {
            "soul_present": _contained(root, _SOUL).stat().st_size > 0,
            "agent_directory_present": _contained(
                root, _AGENTS, directory=True
            ).is_dir(),
            "catalog_present": _contained(root, _CATALOG).is_file(),
            "matrix_present": _contained(root, _MATRIX).is_file(),
            "lock_present": _contained(root, _LOCK).is_file(),
        }

    def _catalog(self, root):
        catalog = _read_json(root, _CATALOG)
        records = catalog.get("agents", [])
        paths = [item.get("path") for item in records if isinstance(item, dict)]
        hashes_match = True
        for item in records:
            if not isinstance(item, dict):
                hashes_match = False
                continue
            path = _contained(root, item.get("path", ""))
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != item.get("sha256"):
                hashes_match = False
        return {
            "schema": catalog.get("schema")
            == "rapp-local-agent-catalog/1.0",
            "count": catalog.get("agent_count") == len(records) == 12,
            "ordered_paths": paths == sorted(paths),
            "unique_tools": len(
                {
                    item.get("tool_name")
                    for item in records
                    if isinstance(item, dict)
                }
            )
            == len(records),
            "hashes_match": hashes_match,
        }

    def _agents(self, root):
        directory = _contained(root, _AGENTS, directory=True)
        paths = sorted(directory.glob("*_agent.py"), key=lambda item: item.name)
        structures = []
        manifest_names = []
        for path in paths:
            valid, manifest = _agent_structure(path)
            structures.append(valid)
            if manifest:
                manifest_names.append(manifest.get("name"))
        return {
            "count": len(paths) == 12,
            "all_structural": bool(structures) and all(structures),
            "unique_manifest_names": len(set(manifest_names)) == len(paths),
            "sorted_files": [path.name for path in paths]
            == sorted(path.name for path in paths),
        }

    def _mappings(self, root):
        matrix = _read_json(root, _MATRIX)
        records = matrix.get("capabilities", [])
        selected = [
            item for item in records if isinstance(item, dict) and item.get("selected")
        ]
        owners = [
            item.get("owner")
            for item in selected
            if isinstance(item.get("owner"), dict)
        ]
        return {
            "schema": matrix.get("schema")
            == "rapp-implementation-matrix/1.0",
            "capability_count": len(records) == 113,
            "selected_count": len(selected) == 61,
            "all_selected_owned": len(owners) == len(selected)
            and matrix.get("aggregates", {}).get("selected_unmapped_count") == 0,
            "known_owner_kinds": all(
                owner.get("kind")
                in {"agent", "runtime", "packaging", "pages", "future"}
                for owner in owners
            ),
        }

    def _isolation(self, root, data):
        agents = _contained(root, _AGENTS, directory=True)
        mode = stat.S_IMODE(data.stat().st_mode)
        return {
            "explicit_data_root": bool(os.environ.get("RAPP_STACK_DATA_DIR")),
            "data_not_repository_root": data != root,
            "data_not_agent_source": (
                data != agents
                and agents not in data.parents
                and data not in agents.parents
            ),
            "data_root_private_mode": mode & 0o077 == 0,
            "data_root_not_symlink": not data.is_symlink(),
        }

    def _routes(self, root):
        lock = _read_json(root, _LOCK)
        forbidden = [
            item.get("value")
            for item in lock.get("prohibited_surfaces", [])
            if isinstance(item, dict)
            and isinstance(item.get("value"), str)
            and item["value"].startswith("/")
        ]
        sources = []
        for relative in (_RUNTIME, _AGENTS):
            directory = _contained(root, relative, directory=True)
            sources.extend(sorted(directory.glob("*.py")))
        absent = True
        for path in sources:
            text = path.read_text(encoding="utf-8")
            if any(route in text for route in forbidden):
                absent = False
                break
        return {
            "prohibited_routes_absent": absent,
            "runtime_and_agents_scanned": len(sources) >= 12,
            "route_rules_present": bool(forbidden),
        }
