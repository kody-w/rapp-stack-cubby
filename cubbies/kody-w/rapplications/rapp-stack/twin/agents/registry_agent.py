"""Read-only inspection of the frozen local actual-agent catalog."""

import json
import os
from pathlib import Path

from agents.basic_agent import BasicAgent


__manifest__ = {
    "schema": "rapp-agent/1.0",
    "name": "Registry",
    "version": "1.0.0",
    "description": "List and inspect frozen local agents and capability ownership.",
    "actions": ["list", "search", "inspect", "capability"],
    "capability_ids": ["agents.skill-not-agent"],
    "mutability": "read_only",
    "enabled_by_default": True,
    "provenance": "original_new",
    "dependencies": ["python-stdlib", "BasicAgent"],
}

_CATALOG = (
    "cubbies/kody-w/rapplications/rapp-stack/twin/catalog/agent-catalog.json"
)
_MATRIX = (
    "cubbies/kody-w/rapplications/rapp-stack/twin/catalog/"
    "implementation-matrix.json"
)
_MAX_FILE_BYTES = 2 * 1024 * 1024
_MAX_LIMIT = 50


def _json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _response(action, *, ok=True, **values):
    payload = {"agent": "Registry", "action": action, "ok": ok}
    payload.update(values)
    return _json(payload)


def _root():
    raw = os.environ.get("RAPP_STACK_ROOT")
    if not raw:
        raise ValueError("RAPP_STACK_ROOT is required")
    candidate = Path(raw)
    if not candidate.is_absolute():
        raise ValueError("RAPP_STACK_ROOT must be absolute")
    current = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise ValueError("root must not contain symbolic links")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError("root must be a directory")
    return resolved


def _read(root, relative_text):
    relative = Path(relative_text)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("catalog path is invalid")
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("catalog path must not contain symbolic links")
    path = current.resolve(strict=True)
    if root not in path.parents or not path.is_file():
        raise ValueError("catalog path escapes root")
    if path.stat().st_size > _MAX_FILE_BYTES:
        raise ValueError("catalog exceeds read bound")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("catalog must be an object")
    return value


def _limit(value):
    if value is None:
        return 20
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= _MAX_LIMIT
    ):
        raise ValueError("limit is invalid")
    return value


def _agent_view(item):
    return {
        "path": item.get("path"),
        "tool_name": item.get("tool_name"),
        "manifest_name": item.get("manifest_name"),
        "manifest_version": item.get("manifest_version"),
        "sha256": item.get("sha256"),
        "description": item.get("description"),
        "actions": item.get("actions", []),
        "capability_ids": item.get("capability_ids", []),
        "mutability": item.get("mutability"),
        "enabled_by_default": item.get("enabled_by_default"),
        "provenance": item.get("provenance"),
        "dependencies": item.get("dependencies", []),
    }


class Registry(BasicAgent):
    """Expose frozen metadata; never fetch, install, or import catalog code."""

    name = "Registry"
    metadata = {
        "name": "Registry",
        "description": "List, search, or inspect local actual-agent catalog records.",
        "parameters": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["list", "search", "inspect", "capability"],
                },
                "query": {"type": "string", "maxLength": 160},
                "name": {"type": "string", "maxLength": 64},
                "capability_id": {"type": "string", "maxLength": 160},
                "limit": {"type": "integer", "minimum": 1, "maximum": 50},
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
            root = _root()
            catalog = _read(root, _CATALOG)
            matrix = _read(root, _MATRIX)
            limit = _limit(kwargs.get("limit"))
            if action == "list":
                agents = [_agent_view(item) for item in catalog.get("agents", [])]
                return _response(
                    action,
                    count=min(len(agents), limit),
                    total_count=len(agents),
                    truncated=len(agents) > limit,
                    agents=agents[:limit],
                    frozen=True,
                )
            if action == "search":
                return self._search(
                    catalog, matrix, kwargs.get("query"), limit
                )
            if action == "inspect":
                return self._inspect(catalog, kwargs.get("name"))
            return self._capability(
                matrix,
                kwargs.get("capability_id") or kwargs.get("query"),
                limit,
            )
        except Exception:
            return _response(
                action,
                ok=False,
                error={
                    "code": "catalog_unavailable",
                    "message": "The frozen local catalog could not be inspected.",
                },
            )

    def _search(self, catalog, matrix, query, limit):
        if not isinstance(query, str) or not query.strip() or len(query) > 160:
            raise ValueError("query is required")
        needle = query.casefold()
        agents = [
            _agent_view(item)
            for item in catalog.get("agents", [])
            if needle
            in _json(
                {
                    "name": item.get("tool_name"),
                    "description": item.get("description"),
                    "actions": item.get("actions", []),
                    "capabilities": item.get("capability_ids", []),
                }
            ).casefold()
        ]
        capabilities = [
            item
            for item in matrix.get("capabilities", [])
            if item.get("selected") is True
            and needle
            in _json(
                {
                    "id": item.get("capability_id"),
                    "owner": item.get("owner"),
                }
            ).casefold()
        ]
        return _response(
            "search",
            agents=agents[:limit],
            capabilities=capabilities[:limit],
            agent_match_count=len(agents),
            capability_match_count=len(capabilities),
            truncated=len(agents) > limit or len(capabilities) > limit,
        )

    def _inspect(self, catalog, name):
        if not isinstance(name, str) or not name or len(name) > 64:
            raise ValueError("name is required")
        matches = [
            item
            for item in catalog.get("agents", [])
            if name.casefold()
            in {
                str(item.get("tool_name", "")).casefold(),
                str(item.get("manifest_name", "")).casefold(),
            }
        ]
        if len(matches) != 1:
            return _response(
                "inspect",
                ok=False,
                error={"code": "not_found", "message": "Agent was not found."},
            )
        return _response(
            "inspect",
            agent_record=_agent_view(matches[0]),
            executable_source=False,
            frozen=True,
        )

    def _capability(self, matrix, query, limit):
        if not isinstance(query, str) or not query.strip() or len(query) > 160:
            raise ValueError("capability id or query is required")
        needle = query.casefold()
        matches = [
            item
            for item in matrix.get("capabilities", [])
            if needle in str(item.get("capability_id", "")).casefold()
        ]
        return _response(
            "capability",
            count=min(len(matches), limit),
            total_count=len(matches),
            truncated=len(matches) > limit,
            capabilities=matches[:limit],
            selected_unmapped_count=matrix.get("aggregates", {}).get(
                "selected_unmapped_count", 0
            ),
        )
