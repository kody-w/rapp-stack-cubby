"""Bounded, read-only navigation of the audited local RAPP stack map."""

import json
import os
from pathlib import Path

from agents.basic_agent import BasicAgent


__manifest__ = {
    "schema": "rapp-agent/1.0",
    "name": "StackMap",
    "version": "1.0.0",
    "description": "Inspect the frozen local census, capability map, graph, and gaps.",
    "actions": [
        "overview",
        "capability",
        "path",
        "repo",
        "collision",
        "gaps",
        "coverage",
    ],
    "capability_ids": [
        "governance.authority-order",
        "governance.direct-evidence-census",
        "governance.grail-pointer",
        "runtime.installer-brainstem",
    ],
    "mutability": "read_only",
    "enabled_by_default": True,
    "provenance": "original_new",
    "dependencies": ["python-stdlib", "BasicAgent"],
}

_FILES = {
    "census": "SOURCE_CENSUS.json",
    "capabilities": "CAPABILITY_MATRIX.json",
    "graph": "SYSTEM_GRAPH.json",
    "narrative": "RAPP_END_TO_END.md",
}
_MAX_FILE_BYTES = 12 * 1024 * 1024
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
    payload = {"agent": "StackMap", "action": action, "ok": ok}
    payload.update(values)
    return _json(payload)


def _limit(value, default=20):
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("limit must be an integer")
    if not 1 <= value <= _MAX_LIMIT:
        raise ValueError("limit is outside the supported range")
    return value


def _text(value, maximum=320):
    if not isinstance(value, str):
        return ""
    compact = " ".join(value.split())
    return compact[:maximum]


def _explicit_root():
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
            raise ValueError("RAPP_STACK_ROOT must not contain symbolic links")
    root = candidate.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("RAPP_STACK_ROOT must be a directory")
    return root


def _source_path(root, key):
    relative = Path(_FILES[key])
    path = root / relative
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("source files must not be symbolic links")
    resolved = path.resolve(strict=True)
    if root not in resolved.parents or not resolved.is_file():
        raise ValueError("source file is outside the explicit root")
    if resolved.stat().st_size > _MAX_FILE_BYTES:
        raise ValueError("source file exceeds the read bound")
    return resolved


def _load(root, key):
    path = _source_path(root, key)
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("source document must contain a JSON object")
    return value


def _matches(query, *values):
    if not query:
        return True
    needle = query.casefold()
    return any(needle in str(value).casefold() for value in values)


class StackMap(BasicAgent):
    """Read the frozen public evidence without importing or executing it."""

    name = "StackMap"
    metadata = {
        "name": "StackMap",
        "description": "Inspect bounded views of the local RAPP stack evidence.",
        "parameters": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": [
                        "overview",
                        "capability",
                        "path",
                        "repo",
                        "collision",
                        "gaps",
                        "coverage",
                    ],
                },
                "query": {"type": "string", "maxLength": 160},
                "capability_id": {"type": "string", "maxLength": 160},
                "path_id": {"type": "string", "maxLength": 160},
                "repo_name": {"type": "string", "maxLength": 160},
                "collision_id": {"type": "string", "maxLength": 160},
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
            root = _explicit_root()
            limit = _limit(kwargs.get("limit"))
            if action == "overview":
                return self._overview(root)
            if action == "capability":
                return self._capability(
                    root,
                    kwargs.get("capability_id") or kwargs.get("query"),
                    limit,
                )
            if action == "path":
                return self._path(
                    root, kwargs.get("path_id") or kwargs.get("query"), limit
                )
            if action == "repo":
                return self._repo(
                    root, kwargs.get("repo_name") or kwargs.get("query"), limit
                )
            if action == "collision":
                return self._collision(
                    root,
                    kwargs.get("collision_id") or kwargs.get("query"),
                    limit,
                )
            if action == "gaps":
                return self._gaps(root, kwargs.get("query"), limit)
            return self._coverage(root)
        except Exception:
            return _response(
                action,
                ok=False,
                error={
                    "code": "source_unavailable",
                    "message": "The bounded local source could not be inspected.",
                },
            )

    def _overview(self, root):
        census = _load(root, "census")
        matrix = _load(root, "capabilities")
        graph = _load(root, "graph")
        return _response(
            "overview",
            repository_count=census.get("repository_count", 0),
            capability_count=matrix.get("aggregates", {}).get(
                "capability_count", 0
            ),
            selected_capability_count=matrix.get("aggregates", {}).get(
                "selected_count", 0
            ),
            canonical_path_count=graph.get("aggregates", {}).get(
                "canonical_path_count", 0
            ),
            collision_count=graph.get("aggregates", {}).get(
                "collision_count", 0
            ),
            authority=(
                "Frozen project locks and direct local evidence outrank labels, "
                "indexes, mirrors, and behavioral pointers."
            ),
            bounded=True,
        )

    def _capability(self, root, query, limit):
        matrix = _load(root, "capabilities")
        matches = []
        for item in matrix.get("capabilities", []):
            if not isinstance(item, dict) or not _matches(
                query, item.get("id"), item.get("purpose"), item.get("plane")
            ):
                continue
            matches.append(
                {
                    "id": item.get("id"),
                    "plane": item.get("plane"),
                    "purpose": _text(item.get("purpose")),
                    "status": item.get("status"),
                    "selected": item.get("selected_for_cubby") is True,
                    "implementation_owner": item.get("selected_implementation"),
                    "major_gaps": [
                        _text(gap)
                        for gap in item.get("major_gaps", [])[:3]
                        if isinstance(gap, str)
                    ],
                }
            )
        return _response(
            "capability",
            count=min(len(matches), limit),
            total_matches=len(matches),
            truncated=len(matches) > limit,
            capabilities=matches[:limit],
        )

    def _path(self, root, query, limit):
        graph = _load(root, "graph")
        matches = []
        for item in graph.get("canonical_end_to_end_paths", []):
            if not isinstance(item, dict) or not _matches(
                query, item.get("id"), item.get("name"), item.get("outcome")
            ):
                continue
            matches.append(
                {
                    "id": item.get("id"),
                    "name": _text(item.get("name"), 120),
                    "scope": item.get("scope"),
                    "ordered_nodes": [
                        _text(node, 160)
                        for node in item.get("ordered_nodes", [])[:24]
                    ],
                    "outcome": _text(item.get("outcome")),
                }
            )
        return _response(
            "path",
            count=min(len(matches), limit),
            total_matches=len(matches),
            truncated=len(matches) > limit,
            paths=matches[:limit],
        )

    def _repo(self, root, query, limit):
        census = _load(root, "census")
        matches = []
        for item in census.get("repositories", []):
            if not isinstance(item, dict) or not _matches(
                query,
                item.get("name"),
                item.get("description"),
                item.get("direct_evidence_note"),
            ):
                continue
            matches.append(
                {
                    "name": item.get("name"),
                    "classification": item.get("classification"),
                    "language": item.get("language"),
                    "head_sha": item.get("head_sha"),
                    "audited": item.get("audited") is True,
                    "has_pages": item.get("has_pages") is True,
                    "evidence_summary": _text(
                        item.get("direct_evidence_note"), 240
                    ),
                }
            )
        return _response(
            "repo",
            count=min(len(matches), limit),
            total_matches=len(matches),
            truncated=len(matches) > limit,
            repositories=matches[:limit],
        )

    def _collision(self, root, query, limit):
        graph = _load(root, "graph")
        matches = []
        for item in graph.get("collisions", []):
            if not isinstance(item, dict) or not _matches(
                query, item.get("id"), item.get("issue"), item.get("resolution")
            ):
                continue
            matches.append(
                {
                    "id": item.get("id"),
                    "issue": _text(item.get("issue")),
                    "resolution": _text(item.get("resolution")),
                    "node_refs": [
                        _text(ref, 160)
                        for ref in item.get("node_refs", [])[:12]
                    ],
                }
            )
        return _response(
            "collision",
            count=min(len(matches), limit),
            total_matches=len(matches),
            truncated=len(matches) > limit,
            collisions=matches[:limit],
        )

    def _gaps(self, root, query, limit):
        matrix = _load(root, "capabilities")
        matches = []
        for item in matrix.get("capabilities", []):
            if (
                not isinstance(item, dict)
                or item.get("selected_for_cubby") is not True
                or not _matches(
                    query,
                    item.get("id"),
                    item.get("purpose"),
                    " ".join(item.get("major_gaps", [])),
                )
            ):
                continue
            matches.append(
                {
                    "capability_id": item.get("id"),
                    "status": item.get("status"),
                    "owner": item.get("selected_implementation"),
                    "gaps": [
                        _text(gap)
                        for gap in item.get("major_gaps", [])[:3]
                        if isinstance(gap, str)
                    ],
                }
            )
        return _response(
            "gaps",
            count=min(len(matches), limit),
            total_matches=len(matches),
            truncated=len(matches) > limit,
            gaps=matches[:limit],
        )

    def _coverage(self, root):
        matrix = _load(root, "capabilities")
        selected = [
            item
            for item in matrix.get("capabilities", [])
            if isinstance(item, dict) and item.get("selected_for_cubby") is True
        ]
        ownership = {}
        for item in selected:
            owner = str(item.get("selected_implementation") or "unmapped")
            kind = owner.split(":", 1)[0]
            ownership[kind] = ownership.get(kind, 0) + 1
        return _response(
            "coverage",
            capability_count=len(matrix.get("capabilities", [])),
            selected_count=len(selected),
            selected_ownership=dict(sorted(ownership.items())),
            counts_by_plane=matrix.get("aggregates", {}).get(
                "counts_by_plane", {}
            ),
            counts_by_status=matrix.get("aggregates", {}).get(
                "counts_by_status", {}
            ),
        )
