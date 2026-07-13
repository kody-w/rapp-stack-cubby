"""Read public cubby evidence and render a safe manifest without packaging."""

import json
import os
import re
from pathlib import Path

from agents.basic_agent import BasicAgent


__manifest__ = {
    "schema": "rapp-agent/1.0",
    "name": "Cubby",
    "version": "1.0.0",
    "description": "Inspect public cubby data and render a non-secret cubby manifest.",
    "actions": [
        "inspect",
        "list",
        "show",
        "query",
        "render",
        "pack",
        "import",
        "stream",
    ],
    "capability_ids": ["distribution.cubby"],
    "mutability": "read_only",
    "enabled_by_default": True,
    "provenance": "original_new",
    "dependencies": ["python-stdlib", "BasicAgent"],
}

_CUBBY = "cubbies/kody-w/cubby.json"
_CENSUS = "SOURCE_CENSUS.json"
_CATALOG = (
    "cubbies/kody-w/rapplications/rapp-stack/twin/catalog/agent-catalog.json"
)
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,62}$")
_TIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
)
_ANATOMY = [
    "agents",
    "organs",
    "senses",
    "rapplications",
    "neighborhoods",
    "eggs",
    "show-and-tell",
]
_MAX_FILE_BYTES = 12 * 1024 * 1024


def _json(value, pretty=False):
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        indent=2 if pretty else None,
        separators=None if pretty else (",", ":"),
    )


def _response(action, *, ok=True, **values):
    payload = {"agent": "Cubby", "action": action, "ok": ok}
    payload.update(values)
    return _json(payload)


def _root():
    raw = os.environ.get("RAPP_STACK_ROOT")
    if not raw:
        raise ValueError("RAPP_STACK_ROOT is required")
    candidate = Path(raw)
    if not candidate.is_absolute():
        raise ValueError("root must be absolute")
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
        raise ValueError("source path is invalid")
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("source path must not contain symbolic links")
    path = current.resolve(strict=True)
    if root not in path.parents or not path.is_file():
        raise ValueError("source path escapes root")
    if path.stat().st_size > _MAX_FILE_BYTES:
        raise ValueError("source file exceeds read bound")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("source must contain an object")
    return value


def _public_text(value, maximum):
    if not isinstance(value, str):
        raise ValueError("public text is required")
    normalized = " ".join(value.split())
    if not normalized or len(normalized) > maximum:
        raise ValueError("public text is empty or too long")
    if any(ord(character) < 32 for character in normalized):
        raise ValueError("public text contains control characters")
    return normalized


class Cubby(BasicAgent):
    """Keep source inspection separate from future artifact operations."""

    name = "Cubby"
    metadata = {
        "name": "Cubby",
        "description": "Inspect, query, or render public cubby source data.",
        "parameters": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": [
                        "inspect",
                        "list",
                        "show",
                        "query",
                        "render",
                        "pack",
                        "import",
                        "stream",
                    ],
                },
                "resource": {
                    "type": "string",
                    "enum": ["cubby", "agents", "repositories", "anatomy"],
                },
                "query": {"type": "string", "maxLength": 160},
                "limit": {"type": "integer", "minimum": 1, "maximum": 50},
                "slug": {"type": "string", "maxLength": 63},
                "display_name": {"type": "string", "maxLength": 100},
                "description": {"type": "string", "maxLength": 280},
                "created_at": {"type": "string", "maxLength": 20},
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
        if action in {"pack", "import", "stream"}:
            delegated = action != "stream"
            return _response(
                action,
                status=(
                    "implemented_external_cli" if delegated else "delegated"
                ),
                implemented=delegated,
                owner=(
                    "rapp-stack-cubby packaging CLI"
                    if delegated
                    else "controller-agent"
                ),
                artifact_created=False,
                message=(
                    "The read-only inspector does not mutate artifacts; use "
                    "the explicit verified packaging/controller command."
                ),
            )
        try:
            root = _root()
            if action == "inspect":
                cubby = _read(root, _CUBBY)
                return _response(
                    action,
                    schema=cubby.get("schema"),
                    slug=cubby.get("slug"),
                    anatomy=cubby.get("estate", {}).get("anatomy", []),
                    streamable=cubby.get("streamable"),
                    public_source_only=True,
                )
            if action == "list":
                return self._list(root, kwargs)
            if action == "show":
                return self._show(root, kwargs.get("resource"))
            if action == "query":
                return self._query(root, kwargs)
            return self._render(kwargs)
        except Exception:
            return _response(
                action,
                ok=False,
                error={
                    "code": "invalid_or_unavailable",
                    "message": "The bounded public cubby operation was rejected.",
                },
            )

    def _list(self, root, kwargs):
        resource = kwargs.get("resource", "anatomy")
        limit = kwargs.get("limit", 20)
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 50
        ):
            raise ValueError("limit is invalid")
        if resource == "anatomy":
            values = list(_ANATOMY)
        elif resource == "agents":
            values = [
                item.get("tool_name")
                for item in _read(root, _CATALOG).get("agents", [])
            ]
        elif resource == "repositories":
            values = [
                item.get("name")
                for item in _read(root, _CENSUS).get("repositories", [])
            ]
        elif resource == "cubby":
            values = [_read(root, _CUBBY).get("slug")]
        else:
            raise ValueError("resource is invalid")
        return _response(
            "list",
            resource=resource,
            count=min(len(values), limit),
            total_count=len(values),
            truncated=len(values) > limit,
            items=values[:limit],
        )

    def _show(self, root, resource):
        if resource == "cubby":
            value = _read(root, _CUBBY)
        elif resource == "agents":
            value = _read(root, _CATALOG)
        elif resource == "anatomy":
            value = {"anatomy": list(_ANATOMY)}
        elif resource == "repositories":
            census = _read(root, _CENSUS)
            value = {
                "schema": census.get("schema"),
                "repository_count": census.get("repository_count"),
                "classification_counts": census.get("aggregates", {}).get(
                    "classification_counts", {}
                ),
            }
        else:
            raise ValueError("resource is required")
        return _response("show", resource=resource, value=value)

    def _query(self, root, kwargs):
        query = kwargs.get("query")
        limit = kwargs.get("limit", 20)
        if (
            not isinstance(query, str)
            or not query.strip()
            or len(query) > 160
            or isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 50
        ):
            raise ValueError("query or limit is invalid")
        needle = query.casefold()
        matches = []
        for item in _read(root, _CENSUS).get("repositories", []):
            searchable = " ".join(
                str(item.get(key) or "")
                for key in (
                    "name",
                    "description",
                    "classification",
                    "direct_evidence_note",
                )
            ).casefold()
            if needle in searchable:
                matches.append(
                    {
                        "name": item.get("name"),
                        "classification": item.get("classification"),
                        "language": item.get("language"),
                        "audited": item.get("audited") is True,
                    }
                )
        return _response(
            "query",
            count=min(len(matches), limit),
            total_count=len(matches),
            truncated=len(matches) > limit,
            repositories=matches[:limit],
        )

    def _render(self, kwargs):
        slug = kwargs.get("slug")
        if not isinstance(slug, str) or not _SLUG_RE.fullmatch(slug):
            raise ValueError("slug is invalid")
        created_at = kwargs.get("created_at")
        if not isinstance(created_at, str) or not _TIME_RE.fullmatch(created_at):
            raise ValueError("created_at must be injected UTC")
        manifest = {
            "schema": "rapp-cubby/1.0",
            "github_login": slug,
            "slug": slug,
            "display_name": _public_text(kwargs.get("display_name"), 100),
            "what_im_cooking": _public_text(kwargs.get("description"), 280),
            "created_at": created_at,
            "estate": {"anatomy": list(_ANATOMY)},
            "streamable": {"agents": True},
        }
        return _response(
            "render",
            manifest=manifest,
            canonical_json=_json(manifest),
            write_performed=False,
            artifact_created=False,
        )
