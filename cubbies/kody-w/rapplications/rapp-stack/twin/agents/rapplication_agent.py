"""Inspect and render the local rapplication profile without packaging it."""

import json
import os
import re
from pathlib import Path

from agents.basic_agent import BasicAgent


__manifest__ = {
    "schema": "rapp-agent/1.0",
    "name": "Rapplication",
    "version": "1.0.0",
    "description": "Inspect rapplication readiness and render a non-executable manifest template.",
    "actions": [
        "inspect",
        "status",
        "coverage",
        "render",
        "pack",
        "hatch",
        "lifecycle",
    ],
    "capability_ids": ["distribution.rapplication"],
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
_LOCK = "STACK_LOCK.json"
_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$")
_MAX_FILE_BYTES = 3 * 1024 * 1024


def _json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _response(action, *, ok=True, **values):
    payload = {"agent": "Rapplication", "action": action, "ok": ok}
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
        raise ValueError("source document must be an object")
    return value


def _description(value):
    if not isinstance(value, str):
        raise ValueError("description must be text")
    normalized = " ".join(value.split())
    if not normalized or len(normalized) > 280:
        raise ValueError("description is invalid")
    return normalized


class Rapplication(BasicAgent):
    """Describe the assembly while leaving pack, hatch, and lifecycle pending."""

    name = "Rapplication"
    metadata = {
        "name": "Rapplication",
        "description": "Inspect status and render a local rapplication manifest template.",
        "parameters": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": [
                        "inspect",
                        "status",
                        "coverage",
                        "render",
                        "pack",
                        "hatch",
                        "lifecycle",
                    ],
                },
                "name": {"type": "string", "maxLength": 63},
                "description": {"type": "string", "maxLength": 280},
                "version": {"type": "string", "maxLength": 64},
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
        if action in {"pack", "hatch", "lifecycle"}:
            delegated = action in {"pack", "hatch"}
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
                    "The read-only agent reports ownership; explicit verified "
                    "CLI commands perform package and hatch mutations."
                ),
            )
        try:
            root = _root()
            catalog = _read(root, _CATALOG)
            matrix = _read(root, _MATRIX)
            lock = _read(root, _LOCK)
            if action == "inspect":
                return self._inspect(catalog, matrix, lock)
            if action == "status":
                return self._status(catalog, matrix, lock)
            if action == "coverage":
                return self._coverage(matrix)
            return self._render(catalog, matrix, lock, kwargs)
        except Exception:
            return _response(
                action,
                ok=False,
                error={
                    "code": "invalid_or_unavailable",
                    "message": "The local rapplication profile could not be inspected.",
                },
            )

    def _inspect(self, catalog, matrix, lock):
        profile = lock.get("profile", {})
        return _response(
            "inspect",
            application_schema="rapp-application/1.0",
            artifact_chain=lock.get("artifact_chain", {}).get("exact_chain"),
            profile_id=profile.get("id"),
            artifact_profile_ids=profile.get("artifact_profile_ids", []),
            actual_agent_count=catalog.get("agent_count", 0),
            selected_capability_count=matrix.get("aggregates", {}).get(
                "selected_count", 0
            ),
            controller_status="implemented_local",
            packaging_status="implemented_local",
            attested=profile.get("attested") is True,
        )

    def _status(self, catalog, matrix, lock):
        lock_status = lock.get("lock_status", {})
        aggregates = matrix.get("aggregates", {})
        return _response(
            "status",
            actual_agents_ready=catalog.get("agent_count") == 12,
            agent_catalog_validated=catalog.get("schema")
            == "rapp-local-agent-catalog/1.0",
            selected_unmapped_count=aggregates.get("selected_unmapped_count"),
            build_blocked=lock_status.get("build_blocked") is True,
            conformance_claim_allowed=lock_status.get(
                "conformance_claim_allowed"
            )
            is True,
            unresolved_count=lock_status.get("unresolved_count"),
            ready_for_packaging=True,
            pending=[
                "release-attestation",
            ],
            pages_status="implemented_local_unreleased",
        )

    def _coverage(self, matrix):
        aggregates = matrix.get("aggregates", {})
        return _response(
            "coverage",
            capability_count=aggregates.get("capability_count"),
            selected_count=aggregates.get("selected_count"),
            selected_unmapped_count=aggregates.get("selected_unmapped_count"),
            counts_by_implementation_state=aggregates.get(
                "counts_by_implementation_state", {}
            ),
            all_selected_owned=aggregates.get("selected_unmapped_count") == 0,
        )

    def _render(self, catalog, matrix, lock, kwargs):
        name = kwargs.get("name")
        version = kwargs.get("version")
        if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
            raise ValueError("application name is invalid")
        if not isinstance(version, str) or not _VERSION_RE.fullmatch(version):
            raise ValueError("version is invalid")
        agents = [
            {
                "path": item.get("path"),
                "tool_name": item.get("tool_name"),
                "sha256": item.get("sha256"),
                "enabled": item.get("enabled_by_default") is True,
            }
            for item in catalog.get("agents", [])
        ]
        manifest = {
            "schema": "rapp-application/1.0",
            "name": name,
            "version": version,
            "description": _description(kwargs.get("description")),
            "profile_id": lock.get("profile", {}).get("id"),
            "agents": agents,
            "controller": {
                "status": "pending",
                "streaming_boundary": "top_level_only",
            },
            "capability_coverage": {
                "selected": matrix.get("aggregates", {}).get("selected_count"),
                "unmapped": matrix.get("aggregates", {}).get(
                    "selected_unmapped_count"
                ),
            },
            "artifact_status": "template_only",
        }
        return _response(
            "render",
            manifest=manifest,
            canonical_json=_json(manifest),
            artifact_created=False,
            write_performed=False,
        )
