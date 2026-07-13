"""Render non-executing deployment plans from directly audited local references."""

import json
import os
from pathlib import Path

from agents.basic_agent import BasicAgent


__manifest__ = {
    "schema": "rapp-agent/1.0",
    "name": "Deployment",
    "version": "1.0.0",
    "description": "Inspect deployment evidence and render credential-free dry-run plans.",
    "actions": ["inspect", "render"],
    "capability_ids": [],
    "mutability": "read_only",
    "enabled_by_default": True,
    "provenance": "original_new",
    "dependencies": ["python-stdlib", "BasicAgent"],
}

_MATRIX = "CAPABILITY_MATRIX.json"
_LOCK = "STACK_LOCK.json"
_MAX_FILE_BYTES = 3 * 1024 * 1024
_TARGET_CAPABILITIES = {
    "local": [
        "runtime.local-chat-endpoint",
        "substrate.local-private-filesystem",
    ],
    "pages": [
        "substrate.github-pages-static",
        "ux.pages-front-door",
        "security.pages-private-state",
    ],
    "azure-functions": ["cloud.azure-functions-body"],
    "dataverse": ["cloud.dataverse-twin"],
    "m365-copilot-studio": [
        "cloud.m365-agent-surfaces",
        "cloud.copilot-studio-package",
    ],
}
_PLANS = {
    "local": [
        "Verify the explicit root, data root, soul, and frozen agent catalog.",
        "Validate Python and the loopback-only runtime configuration.",
        "Load exact local agent bytes and run deterministic self-tests.",
        "Start the dedicated process only through the future supervisor.",
    ],
    "pages": [
        "Stage public static files from reviewed inputs only.",
        "Verify no loopback calls, browser-private state, credentials, or maps.",
        "Run the future full publication scanner matrix.",
        "Publish only through the future Pages handoff.",
    ],
    "azure-functions": [
        "Select a reviewed immutable rapplication artifact.",
        "Project only explicitly public configuration.",
        "Build a function body from pinned dependencies.",
        "Require future cloud-specific identity and deployment attestation.",
    ],
    "dataverse": [
        "Start from an attested cloud application body.",
        "Map public schemas without exporting local twin state.",
        "Apply least-privilege table and caller policies.",
        "Require future Dataverse deployment and behavior tests.",
    ],
    "m365-copilot-studio": [
        "Start from an attested Dataverse or approved connector boundary.",
        "Generate a reviewed enterprise package without local private state.",
        "Validate caller identity, consent, and capability allowlists.",
        "Require future tenant deployment and end-to-end attestation.",
    ],
}


def _json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _response(action, *, ok=True, **values):
    payload = {"agent": "Deployment", "action": action, "ok": ok}
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


def _evidence(matrix, target):
    wanted = set(_TARGET_CAPABILITIES[target])
    records = []
    for item in matrix.get("capabilities", []):
        if item.get("id") not in wanted:
            continue
        repositories = [
            {
                "name": repository.get("name"),
                "head_sha": repository.get("head_sha"),
            }
            for repository in item.get("direct_source_repositories", [])[:8]
            if isinstance(repository, dict)
        ]
        records.append(
            {
                "capability_id": item.get("id"),
                "audit_status": item.get("status"),
                "selected": item.get("selected_for_cubby") is True,
                "repositories": repositories,
            }
        )
    return sorted(records, key=lambda item: item["capability_id"])


class Deployment(BasicAgent):
    """Plan only; this agent has no network, credential, or execution path."""

    name = "Deployment"
    metadata = {
        "name": "Deployment",
        "description": "Inspect or render a dry-run deployment plan.",
        "parameters": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["inspect", "render"],
                },
                "target": {
                    "type": "string",
                    "enum": [
                        "local",
                        "pages",
                        "azure-functions",
                        "dataverse",
                        "m365-copilot-studio",
                    ],
                },
            },
            "required": ["action", "target"],
            "additionalProperties": False,
        },
    }

    def perform(self, **kwargs):
        action = kwargs.get("action")
        target = kwargs.get("target")
        if action not in __manifest__["actions"]:
            return _response(
                str(action or ""),
                ok=False,
                error={"code": "invalid_action", "message": "Unsupported action."},
            )
        if target not in _TARGET_CAPABILITIES:
            return _response(
                action,
                ok=False,
                error={"code": "invalid_target", "message": "Unsupported target."},
            )
        try:
            root = _root()
            matrix = _read(root, _MATRIX)
            lock = _read(root, _LOCK)
            attested = lock.get("profile", {}).get("attested") is True
            classification = (
                "implemented_unattested" if target == "local" else "mapped_only"
            )
            common = {
                "target": target,
                "classification": classification,
                "attested": attested and target == "local",
                "execution_performed": False,
                "credentials_requested": False,
                "evidence": _evidence(matrix, target),
            }
            if action == "inspect":
                return _response(
                    action,
                    **common,
                    build_blocked=lock.get("lock_status", {}).get(
                        "build_blocked"
                    )
                    is True,
                    statement=(
                        "Local components exist but are not attested."
                        if target == "local"
                        else "This destination is mapped from references only."
                    ),
                )
            return _response(
                action,
                **common,
                dry_run=True,
                steps=list(_PLANS[target]),
                blockers=(
                    ["Future supervisor and host attestation are required."]
                    if target == "local"
                    else [
                        "No deployment implementation is present.",
                        "Future target-specific review and attestation are required.",
                    ]
                ),
            )
        except Exception:
            return _response(
                action,
                ok=False,
                error={
                    "code": "evidence_unavailable",
                    "message": "Local deployment evidence could not be inspected.",
                },
            )
