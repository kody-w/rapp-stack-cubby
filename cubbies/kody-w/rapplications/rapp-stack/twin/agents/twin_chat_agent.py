"""Redacted read-only inspection of this twin's signed-chat transport state."""

import hashlib
import json
import os
import sqlite3
from pathlib import Path

from agents.basic_agent import BasicAgent


__manifest__ = {
    "schema": "rapp-agent/1.0",
    "name": "TwinChat",
    "version": "1.0.0",
    "description": "Report redacted signed-chat status and a synthetic vector.",
    "actions": ["status", "identity", "journal", "vector"],
    "capability_ids": [],
    "mutability": "read_only",
    "enabled_by_default": True,
    "provenance": "original_new",
    "dependencies": ["python-stdlib", "BasicAgent"],
}

_PAIRING_SCHEMA = "rapp-twin-chat-pairing/1.0"
_MAX_JSON_BYTES = 64 * 1024
_SYNTHETIC_VECTOR = {
    "label": "synthetic-not-production",
    "schema": "rapp-twin-chat-vector/1.0",
    "unicode": "λ",
}
_SYNTHETIC_DIGEST = (
    "d39086d0d130fa3238cf62df2522d00c9f19a0b5f8ca1d199d92a26e8dccf9c6"
)


def _json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _response(action, *, ok=True, **values):
    payload = {"agent": "TwinChat", "action": action, "ok": ok}
    payload.update(values)
    return _json(payload)


def _state_directory():
    raw_data = os.environ.get("RAPP_STACK_DATA_DIR")
    raw_state = os.environ.get("RAPP_STACK_TWIN_CHAT_STATE_DIR")
    if not raw_data or not raw_state:
        raise ValueError("explicit twin-chat state paths are required")
    data = Path(raw_data)
    state = Path(raw_state)
    if not data.is_absolute() or not state.is_absolute():
        raise ValueError("state paths must be absolute")
    if data.is_symlink() or state.is_symlink():
        raise ValueError("state paths must not be symbolic links")
    resolved_data = data.resolve(strict=True)
    resolved_state = state.resolve(strict=True)
    if (
        not resolved_data.is_dir()
        or not resolved_state.is_dir()
        or resolved_state != resolved_data
        and resolved_data not in resolved_state.parents
    ):
        raise ValueError("twin-chat state must be contained by data root")
    return resolved_state


def _pairing():
    path = _state_directory() / "pairing.json"
    if path.is_symlink() or not path.is_file():
        raise ValueError("pairing is unavailable")
    if path.stat().st_size > _MAX_JSON_BYTES:
        raise ValueError("pairing exceeds its read bound")
    value = json.loads(path.read_text(encoding="utf-8"))
    required = {
        "schema",
        "twin_rappid",
        "controller_rappid",
        "controller_key_id",
        "controller_public_jwk",
        "child_key_id",
        "child_public_jwk",
        "generation",
        "key_epoch",
        "paired_at",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema") != _PAIRING_SCHEMA
    ):
        raise ValueError("pairing is invalid")
    return value


def _journal_counts():
    raw = os.environ.get("RAPP_STACK_TWIN_CHAT_REPLAY_DB")
    if not raw:
        raise ValueError("explicit replay journal path is required")
    path = Path(raw)
    state = _state_directory()
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("replay journal path is invalid")
    resolved = path.resolve(strict=True)
    if not resolved.is_file() or state not in resolved.parents:
        raise ValueError("replay journal must be contained by twin-chat state")
    escaped = (
        resolved.as_posix()
        .replace("%", "%25")
        .replace("?", "%3F")
        .replace("#", "%23")
    )
    connection = sqlite3.connect(
        "file:" + escaped + "?mode=ro",
        uri=True,
        timeout=1.0,
    )
    try:
        rows = connection.execute(
            "SELECT state, COUNT(*) FROM twin_chat_replay GROUP BY state"
        ).fetchall()
    finally:
        connection.close()
    counts = {
        "processing": 0,
        "completed": 0,
        "rejected": 0,
        "failed": 0,
    }
    for state_name, count in rows:
        if state_name in counts:
            counts[state_name] = int(count)
    counts["total"] = sum(counts.values())
    return counts


class TwinChat(BasicAgent):
    """Expose only bounded public identifiers and aggregate journal state."""

    name = "TwinChat"
    metadata = {
        "name": "TwinChat",
        "description": "Inspect redacted signed twin-chat status.",
        "parameters": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["status", "identity", "journal", "vector"],
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
            if action == "vector":
                encoded = _json(_SYNTHETIC_VECTOR).encode("utf-8")
                digest = hashlib.sha256(encoded).hexdigest()
                return _response(
                    action,
                    synthetic=True,
                    production_identity=False,
                    canonical_sha256=digest,
                    expected_sha256=_SYNTHETIC_DIGEST,
                    matched=digest == _SYNTHETIC_DIGEST,
                )
            pairing = _pairing()
            identity = {
                "profile": "rapp-twin-chat/1.0",
                "twin_rappid": pairing["twin_rappid"],
                "controller_rappid": pairing["controller_rappid"],
                "child_key_id": pairing["child_key_id"],
                "controller_key_id": pairing["controller_key_id"],
                "generation": pairing["generation"],
                "key_epoch": pairing["key_epoch"],
            }
            if action == "identity":
                return _response(action, **identity)
            counts = _journal_counts()
            if action == "journal":
                return _response(
                    action,
                    counts=counts,
                    values_redacted=True,
                )
            return _response(
                action,
                configured=True,
                paired=True,
                identity=identity,
                journal_counts=counts,
                values_redacted=True,
            )
        except Exception:
            return _response(
                action,
                ok=False,
                error={
                    "code": "twin_chat_state_unavailable",
                    "message": "The contained redacted transport state is unavailable.",
                },
            )
