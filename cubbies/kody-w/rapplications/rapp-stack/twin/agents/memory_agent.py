"""Principal-isolated, bounded local memory using the runtime storage shim."""

import contextlib
import fcntl
import hashlib
import json
import os
import re
import stat
import time
from datetime import datetime, timezone
from pathlib import Path

from agents.basic_agent import BasicAgent
from utils.azure_file_storage import AzureFileStorageManager


__manifest__ = {
    "schema": "rapp-agent/1.0",
    "name": "Memory",
    "version": "1.0.0",
    "description": "Remember and recall bounded local facts in an isolated principal namespace.",
    "actions": ["remember", "recall", "list", "forget", "context"],
    "capability_ids": [
        "memory.consent-projection",
        "memory.private-runtime-state",
        "memory.session-context",
    ],
    "mutability": "guarded_local_state",
    "enabled_by_default": True,
    "provenance": "original_new",
    "dependencies": [
        "python-stdlib",
        "BasicAgent",
        "AzureFileStorageManager-local-shim",
    ],
}

_PRINCIPAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$")
_ID_RE = re.compile(r"^mem_[0-9a-f]{24}$")
_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
_TIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
)
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|authorization|credential|password|"
    r"private[_-]?key|secret|token)\b\s*[:=]"
)
_SECRET_SHAPE_RE = re.compile(
    r"(?i)\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"sk-[A-Za-z0-9_-]{20,}|bearer\s+[A-Za-z0-9._~+/-]{16,})\b"
)
_MAX_CONTENT = 2000
_MAX_RECORDS = 128
_MAX_RESULTS = 20
_MAX_CONTEXT_RECORDS = 6
_MAX_CONTEXT_CHARS = 1200
_LOCK_WAIT_SECONDS = 5.0


def _json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _response(action, *, ok=True, **values):
    payload = {"agent": "Memory", "action": action, "ok": ok}
    payload.update(values)
    return _json(payload)


def _explicit_data_root():
    raw = os.environ.get("RAPP_STACK_DATA_DIR")
    if not raw:
        raise ValueError("RAPP_STACK_DATA_DIR is required")
    candidate = Path(raw)
    if not candidate.is_absolute():
        raise ValueError("RAPP_STACK_DATA_DIR must be absolute")
    current = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise ValueError("data root must not contain symbolic links")
    root = candidate.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("data root must be a directory")
    if stat.S_IMODE(root.stat().st_mode) & 0o077:
        raise ValueError("data root must be private")
    return root


@contextlib.contextmanager
def _memory_transaction(root):
    lock_path = root / ".memory-agent.lock"
    if lock_path.is_symlink():
        raise ValueError("memory lock must not be a symbolic link")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    acquired = False
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode):
            raise ValueError("memory lock must be a regular file")
        os.fchmod(descriptor, 0o600)
        deadline = time.monotonic() + _LOCK_WAIT_SECONDS
        while True:
            try:
                fcntl.flock(
                    descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB
                )
                acquired = True
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("memory lock timed out")
                time.sleep(0.01)
        yield
    finally:
        if acquired:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _principal(kwargs):
    value = os.environ.get("RAPP_STACK_PRINCIPAL")
    if not isinstance(value, str) or not _PRINCIPAL_RE.fullmatch(value):
        raise ValueError("an isolated runtime principal is required")
    if value in {".", ".."}:
        raise ValueError("principal is invalid")
    return value


def _timestamp(value):
    if value is None:
        return datetime.now(timezone.utc).replace(microsecond=0).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    if not isinstance(value, str) or not _TIME_RE.fullmatch(value):
        raise ValueError("timestamp must be UTC with whole seconds")
    parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    parsed.replace(tzinfo=timezone.utc)
    return value


def _content(value):
    if not isinstance(value, str):
        raise ValueError("content must be text")
    normalized = " ".join(value.split())
    if not normalized or len(normalized) > _MAX_CONTENT:
        raise ValueError("content is empty or too large")
    marker = "BEGIN" + " PRIVATE KEY"
    if (
        _SECRET_ASSIGNMENT_RE.search(normalized)
        or _SECRET_SHAPE_RE.search(normalized)
        or marker in normalized.upper()
    ):
        raise PermissionError("secret-shaped content is not accepted")
    return normalized


def _tags(value):
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 8:
        raise ValueError("tags must be a short array")
    normalized = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError("tags must be strings")
        tag = item.strip().casefold()
        if not _TAG_RE.fullmatch(tag):
            raise ValueError("tag is invalid")
        if tag not in normalized:
            normalized.append(tag)
    return sorted(normalized)


def _importance(value):
    if value is None:
        return 3
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 5:
        raise ValueError("importance must be an integer from one through five")
    return value


def _record_view(record, include_content=True):
    result = {
        "id": record["id"],
        "tags": list(record["tags"]),
        "importance": record["importance"],
        "created_at": record["created_at"],
    }
    if include_content:
        result["content"] = record["content"]
    return result


class Memory(BasicAgent):
    """Store a small JSON memory model under the runtime-selected principal."""

    name = "Memory"
    metadata = {
        "name": "Memory",
        "description": "Remember, recall, list, forget, or project local memory.",
        "parameters": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["remember", "recall", "list", "forget", "context"],
                },
                "content": {"type": "string", "maxLength": 2000},
                "memory_id": {
                    "type": "string",
                    "pattern": "^mem_[0-9a-f]{24}$",
                },
                "query": {"type": "string", "maxLength": 160},
                "tags": {
                    "type": "array",
                    "maxItems": 8,
                    "items": {"type": "string", "maxLength": 32},
                },
                "importance": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 5,
                },
                "timestamp": {"type": "string", "maxLength": 20},
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 20,
                },
            },
            "required": ["action"],
            "additionalProperties": False,
        },
    }

    def __init__(self):
        data_root = _explicit_data_root()
        self._manager = AzureFileStorageManager()
        manager_root = getattr(getattr(self._manager, "storage", None), "data_root", None)
        if manager_root is None or Path(manager_root).resolve(strict=True) != data_root:
            raise ValueError("storage shim does not match RAPP_STACK_DATA_DIR")
        super().__init__()

    def perform(self, **kwargs):
        action = kwargs.get("action")
        if action not in __manifest__["actions"]:
            return _response(
                str(action or ""),
                ok=False,
                error={"code": "invalid_action", "message": "Unsupported action."},
            )
        try:
            principal = _principal(kwargs)
            with _memory_transaction(_explicit_data_root()):
                self._manager.set_memory_context(principal)
                model = self._read_model()
                if action == "remember":
                    return self._remember(model, principal, kwargs)
                if action == "recall":
                    return self._recall(model, kwargs)
                if action == "list":
                    return self._list(model, kwargs)
                if action == "forget":
                    return self._forget(model, kwargs)
                return self._context(model, kwargs)
        except PermissionError:
            return _response(
                action,
                ok=False,
                error={
                    "code": "secret_rejected",
                    "message": "Secret-shaped memory content is not accepted.",
                },
            )
        except Exception:
            return _response(
                action,
                ok=False,
                error={
                    "code": "invalid_or_unavailable",
                    "message": "The isolated memory operation could not be completed.",
                },
            )

    def system_context(self):
        try:
            principal = _principal({})
            with _memory_transaction(_explicit_data_root()):
                self._manager.set_memory_context(principal)
                model = self._read_model()
                relevant = [
                    record
                    for record in model["records"]
                    if record["importance"] >= 4
                    or set(record["tags"])
                    & {"context", "preference", "system"}
                ]
                relevant.sort(
                    key=lambda record: (
                        -record["importance"],
                        record["created_at"],
                        record["id"],
                    )
                )
                lines = [
                    f"- [{record['id']}] {record['content']}"
                    for record in relevant[:_MAX_CONTEXT_RECORDS]
                ]
                if not lines:
                    return None
                rendered = "Relevant local facts only:\n" + "\n".join(lines)
                return rendered[:_MAX_CONTEXT_CHARS]
        except Exception:
            return None

    def _read_model(self):
        value = self._manager.read_json()
        if value == {}:
            return {"schema": "rapp-memory/1.0", "records": []}
        if (
            not isinstance(value, dict)
            or value.get("schema") != "rapp-memory/1.0"
            or not isinstance(value.get("records"), list)
            or len(value["records"]) > _MAX_RECORDS
        ):
            raise ValueError("stored memory model is invalid")
        records = []
        seen = set()
        for item in value["records"]:
            if (
                not isinstance(item, dict)
                or not _ID_RE.fullmatch(str(item.get("id", "")))
                or not isinstance(item.get("content"), str)
                or len(item["content"]) > _MAX_CONTENT
                or not isinstance(item.get("tags"), list)
                or not isinstance(item.get("importance"), int)
                or not 1 <= item["importance"] <= 5
                or not _TIME_RE.fullmatch(str(item.get("created_at", "")))
                or item["id"] in seen
            ):
                raise ValueError("stored memory record is invalid")
            seen.add(item["id"])
            records.append(
                {
                    "id": item["id"],
                    "content": _content(item["content"]),
                    "tags": _tags(item["tags"]),
                    "importance": item["importance"],
                    "created_at": item["created_at"],
                }
            )
        records.sort(key=lambda record: (record["created_at"], record["id"]))
        return {"schema": "rapp-memory/1.0", "records": records}

    def _remember(self, model, principal, kwargs):
        content = _content(kwargs.get("content"))
        tags = _tags(kwargs.get("tags"))
        importance = _importance(kwargs.get("importance"))
        created_at = _timestamp(kwargs.get("timestamp"))
        material = _json(
            {
                "content": content,
                "created_at": created_at,
                "importance": importance,
                "principal": principal,
                "tags": tags,
            }
        )
        memory_id = "mem_" + hashlib.sha256(
            material.encode("utf-8")
        ).hexdigest()[:24]
        existing = next(
            (item for item in model["records"] if item["id"] == memory_id), None
        )
        record = {
            "id": memory_id,
            "content": content,
            "tags": tags,
            "importance": importance,
            "created_at": created_at,
        }
        if existing is not None:
            return _response(
                "remember", status="already_present", memory=_record_view(existing)
            )
        if len(model["records"]) >= _MAX_RECORDS:
            return _response(
                "remember",
                ok=False,
                error={"code": "record_limit", "message": "Memory record limit reached."},
            )
        if os.environ.get("RAPP_STACK_ALLOW_AGENT_WRITES") != "1":
            return _response(
                "remember",
                status="disabled",
                write_enabled=False,
                would_remember=_record_view(record, include_content=False),
            )
        model["records"].append(record)
        model["records"].sort(
            key=lambda item: (item["created_at"], item["id"])
        )
        self._manager.write_json(model)
        return _response(
            "remember",
            status="stored",
            write_enabled=True,
            memory=_record_view(record),
        )

    def _recall(self, model, kwargs):
        memory_id = kwargs.get("memory_id")
        query = kwargs.get("query")
        if memory_id is not None and (
            not isinstance(memory_id, str) or not _ID_RE.fullmatch(memory_id)
        ):
            raise ValueError("memory id is invalid")
        if query is not None and (
            not isinstance(query, str) or not query.strip() or len(query) > 160
        ):
            raise ValueError("query is invalid")
        if memory_id is None and query is None:
            raise ValueError("recall requires an id or query")
        needle = query.casefold() if isinstance(query, str) else None
        matches = [
            record
            for record in model["records"]
            if (memory_id is not None and record["id"] == memory_id)
            or (
                needle is not None
                and (
                    needle in record["content"].casefold()
                    or any(needle in tag for tag in record["tags"])
                )
            )
        ]
        matches.sort(
            key=lambda item: (
                -item["importance"],
                item["created_at"],
                item["id"],
            )
        )
        return _response(
            "recall",
            count=min(len(matches), _MAX_RESULTS),
            truncated=len(matches) > _MAX_RESULTS,
            memories=[
                _record_view(record) for record in matches[:_MAX_RESULTS]
            ],
        )

    def _list(self, model, kwargs):
        value = kwargs.get("limit", 20)
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 1 <= value <= _MAX_RESULTS
        ):
            raise ValueError("limit is invalid")
        records = sorted(
            model["records"],
            key=lambda item: (
                -item["importance"],
                item["created_at"],
                item["id"],
            ),
        )
        return _response(
            "list",
            count=min(len(records), value),
            total_count=len(records),
            truncated=len(records) > value,
            memories=[_record_view(item) for item in records[:value]],
        )

    def _forget(self, model, kwargs):
        memory_id = kwargs.get("memory_id")
        if not isinstance(memory_id, str) or not _ID_RE.fullmatch(memory_id):
            raise ValueError("memory id is invalid")
        exists = any(item["id"] == memory_id for item in model["records"])
        if os.environ.get("RAPP_STACK_ALLOW_AGENT_WRITES") != "1":
            return _response(
                "forget",
                status="disabled",
                write_enabled=False,
                would_delete=exists,
                memory_id=memory_id,
            )
        if exists:
            model["records"] = [
                item for item in model["records"] if item["id"] != memory_id
            ]
            self._manager.write_json(model)
        return _response(
            "forget",
            status="deleted" if exists else "not_found",
            write_enabled=True,
            memory_id=memory_id,
        )

    def _context(self, model, kwargs):
        query = kwargs.get("query")
        if query is not None and (
            not isinstance(query, str) or not query.strip() or len(query) > 160
        ):
            raise ValueError("query is invalid")
        needle = query.casefold() if isinstance(query, str) else None
        records = [
            record
            for record in model["records"]
            if (
                needle is not None
                and (
                    needle in record["content"].casefold()
                    or any(needle in tag for tag in record["tags"])
                )
            )
            or (
                needle is None
                and (
                    record["importance"] >= 4
                    or set(record["tags"])
                    & {"context", "preference", "system"}
                )
            )
        ]
        records.sort(
            key=lambda item: (
                -item["importance"],
                item["created_at"],
                item["id"],
            )
        )
        projected = records[:_MAX_CONTEXT_RECORDS]
        return _response(
            "context",
            count=len(projected),
            truncated=len(records) > len(projected),
            memories=[_record_view(item) for item in projected],
            projection="relevant_local_facts_only",
        )
