"""Render and optionally persist tightly constrained single-file agents."""

import ast
import contextlib
import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
import time
from pathlib import Path

from agents.basic_agent import BasicAgent


__manifest__ = {
    "schema": "rapp-agent/1.0",
    "name": "AgentFactory",
    "version": "1.0.0",
    "description": "Render a strict portable agent scaffold and guard generated-agent writes.",
    "actions": ["render", "list", "create", "delete"],
    "capability_ids": ["agents.single-file-cartridge"],
    "mutability": "guarded_generated_files",
    "enabled_by_default": True,
    "provenance": "original_new",
    "dependencies": ["python-stdlib", "BasicAgent"],
}

_CLASS_RE = re.compile(r"^[A-Z][A-Za-z0-9]{0,47}$")
_PARAM_RE = re.compile(r"^[a-z][a-z0-9_]{0,47}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_SECRET_TEXT_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|authorization|credential|password|"
    r"private[_-]?key|secret|token)\b\s*[:=]"
)
_SECRET_SHAPE_RE = re.compile(
    r"(?i)\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"sk-[A-Za-z0-9_-]{20,}|bearer\s+[A-Za-z0-9._~+/-]{16,})\b"
)
_ALLOWED_TYPES = frozenset(
    {"array", "boolean", "integer", "number", "object", "string"}
)
_MAX_DESCRIPTION = 240
_MAX_PARAMETERS = 24
_MAX_GENERATED_BYTES = 64 * 1024
_LOCK_WAIT_SECONDS = 5.0
_BUNDLED_AGENTS = (
    "cubbies/kody-w/rapplications/rapp-stack/twin/agents"
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
    payload = {"agent": "AgentFactory", "action": action, "ok": ok}
    payload.update(values)
    return _json(payload)


def _safe_root(variable, *, private=False):
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
    if private and stat.S_IMODE(resolved.stat().st_mode) & 0o077:
        raise ValueError(f"{variable} must be private")
    return resolved


def _generated_root():
    generated = _safe_root(
        "RAPP_STACK_GENERATED_AGENTS_DIR", private=True
    )
    stack = _safe_root("RAPP_STACK_ROOT")
    bundled = stack.joinpath(*Path(_BUNDLED_AGENTS).parts).resolve(strict=True)
    if (
        generated == bundled
        or generated in bundled.parents
        or bundled in generated.parents
    ):
        raise ValueError("generated root must not overlap bundled agents")
    return generated


def _file_name(name):
    pieces = re.findall(r"[A-Z]+(?=[A-Z][a-z0-9]|$)|[A-Z]?[a-z0-9]+", name)
    if not pieces:
        raise ValueError("agent name cannot form a file name")
    return "_".join(piece.casefold() for piece in pieces) + "_agent.py"


def _description(value):
    if not isinstance(value, str):
        raise ValueError("description must be text")
    normalized = " ".join(value.split())
    if not normalized or len(normalized) > _MAX_DESCRIPTION:
        raise ValueError("description is empty or too long")
    if any(ord(character) < 32 for character in normalized):
        raise ValueError("description contains control characters")
    if (
        _SECRET_TEXT_RE.search(normalized)
        or _SECRET_SHAPE_RE.search(normalized)
        or ("BEGIN" + " PRIVATE KEY") in normalized.upper()
    ):
        raise ValueError("description contains secret-shaped content")
    return normalized


def _parameters(value):
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > _MAX_PARAMETERS:
        raise ValueError("parameters must be a bounded array")
    result = []
    seen = {"action"}
    for item in value:
        if not isinstance(item, dict) or set(item) - {
            "name",
            "type",
            "description",
            "required",
        }:
            raise ValueError("parameter template contains unsupported fields")
        name = item.get("name")
        kind = item.get("type")
        description = item.get("description")
        required = item.get("required", False)
        if not isinstance(name, str) or not _PARAM_RE.fullmatch(name):
            raise ValueError("parameter name is invalid")
        if name in seen:
            raise ValueError("parameter names must be unique")
        if kind not in _ALLOWED_TYPES:
            raise ValueError("parameter type is invalid")
        if not isinstance(description, str):
            raise ValueError("parameter description must be text")
        description = " ".join(description.split())
        if not description or len(description) > 200:
            raise ValueError("parameter description is invalid")
        if (
            _SECRET_TEXT_RE.search(description)
            or _SECRET_SHAPE_RE.search(description)
            or ("BEGIN" + " PRIVATE KEY") in description.upper()
        ):
            raise ValueError("parameter description contains secret-shaped content")
        if not isinstance(required, bool):
            raise ValueError("parameter required flag must be boolean")
        seen.add(name)
        result.append(
            {
                "name": name,
                "type": kind,
                "description": description,
                "required": required,
            }
        )
    return sorted(result, key=lambda item: item["name"])


def _render(name, description, parameters):
    if not isinstance(name, str) or not _CLASS_RE.fullmatch(name):
        raise ValueError("name must be a short PascalCase identifier")
    description = _description(description)
    parameters = _parameters(parameters)
    properties = {
        "action": {"type": "string", "enum": ["run"]},
    }
    required = ["action"]
    for item in parameters:
        properties[item["name"]] = {
            "type": item["type"],
            "description": item["description"],
        }
        if item["required"]:
            required.append(item["name"])
    schema = {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }
    manifest = {
        "schema": "rapp-agent/1.0",
        "name": name,
        "version": "1.0.0",
        "description": description,
        "actions": ["run"],
        "capability_ids": [],
        "mutability": "read_only",
        "enabled_by_default": False,
        "provenance": "generated_local",
        "dependencies": ["python-stdlib", "BasicAgent"],
    }
    allowed = ["action"] + [item["name"] for item in parameters]
    runtime_required = [
        item["name"] for item in parameters if item["required"]
    ]
    source = (
        f'"""{description}"""\n\n'
        "import json\n\n"
        "from agents.basic_agent import BasicAgent\n\n\n"
        f"__manifest__ = {manifest!r}\n\n\n"
        f"class {name}(BasicAgent):\n"
        f"    name = {name!r}\n"
        "    metadata = {\n"
        f"        'name': {name!r},\n"
        f"        'description': {description!r},\n"
        f"        'parameters': {schema!r},\n"
        "    }\n\n"
        "    def perform(self, **kwargs):\n"
        f"        allowed = {allowed!r}\n"
        f"        required = {runtime_required!r}\n"
        "        unknown = sorted(set(kwargs) - set(allowed))\n"
        "        missing = sorted(key for key in required if key not in kwargs)\n"
        "        if kwargs.get('action') != 'run' or unknown or missing:\n"
        "            result = {'ok': False, 'error': 'invalid_parameters'}\n"
        "        else:\n"
        "            received = sorted(key for key in allowed\n"
        "                              if key != 'action' and key in kwargs)\n"
        f"            result = {{'ok': True, 'agent': {name!r},\n"
        "                      'received_parameters': received}\n"
        "        return json.dumps(result, ensure_ascii=False, allow_nan=False,\n"
        "                          sort_keys=True, separators=(',', ':'))\n"
    )
    _validate_emitted(source, name)
    encoded = source.encode("utf-8")
    if len(encoded) > _MAX_GENERATED_BYTES:
        raise ValueError("rendered source exceeds the size bound")
    return {
        "source": source,
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "file_name": _file_name(name),
        "manifest": manifest,
    }


def _call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _validate_emitted(source, expected_name):
    tree = ast.parse(source)
    if ast.get_docstring(tree) is None:
        raise ValueError("rendered source needs a module docstring")
    manifests = [
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "__manifest__"
            for target in node.targets
        )
    ]
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef)]
    if len(manifests) != 1 or len(classes) != 1:
        raise ValueError("rendered source contract is invalid")
    agent_class = classes[0]
    if (
        agent_class.name != expected_name
        or len(agent_class.bases) != 1
        or _call_name(agent_class.bases[0]) != "BasicAgent"
    ):
        raise ValueError("rendered agent class is invalid")
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append(node.module or "")
    if set(imports) - {"json", "agents.basic_agent"}:
        raise ValueError("rendered imports are invalid")
    methods = [
        node
        for node in agent_class.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "perform"
    ]
    if len(methods) != 1 or methods[0].args.kwarg is None:
        raise ValueError("rendered perform signature is invalid")
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node.func) in {
            "eval",
            "exec",
            "compile",
            "__import__",
        }:
            raise ValueError("rendered source contains a forbidden call")


def _digest(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("generated path must be a regular file")
    if path.stat().st_size > _MAX_GENERATED_BYTES:
        raise ValueError("generated file exceeds the size bound")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _atomic_write(path, source):
    pending = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix=f".{path.name}.",
            suffix=".pending",
            dir=path.parent,
            delete=False,
        ) as handle:
            pending = Path(handle.name)
            os.fchmod(handle.fileno(), 0o600)
            handle.write(source)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(pending, path)
        pending = None
        os.chmod(path, 0o600)
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if pending is not None and pending.exists():
            pending.unlink()


@contextlib.contextmanager
def _generated_transaction(root):
    lock_path = root / ".agent-factory.lock"
    if lock_path.is_symlink():
        raise ValueError("generated-agent lock must not be a symbolic link")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    acquired = False
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode):
            raise ValueError("generated-agent lock must be a regular file")
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
                    raise TimeoutError("generated-agent lock timed out")
                time.sleep(0.01)
        yield
    finally:
        if acquired:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


class AgentFactory(BasicAgent):
    """Generate only inert, reviewable BasicAgent scaffolds."""

    name = "AgentFactory"
    metadata = {
        "name": "AgentFactory",
        "description": "Render, list, create, or delete strict local agent scaffolds.",
        "parameters": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["render", "list", "create", "delete"],
                },
                "name": {"type": "string", "maxLength": 48},
                "description": {"type": "string", "maxLength": 240},
                "parameters": {
                    "type": "array",
                    "maxItems": 24,
                    "items": {"type": "object"},
                },
                "expected_digest": {
                    "type": "string",
                    "pattern": "^[0-9a-f]{64}$",
                },
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
            if action == "render":
                rendered = _render(
                    kwargs.get("name"),
                    kwargs.get("description"),
                    kwargs.get("parameters"),
                )
                return _response(action, **rendered, write_performed=False)
            if action == "list":
                return self._list()
            if action == "create":
                return self._create(kwargs)
            return self._delete(kwargs)
        except Exception:
            return _response(
                action,
                ok=False,
                error={
                    "code": "invalid_or_unavailable",
                    "message": "The guarded generated-agent operation was rejected.",
                },
            )

    def _list(self):
        root = _generated_root()
        records = []
        with _generated_transaction(root):
            for path in sorted(
                root.glob("*_agent.py"), key=lambda item: item.name
            ):
                if path.is_symlink():
                    continue
                records.append(
                    {
                        "file_name": path.name,
                        "sha256": _digest(path),
                        "size": path.stat().st_size,
                    }
                )
        return _response(
            "list",
            count=len(records),
            generated_agents=records[:100],
            truncated=len(records) > 100,
            write_performed=False,
        )

    def _create(self, kwargs):
        rendered = _render(
            kwargs.get("name"),
            kwargs.get("description"),
            kwargs.get("parameters"),
        )
        root = _generated_root()
        path = root / rendered["file_name"]
        with _generated_transaction(root):
            if path.parent != root or path.is_symlink():
                raise ValueError("generated path is invalid")
            exists = path.exists()
            expected = kwargs.get("expected_digest")
            if exists:
                if (
                    not isinstance(expected, str)
                    or not _DIGEST_RE.fullmatch(expected)
                ):
                    return _response(
                        "create",
                        ok=False,
                        error={
                            "code": "overwrite_requires_digest",
                            "message": "Existing files require their expected digest.",
                        },
                        write_performed=False,
                    )
                if _digest(path) != expected:
                    return _response(
                        "create",
                        ok=False,
                        error={
                            "code": "digest_conflict",
                            "message": "Existing file digest does not match.",
                        },
                        write_performed=False,
                    )
            elif expected is not None:
                raise ValueError(
                    "expected digest was supplied for a missing file"
                )
            if os.environ.get("RAPP_STACK_ALLOW_AGENT_WRITES") != "1":
                return _response(
                    "create",
                    status="disabled",
                    write_enabled=False,
                    write_performed=False,
                    file_name=rendered["file_name"],
                    sha256=rendered["sha256"],
                )
            _atomic_write(path, rendered["source"])
            if _digest(path) != rendered["sha256"]:
                raise OSError("post-write digest mismatch")
            return _response(
                "create",
                status="updated" if exists else "created",
                write_enabled=True,
                write_performed=True,
                file_name=path.name,
                sha256=rendered["sha256"],
            )

    def _delete(self, kwargs):
        name = kwargs.get("name")
        if not isinstance(name, str) or not _CLASS_RE.fullmatch(name):
            raise ValueError("name is invalid")
        expected = kwargs.get("expected_digest")
        if not isinstance(expected, str) or not _DIGEST_RE.fullmatch(expected):
            raise ValueError("delete requires an expected digest")
        root = _generated_root()
        path = root / _file_name(name)
        with _generated_transaction(root):
            if path.parent != root or path.is_symlink():
                raise ValueError("generated path is invalid")
            if not path.exists():
                return _response(
                    "delete",
                    status="not_found",
                    write_performed=False,
                    file_name=path.name,
                )
            if _digest(path) != expected:
                return _response(
                    "delete",
                    ok=False,
                    error={
                        "code": "digest_conflict",
                        "message": "Existing file digest does not match.",
                    },
                    write_performed=False,
                )
            if os.environ.get("RAPP_STACK_ALLOW_AGENT_WRITES") != "1":
                return _response(
                    "delete",
                    status="disabled",
                    write_enabled=False,
                    write_performed=False,
                    file_name=path.name,
                )
            path.unlink()
            descriptor = os.open(root, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            return _response(
                "delete",
                status="deleted",
                write_enabled=True,
                write_performed=True,
                file_name=path.name,
            )
