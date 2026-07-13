"""Redacted structural security inspection for explicitly contained local data."""

import ast
import hashlib
import json
import os
import re
import stat
from pathlib import Path

from agents.basic_agent import BasicAgent


__manifest__ = {
    "schema": "rapp-agent/1.0",
    "name": "Security",
    "version": "1.0.1",
    "description": "Inspect policy, provenance, unresolved locks, and hard-bounded source risks.",
    "actions": ["boundary", "provenance", "unresolved", "scan", "verify"],
    "capability_ids": [
        "governance.license-provenance",
        "governance.public-private-boundary",
        "release.provenance-file-gate",
        "substrate.git-source-identity",
    ],
    "mutability": "read_only",
    "enabled_by_default": True,
    "provenance": "original_new",
    "dependencies": ["python-stdlib", "BasicAgent"],
}

_POLICY = "docs/PUBLIC_PRIVATE_BOUNDARY.md"
_PROVENANCE = "PROVENANCE.json"
_LOCK = "STACK_LOCK.json"
_CATALOG = (
    "cubbies/kody-w/rapplications/rapp-stack/twin/catalog/agent-catalog.json"
)
_MATRIX = (
    "cubbies/kody-w/rapplications/rapp-stack/twin/catalog/"
    "implementation-matrix.json"
)
_MAX_POLICY_BYTES = 512 * 1024
_MAX_SCAN_FILE_BYTES = 512 * 1024
_MAX_SCAN_TOTAL_BYTES = 4 * 1024 * 1024
_MAX_SCAN_FILES = 500
_MAX_SCAN_ENTRIES = 2048
_MAX_SCAN_DIRECTORIES = 256
_MAX_SCAN_DEPTH = 64
_TEXT_SUFFIXES = frozenset(
    {".json", ".md", ".py", ".sh", ".toml", ".txt", ".yaml", ".yml"}
)
_FORBIDDEN_NAMES = frozenset(
    {
        ".env",
        "credentials.json",
        "id_ed25519",
        "id_rsa",
        "secrets.json",
    }
)
_PRIVATE_SUFFIXES = (
    ".db",
    ".key",
    ".p12",
    ".pem",
    ".pfx",
    ".sqlite",
    ".sqlite3",
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?key|authorization|credential|password|"
    r"private[_-]?key|secret|token)\b\s*[:=]"
)
_SECRET_SHAPE = re.compile(
    r"(?i)\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"sk-[A-Za-z0-9_-]{20,}|bearer\s+[A-Za-z0-9._~+/-]{16,})\b"
)
_LOCAL_PATH = re.compile(
    r"(?:/(?:Users|home)/[^/\s]+/|[A-Za-z]:\\Users\\[^\\\s]+\\)"
)
_PHONE_SHAPE = re.compile(r"(?:\+?[0-9][0-9 .()_-]{7,}[0-9])")
_NETWORK_MODULES = frozenset(
    {"ftplib", "http.client", "requests", "socket", "urllib", "urllib.request"}
)
_PROCESS_MODULES = frozenset({"subprocess"})


def _json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _response(action, *, ok=True, **values):
    payload = {"agent": "Security", "action": action, "ok": ok}
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


def _contained(root, relative_text, *, file_only=False):
    if not isinstance(relative_text, str) or not relative_text:
        raise ValueError("relative path is required")
    relative = Path(relative_text)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("relative path is invalid")
    current = root
    for part in relative.parts:
        if part == ".":
            continue
        current = current / part
        if current.is_symlink():
            raise ValueError("symbolic links are not allowed")
    resolved = current.resolve(strict=True)
    if resolved != root and root not in resolved.parents:
        raise ValueError("path escapes the explicit root")
    if file_only and not resolved.is_file():
        raise ValueError("path must be a file")
    if not file_only and not resolved.is_dir():
        raise ValueError("path must be a directory")
    return resolved


def _read_json(root, relative):
    path = _contained(root, relative, file_only=True)
    if path.stat().st_size > _MAX_POLICY_BYTES:
        raise ValueError("document exceeds read bound")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("document must contain an object")
    return value


def _call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _python_rules(text):
    findings = set()
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return {"invalid_python"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            modules = [node.module or ""]
        else:
            modules = []
        for module in modules:
            if module in _PROCESS_MODULES:
                findings.add("process_import")
            if module in _NETWORK_MODULES or module.split(".", 1)[0] in {
                "ftplib",
                "requests",
                "socket",
                "urllib",
            }:
                findings.add("network_import")
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            if name in {"eval", "exec", "os.system", "subprocess.Popen"}:
                findings.add("dynamic_or_process_call")
    return findings


def _stop_scan(state, reason):
    if state["truncation_reason"] is None:
        state["truncation_reason"] = reason


def _iter_scan_paths(directory, state):
    stack = [("directory", directory, 0)]
    while stack:
        kind, path, depth = stack.pop()
        if kind == "directory":
            if state["directory_count"] >= _MAX_SCAN_DIRECTORIES:
                state["rejected_count"] += 1
                yield path, "directory_count_bound", depth
                _stop_scan(state, "directory_limit")
                return
            state["directory_count"] += 1
            state["maximum_depth"] = max(state["maximum_depth"], depth)
            names = []
            try:
                with os.scandir(path) as handle:
                    iterator = iter(handle)
                    while True:
                        if state["entry_count"] >= _MAX_SCAN_ENTRIES:
                            _stop_scan(state, "entry_limit")
                            stack.clear()
                            break
                        try:
                            entry = next(iterator)
                        except StopIteration:
                            break
                        state["entry_count"] += 1
                        names.append(entry.name)
            except OSError:
                state["rejected_count"] += 1
                yield path, "directory_read_error", depth
                continue
            for name in sorted(names, reverse=True):
                stack.append(("entry", path / name, depth + 1))
            continue

        try:
            details = os.stat(path, follow_symlinks=False)
        except OSError:
            state["rejected_count"] += 1
            yield path, "entry_stat_error", depth
            continue
        mode = details.st_mode
        if stat.S_ISLNK(mode):
            state["rejected_count"] += 1
            yield path, "symbolic_link", depth
        elif stat.S_ISDIR(mode):
            if depth > _MAX_SCAN_DEPTH:
                state["rejected_count"] += 1
                yield path, "depth_bound", depth
                _stop_scan(state, "depth_limit")
                return
            stack.append(("directory", path, depth))
        elif stat.S_ISREG(mode):
            yield path, "regular_file", depth
        else:
            state["rejected_count"] += 1
            yield path, "nonregular_entry", depth


def _read_scan_file(path, maximum_bytes, include_content):
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return "file_read_error", None, 0
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode):
            return "nonregular_entry", None, 0
        if details.st_size > _MAX_SCAN_FILE_BYTES:
            return "file_size_bound", None, 0
        if details.st_size > maximum_bytes:
            return "total_byte_bound", None, 0
        if not include_content:
            return None, None, details.st_size

        limit = min(_MAX_SCAN_FILE_BYTES, maximum_bytes)
        chunks = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > limit:
            rule = (
                "file_size_bound"
                if _MAX_SCAN_FILE_BYTES <= maximum_bytes
                else "total_byte_bound"
            )
            return rule, None, 0
        return None, raw, len(raw)
    except OSError:
        return "file_read_error", None, 0
    finally:
        os.close(descriptor)


class Security(BasicAgent):
    """Report only paths and rule identifiers, never matched content."""

    name = "Security"
    metadata = {
        "name": "Security",
        "description": "Inspect security boundaries and run a redacted hard-bounded scan.",
        "parameters": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": [
                        "boundary",
                        "provenance",
                        "unresolved",
                        "scan",
                        "verify",
                    ],
                },
                "subtree": {"type": "string", "maxLength": 240},
                "max_files": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
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
            root = _root()
            if action == "boundary":
                return self._boundary(root)
            if action == "provenance":
                return self._provenance(root)
            if action == "unresolved":
                return self._unresolved(root)
            if action == "scan":
                return self._scan(root, kwargs)
            return self._verify(root)
        except Exception:
            return _response(
                action,
                ok=False,
                error={
                    "code": "invalid_or_unavailable",
                    "message": "The contained security operation could not be completed.",
                },
            )

    def _boundary(self, root):
        path = _contained(root, _POLICY, file_only=True)
        if path.stat().st_size > _MAX_POLICY_BYTES:
            raise ValueError("policy exceeds read bound")
        text = path.read_text(encoding="utf-8")
        headings = [
            line[3:].strip()
            for line in text.splitlines()
            if line.startswith("## ")
        ]
        return _response(
            "boundary",
            policy_path=_POLICY,
            policy_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            default_deny=True,
            section_count=len(headings),
            sections=headings[:20],
            private_runtime_state_outside_publication=True,
        )

    def _provenance(self, root):
        provenance = _read_json(root, _PROVENANCE)
        entries = []
        for item in provenance.get("entries", []):
            if not isinstance(item, dict):
                continue
            entries.append(
                {
                    "id": item.get("id"),
                    "inclusion_state": item.get("inclusion_state"),
                    "commit": item.get("commit"),
                    "cleared_file_count": len(item.get("cleared_files", [])),
                    "copied_file_count": len(item.get("copied_files", [])),
                }
            )
        return _response(
            "provenance",
            schema=provenance.get("schema"),
            counts=provenance.get("counts", {}),
            entries=entries[:50],
            truncated=len(entries) > 50,
            release_rule=provenance.get("release_rule"),
        )

    def _unresolved(self, root):
        lock = _read_json(root, _LOCK)
        records = [
            {
                "id": item.get("id"),
                "build_blocking": item.get("build_blocking") is True,
                "status": item.get("status"),
            }
            for item in lock.get("unresolved", [])
            if isinstance(item, dict)
        ]
        return _response(
            "unresolved",
            build_blocked=lock.get("lock_status", {}).get("build_blocked")
            is True,
            count=len(records),
            unresolved=records,
        )

    def _scan(self, root, kwargs):
        subtree = _contained(root, kwargs.get("subtree", ""))
        max_files = kwargs.get("max_files", 200)
        if (
            isinstance(max_files, bool)
            or not isinstance(max_files, int)
            or not 1 <= max_files <= _MAX_SCAN_FILES
        ):
            raise ValueError("max_files is invalid")
        findings = set()
        scanned = 0
        total_bytes = 0
        state = {
            "directory_count": 0,
            "entry_count": 0,
            "maximum_depth": 0,
            "rejected_count": 0,
            "truncation_reason": None,
        }
        for path, entry_kind, depth in _iter_scan_paths(subtree, state):
            relative = path.relative_to(root).as_posix()
            if entry_kind != "regular_file":
                findings.add((relative, entry_kind))
                continue
            if scanned >= max_files:
                state["rejected_count"] += 1
                findings.add((relative, "file_count_bound"))
                _stop_scan(state, "file_limit")
                break
            scanned += 1
            state["maximum_depth"] = max(state["maximum_depth"], depth)
            lower_name = path.name.casefold()
            if path.name in _FORBIDDEN_NAMES or lower_name.startswith(".env."):
                findings.add((relative, "forbidden_file_name"))
            if lower_name.endswith(_PRIVATE_SUFFIXES):
                findings.add((relative, "private_file_suffix"))
            is_text = path.suffix.casefold() in _TEXT_SUFFIXES
            rule, raw, consumed = _read_scan_file(
                path,
                _MAX_SCAN_TOTAL_BYTES - total_bytes,
                is_text,
            )
            if rule is not None:
                findings.add((relative, rule))
                state["rejected_count"] += 1
                if rule == "total_byte_bound":
                    _stop_scan(state, "byte_limit")
                    break
                continue
            total_bytes += consumed
            if raw is None:
                continue
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                findings.add((relative, "invalid_utf8"))
                continue
            marker = "BEGIN" + " PRIVATE KEY"
            if _SECRET_ASSIGNMENT.search(text):
                findings.add((relative, "secret_assignment"))
            if _SECRET_SHAPE.search(text):
                findings.add((relative, "secret_shape"))
            if marker in text.upper():
                findings.add((relative, "private_key_block"))
            if _LOCAL_PATH.search(text):
                findings.add((relative, "absolute_local_path"))
            if _PHONE_SHAPE.search(text):
                findings.add((relative, "phone_number_shape"))
            if path.suffix.casefold() == ".py":
                for rule in _python_rules(text):
                    findings.add((relative, rule))
        rendered = [
            {"file": file_name, "rule": rule}
            for file_name, rule in sorted(findings)
        ]
        return _response(
            "scan",
            clean=not rendered,
            finding_count=len(rendered),
            findings=rendered[:200],
            findings_truncated=len(rendered) > 200,
            scan_truncated=state["truncation_reason"] is not None,
            truncation_reason=state["truncation_reason"],
            encountered_entry_count=state["entry_count"],
            scanned_directory_count=state["directory_count"],
            scanned_file_count=scanned,
            scanned_byte_count=total_bytes,
            rejected_entry_count=state["rejected_count"],
            maximum_depth_scanned=state["maximum_depth"],
            scan_limits={
                "bytes": _MAX_SCAN_TOTAL_BYTES,
                "depth": _MAX_SCAN_DEPTH,
                "directories": _MAX_SCAN_DIRECTORIES,
                "entries": _MAX_SCAN_ENTRIES,
                "files": max_files,
                "file_bytes": _MAX_SCAN_FILE_BYTES,
            },
            values_redacted=True,
            network_used=False,
        )

    def _verify(self, root):
        lock = _read_json(root, _LOCK)
        provenance = _read_json(root, _PROVENANCE)
        catalog = _read_json(root, _CATALOG)
        matrix = _read_json(root, _MATRIX)
        checks = {
            "lock_schema": lock.get("schema") == "rapp-stack-lock/1.0",
            "build_remains_blocked": lock.get("lock_status", {}).get(
                "build_blocked"
            )
            is True,
            "provenance_schema": provenance.get("schema")
            == "rapp-provenance/1.0",
            "adapted_files_attributed": (
                provenance.get("counts", {}).get("copied_file_count") == 6
                and provenance.get("counts", {}).get("cleared_file_count") == 6
            ),
            "catalog_schema": catalog.get("schema")
            == "rapp-local-agent-catalog/1.0",
            "catalog_agent_count": catalog.get("agent_count") == 12,
            "matrix_schema": matrix.get("schema")
            == "rapp-implementation-matrix/1.0",
            "selected_capabilities_mapped": matrix.get("aggregates", {}).get(
                "selected_unmapped_count"
            )
            == 0,
        }
        return _response(
            "verify",
            passed=all(checks.values()),
            checks=checks,
            execution_performed=False,
        )
