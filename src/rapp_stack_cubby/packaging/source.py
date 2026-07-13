"""Strict deterministic source-tree manifests without commit self-reference."""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import math
import os
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath
from typing import Iterable

from .common import (
    CANONICAL_REPOSITORY_URL,
    PackagingError,
    atomic_write,
    canonical_json_bytes,
    mode_text,
    pretty_json_bytes,
    read_json_object,
    sha256_file,
    validate_relative_path,
)

RELEASE_SOURCE_MANIFEST = "rapp-release-source-manifest.json"
SOURCE_MANIFEST_SCHEMA = "rapp-release-source-manifest/1.0"
SOURCE_TREE_SCHEMA = "rapp-source-tree/1.0"

MAX_SOURCE_FILES = 20_000
MAX_SOURCE_BYTES = 512 * 1024 * 1024
MAX_SOURCE_FILE_BYTES = 32 * 1024 * 1024

_SKIPPED_TOP_LEVEL = frozenset(
    {
        ".check-cache",
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".rapp-stack-cubby",
        ".ruff_cache",
        ".venv",
        "build",
        "dist",
        "loadout",
        "locks",
        "receipts",
        "runtime",
        "sessions",
        "staging",
        "state",
        "twins",
        "venv",
    }
)
_SKIPPED_COMPONENTS = frozenset(
    {
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "node_modules",
    }
)
_FORBIDDEN_NAMES = frozenset(
    {
        ".DS_Store",
        ".copilot_token",
        ".env",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "credentials.json",
        "credentials",
        "copilot-token.json",
        "id_ed25519",
        "id_ecdsa",
        "id_rsa",
        "service-account.json",
        "provider-token.json",
        "secrets.json",
    }
)
_FORBIDDEN_SUFFIXES = (
    ".db",
    ".egg",
    ".journal",
    ".key",
    ".log",
    ".p12",
    ".pem",
    ".pfx",
    ".pid",
    ".pyc",
    ".pyo",
    ".sqlite",
    ".sqlite3",
    ".sqlite-shm",
    ".sqlite-wal",
    ".whl",
    ".zip",
)
_TEXT_SUFFIXES = frozenset(
    {
        "",
        ".cfg",
        ".css",
        ".html",
        ".ini",
        ".json",
        ".lock",
        ".map",
        ".md",
        ".py",
        ".rst",
        ".sh",
        ".svg",
        ".toml",
        ".txt",
        ".xml",
        ".yaml",
        ".yml",
    }
)
_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?im)^[ \t]*(?:(?:api[_-]?key|access[_-]?key|auth[_-]?token|"
    r"client[_-]?secret|password|private[_-]?key|secret|token)[ \t]*="
    r"|[\"'](?:api[_-]?key|access[_-]?key|auth[_-]?token|client[_-]?secret|"
    r"password|private[_-]?key|secret|token)[\"'][ \t]*:)"
    r"[ \t]*[\"']?([A-Za-z0-9_./+=:-]{8,})"
    r"[\"']?[ \t]*[,;]?[ \t]*$"
)
_PRIVATE_KEY_RE = re.compile(
    rb"-----BEGIN (?:EC |RSA |OPENSSH )?PRIVATE KEY-----"
    rb"[\r\n]+[A-Za-z0-9+/=\r\n]{48,}"
    rb"-----END (?:EC |RSA |OPENSSH )?PRIVATE KEY-----",
    re.DOTALL,
)
_TOKEN_RE = re.compile(
    rb"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    rb"AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|"
    rb"xox[baprs]-[0-9A-Za-z-]{20,})"
)
_BASE64_RE = re.compile(rb"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{64,}={0,2}")
_PLACEHOLDERS = (
    "example",
    "fake",
    "not_set",
    "not-set",
    "placeholder",
    "redacted",
    "synthetic",
    "supersecret",
    "unset",
)
MAX_ARCHIVE_DEPTH = 4
MAX_SECRET_SCAN_EXPANDED_BYTES = 128 * 1024 * 1024


def _is_skipped(relative: PurePosixPath) -> bool:
    if not relative.parts:
        return False
    if relative.parts[0] in _SKIPPED_TOP_LEVEL:
        return True
    if any(part.casefold().endswith(".egg-info") for part in relative.parts):
        return True
    return any(part in _SKIPPED_COMPONENTS for part in relative.parts)


def _validate_name(relative: PurePosixPath) -> None:
    for part in relative.parts:
        if part in _FORBIDDEN_NAMES or part.casefold() in {
            name.casefold() for name in _FORBIDDEN_NAMES
        }:
            raise PackagingError(f"forbidden source name: {relative.as_posix()}")
    lowered = relative.name.casefold()
    if any(lowered.endswith(suffix) for suffix in _FORBIDDEN_SUFFIXES):
        raise PackagingError(f"forbidden source type: {relative.as_posix()}")


def _text_content(content: bytes) -> str | None:
    if content.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return content.decode("utf-16")
        except UnicodeError:
            return None
    if b"\x00" in content:
        for encoding in ("utf-16-le", "utf-16-be"):
            try:
                value = content.decode(encoding)
            except UnicodeError:
                continue
            if value and sum(character.isprintable() or character.isspace() for character in value) / len(value) > 0.9:
                return value
        return None
    try:
        return content.decode("utf-8")
    except UnicodeError:
        return None


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    return -sum(
        (count / len(value)) * math.log2(count / len(value))
        for count in (value.count(character) for character in set(value))
    )


def _scan_secret_bytes(
    content: bytes,
    label: str,
    *,
    depth: int = 0,
    budget: list[int],
) -> None:
    budget[0] += len(content)
    if budget[0] > MAX_SECRET_SCAN_EXPANDED_BYTES:
        raise PackagingError("secret scan exceeds expanded-byte limit")
    if _PRIVATE_KEY_RE.search(content) or _TOKEN_RE.search(content):
        raise PackagingError(f"possible embedded credential in {label}")
    text = _text_content(content)
    if text is not None:
        encoded = text.encode("utf-8", "ignore")
        if _PRIVATE_KEY_RE.search(encoded) or _TOKEN_RE.search(encoded):
            raise PackagingError(f"possible embedded credential in {label}")
        for match in _SENSITIVE_ASSIGNMENT_RE.finditer(text):
            value = match.group(1)
            lowered = value.casefold()
            if lowered.startswith(("self.", "cls.", "args.", "config.")):
                continue
            if "supersecret" in lowered or lowered in _PLACEHOLDERS or lowered.startswith(
                tuple(marker + "-" for marker in _PLACEHOLDERS)
            ):
                continue
            if len(value) >= 8 and (
                len(value) < 24 or _entropy(value) >= 3.0
            ):
                raise PackagingError(f"possible embedded secret in {label}")
        for match in _BASE64_RE.finditer(encoded):
            candidate = match.group(0)
            try:
                decoded = base64.b64decode(candidate, validate=True)
            except (binascii.Error, ValueError):
                continue
            if _PRIVATE_KEY_RE.search(decoded) or _TOKEN_RE.search(decoded):
                raise PackagingError(
                    f"base64-encoded credential material in {label}"
                )
    if depth >= MAX_ARCHIVE_DEPTH:
        return
    try:
        possible_zip = zipfile.is_zipfile(io.BytesIO(content))
    except (OSError, ValueError):
        possible_zip = False
    if not possible_zip:
        return
    try:
        with zipfile.ZipFile(io.BytesIO(content), "r") as archive:
            infos = archive.infolist()
            if len(infos) > 2_000:
                raise PackagingError("nested source archive has too many members")
            seen: set[str] = set()
            for info in infos:
                raw_name = info.filename[:-1] if info.is_dir() else info.filename
                name = validate_relative_path(raw_name)
                if name in seen or info.is_dir():
                    if name in seen:
                        raise PackagingError("duplicate nested archive member")
                    seen.add(name)
                    continue
                seen.add(name)
                if info.file_size > MAX_SOURCE_FILE_BYTES:
                    raise PackagingError("nested source archive member is too large")
                _scan_secret_bytes(
                    archive.read(info),
                    f"{label}!/{name}",
                    depth=depth + 1,
                    budget=budget,
                )
    except (zipfile.BadZipFile, RuntimeError, OSError) as error:
        if isinstance(error, PackagingError):
            raise
        raise PackagingError(f"invalid nested source archive: {label}") from error


def _validate_content(
    path: Path,
    relative: PurePosixPath,
    size: int,
    *,
    secret_budget: list[int],
) -> None:
    try:
        content = path.read_bytes()
    except OSError as error:
        raise PackagingError(f"cannot read {relative.as_posix()}") from error
    if len(content) != size:
        raise PackagingError(f"{relative.as_posix()} changed while scanning")
    text = _text_content(content)
    if path.suffix.casefold() in _TEXT_SUFFIXES and text is None:
        raise PackagingError(f"invalid source text: {relative.as_posix()}")
    _scan_secret_bytes(
        content,
        relative.as_posix(),
        budget=secret_budget,
    )


def _tree_digest(files: list[dict]) -> str:
    value = {"files": files, "schema": SOURCE_TREE_SCHEMA}
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def scan_source_tree(
    root: str | Path,
    *,
    excluded_paths: Iterable[str] = (RELEASE_SOURCE_MANIFEST,),
    maximum_files: int = MAX_SOURCE_FILES,
    maximum_bytes: int = MAX_SOURCE_BYTES,
    maximum_file_bytes: int = MAX_SOURCE_FILE_BYTES,
) -> dict:
    """Scan all product source using stable paths, hashes, and modes."""

    base = Path(root)
    try:
        base_info = base.lstat()
        base = base.resolve(strict=True)
    except OSError as error:
        raise PackagingError("source root is unavailable") from error
    if not stat.S_ISDIR(base_info.st_mode) or stat.S_ISLNK(base_info.st_mode):
        raise PackagingError("source root must be a regular directory")
    excluded = {
        validate_relative_path(str(value)) for value in excluded_paths
    }
    records: list[dict] = []
    total_bytes = 0
    secret_budget = [0]

    def walk(directory: Path, prefix: PurePosixPath | None) -> None:
        nonlocal total_bytes
        try:
            entries = sorted(
                os.scandir(directory),
                key=lambda item: item.name.encode("utf-8"),
            )
        except (OSError, UnicodeError) as error:
            raise PackagingError("cannot enumerate source tree") from error
        for entry in entries:
            relative = (
                PurePosixPath(entry.name)
                if prefix is None
                else prefix / entry.name
            )
            text = validate_relative_path(relative.as_posix())
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise PackagingError(f"cannot inspect {text}") from error
            if stat.S_ISLNK(info.st_mode):
                raise PackagingError(f"symbolic link in source: {text}")
            if _is_skipped(relative):
                if not stat.S_ISDIR(info.st_mode):
                    raise PackagingError(
                        f"reserved source path is not a directory: {text}"
                    )
                continue
            _validate_name(relative)
            if stat.S_ISDIR(info.st_mode):
                walk(Path(entry.path), relative)
                continue
            if not stat.S_ISREG(info.st_mode):
                raise PackagingError(f"special file in source: {text}")
            if text in excluded:
                continue
            if info.st_size > maximum_file_bytes:
                raise PackagingError(f"source file is too large: {text}")
            total_bytes += info.st_size
            if len(records) + 1 > maximum_files or total_bytes > maximum_bytes:
                raise PackagingError("source tree exceeds resource limits")
            path = Path(entry.path)
            _validate_content(
                path,
                relative,
                info.st_size,
                secret_budget=secret_budget,
            )
            digest, size = sha256_file(path, limit=maximum_file_bytes)
            mode = mode_text(info.st_mode)
            records.append(
                {
                    "executable": mode == "0755",
                    "mode": mode,
                    "path": text,
                    "sha256": digest,
                    "size": size,
                }
            )

    walk(base, None)
    records.sort(key=lambda item: item["path"].encode("utf-8"))
    return {
        "file_count": len(records),
        "files": records,
        "schema": SOURCE_TREE_SCHEMA,
        "secret_scan": {
            "expanded_bytes": secret_budget[0],
            "passed": True,
            "profile": "rapp-source-secret-scan/1.0",
        },
        "source_tree_digest": _tree_digest(records),
        "total_bytes": total_bytes,
    }


def build_source_manifest(root: str | Path) -> dict:
    """Build the self-excluding committed source manifest."""

    scan = scan_source_tree(root)
    return {
        "exclusions": {
            "generated_release_assets": True,
            "manifest_self": RELEASE_SOURCE_MANIFEST,
            "private_and_runtime_state": True,
            "repository_metadata_and_caches": True,
        },
        "file_count": scan["file_count"],
        "files": scan["files"],
        "repository_url": CANONICAL_REPOSITORY_URL,
        "schema": SOURCE_MANIFEST_SCHEMA,
        "source_tree_digest": scan["source_tree_digest"],
        "total_bytes": scan["total_bytes"],
    }


def write_source_manifest(
    root: str | Path,
    output: str | Path | None = None,
) -> dict:
    """Write the canonical source manifest and immediately revalidate it."""

    repository = Path(root).resolve()
    destination = (
        Path(output).resolve()
        if output is not None
        else repository / RELEASE_SOURCE_MANIFEST
    )
    if destination != repository / RELEASE_SOURCE_MANIFEST:
        raise PackagingError("source manifest must use its canonical root path")
    manifest = build_source_manifest(repository)
    atomic_write(destination, pretty_json_bytes(manifest))
    validate_source_manifest(repository)
    return manifest


def validate_source_manifest(root: str | Path) -> dict:
    """Verify that the committed manifest exactly describes the source tree."""

    repository = Path(root).resolve()
    path = repository / RELEASE_SOURCE_MANIFEST
    manifest = read_json_object(path, maximum_bytes=64 * 1024 * 1024)
    expected_keys = {
        "exclusions",
        "file_count",
        "files",
        "repository_url",
        "schema",
        "source_tree_digest",
        "total_bytes",
    }
    if set(manifest) != expected_keys:
        raise PackagingError("source manifest fields are invalid")
    if (
        manifest["schema"] != SOURCE_MANIFEST_SCHEMA
        or manifest["repository_url"] != CANONICAL_REPOSITORY_URL
        or "commit" in manifest
        or "source_commit" in manifest
    ):
        raise PackagingError("source manifest identity is invalid")
    actual = build_source_manifest(repository)
    if manifest != actual:
        raise PackagingError("source manifest is stale or does not match source")
    digest, size = sha256_file(path)
    return {
        "file_count": actual["file_count"],
        "manifest_sha256": digest,
        "manifest_size": size,
        "source_tree_digest": actual["source_tree_digest"],
        "total_bytes": actual["total_bytes"],
    }
