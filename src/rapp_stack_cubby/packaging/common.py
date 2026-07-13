"""Shared strict primitives for package builders and verifiers."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import unicodedata
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

from ..errors import RappStackCubbyError

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
CANONICAL_REPOSITORY_URL = (
    "https://github.com/kody-w/rapp-stack-cubby.git"
)
BUFFER_SIZE = 128 * 1024


class PackagingError(RappStackCubbyError, ValueError):
    """Raised when package input or output violates a product contract."""


def canonical_json_bytes(value: Any) -> bytes:
    """Encode the project's canonical JSON subset."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise PackagingError("value is not canonical JSON") from error


def pretty_json_bytes(value: Any) -> bytes:
    """Encode stable human-readable JSON with one trailing LF."""

    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    except (TypeError, ValueError, UnicodeError) as error:
        raise PackagingError("value is not valid JSON") from error
    return (rendered + "\n").encode("utf-8")


def read_json_object(path: Path, *, maximum_bytes: int = 4 * 1024 * 1024) -> dict:
    """Read one bounded, duplicate-key-free UTF-8 JSON object."""

    try:
        raw = path.read_bytes()
    except OSError as error:
        raise PackagingError(f"cannot read {path.name}") from error
    if not raw or len(raw) > maximum_bytes:
        raise PackagingError(f"{path.name} has an invalid size")

    def pairs(values: list[tuple[str, Any]]) -> dict:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise PackagingError(f"{path.name} contains a duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise PackagingError(f"{path.name} is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise PackagingError(f"{path.name} must contain a JSON object")
    return value


def validate_relative_path(value: str, *, maximum_bytes: int = 1024) -> str:
    """Return a canonical safe UTF-8 POSIX relative file path."""

    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or "\\" in value
        or unicodedata.normalize("NFC", value) != value
        or len(value.encode("utf-8")) > maximum_bytes
    ):
        raise PackagingError("unsafe relative path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value.startswith("/")
        or value.endswith("/")
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != value
        or re.match(r"^[A-Za-z]:", value)
    ):
        raise PackagingError(f"unsafe relative path: {value!r}")
    return value


def normalized_mode(mode: int) -> int:
    """Reduce a source mode to the two supported deterministic file modes."""

    return 0o755 if mode & 0o111 else 0o644


def mode_text(mode: int) -> str:
    """Render a supported normalized mode."""

    normalized = normalized_mode(mode)
    return "0755" if normalized == 0o755 else "0644"


def exact_mode_text(mode: int) -> str:
    """Render exact permission bits without erasing writable-bit changes."""

    return f"{stat.S_IMODE(mode):04o}"


def parse_mode(value: object) -> int:
    """Parse and validate a normalized manifest mode."""

    if value == "0644" or value == 0o644:
        return 0o644
    if value == "0755" or value == 0o755:
        return 0o755
    raise PackagingError("manifest mode must be 0644 or 0755")


def hash_stream(stream: BinaryIO, *, limit: int | None = None) -> tuple[str, int]:
    """Hash a stream while enforcing an optional byte limit."""

    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = stream.read(BUFFER_SIZE)
        if not chunk:
            break
        total += len(chunk)
        if limit is not None and total > limit:
            raise PackagingError("input exceeds its byte limit")
        digest.update(chunk)
    return digest.hexdigest(), total


def sha256_file(path: Path, *, limit: int | None = None) -> tuple[str, int]:
    """Hash one regular non-link file without following links."""

    try:
        info = path.lstat()
    except OSError as error:
        raise PackagingError(f"cannot inspect {path.name}") from error
    if not stat.S_ISREG(info.st_mode):
        raise PackagingError(f"{path.name} is not a regular file")
    try:
        with path.open("rb") as source:
            digest, size = hash_stream(source, limit=limit)
    except OSError as error:
        raise PackagingError(f"cannot read {path.name}") from error
    if size != info.st_size:
        raise PackagingError(f"{path.name} changed while being read")
    return digest, size


def open_regular_nofollow(path: Path) -> tuple[int, os.stat_result]:
    """Open one regular file without following its final symbolic link."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise PackagingError(f"{path.name} is not a regular file")
        return descriptor, info
    except Exception:
        if "descriptor" in locals():
            os.close(descriptor)
        raise


def copy_verified_file(
    source: Path,
    destination: Path,
    *,
    expected_sha256: str,
    expected_size: int,
    mode: int,
    expected_source_mode: int | None = None,
    limit: int | None = None,
) -> tuple[str, int]:
    """Hash and copy bytes through one source descriptor, then rehash output."""

    if destination.exists() or destination.is_symlink():
        raise PackagingError(f"staging collision: {destination.name}")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    source_descriptor, source_info = open_regular_nofollow(source)
    temporary = destination.with_name(
        f".{destination.name}.copy-{os.getpid()}-{os.urandom(8).hex()}"
    )
    try:
        if source_info.st_size != expected_size:
            raise PackagingError(f"{source.name} size does not match its record")
        if (
            expected_source_mode is not None
            and normalized_mode(source_info.st_mode)
            != normalized_mode(expected_source_mode)
        ):
            raise PackagingError(f"{source.name} mode does not match its record")
        output_descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            mode,
        )
        digest = hashlib.sha256()
        count = 0
        with os.fdopen(source_descriptor, "rb", closefd=True) as input_, os.fdopen(
            output_descriptor, "wb", closefd=True
        ) as output:
            source_descriptor = -1
            while True:
                chunk = input_.read(BUFFER_SIZE)
                if not chunk:
                    break
                count += len(chunk)
                if (limit is not None and count > limit) or count > expected_size:
                    raise PackagingError(f"{source.name} exceeds its record")
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        if count != expected_size or digest.hexdigest() != expected_sha256:
            raise PackagingError(f"{source.name} changed or does not match its record")
        os.chmod(temporary, mode)
        output_digest, output_size = sha256_file(temporary, limit=limit)
        if output_digest != expected_sha256 or output_size != expected_size:
            raise PackagingError(f"staged {source.name} does not match its record")
        os.replace(temporary, destination)
        return output_digest, output_size
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    finally:
        if source_descriptor >= 0:
            os.close(source_descriptor)


def atomic_write(path: Path, content: bytes, *, mode: int = 0o644) -> None:
    """Write bytes beside their destination and atomically replace it."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.new-{os.getpid()}")
    if temporary.exists() or temporary.is_symlink():
        raise PackagingError("atomic output path collision")
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            mode,
        )
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(content)
            destination.flush()
            os.fsync(destination.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except OSError as error:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise PackagingError(f"cannot write {path.name}") from error
