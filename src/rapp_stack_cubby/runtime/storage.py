"""Contained, atomic local storage for isolated runtime instances."""

from __future__ import annotations

import contextlib
import json
import os
import re
import tempfile
import threading
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

try:
    import fcntl
except ImportError:  # pragma: no cover - Python 3.11 target platforms provide it.
    fcntl = None

DEFAULT_MAX_FILE_BYTES: Final = 8 * 1024 * 1024
_PRINCIPAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$")
_MISSING = object()
_LOCKS_GUARD = threading.Lock()
_ROOT_LOCKS: dict[str, threading.RLock] = {}


class StorageError(Exception):
    """Base class for local storage failures."""


class StoragePathError(StorageError, ValueError):
    """Raised when a requested path is outside the configured data root."""


class StorageDecodeError(StorageError, ValueError):
    """Raised when stored JSON is invalid."""


class StorageSizeError(StorageError, ValueError):
    """Raised when an operation exceeds the configured storage bound."""


class StorageSerializationError(StorageError, TypeError):
    """Raised when a value cannot be represented as JSON."""


class LocalStorage:
    """A per-instance data root with contained and atomic operations."""

    def __init__(
        self,
        data_root: str | os.PathLike[str],
        *,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    ) -> None:
        if not isinstance(max_file_bytes, int) or isinstance(max_file_bytes, bool):
            raise StorageSizeError("max_file_bytes must be an integer")
        if max_file_bytes < 1:
            raise StorageSizeError("max_file_bytes must be positive")

        supplied_root = Path(data_root)
        if supplied_root.is_symlink():
            raise StoragePathError("data root must not be a symbolic link")
        try:
            supplied_root.mkdir(mode=0o700, parents=True, exist_ok=True)
            root = supplied_root.resolve(strict=True)
        except OSError as error:
            raise StorageError("data root cannot be prepared") from error
        if not root.is_dir():
            raise StoragePathError("data root must be a directory")
        try:
            os.chmod(root, 0o700)
        except OSError as error:
            raise StorageError("data root permissions cannot be secured") from error

        self._root = root
        self._max_file_bytes = max_file_bytes
        lock_key = os.path.normcase(str(root))
        with _LOCKS_GUARD:
            self._thread_lock = _ROOT_LOCKS.setdefault(
                lock_key, threading.RLock()
            )
        self._lock_path = root / ".storage.lock"

    @property
    def data_root(self) -> Path:
        """Return the explicitly configured root."""

        return self._root

    @property
    def max_file_bytes(self) -> int:
        return self._max_file_bytes

    def resolve(self, relative_path: str | os.PathLike[str]) -> Path:
        """Resolve a relative path while rejecting traversal and symlinks."""

        relative = _validate_relative_path(relative_path)
        candidate = self._root.joinpath(*relative.parts)
        current = self._root
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise StoragePathError("symbolic links are not permitted in storage")

        resolved = candidate.resolve(strict=False)
        if resolved == self._root or self._root not in resolved.parents:
            raise StoragePathError("path escapes the configured data root")
        return resolved

    def read_text(
        self,
        relative_path: str | os.PathLike[str],
        *,
        encoding: str = "utf-8",
    ) -> str:
        path = self.resolve(relative_path)
        with self._locked():
            self._check_readable_file(path)
            try:
                size = path.stat().st_size
                if size > self._max_file_bytes:
                    raise StorageSizeError("stored file exceeds the read limit")
                return path.read_text(encoding=encoding)
            except UnicodeError as error:
                raise StorageDecodeError("stored text is not valid UTF-8") from error
            except OSError as error:
                raise StorageError("stored text cannot be read") from error

    def write_text(
        self,
        relative_path: str | os.PathLike[str],
        content: str,
        *,
        encoding: str = "utf-8",
    ) -> None:
        if not isinstance(content, str):
            raise TypeError("text content must be a string")
        try:
            payload = content.encode(encoding)
        except UnicodeError as error:
            raise StorageDecodeError("text content cannot be encoded") from error
        self.write_bytes(relative_path, payload)

    def read_bytes(self, relative_path: str | os.PathLike[str]) -> bytes:
        path = self.resolve(relative_path)
        with self._locked():
            self._check_readable_file(path)
            try:
                size = path.stat().st_size
                if size > self._max_file_bytes:
                    raise StorageSizeError("stored file exceeds the read limit")
                return path.read_bytes()
            except OSError as error:
                raise StorageError("stored file cannot be read") from error

    def write_bytes(
        self,
        relative_path: str | os.PathLike[str],
        content: bytes | bytearray | memoryview,
    ) -> None:
        if not isinstance(content, (bytes, bytearray, memoryview)):
            raise TypeError("file content must be bytes-like")
        payload = bytes(content)
        if len(payload) > self._max_file_bytes:
            raise StorageSizeError("file content exceeds the write limit")
        path = self.resolve(relative_path)
        with self._locked():
            self._ensure_parent(path)
            self._atomic_write(path, payload)

    def read_json(
        self,
        relative_path: str | os.PathLike[str],
        *,
        default: Any = _MISSING,
    ) -> Any:
        try:
            raw = self.read_text(relative_path)
        except FileNotFoundError:
            if default is _MISSING:
                raise
            return default
        try:
            return json.loads(raw)
        except json.JSONDecodeError as error:
            raise StorageDecodeError(
                f"stored JSON is invalid at line {error.lineno}, "
                f"column {error.colno}"
            ) from error

    def write_json(
        self,
        relative_path: str | os.PathLike[str],
        value: Any,
    ) -> None:
        try:
            raw = json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                indent=2,
                sort_keys=True,
            )
        except (TypeError, ValueError) as error:
            raise StorageSerializationError(
                "value must contain only finite JSON data"
            ) from error
        self.write_text(relative_path, raw + "\n")

    def read_file(
        self,
        relative_path: str | os.PathLike[str],
        *,
        binary: bool = False,
    ) -> str | bytes:
        """Read a contained file as UTF-8 text or bytes."""

        return (
            self.read_bytes(relative_path)
            if binary
            else self.read_text(relative_path)
        )

    def write_file(
        self,
        relative_path: str | os.PathLike[str],
        content: str | bytes | bytearray | memoryview,
    ) -> bool:
        """Atomically write text or bytes and report compatibility success."""

        if isinstance(content, str):
            self.write_text(relative_path, content)
        elif isinstance(content, (bytes, bytearray, memoryview)):
            self.write_bytes(relative_path, content)
        else:
            raise TypeError("file content must be text or bytes-like")
        return True

    def exists(self, relative_path: str | os.PathLike[str]) -> bool:
        path = self.resolve(relative_path)
        with self._locked():
            if path.is_symlink():
                return False
            return path.is_file()

    def delete(self, relative_path: str | os.PathLike[str]) -> bool:
        path = self.resolve(relative_path)
        with self._locked():
            if path.is_symlink():
                raise StoragePathError("symbolic links are not permitted in storage")
            if not path.exists():
                return False
            if not path.is_file():
                raise StoragePathError("only files may be deleted")
            try:
                path.unlink()
                self._sync_directory(path.parent)
            except OSError as error:
                raise StorageError("stored file cannot be deleted") from error
            return True

    file_exists = exists
    delete_file = delete

    def list_files(
        self, relative_directory: str | os.PathLike[str] | None = None
    ) -> tuple[str, ...]:
        directory = (
            self._root
            if relative_directory in (None, "")
            else self.resolve(relative_directory)
        )
        with self._locked():
            if directory.is_symlink():
                raise StoragePathError("symbolic links are not permitted in storage")
            if not directory.exists():
                return ()
            if not directory.is_dir():
                raise StoragePathError("list target must be a directory")
            try:
                names = [
                    entry.name
                    for entry in directory.iterdir()
                    if entry.name != ".storage.lock" and not entry.is_symlink()
                ]
            except OSError as error:
                raise StorageError("storage directory cannot be listed") from error
            return tuple(sorted(names))

    def shared_context(self) -> "MemoryContext":
        return MemoryContext(self, Path("shared_memories"))

    def principal_context(self, principal: str) -> "MemoryContext":
        validated = validate_principal(principal)
        return MemoryContext(self, Path("memory") / validated)

    def memory_context(self, principal: str | None = None) -> "MemoryContext":
        return (
            self.shared_context()
            if principal is None
            else self.principal_context(principal)
        )

    def _check_readable_file(self, path: Path) -> None:
        if path.is_symlink():
            raise StoragePathError("symbolic links are not permitted in storage")
        if not path.exists():
            raise FileNotFoundError("stored file does not exist")
        if not path.is_file():
            raise StoragePathError("storage path is not a file")

    def _ensure_parent(self, path: Path) -> None:
        relative_parent = path.parent.relative_to(self._root)
        current = self._root
        try:
            for part in relative_parent.parts:
                current = current / part
                if current.is_symlink():
                    raise StoragePathError(
                        "symbolic links are not permitted in storage"
                    )
                current.mkdir(mode=0o700, exist_ok=True)
                os.chmod(current, 0o700)
        except OSError as error:
            raise StorageError("storage directory cannot be prepared") from error

    def _atomic_write(self, path: Path, payload: bytes) -> None:
        temporary_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                prefix=f".{path.name}.",
                suffix=".pending",
                dir=path.parent,
                delete=False,
            ) as temporary:
                temporary_name = temporary.name
                os.fchmod(temporary.fileno(), 0o600)
                temporary.write(payload)
                temporary.flush()
                os.fsync(temporary.fileno())
            os.replace(temporary_name, path)
            temporary_name = None
            os.chmod(path, 0o600)
            self._sync_directory(path.parent)
        except OSError as error:
            raise StorageError("stored file cannot be written atomically") from error
        finally:
            if temporary_name is not None:
                with contextlib.suppress(OSError):
                    os.unlink(temporary_name)

    @staticmethod
    def _sync_directory(directory: Path) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        descriptor = os.open(directory, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        with self._thread_lock:
            flags = os.O_RDWR | os.O_CREAT
            flags |= getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(self._lock_path, flags, 0o600)
            except OSError as error:
                raise StorageError("storage lock cannot be opened") from error
            try:
                os.fchmod(descriptor, 0o600)
                if fcntl is not None:
                    fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)


@dataclass(frozen=True, slots=True)
class MemoryContext:
    """A namespace for shared or per-principal memory."""

    storage: LocalStorage
    prefix: Path

    def read_json(self, name: str = "memory.json", *, default: Any = _MISSING) -> Any:
        return self.storage.read_json(self._path(name), default=default)

    def write_json(self, value: Any, name: str = "memory.json") -> None:
        self.storage.write_json(self._path(name), value)

    def read_text(self, name: str) -> str:
        return self.storage.read_text(self._path(name))

    def write_text(self, name: str, value: str) -> None:
        self.storage.write_text(self._path(name), value)

    def read_bytes(self, name: str) -> bytes:
        return self.storage.read_bytes(self._path(name))

    def write_bytes(self, name: str, value: bytes) -> None:
        self.storage.write_bytes(self._path(name), value)

    def exists(self, name: str) -> bool:
        return self.storage.exists(self._path(name))

    def delete(self, name: str) -> bool:
        return self.storage.delete(self._path(name))

    def _path(self, name: str | os.PathLike[str]) -> Path:
        relative = _validate_relative_path(name)
        return self.prefix.joinpath(*relative.parts)


class AzureFileStorageManager:
    """Compatibility adapter backed only by an explicitly supplied LocalStorage."""

    DEFAULT_MARKER_GUID: Final = "c0p110t0-aaaa-bbbb-cccc-123456789abc"

    def __init__(
        self,
        share_name: str | None = None,
        *,
        data_root: str | os.PathLike[str] | None = None,
        storage: LocalStorage | None = None,
        **kwargs: Any,
    ) -> None:
        if kwargs:
            names = ", ".join(sorted(kwargs))
            raise TypeError(f"unsupported storage options: {names}")
        if storage is not None and data_root is not None:
            raise TypeError("provide storage or data_root, not both")
        if storage is None:
            if data_root is None:
                raise StorageError("an explicit data_root is required")
            storage = LocalStorage(data_root)
        if share_name is not None and (
            not isinstance(share_name, str) or not share_name.strip()
        ):
            raise StoragePathError("share_name must be a non-empty string")
        self.storage = storage
        self.share_name = share_name
        self.current_guid: str | None = None
        self.current_memory_path = "shared_memories"
        self.shared_memory_path = "shared_memories"
        self.default_file_name = "memory.json"

    def set_memory_context(self, user_guid: str | None = None) -> bool:
        if not user_guid or user_guid == self.DEFAULT_MARKER_GUID:
            self.current_guid = None
            self.current_memory_path = self.shared_memory_path
        else:
            self.current_guid = validate_principal(user_guid)
            self.current_memory_path = f"memory/{self.current_guid}"
        return True

    def read_json(self, file_path: str | None = None) -> Any:
        return self.storage.read_json(
            file_path or self._memory_file(),
            default={},
        )

    def write_json(self, data: Any, file_path: str | None = None) -> bool:
        self.storage.write_json(file_path or self._memory_file(), data)
        return True

    def read_file(self, file_path: str) -> str | None:
        try:
            return self.storage.read_text(file_path)
        except FileNotFoundError:
            return None

    def write_file(self, file_path: str, content: str) -> bool:
        self.storage.write_text(file_path, content)
        return True

    def list_files(self, directory: str = "") -> list[str]:
        return list(self.storage.list_files(directory))

    def delete_file(self, file_path: str) -> bool:
        return self.storage.delete(file_path)

    def file_exists(self, file_path: str) -> bool:
        try:
            return self.storage.exists(file_path)
        except StoragePathError:
            return False

    def _memory_file(self) -> str:
        if self.current_guid is None:
            return f"{self.shared_memory_path}/{self.default_file_name}"
        return f"memory/{self.current_guid}/user_memory.json"


def configured_storage_manager(
    storage: LocalStorage,
) -> type[AzureFileStorageManager]:
    """Create the audited import-shim class bound to one runtime data root."""

    class ConfiguredAzureFileStorageManager(AzureFileStorageManager):
        def __init__(self, share_name: str | None = None, **kwargs: Any) -> None:
            if "data_root" in kwargs or "storage" in kwargs:
                raise TypeError("the runtime controls the storage data root")
            super().__init__(share_name=share_name, storage=storage, **kwargs)

    ConfiguredAzureFileStorageManager.__name__ = "AzureFileStorageManager"
    ConfiguredAzureFileStorageManager.__qualname__ = "AzureFileStorageManager"
    return ConfiguredAzureFileStorageManager


def safe_json_loads(value: str | bytes, default: Any = None) -> Any:
    """Decode JSON for compatibility without accepting non-string input."""

    if not isinstance(value, (str, bytes)):
        raise TypeError("JSON input must be text or bytes")
    try:
        return json.loads(value)
    except (json.JSONDecodeError, UnicodeError):
        return default


def validate_principal(principal: object) -> str:
    if not isinstance(principal, str):
        raise StoragePathError("principal must be a string")
    if not _PRINCIPAL_RE.fullmatch(principal) or principal in {".", ".."}:
        raise StoragePathError("principal contains unsafe characters")
    return principal


def _validate_relative_path(
    relative_path: str | os.PathLike[str],
) -> Path:
    try:
        raw = os.fspath(relative_path)
    except TypeError as error:
        raise StoragePathError("storage path must be path-like") from error
    if not isinstance(raw, str):
        raise StoragePathError("storage path must be text")
    if not raw or "\x00" in raw or "\\" in raw:
        raise StoragePathError("storage path is empty or contains unsafe characters")
    relative = Path(raw)
    if relative.is_absolute():
        raise StoragePathError("storage paths must be relative")
    if any(part in {"", ".", ".."} for part in relative.parts):
        raise StoragePathError("storage path contains traversal")
    return relative


Storage = LocalStorage
StorageManager = LocalStorage
StorageContext = MemoryContext
