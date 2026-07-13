"""Fetch inert dependency archives from the exact checked-in lock."""

from __future__ import annotations

import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from .common import (
    PackagingError,
    copy_verified_file,
    read_json_object,
    sha256_file,
)

DEPENDENCY_LOCK_SCHEMA = "rapp-python-dependency-lock/1.0"
MAX_DEPENDENCY_BYTES = 128 * 1024 * 1024
_ALLOWED_SCHEMES = frozenset({"https"})
_ALLOWED_HOSTS = frozenset({"files.pythonhosted.org", "github.com"})


@dataclass(frozen=True, slots=True)
class LockedArtifact:
    """One immutable downloadable file from DEPENDENCY_LOCK.json."""

    kind: str
    name: str
    version: str
    filename: str
    url: str
    sha256: str
    size: int


def locked_artifacts(lock: dict) -> tuple[LockedArtifact, ...]:
    """Parse and validate exactly the three wheels and pinned imsg archive."""

    if (
        lock.get("schema") != DEPENDENCY_LOCK_SCHEMA
        or not isinstance(lock.get("packages"), list)
        or not isinstance(lock.get("tools"), list)
    ):
        raise PackagingError("dependency lock schema is invalid")
    values: list[LockedArtifact] = []
    for package in lock["packages"]:
        if not isinstance(package, dict) or not isinstance(
            package.get("wheel"), dict
        ):
            raise PackagingError("locked wheel entry is invalid")
        wheel = package["wheel"]
        values.append(
            _artifact(
                "python-wheel",
                package.get("name"),
                package.get("version"),
                wheel.get("filename"),
                wheel.get("url"),
                wheel.get("sha256"),
                wheel.get("size"),
            )
        )
    for tool in lock["tools"]:
        if not isinstance(tool, dict) or not isinstance(
            tool.get("release"), dict
        ):
            raise PackagingError("locked tool entry is invalid")
        release = tool["release"]
        values.append(
            _artifact(
                "tool-archive",
                tool.get("name"),
                tool.get("version"),
                release.get("asset"),
                release.get("url"),
                release.get("archive_sha256"),
                release.get("size"),
            )
        )
    if len(values) != 4:
        raise PackagingError(
            "dependency lock must contain three wheels and one tool archive"
        )
    if len({item.filename for item in values}) != len(values):
        raise PackagingError("locked dependency filenames are not unique")
    if sum(item.kind == "python-wheel" for item in values) != 3:
        raise PackagingError("dependency lock must contain exactly three wheels")
    if (
        sum(
            item.kind == "tool-archive" and item.name == "imsg"
            for item in values
        )
        != 1
    ):
        raise PackagingError("dependency lock must contain one imsg archive")
    return tuple(sorted(values, key=lambda item: item.filename))


def _artifact(
    kind: str,
    name: object,
    version: object,
    filename: object,
    url: object,
    sha256: object,
    size: object,
) -> LockedArtifact:
    if not all(
        isinstance(value, str) and value
        for value in (name, version, filename, url, sha256)
    ):
        raise PackagingError("locked dependency fields are invalid")
    assert isinstance(name, str)
    assert isinstance(version, str)
    assert isinstance(filename, str)
    assert isinstance(url, str)
    assert isinstance(sha256, str)
    if (
        "/" in filename
        or "\\" in filename
        or filename in {".", ".."}
        or not isinstance(size, int)
        or isinstance(size, bool)
        or not 0 < size <= MAX_DEPENDENCY_BYTES
        or len(sha256) != 64
        or any(character not in "0123456789abcdef" for character in sha256)
    ):
        raise PackagingError("locked dependency identity is invalid")
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme not in _ALLOWED_SCHEMES
        or parsed.hostname not in _ALLOWED_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.query
        or not parsed.path
    ):
        raise PackagingError("locked dependency URL is not allowed")
    return LockedArtifact(
        kind=kind,
        name=name,
        version=version,
        filename=filename,
        url=url,
        sha256=sha256,
        size=size,
    )


def load_dependency_lock(root: str | Path) -> tuple[dict, tuple[LockedArtifact, ...]]:
    """Load the repository dependency lock and its immutable artifacts."""

    repository = Path(root).resolve()
    lock = read_json_object(repository / "DEPENDENCY_LOCK.json")
    return lock, locked_artifacts(lock)


def _outside_repository(repository: Path, cache: Path) -> Path:
    if not cache.is_absolute():
        raise PackagingError("dependency cache must be an explicit absolute path")
    resolved = cache.expanduser().resolve(strict=False)
    if resolved == repository or repository in resolved.parents:
        raise PackagingError("dependency cache must be outside the repository")
    return resolved


def verify_dependency_cache(
    root: str | Path,
    cache: str | Path,
) -> dict:
    """Verify all locked dependency bytes already present in a cache."""

    repository = Path(root).resolve()
    cache_root = _outside_repository(repository, Path(cache))
    _, artifacts = load_dependency_lock(repository)
    records = []
    for artifact in artifacts:
        path = cache_root / artifact.filename
        digest, size = sha256_file(path, limit=MAX_DEPENDENCY_BYTES)
        if digest != artifact.sha256 or size != artifact.size:
            raise PackagingError(
                f"cached dependency does not match lock: {artifact.filename}"
            )
        records.append(_record(artifact, path))
    return {
        "artifact_count": len(records),
        "artifacts": records,
        "cache": str(cache_root),
        "schema": "rapp-dependency-cache-verification/1.0",
        "verified": True,
    }


def fetch_dependencies(
    root: str | Path,
    cache: str | Path,
    *,
    timeout: float = 120.0,
    opener: Callable[..., object] | None = None,
) -> dict:
    """Download only lock URLs, verify bytes, and never execute them."""

    repository = Path(root).resolve()
    cache_root = _outside_repository(repository, Path(cache))
    if not isinstance(timeout, (int, float)) or not 0 < float(timeout) <= 600:
        raise PackagingError("dependency timeout is invalid")
    _, artifacts = load_dependency_lock(repository)
    cache_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(cache_root, 0o700)
    open_url = opener or urllib.request.urlopen
    records = []
    context = ssl.create_default_context()
    for artifact in artifacts:
        destination = cache_root / artifact.filename
        if destination.exists():
            digest, size = sha256_file(
                destination, limit=MAX_DEPENDENCY_BYTES
            )
            if digest == artifact.sha256 and size == artifact.size:
                records.append(_record(artifact, destination))
                continue
            raise PackagingError(
                f"refuse to replace invalid cache entry: {artifact.filename}"
            )
        partial = cache_root / (
            f".{artifact.filename}.partial-{os.getpid()}"
        )
        if partial.exists() or partial.is_symlink():
            raise PackagingError("dependency partial-file collision")
        request = urllib.request.Request(
            artifact.url,
            headers={
                "Accept": "application/octet-stream",
                "User-Agent": "rapp-stack-cubby-dependency-fetch/1.0",
            },
            method="GET",
        )
        try:
            kwargs = {"timeout": float(timeout)}
            if opener is None:
                kwargs["context"] = context
            response = open_url(request, **kwargs)
            descriptor = os.open(
                partial,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            count = 0
            with os.fdopen(descriptor, "wb") as output:
                try:
                    while True:
                        chunk = response.read(128 * 1024)
                        if not chunk:
                            break
                        count += len(chunk)
                        if count > artifact.size:
                            raise PackagingError(
                                f"download exceeds locked size: {artifact.filename}"
                            )
                        output.write(chunk)
                finally:
                    response.close()
                output.flush()
                os.fsync(output.fileno())
            digest, size = sha256_file(partial, limit=MAX_DEPENDENCY_BYTES)
            if digest != artifact.sha256 or size != artifact.size:
                raise PackagingError(
                    f"download does not match lock: {artifact.filename}"
                )
            os.chmod(partial, 0o600)
            os.replace(partial, destination)
        except (OSError, urllib.error.URLError) as error:
            partial.unlink(missing_ok=True)
            raise PackagingError(
                f"dependency fetch failed: {artifact.filename}"
            ) from error
        except Exception:
            partial.unlink(missing_ok=True)
            raise
        records.append(_record(artifact, destination))
    return {
        "artifact_count": len(records),
        "artifacts": records,
        "cache": str(cache_root),
        "schema": "rapp-dependency-cache-verification/1.0",
        "verified": True,
    }


def dependency_paths(
    root: str | Path,
    cache: str | Path,
) -> tuple[tuple[LockedArtifact, Path], ...]:
    """Do not expose a mutable cache path as trusted build material."""

    del root, cache
    raise PackagingError(
        "mutable dependency paths are not trusted; stage locked artifacts instead"
    )


def stage_dependency_artifacts(
    root: str | Path,
    cache: str | Path,
    destination: str | Path,
) -> tuple[dict, ...]:
    """Copy each locked archive through the descriptor used to verify it."""

    repository = Path(root).resolve()
    cache_root = _outside_repository(repository, Path(cache))
    _, artifacts = load_dependency_lock(repository)
    stage = Path(destination)
    records: list[dict] = []
    for artifact in artifacts:
        relative = (
            Path("wheelhouse") / artifact.filename
            if artifact.kind == "python-wheel"
            else Path("vendor/imsg") / artifact.filename
        )
        output = stage / relative
        copy_verified_file(
            cache_root / artifact.filename,
            output,
            expected_sha256=artifact.sha256,
            expected_size=artifact.size,
            mode=0o644,
            limit=MAX_DEPENDENCY_BYTES,
        )
        records.append(
            {
                "kind": artifact.kind,
                "name": artifact.name,
                "path": relative.as_posix(),
                "sha256": artifact.sha256,
                "size": artifact.size,
                "version": artifact.version,
            }
        )
    return tuple(records)


def _record(artifact: LockedArtifact, path: Path) -> dict:
    return {
        "filename": artifact.filename,
        "kind": artifact.kind,
        "name": artifact.name,
        "sha256": artifact.sha256,
        "size": artifact.size,
        "version": artifact.version,
    }
