"""Repository path helpers."""

from __future__ import annotations

from os import PathLike
from pathlib import Path

from .constants import REPOSITORY_MARKERS
from .errors import RepositoryNotFoundError, UnsafePathError


def find_repository_root(start: str | PathLike[str] | None = None) -> Path:
    """Find the nearest ancestor containing the repository contract markers."""

    candidate = Path.cwd() if start is None else Path(start)
    candidate = candidate.expanduser().resolve()
    if candidate.is_file():
        candidate = candidate.parent

    for directory in (candidate, *candidate.parents):
        if all((directory / marker).is_file() for marker in REPOSITORY_MARKERS):
            return directory

    raise RepositoryNotFoundError(
        "repository root not found; expected SOURCE_CENSUS.json and "
        "STACK_LOCK.json in this directory or an ancestor"
    )


def repository_path(
    root: str | PathLike[str], relative_path: str | PathLike[str]
) -> Path:
    """Resolve a repository-relative path without permitting traversal."""

    repository = Path(root).expanduser().resolve()
    relative = Path(relative_path)
    if relative.is_absolute():
        raise UnsafePathError("repository paths must be relative")

    resolved = (repository / relative).resolve()
    if resolved != repository and repository not in resolved.parents:
        raise UnsafePathError(f"path escapes repository: {relative.as_posix()}")
    return resolved
