"""Build and verify a deterministic external controller-only loadout."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import uuid
from pathlib import Path
from typing import Any, Final, Mapping

from ..catalog import CatalogValidationError, inspect_controller_source
from ..errors import RappStackCubbyError

LOADOUT_SCHEMA: Final = "rapp-controller-loadout/1.0"
CONTROLLER_CATALOG_SCHEMA: Final = "rapp-controller-catalog/1.0"
CONTROLLER_SOURCE_RELATIVE: Final = Path(
    "cubbies/kody-w/agents/rapp_stack_cubby_agent.py"
)
CONTROLLER_CATALOG_RELATIVE: Final = Path(
    "cubbies/kody-w/catalog/controller-catalog.json"
)
CONTROLLER_SOUL_RELATIVE: Final = Path("cubbies/kody-w/soul.md")
LOADOUT_AGENT_RELATIVE: Final = Path(
    "agents/rapp_stack_cubby_agent.py"
)
LOADOUT_SOUL_RELATIVE: Final = Path("soul.md")
LOADOUT_MANIFEST_NAME: Final = "controller-loadout.json"
_HEX_64 = frozenset("0123456789abcdef")


class ControllerLoadoutError(RappStackCubbyError, ValueError):
    """Raised when an external controller loadout cannot be built safely."""


def canonical_json_bytes(value: Any) -> bytes:
    """Return the deterministic compact JSON representation used for hashes."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_file(path: Path) -> str:
    """Hash one regular, non-symlink file."""

    if path.is_symlink() or not path.is_file():
        raise ControllerLoadoutError("loadout source must be a regular file")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            while chunk := source.read(64 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise ControllerLoadoutError("loadout source cannot be read") from error
    return digest.hexdigest()


def build_controller_loadout(
    repository_root: str | os.PathLike[str],
    output_dir: str | os.PathLike[str],
) -> dict[str, Any]:
    """Atomically copy only the verified controller agent to an external root."""

    repository = _repository_root(repository_root)
    output = _external_output(repository, output_dir)
    source = _contained_file(repository, CONTROLLER_SOURCE_RELATIVE)
    soul_source = _contained_file(repository, CONTROLLER_SOUL_RELATIVE)
    catalog_path = _contained_file(repository, CONTROLLER_CATALOG_RELATIVE)
    catalog = _read_object(catalog_path)
    _validate_catalog(catalog)
    catalog_sha = sha256_file(catalog_path)
    source_before = sha256_file(source)
    soul_before = sha256_file(soul_source)
    if source_before != catalog["source"]["sha256"]:
        raise ControllerLoadoutError(
            "controller catalog does not match controller source"
        )
    if output.exists():
        raise ControllerLoadoutError("controller loadout output already exists")

    parent = output.parent
    stage = parent / f".{output.name}.controller-stage-{uuid.uuid4().hex}"
    try:
        stage.mkdir(mode=0o700)
        agents = stage / "agents"
        agents.mkdir(mode=0o700)
        destination = stage / LOADOUT_AGENT_RELATIVE
        shutil.copyfile(source, destination)
        os.chmod(destination, 0o600)
        soul_destination = stage / LOADOUT_SOUL_RELATIVE
        shutil.copyfile(soul_source, soul_destination)
        os.chmod(soul_destination, 0o600)
        manifest = {
            "schema": LOADOUT_SCHEMA,
            "controller": {
                "name": catalog["name"],
                "actions": list(catalog["actions"]),
                "capability_ids": list(catalog["capability_ids"]),
                "dependencies": list(catalog["dependencies"]),
                "mutability": catalog["mutability"],
                "only_streamable_agent": catalog["only_streamable_agent"],
                "path": LOADOUT_AGENT_RELATIVE.as_posix(),
                "sha256": source_before,
            },
            "catalog": catalog,
            "files": [
                {
                    "path": LOADOUT_AGENT_RELATIVE.as_posix(),
                    "sha256": source_before,
                },
                {
                    "path": LOADOUT_SOUL_RELATIVE.as_posix(),
                    "sha256": soul_before,
                },
            ],
            "soul": {
                "path": LOADOUT_SOUL_RELATIVE.as_posix(),
                "sha256": soul_before,
            },
            "source": {
                "catalog_path": CONTROLLER_CATALOG_RELATIVE.as_posix(),
                "catalog_sha256": catalog_sha,
                "catalog_schema": catalog["schema"],
                "path": CONTROLLER_SOURCE_RELATIVE.as_posix(),
                "sha256": source_before,
            },
            "determinism": {
                "encoding": "UTF-8",
                "file_order": "path",
                "key_order": "lexicographic",
                "trailing_newline": True,
            },
        }
        _write_private_json(stage / LOADOUT_MANIFEST_NAME, manifest)
        if (
            sha256_file(source) != source_before
            or sha256_file(soul_source) != soul_before
        ):
            raise ControllerLoadoutError(
                "controller source changed during loadout construction"
            )
        verified = _verify_at(stage, expected_source_sha=source_before)
        os.replace(stage, output)
        stage = None
        return verified
    except ControllerLoadoutError:
        raise
    except OSError as error:
        raise ControllerLoadoutError(
            "controller loadout could not be promoted atomically"
        ) from error
    finally:
        if stage is not None and stage.exists():
            shutil.rmtree(stage, ignore_errors=True)


def verify_controller_loadout(
    output_dir: str | os.PathLike[str],
) -> dict[str, Any]:
    """Verify a completed controller-only loadout without executing it."""

    output = Path(output_dir)
    if not output.is_absolute():
        raise ControllerLoadoutError("controller loadout path must be absolute")
    _reject_symlink_components(output)
    try:
        resolved = output.resolve(strict=True)
    except OSError as error:
        raise ControllerLoadoutError(
            "controller loadout does not exist"
        ) from error
    return _verify_at(resolved)


def _verify_at(
    output: Path,
    *,
    expected_source_sha: str | None = None,
) -> dict[str, Any]:
    if output.is_symlink() or not output.is_dir():
        raise ControllerLoadoutError("controller loadout must be a directory")
    if stat.S_IMODE(output.stat().st_mode) & 0o077:
        raise ControllerLoadoutError("controller loadout root must be mode 0700")
    manifest_path = output / LOADOUT_MANIFEST_NAME
    manifest = _read_object(manifest_path)
    if manifest.get("schema") != LOADOUT_SCHEMA:
        raise ControllerLoadoutError("controller loadout schema is invalid")
    if set(manifest) != {
        "schema",
        "controller",
        "catalog",
        "files",
        "soul",
        "source",
        "determinism",
    }:
        raise ControllerLoadoutError("controller loadout fields are invalid")
    expected_files = {
        LOADOUT_MANIFEST_NAME,
        LOADOUT_AGENT_RELATIVE.as_posix(),
        LOADOUT_SOUL_RELATIVE.as_posix(),
    }
    observed_files: set[str] = set()
    observed_directories: set[str] = set()
    for directory, names, files in os.walk(output, topdown=True):
        current = Path(directory)
        if current.is_symlink() or stat.S_IMODE(current.stat().st_mode) & 0o077:
            raise ControllerLoadoutError(
                "controller loadout contains an unsafe directory"
            )
        for name in names:
            child_directory = current / name
            if child_directory.is_symlink():
                raise ControllerLoadoutError(
                    "controller loadout contains a symbolic link"
                )
            observed_directories.add(
                child_directory.relative_to(output).as_posix()
            )
        for name in files:
            path = current / name
            if path.is_symlink() or not path.is_file():
                raise ControllerLoadoutError(
                    "controller loadout contains a non-regular file"
                )
            if stat.S_IMODE(path.stat().st_mode) != 0o600:
                raise ControllerLoadoutError(
                    "controller loadout files must be mode 0600"
                )
            observed_files.add(path.relative_to(output).as_posix())
    if observed_files != expected_files:
        raise ControllerLoadoutError(
            "controller loadout contains unexpected or missing files"
        )
    if observed_directories != {"agents"}:
        raise ControllerLoadoutError(
            "controller loadout contains an unexpected directory"
        )
    controller = manifest.get("controller")
    catalog = manifest.get("catalog")
    files = manifest.get("files")
    soul = manifest.get("soul")
    if (
        not isinstance(controller, dict)
        or not isinstance(catalog, dict)
        or not isinstance(soul, dict)
        or files
        != [
            {
                "path": LOADOUT_AGENT_RELATIVE.as_posix(),
                "sha256": controller.get("sha256"),
            },
            {
                "path": LOADOUT_SOUL_RELATIVE.as_posix(),
                "sha256": soul.get("sha256"),
            },
        ]
    ):
        raise ControllerLoadoutError("controller loadout manifest is invalid")
    digest = sha256_file(output / LOADOUT_AGENT_RELATIVE)
    try:
        inspected = inspect_controller_source(
            output / LOADOUT_AGENT_RELATIVE
        )
    except CatalogValidationError as error:
        raise ControllerLoadoutError(
            "copied controller source contract is invalid"
        ) from error
    reconstructed = _catalog_from_inspection(inspected)
    if (
        catalog != reconstructed
        or controller
        != {
            "name": reconstructed["name"],
            "actions": reconstructed["actions"],
            "capability_ids": reconstructed["capability_ids"],
            "dependencies": reconstructed["dependencies"],
            "mutability": reconstructed["mutability"],
            "only_streamable_agent": True,
            "path": LOADOUT_AGENT_RELATIVE.as_posix(),
            "sha256": digest,
        }
        or controller.get("path") != LOADOUT_AGENT_RELATIVE.as_posix()
        or controller.get("sha256") != digest
        or (
            expected_source_sha is not None
            and digest != expected_source_sha
        )
    ):
        raise ControllerLoadoutError(
            "controller loadout digest does not match its manifest"
        )
    soul_digest = sha256_file(output / LOADOUT_SOUL_RELATIVE)
    if (
        soul.get("path") != LOADOUT_SOUL_RELATIVE.as_posix()
        or soul.get("sha256") != soul_digest
    ):
        raise ControllerLoadoutError("controller soul does not match its manifest")
    source = manifest.get("source")
    if (
        source
        != {
            "catalog_path": CONTROLLER_CATALOG_RELATIVE.as_posix(),
            "catalog_sha256": hashlib.sha256(
                (
                    json.dumps(
                        reconstructed,
                        ensure_ascii=False,
                        allow_nan=False,
                        sort_keys=True,
                        indent=2,
                    )
                    + "\n"
                ).encode("utf-8")
            ).hexdigest(),
            "catalog_schema": CONTROLLER_CATALOG_SCHEMA,
            "path": CONTROLLER_SOURCE_RELATIVE.as_posix(),
            "sha256": digest,
        }
    ):
        raise ControllerLoadoutError(
            "controller loadout source provenance is invalid"
        )
    if manifest.get("determinism") != {
        "encoding": "UTF-8",
        "file_order": "path",
        "key_order": "lexicographic",
        "trailing_newline": True,
    }:
        raise ControllerLoadoutError(
            "controller loadout determinism profile is invalid"
        )
    return manifest


def _catalog_from_inspection(inspected: Mapping[str, Any]) -> dict[str, Any]:
    manifest = inspected["manifest"]
    return {
        "schema": CONTROLLER_CATALOG_SCHEMA,
        "name": inspected["tool_name"],
        "source": {
            "path": CONTROLLER_SOURCE_RELATIVE.as_posix(),
            "sha256": inspected["sha256"],
        },
        "actions": list(manifest["actions"]),
        "capability_ids": list(manifest["capability_ids"]),
        "mutability": manifest["mutability"],
        "dependencies": list(manifest["dependencies"]),
        "only_streamable_agent": True,
        "determinism": {
            "encoding": "UTF-8",
            "key_order": "lexicographic",
            "indent_spaces": 2,
            "trailing_newline": True,
        },
    }


def _repository_root(value: str | os.PathLike[str]) -> Path:
    supplied = Path(value)
    if supplied.is_symlink():
        raise ControllerLoadoutError("repository root must not be a symlink")
    try:
        resolved = supplied.resolve(strict=True)
    except OSError as error:
        raise ControllerLoadoutError("repository root does not exist") from error
    if not resolved.is_dir():
        raise ControllerLoadoutError("repository root must be a directory")
    return resolved


def _external_output(
    repository: Path,
    value: str | os.PathLike[str],
) -> Path:
    output = Path(value)
    if not output.is_absolute() or ".." in output.parts:
        raise ControllerLoadoutError(
            "controller loadout output must be an explicit absolute path"
        )
    _reject_symlink_components(output.parent)
    try:
        parent = output.parent.resolve(strict=True)
    except OSError as error:
        raise ControllerLoadoutError(
            "controller loadout parent must already exist"
        ) from error
    selected = parent / output.name
    if (
        selected == repository
        or repository in selected.parents
        or selected in repository.parents
    ):
        raise ControllerLoadoutError(
            "controller loadout must be outside the source worktree"
        )
    return selected


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise ControllerLoadoutError(
                "controller loadout path cannot be inspected"
            ) from error
        if stat.S_ISLNK(info.st_mode):
            raise ControllerLoadoutError(
                "controller loadout path must not contain symlinks"
            )


def _contained_file(root: Path, relative: Path) -> Path:
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ControllerLoadoutError(
                "controller source path contains a symbolic link"
            )
    try:
        resolved = current.resolve(strict=True)
    except OSError as error:
        raise ControllerLoadoutError("controller source is missing") from error
    if root not in resolved.parents or not resolved.is_file():
        raise ControllerLoadoutError("controller source path is not contained")
    return resolved


def _read_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ControllerLoadoutError("controller JSON input is invalid")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ControllerLoadoutError("controller JSON input is invalid") from error
    if not isinstance(value, dict):
        raise ControllerLoadoutError("controller JSON input must be an object")
    return value


def _validate_catalog(catalog: Mapping[str, Any]) -> None:
    source = catalog.get("source")
    digest = source.get("sha256") if isinstance(source, Mapping) else None
    actions = catalog.get("actions")
    capabilities = catalog.get("capability_ids")
    if (
        catalog.get("schema") != CONTROLLER_CATALOG_SCHEMA
        or set(catalog)
        != {
            "schema",
            "name",
            "source",
            "actions",
            "capability_ids",
            "mutability",
            "dependencies",
            "only_streamable_agent",
            "determinism",
        }
        or catalog.get("name") != "RappStackCubbyController"
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in _HEX_64 for character in digest)
        or source.get("path") != CONTROLLER_SOURCE_RELATIVE.as_posix()
        or not isinstance(actions, list)
        or not actions
        or not all(isinstance(item, str) and item for item in actions)
        or not isinstance(capabilities, list)
        or not all(isinstance(item, str) and item for item in capabilities)
        or not isinstance(catalog.get("mutability"), str)
        or not isinstance(catalog.get("dependencies"), list)
        or not all(
            isinstance(item, str) and item
            for item in catalog.get("dependencies", [])
        )
        or catalog.get("only_streamable_agent") is not True
        or catalog.get("determinism")
        != {
            "encoding": "UTF-8",
            "key_order": "lexicographic",
            "indent_spaces": 2,
            "trailing_newline": True,
        }
    ):
        raise ControllerLoadoutError("controller catalog is invalid")


def _write_private_json(path: Path, value: Mapping[str, Any]) -> None:
    payload = (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, 0o600)
