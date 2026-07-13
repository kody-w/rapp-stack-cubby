"""Verify, atomically hatch, statically attest, and uninstall a cubby egg."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import uuid
from dataclasses import dataclass
from email.parser import Parser
from pathlib import Path
from pathlib import PurePosixPath
from typing import Callable, Mapping, Sequence

from ..controller import build_controller_loadout, verify_controller_loadout
from .builder import EGG_SCHEMA, extract_verified_artifact
from .common import (
    PackagingError,
    atomic_write,
    canonical_json_bytes,
    exact_mode_text,
    pretty_json_bytes,
    read_json_object,
    sha256_file,
    validate_relative_path,
)
from .identity import build_instance_identity
from .release import ReleaseVerification
from .source import validate_source_manifest

INSTALLED_SCHEMA = "rapp-installed-twin/1.1"
RECEIPT_SCHEMA = "rapp-hatch-receipt/1.1"
UNINSTALL_SCHEMA = "rapp-uninstall-journal/1.0"
_APPLICATION_ROOT = Path("cubby/kody-w/rapplications/rapp-stack")
_EXPECTED_VERSIONS = {
    "cffi": "2.1.0",
    "cryptography": "49.0.0",
    "pycparser": "3.0",
}
_ALLOWED_DISTRIBUTIONS = frozenset(_EXPECTED_VERSIONS)
_INVENTORY_EXCLUSIONS = frozenset(
    {"hatch-receipt.json", "installed-twin.json"}
)
_MUTABLE_DIRECTORY_MODES = {
    "state": "0700",
    "state/home": "0700",
    "workspace": "0700",
}
_EXPECTED_TOP_LEVEL = frozenset(
    {
        "artifacts",
        "controller-loadout",
        "hatch-receipt.json",
        "installed-twin.json",
        "source",
        "state",
        "venv",
        "workspace",
    }
)


def _remove_tree(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink():
        path.unlink(missing_ok=True)
        return
    for directory, names, files in os.walk(path, topdown=True):
        current = Path(directory)
        try:
            os.chmod(current, 0o700)
        except OSError:
            pass
        for name in names:
            child = current / name
            if not child.is_symlink():
                try:
                    os.chmod(child, 0o700)
                except OSError:
                    pass
        for name in files:
            child = current / name
            if not child.is_symlink():
                try:
                    os.chmod(child, 0o600)
                except OSError:
                    pass
    shutil.rmtree(path)


@dataclass(frozen=True, slots=True)
class HatchTestSeam:
    """Injected non-production environment creator; never exposed by the CLI."""

    create_environment: Callable[[Path, Path, Path], Mapping[str, str]]


def _absolute(value: str | Path, label: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise PackagingError(f"{label} must be an explicit absolute path")
    return path.resolve(strict=False)


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise PackagingError("path contains a symbolic-link component")


def _safe_environment(home: Path, venv_bin: Path | None = None) -> dict[str, str]:
    path = "/usr/bin:/bin"
    if venv_bin is not None:
        path = f"{venv_bin}:{path}"
    return {
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": path,
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INDEX": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
    }


def _run(
    argv: Sequence[str],
    *,
    env: Mapping[str, str],
    timeout: float,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> subprocess.CompletedProcess:
    try:
        result = runner(
            list(argv),
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(env),
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PackagingError("fixed hatch subprocess failed") from error
    if result.returncode != 0:
        raise PackagingError("fixed hatch subprocess returned an error")
    return result


def _probe_python(
    python: Path,
    home: Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> None:
    if not python.is_file() or not os.access(python, os.X_OK):
        raise PackagingError("Python path must be an executable file")
    result = _run(
        [
            str(python),
            "-I",
            "-c",
            (
                "import json,platform,sys;"
                "print(json.dumps({'implementation':platform.python_implementation(),"
                "'version':list(sys.version_info[:2])},sort_keys=True))"
            ),
        ],
        env=_safe_environment(home),
        timeout=15,
        runner=runner,
    )
    try:
        value = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise PackagingError("Python probe returned invalid output") from error
    if value != {"implementation": "CPython", "version": [3, 11]}:
        raise PackagingError("hatch requires exactly CPython 3.11")


def _create_environment(
    stage: Path,
    python: Path,
    application: Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> dict[str, str]:
    private_home = stage / "state/home"
    private_home.mkdir(parents=True, exist_ok=True, mode=0o700)
    venv = stage / "venv"
    environment = _safe_environment(private_home)
    _probe_python(python, private_home, runner=runner)
    _run(
        [
            str(python),
            "-I",
            "-m",
            "venv",
            "--without-pip",
            "--copies",
            str(venv),
        ],
        env=environment,
        timeout=120,
        runner=runner,
    )
    venv_python = venv / "bin/python"
    if not venv_python.exists():
        raise PackagingError("venv did not create its Python executable")
    site_packages = venv / "lib/python3.11/site-packages"
    site_packages.mkdir(parents=True, exist_ok=True, mode=0o700)
    pip_environment = _safe_environment(private_home, venv / "bin")
    _run(
        [
            str(python),
            "-I",
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-input",
            "--no-index",
            "--find-links",
            str(application / "wheelhouse"),
            "--require-hashes",
            "--no-compile",
            "--target",
            str(site_packages),
            "-r",
            str(application / "requirements.lock"),
        ],
        env=pip_environment,
        timeout=300,
        runner=runner,
    )
    _remove_target_scripts(site_packages)
    return _dependency_versions(_distribution_inventory(stage, require_all=True))


def _remove_target_scripts(site_packages: Path) -> None:
    """Remove wheel console scripts; the runtime exposes no dependency CLIs."""

    script_pattern = re.compile(r"^(?:\.\./)+bin/([A-Za-z0-9._-]+)$")
    for record_path in sorted(
        site_packages.glob("*.dist-info/RECORD"),
        key=lambda path: path.name,
    ):
        try:
            rows = list(
                csv.reader(record_path.read_text(encoding="utf-8").splitlines())
            )
        except (OSError, UnicodeError, csv.Error) as error:
            raise PackagingError("installed wheel RECORD is invalid") from error
        retained: list[list[str]] = []
        for row in rows:
            if len(row) != 3:
                raise PackagingError("installed wheel RECORD row is invalid")
            if ".." not in PurePosixPath(row[0]).parts:
                retained.append(row)
                continue
            match = script_pattern.fullmatch(row[0])
            if match is None:
                raise PackagingError("wheel RECORD path escapes the install")
            script = site_packages / "bin" / match.group(1)
            if script.is_symlink():
                raise PackagingError("installed dependency script is invalid")
            if script.exists():
                if not script.is_file():
                    raise PackagingError("installed dependency script is invalid")
                script.unlink()
        output = io.StringIO(newline="")
        writer = csv.writer(output, lineterminator="\n")
        writer.writerows(retained)
        atomic_write(record_path, output.getvalue().encode("utf-8"), mode=0o644)
    scripts = site_packages / "bin"
    if scripts.exists():
        if scripts.is_symlink() or not scripts.is_dir():
            raise PackagingError("installed dependency script directory is invalid")
        try:
            scripts.rmdir()
        except OSError as error:
            raise PackagingError("unexpected installed dependency script remains") from error


def _install_imsg(
    stage: Path,
    application: Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> None:
    root = stage / "state/tools"
    root.mkdir(parents=True, mode=0o700)
    _run(
        [
            "/bin/bash",
            str(application / "scripts/install-imsg.sh"),
            "--root",
            str(root),
            "--archive",
            str(application / "vendor/imsg/imsg-macos.zip"),
        ],
        env=_safe_environment(stage / "state/home"),
        timeout=180,
        runner=runner,
    )


def _copy_product(source: Path, destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        raise PackagingError("immutable destination exists")
    shutil.copytree(
        source,
        destination,
        symlinks=False,
        copy_function=shutil.copyfile,
    )
    for path in sorted(destination.rglob("*"), reverse=True):
        if path.is_symlink():
            raise PackagingError("product source contains a symbolic link")
        if path.is_dir():
            os.chmod(path, 0o555)
        elif path.is_file():
            source_path = source / path.relative_to(destination)
            os.chmod(path, 0o555 if source_path.stat().st_mode & 0o111 else 0o444)
        else:
            raise PackagingError("product source contains a special file")
    os.chmod(destination, 0o555)


def _copy_readonly(source: Path, destination: Path) -> None:
    if source.is_symlink() or not source.is_file():
        raise PackagingError("readonly install input is invalid")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o400,
    )
    with source.open("rb") as input_, os.fdopen(descriptor, "wb") as output:
        shutil.copyfileobj(input_, output, 128 * 1024)
        output.flush()
        os.fsync(output.fileno())
    os.chmod(destination, 0o444)


def _file_record(path: Path, root: Path, prefix: str = "") -> dict:
    if path.is_symlink() or not path.is_file():
        raise PackagingError("installed inventory file is invalid")
    digest, size = sha256_file(path)
    relative = path.relative_to(root).as_posix()
    return {
        "mode": exact_mode_text(path.stat().st_mode),
        "path": validate_relative_path(f"{prefix}{relative}"),
        "sha256": digest,
        "size": size,
        "type": "file",
    }


def _tree_records(root: Path, prefix: str, *, allow_links: bool = False) -> list[dict]:
    records: list[dict] = []
    for path in sorted(
        root.rglob("*"),
        key=lambda item: item.relative_to(root).as_posix().encode("utf-8"),
    ):
        relative = validate_relative_path(
            f"{prefix}/{path.relative_to(root).as_posix()}"
        )
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if stat.S_ISLNK(info.st_mode):
            if not allow_links:
                raise PackagingError("installed logical tree contains a link")
            target = os.readlink(path)
            if not target or os.path.isabs(target):
                raise PackagingError("installed tool link target is unsafe")
            records.append(
                {
                    "mode": exact_mode_text(info.st_mode),
                    "path": relative,
                    "target": target,
                    "type": "symlink",
                }
            )
            continue
        if not stat.S_ISREG(info.st_mode):
            raise PackagingError("installed tree contains a special file")
        digest, size = sha256_file(path)
        records.append(
            {
                "mode": exact_mode_text(info.st_mode),
                "path": relative,
                "sha256": digest,
                "size": size,
                "type": "file",
            }
        )
    return records


def _seal_tree(root: Path, *, writable_root: bool = False) -> None:
    """Remove every write bit after installation without following links."""

    if root.is_symlink() or not root.is_dir():
        raise PackagingError("installed immutable tree is invalid")
    paths = sorted(
        root.rglob("*"),
        key=lambda item: (
            -len(item.relative_to(root).parts),
            item.relative_to(root).as_posix().encode("utf-8"),
        ),
    )
    for path in paths:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            continue
        if stat.S_ISDIR(info.st_mode):
            os.chmod(path, 0o555)
        elif stat.S_ISREG(info.st_mode):
            os.chmod(path, 0o555 if info.st_mode & 0o111 else 0o444)
        else:
            raise PackagingError("installed tree contains a special file")
    os.chmod(root, 0o700 if writable_root else 0o555)


def _safe_inventory_link(root: Path, path: Path, target: str) -> None:
    if not target or "\x00" in target or "\\" in target:
        raise PackagingError("installed symbolic link target is unsafe")
    relative = path.relative_to(root).as_posix()
    if os.path.isabs(target):
        if not relative.startswith("venv/bin/python"):
            raise PackagingError("installed absolute symbolic link is unsafe")
        try:
            resolved = path.resolve(strict=True)
        except OSError as error:
            raise PackagingError("installed Python link is broken") from error
        if not resolved.is_file():
            raise PackagingError("installed Python link target is invalid")
        return
    pure = PurePosixPath(target)
    if any(part in {"", "."} for part in pure.parts):
        raise PackagingError("installed symbolic link target is unsafe")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise PackagingError("installed symbolic link escapes the install") from error


def _installed_inventory(root: Path) -> dict:
    """Return the exact non-self-referential install inventory."""

    try:
        top_level = {path.name for path in root.iterdir()}
    except OSError as error:
        raise PackagingError("installed root cannot be enumerated") from error
    if top_level - _INVENTORY_EXCLUSIONS != _EXPECTED_TOP_LEVEL - _INVENTORY_EXCLUSIONS:
        raise PackagingError("installed top-level inventory is not exact")
    present_exclusions = frozenset(top_level & _INVENTORY_EXCLUSIONS)
    if present_exclusions not in {
        frozenset(),
        _INVENTORY_EXCLUSIONS,
    }:
        raise PackagingError("installed manifest inventory is incomplete")

    records: list[dict] = []
    scopes: dict[str, int] = {}
    for path in sorted(
        root.rglob("*"),
        key=lambda item: item.relative_to(root).as_posix().encode("utf-8"),
    ):
        relative = validate_relative_path(path.relative_to(root).as_posix())
        if relative in _INVENTORY_EXCLUSIONS:
            continue
        info = path.lstat()
        mode = exact_mode_text(info.st_mode)
        scope = relative.split("/", 1)[0]
        if stat.S_ISDIR(info.st_mode):
            expected_mode = _MUTABLE_DIRECTORY_MODES.get(
                relative,
                "0700" if relative.startswith("controller-loadout") else "0555",
            )
            if mode != expected_mode:
                raise PackagingError("installed directory has an unexpected mode")
            record = {"mode": mode, "path": relative, "type": "directory"}
        elif stat.S_ISLNK(info.st_mode):
            target = os.readlink(path)
            _safe_inventory_link(root, path, target)
            record = {
                "mode": mode,
                "path": relative,
                "target": target,
                "type": "symlink",
            }
        elif stat.S_ISREG(info.st_mode):
            expected_writable = (
                relative.startswith("controller-loadout/")
                and mode == "0600"
            )
            if info.st_mode & 0o222 and not expected_writable:
                raise PackagingError("installed immutable file is writable")
            if (
                "__pycache__" in path.parts
                or path.suffix in {".pyc", ".pyo"}
                or path.name in {"sitecustomize.py", "usercustomize.py"}
            ):
                raise PackagingError("installed executable Python injection file found")
            digest, size = sha256_file(path)
            record = {
                "mode": mode,
                "path": relative,
                "sha256": digest,
                "size": size,
                "type": "file",
            }
        else:
            raise PackagingError("installed inventory contains a special file")
        records.append(record)
        scopes[scope] = scopes.get(scope, 0) + 1
    return {
        "excluded_self_records": sorted(_INVENTORY_EXCLUSIONS),
        "record_count": len(records),
        "records": records,
        "root_mode": exact_mode_text(root.stat().st_mode),
        "scopes": dict(sorted(scopes.items())),
        "sha256": hashlib.sha256(canonical_json_bytes(records)).hexdigest(),
    }


def _python_identity(root: Path) -> dict:
    path = root / "venv/bin/python"
    try:
        link_info = path.lstat()
        resolved = path.resolve(strict=True)
        real_info = resolved.stat()
    except OSError as error:
        raise PackagingError("installed Python is unavailable") from error
    if not stat.S_ISREG(real_info.st_mode) or not os.access(resolved, os.X_OK):
        raise PackagingError("installed Python real executable is invalid")
    digest, size = sha256_file(resolved)
    kind = "symlink" if stat.S_ISLNK(link_info.st_mode) else "file"
    if kind == "file" and not stat.S_ISREG(link_info.st_mode):
        raise PackagingError("installed Python path type is invalid")
    try:
        real_identity = resolved.relative_to(root).as_posix()
    except ValueError:
        real_identity = str(resolved)
    return {
        "kind": kind,
        "link_mode": exact_mode_text(link_info.st_mode),
        "link_target": os.readlink(path) if kind == "symlink" else None,
        "path": "venv/bin/python",
        "real_executable": real_identity,
        "real_mode": exact_mode_text(real_info.st_mode),
        "sha256": digest,
        "size": size,
    }


def _record_hash(value: str) -> str:
    if not value.startswith("sha256="):
        raise PackagingError("wheel RECORD uses a non-SHA256 hash")
    encoded = value.removeprefix("sha256=")
    try:
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except (ValueError, TypeError) as error:
        raise PackagingError("wheel RECORD hash is invalid") from error
    if len(raw) != 32:
        raise PackagingError("wheel RECORD hash length is invalid")
    return raw.hex()


def _safe_record_candidate(site: Path, root: Path, value: str) -> tuple[Path, str]:
    if (
        not value
        or "\x00" in value
        or "\\" in value
        or value.startswith("/")
        or PurePosixPath(value).is_absolute()
        or any(part in {"", "."} for part in PurePosixPath(value).parts)
    ):
        raise PackagingError("wheel RECORD path is unsafe")
    candidate = site.joinpath(*PurePosixPath(value).parts)
    try:
        resolved = candidate.resolve(strict=True)
        relative = resolved.relative_to(root).as_posix()
    except (OSError, ValueError) as error:
        raise PackagingError("wheel RECORD path escapes the install") from error
    return candidate, validate_relative_path(relative)


def _distribution_inventory(root: Path, *, require_all: bool) -> list[dict]:
    sites = list((root / "venv/lib").glob("python3.11/site-packages"))
    if len(sites) != 1:
        if require_all:
            raise PackagingError("installed site-packages root is missing")
        return []
    site = sites[0]
    distributions: list[dict] = []
    observed_names: set[str] = set()
    for dist_info in sorted(site.glob("*.dist-info"), key=lambda path: path.name):
        if dist_info.is_symlink() or not dist_info.is_dir():
            raise PackagingError("installed distribution directory is invalid")
        metadata_path = dist_info / "METADATA"
        record_path = dist_info / "RECORD"
        if (
            metadata_path.is_symlink()
            or record_path.is_symlink()
            or not metadata_path.is_file()
            or not record_path.is_file()
        ):
            raise PackagingError("installed distribution metadata is incomplete")
        try:
            metadata = Parser().parsestr(metadata_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError) as error:
            raise PackagingError("installed distribution metadata is invalid") from error
        name = metadata.get("Name", "").casefold()
        version = metadata.get("Version", "")
        if (
            not name
            or not version
            or "\n" in name
            or "\n" in version
            or name in observed_names
            or name not in _ALLOWED_DISTRIBUTIONS
        ):
            raise PackagingError("installed distribution identity is invalid")
        observed_names.add(name)
        try:
            rows = list(
                csv.reader(record_path.read_text(encoding="utf-8").splitlines())
            )
        except (OSError, UnicodeError, csv.Error) as error:
            raise PackagingError("installed wheel RECORD is invalid") from error
        files: list[dict] = []
        seen: set[str] = set()
        for row in rows:
            if len(row) != 3 or not row[0] or row[0] in seen:
                raise PackagingError("installed wheel RECORD row is invalid")
            seen.add(row[0])
            candidate, relative = _safe_record_candidate(site, root, row[0])
            if candidate.is_symlink() or not candidate.is_file():
                raise PackagingError("wheel RECORD path is not a regular file")
            digest, size = sha256_file(candidate)
            declared_hash = _record_hash(row[1]) if row[1] else None
            try:
                declared_size = int(row[2]) if row[2] else None
            except ValueError as error:
                raise PackagingError("wheel RECORD size is invalid") from error
            if (
                declared_hash is not None
                and declared_hash != digest
                or declared_size is not None
                and declared_size != size
            ):
                raise PackagingError("installed file does not match wheel RECORD")
            files.append(
                {
                    "mode": exact_mode_text(candidate.stat().st_mode),
                    "path": relative,
                    "record_sha256": declared_hash,
                    "record_size": declared_size,
                    "sha256": digest,
                    "size": size,
                }
            )
        files.sort(key=lambda item: item["path"].encode("utf-8"))
        record_digest, record_size = sha256_file(record_path)
        distributions.append(
            {
                "files": files,
                "name": name,
                "record_path": record_path.relative_to(root).as_posix(),
                "record_sha256": record_digest,
                "record_size": record_size,
                "version": version,
            }
        )
    distributions.sort(key=lambda item: item["name"])
    if require_all and not set(_EXPECTED_VERSIONS).issubset(observed_names):
        raise PackagingError("installed distributions are incomplete")
    versions = {
        item["name"]: item["version"]
        for item in distributions
        if item["name"] in _EXPECTED_VERSIONS
    }
    if require_all and versions != _EXPECTED_VERSIONS:
        raise PackagingError("installed dependency versions do not match lock")
    return distributions


def _dependency_versions(distributions: Sequence[Mapping[str, object]]) -> dict[str, str]:
    versions = {
        str(item.get("name")): str(item.get("version"))
        for item in distributions
        if item.get("name") in _EXPECTED_VERSIONS
    }
    if versions != _EXPECTED_VERSIONS:
        raise PackagingError("installed dependency versions do not match lock")
    return versions


def _write_private_json(path: Path, value: object) -> None:
    atomic_write(path, pretty_json_bytes(value), mode=0o600)


def _release_binding(
    release_verification: Mapping[str, object] | None,
) -> dict:
    if release_verification is None:
        return {
            "development_only": True,
            "key_id": None,
            "release": False,
            "release_manifest_sha256": None,
            "signed": False,
            "verified": False,
        }
    return {
        "development_only": release_verification.get("development_only"),
        "key_id": release_verification.get("key_id"),
        "release": release_verification.get("release"),
        "release_manifest_sha256": release_verification.get(
            "release_manifest_sha256"
        ),
        "signed": release_verification.get("signed"),
        "verified": release_verification.get("verified"),
    }


def hatch_egg(
    egg_path: str | Path,
    install_root: str | Path,
    python_path: str | Path,
    *,
    expected_egg_sha256: str | None = None,
    release_verification: Mapping[str, object] | None = None,
    controller_loadout_root: str | Path | None = None,
    allow_trusted_development: bool = False,
    test_seam: HatchTestSeam | None = None,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> dict:
    """Verify, install offline, inventory statically, and atomically promote."""

    if (
        not isinstance(expected_egg_sha256, str)
        or len(expected_egg_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_egg_sha256)
    ):
        raise PackagingError("expected egg SHA-256 is required")
    if not isinstance(allow_trusted_development, bool):
        raise PackagingError("trusted development selection must be boolean")
    if allow_trusted_development and not (
        isinstance(release_verification, ReleaseVerification)
        and release_verification.get("verified") is True
        and release_verification.get("signed") is True
        and release_verification.get("development_only") is True
        and release_verification.get("release") is False
    ):
        raise PackagingError(
            "trusted development hatch requires a verified signed development release"
        )
    egg = _absolute(egg_path, "egg path")
    target = _absolute(install_root, "install root")
    python = _absolute(python_path, "Python path")
    loadout_target = (
        _absolute(controller_loadout_root, "controller loadout root")
        if controller_loadout_root is not None
        else None
    )
    if target == Path(target.anchor):
        raise PackagingError("install root cannot be a filesystem root")
    _reject_symlink_components(target)
    if target.exists() or target.is_symlink():
        raise PackagingError("install identity already exists")
    if loadout_target is not None and (
        loadout_target.exists() or loadout_target.is_symlink()
    ):
        raise PackagingError("controller loadout target already exists")
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    stage = parent / f".{target.name}.hatch-{uuid.uuid4().hex}"
    extract = parent / f".{target.name}.extract-{uuid.uuid4().hex}"
    loadout_stage: Path | None = None
    promoted_loadout = False
    promoted_install = False
    try:
        verified = extract_verified_artifact(
            egg,
            extract,
            expected_sha256=expected_egg_sha256,
            release_verification=release_verification,
            test_only_allow_development=(
                test_seam is not None or allow_trusted_development
            ),
        )
        if verified["artifact_type"] != "cubby-egg":
            raise PackagingError("hatch input is not a cubby egg")
        egg_manifest = verified["manifest"]
        if egg_manifest.get("schema") != EGG_SCHEMA:
            raise PackagingError("egg profile is invalid")
        application = extract / _APPLICATION_ROOT
        application_manifest = read_json_object(application / "manifest.json")
        identity = read_json_object(application / "rappid.json")
        if (
            application_manifest.get("schema") != "rapp-application/1.0"
            or application_manifest.get("identity") != identity.get("rappid")
        ):
            raise PackagingError("egg application identity is invalid")

        stage.mkdir(mode=0o700)
        (stage / "state").mkdir(mode=0o700)
        (stage / "state/home").mkdir(mode=0o700)
        (stage / "workspace").mkdir(mode=0o700)
        source = stage / "source"
        _copy_product(application / "source", source)
        source_manifest = validate_source_manifest(source)
        instance_identity = build_instance_identity(
            identity["rappid"],
            application_manifest["source_revision"],
            source_manifest["source_tree_digest"],
        )
        artifacts_root = stage / "artifacts"
        _copy_product(application / "wheelhouse", artifacts_root / "wheelhouse")
        _copy_product(application / "vendor", artifacts_root / "vendor")
        _copy_readonly(
            application / "requirements.lock",
            artifacts_root / "requirements.lock",
        )

        if test_seam is None:
            versions = _create_environment(stage, python, application, runner=runner)
            _install_imsg(stage, application, runner=runner)
        else:
            versions = dict(test_seam.create_environment(stage, python, application))
            if versions != _EXPECTED_VERSIONS:
                raise PackagingError(
                    "test seam must attest exact locked dependency versions"
                )

        loadout = stage / "controller-loadout"
        build_controller_loadout(source, loadout)
        verify_controller_loadout(loadout)
        _seal_tree(stage / "venv")
        _seal_tree(artifacts_root)
        tools_root = stage / "state/tools"
        if tools_root.exists():
            _seal_tree(tools_root)
        _seal_tree(stage / "state/home", writable_root=True)
        os.chmod(stage / "state", 0o700)
        os.chmod(stage / "workspace", 0o700)
        os.chmod(stage, 0o700)

        application_sha, _ = sha256_file(application / "manifest.json")
        catalog_sha, _ = sha256_file(
            source
            / "cubbies/kody-w/rapplications/rapp-stack/twin/catalog/"
            "agent-catalog.json"
        )
        files = _tree_records(source, "source")
        files.extend(_tree_records(loadout, "controller-loadout"))
        files.sort(key=lambda item: item["path"].encode("utf-8"))
        archive_records = _tree_records(artifacts_root, "artifacts")
        dependencies = application_manifest.get("dependencies")
        if not isinstance(dependencies, list):
            raise PackagingError("application dependency inventory is invalid")
        declared = {
            item["path"]: item
            for item in dependencies
            if isinstance(item, dict)
        }
        for record in archive_records:
            if record["path"] == "artifacts/requirements.lock":
                continue
            item = declared.get(record["path"].removeprefix("artifacts/"))
            if (
                item is None
                or item.get("sha256") != record["sha256"]
                or item.get("size") != record["size"]
            ):
                raise PackagingError("installed archive does not match dependency lock")
        distributions = _distribution_inventory(
            stage, require_all=test_seam is None
        )
        python_identity = _python_identity(stage)
        imsg_files = (
            _tree_records(tools_root, "state/tools", allow_links=True)
            if tools_root.exists()
            else []
        )
        imsg_dependency = next(
            (
                item
                for item in dependencies
                if isinstance(item, dict)
                and item.get("kind") == "tool-archive"
                and item.get("name") == "imsg"
            ),
            None,
        )
        if imsg_dependency is None:
            raise PackagingError("pinned imsg dependency is missing")
        installed = {
            "agent_catalog_sha256": catalog_sha,
            "application_manifest_sha256": application_sha,
            "archive_files": archive_records,
            "artifact_sha256": verified["sha256"],
            "dependency_versions": versions,
            "distributions": distributions,
            "files": files,
            "imsg": {
                "archive_path": "artifacts/" + imsg_dependency["path"],
                "archive_sha256": imsg_dependency["sha256"],
                "archive_size": imsg_dependency["size"],
                "files": imsg_files,
                "test_only_not_installed": test_seam is not None and not imsg_files,
                "version": imsg_dependency["version"],
            },
            "isolation": {
                "dedicated_agent_directory": True,
                "dedicated_state_root": True,
                "dedicated_virtual_environment": True,
                "dedicated_workspace": True,
            },
            "immutable_inventory": _installed_inventory(stage),
            "rappid": instance_identity["instance_rappid"],
            "instance_rappid": instance_identity["instance_rappid"],
            "product_rappid": identity["rappid"],
            "identity_hash": instance_identity["identity_hash"],
            "python": python_identity,
            "release_verification": _release_binding(release_verification),
            "requirements": next(
                item
                for item in archive_records
                if item["path"] == "artifacts/requirements.lock"
            ),
            "schema": INSTALLED_SCHEMA,
            "source_revision": application_manifest["source_revision"],
            "source_tree_digest": source_manifest["source_tree_digest"],
            "started": False,
            "streamable_agent_count": 0,
            "test_only_environment": test_seam is not None,
        }
        _write_private_json(stage / "installed-twin.json", installed)
        receipt = {
            "artifact_sha256": verified["sha256"],
            "installed_manifest_sha256": sha256_file(
                stage / "installed-twin.json"
            )[0],
            "rappid": instance_identity["instance_rappid"],
            "instance_rappid": instance_identity["instance_rappid"],
            "product_rappid": identity["rappid"],
            "schema": RECEIPT_SCHEMA,
            "started": False,
        }
        _write_private_json(stage / "hatch-receipt.json", receipt)
        os.chmod(stage / "installed-twin.json", 0o400)
        os.chmod(stage / "hatch-receipt.json", 0o400)
        verify_install(
            stage,
            verify_dependencies=False,
            allow_test_environment=test_seam is not None,
            runner=runner,
        )
        os.replace(stage, target)
        promoted_install = True

        if loadout_target is not None:
            loadout_stage = loadout_target.parent / (
                f".{loadout_target.name}.hatch-{uuid.uuid4().hex}"
            )
            loadout_target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copytree(
                target / "controller-loadout",
                loadout_stage,
                copy_function=shutil.copy2,
            )
            os.replace(loadout_stage, loadout_target)
            promoted_loadout = True
        return verify_install(
            target,
            verify_dependencies=test_seam is None,
            allow_test_environment=test_seam is not None,
            runner=runner,
        )
    except Exception:
        if promoted_loadout and loadout_target is not None:
            _remove_tree(loadout_target)
        if promoted_install:
            _remove_tree(target)
        raise
    finally:
        if loadout_stage is not None:
            _remove_tree(loadout_stage)
        _remove_tree(stage)
        _remove_tree(extract)


def _verify_record(root: Path, record: Mapping[str, object]) -> None:
    path_value = record.get("path")
    if not isinstance(path_value, str):
        raise PackagingError("installed inventory path is invalid")
    path = root / validate_relative_path(path_value)
    kind = record.get("type", "file")
    info = path.lstat()
    if exact_mode_text(info.st_mode) != record.get("mode"):
        raise PackagingError("installed file mode changed")
    if kind == "symlink":
        if not stat.S_ISLNK(info.st_mode) or os.readlink(path) != record.get("target"):
            raise PackagingError("installed symbolic link changed")
        return
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise PackagingError("installed file type changed")
    digest, size = sha256_file(path)
    if digest != record.get("sha256") or size != record.get("size"):
        raise PackagingError("installed file bytes changed")


def verify_install(
    install_root: str | Path,
    *,
    verify_dependencies: bool = True,
    allow_test_environment: bool = False,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> dict:
    """Statically verify every installed byte before any optional Python probe."""

    del verify_dependencies, runner
    root = _absolute(install_root, "install root")
    _reject_symlink_components(root)
    if root.is_symlink() or not root.is_dir():
        raise PackagingError("installed twin does not exist")
    for name in _INVENTORY_EXCLUSIONS:
        path = root / name
        try:
            info = path.lstat()
        except OSError as error:
            raise PackagingError("installed manifest file is missing") from error
        if not stat.S_ISREG(info.st_mode) or exact_mode_text(info.st_mode) != "0400":
            raise PackagingError("installed manifest file type or mode changed")
    manifest = read_json_object(root / "installed-twin.json")
    receipt = read_json_object(root / "hatch-receipt.json")
    if (
        manifest.get("schema") != INSTALLED_SCHEMA
        or receipt.get("schema") != RECEIPT_SCHEMA
        or receipt.get("rappid") != manifest.get("rappid")
        or receipt.get("instance_rappid") != manifest.get("instance_rappid")
        or receipt.get("product_rappid") != manifest.get("product_rappid")
        or manifest.get("rappid") != manifest.get("instance_rappid")
        or manifest.get("rappid") == manifest.get("product_rappid")
        or manifest.get("test_only_environment") is True
        and not allow_test_environment
    ):
        raise PackagingError("installed twin manifest or receipt is invalid")
    manifest_sha, _ = sha256_file(root / "installed-twin.json")
    if receipt.get("installed_manifest_sha256") != manifest_sha:
        raise PackagingError("installed receipt does not bind the manifest")
    immutable_inventory = manifest.get("immutable_inventory")
    if (
        not isinstance(immutable_inventory, dict)
        or _installed_inventory(root) != immutable_inventory
    ):
        raise PackagingError("installed exhaustive inventory changed")
    for name in ("state", "workspace"):
        path = root / name
        if path.is_symlink() or not path.is_dir():
            raise PackagingError(f"installed {name} root is invalid")
        if stat.S_IMODE(path.stat().st_mode) != 0o700:
            raise PackagingError(f"installed {name} root mode is invalid")
    if (root / "venv").is_symlink() or not (root / "venv").is_dir():
        raise PackagingError("installed virtual environment is missing")
    source_result = validate_source_manifest(root / "source")
    if source_result["source_tree_digest"] != manifest.get("source_tree_digest"):
        raise PackagingError("installed source digest does not match")
    verify_controller_loadout(root / "controller-loadout")
    for group in ("files", "archive_files"):
        values = manifest.get(group)
        if not isinstance(values, list):
            raise PackagingError("installed file inventory is missing")
        for record in values:
            if not isinstance(record, dict):
                raise PackagingError("installed file inventory is invalid")
            _verify_record(root, record)
    requirements = manifest.get("requirements")
    if not isinstance(requirements, dict):
        raise PackagingError("installed requirements record is missing")
    _verify_record(root, requirements)
    python_identity = manifest.get("python")
    if not isinstance(python_identity, dict) or _python_identity(root) != python_identity:
        raise PackagingError("installed Python identity changed")
    distributions = _distribution_inventory(
        root, require_all=manifest.get("test_only_environment") is not True
    )
    if distributions != manifest.get("distributions"):
        raise PackagingError("installed package RECORD inventory changed")
    if _dependency_versions(distributions) != manifest.get("dependency_versions"):
        raise PackagingError("installed dependency metadata changed")
    imsg = manifest.get("imsg")
    if not isinstance(imsg, dict) or not isinstance(imsg.get("files"), list):
        raise PackagingError("installed imsg inventory is invalid")
    archive_path = root / validate_relative_path(str(imsg.get("archive_path")))
    archive_digest, archive_size = sha256_file(archive_path)
    if (
        archive_digest != imsg.get("archive_sha256")
        or archive_size != imsg.get("archive_size")
    ):
        raise PackagingError("installed imsg archive changed")
    for record in imsg["files"]:
        if not isinstance(record, dict):
            raise PackagingError("installed imsg file record is invalid")
        _verify_record(root, record)
    if (
        not imsg["files"]
        and not (
            manifest.get("test_only_environment") is True
            and imsg.get("test_only_not_installed") is True
            and allow_test_environment
        )
    ):
        raise PackagingError("installed imsg tool inventory is missing")
    return {
        "artifact_sha256": manifest["artifact_sha256"],
        "file_count": immutable_inventory["record_count"],
        "inventory_sha256": immutable_inventory["sha256"],
        "installed_manifest_sha256": manifest_sha,
        "rappid": manifest["rappid"],
        "instance_rappid": manifest["instance_rappid"],
        "product_rappid": manifest["product_rappid"],
        "release": manifest["release_verification"]["release"],
        "release_verified": manifest["release_verification"]["verified"],
        "schema": manifest["schema"],
        "source_tree_digest": manifest["source_tree_digest"],
        "started": False,
        "verified": True,
    }


def uninstall_preview(install_root: str | Path) -> dict:
    """Return a content-free deletion preview; never remove the install."""

    root = _absolute(install_root, "install root")
    verified = verify_install(
        root, verify_dependencies=False, allow_test_environment=True
    )
    return {
        "action": "preview-only",
        "install_root": str(root),
        "rappid": verified["rappid"],
        "requires_exact_rappid_confirmation": True,
        "schema": "rapp-uninstall-preview/1.0",
    }


def _pid_is_alive(pid: object) -> bool:
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _check_process_records(root: Path) -> None:
    for name in ("process.json", "runtime.json", "process-state.json"):
        path = root / "state" / name
        if not path.exists():
            continue
        value = read_json_object(path)
        if _pid_is_alive(value.get("pid")) or value.get("status") in {
            "running",
            "starting",
        }:
            raise PackagingError("installed twin still references a running process")


def _check_controller_references(controller_root: Path, install_root: Path) -> None:
    _reject_symlink_components(controller_root)
    if controller_root.is_symlink() or not controller_root.is_dir():
        raise PackagingError("controller root is invalid")
    for path in controller_root.rglob("*.json"):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
            continue
        try:
            value = read_json_object(path)
        except PackagingError:
            continue
        adopted = value.get("adopted_install")
        if isinstance(adopted, dict) and adopted.get("root") == str(install_root):
            raise PackagingError("controller still references the installed twin")


def uninstall_twin(
    install_root: str | Path,
    *,
    expected_product_rappid: str,
    expected_instance_rappid: str,
    confirmation: str,
    controller_root: str | Path,
    dry_run: bool = False,
) -> dict:
    """Identity-bound quarantine/delete with process and controller checks."""

    root = _absolute(install_root, "install root")
    controller = _absolute(controller_root, "controller root")
    if root == Path(root.anchor) or root == controller or root in controller.parents:
        raise PackagingError("uninstall target containment is invalid")
    verified = verify_install(
        root, verify_dependencies=False, allow_test_environment=True
    )
    if (
        verified["product_rappid"] != expected_product_rappid
        or verified["instance_rappid"] != expected_instance_rappid
        or confirmation != expected_instance_rappid
    ):
        raise PackagingError("uninstall identity confirmation does not match")
    _check_process_records(root)
    _check_controller_references(controller, root)
    if dry_run:
        return {
            "action": "dry-run",
            "instance_rappid": expected_instance_rappid,
            "product_rappid": expected_product_rappid,
            "schema": UNINSTALL_SCHEMA,
            "verified": True,
        }
    quarantine = root.parent / f".{root.name}.uninstall-{uuid.uuid4().hex}"
    journal = root.parent / (
        ".uninstall-journal-"
        + hashlib.sha256(expected_instance_rappid.encode("utf-8")).hexdigest()
        + ".json"
    )
    if quarantine.exists() or quarantine.is_symlink():
        raise PackagingError("uninstall quarantine collision")
    event = {
        "action": "uninstall-twin",
        "instance_identity_hash": hashlib.sha256(
            expected_instance_rappid.encode("utf-8")
        ).hexdigest(),
        "phase": "verified",
        "product_identity_hash": hashlib.sha256(
            expected_product_rappid.encode("utf-8")
        ).hexdigest(),
        "schema": UNINSTALL_SCHEMA,
    }
    _write_private_json(journal, event)
    os.replace(root, quarantine)
    event["phase"] = "quarantined"
    _write_private_json(journal, event)
    _remove_tree(quarantine)
    event["phase"] = "deleted"
    _write_private_json(journal, event)
    return {
        "action": "deleted",
        "journal": str(journal),
        "schema": UNINSTALL_SCHEMA,
        "verified": True,
    }
