"""Offline validation of the exact signed-chat dependency and SBOM inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_EXPECTED = {
    "cryptography": {
        "version": "49.0.0",
        "license": "Apache-2.0 OR BSD-3-Clause",
        "wheel": "cryptography-49.0.0-cp311-abi3-macosx_11_0_arm64.whl",
        "hash": "966fe0e9c67490071f14c0d2b1cb2dfb3023c5ce39457343931415f08382f2db",
        "size": 4032100,
    },
    "cffi": {
        "version": "2.1.0",
        "license": "MIT-0",
        "wheel": "cffi-2.1.0-cp311-cp311-macosx_11_0_arm64.whl",
        "hash": "f5bce581e6b8c235e566a14768a943b172ada3ed73537bb0c0be1edee312d4e7",
        "size": 184186,
    },
    "pycparser": {
        "version": "3.0",
        "license": "BSD-3-Clause",
        "wheel": "pycparser-3.0-py3-none-any.whl",
        "hash": "b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992",
        "size": 48172,
    },
}
_EXPECTED_IMSG = {
    "version": "0.12.3",
    "archive_sha256": (
        "35977a22e9721440acf9f5b945d67034939948ba4fa4ea46b0f55d527f24d4f2"
    ),
    "annotated_ref": "76585a9e13a33534bec26d5478482efcc238f803",
    "source_commit": "dea78a9e9c493740575b03e443041ef5fbd2d463",
    "license_blob": "0ae0cb57d8c6c1417f796b39fc0d6a7f2f7c5c39",
    "team_id": "Y5PE65HELJ",
    "authority": "Developer ID Application: Peter Steinberger",
    "url": "https://github.com/openclaw/imsg/releases/download/v0.12.3/imsg-macos.zip",
    "size": 2887679,
}
_PRIVATE_SUFFIXES = {
    ".key",
    ".p12",
    ".pem",
    ".pfx",
    ".sqlite",
    ".sqlite3",
}
_IGNORED_PARTS = {".git", ".check-cache", "__pycache__"}


@dataclass(frozen=True, slots=True)
class DependencyValidationResult:
    errors: tuple[str, ...]
    package_count: int
    scanned_file_count: int

    @property
    def ok(self) -> bool:
        return not self.errors


def validate_dependency_inputs(root: str | Path) -> DependencyValidationResult:
    repository = Path(root).resolve(strict=True)
    errors: list[str] = []
    lock = _read_object(repository / "DEPENDENCY_LOCK.json", errors)
    sbom = _read_object(repository / "SBOM_INPUT.json", errors)
    packages = lock.get("packages", []) if isinstance(lock, dict) else []
    by_name = {
        item.get("name"): item
        for item in packages
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    if lock.get("schema") != "rapp-python-dependency-lock/1.0":
        errors.append("DEPENDENCY_LOCK.json schema is invalid")
    if set(by_name) != set(_EXPECTED) or len(packages) != len(_EXPECTED):
        errors.append("dependency lock must contain exactly three target packages")
    target = lock.get("target")
    if target != {
        "architecture": "arm64",
        "implementation": "CPython",
        "macos_minimum": "11.0",
        "python": "3.11",
    }:
        errors.append("dependency target must be CPython 3.11 macOS arm64")
    for name, expected in _EXPECTED.items():
        item = by_name.get(name)
        if not isinstance(item, dict):
            continue
        wheel = item.get("wheel")
        source = item.get("source")
        sdist = item.get("sdist")
        if item.get("version") != expected["version"]:
            errors.append(f"{name}: version is not exact")
        if item.get("license_expression") != expected["license"]:
            errors.append(f"{name}: license expression is stale")
        if (
            not isinstance(wheel, dict)
            or wheel.get("filename") != expected["wheel"]
            or wheel.get("sha256") != expected["hash"]
            or wheel.get("size") != expected["size"]
            or not isinstance(wheel.get("url"), str)
            or not wheel["url"].startswith("https://files.pythonhosted.org/")
        ):
            errors.append(f"{name}: target wheel metadata is invalid")
        if (
            not isinstance(source, dict)
            or not isinstance(source.get("commit"), str)
            or not _HEX_40.fullmatch(source["commit"])
        ):
            errors.append(f"{name}: source commit is invalid")
        if (
            not isinstance(sdist, dict)
            or not isinstance(sdist.get("sha256"), str)
            or not _HEX_64.fullmatch(sdist["sha256"])
        ):
            errors.append(f"{name}: sdist hash is invalid")
    _validate_project_metadata(repository, errors)
    if lock.get("build_system") != {
        "backend": "setuptools.build_meta",
        "license_expression": "MIT",
        "name": "setuptools",
        "source": {
            "repository": "https://github.com/pypa/setuptools",
            "sdist_sha256": (
                "f36b47402ecde768dbfafc46e8e4207b4360c654f1f3bb84475f0a28628fb19c"
            ),
        },
        "version": "80.9.0",
        "wheel": {
            "filename": "setuptools-80.9.0-py3-none-any.whl",
            "sha256": (
                "062d34222ad13e0cc312a4c02d73f059e86a4acbfbdea8f8f76b28c99f306922"
            ),
            "size": 1201486,
            "url": (
                "https://files.pythonhosted.org/packages/a3/dc/"
                "17031897dae0efacfea57dfd3a82fdd2a2aeb58e0ff71b77b87e44edc772/"
                "setuptools-80.9.0-py3-none-any.whl"
            ),
        },
    }:
        errors.append("build-system dependency lock is invalid")
    _validate_requirements(repository, errors)
    _validate_ci_requirements(repository, lock, errors)
    _validate_imsg(lock, errors)
    _validate_sbom(sbom, errors)
    scanned = _scan_repository(repository, errors)
    return DependencyValidationResult(
        errors=tuple(errors),
        package_count=len(by_name),
        scanned_file_count=scanned,
    )


def _validate_project_metadata(repository: Path, errors: list[str]) -> None:
    try:
        metadata = tomllib.loads(
            (repository / "pyproject.toml").read_text(encoding="utf-8")
        )
        project = metadata["project"]
        build = metadata["build-system"]
    except (OSError, KeyError, tomllib.TOMLDecodeError):
        errors.append("pyproject.toml cannot be validated")
        return
    if project.get("dependencies") != ["cryptography==49.0.0"]:
        errors.append("pyproject dependency must be exactly cryptography==49.0.0")
    if build != {
        "requires": ["setuptools==80.9.0"],
        "build-backend": "setuptools.build_meta",
    }:
        errors.append("build backend must be exactly pinned")


def _validate_requirements(repository: Path, errors: list[str]) -> None:
    try:
        text = (repository / "requirements.lock").read_text(encoding="utf-8")
    except OSError:
        errors.append("requirements.lock cannot be read")
        return
    for name, expected in _EXPECTED.items():
        requirement = f"{name}=={expected['version']}"
        digest = f"--hash=sha256:{expected['hash']}"
        if text.count(requirement) != 1 or text.count(digest) != 1:
            errors.append(f"requirements.lock entry for {name} is invalid")


def _validate_ci_requirements(
    repository: Path, lock: dict[str, Any], errors: list[str]
) -> None:
    try:
        text = (repository / "requirements-ci.lock").read_text(encoding="utf-8")
    except OSError:
        errors.append("requirements-ci.lock cannot be read")
        return
    for name, expected in _EXPECTED.items():
        requirement = f"{name}=={expected['version']}"
        digest = f"--hash=sha256:{expected['hash']}"
        if text.count(requirement) != 1 or text.count(digest) != 1:
            errors.append(f"requirements-ci.lock entry for {name} is invalid")
    ci = lock.get("ci")
    expected_packages = [
        {
            "filename": value["wheel"],
            "license_expression": value["license"],
            "name": name,
            "sha256": value["hash"],
            "version": value["version"],
        }
        for name, value in sorted(_EXPECTED.items())
    ]
    if ci != {
        "architecture": "arm64",
        "operating_system": "macOS 15",
        "packages": expected_packages,
        "python": "3.11.9",
        "requirements_file": "requirements-ci.lock",
        "runner": "macos-15",
    }:
        errors.append("CI dependency target metadata is invalid")


def _validate_imsg(lock: dict[str, Any], errors: list[str]) -> None:
    tools = lock.get("tools")
    if not isinstance(tools, list) or len(tools) != 1:
        errors.append("dependency lock must contain exactly one pinned external tool")
        return
    tool = tools[0]
    source = tool.get("source") if isinstance(tool, dict) else None
    release = tool.get("release") if isinstance(tool, dict) else None
    license_value = tool.get("license") if isinstance(tool, dict) else None
    signing = tool.get("signing") if isinstance(tool, dict) else None
    architectures = tool.get("architectures") if isinstance(tool, dict) else None
    verification = lock.get("verification")
    installed = (
        verification.get("imsg_installed_content_free_verification")
        if isinstance(verification, dict)
        else None
    )
    if (
        not isinstance(tool, dict)
        or tool.get("name") != "imsg"
        or tool.get("version") != _EXPECTED_IMSG["version"]
        or not isinstance(source, dict)
        or source.get("annotated_ref") != _EXPECTED_IMSG["annotated_ref"]
        or source.get("commit") != _EXPECTED_IMSG["source_commit"]
        or source.get("tag") != "v0.12.3"
        or source.get("repository") != "https://github.com/openclaw/imsg"
        or not isinstance(release, dict)
        or release.get("archive_sha256") != _EXPECTED_IMSG["archive_sha256"]
        or release.get("url") != _EXPECTED_IMSG["url"]
        or release.get("asset") != "imsg-macos.zip"
        or release.get("size") != _EXPECTED_IMSG["size"]
        or not isinstance(license_value, dict)
        or license_value.get("spdx") != "MIT"
        or license_value.get("blob") != _EXPECTED_IMSG["license_blob"]
        or not isinstance(signing, dict)
        or signing.get("strict") is not True
        or signing.get("team_id") != _EXPECTED_IMSG["team_id"]
        or signing.get("authority_contains") != _EXPECTED_IMSG["authority"]
        or not isinstance(architectures, dict)
        or set(architectures.get("imsg", [])) != {"x86_64", "arm64"}
        or set(architectures.get("imsg-bridge-helper.dylib", []))
        != {"x86_64", "arm64", "arm64e"}
        or not isinstance(installed, dict)
        or set(installed)
        != {
            "archive_hash",
            "architectures",
            "codesign_strict",
            "layout",
            "team_and_authority",
            "version",
        }
        or not all(value is True for value in installed.values())
    ):
        errors.append("pinned imsg dependency metadata is invalid")


def _validate_sbom(sbom: dict[str, Any], errors: list[str]) -> None:
    if (
        sbom.get("schema") != "rapp-sbom-input/1.0"
        or sbom.get("final_sbom_created") is not False
        or sbom.get("target") != "cp311-macosx_11_0_arm64"
    ):
        errors.append("SBOM input header is invalid")
    components = sbom.get("components")
    if not isinstance(components, list) or len(components) != len(_EXPECTED) + 2:
        errors.append("SBOM input components are incomplete")
        return
    purls = {
        item.get("purl"): item
        for item in components
        if isinstance(item, dict)
    }
    for name, expected in _EXPECTED.items():
        component = purls.get(f"pkg:pypi/{name}@{expected['version']}")
        if (
            not isinstance(component, dict)
            or component.get("hash") != expected["hash"]
            or component.get("license") != expected["license"]
        ):
            errors.append(f"SBOM input component for {name} is invalid")
    imsg = purls.get("pkg:github/openclaw/imsg@0.12.3")
    if (
        not isinstance(imsg, dict)
        or imsg.get("hash") != _EXPECTED_IMSG["archive_sha256"]
        or imsg.get("license") != "MIT"
        or imsg.get("scope") != "required"
    ):
        errors.append("SBOM input component for imsg is invalid")
    setuptools = purls.get("pkg:pypi/setuptools@80.9.0")
    if (
        not isinstance(setuptools, dict)
        or setuptools.get("hash")
        != "062d34222ad13e0cc312a4c02d73f059e86a4acbfbdea8f8f76b28c99f306922"
        or setuptools.get("license") != "MIT"
        or setuptools.get("scope") != "build"
    ):
        errors.append("SBOM input component for setuptools is invalid")


def _scan_repository(repository: Path, errors: list[str]) -> int:
    scanned = 0
    for path in sorted(repository.rglob("*")):
        if any(part in _IGNORED_PARTS for part in path.relative_to(repository).parts):
            continue
        if path.is_symlink():
            errors.append(f"{path.relative_to(repository)}: symbolic link is forbidden")
            continue
        if not path.is_file():
            continue
        scanned += 1
        suffix = path.suffix.casefold()
        if suffix in _PRIVATE_SUFFIXES:
            errors.append(f"{path.relative_to(repository)}: private-state file is forbidden")
        if suffix in {".whl", ".tar", ".gz"}:
            errors.append(f"{path.relative_to(repository)}: dependency artifact is forbidden")
        if path.stat().st_size <= 2 * 1024 * 1024:
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeError:
                continue
            if any(
                line.startswith("-----BEGIN ") and "PRIVATE KEY-----" in line
                for line in text.splitlines()
            ):
                errors.append(f"{path.relative_to(repository)}: private key material")
    return scanned


def _read_object(path: Path, errors: list[str]) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        errors.append(f"{path.name} cannot be read")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{path.name} must contain an object")
        return {}
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    arguments = parser.parse_args(argv)
    result = validate_dependency_inputs(arguments.root)
    if result.ok:
        print(
            "PASS dependency/key scan: "
            f"{result.package_count} exact packages; "
            f"{result.scanned_file_count} repository files; no private key artifacts"
        )
        return 0
    for error in result.errors:
        print(f"error: {error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
