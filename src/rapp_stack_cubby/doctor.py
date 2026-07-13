"""Content-free readiness checks for development and opt-in live modes."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any, Final, Sequence

from .packaging.dependencies import verify_dependency_cache
from .packaging.source import validate_source_manifest

_PACKAGE_VERSIONS: Final = {
    "cffi": "2.1.0",
    "cryptography": "49.0.0",
    "pycparser": "3.0",
}
_PROBE_LIMIT: Final = 1024 * 1024


class DoctorError(ValueError):
    """Raised when doctor arguments are unsafe rather than merely unready."""


def run_doctor(
    repository_root: Path,
    *,
    python: Path,
    work_dir: Path,
    dependency_cache: Path,
    install_dir: Path,
    controller_dir: Path,
    live: bool = False,
    model: str | None = None,
    github_token_file: Path | None = None,
    imessage: bool = False,
    imessage_config: Path | None = None,
    runner: Any = subprocess.run,
) -> dict[str, Any]:
    repository = repository_root.resolve(strict=True)
    selected_python = _absolute_regular(python, "python", executable=True)
    external = {
        "controller": controller_dir,
        "dependency_cache": dependency_cache,
        "install": install_dir,
        "work": work_dir,
    }
    directory_checks = {
        name: _private_external_directory(repository, path, name)
        for name, path in external.items()
    }

    python_probe = _run(
        runner,
        [
            str(selected_python),
            "-c",
            (
                "import importlib.metadata as m,json,sys;"
                "print(json.dumps({'python':list(sys.version_info[:3]),"
                "'packages':{n:m.version(n) for n in"
                "('cffi','cryptography','pycparser')}}))"
            ),
        ],
    )
    python_value = _json_object(python_probe.stdout) if python_probe.returncode == 0 else {}
    package_value = python_value.get("packages")
    python_ok = (
        isinstance(python_value.get("python"), list)
        and python_value["python"][:2] == [3, 11]
    )
    packages_ok = package_value == _PACKAGE_VERSIONS

    tool_results: dict[str, bool] = {}
    for name in ("git", "gh"):
        executable = shutil.which(name)
        if executable is None:
            tool_results[name] = False
            continue
        result = _run(
            runner,
            [executable, "--version"],
            maximum=64 * 1024,
        )
        tool_results[name] = result.returncode == 0

    try:
        validate_source_manifest(repository)
        source_manifest_ok = True
    except Exception:
        source_manifest_ok = False
    try:
        cache_result = verify_dependency_cache(
            repository, dependency_cache
        )
        cache_ok = cache_result.get("verified") is True
        cache_count = int(cache_result.get("artifact_count", 0))
    except Exception:
        cache_ok = False
        cache_count = 0

    git_status = _run(
        runner,
        [
            shutil.which("git") or "git",
            "-C",
            str(repository),
            "status",
            "--porcelain=v1",
            "--untracked-files=normal",
        ],
    )
    status_lines = (
        git_status.stdout.splitlines() if git_status.returncode == 0 else []
    )

    live_result: dict[str, Any] = {
        "checked": False,
        "authenticated": False,
        "model": None,
        "model_valid": False,
        "status": "not_checked",
    }
    if live:
        if not isinstance(model, str) or not model.strip():
            raise DoctorError("--live requires an explicit --model")
        selected_token_file: Path | None = None
        if github_token_file is not None:
            from .runtime.github_auth import (
                GitHubAuthError,
                read_github_token_file,
                validate_github_token_file,
            )

            try:
                selected_token_file = validate_github_token_file(
                    github_token_file
                )
                read_github_token_file(selected_token_file)
            except GitHubAuthError as error:
                raise DoctorError(str(error)) from error
        preflight_argv = [
            str(selected_python),
            "-m",
            "rapp_stack_cubby",
            "provider-preflight",
            "--model",
            model,
            "--json",
        ]
        if selected_token_file is not None:
            preflight_argv.extend(
                ["--github-token-file", str(selected_token_file)]
            )
        preflight = _run(
            runner,
            preflight_argv,
            cwd=repository,
            env=_python_environment(repository),
        )
        preflight_value = (
            _json_object(preflight.stdout)
            if preflight.returncode == 0
            else {}
        )
        live_result = {
            "checked": True,
            "authenticated": (
                preflight_value.get("authenticated") is True
            ),
            "model": model,
            "model_valid": (
                preflight_value.get("selected_model") == model
                and preflight_value.get("selected_model_valid") is True
            ),
            "status": (
                preflight_value.get("status")
                if isinstance(preflight_value.get("status"), str)
                else "provider_error"
            ),
        }

    imessage_result: dict[str, Any] = {
        "checked": False,
        "account_binding_verified": False,
        "automation_ready": None,
        "fda_read_ready": False,
        "tool_verified": False,
    }
    if imessage:
        if imessage_config is None:
            raise DoctorError(
                "--imessage requires an explicit --imessage-config"
            )
        config = _absolute_regular(
            imessage_config, "imessage config", executable=False
        )
        if stat.S_IMODE(config.stat().st_mode) & 0o077:
            raise DoctorError("imessage config must have mode 0600 or stricter")
        preflight = _run(
            runner,
            [
                str(selected_python),
                "-m",
                "rapp_stack_cubby",
                "imessage",
                "preflight",
                "--config",
                str(config),
            ],
            cwd=repository,
            env=_python_environment(repository),
        )
        value = (
            _json_object(preflight.stdout)
            if preflight.returncode == 0
            else {}
        )
        imessage_result = {
            "checked": True,
            "account_binding_verified": (
                value.get("account_binding_verified") is True
            ),
            "automation_ready": value.get("send_ready"),
            "fda_read_ready": value.get("read_ready") is True,
            "tool_verified": all(
                value.get(key) is True
                for key in (
                    "archive_hash_verified",
                    "architectures_verified",
                    "codesign_verified",
                    "layout_verified",
                    "team_verified",
                    "version_verified",
                )
            ),
        }

    required = [
        python_ok,
        packages_ok,
        all(tool_results.values()),
        source_manifest_ok,
        cache_ok,
        git_status.returncode == 0,
        all(directory_checks.values()),
    ]
    if live:
        required.extend(
            [
                live_result["authenticated"],
                live_result["model_valid"],
            ]
        )
    if imessage:
        required.extend(
            [
                imessage_result["account_binding_verified"],
                imessage_result["fda_read_ready"],
                imessage_result["tool_verified"],
            ]
        )
    return {
        "schema": "rapp-development-doctor/1.0",
        "ok": all(required),
        "python": {
            "executable": str(selected_python),
            "python311": python_ok,
            "exact_packages": packages_ok,
            "packages": (
                package_value if isinstance(package_value, dict) else {}
            ),
        },
        "tools": tool_results,
        "source_manifest": {"verified": source_manifest_ok},
        "dependency_cache": {
            "verified": cache_ok,
            "artifact_count": cache_count,
        },
        "repository": {
            "status_checked": git_status.returncode == 0,
            "clean": not status_lines,
            "change_count": len(status_lines),
        },
        "external_directories": directory_checks,
        "live": live_result,
        "imessage": imessage_result,
    }


def _private_external_directory(
    repository: Path,
    value: Path,
    label: str,
) -> bool:
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise DoctorError(f"{label} directory must be an explicit absolute path")
    _reject_symlink_components(path)
    try:
        resolved = path.resolve(strict=True)
        info = resolved.stat()
    except OSError:
        return False
    if (
        not stat.S_ISDIR(info.st_mode)
        or resolved == repository
        or repository in resolved.parents
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        return False
    return True


def _absolute_regular(
    value: Path,
    label: str,
    *,
    executable: bool,
) -> Path:
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise DoctorError(f"{label} must be an explicit absolute path")
    if not executable:
        _reject_symlink_components(path)
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise DoctorError(f"{label} does not exist") from error
    if not resolved.is_file() or (executable and not os.access(resolved, os.X_OK)):
        raise DoctorError(f"{label} must be a regular executable file")
    return resolved


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            if stat.S_ISLNK(os.lstat(current).st_mode):
                raise DoctorError("explicit paths must not contain symbolic links")
        except FileNotFoundError:
            continue


def _python_environment(repository: Path) -> dict[str, str]:
    allowed = {
        key: value
        for key, value in os.environ.items()
        if key
        in {
            "GH_CONFIG_DIR",
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "HOME",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "LOGNAME",
            "PATH",
            "SSH_AUTH_SOCK",
            "TMPDIR",
            "USER",
            "XDG_CONFIG_HOME",
        }
    }
    allowed["PYTHONDONTWRITEBYTECODE"] = "1"
    allowed["PYTHONPATH"] = str(repository / "src")
    return allowed


def _run(
    runner: Any,
    argv: Sequence[str],
    *,
    maximum: int = _PROBE_LIMIT,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        result = runner(
            list(argv),
            capture_output=True,
            text=True,
            check=False,
            shell=False,
            timeout=120.0,
            cwd=cwd,
            env=env,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return subprocess.CompletedProcess(list(argv), 127, "", "")
    stdout = result.stdout if isinstance(result.stdout, str) else ""
    stderr = result.stderr if isinstance(result.stderr, str) else ""
    if len(stdout.encode("utf-8")) > maximum or len(stderr.encode("utf-8")) > maximum:
        return subprocess.CompletedProcess(list(argv), 126, "", "")
    return subprocess.CompletedProcess(
        list(argv), result.returncode, stdout, stderr
    )


def _json_object(text: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, UnicodeError, RecursionError):
        return {}
    return value if isinstance(value, dict) else {}
