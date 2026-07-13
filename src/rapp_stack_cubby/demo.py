"""One-command offline development product journey."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import signal
import socket
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Final, Mapping, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .context import context_summary
from .packaging.builder import (
    EGG_ARCHIVE_NAME,
    RELEASE_MANIFEST_NAME,
    build_release,
    verify_artifact,
)
from .packaging.dependencies import verify_dependency_cache
from .packaging.hatch import (
    HatchTestSeam,
    hatch_egg,
    uninstall_twin,
    verify_install,
)
from .packaging.release import verify_release
from .packaging.source import validate_source_manifest
from .pages import check_pages
from .runtime.provider import ATTESTATION_MODE, ATTESTATION_MODEL
from .verification import verify_repository

DEMO_RECEIPT_SCHEMA: Final = "rapp-product-demo-receipt/1.0"
_DEMO_STAGE_NAMES: Final = (
    "source_checked",
    "cache_verified",
    "build_reproducible",
    "development_release_verified",
    "egg_verified",
    "hatched",
    "install_verified",
    "controller_authenticated",
    "installed_adopted",
    "attestation_child_started",
    "signed_self_test",
    "child_stopped",
    "archived",
    "unarchived",
    "no_orphan",
    "cleanup",
)


class DemoError(RuntimeError):
    """Raised when the development journey cannot finish safely."""


@dataclass(frozen=True, slots=True)
class DemoTestSeam:
    """Non-CLI seam for fixture hatch and lifecycle coverage."""

    hatch: HatchTestSeam
    lifecycle: Callable[[Path, Path], Mapping[str, Any]]
    skip_repository_checks: bool = False


def run_demo(
    repository_root: Path,
    *,
    python: Path,
    work_dir: Path,
    dependency_cache: Path,
    install_dir: Path,
    controller_dir: Path,
    receipt_path: Path,
    source_date_epoch: int = 1700000000,
    cleanup: bool = False,
    test_seam: DemoTestSeam | None = None,
) -> dict[str, Any]:
    repository = repository_root.resolve(strict=True)
    selected_python = _absolute_executable(python)
    work_parent = _private_external_directory(repository, work_dir, create=True)
    cache = _private_external_directory(
        repository, dependency_cache, create=False
    )
    install_parent = _private_external_directory(
        repository, install_dir, create=True
    )
    controller_parent = _private_external_directory(
        repository, controller_dir, create=True
    )
    receipt = _external_file(repository, receipt_path)
    if (
        not isinstance(source_date_epoch, int)
        or isinstance(source_date_epoch, bool)
        or source_date_epoch < 315532800
    ):
        raise DemoError("source-date-epoch is invalid")

    run_work = work_parent / "rapp-stack-cubby-demo"
    install_root = install_parent / "rapp-stack-cubby-demo"
    controller_root = controller_parent / "rapp-stack-cubby-demo"
    _reset_owned_directory(run_work)
    _reset_owned_directory(controller_root)
    if install_root.exists() or install_root.is_symlink():
        raise DemoError(
            "demo install target already exists; use cleanup or a fresh install directory"
        )
    run_work.mkdir(mode=0o700)
    controller_root.mkdir(mode=0o700)
    _write_marker(run_work)
    _write_marker(controller_root)

    stages = {name: False for name in _DEMO_STAGE_NAMES}
    built: dict[str, Any] | None = None
    installed: dict[str, Any] | None = None
    lifecycle: dict[str, Any] = {}
    failure: Exception | None = None
    try:
        if test_seam is None or not test_seam.skip_repository_checks:
            verification = verify_repository(repository)
            if not verification.ok:
                raise DemoError("repository source verification failed")
            context_summary(repository)
            pages = check_pages(repository)
            if not pages.ok:
                raise DemoError("Pages verification failed")
        validate_source_manifest(repository)
        stages["source_checked"] = True

        cache_result = verify_dependency_cache(repository, cache)
        if cache_result.get("verified") is not True:
            raise DemoError("locked dependency cache verification failed")
        stages["cache_verified"] = True

        key_path, trust_path = _write_development_trust(run_work / "trust")
        build_one = run_work / "build-one"
        build_two = run_work / "build-two"
        built = build_release(
            repository,
            cache,
            build_one,
            source_date_epoch=source_date_epoch,
            source_revision="WORKTREE",
            signing_key=key_path,
            signing_trust=trust_path,
        )
        build_release(
            repository,
            cache,
            build_two,
            source_date_epoch=source_date_epoch,
            source_revision="WORKTREE",
            signing_key=key_path,
            signing_trust=trust_path,
        )
        _assert_equal_trees(build_one, build_two)
        stages["build_reproducible"] = True

        release = verify_release(
            build_one / RELEASE_MANIFEST_NAME,
            expected_manifest_sha256=built["release_manifest_sha256"],
            trust_path=trust_path,
            signature_path=build_one / "release-manifest.json.sig",
            checksums_path=build_one / "SHA256SUMS",
            source_root=repository,
        )
        if not (
            release.get("verified") is True
            and release.get("signed") is True
            and release.get("development_only") is True
            and release.get("release") is False
        ):
            raise DemoError("trusted development release verification failed")
        stages["development_release_verified"] = True

        egg = build_one / EGG_ARCHIVE_NAME
        egg_sha = hashlib.sha256(egg.read_bytes()).hexdigest()
        egg_result = verify_artifact(egg, expected_sha256=egg_sha)
        if egg_result.get("artifact_type") != "cubby-egg":
            raise DemoError("development egg verification failed")
        stages["egg_verified"] = True

        installed = hatch_egg(
            egg,
            install_root,
            selected_python,
            expected_egg_sha256=egg_sha,
            release_verification=release,
            allow_trusted_development=True,
            test_seam=None if test_seam is None else test_seam.hatch,
        )
        stages["hatched"] = True
        installed = verify_install(
            install_root,
            verify_dependencies=test_seam is None,
            allow_test_environment=test_seam is not None,
        )
        if installed["source_tree_digest"] != built["source_tree_digest"]:
            raise DemoError("installed source digest does not match built bytes")
        stages["install_verified"] = True

        if test_seam is None:
            lifecycle = _run_installed_lifecycle(
                install_root,
                controller_root,
                cleanup=cleanup,
                trusted_development=True,
            )
        else:
            lifecycle = dict(test_seam.lifecycle(install_root, controller_root))
        for stage in (
            "controller_authenticated",
            "installed_adopted",
            "attestation_child_started",
            "signed_self_test",
            "child_stopped",
            "archived",
            "unarchived",
            "no_orphan",
        ):
            if lifecycle.get(stage) is not True:
                raise DemoError(f"demo lifecycle did not prove {stage}")
            stages[stage] = True

        if cleanup:
            _cleanup_install(
                install_root,
                controller_root,
                installed,
                lifecycle,
            )
            _reset_owned_directory(controller_root)
            _reset_owned_directory(run_work)
            stages["cleanup"] = (
                not install_root.exists()
                and not controller_root.exists()
                and not run_work.exists()
            )
            if not stages["cleanup"]:
                raise DemoError("demo cleanup did not remove owned state")
        else:
            stages["cleanup"] = False
    except Exception as error:
        failure = error
        _best_effort_failure_cleanup(
            install_root,
            controller_root,
            run_work,
            installed,
            lifecycle,
        )

    result = {
        "schema": DEMO_RECEIPT_SCHEMA,
        "ok": failure is None,
        "offline": True,
        "published": False,
        "imessage_sent": False,
        "attestation_mode": ATTESTATION_MODE,
        "attestation_model": ATTESTATION_MODEL,
        "source_tree_digest": (
            None if built is None else built.get("source_tree_digest")
        ),
        "installed_source_digest_matches": (
            built is not None
            and installed is not None
            and built.get("source_tree_digest")
            == installed.get("source_tree_digest")
        ),
        "stages": stages,
        "cleanup_requested": cleanup,
        "failure_code": None if failure is None else "demo_failed",
    }
    _write_receipt(receipt, result)
    if failure is not None:
        raise DemoError("product demo failed safely; see the local receipt") from failure
    return result


def _run_installed_lifecycle(
    install_root: Path,
    controller_root: Path,
    *,
    cleanup: bool,
    trusted_development: bool,
) -> dict[str, Any]:
    installed_python = install_root / "venv/bin/python"
    source = install_root / "source"
    loadout = install_root / "controller-loadout"
    auth_dir = controller_root / "auth"
    runtime_data = controller_root / "runtime"
    state_root = controller_root / "state"
    home = controller_root / "home"
    for path in (auth_dir, runtime_data, state_root, home):
        path.mkdir(mode=0o700)
    env = _installed_environment(source, home)
    auth = _run_json(
        [
            str(installed_python),
            "-m",
            "rapp_stack_cubby",
            "controller-auth",
            "--private-dir",
            str(auth_dir),
        ],
        cwd=source,
        env=env,
    )
    token_file = Path(str(auth["token_file"]))
    if (
        not token_file.is_file()
        or stat.S_IMODE(token_file.stat().st_mode) != 0o600
    ):
        raise DemoError("controller authentication token is not private")

    port = _ephemeral_port()
    url = f"http://127.0.0.1:{port}"
    log = controller_root / "controller.log"
    descriptor = os.open(
        log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )
    output = os.fdopen(descriptor, "wb")
    process_env = dict(env)
    process_env.update(
        {
            "RAPP_STACK_ALLOW_CONTROLLER_MUTATIONS": "1",
            "RAPP_STACK_CONTROLLER_DATA_DIR": str(state_root),
        }
    )
    command = [
        str(installed_python),
        "-m",
        "rapp_stack_cubby",
        "serve",
        "--soul",
        str(loadout / "soul.md"),
        "--agents-dir",
        str(loadout / "agents"),
        "--data-dir",
        str(runtime_data),
        "--instance-id",
        "development-demo-controller",
        "--root",
        str(source),
        "--principal",
        "development-demo-controller",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--controller-route",
        "--controller-loadout-root",
        str(loadout),
        "--auth-token-file",
        str(token_file),
    ]
    process = subprocess.Popen(
        command,
        shell=False,
        cwd=source,
        env=process_env,
        stdin=subprocess.DEVNULL,
        stdout=output,
        stderr=output,
        start_new_session=True,
        close_fds=True,
    )
    output.close()
    instance_rappid: str | None = None
    product_rappid: str | None = None
    install_instance_rappid: str | None = None
    stopped = False
    purged = False
    try:
        _wait_controller(
            installed_python, source, env, url, token_file, process
        )
        common = [
            str(installed_python),
            "-m",
            "rapp_stack_cubby",
            "controller",
            "--url",
            url + "/chat",
            "--auth-token-file",
            str(token_file),
        ]
        adopt_command = [
            *common,
            "--idempotency-key",
            "demo-adopt-installed",
            "adopt",
            "--install-root",
            str(install_root),
            "--model",
            ATTESTATION_MODEL,
            "--attestation-mode",
            ATTESTATION_MODE,
        ]
        if trusted_development:
            adopt_command.append("--trusted-development")
        adopted_outer = _run_json(
            adopt_command,
            cwd=source,
            env=env,
        )
        adopted = _controller_result(adopted_outer)
        instance_rappid = _rappid(adopted.get("instance_rappid"))
        product_rappid = _rappid(adopted.get("product_rappid"))
        if (
            adopted.get("adopted") is not True
            or adopted.get("source_tree_digest")
            != verify_install(install_root)["source_tree_digest"]
        ):
            raise DemoError("installed-byte controller adoption failed")

        started = _controller_result(
            _run_json(
                [
                    *common,
                    "--idempotency-key",
                    "demo-start-attestation",
                    "start",
                    "--rappid",
                    instance_rappid,
                    "--model",
                    ATTESTATION_MODEL,
                    "--attestation-mode",
                    ATTESTATION_MODE,
                ],
                cwd=source,
                env=env,
            )
        )
        if not (
            started.get("status") == "running"
            and started.get("signed_only") is True
            and started.get("attestation_mode") == ATTESTATION_MODE
        ):
            raise DemoError("attestation child did not start signed-only")

        self_test = _controller_result(
            _run_json(
                [
                    *common,
                    "--idempotency-key",
                    "demo-signed-self-test",
                    "self-test",
                    "--rappid",
                    instance_rappid,
                ],
                cwd=source,
                env=env,
            )
        )
        child = self_test.get("child")
        if not (
            self_test.get("passed") is True
            and self_test.get("signed_twin_chat_verified") is True
            and isinstance(child, Mapping)
            and child.get("response") == ""
            and "[SelfTest] completed"
            in str(child.get("agent_logs", "")).splitlines()
        ):
            raise DemoError("signed content-free SelfTest proof failed")

        time.sleep(0.2)
        stop_outer = _run_json(
            [
                *common,
                "--idempotency-key",
                "demo-stop-attestation",
                "stop",
                "--rappid",
                instance_rappid,
            ],
            cwd=source,
            env=env,
        )
        stop_value = stop_outer.get("controller_result")
        stop_error = (
            stop_value.get("error")
            if isinstance(stop_value, Mapping)
            else None
        )
        if (
            isinstance(stop_error, Mapping)
            and stop_error.get("code") == "process_identity_mismatch"
        ):
            time.sleep(0.2)
            stop_outer = _run_json(
                [
                    *common,
                    "--idempotency-key",
                    "demo-stop-attestation-recovery",
                    "stop",
                    "--rappid",
                    instance_rappid,
                ],
                cwd=source,
                env=env,
            )
        stopped_result = _controller_result(stop_outer)
        stopped = stopped_result.get("status") == "stopped"
        archived = _controller_result(
            _run_json(
                [
                    *common,
                    "--idempotency-key",
                    "demo-archive",
                    "archive",
                    "--rappid",
                    instance_rappid,
                ],
                cwd=source,
                env=env,
            )
        )
        unarchived = _controller_result(
            _run_json(
                [
                    *common,
                    "--idempotency-key",
                    "demo-unarchive",
                    "unarchive",
                    "--rappid",
                    instance_rappid,
                ],
                cwd=source,
                env=env,
            )
        )
        status = _controller_result(
            _run_json(
                [
                    *common,
                    "--idempotency-key",
                    "demo-status",
                    "status",
                    "--rappid",
                    instance_rappid,
                ],
                cwd=source,
                env=env,
            )
        )
        no_orphan = (
            status.get("runtime_status") == "stopped"
            and status.get("healthy") is False
        )

        installed_value = verify_install(install_root)
        install_instance_rappid = _rappid(
            installed_value.get("instance_rappid")
        )
        if cleanup:
            _controller_result(
                _run_json(
                    [
                        *common,
                        "--idempotency-key",
                        "demo-cleanup-archive",
                        "archive",
                        "--rappid",
                        instance_rappid,
                    ],
                    cwd=source,
                    env=env,
                )
            )
            purge = _controller_result(
                _run_json(
                    [
                        *common,
                        "--idempotency-key",
                        "demo-cleanup-purge",
                        "purge",
                        "--rappid",
                        instance_rappid,
                        "--confirmation",
                        instance_rappid,
                    ],
                    cwd=source,
                    env=env,
                )
            )
            purged = purge.get("lifecycle_state") == "purged"
        return {
            "controller_authenticated": True,
            "installed_adopted": True,
            "attestation_child_started": True,
            "signed_self_test": True,
            "child_stopped": stopped,
            "archived": archived.get("lifecycle_state") == "archived",
            "unarchived": unarchived.get("lifecycle_state") == "active",
            "no_orphan": no_orphan,
            "controller_instance_rappid": instance_rappid,
            "product_rappid": product_rappid,
            "install_instance_rappid": install_instance_rappid,
            "purged": purged,
        }
    finally:
        if instance_rappid is not None and not stopped and process.poll() is None:
            try:
                _run_json(
                    [
                        str(installed_python),
                        "-m",
                        "rapp_stack_cubby",
                        "controller",
                        "--url",
                        url + "/chat",
                        "--auth-token-file",
                        str(token_file),
                        "--idempotency-key",
                        "demo-rollback-stop",
                        "stop",
                        "--rappid",
                        instance_rappid,
                    ],
                    cwd=source,
                    env=env,
                )
                stopped = True
            except Exception:
                pass
        _terminate_exact_process(process)
        _terminate_recorded_children(state_root)


def run_installed_attestation(
    install_root: Path,
    controller_root: Path,
    *,
    receipt_path: Path,
) -> dict[str, Any]:
    install = install_root.resolve(strict=True)
    controller = Path(controller_root)
    if not controller.is_absolute() or ".." in controller.parts:
        raise DemoError("controller root must be an explicit absolute path")
    controller.mkdir(parents=True, exist_ok=False, mode=0o700)
    receipt = Path(receipt_path)
    if not receipt.is_absolute() or ".." in receipt.parts:
        raise DemoError("attestation receipt must be an explicit absolute path")
    verified = verify_install(install)
    lifecycle = _run_installed_lifecycle(
        install,
        controller,
        cleanup=True,
        trusted_development=False,
    )
    result = {
        "schema": "rapp-installed-offline-attestation/1.0",
        "verified": all(
            lifecycle.get(name) is True
            for name in (
                "controller_authenticated",
                "installed_adopted",
                "attestation_child_started",
                "signed_self_test",
                "child_stopped",
                "no_orphan",
                "purged",
            )
        ),
        "attestation_mode": ATTESTATION_MODE,
        "attestation_model": ATTESTATION_MODEL,
        "signed_only": True,
        "installed_source_digest": verified["source_tree_digest"],
        "orphan_count": 0,
        "published": False,
        "imessage_sent": False,
    }
    _write_receipt(receipt, result)
    if result["verified"] is not True:
        raise DemoError("installed offline attestation failed")
    return result


def _cleanup_install(
    install_root: Path,
    controller_root: Path,
    installed: Mapping[str, Any],
    lifecycle: Mapping[str, Any],
) -> None:
    if not lifecycle.get("purged", False) and (controller_root / "state").exists():
        raise DemoError("controller identity must be purged before uninstall")
    uninstall_twin(
        install_root,
        expected_product_rappid=_rappid(installed.get("product_rappid")),
        expected_instance_rappid=_rappid(installed.get("instance_rappid")),
        confirmation=_rappid(installed.get("instance_rappid")),
        controller_root=controller_root / "state",
    )


def _best_effort_failure_cleanup(
    install_root: Path,
    controller_root: Path,
    run_work: Path,
    installed: Mapping[str, Any] | None,
    lifecycle: Mapping[str, Any],
) -> None:
    _terminate_recorded_children(controller_root / "state")
    if (
        installed is not None
        and install_root.exists()
        and lifecycle.get("purged") is True
    ):
        try:
            _cleanup_install(
                install_root, controller_root, installed, lifecycle
            )
        except Exception:
            pass
    if install_root.exists():
        _remove_tree(install_root)
    _reset_owned_directory(controller_root, strict=False)
    _reset_owned_directory(run_work, strict=False)


def _write_development_trust(root: Path) -> tuple[Path, Path]:
    root.mkdir(mode=0o700)
    key = ec.generate_private_key(ec.SECP256R1())
    key_path = root / "development-signing.pem"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(key_path, 0o600)
    numbers = key.public_key().public_numbers()

    def encoded(value: int) -> str:
        return (
            base64.urlsafe_b64encode(value.to_bytes(32, "big"))
            .rstrip(b"=")
            .decode("ascii")
        )

    jwk = {
        "crv": "P-256",
        "kty": "EC",
        "x": encoded(numbers.x),
        "y": encoded(numbers.y),
    }
    key_id = hashlib.sha256(
        json.dumps(jwk, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()
    trust = {
        "algorithm": "ecdsa-p256-sha256",
        "generation": "ephemeral local development demo",
        "key_id": key_id,
        "profile": "rapp-release-trust/1.0",
        "public_jwk": jwk,
        "schema": "rapp-release-trust/1.0",
    }
    trust_path = root / "development-trust.json"
    trust_path.write_text(
        json.dumps(trust, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.chmod(trust_path, 0o600)
    return key_path, trust_path


def _installed_environment(source: Path, home: Path) -> dict[str, str]:
    return {
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONPATH": str(source / "src"),
    }


def _run_json(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout: float = 180.0,
) -> dict[str, Any]:
    try:
        result = subprocess.run(
            list(argv),
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=dict(env),
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise DemoError("fixed demo subprocess failed") from error
    if (
        result.returncode not in {0, 1}
        or len(result.stdout) > 2 * 1024 * 1024
        or len(result.stderr) > 2 * 1024 * 1024
    ):
        raise DemoError("fixed demo subprocess returned an error")
    try:
        value = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise DemoError("demo subprocess returned invalid JSON") from error
    if not isinstance(value, dict):
        raise DemoError("demo subprocess result must be an object")
    return value


def _controller_result(value: Mapping[str, Any]) -> dict[str, Any]:
    result = value.get("controller_result")
    if not isinstance(result, dict) or result.get("ok") is not True:
        error = result.get("error") if isinstance(result, dict) else None
        code = error.get("code") if isinstance(error, Mapping) else "invalid"
        raise DemoError(f"controller action failed safely: {code}")
    return result


def _wait_controller(
    python: Path,
    source: Path,
    env: Mapping[str, str],
    url: str,
    token_file: Path,
    process: subprocess.Popen[bytes],
) -> None:
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise DemoError("global controller exited during startup")
        try:
            value = _run_json(
                [
                    str(python),
                    "-m",
                    "rapp_stack_cubby",
                    "health",
                    "--url",
                    url + "/health",
                    "--auth-token-file",
                    str(token_file),
                    "--timeout",
                    "2",
                ],
                cwd=source,
                env=env,
                timeout=5.0,
            )
            if value.get("ready") is True:
                return
        except DemoError:
            time.sleep(0.1)
    raise DemoError("global controller did not become ready")


def _terminate_exact_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.getpgid(process.pid) != process.pid:
            raise DemoError("global controller process group identity changed")
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5.0)
    except ProcessLookupError:
        return


def _terminate_recorded_children(state_root: Path) -> None:
    if not state_root.is_dir():
        return
    for state_path in state_root.glob("twins/active/*/state.json"):
        try:
            value = json.loads(state_path.read_text(encoding="utf-8"))
            process = value.get("process")
            pid = process.get("pid") if isinstance(process, dict) else None
            pgid = process.get("pgid") if isinstance(process, dict) else None
            if (
                not isinstance(pid, int)
                or isinstance(pid, bool)
                or pid <= 1
                or pgid != pid
                or os.getpgid(pid) != pid
            ):
                continue
            command = subprocess.run(
                ["/bin/ps", "-p", str(pid), "-o", "command="],
                capture_output=True,
                text=True,
                check=False,
                timeout=5.0,
            )
            if (
                command.returncode == 0
                and "-m rapp_stack_cubby serve" in command.stdout
            ):
                os.killpg(pid, signal.SIGTERM)
        except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError):
            continue


def _assert_equal_trees(first: Path, second: Path) -> None:
    def inventory(root: Path) -> dict[str, str]:
        return {
            path.relative_to(root).as_posix(): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in sorted(root.rglob("*"))
            if path.is_file()
        }

    if inventory(first) != inventory(second):
        raise DemoError("development builds are not byte-identical")


def _absolute_executable(value: Path) -> Path:
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise DemoError("python must be an explicit absolute path")
    resolved = path.resolve(strict=True)
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise DemoError("python must be an executable regular file")
    return resolved


def _private_external_directory(
    repository: Path,
    value: Path,
    *,
    create: bool,
) -> Path:
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise DemoError("demo directories must be explicit absolute paths")
    if create:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    resolved = path.resolve(strict=True)
    if (
        resolved == repository
        or repository in resolved.parents
        or resolved.is_symlink()
        or not resolved.is_dir()
    ):
        raise DemoError("demo directories must be outside the repository")
    os.chmod(resolved, 0o700)
    return resolved


def _external_file(repository: Path, value: Path) -> Path:
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise DemoError("demo receipt must be an explicit absolute path")
    parent = path.parent.resolve(strict=True)
    if parent == repository or repository in parent.parents:
        raise DemoError("demo receipt must be outside the repository")
    return parent / path.name


def _write_marker(root: Path) -> None:
    marker = root / ".demo-owner.json"
    marker.write_text(
        '{"schema":"rapp-stack-cubby-demo-owned/1.0"}\n',
        encoding="utf-8",
    )
    os.chmod(marker, 0o600)


def _reset_owned_directory(path: Path, *, strict: bool = True) -> None:
    if not path.exists() and not path.is_symlink():
        return
    marker = path / ".demo-owner.json"
    owned = False
    try:
        value = json.loads(marker.read_text(encoding="utf-8"))
        owned = value == {"schema": "rapp-stack-cubby-demo-owned/1.0"}
    except (OSError, json.JSONDecodeError):
        owned = False
    if not owned:
        if strict:
            raise DemoError("refuse to remove an unowned demo directory")
        return
    _remove_tree(path)


def _remove_tree(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink():
        path.unlink()
        return
    for directory, names, files in os.walk(path, topdown=True):
        current = Path(directory)
        os.chmod(current, 0o700)
        for name in names:
            child = current / name
            if not child.is_symlink():
                os.chmod(child, 0o700)
        for name in files:
            child = current / name
            if not child.is_symlink():
                os.chmod(child, 0o600)
    shutil.rmtree(path)


def _ephemeral_port() -> int:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])
    finally:
        listener.close()


def _rappid(value: object) -> str:
    if not isinstance(value, str) or not value.startswith("rappid:@"):
        raise DemoError("controller returned an invalid private identity")
    return value


def _write_receipt(path: Path, value: Mapping[str, Any]) -> None:
    payload = (
        json.dumps(value, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    staged = path.parent / f".{path.name}.write-{os.getpid()}"
    if staged.exists() or staged.is_symlink():
        staged.unlink()
    descriptor = os.open(
        staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(staged, path)
    os.chmod(path, 0o600)
