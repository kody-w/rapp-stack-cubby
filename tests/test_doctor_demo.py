from __future__ import annotations

import json
import hashlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from rapp_stack_cubby.cli import main
from rapp_stack_cubby.context import validate_schema_instance
from rapp_stack_cubby.demo import (
    DemoError,
    DemoTestSeam,
    InstalledAttestationError,
    _AttestationDiagnostics,
    _CONTROLLER_ACTION_TIMEOUT_SECONDS,
    _CONTROLLER_CLIENT_CATEGORIES,
    _CONTROLLER_ERROR_CODES,
    _CONTROLLER_STARTUP_TIMEOUT_SECONDS,
    _ControllerActionFailure,
    _ContentFreeProcessFailure,
    _INSTALLED_CHILD_HEALTH_BUDGET_SECONDS,
    _RUN_JSON_SUBPROCESS_TIMEOUT_SECONDS,
    _controller_result,
    _probe_installed_python,
    _run_json,
    _run_installed_lifecycle,
    _validate_host_controller_python,
    _wait_controller,
    run_demo,
    run_installed_attestation,
)
from rapp_stack_cubby.doctor import DoctorError, run_doctor
from rapp_stack_cubby.packaging.hatch import HatchTestSeam
from tests.packaging._support import (
    PackagingWorkspace,
    create_fake_installed_environment,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class DoctorTests(unittest.TestCase):
    def test_default_mode_is_offline_and_live_requires_model(self):
        with tempfile.TemporaryDirectory(
            prefix=".doctor-",
            dir=REPOSITORY_ROOT.parent,
        ) as temporary:
            root = Path(temporary)
            directories = {
                name: root / name
                for name in ("work", "cache", "install", "controller")
            }
            for path in directories.values():
                path.mkdir(mode=0o700)

            calls = []

            def runner(argv, **kwargs):
                calls.append(list(argv))
                if "-c" in argv:
                    return subprocess.CompletedProcess(
                        argv,
                        0,
                        json.dumps(
                            {
                                "python": [3, 11, 15],
                                "packages": {
                                    "cffi": "2.1.0",
                                    "cryptography": "49.0.0",
                                    "pycparser": "3.0",
                                },
                            }
                        ),
                        "",
                    )
                return subprocess.CompletedProcess(argv, 0, "", "")

            with patch(
                "rapp_stack_cubby.doctor.validate_source_manifest"
            ), patch(
                "rapp_stack_cubby.doctor.verify_dependency_cache",
                return_value={"verified": True, "artifact_count": 4},
            ):
                result = run_doctor(
                    REPOSITORY_ROOT,
                    python=Path(sys.executable).resolve(),
                    work_dir=directories["work"],
                    dependency_cache=directories["cache"],
                    install_dir=directories["install"],
                    controller_dir=directories["controller"],
                    runner=runner,
                )
                with self.assertRaises(DoctorError):
                    run_doctor(
                        REPOSITORY_ROOT,
                        python=Path(sys.executable).resolve(),
                        work_dir=directories["work"],
                        dependency_cache=directories["cache"],
                        install_dir=directories["install"],
                        controller_dir=directories["controller"],
                        live=True,
                        runner=runner,
                    )

        self.assertTrue(result["ok"], result)
        self.assertFalse(result["live"]["checked"])
        self.assertFalse(
            any("auth" in " ".join(call) for call in calls)
        )

    def test_live_and_imessage_checks_are_explicit(self):
        with tempfile.TemporaryDirectory(
            prefix=".doctor-modes-",
            dir=REPOSITORY_ROOT.parent,
        ) as temporary:
            root = Path(temporary)
            directories = {
                name: root / name
                for name in ("work", "cache", "install", "controller")
            }
            for path in directories.values():
                path.mkdir(mode=0o700)
            config = root / "imessage.json"
            config.write_text("{}\n", encoding="utf-8")
            config.chmod(0o600)
            github_token = root / "provider-token.json"
            github_token.write_text(
                json.dumps({"access_token": "synthetic-provider-access"})
                + "\n",
                encoding="utf-8",
            )
            github_token.chmod(0o600)

            def runner(argv, **kwargs):
                if "-c" in argv:
                    output = {
                        "python": [3, 11, 15],
                        "packages": {
                            "cffi": "2.1.0",
                            "cryptography": "49.0.0",
                            "pycparser": "3.0",
                        },
                    }
                elif "provider-preflight" in argv:
                    output = {
                        "authenticated": True,
                        "selected_model": "live-model",
                        "selected_model_valid": True,
                        "status": "ok",
                    }
                elif "imessage" in argv and "preflight" in argv:
                    output = {
                        "account_binding_verified": True,
                        "archive_hash_verified": True,
                        "architectures_verified": True,
                        "codesign_verified": True,
                        "layout_verified": True,
                        "read_ready": True,
                        "send_ready": None,
                        "team_verified": True,
                        "version_verified": True,
                    }
                else:
                    output = {}
                return subprocess.CompletedProcess(
                    argv, 0, json.dumps(output), ""
                )

            with patch(
                "rapp_stack_cubby.doctor.validate_source_manifest"
            ), patch(
                "rapp_stack_cubby.doctor.verify_dependency_cache",
                return_value={"verified": True, "artifact_count": 4},
            ):
                result = run_doctor(
                    REPOSITORY_ROOT,
                    python=Path(sys.executable).resolve(),
                    work_dir=directories["work"],
                    dependency_cache=directories["cache"],
                    install_dir=directories["install"],
                    controller_dir=directories["controller"],
                    live=True,
                    model="live-model",
                    github_token_file=github_token,
                    imessage=True,
                    imessage_config=config,
                    runner=runner,
                )

        self.assertTrue(result["ok"], result)
        self.assertTrue(result["live"]["model_valid"])
        self.assertEqual(result["live"]["status"], "ok")
        self.assertTrue(result["imessage"]["fda_read_ready"])
        self.assertIsNone(result["imessage"]["automation_ready"])


class ProductDemoTests(unittest.TestCase):
    def test_fixture_demo_covers_transitions_receipt_and_cleanup(self):
        with PackagingWorkspace() as workspace:
            source, cache = workspace.copy_repository_with_fake_dependencies()
            work = workspace.root / "demo-work"
            install = workspace.root / "demo-install"
            controller = workspace.root / "demo-controller"
            receipt = workspace.root / "demo-receipt.json"
            for path in (work, install, controller):
                path.mkdir(mode=0o700)

            def lifecycle(install_root, controller_root):
                del install_root
                (controller_root / "state").mkdir(mode=0o700)
                return {
                    "controller_authenticated": True,
                    "installed_adopted": True,
                    "attestation_child_started": True,
                    "signed_self_test": True,
                    "child_stopped": True,
                    "archived": True,
                    "unarchived": True,
                    "no_orphan": True,
                    "purged": True,
                }

            before_home = os.environ.get("HOME")
            with patch.dict(os.environ, {}, clear=True):
                seam = DemoTestSeam(
                    hatch=HatchTestSeam(
                        create_fake_installed_environment
                    ),
                    lifecycle=lifecycle,
                    skip_repository_checks=True,
                )
                for _attempt in range(2):
                    result = run_demo(
                        source,
                        python=Path(sys.executable).resolve(),
                        work_dir=work,
                        dependency_cache=cache,
                        install_dir=install,
                        controller_dir=controller,
                        receipt_path=receipt,
                        cleanup=True,
                        test_seam=seam,
                    )

            value = json.loads(receipt.read_text(encoding="utf-8"))
            self.assertTrue(result["ok"], result)
            self.assertTrue(all(result["stages"].values()))
            self.assertEqual(value["schema"], "rapp-product-demo-receipt/1.0")
            self.assertFalse(value["imessage_sent"])
            self.assertFalse(value["published"])
            self.assertEqual(
                value["diagnostics"]["child_health_attempts"], 0
            )
            self.assertEqual(
                value["diagnostics"]["child_health_last_category"],
                "not_attempted",
            )
            schema_path = (
                REPOSITORY_ROOT / "schemas/demo-receipt.schema.json"
            )
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            self.assertFalse(
                validate_schema_instance(
                    value, schema, schema_path=schema_path
                )
            )
            self.assertNotIn("HOME", receipt.read_text(encoding="utf-8"))
            self.assertEqual(os.environ.get("HOME"), before_home)
            self.assertFalse((install / "rapp-stack-cubby-demo").exists())

    def test_demo_uses_selected_python_for_installed_lifecycle_host(self):
        with tempfile.TemporaryDirectory(
            prefix=".demo-host-python-",
            dir=REPOSITORY_ROOT.parent,
        ) as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir(mode=0o700)
            directories = {
                name: root / name
                for name in ("work", "cache", "install", "controller")
            }
            for path in directories.values():
                path.mkdir(mode=0o700)
            selected_python = Path(sys.executable).resolve(strict=True)
            source_digest = "a" * 64
            lifecycle_result = {
                "controller_authenticated": True,
                "installed_adopted": True,
                "attestation_child_started": True,
                "signed_self_test": True,
                "child_stopped": True,
                "archived": True,
                "unarchived": True,
                "no_orphan": True,
                "purged": False,
            }

            def build_release(
                source,
                cache,
                output,
                **kwargs,
            ):
                del source, cache, kwargs
                output.mkdir(mode=0o700)
                (output / "rapp-stack-cubby.egg").write_bytes(b"fixture")
                return {
                    "release_manifest_sha256": "b" * 64,
                    "source_tree_digest": source_digest,
                }

            def hatch(
                egg,
                install_root,
                python,
                **kwargs,
            ):
                del egg, kwargs
                self.assertEqual(python, selected_python)
                install_root.mkdir(mode=0o700)
                return {"source_tree_digest": source_digest}

            lifecycle = Mock(return_value=lifecycle_result)
            with patch(
                "rapp_stack_cubby.demo.verify_repository",
                return_value=Mock(ok=True),
            ), patch(
                "rapp_stack_cubby.demo.context_summary"
            ), patch(
                "rapp_stack_cubby.demo.check_pages",
                return_value=Mock(ok=True),
            ), patch(
                "rapp_stack_cubby.demo.validate_source_manifest"
            ), patch(
                "rapp_stack_cubby.demo.verify_dependency_cache",
                return_value={"verified": True},
            ), patch(
                "rapp_stack_cubby.demo._write_development_trust",
                return_value=(root / "key", root / "trust"),
            ), patch(
                "rapp_stack_cubby.demo.build_release",
                side_effect=build_release,
            ), patch(
                "rapp_stack_cubby.demo.verify_release",
                return_value={
                    "development_only": True,
                    "release": False,
                    "signed": True,
                    "verified": True,
                },
            ), patch(
                "rapp_stack_cubby.demo.verify_artifact",
                return_value={"artifact_type": "cubby-egg"},
            ), patch(
                "rapp_stack_cubby.demo.hatch_egg",
                side_effect=hatch,
            ), patch(
                "rapp_stack_cubby.demo.verify_install",
                return_value={"source_tree_digest": source_digest},
            ), patch(
                "rapp_stack_cubby.demo._run_installed_lifecycle",
                lifecycle,
            ):
                receipt_path = root / "receipt.json"
                result = run_demo(
                    repository,
                    python=selected_python,
                    work_dir=directories["work"],
                    dependency_cache=directories["cache"],
                    install_dir=directories["install"],
                    controller_dir=directories["controller"],
                    receipt_path=receipt_path,
                )
                serialized = receipt_path.read_text(encoding="utf-8")

        self.assertTrue(result["ok"])
        diagnostic = lifecycle.call_args.kwargs["diagnostics"]
        self.assertIsInstance(diagnostic, _AttestationDiagnostics)
        self.assertEqual(result["diagnostics"], diagnostic.public())
        self.assertEqual(
            lifecycle.call_args.kwargs["host_controller_python"],
            selected_python,
        )
        for forbidden in (
            str(root),
            str(selected_python),
            "controller.log",
            "port",
            "token",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_demo_failure_receipt_has_only_fixed_diagnostics(self):
        arbitrary_detail = (
            "opaque exception content that must never be serialized"
        )
        with PackagingWorkspace() as workspace:
            source, cache = workspace.copy_repository_with_fake_dependencies()
            work = workspace.root / "demo-failure-work"
            install = workspace.root / "demo-failure-install"
            controller = workspace.root / "demo-failure-controller"
            receipt = workspace.root / "demo-failure-receipt.json"
            for path in (work, install, controller):
                path.mkdir(mode=0o700)

            def fail_lifecycle(install_root, controller_root):
                del install_root, controller_root
                raise RuntimeError(arbitrary_detail)

            seam = DemoTestSeam(
                hatch=HatchTestSeam(create_fake_installed_environment),
                lifecycle=fail_lifecycle,
                skip_repository_checks=True,
            )
            with self.assertRaisesRegex(
                DemoError, "product demo failed safely"
            ):
                run_demo(
                    source,
                    python=Path(sys.executable).resolve(),
                    work_dir=work,
                    dependency_cache=cache,
                    install_dir=install,
                    controller_dir=controller,
                    receipt_path=receipt,
                    cleanup=True,
                    test_seam=seam,
                )
            value = json.loads(receipt.read_text(encoding="utf-8"))

        expected_keys = {
            "child_stage",
            "child_health_attempts",
            "child_health_last_category",
            "child_health_timeout_seconds",
            "child_process_category",
            "child_process_return_code",
            "child_stdout_size",
            "child_stdout_sha256",
            "child_stderr_size",
            "child_stderr_sha256",
            "controller_client_category",
            "controller_client_return_code",
            "controller_log_sha256",
            "controller_log_size",
            "controller_error_code",
            "process_category",
            "process_return_code",
            "stage_code",
        }
        schema_path = REPOSITORY_ROOT / "schemas/demo-receipt.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertFalse(value["ok"])
        self.assertEqual(value["failure_code"], "demo_failed")
        self.assertEqual(set(value["diagnostics"]), expected_keys)
        self.assertFalse(
            validate_schema_instance(value, schema, schema_path=schema_path)
        )
        serialized = json.dumps(value)
        for forbidden in (
            arbitrary_detail,
            str(workspace.root),
        ):
            self.assertNotIn(forbidden, serialized)


class InstalledAttestationTests(unittest.TestCase):
    def test_host_python_is_canonicalized_before_controller_override(self):
        with tempfile.TemporaryDirectory(
            prefix=".attestation-host-python-",
            dir=REPOSITORY_ROOT.parent,
        ) as temporary:
            root = Path(temporary)
            linked = root / "python"
            linked.symlink_to(Path(sys.executable).resolve(strict=True))
            runner = Mock(
                return_value=subprocess.CompletedProcess([], 0)
            )
            selected = _validate_host_controller_python(
                linked,
                home=root,
                runner=runner,
            )

        self.assertEqual(
            selected, Path(sys.executable).resolve(strict=True)
        )
        self.assertFalse(selected.is_symlink())
        self.assertEqual(runner.call_args.args[0][0], str(selected))
        self.assertEqual(
            runner.call_args.args[0][1:3], ["-I", "-S"]
        )

    def test_child_start_diagnostics_are_size_hash_and_status_only(self):
        secret_stdout = b"private child stdout payload\n"
        secret_stderr = b"private child stderr payload\n"
        identity_hash = "d" * 64
        rappid = f"rappid:@kody-w/child:{identity_hash}"
        with tempfile.TemporaryDirectory(
            prefix=".attestation-child-diagnostics-",
            dir=REPOSITORY_ROOT.parent,
        ) as temporary:
            state_root = Path(temporary)
            twin = state_root / "twins/active" / identity_hash
            logs = twin / "workspace/logs"
            logs.mkdir(parents=True)
            (logs / "stdout.log").write_bytes(secret_stdout)
            (logs / "stderr.log").write_bytes(secret_stderr)
            (twin / "state.json").write_text(
                json.dumps(
                    {
                        "last_start_failure": {
                            "health_timeout_seconds": 75.0,
                            "health_attempts": 5,
                            "health_last_category": "response_invalid",
                            "process_category": "exited_nonzero",
                            "process_return_code": 72,
                        }
                    }
                ),
                encoding="utf-8",
            )
            diagnostic = _AttestationDiagnostics(
                stage_code="child_start",
                child_stage="adopted",
            )
            diagnostic.capture_child_start(state_root, rappid)
            public = diagnostic.public()

        self.assertEqual(
            public["child_process_category"], "exited_nonzero"
        )
        self.assertEqual(public["child_process_return_code"], 72)
        self.assertEqual(
            public["child_health_timeout_seconds"], 75.0
        )
        self.assertEqual(public["child_health_attempts"], 5)
        self.assertEqual(
            public["child_health_last_category"], "response_invalid"
        )
        self.assertEqual(
            public["child_stdout_size"], len(secret_stdout)
        )
        self.assertEqual(
            public["child_stdout_sha256"],
            hashlib.sha256(secret_stdout).hexdigest(),
        )
        self.assertEqual(
            public["child_stderr_size"], len(secret_stderr)
        )
        self.assertEqual(
            public["child_stderr_sha256"],
            hashlib.sha256(secret_stderr).hexdigest(),
        )
        serialized = json.dumps(public)
        self.assertNotIn(secret_stdout.decode().strip(), serialized)
        self.assertNotIn(secret_stderr.decode().strip(), serialized)
        schema = json.loads(
            (
                REPOSITORY_ROOT
                / "schemas/installed-offline-attestation.schema.json"
            ).read_text(encoding="utf-8")
        )
        properties = schema["properties"]["diagnostics"]["properties"]
        self.assertEqual(
            set(properties["child_health_last_category"]["enum"]),
            {
                "not_attempted",
                "transport_unavailable",
                "response_invalid",
                "status_not_ok",
                "not_ready",
                "instance_mismatch",
                "ready",
            },
        )
        self.assertEqual(properties["child_health_attempts"]["minimum"], 0)
        self.assertEqual(properties["child_health_attempts"]["maximum"], 75)

    def test_child_health_diagnostics_reject_unvalidated_state_values(self):
        identity_hash = "e" * 64
        rappid = f"rappid:@kody-w/child:{identity_hash}"
        arbitrary_category = "opaque-health-category-content"
        with tempfile.TemporaryDirectory(
            prefix=".attestation-invalid-health-",
            dir=REPOSITORY_ROOT.parent,
        ) as temporary:
            state_root = Path(temporary)
            twin = state_root / "twins/active" / identity_hash
            twin.mkdir(parents=True)
            (twin / "state.json").write_text(
                json.dumps(
                    {
                        "process": {
                            "health_attempts": True,
                            "health_last_category": arbitrary_category,
                            "health_timeout_seconds": 75.0,
                        }
                    }
                ),
                encoding="utf-8",
            )
            diagnostic = _AttestationDiagnostics()
            diagnostic.capture_child_start(state_root, rappid)
            public = diagnostic.public()

        self.assertEqual(public["child_health_attempts"], 0)
        self.assertEqual(
            public["child_health_last_category"], "not_attempted"
        )
        self.assertNotIn(arbitrary_category, json.dumps(public))

    def test_child_health_diagnostics_capture_starting_process(self):
        identity_hash = "f" * 64
        rappid = f"rappid:@kody-w/child:{identity_hash}"
        with tempfile.TemporaryDirectory(
            prefix=".attestation-starting-health-",
            dir=REPOSITORY_ROOT.parent,
        ) as temporary:
            state_root = Path(temporary)
            twin = state_root / "twins/active" / identity_hash
            twin.mkdir(parents=True)
            (twin / "state.json").write_text(
                json.dumps(
                    {
                        "runtime_status": "starting",
                        "process": {
                            "health_attempts": 5,
                            "health_last_category": "transport_unavailable",
                            "health_timeout_seconds": 75.0,
                        },
                    }
                ),
                encoding="utf-8",
            )
            diagnostic = _AttestationDiagnostics()
            diagnostic.capture_child_start(state_root, rappid)
            public = diagnostic.public()

        self.assertEqual(public["child_health_attempts"], 5)
        self.assertEqual(
            public["child_health_last_category"],
            "transport_unavailable",
        )
        self.assertEqual(public["child_health_timeout_seconds"], 75.0)

    def test_controller_failure_code_is_typed_allowlisted_and_redacted(self):
        arbitrary_code = "opaque-controller-detail"
        arbitrary_message = "private controller rejection detail"
        diagnostic = _AttestationDiagnostics()

        with self.assertRaises(_ControllerActionFailure) as raised:
            _controller_result(
                {
                    "controller_result": {
                        "error": {
                            "code": arbitrary_code,
                            "message": arbitrary_message,
                        },
                        "ok": False,
                    }
                }
            )
        diagnostic.observe_error(raised.exception)
        public = diagnostic.public()
        serialized = json.dumps(public)

        self.assertEqual(
            raised.exception.controller_error_code,
            "unclassified",
        )
        self.assertEqual(str(raised.exception), "controller_action_failed")
        self.assertIn(
            raised.exception.controller_error_code,
            _CONTROLLER_ERROR_CODES,
        )
        self.assertEqual(public["controller_error_code"], "unclassified")
        self.assertNotIn(arbitrary_code, serialized)
        self.assertNotIn(arbitrary_message, serialized)
        schema = json.loads(
            (
                REPOSITORY_ROOT
                / "schemas/installed-offline-attestation.schema.json"
            ).read_text(encoding="utf-8")
        )
        schema_codes = set(
            schema["properties"]["diagnostics"]["properties"][
                "controller_error_code"
            ]["enum"]
        )
        self.assertEqual(
            schema_codes,
            {*_CONTROLLER_ERROR_CODES, None},
        )
        with self.assertRaises(_ControllerActionFailure) as malformed:
            _controller_result({})
        self.assertEqual(
            malformed.exception.controller_error_code,
            "unclassified",
        )

    def test_controller_client_failure_is_independent_and_finite(self):
        diagnostic = _AttestationDiagnostics(
            process_category="running",
            process_return_code=None,
        )
        failure = _ContentFreeProcessFailure(
            "exited_nonzero",
            return_code=23,
        )

        diagnostic.observe_error(failure)
        public = diagnostic.public()

        self.assertEqual(
            failure.controller_client_category,
            "exited_nonzero",
        )
        self.assertEqual(failure.controller_client_return_code, 23)
        self.assertEqual(
            public["controller_client_category"],
            "exited_nonzero",
        )
        self.assertEqual(public["controller_client_return_code"], 23)
        self.assertEqual(public["process_category"], "running")
        self.assertIsNone(public["process_return_code"])
        schema = json.loads(
            (
                REPOSITORY_ROOT
                / "schemas/installed-offline-attestation.schema.json"
            ).read_text(encoding="utf-8")
        )
        schema_categories = set(
            schema["properties"]["diagnostics"]["properties"][
                "controller_client_category"
            ]["enum"]
        )
        self.assertEqual(
            schema_categories,
            set(_CONTROLLER_CLIENT_CATEGORIES),
        )
        unknown = _ContentFreeProcessFailure(
            "private-arbitrary-category",
            return_code=True,
        )
        self.assertEqual(
            unknown.controller_client_category,
            "status_unavailable",
        )
        self.assertIsNone(unknown.controller_client_return_code)

    def test_controller_action_timeout_bounds_child_health_and_process(self):
        self.assertEqual(_INSTALLED_CHILD_HEALTH_BUDGET_SECONDS, 75.0)
        self.assertEqual(_CONTROLLER_ACTION_TIMEOUT_SECONDS, 90.0)
        self.assertEqual(_RUN_JSON_SUBPROCESS_TIMEOUT_SECONDS, 180.0)
        self.assertGreater(
            _CONTROLLER_ACTION_TIMEOUT_SECONDS,
            _INSTALLED_CHILD_HEALTH_BUDGET_SECONDS,
        )
        self.assertLess(
            _CONTROLLER_ACTION_TIMEOUT_SECONDS,
            _RUN_JSON_SUBPROCESS_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            _run_json.__kwdefaults__["timeout"],
            _RUN_JSON_SUBPROCESS_TIMEOUT_SECONDS,
        )

    def test_controller_readiness_allows_cold_start_within_bound(self):
        elapsed = 0.0
        probe_times: list[float] = []
        process = Mock()
        process.poll.return_value = None

        def clock() -> float:
            return elapsed

        def pause(delay: float) -> None:
            nonlocal elapsed
            elapsed += delay

        def probe(remaining: float) -> bool:
            self.assertGreater(remaining, 0.0)
            probe_times.append(elapsed)
            return elapsed > 15.0

        _wait_controller(
            Path("/python"),
            Path("/source"),
            {},
            "http://127.0.0.1:1",
            Path("/token"),
            process,
            clock=clock,
            probe=probe,
            pause=pause,
        )

        self.assertGreater(elapsed, 15.0)
        self.assertLess(elapsed, _CONTROLLER_STARTUP_TIMEOUT_SECONDS)
        self.assertEqual(probe_times[-1], elapsed)

    def test_controller_readiness_times_out_at_named_bound(self):
        elapsed = 0.0
        process = Mock()
        process.poll.return_value = None
        probe = Mock(return_value=False)

        def clock() -> float:
            return elapsed

        def pause(delay: float) -> None:
            nonlocal elapsed
            elapsed += delay

        with self.assertRaisesRegex(
            DemoError,
            "global controller did not become ready",
        ):
            _wait_controller(
                Path("/python"),
                Path("/source"),
                {},
                "http://127.0.0.1:1",
                Path("/token"),
                process,
                clock=clock,
                probe=probe,
                pause=pause,
            )

        self.assertEqual(elapsed, _CONTROLLER_STARTUP_TIMEOUT_SECONDS)
        self.assertEqual(
            probe.call_count,
            int(_CONTROLLER_STARTUP_TIMEOUT_SECONDS),
        )

    def test_controller_readiness_fails_fast_when_process_exited(self):
        process = Mock()
        process.poll.return_value = 9
        probe = Mock(side_effect=AssertionError("probe must not run"))
        pause = Mock(side_effect=AssertionError("pause must not run"))

        with self.assertRaisesRegex(
            DemoError,
            "global controller exited during startup",
        ):
            _wait_controller(
                Path("/python"),
                Path("/source"),
                {},
                "http://127.0.0.1:1",
                Path("/token"),
                process,
                clock=lambda: 0.0,
                probe=probe,
                pause=pause,
            )

        probe.assert_not_called()
        pause.assert_not_called()

    def test_global_controller_argv_uses_explicit_host_python(self):
        with tempfile.TemporaryDirectory(
            prefix=".attestation-host-",
            dir=REPOSITORY_ROOT.parent,
        ) as temporary:
            root = Path(temporary)
            install = root / "install"
            controller = root / "controller"
            for path in (
                install / "source",
                install / "state/home",
                controller,
            ):
                path.mkdir(parents=True, mode=0o700)
            token = controller / "auth/token.json"
            host_python = Path(sys.executable)
            installed_python = install / "venv/bin/python"
            source_digest = "a" * 64
            instance = "rappid:@kody-w/attestation:" + "b" * 64
            product = "rappid:@kody-w/product:" + "c" * 64
            installed_instance = "rappid:@kody-w/installed:" + "d" * 64
            calls: list[list[str]] = []

            def run_json(argv, **kwargs):
                del kwargs
                command = list(argv)
                calls.append(command)
                if "controller-auth" in command:
                    token.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    token.write_text("{}\n", encoding="utf-8")
                    token.chmod(0o600)
                    return {"token_file": str(token)}
                result: dict[str, object] = {"ok": True}
                if "adopt" in command:
                    result.update(
                        {
                            "adopted": True,
                            "instance_rappid": instance,
                            "product_rappid": product,
                            "source_tree_digest": source_digest,
                        }
                    )
                elif "start" in command:
                    result.update(
                        {
                            "attestation_mode": "offline-self-test",
                            "signed_only": True,
                            "status": "running",
                        }
                    )
                elif "self-test" in command:
                    result.update(
                        {
                            "child": {
                                "agent_logs": "[SelfTest] completed",
                                "response": "",
                            },
                            "passed": True,
                            "signed_twin_chat_verified": True,
                        }
                    )
                elif "demo-stop-attestation" in command:
                    return {
                        "controller_result": {
                            "error": {
                                "code": "process_identity_mismatch",
                                "message": (
                                    "The recorded process no longer belongs "
                                    "to this twin."
                                ),
                            },
                            "ok": False,
                        }
                    }
                elif "stop" in command:
                    result["status"] = "stopped"
                elif "unarchive" in command:
                    result["lifecycle_state"] = "active"
                elif "purge" in command:
                    result["lifecycle_state"] = "purged"
                elif "archive" in command:
                    result["lifecycle_state"] = "archived"
                elif "status" in command:
                    result.update(
                        {"healthy": False, "runtime_status": "stopped"}
                    )
                return {"controller_result": result}

            process = Mock(pid=71001)
            process.poll.return_value = None
            verified = {
                "instance_rappid": installed_instance,
                "source_tree_digest": source_digest,
            }
            with patch(
                "rapp_stack_cubby.demo._validate_host_controller_python",
                return_value=host_python,
            ), patch(
                "rapp_stack_cubby.demo._probe_installed_python"
            ) as probe, patch(
                "rapp_stack_cubby.demo.verify_install",
                return_value=verified,
            ), patch(
                "rapp_stack_cubby.demo._run_json",
                side_effect=run_json,
            ), patch(
                "rapp_stack_cubby.demo.subprocess.Popen",
                return_value=process,
            ) as popen, patch(
                "rapp_stack_cubby.demo._wait_controller"
            ) as wait, patch(
                "rapp_stack_cubby.demo._terminate_exact_process"
            ), patch(
                "rapp_stack_cubby.demo._terminate_recorded_children"
            ), patch(
                "rapp_stack_cubby.demo.time.sleep"
            ):
                result = _run_installed_lifecycle(
                    install,
                    controller,
                    cleanup=True,
                    trusted_development=False,
                    host_controller_python=host_python,
                )

        self.assertTrue(result["purged"])
        self.assertTrue(calls)
        self.assertTrue(
            all(command[0] == str(host_python) for command in calls)
        )
        adopt_call = next(command for command in calls if "adopt" in command)
        self.assertEqual(
            adopt_call[adopt_call.index("--attestation-python") + 1],
            str(host_python),
        )
        self.assertEqual(popen.call_args.args[0][0], str(host_python))
        self.assertEqual(
            popen.call_args.kwargs["env"]["PYTHONUNBUFFERED"],
            "1",
        )
        self.assertEqual(wait.call_args.args[0], host_python)
        self.assertEqual(probe.call_args.args[0], installed_python)
        lifecycle_calls = [
            command for command in calls if "controller" in command
        ]
        expected_keys = {
            "demo-adopt-installed",
            "demo-start-attestation",
            "demo-signed-self-test",
            "demo-stop-attestation",
            "demo-stop-attestation-recovery",
            "demo-archive",
            "demo-unarchive",
            "demo-status",
            "demo-cleanup-archive",
            "demo-cleanup-purge",
        }
        self.assertEqual(len(lifecycle_calls), len(expected_keys))
        self.assertEqual(
            {
                command[command.index("--idempotency-key") + 1]
                for command in lifecycle_calls
            },
            expected_keys,
        )
        for command in lifecycle_calls:
            self.assertEqual(command.count("--timeout"), 1)
            self.assertEqual(
                command[command.index("--timeout") + 1],
                f"{_CONTROLLER_ACTION_TIMEOUT_SECONDS:g}",
            )

    def test_controller_start_rejection_rolls_back_with_explicit_timeout(self):
        with tempfile.TemporaryDirectory(
            prefix=".attestation-rollback-timeout-",
            dir=REPOSITORY_ROOT.parent,
        ) as temporary:
            root = Path(temporary)
            install = root / "install"
            controller = root / "controller"
            for path in (
                install / "source",
                install / "state/home",
                controller,
            ):
                path.mkdir(parents=True, mode=0o700)
            token = controller / "auth/token.json"
            host_python = Path(sys.executable)
            source_digest = "a" * 64
            instance = "rappid:@kody-w/attestation:" + "b" * 64
            product = "rappid:@kody-w/product:" + "c" * 64
            diagnostic = _AttestationDiagnostics()
            calls: list[list[str]] = []

            def run_json(argv, **kwargs):
                del kwargs
                command = list(argv)
                calls.append(command)
                if "controller-auth" in command:
                    token.parent.mkdir(
                        parents=True, exist_ok=True, mode=0o700
                    )
                    token.write_text("{}\n", encoding="utf-8")
                    token.chmod(0o600)
                    return {"token_file": str(token)}
                if "adopt" in command:
                    return {
                        "controller_result": {
                            "adopted": True,
                            "instance_rappid": instance,
                            "ok": True,
                            "product_rappid": product,
                            "source_tree_digest": source_digest,
                        }
                    }
                if "start" in command:
                    twin = (
                        controller
                        / "state/twins/active"
                        / instance.rsplit(":", 1)[-1]
                    )
                    twin.mkdir(parents=True, mode=0o700)
                    (twin / "state.json").write_text(
                        json.dumps(
                            {
                                "runtime_status": "starting",
                                "process": {
                                    "health_attempts": 5,
                                    "health_last_category": (
                                        "response_invalid"
                                    ),
                                    "health_timeout_seconds": 75.0,
                                },
                            }
                        ),
                        encoding="utf-8",
                    )
                    return {
                        "controller_result": {
                            "error": {
                                "code": "health_failed",
                                "message": "private child startup detail",
                            },
                            "ok": False,
                        }
                    }
                if "demo-rollback-stop" in command:
                    return {
                        "controller_result": {
                            "ok": True,
                            "status": "stopped",
                        }
                    }
                raise AssertionError("unexpected lifecycle command")

            process = Mock(pid=71003)
            process.poll.return_value = None
            with patch(
                "rapp_stack_cubby.demo._validate_host_controller_python",
                return_value=host_python,
            ), patch(
                "rapp_stack_cubby.demo._probe_installed_python"
            ), patch(
                "rapp_stack_cubby.demo.verify_install",
                return_value={
                    "instance_rappid": (
                        "rappid:@kody-w/installed:" + "d" * 64
                    ),
                    "source_tree_digest": source_digest,
                },
            ), patch(
                "rapp_stack_cubby.demo._run_json",
                side_effect=run_json,
            ), patch(
                "rapp_stack_cubby.demo.subprocess.Popen",
                return_value=process,
            ), patch(
                "rapp_stack_cubby.demo._wait_controller"
            ), patch(
                "rapp_stack_cubby.demo._terminate_exact_process"
            ), patch(
                "rapp_stack_cubby.demo._terminate_recorded_children"
            ), self.assertRaises(_ControllerActionFailure) as raised:
                _run_installed_lifecycle(
                    install,
                    controller,
                    cleanup=True,
                    trusted_development=False,
                    host_controller_python=host_python,
                    diagnostics=diagnostic,
                )

        rollback = next(
            command
            for command in calls
            if "demo-rollback-stop" in command
        )
        self.assertEqual(rollback.count("--timeout"), 1)
        self.assertEqual(
            rollback[rollback.index("--timeout") + 1],
            f"{_CONTROLLER_ACTION_TIMEOUT_SECONDS:g}",
        )
        self.assertEqual(
            raised.exception.controller_error_code,
            "health_failed",
        )
        self.assertEqual(
            diagnostic.public()["controller_error_code"],
            "health_failed",
        )
        self.assertEqual(
            diagnostic.public()["child_health_attempts"], 5
        )
        self.assertEqual(
            diagnostic.public()["child_health_last_category"],
            "response_invalid",
        )
        self.assertNotIn(
            "private child startup detail",
            json.dumps(diagnostic.public()),
        )

    def test_invalid_host_python_is_rejected_without_execution(self):
        with tempfile.TemporaryDirectory(
            prefix=".attestation-invalid-host-",
            dir=REPOSITORY_ROOT.parent,
        ) as temporary:
            root = Path(temporary)
            install = root / "install"
            install.mkdir(mode=0o700)
            receipt = root / "receipt.json"
            with patch(
                "rapp_stack_cubby.demo.verify_install",
                return_value={"source_tree_digest": "a" * 64},
            ) as verify, self.assertRaises(
                InstalledAttestationError
            ) as raised:
                run_installed_attestation(
                    install,
                    root / "controller",
                    host_controller_python=Path("python3.11"),
                    receipt_path=receipt,
                )
            value = json.loads(receipt.read_text(encoding="utf-8"))

        verify.assert_called_once_with(install)
        self.assertEqual(
            raised.exception.diagnostics["stage_code"],
            "host_python_validation",
        )
        self.assertFalse(value["verified"])

    def test_installed_python_probe_is_isolated_and_fails_closed(self):
        with tempfile.TemporaryDirectory(
            prefix=".attestation-probe-",
            dir=REPOSITORY_ROOT.parent,
        ) as temporary:
            root = Path(temporary)
            source = root / "source"
            home = root / "home"
            python = root / "venv/bin/python"
            for path in (source, home, python.parent):
                path.mkdir(parents=True, exist_ok=True, mode=0o700)
            python.write_bytes(b"fixture")
            python.chmod(0o700)
            runner = Mock(
                return_value=subprocess.CompletedProcess([], 9)
            )
            with self.assertRaises(_ContentFreeProcessFailure) as raised:
                _probe_installed_python(
                    python,
                    source=source,
                    home=home,
                    runner=runner,
                )

        argv = runner.call_args.args[0]
        self.assertEqual(argv, [str(python), "-I", "-S", "-c", "pass"])
        self.assertIs(runner.call_args.kwargs["stdout"], subprocess.DEVNULL)
        self.assertIs(runner.call_args.kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(
            raised.exception.controller_client_return_code,
            9,
        )
        self.assertEqual(
            raised.exception.controller_client_category,
            "exited_nonzero",
        )

    def test_readiness_failure_receipt_and_cli_diagnostics_are_redacted(self):
        secret = b"message=private key=secret account-id=private-id\n"
        with tempfile.TemporaryDirectory(
            prefix=".attestation-redaction-",
            dir=REPOSITORY_ROOT.parent,
        ) as temporary:
            root = Path(temporary)
            install = root / "install"
            for path in (install / "source", install / "state/home"):
                path.mkdir(parents=True, mode=0o700)
            controller = root / "controller"
            receipt = root / "receipt.json"
            token = root / "controller-token.json"
            host_python = Path(sys.executable)
            process = Mock(pid=71002)
            process.poll.return_value = None

            def run_json(argv, **kwargs):
                del argv, kwargs
                token.write_text("{}\n", encoding="utf-8")
                token.chmod(0o600)
                return {"token_file": str(token)}

            def spawn(argv, **kwargs):
                del argv
                output = kwargs["stdout"]
                output.write(secret)
                output.flush()
                return process

            output = io.StringIO()
            errors = io.StringIO()
            with patch(
                "rapp_stack_cubby.demo._validate_host_controller_python",
                return_value=host_python,
            ), patch(
                "rapp_stack_cubby.demo._probe_installed_python"
            ), patch(
                "rapp_stack_cubby.demo.verify_install",
                return_value={
                    "instance_rappid": "rappid:@kody-w/install:" + "e" * 64,
                    "source_tree_digest": "f" * 64,
                },
            ), patch(
                "rapp_stack_cubby.demo._run_json",
                side_effect=run_json,
            ), patch(
                "rapp_stack_cubby.demo.subprocess.Popen",
                side_effect=spawn,
            ), patch(
                "rapp_stack_cubby.demo._wait_controller",
                side_effect=DemoError(secret.decode("ascii")),
            ), patch(
                "rapp_stack_cubby.demo._terminate_exact_process"
            ), patch(
                "rapp_stack_cubby.demo._terminate_recorded_children"
            ), redirect_stdout(output), redirect_stderr(errors):
                status = main(
                    [
                        "attest-installed",
                        "--install-root",
                        str(install),
                        "--host-python",
                        str(host_python),
                        "--controller-dir",
                        str(controller),
                        "--receipt",
                        str(receipt),
                    ]
                )

            value = json.loads(receipt.read_text(encoding="utf-8"))
            diagnostic = value["diagnostics"]
            emitted = json.loads(errors.getvalue())
            combined = receipt.read_text(encoding="utf-8") + errors.getvalue()
            receipt_mode = receipt.stat().st_mode & 0o777

        self.assertEqual(status, 2)
        self.assertEqual(output.getvalue(), "")
        self.assertFalse(value["verified"])
        self.assertEqual(emitted, diagnostic)
        self.assertEqual(
            set(diagnostic),
            {
                "child_stage",
                "child_health_attempts",
                "child_health_last_category",
                "child_health_timeout_seconds",
                "child_process_category",
                "child_process_return_code",
                "child_stdout_size",
                "child_stdout_sha256",
                "child_stderr_size",
                "child_stderr_sha256",
                "controller_client_category",
                "controller_client_return_code",
                "controller_log_sha256",
                "controller_log_size",
                "controller_error_code",
                "process_category",
                "process_return_code",
                "stage_code",
            },
        )
        self.assertEqual(diagnostic["stage_code"], "controller_readiness")
        self.assertEqual(diagnostic["child_stage"], "not_adopted")
        self.assertIsNone(diagnostic["controller_error_code"])
        self.assertEqual(
            diagnostic["controller_client_category"],
            "not_started",
        )
        self.assertIsNone(diagnostic["controller_client_return_code"])
        self.assertIsNone(diagnostic["child_health_timeout_seconds"])
        self.assertEqual(diagnostic["child_health_attempts"], 0)
        self.assertEqual(
            diagnostic["child_health_last_category"], "not_attempted"
        )
        self.assertEqual(
            diagnostic["child_process_category"], "not_started"
        )
        self.assertIsNone(diagnostic["child_process_return_code"])
        self.assertEqual(diagnostic["child_stdout_size"], 0)
        self.assertEqual(diagnostic["child_stderr_size"], 0)
        self.assertEqual(diagnostic["process_category"], "running")
        self.assertIsNone(diagnostic["process_return_code"])
        self.assertEqual(diagnostic["controller_log_size"], len(secret))
        self.assertEqual(
            diagnostic["controller_log_sha256"],
            hashlib.sha256(secret).hexdigest(),
        )
        self.assertEqual(receipt_mode, 0o600)
        for forbidden in (
            secret.decode("ascii").strip(),
            str(controller),
            str(token),
            "private-id",
            "key=secret",
        ):
            self.assertNotIn(forbidden, combined)


if __name__ == "__main__":
    unittest.main()
