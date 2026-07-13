from __future__ import annotations

import os
import hashlib
import stat
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from rapp_stack_cubby.packaging.builder import (
    EGG_ARCHIVE_NAME,
    RELEASE_MANIFEST_NAME,
    build_release,
)
from rapp_stack_cubby.packaging.hatch import HatchTestSeam, hatch_egg
from rapp_stack_cubby.packaging.release import verify_release
from tests.packaging._support import (
    PackagingWorkspace,
    create_fake_installed_environment,
)
from tests.packaging.test_release_security import _write_key_and_trust

from ._support import ControllerEnvironment, decoded


class ControllerAdoptionTests(unittest.TestCase):
    @staticmethod
    def _fake_environment(stage: Path, python: Path, application: Path):
        return create_fake_installed_environment(stage, python, application)

    def test_verified_install_adopts_distinct_instance_and_tamper_blocks_start(self):
        with PackagingWorkspace() as packaging:
            source, cache = packaging.copy_repository_with_fake_dependencies()
            artifacts = packaging.root / "artifacts"
            build_release(
                source,
                cache,
                artifacts,
                source_date_epoch=1783892570,
                source_revision="WORKTREE",
            )
            install = packaging.root / "installed"
            installed = hatch_egg(
                artifacts / EGG_ARCHIVE_NAME,
                install,
                Path(os.path.realpath(os.sys.executable)),
                expected_egg_sha256=hashlib.sha256(
                    (artifacts / EGG_ARCHIVE_NAME).read_bytes()
                ).hexdigest(),
                test_seam=HatchTestSeam(self._fake_environment),
            )
            with ControllerEnvironment() as environment, patch.dict(
                environment.globals,
                {
                    "_probe_installed_dependencies": (
                        lambda python, root: {
                            "cffi": "2.1.0",
                            "cryptography": "49.0.0",
                            "pycparser": "3.0",
                        }
                    )
                },
            ):
                adopted = decoded(
                    environment.agent,
                    action="adopt_install",
                    install_root=str(install),
                    idempotency_key="adopt-verified",
                )
                replay = decoded(
                    environment.agent,
                    action="adopt_install",
                    install_root=str(install),
                    idempotency_key="adopt-verified",
                )
                self.assertTrue(adopted["ok"], adopted)
                self.assertTrue(replay["idempotent_replay"])
                self.assertNotEqual(
                    adopted["instance_rappid"], installed["instance_rappid"]
                )
                self.assertNotEqual(
                    adopted["instance_rappid"], adopted["product_rappid"]
                )
                provider_token = environment.create_provider_token()

                child = Mock()
                child.pid = 60010
                child.poll.return_value = None
                with patch.object(
                    environment.globals["subprocess"],
                    "Popen",
                    return_value=child,
                ) as popen, patch.object(
                    environment.globals["os"],
                    "getpgid",
                    side_effect=lambda pid: pid,
                ), patch.dict(
                    environment.globals,
                    {
                        "_validate_python": (
                            lambda selected=None: str(selected)
                        ),
                        "_preflight_model": (
                            lambda python, runtime_source, model, token: model
                        ),
                        "_process_start_identity": lambda pid: "c" * 64,
                        "_wait_health": lambda port, instance, timeout: True,
                    },
                ):
                    started = decoded(
                        environment.agent,
                        action="start",
                        rappid=adopted["instance_rappid"],
                        model="explicit-model",
                        github_token_file=str(provider_token),
                        idempotency_key="start-adoption",
                    )
                self.assertTrue(started["ok"], started)
                active = (
                    environment.controller_data
                    / "twins/active"
                    / adopted["identity_hash"]
                )
                self.assertEqual(
                    popen.call_args.args[0][0],
                    str(active / "runtime/venv/bin/python"),
                )

                manifest = install / "source/README.md"
                os.chmod(manifest, 0o644)
                manifest.write_text("tampered\n", encoding="utf-8")
                rejected_adoption = decoded(
                    environment.agent,
                    action="adopt_install",
                    install_root=str(install),
                    idempotency_key="adopt-tampered",
                )
                self.assertFalse(rejected_adoption["ok"])
                self.assertEqual(
                    rejected_adoption["error"]["code"], "adopt_invalid"
                )

                copied = active / "source/README.md"
                copied.write_text("tampered active copy\n", encoding="utf-8")
                blocked_start = decoded(
                    environment.agent,
                    action="start",
                    rappid=adopted["instance_rappid"],
                    model="explicit-model",
                    github_token_file=str(provider_token),
                    idempotency_key="start-tampered-adoption",
                )
                self.assertFalse(blocked_start["ok"])
                self.assertEqual(
                    blocked_start["error"]["code"], "source_mismatch"
                )

    def test_unverified_install_path_is_rejected(self):
        with ControllerEnvironment() as environment:
            unverified = environment.root / "unverified"
            unverified.mkdir()
            result = decoded(
                environment.agent,
                action="adopt_install",
                install_root=str(unverified),
                idempotency_key="adopt-unverified",
            )
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "adopt_invalid")

    def test_signed_development_bytes_flow_through_verify_hatch_adopt_start(self):
        with PackagingWorkspace() as packaging:
            source, cache = packaging.copy_repository_with_fake_dependencies()
            key = _write_key_and_trust(
                source, packaging.root / "chain-private"
            )
            artifacts = packaging.root / "chain-artifacts"
            built = build_release(
                source,
                cache,
                artifacts,
                source_date_epoch=1783892570,
                source_revision="WORKTREE",
                signing_key=key,
            )
            release = verify_release(
                artifacts / RELEASE_MANIFEST_NAME,
                expected_manifest_sha256=built["release_manifest_sha256"],
                trust_path=source / "RELEASE_TRUST.json",
                source_root=source,
            )
            egg = artifacts / EGG_ARCHIVE_NAME
            install = packaging.root / "chain-install"
            hatch_egg(
                egg,
                install,
                Path(os.path.realpath(os.sys.executable)),
                expected_egg_sha256=hashlib.sha256(egg.read_bytes()).hexdigest(),
                release_verification=release,
                test_seam=HatchTestSeam(self._fake_environment),
            )
            with ControllerEnvironment() as environment, patch.dict(
                environment.globals,
                {
                    "_probe_installed_dependencies": (
                        lambda python, root: {
                            "cffi": "2.1.0",
                            "cryptography": "49.0.0",
                            "pycparser": "3.0",
                        }
                    )
                },
            ):
                adopted = decoded(
                    environment.agent,
                    action="adopt_install",
                    install_root=str(install),
                    idempotency_key="signed-chain-adopt",
                )
                self.assertTrue(adopted["ok"], adopted)
                provider_token = environment.create_provider_token()
                child = Mock(pid=60123)
                child.poll.return_value = None
                with patch.object(
                    environment.globals["subprocess"],
                    "Popen",
                    return_value=child,
                ), patch.object(
                    environment.globals["os"],
                    "getpgid",
                    return_value=60123,
                ), patch.dict(
                    environment.globals,
                    {
                        "_validate_python": lambda selected=None: str(selected),
                        "_preflight_model": (
                            lambda python, runtime_source, model, token: model
                        ),
                        "_process_start_identity": lambda pid: "d" * 64,
                        "_wait_health": lambda port, instance, timeout: True,
                    },
                ):
                    started = decoded(
                        environment.agent,
                        action="start",
                        rappid=adopted["instance_rappid"],
                        model="fixture-model",
                        github_token_file=str(provider_token),
                        idempotency_key="signed-chain-start",
                    )
                self.assertTrue(started["ok"], started)

    def test_adoption_recovers_every_persisted_boundary(self):
        with PackagingWorkspace() as packaging:
            source, cache = packaging.copy_repository_with_fake_dependencies()
            artifacts = packaging.root / "recovery-artifacts"
            build_release(
                source,
                cache,
                artifacts,
                source_date_epoch=1783892570,
                source_revision="WORKTREE",
            )
            install = packaging.root / "recovery-install"
            hatch_egg(
                artifacts / EGG_ARCHIVE_NAME,
                install,
                Path(os.path.realpath(os.sys.executable)),
                expected_egg_sha256=hashlib.sha256(
                    (artifacts / EGG_ARCHIVE_NAME).read_bytes()
                ).hexdigest(),
                test_seam=HatchTestSeam(self._fake_environment),
            )
            for phase in ("verified", "prepared", "promoted", "completed"):
                with self.subTest(phase=phase), ControllerEnvironment() as environment:
                    fired = False

                    def boundary(action, observed):
                        nonlocal fired
                        if (
                            action == "adopt_install"
                            and observed == phase
                            and not fired
                        ):
                            fired = True
                            raise RuntimeError("transition_failed")

                    base = {
                        "_probe_installed_dependencies": (
                            lambda python, root: {
                                "cffi": "2.1.0",
                                "cryptography": "49.0.0",
                                "pycparser": "3.0",
                            }
                        )
                    }
                    arguments = {
                        "action": "adopt_install",
                        "install_root": str(install),
                        "idempotency_key": f"adopt-{phase}",
                    }
                    with patch.dict(
                        environment.globals,
                        {**base, "_transition_boundary": boundary},
                    ):
                        first = decoded(environment.agent, **arguments)
                    self.assertFalse(first["ok"])
                    with patch.dict(environment.globals, base):
                        recovered = decoded(environment.agent, **arguments)
                    self.assertTrue(recovered["ok"], recovered)


if __name__ == "__main__":
    unittest.main()
