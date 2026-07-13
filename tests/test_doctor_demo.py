from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rapp_stack_cubby.demo import DemoTestSeam, run_demo
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
            self.assertNotIn("HOME", receipt.read_text(encoding="utf-8"))
            self.assertEqual(os.environ.get("HOME"), before_home)
            self.assertFalse((install / "rapp-stack-cubby-demo").exists())


if __name__ == "__main__":
    unittest.main()
