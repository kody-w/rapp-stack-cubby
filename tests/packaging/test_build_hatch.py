from __future__ import annotations

import json
import hashlib
import inspect
import os
import shutil
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from rapp_stack_cubby.packaging.builder import (
    CHECKSUMS_NAME,
    EGG_ARCHIVE_NAME,
    RELEASE_MANIFEST_NAME,
    SBOM_NAME,
    STORE_ARCHIVE_NAME,
    _file_provenance,
    build_release,
    verify_artifact,
)
from rapp_stack_cubby.packaging.common import PackagingError, copy_verified_file
from rapp_stack_cubby.packaging.hatch import (
    HatchTestSeam,
    hatch_egg,
    uninstall_preview,
    uninstall_twin,
    verify_install,
)
from rapp_stack_cubby.packaging import hatch as hatch_module
from rapp_stack_cubby.packaging.source import (
    scan_source_tree,
    validate_source_manifest,
)

from ._support import PackagingWorkspace, create_fake_installed_environment


class BuildAndHatchTests(unittest.TestCase):
    EPOCH = 1783892570

    def test_production_venv_uses_copied_python_for_self_containment(self):
        source = inspect.getsource(hatch_module._create_environment)
        self.assertIn('"--copies"', source)
        self.assertIn('"--without-pip"', source)
        self.assertIn('"--target"', source)
        self.assertIn('"--no-compile"', source)

    def test_target_install_removes_dependency_console_scripts(self):
        site = self.workspace.root / "target-site"
        dist_info = site / "example-1.0.dist-info"
        scripts = site / "bin"
        dist_info.mkdir(parents=True)
        scripts.mkdir()
        (scripts / "example-cli").write_text("not executed\n", encoding="utf-8")
        record = dist_info / "RECORD"
        record.write_text(
            "../../bin/example-cli,,\n"
            "example-1.0.dist-info/RECORD,,\n",
            encoding="utf-8",
        )

        hatch_module._remove_target_scripts(site)

        self.assertFalse(scripts.exists())
        self.assertEqual(
            record.read_text(encoding="utf-8"),
            "example-1.0.dist-info/RECORD,,\n",
        )

    def setUp(self):
        self.workspace = PackagingWorkspace()
        self.workspace.__enter__()
        self.source, self.cache = (
            self.workspace.copy_repository_with_fake_dependencies()
        )

    def tearDown(self):
        self.workspace.__exit__(None, None, None)

    def _build(self, name):
        output = self.workspace.root / name
        result = build_release(
            self.source,
            self.cache,
            output,
            source_date_epoch=self.EPOCH,
            source_revision="WORKTREE",
        )
        return output, result

    def test_complete_build_is_reproducible_and_development_only(self):
        first, first_result = self._build("first")
        second, second_result = self._build("second")
        self.assertTrue(first_result["development_only"])
        self.assertFalse(first_result["release"])
        self.assertEqual(
            first_result["source_tree_digest"],
            second_result["source_tree_digest"],
        )
        first_files = sorted(path.name for path in first.iterdir())
        second_files = sorted(path.name for path in second.iterdir())
        self.assertEqual(first_files, second_files)
        for name in first_files:
            self.assertEqual(
                (first / name).read_bytes(), (second / name).read_bytes(), name
            )
        release = json.loads((first / RELEASE_MANIFEST_NAME).read_text())
        self.assertEqual(release["source_commit"], "WORKTREE")
        self.assertTrue(release["development_only"])
        self.assertFalse(release["signed"])
        self.assertIn(STORE_ARCHIVE_NAME, (first / CHECKSUMS_NAME).read_text())
        sbom = json.loads((first / SBOM_NAME).read_text())
        self.assertEqual(sbom["spdxVersion"], "SPDX-2.3")
        relationships = {
            (
                item["spdxElementId"],
                item["relationshipType"],
                item["relatedSpdxElement"],
            )
            for item in sbom["relationships"]
        }
        package_ids = {item["name"]: item["SPDXID"] for item in sbom["packages"]}
        root_id = package_ids["rapp-stack-cubby"]
        external_ids = set(package_ids.values()) - {root_id}
        self.assertEqual(
            {
                related
                for source, kind, related in relationships
                if source == root_id and kind == "DEPENDS_ON"
            },
            external_ids,
        )
        file_ids = {item["SPDXID"] for item in sbom["files"]}
        self.assertEqual(
            {
                related
                for source, kind, related in relationships
                if source == root_id and kind == "CONTAINS"
            },
            file_ids,
        )
        adapted = [
            item
            for item in sbom["files"]
            if "Adapted from kody-w/openrappter"
            in item.get("fileComment", "")
        ]
        self.assertEqual(len(adapted), 6)
        for item in adapted:
            self.assertEqual(item["licenseConcluded"], "MIT")
            self.assertIn("OpenRappter-MIT.txt", item["fileComment"])
            self.assertEqual(item["copyrightText"], "Copyright (c) 2025 Kody W")
            self.assertEqual(item["licenseInfoInFiles"], ["NOASSERTION"])

        by_name = {item["fileName"]: item for item in sbom["files"]}
        project_license = by_name["./LICENSE"]
        self.assertEqual(project_license["licenseConcluded"], "MIT")
        self.assertEqual(project_license["licenseInfoInFiles"], ["MIT"])
        self.assertEqual(
            project_license["copyrightText"],
            "Copyright (c) 2026 Kody Wildfeuer",
        )
        original_without_header = by_name[
            "./src/rapp_stack_cubby/census_refresh.py"
        ]
        self.assertEqual(original_without_header["licenseConcluded"], "MIT")
        self.assertEqual(
            original_without_header["licenseInfoInFiles"],
            ["NOASSERTION"],
        )
        self.assertEqual(
            original_without_header["copyrightText"],
            "Copyright (c) 2026 Kody Wildfeuer",
        )
        openrappter_license = by_name[
            "./THIRD_PARTY_LICENSES/OpenRappter-MIT.txt"
        ]
        self.assertEqual(openrappter_license["licenseInfoInFiles"], ["MIT"])
        self.assertEqual(
            openrappter_license["copyrightText"],
            "Copyright (c) 2025 Kody W",
        )
        imsg_license = by_name["./THIRD_PARTY_LICENSES/imsg-MIT.txt"]
        self.assertEqual(imsg_license["licenseInfoInFiles"], ["MIT"])
        self.assertEqual(
            imsg_license["copyrightText"],
            "Copyright (c) 2026 Peter Steinberger",
        )
        raw_snapshot = by_name[
            "./docs/research/public-account-snapshot.json"
        ]
        self.assertEqual(raw_snapshot["licenseConcluded"], "NOASSERTION")
        self.assertEqual(raw_snapshot["copyrightText"], "NOASSERTION")
        self.assertGreater(
            len({item["copyrightText"] for item in sbom["files"]}),
            3,
        )
        self.assertTrue(
            any(
                item["licenseInfoInFiles"] == ["NOASSERTION"]
                for item in sbom["files"]
            )
        )

    def test_root_dist_build_uses_clean_deterministic_source_snapshot(self):
        baseline = validate_source_manifest(self.source)
        output = self.source / "dist"
        first = build_release(
            self.source,
            self.cache,
            output,
            source_date_epoch=self.EPOCH,
            source_revision="WORKTREE",
        )
        first_artifacts = {
            path.name: path.read_bytes()
            for path in output.iterdir()
        }
        self.assertEqual(validate_source_manifest(self.source), baseline)
        self.assertEqual(
            scan_source_tree(self.source)["source_tree_digest"],
            baseline["source_tree_digest"],
        )
        self.assertEqual(list(self.source.glob(".dist.build-*")), [])

        shutil.rmtree(output)
        second = build_release(
            self.source,
            self.cache,
            output,
            source_date_epoch=self.EPOCH,
            source_revision="WORKTREE",
        )
        self.assertEqual(first["source_tree_digest"], second["source_tree_digest"])
        self.assertEqual(
            first_artifacts,
            {path.name: path.read_bytes() for path in output.iterdir()},
        )
        self.assertEqual(validate_source_manifest(self.source), baseline)

    def test_worktree_mutation_during_snapshot_fails_before_output_staging(self):
        output = self.workspace.root / "mutation-output"
        target = self.source / "README.md"
        real_copy = copy_verified_file

        def mutate_then_copy(source, destination, **arguments):
            if source == target:
                target.write_text("moved during snapshot\n", encoding="utf-8")
            return real_copy(source, destination, **arguments)

        with patch(
            "rapp_stack_cubby.packaging.immutable.copy_verified_file",
            side_effect=mutate_then_copy,
        ), self.assertRaisesRegex(
            PackagingError,
            "does not match its record",
        ):
            build_release(
                self.source,
                self.cache,
                output,
                source_date_epoch=self.EPOCH,
                source_revision="WORKTREE",
            )
        self.assertFalse(output.exists())
        self.assertEqual(list(self.workspace.root.glob(".mutation-output.build-*")), [])
        self.assertEqual(
            list(self.workspace.root.glob(".mutation-output.builder-*")),
            [],
        )

    def test_per_file_provenance_rejects_adapted_blob_tamper(self):
        provenance_path = self.source / "PROVENANCE.json"
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        target = next(
            item
            for item in provenance["entries"]
            if item["id"] == "target-rapp-stack-cubby"
        )
        record = next(
            item
            for item in target["source_file_provenance"]["files"]
            if item["path"] == "src/rapp_stack_cubby/imessage/bridge.py"
        )
        record["source_blob"] = "0" * 40
        provenance_path.write_text(
            json.dumps(provenance, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            PackagingError,
            "adapted provenance does not cross-bind",
        ):
            _file_provenance(self.source, scan_source_tree(self.source))

    def test_store_and_egg_include_complete_context_and_locked_archives(self):
        output, _ = self._build("artifacts")
        store = verify_artifact(output / STORE_ARCHIVE_NAME)
        egg = verify_artifact(output / EGG_ARCHIVE_NAME)
        self.assertEqual(store["artifact_type"], "store-rapplication")
        self.assertEqual(egg["artifact_type"], "cubby-egg")
        with zipfile.ZipFile(output / STORE_ARCHIVE_NAME) as archive:
            names = set(archive.namelist())
        for required in (
            "rapp-stack/source/AI_CONTEXT.md",
            "rapp-stack/source/CONTEXT_INDEX.json",
            "rapp-stack/source/src/rapp_stack_cubby/runtime/app.py",
            "rapp-stack/source/tests/packaging/test_build_hatch.py",
            "rapp-stack/wheelhouse/cryptography-49.0.0-cp311-abi3-macosx_11_0_arm64.whl",
            "rapp-stack/vendor/imsg/imsg-macos.zip",
            "rapp-stack/singleton/rapp_stack_cubby_agent.py",
        ):
            self.assertIn(required, names)
        self.assertFalse(any("/dist/" in name or "/.git/" in name for name in names))
        self.assertFalse(
            any(
                "__pycache__" in name
                or any(
                    part.casefold().endswith(".egg-info")
                    for part in Path(name).parts
                )
                for name in names
            )
        )

    @staticmethod
    def _fake_environment(stage: Path, python: Path, application: Path):
        return create_fake_installed_environment(stage, python, application)

    def test_egg_hatches_atomically_and_verifies_without_starting(self):
        output, _ = self._build("hatch-artifacts")
        install = self.workspace.root / "installed"
        result = hatch_egg(
            output / EGG_ARCHIVE_NAME,
            install,
            Path(os.path.realpath(os.sys.executable)),
            expected_egg_sha256=hashlib.sha256(
                (output / EGG_ARCHIVE_NAME).read_bytes()
            ).hexdigest(),
            test_seam=HatchTestSeam(self._fake_environment),
        )
        self.assertTrue(result["verified"])
        self.assertFalse(result["started"])
        self.assertEqual(
            verify_install(
                install,
                verify_dependencies=False,
                allow_test_environment=True,
            )["rappid"],
            result["rappid"],
        )
        manifest = json.loads((install / "installed-twin.json").read_text())
        self.assertTrue(manifest["isolation"]["dedicated_virtual_environment"])
        self.assertEqual(
            (install / "source/AI_CONTEXT.md").read_bytes(),
            (self.source / "AI_CONTEXT.md").read_bytes(),
        )
        self.assertEqual(
            uninstall_preview(install)["action"],
            "preview-only",
        )
        with self.assertRaises(PackagingError):
            hatch_egg(
                output / EGG_ARCHIVE_NAME,
                install,
                Path(os.path.realpath(os.sys.executable)),
                expected_egg_sha256=hashlib.sha256(
                    (output / EGG_ARCHIVE_NAME).read_bytes()
                ).hexdigest(),
                test_seam=HatchTestSeam(self._fake_environment),
            )

    def test_hatch_rolls_back_when_injected_environment_fails(self):
        output, _ = self._build("rollback-artifacts")
        install = self.workspace.root / "failed-install"

        def fail(stage, python, application):
            del stage, python, application
            raise RuntimeError("synthetic failure")

        with self.assertRaises(RuntimeError):
            hatch_egg(
                output / EGG_ARCHIVE_NAME,
                install,
                Path(os.path.realpath(os.sys.executable)),
                expected_egg_sha256=hashlib.sha256(
                    (output / EGG_ARCHIVE_NAME).read_bytes()
                ).hexdigest(),
                test_seam=HatchTestSeam(fail),
            )
        self.assertFalse(install.exists())
        self.assertEqual(
            list(self.workspace.root.glob(".failed-install.hatch-*")), []
        )

    def test_hatch_removes_install_and_loadout_stage_when_promotion_fails(self):
        output, _ = self._build("loadout-rollback-artifacts")
        egg = output / EGG_ARCHIVE_NAME
        install = self.workspace.root / "loadout-failed-install"
        loadout = self.workspace.root / "loadout-target"
        real_replace = os.replace

        def fail_loadout(source, destination):
            if Path(destination) == loadout:
                raise OSError("synthetic loadout promotion failure")
            return real_replace(source, destination)

        with patch(
            "rapp_stack_cubby.packaging.hatch.os.replace",
            side_effect=fail_loadout,
        ), self.assertRaises(OSError):
            hatch_egg(
                egg,
                install,
                Path(os.path.realpath(os.sys.executable)),
                expected_egg_sha256=hashlib.sha256(egg.read_bytes()).hexdigest(),
                controller_loadout_root=loadout,
                test_seam=HatchTestSeam(self._fake_environment),
            )
        self.assertFalse(install.exists())
        self.assertFalse(loadout.exists())
        self.assertEqual(
            list(self.workspace.root.glob(".loadout-target.hatch-*")), []
        )

    def test_static_install_inventory_detects_python_record_package_imsg_and_mode(self):
        output, _ = self._build("tamper-artifacts")
        egg = output / EGG_ARCHIVE_NAME
        install = self.workspace.root / "tamper-install"
        hatch_egg(
            egg,
            install,
            Path(os.path.realpath(os.sys.executable)),
            expected_egg_sha256=hashlib.sha256(egg.read_bytes()).hexdigest(),
            test_seam=HatchTestSeam(self._fake_environment),
        )

        def assert_tamper(relative, mutate):
            clone = self.workspace.root / (
                "tamper-" + relative.replace("/", "-").replace(".", "-")
            )
            shutil.copytree(install, clone, symlinks=True)
            path = clone / relative
            mutate(path)

            def must_not_execute(*args, **kwargs):
                raise AssertionError("static verification must precede execution")

            with self.assertRaises(PackagingError):
                verify_install(
                    clone,
                    verify_dependencies=True,
                    allow_test_environment=True,
                    runner=must_not_execute,
                )

        def overwrite_text(path, value):
            path.chmod(0o600)
            path.write_text(value, encoding="utf-8")

        def overwrite_bytes(path, value):
            path.chmod(0o600)
            path.write_bytes(value)

        assert_tamper(
            "venv/bin/python",
            lambda path: overwrite_text(path, "#!/bin/sh\nexit 1\n"),
        )
        assert_tamper(
            "venv/lib/python3.11/site-packages/cffi/__init__.py",
            lambda path: overwrite_text(path, "tampered\n"),
        )
        assert_tamper(
            "venv/lib/python3.11/site-packages/cffi-2.1.0.dist-info/RECORD",
            lambda path: overwrite_text(path, "tampered,,\n"),
        )
        assert_tamper(
            "artifacts/wheelhouse/"
            "cffi-2.1.0-cp311-cp311-macosx_11_0_arm64.whl",
            lambda path: overwrite_bytes(path, b"tampered wheel"),
        )
        assert_tamper(
            "state/tools/imsg/0.12.3/imsg",
            lambda path: overwrite_text(path, "tampered tool\n"),
        )
        assert_tamper(
            "source/README.md",
            lambda path: path.chmod(0o644),
        )

    def test_exhaustive_inventory_rejects_pth_extras_links_modes_and_pycache(self):
        output, _ = self._build("exhaustive-inventory-artifacts")
        egg = output / EGG_ARCHIVE_NAME
        install = self.workspace.root / "exhaustive-inventory-install"
        hatch_egg(
            egg,
            install,
            Path(os.path.realpath(os.sys.executable)),
            expected_egg_sha256=hashlib.sha256(egg.read_bytes()).hexdigest(),
            test_seam=HatchTestSeam(self._fake_environment),
        )
        site_relative = Path("venv/lib/python3.11/site-packages")

        def add_file(root, relative, content):
            path = root / relative
            ancestor = path.parent
            missing = []
            while not ancestor.exists():
                missing.append(ancestor)
                ancestor = ancestor.parent
            ancestor.chmod(0o755)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.parent.chmod(0o755)
            path.write_text(content, encoding="utf-8")
            path.chmod(0o444)
            for directory in missing:
                directory.chmod(0o555)
            ancestor.chmod(0o555)

        mutations = {
            "extra-package": lambda root, sentinel: add_file(
                root, site_relative / "surprise/__init__.py", "value = 1\n"
            ),
            "extra-imsg": lambda root, sentinel: add_file(
                root, Path("state/tools/imsg/0.12.3/extra.txt"), "extra\n"
            ),
            "extra-script": lambda root, sentinel: add_file(
                root, Path("venv/bin/surprise"), "#!/bin/sh\nexit 0\n"
            ),
            "pycache": lambda root, sentinel: add_file(
                root,
                site_relative / "cffi/__pycache__/__init__.cpython-311.pyc",
                "not bytecode\n",
            ),
            "pth": lambda root, sentinel: add_file(
                root,
                site_relative / "execute-me.pth",
                "import pathlib; pathlib.Path("
                + repr(str(sentinel))
                + ").write_text('executed')\n",
            ),
            "writable-mode": lambda root, sentinel: (
                root / "venv/bin/python"
            ).chmod(0o755),
        }

        def alter_link(root, sentinel):
            del sentinel
            link = root / "state/tools/bin/imsg"
            link.parent.chmod(0o755)
            link.unlink()
            link.symlink_to("../../../../venv/bin/python")
            link.parent.chmod(0o555)

        mutations["symlink-target"] = alter_link
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                clone = self.workspace.root / f"inventory-{name}"
                shutil.copytree(install, clone, symlinks=True)
                sentinel = self.workspace.root / f"{name}-executed"
                mutate(clone, sentinel)

                def must_not_execute(*args, **kwargs):
                    raise AssertionError(
                        "installed targets must not execute during verification"
                    )

                with self.assertRaises(PackagingError):
                    verify_install(
                        clone,
                        verify_dependencies=True,
                        allow_test_environment=True,
                        runner=must_not_execute,
                    )
                self.assertFalse(sentinel.exists())

    def test_uninstall_is_identity_bound_checks_references_and_journals(self):
        output, _ = self._build("uninstall-artifacts")
        egg = output / EGG_ARCHIVE_NAME
        install = self.workspace.root / "uninstall-install"
        installed = hatch_egg(
            egg,
            install,
            Path(os.path.realpath(os.sys.executable)),
            expected_egg_sha256=hashlib.sha256(egg.read_bytes()).hexdigest(),
            test_seam=HatchTestSeam(self._fake_environment),
        )
        controller = self.workspace.root / "controller"
        controller.mkdir()
        arguments = {
            "expected_product_rappid": installed["product_rappid"],
            "expected_instance_rappid": installed["instance_rappid"],
            "confirmation": installed["instance_rappid"],
            "controller_root": controller,
        }
        dry = uninstall_twin(install, dry_run=True, **arguments)
        self.assertEqual(dry["action"], "dry-run")
        self.assertTrue(install.exists())
        with self.assertRaises(PackagingError):
            uninstall_twin(
                install,
                dry_run=True,
                **{**arguments, "confirmation": installed["product_rappid"]},
            )
        reference = controller / "twins/state.json"
        reference.parent.mkdir()
        reference.write_text(
            json.dumps({"adopted_install": {"root": str(install)}}),
            encoding="utf-8",
        )
        with self.assertRaises(PackagingError):
            uninstall_twin(install, dry_run=True, **arguments)
        reference.unlink()
        process = install / "state/process.json"
        process.write_text(
            json.dumps({"pid": os.getpid(), "status": "running"}),
            encoding="utf-8",
        )
        with self.assertRaises(PackagingError):
            uninstall_twin(install, dry_run=True, **arguments)
        process.unlink()
        result = uninstall_twin(install, dry_run=False, **arguments)
        self.assertEqual(result["action"], "deleted")
        self.assertFalse(install.exists())
        journal = json.loads(Path(result["journal"]).read_text(encoding="utf-8"))
        self.assertEqual(journal["phase"], "deleted")


if __name__ == "__main__":
    unittest.main()
