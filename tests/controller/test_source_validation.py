from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from ._support import ControllerEnvironment, REPOSITORY_ROOT


class ControllerSourceValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.environment = ControllerEnvironment()
        self.environment.__enter__()
        self.globals = self.environment.globals
        self.temporary = tempfile.TemporaryDirectory(
            prefix=".test-controller-source-",
            dir=REPOSITORY_ROOT,
        )
        self.source = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()
        self.environment.__exit__(None, None, None)

    def test_repository_and_commit_validation_fail_closed(self):
        validate_url = self.globals["validate_repository_url"]
        validate_commit = self.globals["validate_commit"]
        allowed = "https://github.com/kody-w/rapp-stack-cubby"

        self.assertEqual(
            validate_url(allowed),
            "https://github.com/kody-w/rapp-stack-cubby.git",
        )
        self.assertEqual(validate_url(allowed + ".git"), allowed + ".git")
        for value in (
            "http://github.com/kody-w/rapp-stack-cubby.git",
            "https://github.com/kody-w/other.git",
            "https://github.com/kody-w/rapp-stack-cubby.git?ref=main",
            "https://github.com/kody-w/rapp-stack-cubby.git#main",
            "https://github.com:443/kody-w/rapp-stack-cubby.git",
            "******github.com/kody-w/rapp-stack-cubby.git",
            "git@github.com:kody-w/rapp-stack-cubby.git",
            "file:///checkout",
        ):
            with self.subTest(value=value):
                with self.assertRaises(RuntimeError):
                    validate_url(value)
        self.assertEqual(validate_commit("a" * 40), "a" * 40)
        for value in ("main", "A" * 40, "a" * 39, "a" * 41):
            with self.assertRaises(RuntimeError):
                validate_commit(value)

    def test_tree_digest_is_deterministic_and_content_sensitive(self):
        (self.source / "z.txt").write_text("z\n", encoding="utf-8")
        (self.source / "nested").mkdir()
        (self.source / "nested/a.txt").write_text("a\n", encoding="utf-8")
        digest = self.globals["deterministic_tree_digest"](self.source)
        os.utime(self.source / "z.txt", (1, 1))

        self.assertEqual(
            self.globals["deterministic_tree_digest"](self.source),
            digest,
        )
        (self.source / "z.txt").write_text("changed\n", encoding="utf-8")
        self.assertNotEqual(
            self.globals["deterministic_tree_digest"](self.source),
            digest,
        )

    def test_symlink_special_forbidden_executable_count_and_size_rejected(self):
        scan = self.globals["scan_source_tree"]
        target = self.source / "target"
        target.write_text("x", encoding="utf-8")
        link = self.source / "link"
        link.symlink_to(target)
        with self.assertRaises(RuntimeError):
            scan(self.source)
        link.unlink()

        fifo = self.source / "pipe"
        os.mkfifo(fifo)
        with self.assertRaises(RuntimeError):
            scan(self.source)
        fifo.unlink()

        forbidden = self.source / ".env"
        forbidden.write_text("TOKEN=x", encoding="utf-8")
        with self.assertRaises(RuntimeError):
            scan(self.source)
        forbidden.unlink()

        executable = self.source / "unexpected.sh"
        executable.write_text("#!/bin/sh\n", encoding="utf-8")
        executable.chmod(0o755)
        scanned = scan(self.source)
        self.assertTrue(
            next(
                item
                for item in scanned["files"]
                if item["path"] == "unexpected.sh"
            )["executable"]
        )
        executable.chmod(0o600)

        with patch.dict(
            self.globals,
            {"_MAX_SOURCE_FILES": 1},
        ):
            with self.assertRaises(RuntimeError):
                scan(self.source)
        with patch.dict(
            self.globals,
            {"_MAX_SOURCE_FILE_BYTES": 0},
        ):
            with self.assertRaises(RuntimeError):
                scan(self.source)

    def test_release_manifest_rejects_hash_extra_and_missing_files(self):
        (self.source / "one.txt").write_text("one\n", encoding="utf-8")
        (self.source / "two.txt").write_text("two\n", encoding="utf-8")
        scan = self.globals["scan_source_tree"](self.source)
        manifest = {
            "exclusions": {
                "generated_release_assets": True,
                "manifest_self": "rapp-release-source-manifest.json",
                "private_and_runtime_state": True,
                "repository_metadata_and_caches": True,
            },
            "schema": "rapp-release-source-manifest/1.0",
            "repository_url": (
                "https://github.com/kody-w/rapp-stack-cubby.git"
            ),
            "file_count": scan["file_count"],
            "source_tree_digest": scan["tree_digest"],
            "total_bytes": scan["total_bytes"],
            "files": scan["files"],
        }
        path = self.source / "rapp-release-source-manifest.json"
        path.write_text(
            json.dumps(manifest, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        validate = self.globals["validate_release_source_manifest"]

        result = validate(
            self.source,
            "https://github.com/kody-w/rapp-stack-cubby.git",
            "a" * 40,
        )
        self.assertEqual(result["profile"], "release")
        self.assertNotIn("commit", manifest)

        cases = []
        bad_hash = json.loads(json.dumps(manifest))
        bad_hash["files"][0]["sha256"] = "0" * 64
        cases.append(bad_hash)
        missing = json.loads(json.dumps(manifest))
        missing["files"].pop()
        missing["file_count"] -= 1
        cases.append(missing)
        extra = json.loads(json.dumps(manifest))
        extra["files"].append(
            {
                "mode": "0644",
                "path": "absent.txt",
                "sha256": "0" * 64,
                "size": 0,
                "executable": False,
            }
        )
        extra["file_count"] += 1
        cases.append(extra)
        for invalid in cases:
            with self.subTest(files=len(invalid["files"])):
                path.write_text(
                    json.dumps(invalid, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                with self.assertRaises(RuntimeError):
                    validate(
                        self.source,
                        "https://github.com/kody-w/rapp-stack-cubby.git",
                        "a" * 40,
                    )

    def test_git_execution_uses_fixed_argv_and_never_a_shell(self):
        completed = Mock(returncode=0, stdout=b"", stderr=b"")
        run = Mock(return_value=completed)
        with patch.dict(self.globals, {"subprocess": Mock(run=run)}):
            self.globals["_run_git"](["version"])

        argv = run.call_args.args[0]
        self.assertEqual(argv[0], "/usr/bin/git")
        self.assertIn("protocol.file.allow=never", argv)
        self.assertIs(run.call_args.kwargs["shell"], False)
        self.assertIsInstance(argv, list)

    def test_checkout_is_contained_in_unique_controller_staging(self):
        self.environment.initialize()
        outside = self.environment.root / "outside-checkout"
        with self.assertRaises(RuntimeError):
            self.globals["_checkout_exact"](
                outside,
                "https://github.com/kody-w/rapp-stack-cubby.git",
                "a" * 40,
            )

    def test_production_fails_closed_and_development_rejects_executable(self):
        script = self.source / "unexpected.sh"
        script.write_text("#!/bin/sh\n", encoding="utf-8")
        script.chmod(0o755)
        digest = self.globals["deterministic_tree_digest"](self.source)
        with patch.dict(
            os.environ,
            {"RAPP_STACK_ALLOW_DEVELOPMENT_HATCH": ""},
            clear=False,
        ):
            with self.assertRaisesRegex(
                RuntimeError, "development_hatch_disabled"
            ):
                self.globals["_source_profile"](
                    self.source,
                    "https://github.com/kody-w/rapp-stack-cubby.git",
                    "a" * 40,
                    digest,
                )
        with self.assertRaisesRegex(RuntimeError, "source_invalid"):
            self.globals["_source_profile"](
                self.source,
                "https://github.com/kody-w/rapp-stack-cubby.git",
                "a" * 40,
                digest,
            )

    def test_atomic_json_is_private_and_never_leaves_staging_file(self):
        root = self.environment.initialize()
        destination = root / "receipts/example.json"
        self.globals["_atomic_json"](destination, {"ok": True})

        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
        self.assertEqual(json.loads(destination.read_text()), {"ok": True})
        self.assertEqual(list(destination.parent.glob("*.tmp-*")), [])


if __name__ == "__main__":
    unittest.main()
