from __future__ import annotations

import json
import os
import subprocess
import unittest

from ._support import PackagingWorkspace, initialize_exact_git_source


class RollbackScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = PackagingWorkspace()
        self.workspace.__enter__()
        self.source, _cache = (
            self.workspace.copy_repository_with_fake_dependencies()
        )
        self.commit = initialize_exact_git_source(self.source)
        self.remote = self.workspace.root / "rollback-remote.git"
        subprocess.run(
            ["git", "init", "--bare", "-q", str(self.remote)], check=True
        )
        subprocess.run(
            ["git", "-C", str(self.source), "remote", "add", "origin", str(self.remote)],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.source), "push", "-q", "origin", "main"],
            check=True,
        )
        self.previous_tag = "v0.0.9"
        subprocess.run(
            [
                "git",
                "-C",
                str(self.source),
                "tag",
                "-a",
                self.previous_tag,
                "-m",
                "previous",
            ],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(self.source),
                "push",
                "-q",
                "origin",
                f"refs/tags/{self.previous_tag}",
            ],
            check=True,
        )
        self.bin = self.workspace.root / "rollback-bin"
        self.bin.mkdir()
        self.python_log = self.workspace.root / "python-calls.jsonl"
        python = self.bin / "installed-python"
        python.write_text(
            """#!/usr/bin/env python3
import json
import os
import pathlib
import sys
with pathlib.Path(os.environ["MOCK_PYTHON_LOG"]).open("a") as output:
    output.write(json.dumps(sys.argv[1:]) + "\\n")
""",
            encoding="utf-8",
        )
        python.chmod(0o755)
        self.gh_log = self.workspace.root / "gh-calls.jsonl"
        gh = self.bin / "gh"
        gh.write_text(
            """#!/usr/bin/env python3
import json
import os
import pathlib
import sys
with pathlib.Path(os.environ["MOCK_GH_LOG"]).open("a") as output:
    output.write(json.dumps(sys.argv[1:]) + "\\n")
if sys.argv[1:3] == ["release", "download"]:
    print('{"schema":"rapp-promotion-receipt/1.0"}')
""",
            encoding="utf-8",
        )
        gh.chmod(0o755)
        self.receipt = self.workspace.root / "private-rollback.json"
        rappid_base = (
            "rappid:@kody-w/rapp-stack-cubby:"
        )
        self.controller_rappid = rappid_base + "1" * 64
        self.product_rappid = rappid_base + "2" * 64
        self.install_rappid = rappid_base + "3" * 64
        value = {
            "controller": {
                "python": str(python),
                "rappid": self.controller_rappid,
                "root": str(self.workspace.root / "controller"),
                "token_file": str(self.workspace.root / "token"),
                "url": "http://127.0.0.1:9999/chat",
            },
            "imessage": {
                "config": str(self.workspace.root / "imessage.json"),
                "plist": str(self.workspace.root / "service.plist"),
                "tools_root": str(self.workspace.root / "tools"),
            },
            "installation": {
                "instance_rappid": self.install_rappid,
                "product_rappid": self.product_rappid,
                "root": str(self.workspace.root / "install"),
            },
            "previous_pages": {
                "commit": self.commit,
                "manifest_sha256": "4" * 64,
                "promotion_receipt_sha256": "5" * 64,
                "promotion_run_id": "123456",
                "tag": self.previous_tag,
            },
            "release": {"tag": "v0.1.0-rc.1"},
            "schema": "rapp-private-demo-live-receipt/1.0",
        }
        self.receipt.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.receipt.chmod(0o600)

    def tearDown(self) -> None:
        self.workspace.__exit__(None, None, None)

    def _environment(self) -> dict[str, str]:
        value = dict(os.environ)
        value["PATH"] = f"{self.bin}:{value['PATH']}"
        value["MOCK_GH_LOG"] = str(self.gh_log)
        value["MOCK_PYTHON_LOG"] = str(self.python_log)
        value["PYTHON"] = os.path.realpath(os.sys.executable)
        return value

    def test_receipt_identities_and_previous_tag_ref_are_used(self) -> None:
        completed = subprocess.run(
            [
                str(self.source / "scripts/rollback-product.sh"),
                "--receipt",
                str(self.receipt),
                "--release-action",
                "mark-failed",
            ],
            cwd=self.source,
            env=self._environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        python_calls = self.python_log.read_text(encoding="utf-8")
        self.assertIn(self.controller_rappid, python_calls)
        self.assertIn(self.product_rappid, python_calls)
        self.assertIn(self.install_rappid, python_calls)
        calls = [
            json.loads(line)
            for line in self.gh_log.read_text(encoding="utf-8").splitlines()
        ]
        dispatch = next(call for call in calls if call[:2] == ["workflow", "run"])
        self.assertEqual(
            dispatch[dispatch.index("--ref") + 1],
            self.previous_tag,
        )
        edit = next(call for call in calls if call[:2] == ["release", "edit"])
        self.assertIn("FAILED POSTFLIGHT", " ".join(edit))

    def test_non_private_receipt_is_rejected_before_actions(self) -> None:
        self.receipt.chmod(0o644)
        completed = subprocess.run(
            [
                str(self.source / "scripts/rollback-product.sh"),
                "--receipt",
                str(self.receipt),
                "--release-action",
                "delete",
            ],
            cwd=self.source,
            env=self._environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse(self.gh_log.exists())


if __name__ == "__main__":
    unittest.main()
