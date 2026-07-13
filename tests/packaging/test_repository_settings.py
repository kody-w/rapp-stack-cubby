from __future__ import annotations

import json
import os
import subprocess
import unittest

from ._support import PackagingWorkspace


class RepositorySettingsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = PackagingWorkspace()
        self.workspace.__enter__()
        self.source, _cache = (
            self.workspace.copy_repository_with_fake_dependencies()
        )
        self.bin = self.workspace.root / "settings-bin"
        self.bin.mkdir()
        self.log = self.workspace.root / "gh-calls.jsonl"
        gh = self.bin / "gh"
        gh.write_text(
            """#!/usr/bin/env python3
import json
import os
import pathlib
import sys

args = sys.argv[1:]
with pathlib.Path(os.environ["MOCK_GH_LOG"]).open("a", encoding="utf-8") as log:
    log.write(json.dumps(args) + "\\n")
endpoint = next((item for item in args if item.startswith("repos/")), "")
jq = args[args.index("--jq") + 1] if "--jq" in args else ""
method = args[args.index("--method") + 1] if "--method" in args else "GET"
if method != "GET":
    if "--input" in args:
        sys.stdin.read()
    raise SystemExit(0)
if jq:
    if "immutable-release-tags" in jq:
        print("42")
    elif "| length" in jq:
        print("1")
    elif "branch_policies[]" in jq:
        print("99")
    raise SystemExit(0)
if endpoint.endswith("/pages"):
    print(json.dumps({"build_type": "branch" if os.environ.get("MOCK_BAD") else "workflow"}))
elif endpoint.endswith("/immutable_releases/enforcement"):
    print(json.dumps({"enabled": True}))
elif endpoint.endswith("/branches/main/protection"):
    print(json.dumps({
        "allow_deletions": {"enabled": False},
        "allow_force_pushes": {"enabled": False},
        "enforce_admins": {"enabled": True},
        "required_status_checks": {"contexts": ["verify"]},
    }))
elif endpoint.endswith("/rulesets/42"):
    print(json.dumps({
        "bypass_actors": [],
        "conditions": {"ref_name": {"include": ["refs/tags/*"]}},
        "enforcement": "active",
        "rules": [{"type": "deletion"}, {"type": "update"}],
        "target": "tag",
    }))
elif "/environments/" in endpoint and not endpoint.endswith("deployment-branch-policies"):
    print(json.dumps({
        "deployment_branch_policy": {
            "custom_branch_policies": True,
            "protected_branches": False,
        },
        "protection_rules": [{
            "prevent_self_review": True,
            "reviewers": [{
                "reviewer": {"id": 123},
                "type": "User",
            }],
            "type": "required_reviewers",
        }],
    }))
else:
    print(json.dumps({"immutable_releases": True}))
""",
            encoding="utf-8",
        )
        gh.chmod(0o755)

    def tearDown(self) -> None:
        self.workspace.__exit__(None, None, None)

    def _environment(self, *, bad: bool = False) -> dict[str, str]:
        value = dict(os.environ)
        value["PATH"] = f"{self.bin}:{value['PATH']}"
        value["MOCK_GH_LOG"] = str(self.log)
        value["PYTHON"] = os.path.realpath(os.sys.executable)
        if bad:
            value["MOCK_BAD"] = "1"
        return value

    def _run(self, *, bad: bool = False) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                str(self.source / "scripts/configure-repository.sh"),
                "--repo",
                "kody-w/rapp-stack-cubby",
                "--reviewer-user-id",
                "123",
            ],
            cwd=self.source,
            env=self._environment(bad=bad),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_settings_are_idempotently_written_and_verified(self) -> None:
        completed = self._run()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        calls = [
            json.loads(line)
            for line in self.log.read_text(encoding="utf-8").splitlines()
        ]
        self.assertTrue(
            any(
                "repos/kody-w/rapp-stack-cubby/pages" in call
                and "PUT" in call
                for call in calls
            )
        )
        for environment in ("release", "promotion"):
            self.assertTrue(
                any(
                    f"/environments/{environment}" in " ".join(call)
                    and "PUT" in call
                    for call in calls
                )
            )

    def test_unverifiable_setting_fails(self) -> None:
        completed = self._run(bad=True)
        self.assertNotEqual(completed.returncode, 0)


if __name__ == "__main__":
    unittest.main()
