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
endpoint = next((item for item in args if item.startswith("repos/")), "")
jq = args[args.index("--jq") + 1] if "--jq" in args else ""
method = args[args.index("--method") + 1] if "--method" in args else "GET"
payload = sys.stdin.read() if "--input" in args else None
with pathlib.Path(os.environ["MOCK_GH_LOG"]).open("a", encoding="utf-8") as log:
    log.write(json.dumps({"args": args, "input": payload}) + "\\n")

immutable = os.environ.get("MOCK_IMMUTABLE", "supported")
ruleset = os.environ.get("MOCK_RULESET", "valid")
if endpoint.endswith("/immutable_releases/enforcement"):
    if immutable != "supported":
        status = "404 Not Found" if immutable == "404" else "500 Server Error"
        if "--include" in args:
            print(f"HTTP/2.0 {status}")
            print()
        print(json.dumps({"message": status}))
        raise SystemExit(1)
    if method == "PUT":
        raise SystemExit(0)
    if "--include" in args:
        print("HTTP/2.0 200 OK")
        print()
    print(json.dumps({"enabled": os.environ.get("MOCK_DISABLED") != "1"}))
    raise SystemExit(0)

if method != "GET":
    raise SystemExit(0)
if jq:
    if "immutable-release-tags" in jq:
        if ruleset == "duplicate":
            print("42")
            print("43")
        elif ruleset != "missing":
            print("42")
    elif "| length" in jq:
        print("1")
    elif "branch_policies[]" in jq:
        print("99")
    raise SystemExit(0)
if endpoint.endswith("/pages"):
    print(json.dumps({
        "build_type": "branch" if os.environ.get("MOCK_BAD") else "workflow",
    }))
elif endpoint.endswith("/branches/main/protection"):
    print(json.dumps({
        "allow_deletions": {"enabled": False},
        "allow_force_pushes": {"enabled": False},
        "enforce_admins": {"enabled": True},
        "required_status_checks": {"contexts": ["verify"]},
    }))
elif endpoint.endswith("/rulesets/42"):
    value = {
        "bypass_actors": [],
        "conditions": {
            "ref_name": {
                "exclude": [],
                "include": ["refs/tags/*"],
            },
        },
        "enforcement": "active",
        "name": "immutable-release-tags",
        "rules": [{"type": "deletion"}, {"type": "update"}],
        "target": "tag",
    }
    if ruleset == "malformed":
        value["bypass_actors"] = [{"actor_id": 1, "actor_type": "RepositoryRole"}]
    print(json.dumps(value))
elif "/environments/" in endpoint and not endpoint.endswith(
    "deployment-branch-policies"
):
    protection_rules = []
    if not os.environ.get("MOCK_SOLE_OWNER"):
        protection_rules.append({
            "prevent_self_review": True,
            "reviewers": [{
                "reviewer": {"id": 123},
                "type": "User",
            }],
            "type": "required_reviewers",
        })
    print(json.dumps({
        "deployment_branch_policy": {
            "custom_branch_policies": True,
            "protected_branches": False,
        },
        "protection_rules": protection_rules,
    }))
else:
    print(json.dumps({}))
""",
            encoding="utf-8",
        )
        gh.chmod(0o755)

    def tearDown(self) -> None:
        self.workspace.__exit__(None, None, None)

    def _environment(
        self,
        *,
        bad: bool = False,
        immutable: str = "supported",
        ruleset: str = "valid",
        sole_owner: bool = False,
    ) -> dict[str, str]:
        value = dict(os.environ)
        value["PATH"] = f"{self.bin}:{value['PATH']}"
        value["MOCK_GH_LOG"] = str(self.log)
        value["MOCK_IMMUTABLE"] = immutable
        value["MOCK_RULESET"] = ruleset
        value["PYTHON"] = os.path.realpath(os.sys.executable)
        if bad:
            value["MOCK_BAD"] = "1"
        if sole_owner:
            value["MOCK_SOLE_OWNER"] = "1"
        return value

    def _run(
        self,
        *,
        bad: bool = False,
        immutable: str = "supported",
        ruleset: str = "valid",
        sole_owner: bool = False,
        reviewer: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        arguments = [
            str(self.source / "scripts/configure-repository.sh"),
            "--repo",
            "kody-w/rapp-stack-cubby",
        ]
        if sole_owner:
            arguments.append("--sole-owner")
        elif reviewer:
            arguments.extend(("--reviewer-user-id", "123"))
        return subprocess.run(
            arguments,
            cwd=self.source,
            env=self._environment(
                bad=bad,
                immutable=immutable,
                ruleset=ruleset,
                sole_owner=sole_owner,
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def _calls(self) -> list[dict[str, object]]:
        return [
            json.loads(line)
            for line in self.log.read_text(encoding="utf-8").splitlines()
        ]

    def test_supported_endpoint_is_enabled_and_settings_are_verified(self) -> None:
        completed = self._run()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        calls = self._calls()
        immutable_calls = [
            call
            for call in calls
            if call["args"]
            and "immutable_releases/enforcement" in " ".join(call["args"])
        ]
        self.assertTrue(any("--include" in call["args"] for call in immutable_calls))
        self.assertTrue(any("PUT" in call["args"] for call in immutable_calls))
        self.assertGreaterEqual(len(immutable_calls), 3)
        for environment in ("release", "promotion"):
            environment_calls = [
                call
                for call in calls
                if f"/environments/{environment}" in " ".join(call["args"])
            ]
            self.assertTrue(any("PUT" in call["args"] for call in environment_calls))
            self.assertTrue(
                all(
                    "X-GitHub-Api-Version: 2022-11-28" in call["args"]
                    for call in environment_calls
                )
            )
        release_put = next(
            call
            for call in calls
            if "/environments/release" in " ".join(call["args"])
            and "PUT" in call["args"]
        )
        payload = json.loads(str(release_put["input"]))
        self.assertTrue(payload["prevent_self_review"])
        self.assertEqual(payload["reviewers"], [{"id": 123, "type": "User"}])

    def test_404_falls_back_to_exact_active_tag_ruleset(self) -> None:
        completed = self._run(immutable="404")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        calls = self._calls()
        immutable_calls = [
            call
            for call in calls
            if "immutable_releases/enforcement" in " ".join(call["args"])
        ]
        self.assertEqual(len(immutable_calls), 1)
        self.assertIn("--include", immutable_calls[0]["args"])
        self.assertTrue(
            any(
                "/rulesets/42" in " ".join(call["args"])
                for call in calls
            )
        )

    def test_fallback_rejects_malformed_ruleset(self) -> None:
        completed = self._run(immutable="404", ruleset="malformed")
        self.assertNotEqual(completed.returncode, 0)

    def test_fallback_rejects_missing_ruleset_after_configuration(self) -> None:
        completed = self._run(immutable="404", ruleset="missing")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("ruleset is missing", completed.stderr)

    def test_non_404_endpoint_error_does_not_fall_back(self) -> None:
        completed = self._run(immutable="500")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("HTTP 500", completed.stderr)
        self.assertFalse(
            any("/rulesets" in " ".join(call["args"]) for call in self._calls())
        )

    def test_sole_owner_mode_has_no_impossible_reviewer(self) -> None:
        completed = self._run(immutable="404", sole_owner=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        release_put = next(
            call
            for call in self._calls()
            if "/environments/release" in " ".join(call["args"])
            and "PUT" in call["args"]
        )
        payload = json.loads(str(release_put["input"]))
        self.assertFalse(payload["prevent_self_review"])
        self.assertEqual(payload["reviewers"], [])

    def test_strict_mode_still_requires_a_reviewer(self) -> None:
        completed = self._run(reviewer=False)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("strict reviewer mode", completed.stderr)

    def test_unverifiable_setting_fails(self) -> None:
        completed = self._run(bad=True)
        self.assertNotEqual(completed.returncode, 0)


if __name__ == "__main__":
    unittest.main()
