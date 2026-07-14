from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import unittest
from pathlib import Path

from rapp_stack_cubby.packaging.publication import (
    sign_publication_receipt,
    write_publication_receipt,
)

from ._support import PackagingWorkspace, create_exact_signed_release


class ReleaseScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workspace = PackagingWorkspace()
        cls.workspace.__enter__()
        (
            cls.source,
            _cache,
            cls.output,
            cls.result,
            _verified,
            _attestation,
        ) = create_exact_signed_release(cls.workspace)
        cls.commit = subprocess.check_output(
            ["git", "-C", str(cls.source), "rev-parse", "HEAD"],
            text=True,
        ).strip()
        candidate_receipt = cls.workspace.root / "candidate-publication-scan.json"
        candidate_signature = (
            cls.workspace.root / "candidate-publication-scan.json.sig"
        )
        policy_sha = hashlib.sha256(
            (cls.source / "PUBLICATION_SCAN_POLICY.json").read_bytes()
        ).hexdigest()
        receipt = {
            "actions_evidence": [],
            "allowlist_uses": [],
            "counts": {
                "artifacts": 4,
                "bytes": 4,
                "findings": 0,
                "git_blobs": 1,
                "members": 0,
            },
            "findings": [],
            "phase": "candidate",
            "policy_sha256": policy_sha,
            "result": "pass",
            "scanner": "rapp-stack-cubby-publication-scanner/1.0",
            "schema": "rapp-publication-scan-receipt/1.0",
            "scopes": [
                {
                    "artifact_count": 1,
                    "byte_count": 1,
                    "member_count": 0,
                    "name": name,
                    "sha256": hashlib.sha256(name.encode()).hexdigest(),
                    "status": "complete",
                }
                for name in ("source", "history", "pages", "release_assets")
            ],
            "source": {"commit": cls.commit},
            "timestamp": "2026-07-13T00:00:00Z",
        }
        write_publication_receipt(candidate_receipt, receipt)
        sign_publication_receipt(
            candidate_receipt,
            candidate_signature,
            key_path=cls.workspace.root / "private/signing.pem",
            repository_root=cls.source,
            trust_path=cls.source / "RELEASE_TRUST.json",
        )
        shutil.copyfile(
            candidate_receipt,
            cls.output / "candidate-publication-scan.json",
        )
        shutil.copyfile(
            candidate_signature,
            cls.output / "candidate-publication-scan.json.sig",
        )
        cls.remote = cls.workspace.root / "remote.git"
        subprocess.run(
            ["git", "init", "--bare", "-q", str(cls.remote)], check=True
        )
        subprocess.run(
            ["git", "-C", str(cls.source), "remote", "add", "origin", str(cls.remote)],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(cls.source), "push", "-q", "origin", "main"],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(cls.source),
                "tag",
                "-a",
                "v0.1.0-rc.10",
                "-m",
                "candidate",
            ],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(cls.source),
                "push",
                "-q",
                "origin",
                "refs/tags/v0.1.0-rc.10",
            ],
            check=True,
        )
        cls.bin = cls.workspace.root / "mock-bin"
        cls.bin.mkdir()
        gh = cls.bin / "gh"
        gh.write_text(
            """#!/usr/bin/env python3
import hashlib
import json
import os
import pathlib
import shutil
import sys

args = sys.argv[1:]
if args and args[0] == "api":
    source = pathlib.Path(os.environ["MOCK_ASSETS"])
    commit = os.environ["MOCK_COMMIT"]
    print(json.dumps({
        "assets": [
            {"name": item.name, "size": item.stat().st_size}
            for item in sorted(source.iterdir())
            if item.is_file()
        ] + (
            [{"name": "unexpected.txt", "size": 1}]
            if os.environ.get("MOCK_EXTRA") else []
        ),
        "draft": False,
        "immutable": True,
        "name": "RAPP Stack CUBBY v0.1.0-rc.10",
        "prerelease": True,
        "tag_name": "v0.1.0-rc.10",
        "target_commitish": commit,
    }))
    raise SystemExit(0)
if args[:2] == ["release", "download"]:
    destination = pathlib.Path(args[args.index("--dir") + 1])
    source = pathlib.Path(os.environ["MOCK_ASSETS"])
    for item in source.iterdir():
        if item.is_file():
            shutil.copyfile(item, destination / item.name)
    tamper = os.environ.get("MOCK_TAMPER")
    if tamper:
        with (destination / tamper).open("ab") as output:
            output.write(b"tampered")
    raise SystemExit(0)
if args[:2] == ["attestation", "verify"]:
    artifact = pathlib.Path(args[2])
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    print(json.dumps([{
        "attestation": {},
        "verificationResult": {
            "statement": {
                "subject": [{
                    "name": artifact.name,
                    "digest": {"sha256": digest},
                }]
            }
        },
    }]))
    raise SystemExit(0)
raise SystemExit(2)
""",
            encoding="utf-8",
        )
        gh.chmod(0o755)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.workspace.__exit__(None, None, None)

    def environment(
        self,
        *,
        tamper: str | None = None,
        extra: bool = False,
    ) -> dict[str, str]:
        value = dict(os.environ)
        value["PATH"] = f"{self.bin}:{value['PATH']}"
        value["MOCK_ASSETS"] = str(self.output)
        value["MOCK_COMMIT"] = self.commit
        value["PYTHON"] = os.path.realpath(os.sys.executable)
        if tamper is not None:
            value["MOCK_TAMPER"] = tamper
        else:
            value.pop("MOCK_TAMPER", None)
        if extra:
            value["MOCK_EXTRA"] = "1"
        else:
            value.pop("MOCK_EXTRA", None)
        return value

    def test_malicious_and_wrong_tag_inputs_fail_before_gh(self) -> None:
        validator = self.source / "scripts/validate-release-inputs.sh"
        malicious = subprocess.run(
            [
                str(validator),
                "v0.1.0-rc.10;touch-pwned",
                self.commit,
            ],
            cwd=self.source,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertNotEqual(malicious.returncode, 0)
        resolver = self.source / "scripts/resolve-release-tag.sh"
        wrong = subprocess.run(
            [str(resolver), "v0.1.0-rc.10", "f" * 40],
            cwd=self.source,
            env=self.environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertNotEqual(wrong.returncode, 0)

    def test_postflight_uses_mocked_gh_and_records_success(self) -> None:
        command = [
            str(self.source / "scripts/postflight-release.sh"),
            "v0.1.0-rc.10",
            self.commit,
            str(self.output),
            str(self.workspace.root / "download-ok"),
            str(self.workspace.root / "evidence-ok"),
            str(self.workspace.root / "attestation-ok.json"),
            str(self.workspace.root / "postflight-ok.json"),
        ]
        completed = subprocess.run(
            command,
            cwd=self.source,
            env=self.environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue((self.workspace.root / "postflight-ok.json").is_file())

    def test_postflight_byte_mismatch_fails_without_success(self) -> None:
        success = self.workspace.root / "postflight-bad.json"
        command = [
            str(self.source / "scripts/postflight-release.sh"),
            "v0.1.0-rc.10",
            self.commit,
            str(self.output),
            str(self.workspace.root / "download-bad"),
            str(self.workspace.root / "evidence-bad"),
            str(self.workspace.root / "attestation-bad.json"),
            str(success),
        ]
        completed = subprocess.run(
            command,
            cwd=self.source,
            env=self.environment(tamper="store-index.json"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("byte mismatch", completed.stderr)
        self.assertFalse(success.exists())

    def test_postflight_rejects_extra_remote_asset(self) -> None:
        success = self.workspace.root / "postflight-extra.json"
        completed = subprocess.run(
            [
                str(self.source / "scripts/postflight-release.sh"),
                "v0.1.0-rc.10",
                self.commit,
                str(self.output),
                str(self.workspace.root / "download-extra"),
                str(self.workspace.root / "evidence-extra"),
                str(self.workspace.root / "attestation-extra.json"),
                str(success),
            ],
            cwd=self.source,
            env=self.environment(extra=True),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("exact remote inventory", completed.stderr)
        self.assertFalse(success.exists())


if __name__ == "__main__":
    unittest.main()
