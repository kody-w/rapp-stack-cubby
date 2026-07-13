from __future__ import annotations

import json
import io
import stat
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from rapp_stack_cubby.cli import build_parser
from rapp_stack_cubby.command_manifest import (
    build_command_manifest,
    validate_documented_commands,
)

ROOT = Path(__file__).resolve().parents[1]


class UserJourneyContractTests(unittest.TestCase):
    def test_command_manifest_matches_parser_and_tutorial_flags(self):
        observed = json.loads(
            (ROOT / "COMMAND_MANIFEST.json").read_text(encoding="utf-8")
        )
        self.assertEqual(observed, build_command_manifest())
        self.assertEqual(validate_documented_commands(ROOT), ())
        for command in observed["commands"]:
            argv = [*command["path"], "--help"]
            with self.subTest(argv=argv):
                with redirect_stdout(io.StringIO()), redirect_stderr(
                    io.StringIO()
                ), self.assertRaises(SystemExit) as raised:
                    build_parser().parse_args(argv)
                self.assertEqual(raised.exception.code, 0)

    def test_bootstrap_is_offline_fixed_argv_without_home_default(self):
        text = (ROOT / "scripts/bootstrap-development.sh").read_text()
        for value in (
            "--python",
            "--venv",
            "--dependency-cache",
            "--work-dir",
            "--install-dir",
            "--controller-dir",
            "--no-index",
            "--require-hashes",
            "--no-deps",
            "rapp_stack_cubby doctor",
        ):
            self.assertIn(value, text)
        self.assertNotIn("$HOME", text)
        self.assertNotIn("gh-copilot", text.casefold())

    def test_release_orders_installed_attestation_before_publication(self):
        text = (ROOT / ".github/workflows/release.yml").read_text()
        hatch = text.index("Temporary offline hatch")
        attestation = text.index(
            "Prove installed bytes through signed offline attestation child"
        )
        publish = text.index("gh release create")
        postflight = text.index("scripts/postflight-release.sh")
        failed = text.index("FAILED POSTFLIGHT")
        self.assertLess(hatch, attestation)
        self.assertLess(attestation, publish)
        self.assertLess(publish, postflight)
        self.assertLess(postflight, failed)
        self.assertNotIn("deploy-pages", text)

    def test_demo_adopts_installed_bytes_without_git_refetch(self):
        text = (ROOT / "src/rapp_stack_cubby/demo.py").read_text()
        self.assertIn('"adopt"', text)
        self.assertIn("installed_source_digest_matches", text)
        self.assertNotIn("hatch_repo", text)
        self.assertNotIn("git fetch", text)
        self.assertNotIn("git clone", text)

    def test_rollback_script_is_complete_and_scripts_are_executable(self):
        rollback = (ROOT / "scripts/rollback-product.sh").read_text()
        for value in (
            " rollback-stop stop ",
            " rollback-archive archive ",
            "service-uninstall",
            "--uninstall",
            " rollback-purge purge ",
            "uninstall-twin",
            "gh release delete",
            "gh release edit",
            "gh workflow run pages.yml",
        ):
            self.assertIn(value, rollback)
        for name in (
            "attest-installed-offline.sh",
            "bootstrap-development.sh",
            "demo-product.sh",
            "rollback-product.sh",
        ):
            mode = stat.S_IMODE((ROOT / "scripts" / name).stat().st_mode)
            self.assertEqual(mode, 0o755)

    def test_release_docs_name_ordered_same_commit_phases(self):
        for relative in (
            "RELEASE_CHECKLIST.md",
            "docs/operations/EXACT_COMMIT_PROMOTION.md",
            "docs/operations/PACKAGING_AND_RELEASE.md",
        ):
            text = (ROOT / relative).read_text()
            indexes = [
                text.index(marker)
                for marker in ("Phase A", "Phase B", "Phase C", "Phase D")
                if marker in text
            ]
            if not indexes:
                indexes = [
                    text.index(marker)
                    for marker in ("A —", "B —", "C —", "D —")
                ]
            self.assertEqual(indexes, sorted(indexes), relative)
            self.assertIn("same", text.casefold())
            self.assertIn("commit", text.casefold())


if __name__ == "__main__":
    unittest.main()
