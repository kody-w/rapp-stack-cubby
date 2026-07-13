from __future__ import annotations

import hashlib
import io
import json
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from rapp_stack_cubby.cli import build_parser, main
from rapp_stack_cubby.controller import (
    ControllerLoadoutError,
    build_controller_loadout,
    verify_controller_loadout,
)

from ._support import REPOSITORY_ROOT


class ControllerLoadoutTests(unittest.TestCase):
    def test_builder_copies_only_controller_and_preserves_source(self):
        source = (
            REPOSITORY_ROOT
            / "cubbies/kody-w/agents/rapp_stack_cubby_agent.py"
        )
        before = source.read_bytes()
        before_stat = source.stat()
        with tempfile.TemporaryDirectory(
            prefix=".test-controller-loadout-parent-",
            dir=REPOSITORY_ROOT.parent,
        ) as parent:
            output = Path(parent) / "loadout"
            manifest = build_controller_loadout(
                REPOSITORY_ROOT, output
            )
            verified = verify_controller_loadout(output)

            observed = sorted(
                path.relative_to(output).as_posix()
                for path in output.rglob("*")
                if path.is_file()
            )
            copied = output / "agents/rapp_stack_cubby_agent.py"

            self.assertEqual(
                observed,
                [
                    "agents/rapp_stack_cubby_agent.py",
                    "controller-loadout.json",
                    "soul.md",
                ],
            )
            self.assertEqual(manifest, verified)
            self.assertEqual(
                manifest["schema"], "rapp-controller-loadout/1.0"
            )
            self.assertEqual(
                manifest["controller"]["sha256"],
                hashlib.sha256(before).hexdigest(),
            )
            self.assertEqual(copied.read_bytes(), before)
            self.assertIn(
                "RAPP_CONTROLLER_ROUTE/1.0",
                (output / "soul.md").read_text(encoding="utf-8"),
            )
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(copied.stat().st_mode), 0o600)
            self.assertEqual(
                stat.S_IMODE(
                    (output / "controller-loadout.json").stat().st_mode
                ),
                0o600,
            )
            self.assertEqual(
                stat.S_IMODE((output / "soul.md").stat().st_mode),
                0o600,
            )

        self.assertEqual(source.read_bytes(), before)
        self.assertEqual(source.stat().st_mtime_ns, before_stat.st_mtime_ns)

    def test_builder_rejects_relative_contained_and_existing_outputs(self):
        with self.assertRaises(ControllerLoadoutError):
            build_controller_loadout(REPOSITORY_ROOT, "relative")
        with self.assertRaises(ControllerLoadoutError):
            build_controller_loadout(
                REPOSITORY_ROOT,
                REPOSITORY_ROOT / "contained-loadout",
            )
        with tempfile.TemporaryDirectory(
            prefix=".test-controller-existing-",
            dir=REPOSITORY_ROOT.parent,
        ) as parent:
            with self.assertRaises(ControllerLoadoutError):
                build_controller_loadout(REPOSITORY_ROOT, parent)

    def test_cli_requires_explicit_output_and_emits_manifest(self):
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                build_parser().parse_args(["controller-loadout"])
        with tempfile.TemporaryDirectory(
            prefix=".test-controller-cli-parent-",
            dir=REPOSITORY_ROOT.parent,
        ) as parent:
            output = Path(parent) / "loadout"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                status = main(
                    [
                        "controller-loadout",
                        "--root",
                        str(REPOSITORY_ROOT),
                        "--output-dir",
                        str(output),
                    ]
                )

            self.assertEqual(status, 0)
            self.assertEqual(
                json.loads(stdout.getvalue())["schema"],
                "rapp-controller-loadout/1.0",
            )

    def test_verifier_reconstructs_catalog_and_rejects_fabricated_fields(self):
        with tempfile.TemporaryDirectory(
            prefix=".test-controller-fabricated-",
            dir=REPOSITORY_ROOT.parent,
        ) as parent:
            output = Path(parent) / "loadout"
            build_controller_loadout(REPOSITORY_ROOT, output)
            manifest_path = output / "controller-loadout.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["controller"]["actions"] = ["inspect"]
            manifest_path.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(ControllerLoadoutError):
                verify_controller_loadout(output)

            manifest["controller"]["actions"] = manifest["catalog"][
                "actions"
            ]
            del manifest["catalog"]["mutability"]
            manifest_path.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(ControllerLoadoutError):
                verify_controller_loadout(output)


if __name__ == "__main__":
    unittest.main()
