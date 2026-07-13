from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from rapp_stack_cubby import __version__
from rapp_stack_cubby.cli import main

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def test_version_command(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            status = main(["version"])

        self.assertEqual(status, 0)
        self.assertEqual(
            output.getvalue().strip(), f"rapp-stack-cubby {__version__}"
        )

    def test_census_command_summarizes_local_contract(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            status = main(["census", "--root", str(REPOSITORY_ROOT)])

        self.assertEqual(status, 0)
        self.assertIn("repositories: 307", output.getvalue())

    def test_context_command_summarizes_local_closure(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            status = main(["context", "--root", str(REPOSITORY_ROOT)])

        self.assertEqual(status, 0)
        self.assertIn("LOCAL RAPP CONTEXT rapp-context-index/1.0", output.getvalue())
        self.assertIn("selected capabilities: 61", output.getvalue())

    def test_verify_command_returns_nonzero_with_readable_errors(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".test-cli-", dir=REPOSITORY_ROOT
        ) as temporary:
            output = io.StringIO()
            errors = io.StringIO()
            with redirect_stdout(output), redirect_stderr(errors):
                status = main(["verify", "--root", temporary])

        self.assertEqual(status, 1)
        self.assertIn("FAIL required_files", output.getvalue())
        self.assertIn("missing required top-level file", output.getvalue())
        self.assertEqual(errors.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
