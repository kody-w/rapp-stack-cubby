from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from rapp_stack_cubby.verification import (
    _check_placeholder_config,
    verify_repository,
)

from ._support import REPOSITORY_ROOT


class RuntimeVerificationTests(unittest.TestCase):
    def test_reviewed_runtime_source_is_permitted_and_counted(self) -> None:
        result = verify_repository(REPOSITORY_ROOT)
        check = next(
            item for item in result.checks if item.name == "placeholder_config"
        )

        self.assertTrue(check.passed, "\n".join(check.errors))
        self.assertEqual(check.details["runtime_source_file_count"], 16)

    def test_generated_runtime_directory_remains_forbidden(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".test-runtime-verifier-",
            dir=REPOSITORY_ROOT,
        ) as temporary:
            root = Path(temporary)
            generated = root / "var" / "runtime"
            generated.mkdir(parents=True)
            (generated / "data.txt").write_text("generated", encoding="utf-8")

            _, errors = _check_placeholder_config(root)

        self.assertTrue(any("runtime directory is forbidden" in error for error in errors))

    def test_runtime_source_check_rejects_unsafe_route(self) -> None:
        names = (
            "__init__.py",
            "app.py",
            "basic_agent.py",
            "config.py",
            "orchestrator.py",
            "provider.py",
            "registry.py",
            "server.py",
            "storage.py",
        )
        with tempfile.TemporaryDirectory(
            prefix=".test-runtime-source-",
            dir=REPOSITORY_ROOT,
        ) as temporary:
            root = Path(temporary)
            runtime = root / "src" / "rapp_stack_cubby" / "runtime"
            runtime.mkdir(parents=True)
            for name in names:
                source = (
                    'ROUTES = {"/health", "/chat", "/eval"}\n'
                    if name == "server.py"
                    else "\n"
                )
                (runtime / name).write_text(source, encoding="utf-8")

            _, errors = _check_placeholder_config(root)

        self.assertTrue(any("forbidden runtime surface" in error for error in errors))
        self.assertTrue(any("unsupported HTTP routes" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
