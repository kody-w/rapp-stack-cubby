from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from rapp_stack_cubby.constants import REQUIRED_TOP_LEVEL_FILES
from rapp_stack_cubby.verification import verify_repository

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class RepositoryVerificationTests(unittest.TestCase):
    def test_current_repository_contracts_pass(self) -> None:
        result = verify_repository(REPOSITORY_ROOT)

        self.assertTrue(
            result.ok,
            "\n".join(
                error
                for check in result.failed_checks
                for error in check.errors
            ),
        )
        self.assertEqual(len(result.checks), 12)

    def test_result_is_structured_and_serializable(self) -> None:
        result = verify_repository(REPOSITORY_ROOT)
        payload = result.as_dict()

        self.assertTrue(payload["ok"])
        self.assertEqual(payload["check_count"], 12)
        self.assertEqual(payload["failed_check_count"], 0)
        json.dumps(payload)

    def test_unsorted_census_is_reported(self) -> None:
        with self._contract_fixture() as fixture:
            path = fixture / "SOURCE_CENSUS.json"
            census = json.loads(path.read_text(encoding="utf-8"))
            census["repositories"][0], census["repositories"][1] = (
                census["repositories"][1],
                census["repositories"][0],
            )
            path.write_text(json.dumps(census) + "\n", encoding="utf-8")

            result = verify_repository(fixture)

        check = self._check(result, "source_census")
        self.assertFalse(check.passed)
        self.assertTrue(
            any("sorted_index" in error or "sorted" in error for error in check.errors)
        )

    def test_malformed_stack_pin_is_reported(self) -> None:
        with self._contract_fixture() as fixture:
            path = fixture / "STACK_LOCK.json"
            lock = json.loads(path.read_text(encoding="utf-8"))
            lock["source_pins"][0]["commit"] = "main"
            path.write_text(json.dumps(lock) + "\n", encoding="utf-8")

            result = verify_repository(fixture)

        check = self._check(result, "stack_lock")
        self.assertFalse(check.passed)
        self.assertTrue(any("40 lowercase hex" in error for error in check.errors))

    def test_real_environment_file_is_rejected(self) -> None:
        with self._contract_fixture() as fixture:
            (fixture / ".env").write_text("TOKEN=x\n", encoding="utf-8")

            result = verify_repository(fixture)

        check = self._check(result, "placeholder_config")
        self.assertFalse(check.passed)
        self.assertTrue(any(".env" in error for error in check.errors))

    def test_python_cache_directory_is_ignored_as_generated_metadata(self) -> None:
        with self._contract_fixture() as fixture:
            cache = fixture / "src" / "__pycache__"
            cache.mkdir(parents=True)
            (cache / "module.pyc").write_bytes(b"synthetic")

            result = verify_repository(fixture)

        check = self._check(result, "placeholder_config")
        self.assertFalse(any("__pycache__" in error for error in check.errors))

    def test_egg_info_directory_is_ignored_as_editable_install_metadata(self) -> None:
        with self._contract_fixture() as fixture:
            metadata = fixture / "src/sample.egg-info"
            metadata.mkdir(parents=True)
            (metadata / "PKG-INFO").write_text(
                "Name: synthetic\n", encoding="utf-8"
            )
            result = verify_repository(fixture)

        check = self._check(result, "placeholder_config")
        self.assertFalse(any(".egg-info" in error for error in check.errors))

    @staticmethod
    def _check(result, name):
        return next(check for check in result.checks if check.name == name)

    def _contract_fixture(self):
        temporary = tempfile.TemporaryDirectory(
            prefix=".test-contract-", dir=REPOSITORY_ROOT
        )
        fixture = Path(temporary.name)
        for relative in REQUIRED_TOP_LEVEL_FILES:
            shutil.copy2(REPOSITORY_ROOT / relative, fixture / relative)
        evidence = fixture / "docs" / "research"
        evidence.mkdir(parents=True)
        shutil.copy2(
            REPOSITORY_ROOT / "docs/research/account-crawl.md",
            evidence / "account-crawl.md",
        )
        return _TemporaryFixture(temporary, fixture)


class _TemporaryFixture:
    def __init__(
        self, temporary: tempfile.TemporaryDirectory[str], path: Path
    ) -> None:
        self._temporary = temporary
        self._path = path

    def __enter__(self) -> Path:
        return self._path

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self._temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
