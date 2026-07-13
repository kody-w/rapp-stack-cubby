from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rapp_stack_cubby.errors import RepositoryNotFoundError, UnsafePathError
from rapp_stack_cubby.paths import find_repository_root, repository_path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class PathTests(unittest.TestCase):
    def test_finds_nearest_contract_root_from_nested_directory(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".test-paths-", dir=REPOSITORY_ROOT
        ) as temporary:
            root = Path(temporary)
            (root / "SOURCE_CENSUS.json").write_text("{}\n", encoding="utf-8")
            (root / "STACK_LOCK.json").write_text("{}\n", encoding="utf-8")
            nested = root / "one" / "two"
            nested.mkdir(parents=True)

            self.assertEqual(find_repository_root(nested), root.resolve())

    def test_unmarked_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".test-unmarked-", dir=REPOSITORY_ROOT
        ) as temporary:
            isolated = Path(temporary) / "child"
            isolated.mkdir()

            with patch(
                "rapp_stack_cubby.paths.REPOSITORY_MARKERS",
                ("ABSENT_CENSUS.json", "ABSENT_LOCK.json"),
            ):
                with self.assertRaises(RepositoryNotFoundError):
                    find_repository_root(isolated)

    def test_repository_path_resolves_relative_path(self) -> None:
        resolved = repository_path(REPOSITORY_ROOT, "docs/.nojekyll")
        self.assertEqual(resolved, REPOSITORY_ROOT / "docs/.nojekyll")

    def test_repository_path_rejects_absolute_and_traversal_paths(self) -> None:
        with self.assertRaises(UnsafePathError):
            repository_path(REPOSITORY_ROOT, REPOSITORY_ROOT / "README.md")
        with self.assertRaises(UnsafePathError):
            repository_path(REPOSITORY_ROOT, "../outside")


if __name__ == "__main__":
    unittest.main()
