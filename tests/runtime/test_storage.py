from __future__ import annotations

import concurrent.futures
import os
import stat
import unittest
from pathlib import Path

from rapp_stack_cubby.runtime.storage import (
    AzureFileStorageManager,
    LocalStorage,
    StorageError,
    StoragePathError,
    StorageSizeError,
)

from ._support import RuntimeFixture


class StorageTests(unittest.TestCase):
    def test_atomic_write_has_mode_0600_and_no_pending_file(self) -> None:
        with RuntimeFixture() as fixture:
            storage = LocalStorage(fixture.data)
            storage.write_text("one/value.txt", "hello")
            path = fixture.data / "one" / "value.txt"

            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertFalse(
                any(item.name.endswith(".pending") for item in path.parent.iterdir())
            )

    def test_json_and_binary_operations_round_trip(self) -> None:
        with RuntimeFixture() as fixture:
            storage = LocalStorage(fixture.data)
            storage.write_json("values/item.json", {"b": 2, "a": 1})
            storage.write_bytes("values/blob.bin", b"\x00\x01")

            self.assertEqual(
                storage.read_json("values/item.json"), {"a": 1, "b": 2}
            )
            self.assertEqual(storage.read_bytes("values/blob.bin"), b"\x00\x01")

    def test_shared_and_principal_contexts_are_isolated(self) -> None:
        with RuntimeFixture() as fixture:
            storage = LocalStorage(fixture.data)
            shared = storage.shared_context()
            alice = storage.principal_context("alice")
            bob = storage.principal_context("bob")
            shared.write_json({"owner": "shared"})
            alice.write_json({"owner": "alice"})
            bob.write_json({"owner": "bob"})

            self.assertEqual(shared.read_json()["owner"], "shared")
            self.assertEqual(alice.read_json()["owner"], "alice")
            self.assertEqual(bob.read_json()["owner"], "bob")

    def test_traversal_absolute_and_portable_backslash_are_rejected(self) -> None:
        with RuntimeFixture() as fixture:
            storage = LocalStorage(fixture.data)
            for unsafe in ("../escape", "/absolute", r"..\escape", "."):
                with self.subTest(path=unsafe):
                    with self.assertRaises(StoragePathError):
                        storage.write_text(unsafe, "x")

    def test_unsafe_principal_is_rejected(self) -> None:
        with RuntimeFixture() as fixture:
            storage = LocalStorage(fixture.data)
            for principal in ("../alice", "", "a/b", ".."):
                with self.subTest(principal=principal):
                    with self.assertRaises(StoragePathError):
                        storage.principal_context(principal)

    def test_symlink_escape_is_rejected(self) -> None:
        with RuntimeFixture() as fixture:
            outside = fixture.root / "outside"
            outside.mkdir()
            (fixture.data / "linked").symlink_to(outside, target_is_directory=True)
            storage = LocalStorage(fixture.data)

            with self.assertRaises(StoragePathError):
                storage.write_text("linked/value.txt", "no")

    def test_concurrent_writers_never_leave_partial_json(self) -> None:
        with RuntimeFixture() as fixture:
            storage = LocalStorage(fixture.data)

            def write(index: int) -> None:
                storage.write_json(
                    "concurrent/value.json",
                    {"index": index, "payload": "x" * 2000},
                )

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(write, range(50)))

            value = storage.read_json("concurrent/value.json")
            self.assertIn(value["index"], range(50))
            self.assertEqual(len(value["payload"]), 2000)
            self.assertEqual(
                stat.S_IMODE(
                    (fixture.data / "concurrent" / "value.json").stat().st_mode
                ),
                0o600,
            )

    def test_size_limit_applies_to_reads_and_writes(self) -> None:
        with RuntimeFixture() as fixture:
            storage = LocalStorage(fixture.data, max_file_bytes=4)
            with self.assertRaises(StorageSizeError):
                storage.write_bytes("large.bin", b"12345")
            (fixture.data / "existing.bin").write_bytes(b"12345")
            with self.assertRaises(StorageSizeError):
                storage.read_bytes("existing.bin")

    def test_azure_compatibility_context_uses_explicit_root(self) -> None:
        with RuntimeFixture() as fixture:
            manager = AzureFileStorageManager(data_root=fixture.data)
            manager.write_json({"scope": "shared"})
            manager.set_memory_context("alice")
            manager.write_json({"scope": "alice"})
            self.assertEqual(manager.read_json(), {"scope": "alice"})
            manager.set_memory_context()
            self.assertEqual(manager.read_json(), {"scope": "shared"})

    def test_azure_compatibility_has_no_global_fallback(self) -> None:
        with self.assertRaisesRegex(StorageError, "explicit data_root"):
            AzureFileStorageManager()

    def test_delete_and_listing_are_contained_and_deterministic(self) -> None:
        with RuntimeFixture() as fixture:
            storage = LocalStorage(fixture.data)
            storage.write_text("items/b.txt", "b")
            storage.write_text("items/a.txt", "a")
            self.assertEqual(storage.list_files("items"), ("a.txt", "b.txt"))
            self.assertTrue(storage.delete("items/a.txt"))
            self.assertFalse(storage.delete("items/a.txt"))


if __name__ == "__main__":
    unittest.main()
