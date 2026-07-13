from __future__ import annotations

import json
import hashlib
import unittest
import os
from pathlib import Path
from unittest.mock import patch

from rapp_stack_cubby.packaging.common import PackagingError
from rapp_stack_cubby.packaging.dependencies import (
    fetch_dependencies,
    stage_dependency_artifacts,
    verify_dependency_cache,
)
from rapp_stack_cubby.packaging.common import open_regular_nofollow

from ._support import PackagingWorkspace


class _Response:
    def __init__(self, content):
        self.content = content
        self.offset = 0

    def read(self, size):
        value = self.content[self.offset : self.offset + size]
        self.offset += len(value)
        return value

    def close(self):
        pass


class LockedDependencyFetchTests(unittest.TestCase):
    def setUp(self):
        self.workspace = PackagingWorkspace()
        self.workspace.__enter__()
        self.source, self.reference_cache = (
            self.workspace.copy_repository_with_fake_dependencies()
        )

    def tearDown(self):
        self.workspace.__exit__(None, None, None)

    def test_fetches_only_lock_urls_and_verifies_size_and_sha(self):
        lock = json.loads(
            (self.source / "DEPENDENCY_LOCK.json").read_text(encoding="utf-8")
        )
        by_url = {}
        for package in lock["packages"]:
            artifact = package["wheel"]
            by_url[artifact["url"]] = (
                self.reference_cache / artifact["filename"]
            ).read_bytes()
        for tool in lock["tools"]:
            artifact = tool["release"]
            by_url[artifact["url"]] = (
                self.reference_cache / artifact["asset"]
            ).read_bytes()
        requested = []

        def opener(request, **kwargs):
            self.assertIn("timeout", kwargs)
            requested.append(request.full_url)
            return _Response(by_url[request.full_url])

        cache = self.workspace.root / "fetched"
        result = fetch_dependencies(
            self.source,
            cache,
            opener=opener,
        )
        self.assertEqual(result["artifact_count"], 4)
        self.assertEqual(set(requested), set(by_url))
        self.assertTrue(verify_dependency_cache(self.source, cache)["verified"])

    def test_rejects_repository_cache_and_does_not_execute(self):
        with self.assertRaises(PackagingError):
            fetch_dependencies(
                self.source,
                self.source / "cache",
                opener=lambda request, **kwargs: _Response(b""),
            )

    def test_bad_download_is_removed(self):
        cache = self.workspace.root / "bad-cache"
        with self.assertRaises(PackagingError):
            fetch_dependencies(
                self.source,
                cache,
                opener=lambda request, **kwargs: _Response(b"bad"),
            )
        self.assertEqual(list(cache.glob("*.partial-*")), [])

    def test_staging_stays_bound_to_open_verified_cache_descriptor(self):
        first = next(self.reference_cache.iterdir())
        expected = first.read_bytes()
        replacement = self.reference_cache / ".replacement"
        replacement.write_bytes(b"attacker replacement")
        real_open = open_regular_nofollow
        replaced = False

        def open_then_replace(path):
            nonlocal replaced
            descriptor, info = real_open(path)
            if path == first and not replaced:
                replaced = True
                os.replace(replacement, first)
            return descriptor, info

        stage = self.workspace.root / "dependency-stage"
        stage.mkdir()
        with patch(
            "rapp_stack_cubby.packaging.common.open_regular_nofollow",
            open_then_replace,
        ):
            records = stage_dependency_artifacts(
                self.source, self.reference_cache, stage
            )
        record = next(
            item
            for item in records
            if item["sha256"] == hashlib.sha256(expected).hexdigest()
        )
        self.assertEqual((stage / record["path"]).read_bytes(), expected)


if __name__ == "__main__":
    unittest.main()
