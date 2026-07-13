from __future__ import annotations

import io
import base64
import os
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from rapp_stack_cubby.packaging.archive import (
    ArchiveEntry,
    ArchiveLimits,
    VerifiedZip,
    extract_verified_zip,
    verify_zip,
    write_deterministic_zip,
)
from rapp_stack_cubby.packaging.common import PackagingError
from rapp_stack_cubby.packaging.source import (
    RELEASE_SOURCE_MANIFEST,
    scan_source_tree,
    validate_source_manifest,
    write_source_manifest,
)

from ._support import REPOSITORY_ROOT


class SourceManifestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix=".test-source-manifest-",
            dir=REPOSITORY_ROOT / "dist",
        )
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_stable_self_excluding_manifest_and_modes(self):
        (self.root / "nested").mkdir()
        (self.root / "nested/a.txt").write_text("alpha\n", encoding="utf-8")
        script = self.root / "check.sh"
        script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        script.chmod(0o755)
        first = write_source_manifest(self.root)
        self.assertNotIn("commit", first)
        self.assertNotIn(
            RELEASE_SOURCE_MANIFEST,
            {item["path"] for item in first["files"]},
        )
        self.assertEqual(validate_source_manifest(self.root)["file_count"], 2)
        os.utime(self.root / "nested/a.txt", (1, 1))
        second = scan_source_tree(self.root)
        self.assertEqual(
            first["source_tree_digest"], second["source_tree_digest"]
        )
        self.assertEqual(
            next(item for item in first["files"] if item["path"] == "check.sh")[
                "mode"
            ],
            "0755",
        )

    def test_rejects_links_special_paths_content_and_limits(self):
        target = self.root / "target.txt"
        target.write_text("safe\n", encoding="utf-8")
        link = self.root / "link"
        link.symlink_to(target)
        with self.assertRaises(PackagingError):
            scan_source_tree(self.root)
        link.unlink()
        secret = self.root / "settings.txt"
        secret.write_text("token=not-a-placeholder-value\n", encoding="utf-8")
        with self.assertRaises(PackagingError):
            scan_source_tree(self.root)
        secret.unlink()
        forbidden = self.root / ".env"
        forbidden.write_text("SAFE=example\n", encoding="utf-8")
        with self.assertRaises(PackagingError):
            scan_source_tree(self.root)
        forbidden.unlink()
        provider_token = self.root / ".copilot_token"
        provider_token.write_text(
            '{"access_token":"synthetic-placeholder"}\n',
            encoding="utf-8",
        )
        os.chmod(provider_token, 0o600)
        with self.assertRaisesRegex(PackagingError, "forbidden source name"):
            scan_source_tree(self.root)
        provider_token.unlink()
        fifo = self.root / "pipe"
        os.mkfifo(fifo)
        with self.assertRaises(PackagingError):
            scan_source_tree(self.root)
        fifo.unlink()
        with self.assertRaises(PackagingError):
            scan_source_tree(self.root, maximum_files=0)

    def test_skips_build_cache_and_private_roots(self):
        (self.root / "kept.txt").write_text("kept\n", encoding="utf-8")
        for name in ("dist", "build", "state", ".git"):
            directory = self.root / name
            directory.mkdir()
            (directory / "private.txt").write_text(
                "not packaged\n", encoding="utf-8"
            )
        result = scan_source_tree(self.root)
        self.assertEqual([item["path"] for item in result["files"]], ["kept.txt"])

    def test_ignores_editable_metadata_and_pycache_without_staling_manifest(self):
        (self.root / "kept.py").write_text("VALUE = 1\n", encoding="utf-8")
        baseline = write_source_manifest(self.root)
        metadata = self.root / "src/sample.egg-info"
        metadata.mkdir(parents=True)
        (metadata / "PKG-INFO").write_text(
            "Name: synthetic\n", encoding="utf-8"
        )
        cache = self.root / "src/package/__pycache__"
        cache.mkdir(parents=True)
        (cache / "module.cpython-311.pyc").write_bytes(b"generated")
        result = scan_source_tree(self.root)
        self.assertEqual(
            [item["path"] for item in result["files"]], ["kept.py"]
        )
        self.assertEqual(
            baseline["source_tree_digest"], result["source_tree_digest"]
        )
        self.assertEqual(validate_source_manifest(self.root)["file_count"], 1)

    def test_finds_credentials_in_nested_utf16_and_base64_content(self):
        pem = (
            b"-----BEGIN PRIVATE KEY-----\n"
            + b"A" * 64
            + b"\n-----END PRIVATE KEY-----"
        )
        cases = {
            "utf16.data": pem.decode().encode("utf-16"),
            "encoded.data": base64.b64encode(pem),
        }
        nested = io.BytesIO()
        with zipfile.ZipFile(nested, "w") as archive:
            archive.writestr("benign.txt", b"token=AbCdEf0123456789\n")
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w") as archive:
            archive.writestr("nested.data", nested.getvalue())
        cases["archive.data"] = outer.getvalue()
        for name, content in cases.items():
            with self.subTest(name=name):
                path = self.root / name
                path.write_bytes(content)
                with self.assertRaises(PackagingError):
                    scan_source_tree(self.root)
                path.unlink()


class DeterministicArchiveTests(unittest.TestCase):
    EPOCH = 1783892570

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix=".test-archive-",
            dir=REPOSITORY_ROOT / "dist",
        )
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def _build(self, name):
        return write_deterministic_zip(
            self.root / name,
            [
                ArchiveEntry("z.txt", data=b"z\n"),
                ArchiveEntry("nested/a.sh", data=b"#!/bin/sh\n", mode=0o755),
            ],
            source_date_epoch=self.EPOCH,
        )

    def test_two_builds_are_identical_and_metadata_is_normalized(self):
        first = self._build("one.zip")
        second = self._build("two.zip")
        self.assertEqual(first["sha256"], second["sha256"])
        self.assertEqual(
            (self.root / "one.zip").read_bytes(),
            (self.root / "two.zip").read_bytes(),
        )
        with zipfile.ZipFile(self.root / "one.zip") as archive:
            infos = archive.infolist()
        self.assertEqual([item.filename for item in infos], ["nested/a.sh", "z.txt"])
        self.assertTrue(all(item.create_system == 3 for item in infos))
        self.assertEqual(
            stat.S_IMODE(infos[0].external_attr >> 16), 0o755
        )

    def test_verified_extract_and_tamper_detection(self):
        built = self._build("artifact.zip")
        extracted = self.root / "extracted"
        result = extract_verified_zip(
            self.root / "artifact.zip",
            extracted,
            expected_sha256=built["sha256"],
            expected_files=built["files"],
        )
        self.assertEqual(result["file_count"], 2)
        self.assertEqual((extracted / "z.txt").read_bytes(), b"z\n")
        with self.assertRaises(PackagingError):
            verify_zip(self.root / "artifact.zip", expected_sha256="0" * 64)

    def test_rejects_traversal_symlink_duplicate_and_bomb(self):
        cases = {}
        traversal = io.BytesIO()
        with zipfile.ZipFile(traversal, "w") as archive:
            archive.writestr("../escape", b"x")
        cases["traversal.zip"] = traversal.getvalue()

        symlink = io.BytesIO()
        with zipfile.ZipFile(symlink, "w") as archive:
            info = zipfile.ZipInfo("link")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, b"target")
        cases["symlink.zip"] = symlink.getvalue()

        duplicate = io.BytesIO()
        with zipfile.ZipFile(duplicate, "w") as archive:
            info = zipfile.ZipInfo("same")
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, b"one")
            archive.writestr(info, b"two")
        cases["duplicate.zip"] = duplicate.getvalue()

        bomb = io.BytesIO()
        with zipfile.ZipFile(
            bomb, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as archive:
            info = zipfile.ZipInfo("large")
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, b"0" * 100_000)
        cases["bomb.zip"] = bomb.getvalue()

        for name, content in cases.items():
            with self.subTest(name=name):
                path = self.root / name
                path.write_bytes(content)
                with self.assertRaises(PackagingError):
                    verify_zip(
                        path,
                        limits=ArchiveLimits(maximum_compression_ratio=5),
                    )

    def test_path_replacement_cannot_change_extracted_verified_bytes(self):
        original = self.root / "bound.zip"
        replacement = self.root / "replacement.zip"
        write_deterministic_zip(
            original,
            [ArchiveEntry("value.txt", data=b"verified\n")],
            source_date_epoch=self.EPOCH,
        )
        write_deterministic_zip(
            replacement,
            [ArchiveEntry("value.txt", data=b"attacker\n")],
            source_date_epoch=self.EPOCH,
        )
        real_verify = VerifiedZip._verify_members

        def replace_after_verify(session):
            result = real_verify(session)
            os.replace(replacement, original)
            return result

        with patch.object(VerifiedZip, "_verify_members", replace_after_verify):
            extract_verified_zip(original, self.root / "bound-output")
        self.assertEqual(
            (self.root / "bound-output/value.txt").read_bytes(),
            b"verified\n",
        )


if __name__ == "__main__":
    unittest.main()
