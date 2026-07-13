"""Deterministic ZIP production and descriptor-bound hostile verification."""

from __future__ import annotations

import hashlib
import os
import stat
import time
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

from .common import (
    BUFFER_SIZE,
    PackagingError,
    open_regular_nofollow,
    mode_text,
    parse_mode,
    sha256_file,
    validate_relative_path,
)


@dataclass(frozen=True, slots=True)
class ArchiveEntry:
    """One deterministic regular-file archive member."""

    path: str
    data: bytes | None = None
    source: Path | None = None
    mode: int = 0o644

    def bytes(self) -> bytes:
        if (self.data is None) == (self.source is None):
            raise PackagingError("archive entry requires exactly one data source")
        if self.data is not None:
            return self.data
        assert self.source is not None
        descriptor, info = open_regular_nofollow(self.source)
        try:
            with os.fdopen(descriptor, "rb", closefd=True) as stream:
                value = stream.read()
        except OSError as error:
            raise PackagingError(f"cannot read archive member {self.path}") from error
        if len(value) != info.st_size:
            raise PackagingError(f"archive member changed: {self.path}")
        return value


@dataclass(frozen=True, slots=True)
class ArchiveLimits:
    """Resource limits applied before and while reading a ZIP."""

    maximum_members: int = 25_000
    maximum_member_bytes: int = 64 * 1024 * 1024
    maximum_total_bytes: int = 1024 * 1024 * 1024
    maximum_compression_ratio: int = 200
    maximum_path_depth: int = 32
    maximum_archive_bytes: int = 1024 * 1024 * 1024


def _zip_timestamp(epoch: int) -> tuple[int, int, int, int, int, int]:
    if not isinstance(epoch, int) or isinstance(epoch, bool):
        raise PackagingError("SOURCE_DATE_EPOCH must be an integer")
    value = time.gmtime(epoch)
    if value.tm_year < 1980 or value.tm_year > 2107:
        raise PackagingError("SOURCE_DATE_EPOCH is outside the ZIP range")
    return (
        value.tm_year,
        value.tm_mon,
        value.tm_mday,
        value.tm_hour,
        value.tm_min,
        value.tm_sec - (value.tm_sec % 2),
    )


def write_deterministic_zip(
    output: str | Path,
    entries: Iterable[ArchiveEntry],
    *,
    source_date_epoch: int,
    compression_level: int = 0,
) -> dict:
    """Write a sorted ZIP using stored entries for locked-toolchain stability."""

    if compression_level != 0:
        raise PackagingError("deterministic ZIP profile requires stored entries")
    destination = Path(output)
    if destination.exists() or destination.is_symlink():
        raise PackagingError(f"refuse to overwrite {destination.name}")
    timestamp = _zip_timestamp(source_date_epoch)
    normalized: list[tuple[str, ArchiveEntry]] = []
    seen: set[str] = set()
    for entry in entries:
        path = validate_relative_path(entry.path)
        if path in seen:
            raise PackagingError(f"duplicate archive member: {path}")
        if entry.mode not in {0o644, 0o755}:
            raise PackagingError(f"unsafe archive mode for {path}")
        seen.add(path)
        normalized.append((path, entry))
    normalized.sort(key=lambda item: item[0].encode("utf-8"))
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(
        f".{destination.name}.new-{uuid.uuid4().hex}"
    )
    records: list[dict] = []
    try:
        with zipfile.ZipFile(
            temporary,
            mode="x",
            compression=zipfile.ZIP_STORED,
            strict_timestamps=True,
        ) as archive:
            archive.comment = b""
            for path, entry in normalized:
                content = entry.bytes()
                info = zipfile.ZipInfo(path, date_time=timestamp)
                info.create_system = 3
                info.create_version = 20
                info.extract_version = 20
                info.flag_bits = 0x800
                info.compress_type = zipfile.ZIP_STORED
                info.external_attr = (stat.S_IFREG | entry.mode) << 16
                info.internal_attr = 0
                info.extra = b""
                info.comment = b""
                archive.writestr(info, content, compress_type=zipfile.ZIP_STORED)
                records.append(
                    {
                        "mode": mode_text(entry.mode),
                        "path": path,
                        "sha256": hashlib.sha256(content).hexdigest(),
                        "size": len(content),
                    }
                )
        os.chmod(temporary, 0o644)
        os.replace(temporary, destination)
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        temporary.unlink(missing_ok=True)
        if isinstance(error, PackagingError):
            raise
        raise PackagingError("deterministic ZIP creation failed") from error
    digest, size = sha256_file(destination)
    return {
        "file_count": len(records),
        "files": records,
        "sha256": digest,
        "size": size,
    }


def _member_mode(info: zipfile.ZipInfo) -> int:
    raw = (info.external_attr >> 16) & 0xFFFF
    if info.create_system != 3 or stat.S_IFMT(raw) != stat.S_IFREG:
        raise PackagingError(f"non-regular ZIP member: {info.filename}")
    permissions = stat.S_IMODE(raw)
    if permissions not in {0o644, 0o755}:
        raise PackagingError(f"unsafe ZIP member mode: {info.filename}")
    return permissions


def _normal_expected(
    expected_files: Iterable[Mapping[str, object]] | None,
) -> list[dict] | None:
    if expected_files is None:
        return None
    normalized: list[dict] = []
    for value in expected_files:
        try:
            normalized.append(
                {
                    "mode": mode_text(parse_mode(value["mode"])),
                    "path": validate_relative_path(str(value["path"])),
                    "sha256": str(value["sha256"]),
                    "size": int(value["size"]),
                }
            )
        except (KeyError, TypeError, ValueError) as error:
            raise PackagingError("invalid expected member manifest") from error
    normalized.sort(key=lambda item: item["path"].encode("utf-8"))
    return normalized


def _open_archive_descriptor(path: Path, limit: int) -> tuple[int, str, int]:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise PackagingError("archive is not a bounded regular file")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(descriptor, BUFFER_SIZE)
            if not chunk:
                break
            size += len(chunk)
            if size > limit:
                raise PackagingError("archive exceeds its byte limit")
            digest.update(chunk)
        if size != info.st_size:
            raise PackagingError("archive changed while being read")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor, digest.hexdigest(), size
    except Exception:
        if "descriptor" in locals():
            os.close(descriptor)
        raise


class VerifiedZip:
    """An open, fully verified archive whose path is never reopened."""

    def __init__(
        self,
        path: str | Path,
        *,
        expected_sha256: str | None = None,
        expected_files: Iterable[Mapping[str, object]] | None = None,
        limits: ArchiveLimits = ArchiveLimits(),
        capture_members: Iterable[str] = (),
    ) -> None:
        self.path = Path(path)
        self.expected_sha256 = expected_sha256
        self.expected_files = _normal_expected(expected_files)
        self.limits = limits
        self.capture_members = frozenset(capture_members)
        self._stream = None
        self._archive = None
        self._infos: dict[str, zipfile.ZipInfo] = {}
        self.captured: dict[str, bytes] = {}
        self.result: dict = {}

    def __enter__(self) -> "VerifiedZip":
        descriptor, archive_digest, archive_size = _open_archive_descriptor(
            self.path, self.limits.maximum_archive_bytes
        )
        if (
            self.expected_sha256 is not None
            and archive_digest != self.expected_sha256
        ):
            os.close(descriptor)
            raise PackagingError("archive SHA-256 mismatch")
        self._stream = os.fdopen(descriptor, "rb", closefd=True)
        try:
            self._archive = zipfile.ZipFile(self._stream, "r")
            records, total = self._verify_members()
            if self.expected_files is not None and self.expected_files != records:
                raise PackagingError("ZIP members do not match the manifest")
            self.result = {
                "file_count": len(records),
                "files": records,
                "sha256": archive_digest,
                "size": archive_size,
                "total_uncompressed_bytes": total,
            }
            return self
        except Exception:
            self.close()
            raise

    def _verify_members(self) -> tuple[list[dict], int]:
        assert self._archive is not None
        infos = self._archive.infolist()
        if not infos or len(infos) > self.limits.maximum_members:
            raise PackagingError("ZIP member count is invalid")
        records: list[dict] = []
        total = 0
        for info in infos:
            name = validate_relative_path(info.filename)
            if name in self._infos:
                raise PackagingError(f"duplicate ZIP member: {name}")
            self._infos[name] = info
            if len(name.split("/")) > self.limits.maximum_path_depth:
                raise PackagingError(f"ZIP path is too deep: {name}")
            if info.flag_bits & 0x1:
                raise PackagingError("encrypted ZIP members are forbidden")
            if info.compress_type not in {
                zipfile.ZIP_DEFLATED,
                zipfile.ZIP_STORED,
            }:
                raise PackagingError("unsupported ZIP compression")
            mode = _member_mode(info)
            if (
                info.file_size < 0
                or info.file_size > self.limits.maximum_member_bytes
                or info.compress_size < 0
            ):
                raise PackagingError("ZIP member exceeds resource limits")
            if (
                info.file_size > 0
                and info.file_size
                > max(1, info.compress_size)
                * self.limits.maximum_compression_ratio
            ):
                raise PackagingError("ZIP compression ratio is unsafe")
            total += info.file_size
            if total > self.limits.maximum_total_bytes:
                raise PackagingError("ZIP expands beyond its total limit")
            digest = hashlib.sha256()
            count = 0
            captured = bytearray() if name in self.capture_members else None
            with self._archive.open(info, "r") as source:
                while True:
                    chunk = source.read(BUFFER_SIZE)
                    if not chunk:
                        break
                    count += len(chunk)
                    if count > info.file_size:
                        raise PackagingError("ZIP member size changed")
                    digest.update(chunk)
                    if captured is not None:
                        captured.extend(chunk)
            if count != info.file_size:
                raise PackagingError("ZIP member is truncated")
            if captured is not None:
                self.captured[name] = bytes(captured)
            records.append(
                {
                    "mode": mode_text(mode),
                    "path": name,
                    "sha256": digest.hexdigest(),
                    "size": count,
                }
            )
        records.sort(key=lambda item: item["path"].encode("utf-8"))
        return records, total

    def extract(self, destination: str | Path) -> None:
        """Extract through this session and hash each output before promotion."""

        assert self._archive is not None
        target = Path(destination)
        if target.exists() or target.is_symlink():
            raise PackagingError("extraction destination already exists")
        target.mkdir(parents=False, mode=0o700)
        try:
            for record in self.result["files"]:
                relative = Path(*record["path"].split("/"))
                output = target / relative
                output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                partial = output.with_name(
                    f".{output.name}.part-{uuid.uuid4().hex}"
                )
                descriptor = os.open(
                    partial,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                digest = hashlib.sha256()
                count = 0
                try:
                    with os.fdopen(descriptor, "wb") as destination_file:
                        with self._archive.open(
                            self._infos[record["path"]], "r"
                        ) as source:
                            while True:
                                chunk = source.read(BUFFER_SIZE)
                                if not chunk:
                                    break
                                count += len(chunk)
                                if count > record["size"]:
                                    raise PackagingError(
                                        "extracted member size changed"
                                    )
                                digest.update(chunk)
                                destination_file.write(chunk)
                        destination_file.flush()
                        os.fsync(destination_file.fileno())
                    if (
                        count != record["size"]
                        or digest.hexdigest() != record["sha256"]
                    ):
                        raise PackagingError(
                            "extracted member does not match verified bytes"
                        )
                    os.chmod(partial, parse_mode(record["mode"]))
                    os.replace(partial, output)
                except Exception:
                    partial.unlink(missing_ok=True)
                    raise
        except Exception:
            _remove_extraction(target)
            raise

    def close(self) -> None:
        if self._archive is not None:
            self._archive.close()
            self._archive = None
        if self._stream is not None:
            self._stream.close()
            self._stream = None

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


def _remove_extraction(path: Path) -> None:
    if not path.exists():
        return
    for directory, names, files in os.walk(path, topdown=False):
        current = Path(directory)
        for name in files:
            (current / name).unlink(missing_ok=True)
        for name in names:
            child = current / name
            if child.is_symlink():
                child.unlink(missing_ok=True)
            else:
                child.rmdir()
    path.rmdir()


def verify_zip(
    path: str | Path,
    *,
    expected_sha256: str | None = None,
    expected_files: Iterable[Mapping[str, object]] | None = None,
    limits: ArchiveLimits = ArchiveLimits(),
) -> dict:
    """Verify a ZIP through one no-follow descriptor."""

    try:
        with VerifiedZip(
            path,
            expected_sha256=expected_sha256,
            expected_files=expected_files,
            limits=limits,
        ) as verified:
            return verified.result
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        if isinstance(error, PackagingError):
            raise
        raise PackagingError("invalid ZIP archive") from error


def extract_verified_zip(
    path: str | Path,
    destination: str | Path,
    *,
    expected_sha256: str | None = None,
    expected_files: Iterable[Mapping[str, object]] | None = None,
    limits: ArchiveLimits = ArchiveLimits(),
) -> dict:
    """Verify and extract without closing or reopening the artifact path."""

    try:
        with VerifiedZip(
            path,
            expected_sha256=expected_sha256,
            expected_files=expected_files,
            limits=limits,
        ) as verified:
            verified.extract(destination)
            return verified.result
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        if isinstance(error, PackagingError):
            raise
        raise PackagingError("invalid ZIP archive") from error
