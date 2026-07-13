"""Deterministic, offline-first RAPP packaging and hatch support."""

from .archive import (
    ArchiveEntry,
    ArchiveLimits,
    extract_verified_zip,
    verify_zip,
    write_deterministic_zip,
)
from .identity import build_identity, validate_identity
from .release import load_release_trust, verify_release
from .source import (
    RELEASE_SOURCE_MANIFEST,
    build_source_manifest,
    scan_source_tree,
    validate_source_manifest,
    write_source_manifest,
)

__all__ = [
    "ArchiveEntry",
    "ArchiveLimits",
    "RELEASE_SOURCE_MANIFEST",
    "build_identity",
    "build_source_manifest",
    "extract_verified_zip",
    "load_release_trust",
    "scan_source_tree",
    "validate_identity",
    "validate_source_manifest",
    "verify_zip",
    "verify_release",
    "write_deterministic_zip",
    "write_source_manifest",
]
