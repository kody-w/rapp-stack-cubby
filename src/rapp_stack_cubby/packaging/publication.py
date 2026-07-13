"""Fail-closed, execution-free scanner for every publication candidate."""

from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import io
import json
import math
import os
import re
import stat
import subprocess
import tarfile
import urllib.parse
import zipfile
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

from .common import (
    PackagingError,
    atomic_write,
    canonical_json_bytes,
    pretty_json_bytes,
    read_json_object,
    sha256_file,
    validate_relative_path,
)

POLICY_SCHEMA = "rapp-publication-scan-policy/1.0"
RECEIPT_SCHEMA = "rapp-publication-scan-receipt/1.0"
SIGNATURE_SCHEMA = "rapp-publication-scan-signature/1.0"
DEFAULT_TIMESTAMP = "1970-01-01T00:00:00Z"
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_CREDENTIAL_PATTERNS = (
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(rb"(?i)\bBearer[ \t]+[A-Za-z0-9._~+/-]{16,}\b"),
    re.compile(rb"(?i)\b(?:client_secret|refresh_token|access_token)="
               rb"[A-Za-z0-9._~+/-]{12,}\b"),
)
_PRIVATE_KEY_RE = re.compile(
    rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
)
_SECRET_ASSIGNMENT_RE = re.compile(
    rb"""(?ix)
    \b(?:api[_-]?key|authorization|client[_-]?secret|credential|password|
    private[_-]?key|recovery[_-]?(?:code|seed)|secret|token)\b
    [ \t]*[:=][ \t]*["']([A-Za-z0-9+/_~.=-]{12,})["']
    """
)
_EMAIL_RE = re.compile(
    rb"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    rb"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,63}\b"
)
_UUID_RE = re.compile(
    rb"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    rb"[89ab][0-9a-f]{3}-[0-9a-f]{12}\b"
)
_PHONE_RE = re.compile(
    rb"(?<![A-Za-z0-9])\+?[0-9](?:[0-9 ()_.-]{7,20})[0-9](?![A-Za-z0-9])"
)
_TRANSPORT_RE = re.compile(
    rb"""(?ix)
    \b(?:iMessage|SMS);[-+];[^\s"',]{3,}|
    \bchat[0-9]{2,}\b|
    ["']?\b(?:account|chat|message|transport)[_-]?(?:guid|id)["']?
    [ \t]*[:=][ \t]*["'][^"']{3,}["']
    """
)
_PRIVATE_CONTENT_RE = re.compile(
    rb"""(?ix)
    ["'](?:body|conversation|memory|message|prompt|response|transcript)["']
    [ \t]*:[ \t]*["']([^"'\r\n]{3,})["']
    """
)
_ENV_DUMP_RE = re.compile(
    rb"(?m)^(HOME|HOSTNAME|GITHUB_TOKEN|PATH|PWD|RUNNER_[A-Z_]+|"
    rb"ACTIONS_[A-Z_]+|USER|USERNAME)=([^\r\n]{2,})$"
)
_LOCAL_PATH_RE = re.compile(
    rb"(?:/(?:Users|home)/[^/\s]+/|[A-Za-z]:\\Users\\[^\\\s]+\\)"
)
_HIGH_ENTROPY_RE = re.compile(rb"(?<![A-Za-z0-9])[A-Za-z0-9+/_=-]{24,}(?![A-Za-z0-9])")
_BASE64_RE = re.compile(
    rb"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}"
    rb"(?![A-Za-z0-9+/_-])"
)
_URL_ESCAPE_RE = re.compile(rb"%[0-9A-Fa-f]{2}")
_ARCHIVE_SUFFIXES = (
    ".egg",
    ".gz",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".whl",
    ".zip",
)
_UNSUPPORTED_ARCHIVE_SUFFIXES = (
    ".7z",
    ".bz2",
    ".cab",
    ".dmg",
    ".iso",
    ".jar",
    ".lz",
    ".lzma",
    ".rar",
    ".xz",
)
_TEXT_SUFFIXES = {
    "",
    ".cfg",
    ".conf",
    ".css",
    ".csv",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".jsonl",
    ".lock",
    ".md",
    ".nojekyll",
    ".py",
    ".rst",
    ".sh",
    ".svg",
    ".toml",
    ".ts",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}
_SAFE_HIGH_ENTROPY_FIELDS = {
    "artifact_sha256",
    "blob",
    "checksum",
    "checksumvalue",
    "commit",
    "digest",
    "hash",
    "key_id",
    "sha",
    "sha1",
    "sha256",
    "sig",
    "signature_der_base64",
    "source_blob",
    "source_commit",
    "relatedspdxelement",
    "spdxid",
    "spdxelementid",
    "tree",
    "x",
    "y",
}
_PLACEHOLDER_WORDS = {
    b"changeme",
    b"example",
    b"placeholder",
    b"redacted",
    b"synthetic",
    b"test-only",
}
_BINARY_MAGICS = (
    b"\x7fELF",
    b"\xca\xfe\xba\xbe",
    b"\xcf\xfa\xed\xfe",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\x89PNG\r\n\x1a\n",
    b"\xff\xd8\xff",
    b"%PDF-",
)


class PublicationScanError(PackagingError):
    """Raised when scanner inputs or a receipt are structurally invalid."""


def load_publication_policy(path: str | Path) -> tuple[dict[str, Any], str]:
    candidate = Path(path)
    policy = read_json_object(candidate)
    required = {
        "allowlist",
        "forbidden_extensions",
        "forbidden_filenames",
        "limits",
        "normalized_timestamp",
        "schema",
        "source_exclusions",
    }
    if (
        set(policy) != required
        or policy.get("schema") != POLICY_SCHEMA
        or policy.get("normalized_timestamp") != DEFAULT_TIMESTAMP
        or not isinstance(policy.get("allowlist"), list)
        or not isinstance(policy.get("forbidden_extensions"), list)
        or not isinstance(policy.get("forbidden_filenames"), list)
        or not isinstance(policy.get("source_exclusions"), list)
        or not isinstance(policy.get("limits"), dict)
    ):
        raise PublicationScanError("publication scan policy fields are invalid")
    limits = policy["limits"]
    required_limits = {
        "max_archive_depth",
        "max_artifact_bytes",
        "max_binary_string_bytes",
        "max_compression_ratio",
        "max_expanded_bytes",
        "max_git_objects",
        "max_members",
    }
    if set(limits) != required_limits or any(
        not isinstance(limits.get(name), int)
        or isinstance(limits.get(name), bool)
        or limits[name] <= 0
        for name in required_limits
    ):
        raise PublicationScanError("publication scan limits are invalid")
    seen: set[str] = set()
    for item in policy["allowlist"]:
        if (
            not isinstance(item, dict)
            or set(item) - {
                "artifact_sha256",
                "expires",
                "id",
                "match_sha256",
                "path",
                "reason",
                "reviewer",
                "rule",
            }
            or set(item) < {"id", "reason", "reviewer", "rule"}
            or not all(isinstance(item.get(name), str) and item[name] for name in (
                "id",
                "reason",
                "reviewer",
                "rule",
            ))
            or item["id"] in seen
            or not any(
                isinstance(item.get(name), str) and item[name]
                for name in ("artifact_sha256", "match_sha256", "path")
            )
        ):
            raise PublicationScanError("publication allowlist entry is invalid")
        for name in ("artifact_sha256", "match_sha256"):
            value = item.get(name)
            if value is not None and (
                not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None
            ):
                raise PublicationScanError("publication allowlist digest is invalid")
        path_value = item.get("path")
        if path_value is not None:
            validate_relative_path(path_value)
        seen.add(item["id"])
    raw = candidate.read_bytes()
    return policy, hashlib.sha256(raw).hexdigest()


class _Scanner:
    def __init__(self, policy: Mapping[str, Any]) -> None:
        self.policy = policy
        self.limits = policy["limits"]
        self.findings: set[tuple[str, str, str, str, str]] = set()
        self.allowlist_uses: Counter[str] = Counter()
        self.scope_entries: dict[str, list[dict[str, Any]]] = {}
        self.scope_counts: dict[str, Counter[str]] = {}
        self.member_count = 0
        self.expanded_bytes = 0

    def _scope(self, name: str) -> Counter[str]:
        self.scope_entries.setdefault(name, [])
        return self.scope_counts.setdefault(name, Counter())

    def finding(
        self,
        rule: str,
        *,
        artifact: str,
        path: str,
        member: str,
        match: bytes,
        artifact_sha256: str,
    ) -> None:
        match_sha256 = hashlib.sha256(match).hexdigest()
        for item in self.policy["allowlist"]:
            if item["rule"] != rule:
                continue
            if item.get("path") not in {None, path}:
                continue
            if item.get("match_sha256") not in {None, match_sha256}:
                continue
            if item.get("artifact_sha256") not in {None, artifact_sha256}:
                continue
            self.allowlist_uses[item["id"]] += 1
            return
        self.findings.add((rule, artifact, member, path, match_sha256))

    def scan_path(
        self,
        scope: str,
        *,
        artifact: str,
        path: str,
        member: str,
        artifact_sha256: str,
    ) -> None:
        try:
            safe = validate_relative_path(path)
        except PackagingError:
            self.finding(
                "unsafe_path",
                artifact=artifact,
                path=path[:256] or ".",
                member=member,
                match=path.encode("utf-8", "backslashreplace"),
                artifact_sha256=artifact_sha256,
            )
            return
        pure = PurePosixPath(safe)
        folded_parts = [part.casefold() for part in pure.parts]
        folded_name = pure.name.casefold()
        suffixes = "".join(pure.suffixes[-2:]).casefold()
        forbidden_names = {
            str(value).casefold() for value in self.policy["forbidden_filenames"]
        }
        forbidden_extensions = {
            str(value).casefold() for value in self.policy["forbidden_extensions"]
        }
        if folded_name in forbidden_names:
            self.finding(
                "forbidden_filename",
                artifact=artifact,
                path=safe,
                member=member,
                match=pure.name.encode(),
                artifact_sha256=artifact_sha256,
            )
        if pure.suffix.casefold() in forbidden_extensions or suffixes in forbidden_extensions:
            self.finding(
                "forbidden_extension",
                artifact=artifact,
                path=safe,
                member=member,
                match=(suffixes or pure.suffix).encode(),
                artifact_sha256=artifact_sha256,
            )
        if any(
            part in {"__pycache__", ".git", ".idea", ".vscode"}
            for part in folded_parts
        ):
            self.finding(
                "forbidden_generated_path",
                artifact=artifact,
                path=safe,
                member=member,
                match=safe.encode(),
                artifact_sha256=artifact_sha256,
            )
        if pure.suffix.casefold() == ".map":
            self.finding(
                "hidden_source_map",
                artifact=artifact,
                path=safe,
                member=member,
                match=safe.encode(),
                artifact_sha256=artifact_sha256,
            )

    def scan_blob(
        self,
        scope: str,
        *,
        artifact: str,
        path: str,
        data: bytes,
        member: str = "",
        depth: int = 0,
        count_expanded: bool = False,
    ) -> None:
        digest = hashlib.sha256(data).hexdigest()
        count = self._scope(scope)
        count["members"] += 1
        count["bytes"] += len(data)
        self.member_count += 1
        if count_expanded:
            self.expanded_bytes += len(data)
        if (
            self.member_count > self.limits["max_members"]
            or self.expanded_bytes > self.limits["max_expanded_bytes"]
        ):
            self.finding(
                "scan_limit_exceeded",
                artifact=artifact,
                path=path,
                member=member,
                match=digest.encode(),
                artifact_sha256=digest,
            )
            return
        self.scope_entries[scope].append(
            {
                "artifact": artifact,
                "member": member,
                "path": path,
                "sha256": digest,
                "size": len(data),
            }
        )
        self.scan_path(
            scope,
            artifact=artifact,
            path=path,
            member=member,
            artifact_sha256=digest,
        )
        if len(data) > self.limits["max_artifact_bytes"]:
            self.finding(
                "artifact_size_limit",
                artifact=artifact,
                path=path,
                member=member,
                match=digest.encode(),
                artifact_sha256=digest,
            )
            return
        lower = path.casefold()
        if lower.endswith(_UNSUPPORTED_ARCHIVE_SUFFIXES):
            self.finding(
                "unsupported_archive",
                artifact=artifact,
                path=path,
                member=member,
                match=digest.encode(),
                artifact_sha256=digest,
            )
            return
        archive_kind = _archive_kind(path, data)
        if archive_kind is not None:
            self._scan_archive(
                scope,
                artifact=artifact,
                path=path,
                data=data,
                member=member,
                depth=depth,
                kind=archive_kind,
            )
            return
        if lower.endswith(_ARCHIVE_SUFFIXES):
            self.finding(
                "corrupt_archive",
                artifact=artifact,
                path=path,
                member=member,
                match=digest.encode(),
                artifact_sha256=digest,
            )
            return
        texts = _decoded_texts(data, suffix=PurePosixPath(path).suffix.casefold())
        if texts:
            for encoding, text in texts:
                self._scan_text(
                    artifact=artifact,
                    path=path,
                    member=member,
                    data=text,
                    artifact_sha256=digest,
                    encoding=encoding,
                    representation_depth=0,
                )
        else:
            if not data.startswith(_BINARY_MAGICS):
                self.finding(
                    "unsupported_binary",
                    artifact=artifact,
                    path=path,
                    member=member,
                    match=data[:64],
                    artifact_sha256=digest,
                )
            strings = b"\n".join(
                re.findall(
                    rb"[\x20-\x7e]{6,}",
                    data[: self.limits["max_binary_string_bytes"]],
                )
            )
            if strings:
                self._scan_text(
                    artifact=artifact,
                    path=path,
                    member=member,
                    data=strings,
                    artifact_sha256=digest,
                    encoding="binary-strings",
                    representation_depth=0,
                )

    def _scan_archive(
        self,
        scope: str,
        *,
        artifact: str,
        path: str,
        data: bytes,
        member: str,
        depth: int,
        kind: str,
    ) -> None:
        digest = hashlib.sha256(data).hexdigest()
        if depth >= self.limits["max_archive_depth"]:
            self.finding(
                "archive_depth_limit",
                artifact=artifact,
                path=path,
                member=member,
                match=digest.encode(),
                artifact_sha256=digest,
            )
            return
        try:
            if kind == "zip":
                self._scan_zip(scope, artifact, path, data, member, depth)
            elif kind == "tar":
                self._scan_tar(scope, artifact, path, data, member, depth)
            elif kind == "gzip":
                self._scan_gzip(scope, artifact, path, data, member, depth)
            else:
                raise PublicationScanError("unsupported archive kind")
        except (EOFError, OSError, tarfile.TarError, ValueError, zipfile.BadZipFile):
            self.finding(
                "corrupt_archive",
                artifact=artifact,
                path=path,
                member=member,
                match=digest.encode(),
                artifact_sha256=digest,
            )

    def _scan_zip(
        self,
        scope: str,
        artifact: str,
        path: str,
        data: bytes,
        member: str,
        depth: int,
    ) -> None:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = sorted(archive.infolist(), key=lambda item: item.filename.encode())
            if len(infos) + self.member_count > self.limits["max_members"]:
                raise ValueError("archive member limit")
            seen: set[str] = set()
            for info in infos:
                name = _safe_archive_member(info.filename, directory=info.is_dir())
                if name in seen:
                    raise ValueError("duplicate archive member")
                seen.add(name)
                mode = (info.external_attr >> 16) & 0o177777
                if info.flag_bits & 0x1:
                    raise ValueError("encrypted archive member")
                if mode and not (
                    stat.S_ISREG(mode)
                    or stat.S_ISDIR(mode)
                    or (mode & 0o170000) == 0
                ):
                    raise ValueError("special archive member")
                if info.file_size > self.limits["max_artifact_bytes"]:
                    raise ValueError("archive member size")
                compressed = max(info.compress_size, 1)
                if (
                    info.file_size > 4096
                    and info.file_size // compressed
                    > self.limits["max_compression_ratio"]
                ):
                    raise ValueError("archive compression ratio")
                chain = f"{member}!{name}" if member else name
                if info.is_dir():
                    self.scan_path(
                        scope,
                        artifact=artifact,
                        path=name,
                        member=chain,
                        artifact_sha256=hashlib.sha256(name.encode()).hexdigest(),
                    )
                    continue
                with archive.open(info, "r") as source:
                    content = _bounded_read(
                        source, self.limits["max_artifact_bytes"]
                    )
                if len(content) != info.file_size:
                    raise ValueError("archive member size mismatch")
                self.scan_blob(
                    scope,
                    artifact=artifact,
                    path=name,
                    data=content,
                    member=chain,
                    depth=depth + 1,
                    count_expanded=True,
                )

    def _scan_tar(
        self,
        scope: str,
        artifact: str,
        path: str,
        data: bytes,
        member: str,
        depth: int,
    ) -> None:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            infos = sorted(archive.getmembers(), key=lambda item: item.name.encode())
            if len(infos) + self.member_count > self.limits["max_members"]:
                raise ValueError("archive member limit")
            seen: set[str] = set()
            for info in infos:
                name = _safe_archive_member(info.name, directory=info.isdir())
                if name in seen:
                    raise ValueError("duplicate archive member")
                seen.add(name)
                chain = f"{member}!{name}" if member else name
                if info.isdir():
                    self.scan_path(
                        scope,
                        artifact=artifact,
                        path=name,
                        member=chain,
                        artifact_sha256=hashlib.sha256(name.encode()).hexdigest(),
                    )
                    continue
                if not info.isreg() or info.issym() or info.islnk():
                    raise ValueError("special tar member")
                if info.size > self.limits["max_artifact_bytes"]:
                    raise ValueError("tar member size")
                source = archive.extractfile(info)
                if source is None:
                    raise ValueError("tar member unavailable")
                with source:
                    content = _bounded_read(
                        source, self.limits["max_artifact_bytes"]
                    )
                if len(content) != info.size:
                    raise ValueError("tar member size mismatch")
                self.scan_blob(
                    scope,
                    artifact=artifact,
                    path=name,
                    data=content,
                    member=chain,
                    depth=depth + 1,
                    count_expanded=True,
                )

    def _scan_gzip(
        self,
        scope: str,
        artifact: str,
        path: str,
        data: bytes,
        member: str,
        depth: int,
    ) -> None:
        with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as archive:
            content = _bounded_read(archive, self.limits["max_artifact_bytes"])
        compressed = max(len(data), 1)
        if (
            len(content) > 4096
            and len(content) // compressed > self.limits["max_compression_ratio"]
        ):
            raise ValueError("gzip compression ratio")
        inner = path
        for suffix in (".tar.gz", ".tgz", ".gz"):
            if inner.casefold().endswith(suffix):
                inner = inner[: -len(suffix)] + (".tar" if suffix != ".gz" else "")
                break
        inner = PurePosixPath(inner).name or "gzip-member"
        chain = f"{member}!{inner}" if member else inner
        self.scan_blob(
            scope,
            artifact=artifact,
            path=inner,
            data=content,
            member=chain,
            depth=depth + 1,
            count_expanded=True,
        )

    def _scan_text(
        self,
        *,
        artifact: str,
        path: str,
        member: str,
        data: bytes,
        artifact_sha256: str,
        encoding: str,
        representation_depth: int,
    ) -> None:
        def report(rule: str, match: bytes) -> None:
            self.finding(
                rule,
                artifact=artifact,
                path=path,
                member=member,
                match=match,
                artifact_sha256=artifact_sha256,
            )

        for pattern in _CREDENTIAL_PATTERNS:
            for found in pattern.finditer(data):
                report("credential_token", found.group(0))
        for found in _PRIVATE_KEY_RE.finditer(data):
            report("private_key", found.group(0))
        for found in _SECRET_ASSIGNMENT_RE.finditer(data):
            value = found.group(1)
            if not any(word in value.lower() for word in _PLACEHOLDER_WORDS):
                report("secret_assignment", value)
        for found in _EMAIL_RE.finditer(data):
            report("email_identifier", found.group(0))
        for found in _UUID_RE.finditer(data):
            report("guid_identifier", found.group(0).lower())
        for found in _PHONE_RE.finditer(data):
            value = found.group(0)
            digits = bytes(character for character in value if 48 <= character <= 57)
            groups = tuple(
                len(group)
                for group in re.findall(rb"[0-9]+", value)
            )
            phone_shape = (
                value.startswith(b"+")
                or re.search(rb"\([0-9]{3}\)", value) is not None
                or (
                    len(groups) in {3, 4}
                    and groups[-1] == 4
                    and all(length <= 3 for length in groups[:-1])
                )
            )
            if 10 <= len(digits) <= 15 and phone_shape:
                report("phone_identifier", value)
        for found in _TRANSPORT_RE.finditer(data):
            report("transport_identifier", found.group(0))
        suffix = PurePosixPath(path).suffix.casefold()
        data_like = suffix in {".csv", ".json", ".jsonl", ".log", ".txt", ".xml"}
        if data_like:
            for found in _PRIVATE_CONTENT_RE.finditer(data):
                report("private_content_marker", found.group(0))
        environment_matches = list(_ENV_DUMP_RE.finditer(data))
        for found in environment_matches:
            key = found.group(1)
            value = found.group(2)
            if (
                b"$" not in value
                and b"<" not in value
                and not any(word in value.lower() for word in _PLACEHOLDER_WORDS)
                and (
                    len(environment_matches) >= 3
                    or key == b"GITHUB_TOKEN"
                    or _LOCAL_PATH_RE.search(value) is not None
                )
            ):
                report("environment_dump", found.group(0))
        for found in _LOCAL_PATH_RE.finditer(data):
            report("private_local_path", found.group(0))
        if (
            encoding != "binary-strings"
            and not path.casefold().endswith(".dist-info/record")
        ):
            for found in _HIGH_ENTROPY_RE.finditer(data):
                value = found.group(0)
                if _high_entropy_candidate(data, found.start(), found.end(), value):
                    report("high_entropy_candidate", value)
        if representation_depth >= 2:
            return
        if _URL_ESCAPE_RE.search(data):
            decoded = urllib.parse.unquote_to_bytes(data.decode("latin-1"))
            if decoded != data and len(decoded) <= self.limits["max_artifact_bytes"]:
                self._scan_text(
                    artifact=artifact,
                    path=path,
                    member=member,
                    data=decoded,
                    artifact_sha256=artifact_sha256,
                    encoding=(
                        "binary-strings"
                        if encoding == "binary-strings"
                        else "url"
                    ),
                    representation_depth=(
                        2
                        if encoding == "binary-strings"
                        else representation_depth + 1
                    ),
                )
        for found in _BASE64_RE.finditer(data):
            token = found.group(0)
            try:
                decoded = base64.b64decode(
                    token + b"=" * (-len(token) % 4),
                    altchars=b"-_",
                    validate=True,
                )
            except (binascii.Error, ValueError):
                continue
            if (
                8 <= len(decoded) <= self.limits["max_artifact_bytes"]
                and _looks_scannable_decoded(decoded)
            ):
                self._scan_text(
                    artifact=artifact,
                    path=path,
                    member=member,
                    data=decoded,
                    artifact_sha256=artifact_sha256,
                    encoding=(
                        "binary-strings"
                        if encoding == "binary-strings"
                        else "base64"
                    ),
                    representation_depth=(
                        2
                        if encoding == "binary-strings"
                        else representation_depth + 1
                    ),
                )

    def receipt_scopes(self, requested: Sequence[tuple[str, str]]) -> list[dict]:
        result: list[dict] = []
        for name, status in requested:
            entries = sorted(
                self.scope_entries.get(name, []),
                key=lambda item: (
                    item["artifact"],
                    item["member"],
                    item["path"],
                    item["sha256"],
                ),
            )
            counts = self.scope_counts.get(name, Counter())
            result.append(
                {
                    "artifact_count": counts["artifacts"],
                    "byte_count": counts["bytes"],
                    "member_count": counts["members"],
                    "name": name,
                    "sha256": hashlib.sha256(
                        canonical_json_bytes(entries)
                    ).hexdigest(),
                    "status": status,
                }
            )
        return result


def _archive_kind(path: str, data: bytes) -> str | None:
    lower = path.casefold()
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
        return "zip"
    if data.startswith(b"\x1f\x8b"):
        if lower.endswith((".tar.gz", ".tgz")):
            return "tar"
        return "gzip"
    if len(data) >= 262 and data[257:262] == b"ustar":
        return "tar"
    return None


def _safe_archive_member(value: str, *, directory: bool) -> str:
    if not isinstance(value, str):
        raise ValueError("archive member name")
    name = value[:-1] if directory and value.endswith("/") else value
    if (
        not name
        or "\x00" in name
        or "\\" in name
        or name.startswith("/")
        or PurePosixPath(name).is_absolute()
        or any(part in {"", ".", ".."} for part in PurePosixPath(name).parts)
        or PurePosixPath(name).as_posix() != name
    ):
        raise ValueError("unsafe archive path")
    validate_relative_path(name)
    return name


def _bounded_read(stream: Any, maximum: int) -> bytes:
    output = bytearray()
    while len(output) <= maximum:
        chunk = stream.read(min(128 * 1024, maximum + 1 - len(output)))
        if not chunk:
            return bytes(output)
        output.extend(chunk)
    raise ValueError("expanded member exceeds limit")


def _decoded_texts(data: bytes, *, suffix: str) -> list[tuple[str, bytes]]:
    if not data:
        return [("utf-8", b"")]
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        encoding = "utf-16-le" if data.startswith(b"\xff\xfe") else "utf-16-be"
        try:
            text = data[2:].decode(encoding)
        except UnicodeError:
            return []
        return [(encoding, text.encode("utf-8"))]
    if data.count(b"\x00") > len(data) // 5:
        for encoding in ("utf-16-le", "utf-16-be"):
            try:
                text = data.decode(encoding)
            except UnicodeError:
                continue
            if text and sum(character.isprintable() for character in text) / len(text) > 0.8:
                return [(encoding, text.encode("utf-8"))]
        return []
    try:
        data.decode("utf-8")
    except UnicodeError:
        return []
    if suffix in _TEXT_SUFFIXES or b"\x00" not in data:
        return [("utf-8", data)]
    return []


def _looks_scannable_decoded(data: bytes) -> bool:
    if _decoded_texts(data, suffix=".txt"):
        return True
    return any(pattern.search(data) for pattern in _CREDENTIAL_PATTERNS)


def _entropy(value: bytes) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def _high_entropy_candidate(
    data: bytes, start: int, end: int, value: bytes
) -> bool:
    folded = value.lower()
    if (
        len(value) < 24
        or folded in _PLACEHOLDER_WORDS
        or any(word in folded for word in _PLACEHOLDER_WORDS)
        or re.fullmatch(rb"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128}", value)
        or value.isdigit()
        or _entropy(value) < 4.15
        or value.startswith(b"/")
        or b"=/" in value
        or b"/" in value and b"-" in value
        or value.startswith(b"com/")
        or b"/blob/" in value
    ):
        return False
    before = data[max(0, start - 80) : start]
    field = re.search(rb"""(?i)["']?([a-z0-9_-]+)["']?[ \t]*[:=][ \t]*["']?$""", before)
    if field and field.group(1).decode("ascii", "ignore").casefold() in _SAFE_HIGH_ENTROPY_FIELDS:
        return False
    if data[max(0, start - 8) : start].lower().endswith((b"https://", b"http://")):
        return False
    has_lower = re.search(rb"[a-z]", value) is not None
    has_upper = re.search(rb"[A-Z]", value) is not None
    has_digit = re.search(rb"[0-9]", value) is not None
    has_base64_symbol = re.search(rb"[+/_=]", value) is not None
    return (
        has_lower
        and has_upper
        and has_digit
        and (has_base64_symbol or len(value) >= 32)
    )


def _run_git(root: Path, arguments: Sequence[str], *, input_: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *arguments],
            input=input_,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            shell=False,
            timeout=120,
            env={
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_OPTIONAL_LOCKS": "0",
                "HOME": str(root),
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
            },
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PublicationScanError("fixed Git plumbing failed") from error
    if result.returncode != 0:
        raise PublicationScanError("fixed Git plumbing returned an error")
    return result.stdout


def _git_available(root: Path) -> bool:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--git-dir"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            shell=False,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def _git_status(root: Path) -> dict[str, int]:
    categories = {
        "ignored": ["ls-files", "-z", "--others", "--ignored", "--exclude-standard"],
        "modified": ["diff", "--name-only", "-z"],
        "staged": ["diff", "--cached", "--name-only", "-z"],
        "tracked": ["ls-files", "-z", "--cached"],
        "untracked": ["ls-files", "-z", "--others", "--exclude-standard"],
    }
    return {
        name: len([item for item in _run_git(root, argv).split(b"\0") if item])
        for name, argv in categories.items()
    }


def _scan_directory(
    scanner: _Scanner,
    root: Path,
    *,
    scope: str,
    artifact: str,
    exclusions: Iterable[str] = (),
) -> None:
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise PublicationScanError(f"{scope} root is invalid")
    excluded = set(exclusions)
    scope_count = scanner._scope(scope)
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        current = Path(directory)
        relative_directory = current.relative_to(root)
        names[:] = sorted(names, key=lambda value: value.encode())
        files.sort(key=lambda value: value.encode())
        retained: list[str] = []
        for name in names:
            child = current / name
            relative = (relative_directory / name).as_posix()
            if relative in excluded or (
                relative_directory == Path(".") and name in excluded
            ):
                continue
            info = child.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                digest = hashlib.sha256(
                    os.readlink(child).encode() if stat.S_ISLNK(info.st_mode) else b"special"
                ).hexdigest()
                scanner.finding(
                    "unsafe_filesystem_entry",
                    artifact=artifact,
                    path=relative,
                    member="",
                    match=digest.encode(),
                    artifact_sha256=digest,
                )
                continue
            retained.append(name)
        names[:] = retained
        for name in files:
            path = current / name
            relative = (relative_directory / name).as_posix()
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                digest = hashlib.sha256(b"special").hexdigest()
                scanner.finding(
                    "unsafe_filesystem_entry",
                    artifact=artifact,
                    path=relative,
                    member="",
                    match=digest.encode(),
                    artifact_sha256=digest,
                )
                continue
            data = path.read_bytes()
            if len(data) != info.st_size:
                raise PublicationScanError("publication input changed while scanning")
            scope_count["artifacts"] += 1
            scanner.scan_blob(
                scope,
                artifact=artifact,
                path=relative,
                data=data,
            )


def _scan_git_history(
    scanner: _Scanner,
    root: Path,
    *,
    required: bool,
    allow_generated_pages: bool = False,
) -> tuple[dict[str, Any], str]:
    if not _git_available(root):
        if required:
            raise PublicationScanError("release scan requires a Git repository")
        return {
            "commit": None,
            "history": "not_available_development",
            "status": {
                "ignored": 0,
                "modified": 0,
                "staged": 0,
                "tracked": 0,
                "untracked": 0,
            },
            "tree": None,
        }, "not_available_development"
    status = _git_status(root)
    try:
        commit = _run_git(root, ["rev-parse", "--verify", "HEAD^{commit}"]).decode().strip()
        tree = _run_git(root, ["rev-parse", "--verify", "HEAD^{tree}"]).decode().strip()
    except PublicationScanError:
        if required:
            raise PublicationScanError("release scan requires a real Git commit")
        return {
            "commit": None,
            "history": "not_available_development",
            "status": status,
            "tree": None,
        }, "not_available_development"
    if _COMMIT_RE.fullmatch(commit) is None or _COMMIT_RE.fullmatch(tree) is None:
        raise PublicationScanError("Git commit or tree identity is invalid")
    generated_pages = {
        "docs/index.html",
        "docs/pages-manifest.json",
        *(f"docs/api/v1/{name}" for name in (
            "architecture.json",
            "capabilities.json",
            "context.json",
            "downloads.json",
            "prompts.json",
            "status.json",
        )),
        "docs/evidence/candidate-publication-scan.json",
        "docs/evidence/candidate-publication-scan.json.sig",
        "docs/evidence/postflight-success.json",
        "docs/evidence/postflight-success.json.sig",
    }
    modified = {
        item.decode("utf-8")
        for item in _run_git(root, ["diff", "--name-only", "-z"]).split(b"\0")
        if item
    }
    untracked = {
        item.decode("utf-8")
        for item in _run_git(
            root, ["ls-files", "-z", "--others", "--exclude-standard"]
        ).split(b"\0")
        if item
    }
    generated_only = (
        allow_generated_pages
        and not status["staged"]
        and modified <= generated_pages
        and untracked <= generated_pages
    )
    if (
        required
        and any(status[name] for name in ("modified", "staged", "untracked"))
        and not generated_only
    ):
        scanner.finding(
            "dirty_release_tree",
            artifact="git-history",
            path=".git/status",
            member="",
            match=canonical_json_bytes(status),
            artifact_sha256=hashlib.sha256(canonical_json_bytes(status)).hexdigest(),
        )
    objects = _run_git(root, ["rev-list", "--objects", "--all"]).splitlines()
    if len(objects) > scanner.limits["max_git_objects"]:
        raise PublicationScanError("Git object count exceeds publication policy")
    seen_blobs: set[str] = set()
    history_count = scanner._scope("history")
    for line in objects:
        oid_raw, _, path_raw = line.partition(b" ")
        try:
            oid = oid_raw.decode("ascii")
        except UnicodeError as error:
            raise PublicationScanError("Git object identity is invalid") from error
        if _COMMIT_RE.fullmatch(oid) is None:
            raise PublicationScanError("Git object identity is invalid")
        object_type = _run_git(root, ["cat-file", "-t", oid]).strip()
        if object_type != b"blob" or oid in seen_blobs:
            continue
        seen_blobs.add(oid)
        size_raw = _run_git(root, ["cat-file", "-s", oid]).strip()
        try:
            size = int(size_raw)
        except ValueError as error:
            raise PublicationScanError("Git blob size is invalid") from error
        if size > scanner.limits["max_artifact_bytes"]:
            data = oid.encode()
            scanner.finding(
                "artifact_size_limit",
                artifact="git-history",
                path=path_raw.decode("utf-8", "replace") or oid,
                member=oid,
                match=data,
                artifact_sha256=hashlib.sha256(data).hexdigest(),
            )
            continue
        data = _run_git(root, ["cat-file", "blob", oid])
        if len(data) != size:
            raise PublicationScanError("Git blob changed while scanning")
        path = path_raw.decode("utf-8", "replace") or f"objects/{oid}"
        history_count["artifacts"] += 1
        scanner.scan_blob(
            "history",
            artifact="git-history",
            path=path,
            data=data,
            member=oid,
        )
    commits = [
        item.decode("ascii")
        for item in _run_git(root, ["rev-list", "--all"]).splitlines()
        if item
    ]
    for oid in commits:
        if _COMMIT_RE.fullmatch(oid) is None:
            raise PublicationScanError("Git commit inventory is invalid")
        content = _run_git(root, ["cat-file", "commit", oid])
        history_count["artifacts"] += 1
        scanner.scan_blob(
            "history",
            artifact="git-history",
            path=f"git-objects/commits/{oid}.txt",
            data=content,
            member=oid,
        )
    refs = _run_git(
        root,
        ["for-each-ref", "--format=%(refname)%00%(objectname)%00%(objecttype)"],
    ).splitlines()
    for line in refs:
        fields = line.split(b"\0")
        if len(fields) != 3:
            raise PublicationScanError("Git ref inventory is invalid")
        ref, oid, kind = fields
        ref_text = ref.decode("utf-8", "replace")
        scanner._scan_text(
            artifact="git-history",
            path=".git/refs",
            member=oid.decode("ascii", "replace"),
            data=ref,
            artifact_sha256=hashlib.sha256(ref).hexdigest(),
            encoding="git-ref",
            representation_depth=0,
        )
        if kind == b"tag":
            tag = _run_git(root, ["cat-file", "tag", oid.decode("ascii")])
            history_count["artifacts"] += 1
            scanner.scan_blob(
                "history",
                artifact="git-history",
                path=f"git-tags/{ref_text.removeprefix('refs/tags/')}.txt",
                data=tag,
                member=oid.decode("ascii"),
            )
    history_count["git_blobs"] = len(seen_blobs)
    return {
        "commit": commit,
        "history": "complete",
        "status": status,
        "tree": tree,
    }, "complete"


def _check_pages_inventory(scanner: _Scanner, pages: Path) -> None:
    manifest_path = pages / "pages-manifest.json"
    try:
        value = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        scanner.finding(
            "pages_inventory_invalid",
            artifact="pages",
            path="pages-manifest.json",
            member="",
            match=b"invalid",
            artifact_sha256=hashlib.sha256(b"invalid").hexdigest(),
        )
        return
    files = value.get("files") if isinstance(value, dict) else None
    if (
        value.get("schema") != "rapp-pages-manifest/1.0"
        or value.get("self_hash") != "sha256-zeroed-self-record"
        or not isinstance(files, list)
    ):
        files = []
    records = {
        item.get("path"): item
        for item in files
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }
    observed = {
        path.relative_to(pages).as_posix()
        for path in pages.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    if set(records) != observed or value.get("file_count") != len(records):
        scanner.finding(
            "pages_inventory_invalid",
            artifact="pages",
            path="pages-manifest.json",
            member="",
            match=canonical_json_bytes(sorted(observed)),
            artifact_sha256=hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        )
        return
    for relative, record in records.items():
        path = pages / relative
        data = path.read_bytes()
        if relative == "pages-manifest.json":
            normalized = json.loads(data)
            own = [
                item
                for item in normalized.get("files", [])
                if item.get("path") == "pages-manifest.json"
            ]
            if len(own) != 1:
                digest = ""
            else:
                own[0]["sha256"] = "0" * 64
                digest = hashlib.sha256(pretty_json_bytes(normalized)).hexdigest()
        else:
            digest = hashlib.sha256(data).hexdigest()
        if record.get("size") != len(data) or record.get("sha256") != digest:
            scanner.finding(
                "pages_inventory_mismatch",
                artifact="pages",
                path=relative,
                member="",
                match=digest.encode(),
                artifact_sha256=hashlib.sha256(data).hexdigest(),
            )


def _check_release_inventory(scanner: _Scanner, release: Path, artifact: str) -> None:
    manifest_path = release / "release-manifest.json"
    if not manifest_path.is_file():
        scanner.finding(
            "release_inventory_invalid",
            artifact=artifact,
            path="release-manifest.json",
            member="",
            match=b"missing",
            artifact_sha256=hashlib.sha256(b"missing").hexdigest(),
        )
        return
    try:
        value = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        value = {}
    records = value.get("artifacts") if isinstance(value, dict) else None
    if not isinstance(records, list):
        records = []
    for item in records:
        if not isinstance(item, dict) or not isinstance(item.get("filename"), str):
            continue
        path = release / item["filename"]
        if path.is_symlink() or not path.is_file():
            digest, size = "", -1
        else:
            digest, size = sha256_file(path)
        if digest != item.get("sha256") or size != item.get("size"):
            scanner.finding(
                "release_inventory_mismatch",
                artifact=artifact,
                path=item["filename"],
                member="",
                match=(digest or "missing").encode(),
                artifact_sha256=digest or hashlib.sha256(b"missing").hexdigest(),
            )
    declared_names = {
        item["filename"]
        for item in records
        if isinstance(item, dict) and isinstance(item.get("filename"), str)
    }
    allowed_names = declared_names | {
        "SHA256SUMS",
        "candidate-publication-scan.json",
        "candidate-publication-scan.json.sig",
        "final-publication-scan.json",
        "final-publication-scan.json.sig",
        "live-proof-receipt.json",
        "live-proof-receipt.json.sig",
        "postflight-success.json",
        "postflight-success.json.sig",
        "promotion-receipt.json",
        "promotion-receipt.json.sig",
        "release-manifest.json",
        "release-manifest.json.sig",
    }
    observed_names = {
        path.name
        for path in release.iterdir()
        if path.is_file() and not path.is_symlink()
    }
    required_names = declared_names | {"SHA256SUMS", "release-manifest.json"}
    if (
        not required_names.issubset(observed_names)
        or not observed_names.issubset(allowed_names)
    ):
        scanner.finding(
            "release_inventory_invalid",
            artifact=artifact,
            path="release-assets",
            member="",
            match=canonical_json_bytes(sorted(observed_names)),
            artifact_sha256=hashlib.sha256(
                canonical_json_bytes(sorted(observed_names))
            ).hexdigest(),
        )
    checksums = release / "SHA256SUMS"
    if checksums.is_file():
        expected: dict[str, str] = {}
        valid_checksums = True
        for line in checksums.read_text(encoding="ascii").splitlines():
            parts = line.split("  ", 1)
            if len(parts) != 2 or _SHA256_RE.fullmatch(parts[0]) is None:
                valid_checksums = False
                break
            expected[parts[1]] = parts[0]
        if not valid_checksums:
            scanner.finding(
                "checksum_manifest_invalid",
                artifact=artifact,
                path="SHA256SUMS",
                member="",
                match=hashlib.sha256(checksums.read_bytes()).digest(),
                artifact_sha256=hashlib.sha256(checksums.read_bytes()).hexdigest(),
            )
        for name, digest in expected.items():
            path = release / name
            if path.is_symlink() or not path.is_file() or sha256_file(path)[0] != digest:
                scanner.finding(
                    "checksum_mismatch",
                    artifact=artifact,
                    path=name,
                    member="",
                    match=digest.encode(),
                    artifact_sha256=digest,
                )


def _directory_digest(root: Path) -> tuple[str, int]:
    records = []
    for path in sorted(
        (item for item in root.rglob("*") if item.is_file() and not item.is_symlink()),
        key=lambda item: item.relative_to(root).as_posix().encode(),
    ):
        digest, size = sha256_file(path)
        records.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": digest,
                "size": size,
            }
        )
    return hashlib.sha256(canonical_json_bytes(records)).hexdigest(), len(records)


def scan_publication(
    source_root: str | Path,
    *,
    policy_path: str | Path,
    pages_root: str | Path | None = None,
    release_assets_root: str | Path | None = None,
    public_redownload_root: str | Path | None = None,
    actions_logs: Sequence[tuple[str, str | Path]] = (),
    phase: str = "development",
    timestamp: str = DEFAULT_TIMESTAMP,
) -> dict[str, Any]:
    """Scan only explicit public candidates and return a redacted receipt."""

    if phase not in {"candidate", "development", "final"}:
        raise PublicationScanError("publication scan phase is invalid")
    if not isinstance(timestamp, str) or _TIMESTAMP_RE.fullmatch(timestamp) is None:
        raise PublicationScanError("publication scan timestamp must be exact UTC")
    root = Path(source_root)
    if not root.is_absolute():
        raise PublicationScanError("source root must be absolute")
    root = root.resolve(strict=True)
    policy, policy_sha256 = load_publication_policy(policy_path)
    scanner = _Scanner(policy)
    required_history = phase in {"candidate", "final"}
    source, history_status = _scan_git_history(
        scanner,
        root,
        required=required_history,
        allow_generated_pages=phase == "final",
    )
    source_exclusions = list(policy["source_exclusions"])
    _scan_directory(
        scanner,
        root,
        scope="source",
        artifact="source",
        exclusions=source_exclusions,
    )
    requested_scopes: list[tuple[str, str]] = [
        ("source", "complete"),
        ("history", history_status),
    ]
    if pages_root is not None:
        pages = Path(pages_root)
        if not pages.is_absolute():
            raise PublicationScanError("Pages root must be absolute")
        pages = pages.resolve(strict=True)
        _check_pages_inventory(scanner, pages)
        _scan_directory(scanner, pages, scope="pages", artifact="pages")
        requested_scopes.append(("pages", "complete"))
    elif phase in {"candidate", "final"}:
        raise PublicationScanError("release scan requires generated Pages")
    else:
        requested_scopes.append(("pages", "not_supplied_development"))
    if release_assets_root is not None:
        release = Path(release_assets_root)
        if not release.is_absolute():
            raise PublicationScanError("release assets root must be absolute")
        release = release.resolve(strict=True)
        _check_release_inventory(scanner, release, "release-assets")
        _scan_directory(
            scanner, release, scope="release_assets", artifact="release-assets"
        )
        requested_scopes.append(("release_assets", "complete"))
    elif phase in {"candidate", "final"}:
        raise PublicationScanError("release scan requires release assets")
    else:
        requested_scopes.append(("release_assets", "not_supplied_development"))
    if public_redownload_root is not None:
        redownload = Path(public_redownload_root)
        if not redownload.is_absolute():
            raise PublicationScanError("public redownload root must be absolute")
        redownload = redownload.resolve(strict=True)
        _check_release_inventory(scanner, redownload, "public-redownload")
        _scan_directory(
            scanner,
            redownload,
            scope="public_redownload",
            artifact="public-redownload",
        )
        if release_assets_root is not None:
            local_digest, local_count = _directory_digest(
                Path(release_assets_root).resolve(strict=True)
            )
            public_digest, public_count = _directory_digest(redownload)
            if (local_digest, local_count) != (public_digest, public_count):
                scanner.finding(
                    "public_redownload_mismatch",
                    artifact="public-redownload",
                    path="release-assets",
                    member="",
                    match=public_digest.encode(),
                    artifact_sha256=public_digest,
                )
        requested_scopes.append(("public_redownload", "complete"))
    elif phase == "final":
        raise PublicationScanError("final scan requires public redownload assets")
    else:
        requested_scopes.append(
            ("public_redownload", "not_required_for_phase")
        )
    actions_evidence: list[dict[str, Any]] = []
    seen_runs: set[str] = set()
    for run_id, path_value in sorted(actions_logs, key=lambda item: item[0]):
        if (
            not isinstance(run_id, str)
            or not run_id.isdigit()
            or run_id in seen_runs
        ):
            raise PublicationScanError("Actions run ID is invalid or duplicate")
        seen_runs.add(run_id)
        path = Path(path_value)
        if not path.is_absolute() or path.is_symlink() or not path.is_file():
            raise PublicationScanError("Actions log archive is invalid")
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        scanner._scope("actions_logs")["artifacts"] += 1
        scanner.scan_blob(
            "actions_logs",
            artifact=f"actions-log:{run_id}",
            path="actions-log.zip",
            data=data,
        )
        actions_evidence.append(
            {"run_id": run_id, "sha256": digest, "size": len(data)}
        )
    if actions_logs:
        requested_scopes.append(("actions_logs", "complete"))
    elif phase == "final":
        raise PublicationScanError("final scan requires completed Actions logs")
    else:
        requested_scopes.append(("actions_logs", "not_required_for_phase"))
    findings = [
        {
            "artifact": artifact,
            "digest": digest,
            "member": member,
            "path": path,
            "rule": rule,
        }
        for rule, artifact, member, path, digest in sorted(scanner.findings)
    ]
    scopes = scanner.receipt_scopes(requested_scopes)
    scope_counts = scanner.scope_counts
    receipt = {
        "actions_evidence": actions_evidence,
        "allowlist_uses": [
            {"count": count, "id": identifier}
            for identifier, count in sorted(scanner.allowlist_uses.items())
        ],
        "counts": {
            "artifacts": sum(value["artifacts"] for value in scope_counts.values()),
            "bytes": sum(value["bytes"] for value in scope_counts.values()),
            "findings": len(findings),
            "git_blobs": scope_counts.get("history", Counter())["git_blobs"],
            "members": sum(value["members"] for value in scope_counts.values()),
        },
        "findings": findings,
        "phase": phase,
        "policy_sha256": policy_sha256,
        "result": "pass" if not findings else "fail",
        "scanner": "rapp-stack-cubby-publication-scanner/1.0",
        "schema": RECEIPT_SCHEMA,
        "scopes": scopes,
        "source": source,
        "timestamp": timestamp,
    }
    return receipt


def write_publication_receipt(path: str | Path, receipt: Mapping[str, Any]) -> None:
    output = Path(path)
    if not output.is_absolute():
        raise PublicationScanError("publication receipt output must be absolute")
    atomic_write(output, pretty_json_bytes(dict(receipt)), mode=0o644)


def sign_publication_receipt(
    receipt_path: str | Path,
    signature_path: str | Path,
    *,
    key_path: str | Path,
    repository_root: str | Path,
    trust_path: str | Path,
) -> dict[str, Any]:
    """Sign exact receipt bytes with the pinned deterministic release key."""

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature,
        encode_dss_signature,
    )

    from .release import ALGORITHM, P256_ORDER, _private_key, load_release_trust

    receipt = Path(receipt_path)
    output = Path(signature_path)
    if not receipt.is_absolute() or not output.is_absolute():
        raise PublicationScanError("receipt and signature paths must be absolute")
    if output.exists() or output.is_symlink():
        raise PublicationScanError("publication signature output already exists")
    value = read_json_object(receipt)
    if value.get("schema") != RECEIPT_SCHEMA or value.get("result") != "pass":
        raise PublicationScanError("only a passing publication receipt may be signed")
    trust = load_release_trust(trust_path)
    key = _private_key(Path(key_path), Path(repository_root), trust)
    content = receipt.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    der = key.sign(content, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    r, s = decode_dss_signature(der)
    if s > P256_ORDER // 2:
        s = P256_ORDER - s
    sidecar = {
        "algorithm": ALGORITHM,
        "artifact": receipt.name,
        "artifact_sha256": digest,
        "key_id": trust["key_id"],
        "schema": SIGNATURE_SCHEMA,
        "signature_der_base64": base64.b64encode(
            encode_dss_signature(r, s)
        ).decode("ascii"),
    }
    atomic_write(output, pretty_json_bytes(sidecar), mode=0o644)
    return sidecar


def verify_publication_receipt(
    receipt_path: str | Path,
    *,
    policy_path: str | Path,
    required_phase: str,
    signature_path: str | Path | None = None,
    trust_path: str | Path | None = None,
    expected_source_commit: str | None = None,
) -> dict[str, Any]:
    """Verify policy binding, mandatory scopes, and optional pinned signature."""

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature,
        encode_dss_signature,
    )

    from .release import (
        ALGORITHM,
        P256_ORDER,
        _public_key,
        load_release_trust,
    )

    if required_phase not in {"candidate", "development", "final"}:
        raise PublicationScanError("required publication phase is invalid")
    if expected_source_commit is not None and (
        not isinstance(expected_source_commit, str)
        or _COMMIT_RE.fullmatch(expected_source_commit) is None
    ):
        raise PublicationScanError("expected publication source commit is invalid")
    receipt = Path(receipt_path)
    value = read_json_object(receipt)
    _, policy_sha256 = load_publication_policy(policy_path)
    if (
        value.get("schema") != RECEIPT_SCHEMA
        or value.get("scanner") != "rapp-stack-cubby-publication-scanner/1.0"
        or value.get("phase") != required_phase
        or value.get("policy_sha256") != policy_sha256
        or value.get("result") != "pass"
        or value.get("findings") != []
        or not isinstance(value.get("counts"), dict)
        or value["counts"].get("findings") != 0
        or (
            expected_source_commit is not None
            and (
                not isinstance(value.get("source"), dict)
                or value["source"].get("commit") != expected_source_commit
            )
        )
    ):
        raise PublicationScanError("publication scan receipt is not a passing proof")
    scopes = {
        item.get("name"): item.get("status")
        for item in value.get("scopes", [])
        if isinstance(item, dict)
    }
    required_scopes = {"source"}
    if required_phase in {"candidate", "final"}:
        required_scopes |= {"history", "pages", "release_assets"}
    if required_phase == "final":
        required_scopes |= {"public_redownload", "actions_logs"}
    if any(scopes.get(name) != "complete" for name in required_scopes):
        raise PublicationScanError("publication scan receipt scopes are incomplete")
    if required_phase == "development" and scopes.get("history") not in {
        "complete",
        "not_available_development",
    }:
        raise PublicationScanError("development history status is invalid")
    signed = signature_path is not None or trust_path is not None
    if required_phase in {"candidate", "final"} and not signed:
        raise PublicationScanError(
            "candidate and final publication receipts must be signed"
        )
    if signed and (signature_path is None or trust_path is None):
        raise PublicationScanError("signature and trust must be supplied together")
    key_id = None
    if signed:
        trust = load_release_trust(trust_path)
        sidecar = read_json_object(Path(signature_path))
        expected_fields = {
            "algorithm",
            "artifact",
            "artifact_sha256",
            "key_id",
            "schema",
            "signature_der_base64",
        }
        content = receipt.read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        if (
            set(sidecar) != expected_fields
            or sidecar.get("schema") != SIGNATURE_SCHEMA
            or sidecar.get("algorithm") != ALGORITHM
            or sidecar.get("artifact") != receipt.name
            or sidecar.get("artifact_sha256") != digest
            or sidecar.get("key_id") != trust["key_id"]
        ):
            raise PublicationScanError("publication scan signature binding is invalid")
        try:
            der = base64.b64decode(
                sidecar["signature_der_base64"], validate=True
            )
            r, s = decode_dss_signature(der)
        except (binascii.Error, TypeError, ValueError) as error:
            raise PublicationScanError("publication signature encoding is invalid") from error
        if (
            not 1 <= r < P256_ORDER
            or not 1 <= s <= P256_ORDER // 2
            or encode_dss_signature(r, s) != der
        ):
            raise PublicationScanError("publication signature is not canonical low-S")
        try:
            _public_key(trust).verify(
                der, content, ec.ECDSA(hashes.SHA256())
            )
        except InvalidSignature as error:
            raise PublicationScanError("publication signature verification failed") from error
        key_id = trust["key_id"]
    return {
        "actions_evidence": value.get("actions_evidence", []),
        "key_id": key_id,
        "phase": required_phase,
        "policy_sha256": policy_sha256,
        "source_commit": (
            value.get("source", {}).get("commit")
            if isinstance(value.get("source"), dict)
            else None
        ),
        "schema": RECEIPT_SCHEMA,
        "signed": signed,
        "verified": True,
    }
