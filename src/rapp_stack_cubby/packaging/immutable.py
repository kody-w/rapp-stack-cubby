"""Immutable Git source staging for release builds and verification."""

from __future__ import annotations

import io
import os
import shutil
import stat
import subprocess
import tarfile
from dataclasses import dataclass
from pathlib import Path

from .common import (
    COMMIT_RE,
    PackagingError,
    copy_verified_file,
    hash_stream,
    mode_text,
    open_regular_nofollow,
    parse_mode,
    read_json_object,
    sha256_file,
    validate_relative_path,
)
from .source import (
    MAX_SOURCE_FILE_BYTES,
    RELEASE_SOURCE_MANIFEST,
    validate_source_manifest,
)


@dataclass(frozen=True, slots=True)
class SourceMaterial:
    root: Path
    revision: str
    source_tree_digest: str
    git_tree: str | None
    head: str | None
    immutable: bool


def _git(repository: Path, *arguments: str) -> bytes:
    environment = {
        "HOME": str(repository),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin:/opt/homebrew/bin",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    try:
        result = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PackagingError("immutable Git source operation failed") from error
    if result.returncode != 0:
        raise PackagingError("release source is not the requested Git commit")
    return result.stdout


def _git_text(repository: Path, *arguments: str) -> str:
    try:
        return _git(repository, *arguments).decode("ascii").strip()
    except UnicodeError as error:
        raise PackagingError("Git returned a non-ASCII object identity") from error


def _require_clean(repository: Path) -> None:
    if _git_text(repository, "rev-parse", "--is-inside-work-tree") != "true":
        raise PackagingError("release source must be a real Git worktree")
    if _git(repository, "diff", "--quiet", "--ignore-submodules", "--") != b"":
        raise PackagingError("release source tracked tree is dirty")
    if (
        _git(
            repository,
            "diff",
            "--cached",
            "--quiet",
            "--ignore-submodules",
            "--",
        )
        != b""
    ):
        raise PackagingError("release source index is dirty")
    status = _git(
        repository,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignored=no",
    )
    if status:
        raise PackagingError("release source tree contains uncommitted files")


def _extract_git_archive(content: bytes, destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        raise PackagingError("immutable source stage already exists")
    destination.mkdir(mode=0o700)
    try:
        with tarfile.open(fileobj=io.BytesIO(content), mode="r:") as archive:
            members = archive.getmembers()
            if len(members) > 25_000:
                raise PackagingError("Git archive has too many entries")
            total = 0
            for member in members:
                path = validate_relative_path(member.name.rstrip("/"))
                output = destination / Path(*path.split("/"))
                if member.isdir():
                    output.mkdir(parents=True, exist_ok=True, mode=0o755)
                    continue
                if not member.isreg():
                    raise PackagingError("Git archive contains a non-regular entry")
                total += member.size
                if member.size > 32 * 1024 * 1024 or total > 512 * 1024 * 1024:
                    raise PackagingError("Git archive exceeds source limits")
                output.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise PackagingError("Git archive member is unavailable")
                mode = 0o755 if member.mode & 0o111 else 0o644
                descriptor = os.open(
                    output,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0),
                    mode,
                )
                count = 0
                with os.fdopen(descriptor, "wb") as stream:
                    while True:
                        chunk = extracted.read(128 * 1024)
                        if not chunk:
                            break
                        count += len(chunk)
                        if count > member.size:
                            raise PackagingError("Git archive member changed")
                        stream.write(chunk)
                    stream.flush()
                    os.fsync(stream.fileno())
                if count != member.size:
                    raise PackagingError("Git archive member is truncated")
                os.chmod(output, mode)
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def _manifest_records(source: Path, validated: dict) -> list[dict]:
    manifest_path = source / RELEASE_SOURCE_MANIFEST
    manifest = read_json_object(
        manifest_path,
        maximum_bytes=64 * 1024 * 1024,
    )
    digest, size = sha256_file(manifest_path, limit=64 * 1024 * 1024)
    if (
        digest != validated["manifest_sha256"]
        or size != validated["manifest_size"]
        or manifest.get("source_tree_digest")
        != validated["source_tree_digest"]
        or manifest.get("file_count") != validated["file_count"]
        or manifest.get("total_bytes") != validated["total_bytes"]
        or not isinstance(manifest.get("files"), list)
    ):
        raise PackagingError("source manifest moved after validation")
    return manifest["files"]


def _require_regular_parent_chain(source: Path, relative: str) -> None:
    current = source
    for part in relative.split("/")[:-1]:
        current /= part
        try:
            info = current.lstat()
        except OSError as error:
            raise PackagingError(f"cannot inspect source path: {relative}") from error
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise PackagingError(f"symbolic or non-directory source path: {relative}")


def _materialize_worktree_snapshot(
    source: Path,
    work_root: Path,
    validated: dict,
) -> Path:
    if work_root == source or source in work_root.parents:
        raise PackagingError(
            "development source work directory must be outside the source root"
        )
    try:
        work_info = work_root.lstat()
    except OSError as error:
        raise PackagingError("builder work directory is unavailable") from error
    if (
        not stat.S_ISDIR(work_info.st_mode)
        or stat.S_ISLNK(work_info.st_mode)
        or stat.S_IMODE(work_info.st_mode) & 0o077
    ):
        raise PackagingError("builder work directory must be a private directory")

    records = _manifest_records(source, validated)
    snapshot = work_root / "development-source"
    if snapshot.exists() or snapshot.is_symlink():
        raise PackagingError("development source snapshot already exists")
    snapshot.mkdir(mode=0o700)
    try:
        for record in records:
            try:
                relative = validate_relative_path(record["path"])
                expected_mode = parse_mode(record["mode"])
                expected_sha256 = str(record["sha256"])
                expected_size = int(record["size"])
            except (KeyError, TypeError, ValueError) as error:
                raise PackagingError("source manifest file record is invalid") from error
            _require_regular_parent_chain(source, relative)
            copy_verified_file(
                source / relative,
                snapshot / relative,
                expected_sha256=expected_sha256,
                expected_size=expected_size,
                mode=expected_mode,
                expected_source_mode=expected_mode,
                limit=MAX_SOURCE_FILE_BYTES,
            )

        copy_verified_file(
            source / RELEASE_SOURCE_MANIFEST,
            snapshot / RELEASE_SOURCE_MANIFEST,
            expected_sha256=validated["manifest_sha256"],
            expected_size=validated["manifest_size"],
            mode=0o644,
            limit=64 * 1024 * 1024,
        )
        snapshot_validated = validate_source_manifest(snapshot)
        source_rechecked = validate_source_manifest(source)
        if snapshot_validated != validated or source_rechecked != validated:
            raise PackagingError("WORKTREE source moved during snapshot")
        return snapshot
    except OSError as error:
        shutil.rmtree(snapshot, ignore_errors=True)
        raise PackagingError("cannot materialize WORKTREE source snapshot") from error
    except Exception:
        shutil.rmtree(snapshot, ignore_errors=True)
        raise


def _verify_manifest_record(source: Path, record: dict) -> None:
    try:
        relative = validate_relative_path(record["path"])
        expected_mode = parse_mode(record["mode"])
        expected_sha256 = str(record["sha256"])
        expected_size = int(record["size"])
    except (KeyError, TypeError, ValueError) as error:
        raise PackagingError("source manifest file record is invalid") from error
    path = source / relative
    _require_regular_parent_chain(source, relative)
    try:
        descriptor, info = open_regular_nofollow(path)
    except OSError as error:
        raise PackagingError(f"cannot recheck {relative}") from error
    try:
        if (
            info.st_size != expected_size
            or mode_text(info.st_mode) != mode_text(expected_mode)
        ):
            raise PackagingError(f"{relative} moved after snapshot")
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = -1
            digest, size = hash_stream(stream, limit=MAX_SOURCE_FILE_BYTES)
        _require_regular_parent_chain(source, relative)
        current = path.lstat()
        if (
            not stat.S_ISREG(current.st_mode)
            or stat.S_ISLNK(current.st_mode)
            or (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino)
            or digest != expected_sha256
            or size != expected_size
        ):
            raise PackagingError(f"{relative} moved after snapshot")
    except OSError as error:
        raise PackagingError(f"cannot recheck {relative}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def prepare_source_material(
    repository: str | Path,
    revision: str,
    work_root: str | Path,
) -> SourceMaterial:
    """Return an immutable development snapshot or exact-commit stage."""

    source = Path(repository).resolve()
    if revision == "WORKTREE":
        validated = validate_source_manifest(source)
        snapshot = _materialize_worktree_snapshot(
            source,
            Path(work_root).resolve(),
            validated,
        )
        return SourceMaterial(
            root=snapshot,
            revision=revision,
            source_tree_digest=validated["source_tree_digest"],
            git_tree=None,
            head=None,
            immutable=True,
        )
    if not isinstance(revision, str) or COMMIT_RE.fullmatch(revision) is None:
        raise PackagingError("source revision must be WORKTREE or 40 lowercase hex")
    if not (source / ".git").exists():
        raise PackagingError("release source must be a real Git repository")
    _require_clean(source)
    head = _git_text(source, "rev-parse", "--verify", "HEAD")
    commit = _git_text(source, "rev-parse", "--verify", f"{revision}^{{commit}}")
    if head != revision or commit != revision:
        raise PackagingError("release source HEAD must equal the exact revision")
    validate_source_manifest(source)
    git_tree = _git_text(source, "rev-parse", "--verify", f"{revision}^{{tree}}")
    archive = _git(source, "archive", "--format=tar", revision)
    stage = Path(work_root) / "immutable-source"
    _extract_git_archive(archive, stage)
    validated = validate_source_manifest(stage)
    return SourceMaterial(
        root=stage,
        revision=revision,
        source_tree_digest=validated["source_tree_digest"],
        git_tree=git_tree,
        head=head,
        immutable=True,
    )


def prepare_committed_source_material(
    repository: str | Path,
    revision: str,
    work_root: str | Path,
) -> SourceMaterial:
    """Materialize exact HEAD from Git while allowing generated worktree output."""

    source = Path(repository).resolve()
    if not isinstance(revision, str) or COMMIT_RE.fullmatch(revision) is None:
        raise PackagingError("committed source revision must be 40 lowercase hex")
    if not (source / ".git").exists():
        raise PackagingError("release source must be a real Git repository")
    head = _git_text(source, "rev-parse", "--verify", "HEAD")
    commit = _git_text(source, "rev-parse", "--verify", f"{revision}^{{commit}}")
    if head != revision or commit != revision:
        raise PackagingError("release source HEAD must equal the exact revision")
    git_tree = _git_text(source, "rev-parse", "--verify", f"{revision}^{{tree}}")
    archive = _git(source, "archive", "--format=tar", revision)
    stage = Path(work_root) / "immutable-source"
    _extract_git_archive(archive, stage)
    validated = validate_source_manifest(stage)
    return SourceMaterial(
        root=stage,
        revision=revision,
        source_tree_digest=validated["source_tree_digest"],
        git_tree=git_tree,
        head=head,
        immutable=True,
    )


def recheck_source_material(
    repository: str | Path,
    material: SourceMaterial,
) -> None:
    """Reject recorded WORKTREE or exact-revision movement during a build."""

    source = Path(repository).resolve()
    if material.revision == "WORKTREE":
        validated = validate_source_manifest(material.root)
        if validated["source_tree_digest"] != material.source_tree_digest:
            raise PackagingError("development source snapshot moved during the build")
        records = _manifest_records(material.root, validated)
        for record in records:
            _verify_manifest_record(source, record)
        manifest_digest, manifest_size = sha256_file(
            source / RELEASE_SOURCE_MANIFEST,
            limit=64 * 1024 * 1024,
        )
        if (
            manifest_digest != validated["manifest_sha256"]
            or manifest_size != validated["manifest_size"]
        ):
            raise PackagingError("WORKTREE source manifest moved during the build")
        return
    if not material.immutable:
        return
    _require_clean(source)
    if (
        _git_text(source, "rev-parse", "--verify", "HEAD") != material.head
        or _git_text(
            source,
            "rev-parse",
            "--verify",
            f"{material.revision}^{{tree}}",
        )
        != material.git_tree
    ):
        raise PackagingError("release source moved during the build")


def recheck_committed_source_material(
    repository: str | Path,
    material: SourceMaterial,
) -> None:
    """Reject HEAD/Git-tree movement without inspecting generated worktree files."""

    if not material.immutable:
        raise PackagingError("committed source material must be immutable")
    source = Path(repository).resolve()
    if (
        _git_text(source, "rev-parse", "--verify", "HEAD") != material.head
        or _git_text(
            source,
            "rev-parse",
            "--verify",
            f"{material.revision}^{{tree}}",
        )
        != material.git_tree
    ):
        raise PackagingError("release source HEAD/tree moved during verification")
