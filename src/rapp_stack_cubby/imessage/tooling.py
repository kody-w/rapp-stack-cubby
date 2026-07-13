"""Pinned ``imsg`` metadata and content-free installed-tool verification."""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Any, Callable, Final


IMSG_VERSION: Final = "0.12.3"
IMSG_RELEASE_URL: Final = (
    "https://github.com/openclaw/imsg/releases/download/v0.12.3/imsg-macos.zip"
)
IMSG_ARCHIVE_SHA256: Final = (
    "35977a22e9721440acf9f5b945d67034939948ba4fa4ea46b0f55d527f24d4f2"
)
IMSG_REPOSITORY: Final = "https://github.com/openclaw/imsg"
IMSG_ANNOTATED_REF: Final = "76585a9e13a33534bec26d5478482efcc238f803"
IMSG_SOURCE_COMMIT: Final = "dea78a9e9c493740575b03e443041ef5fbd2d463"
IMSG_LICENSE_BLOB: Final = "0ae0cb57d8c6c1417f796b39fc0d6a7f2f7c5c39"
IMSG_TEAM_ID: Final = "Y5PE65HELJ"
IMSG_AUTHORITY: Final = "Developer ID Application: Peter Steinberger"
IMSG_EXECUTABLE_ARCHES: Final = frozenset({"x86_64", "arm64"})
IMSG_HELPER_ARCHES: Final = frozenset({"x86_64", "arm64", "arm64e"})
IMSG_REQUIRED_RELATIVE_FILES: Final = (
    "imsg",
    "imsg-bridge-helper.dylib",
    "SQLite.swift_SQLite.bundle/PrivacyInfo.xcprivacy",
    "PhoneNumberKit_PhoneNumberKit.bundle/PhoneNumberMetadata.json",
)

Runner = Callable[..., subprocess.CompletedProcess[str]]


class ToolVerificationError(RuntimeError):
    """Raised when a tool verification invocation is malformed."""


def verify_installed_imsg(
    imsg_path: Path | str,
    *,
    runner: Runner = subprocess.run,
    probe_messages: bool = True,
) -> dict[str, Any]:
    """Verify the immutable installed layout without returning private paths."""

    path = Path(imsg_path)
    facts: dict[str, Any] = {
        "archive_hash_verified": False,
        "architectures_verified": False,
        "codesign_verified": False,
        "error_codes": [],
        "layout_verified": False,
        "ok": False,
        "read_ready": False,
        "send_ready": None,
        "team_verified": False,
        "version": None,
        "version_verified": False,
    }
    errors: list[str] = facts["error_codes"]
    if not path.is_absolute():
        errors.append("imsg_path_not_absolute")
        return facts
    try:
        resolved = path.resolve(strict=True)
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            errors.append("imsg_not_executable")
            return facts
        root = resolved.parent
    except OSError:
        errors.append("imsg_unavailable")
        return facts

    required = [root / relative for relative in IMSG_REQUIRED_RELATIVE_FILES]
    if all(
        candidate.exists()
        and not candidate.is_symlink()
        and candidate.is_file()
        for candidate in required
    ):
        facts["layout_verified"] = True
    else:
        errors.append("layout_invalid")

    evidence = root / "install-evidence.json"
    try:
        info = evidence.stat()
        value = json.loads(evidence.read_text(encoding="utf-8"))
        if (
            not evidence.is_symlink()
            and stat.S_ISREG(info.st_mode)
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_size <= 64 * 1024
            and isinstance(value, dict)
            and value.get("schema") == "rapp-imsg-install-evidence/1.0"
            and value.get("version") == IMSG_VERSION
            and value.get("archive_sha256") == IMSG_ARCHIVE_SHA256
            and value.get("source_commit") == IMSG_SOURCE_COMMIT
            and value.get("annotated_ref") == IMSG_ANNOTATED_REF
            and value.get("license_blob") == IMSG_LICENSE_BLOB
        ):
            facts["archive_hash_verified"] = True
        else:
            errors.append("install_evidence_invalid")
    except (OSError, UnicodeError, json.JSONDecodeError):
        errors.append("install_evidence_unavailable")

    version_probe = _run(
        runner,
        [str(resolved), "--version"],
        timeout=10.0,
    )
    if version_probe is None:
        errors.append("version_probe_failed")
    else:
        version = version_probe.stdout.strip()
        if version_probe.returncode == 0 and version == IMSG_VERSION:
            facts["version"] = IMSG_VERSION
            facts["version_verified"] = True
        else:
            errors.append("version_mismatch")

    helper = root / "imsg-bridge-helper.dylib"
    signatures: list[str] = []
    strict_ok = True
    for candidate in (resolved, helper):
        verify = _run(
            runner,
            ["/usr/bin/codesign", "--verify", "--strict", "--verbose=2", str(candidate)],
            timeout=15.0,
        )
        display = _run(
            runner,
            ["/usr/bin/codesign", "-dv", "--verbose=4", str(candidate)],
            timeout=15.0,
        )
        if verify is None or verify.returncode != 0 or display is None:
            strict_ok = False
            continue
        signatures.append(display.stdout + "\n" + display.stderr)
    if strict_ok and len(signatures) == 2:
        facts["codesign_verified"] = True
    else:
        errors.append("codesign_invalid")
    if signatures and all(
        f"TeamIdentifier={IMSG_TEAM_ID}" in signature
        and f"Authority={IMSG_AUTHORITY}" in signature
        for signature in signatures
    ):
        facts["team_verified"] = True
    else:
        errors.append("signer_invalid")

    executable_arches = _architectures(runner, resolved)
    helper_arches = _architectures(runner, helper)
    if (
        IMSG_EXECUTABLE_ARCHES <= executable_arches
        and IMSG_HELPER_ARCHES <= helper_arches
    ):
        facts["architectures_verified"] = True
    else:
        errors.append("architectures_invalid")

    if probe_messages and facts["version_verified"]:
        read_probe = _run(
            runner,
            [str(resolved), "chats", "--limit", "1", "--json"],
            timeout=30.0,
        )
        if read_probe is not None and read_probe.returncode == 0:
            facts["read_ready"] = True
        else:
            errors.append("messages_read_unavailable")

    facts["ok"] = not errors
    return facts


def _architectures(runner: Runner, path: Path) -> frozenset[str]:
    result = _run(
        runner,
        ["/usr/bin/lipo", "-archs", str(path)],
        timeout=15.0,
    )
    if result is None or result.returncode != 0:
        return frozenset()
    return frozenset(result.stdout.split())


def _run(
    runner: Runner,
    argv: list[str],
    *,
    timeout: float,
) -> subprocess.CompletedProcess[str] | None:
    try:
        return runner(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
