"""Static privacy and fixed-transport checks for the iMessage bridge."""

from __future__ import annotations

import argparse
import ast
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from .tooling import (
    IMSG_ANNOTATED_REF,
    IMSG_ARCHIVE_SHA256,
    IMSG_AUTHORITY,
    IMSG_LICENSE_BLOB,
    IMSG_SOURCE_COMMIT,
    IMSG_TEAM_ID,
    IMSG_VERSION,
)


_LOCAL_PATH = re.compile(r"/(?:Users|home)/[^/\s]+/")
_PHONE = re.compile(
    r"(?<![0-9])(?:\+?1[-. ]?)?\(?[2-9][0-9]{2}\)?"
    r"[-. ][2-9][0-9]{2}[-. ][0-9]{4}(?![0-9])"
)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


@dataclass(frozen=True, slots=True)
class IMessageScanResult:
    findings: tuple[str, ...]
    scanned_file_count: int

    @property
    def ok(self) -> bool:
        return not self.findings


def scan_imessage_sources(root: str | Path) -> IMessageScanResult:
    repository = Path(root).resolve(strict=True)
    candidates = [
        *sorted((repository / "src/rapp_stack_cubby/imessage").glob("*.py")),
        repository
        / "cubbies/kody-w/rapplications/rapp-stack/twin/agents/imessage_agent.py",
        repository / "scripts/install-imsg.sh",
        repository / "scripts/uninstall-imsg.sh",
        repository / "scripts/install-imessage-service.sh",
        repository / "scripts/uninstall-imessage-service.sh",
        repository / "schemas/imessage-local-config.schema.json",
        repository / "schemas/imessage-status.schema.json",
    ]
    findings: list[str] = []
    for path in candidates:
        relative = path.relative_to(repository).as_posix()
        if path.is_symlink() or not path.is_file():
            findings.append(f"{relative}: missing or symbolic link")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            findings.append(f"{relative}: not readable UTF-8")
            continue
        if _LOCAL_PATH.search(text):
            findings.append(f"{relative}: absolute workstation path")
        if _PHONE.search(text):
            findings.append(f"{relative}: phone-shaped source value")
        if _EMAIL.search(text):
            findings.append(f"{relative}: email-shaped source value")
        if path.suffix == ".py":
            findings.extend(_scan_python(path, relative, text))
    installer = (repository / "scripts/install-imsg.sh").read_text(encoding="utf-8")
    for required in (
        IMSG_VERSION,
        IMSG_ARCHIVE_SHA256,
        IMSG_ANNOTATED_REF,
        IMSG_SOURCE_COMMIT,
        IMSG_LICENSE_BLOB,
        IMSG_AUTHORITY,
        IMSG_TEAM_ID,
        "unzip -Z1",
        "codesign --verify --strict",
    ):
        if required not in installer:
            findings.append("scripts/install-imsg.sh: immutable evidence is incomplete")
            break
    for forbidden in ("mktemp", "/tmp", "curl |", "OPENRAPPTER_IMSG_VERSION"):
        if forbidden in installer:
            findings.append(f"scripts/install-imsg.sh: forbidden pattern {forbidden}")
    return IMessageScanResult(tuple(sorted(set(findings))), len(candidates))


def _scan_python(path: Path, relative: str, text: str) -> list[str]:
    findings: list[str] = []
    try:
        tree = ast.parse(text, filename=relative)
    except SyntaxError:
        return [f"{relative}: invalid Python"]
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node.func)
        if name in {"eval", "exec", "os.system", "os.popen"}:
            findings.append(f"{relative}: forbidden call {name}")
        if any(
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        ):
            findings.append(f"{relative}: shell-enabled process execution")
        if name.endswith((".debug", ".info", ".warning", ".error", ".critical")):
            if not node.args or not isinstance(node.args[0], ast.Constant):
                findings.append(f"{relative}: operational log format is not fixed")
    return findings


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    result = scan_imessage_sources(args.root)
    if result.ok:
        print(
            "PASS iMessage source/privacy scan: "
            f"{result.scanned_file_count} fixed public files"
        )
        return 0
    for finding in result.findings:
        print(f"error: {finding}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
