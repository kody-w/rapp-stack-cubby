"""Deterministic privacy and execution-surface scan for bundled agents."""

from __future__ import annotations

import argparse
import ast
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from ..catalog import AGENTS_RELATIVE, CatalogValidationError, inspect_agent_source
from ..constants import EXPECTED_ACTUAL_AGENT_COUNT

_ABSOLUTE_LOCAL_PATH = re.compile(
    r"(?:/(?:Users|home)/[^/\s]+/|[A-Za-z]:\\Users\\[^\\\s]+\\)"
)
_PHONE_SHAPE = re.compile(r"(?:\+?[0-9][0-9 .()_-]{7,}[0-9])")
_EMAIL_SHAPE = re.compile(
    r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b"
)
_SECRET_SHAPE = re.compile(
    r"(?i)\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"sk-[A-Za-z0-9_-]{20,}|bearer\s+[A-Za-z0-9._~+/-]{16,})\b"
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?key|authorization|credential|password|"
    r"private[_-]?key|secret|token)\b\s*[:=]\s*[\"'][^\"']+[\"']"
)
_PUBLIC_RAPPID_VECTOR = re.compile(
    r"^rappid:@[a-z0-9-]+/[a-z0-9-]+:[0-9a-f]{64}$"
)
_REGEX_MARKERS = ("\\d", "[0-9", "[A-Z", "[a-z", "(?:", "(?P", "\\b")


@dataclass(frozen=True, slots=True)
class AgentSourceScanResult:
    """A redacted scan summary containing rule and repository-relative path."""

    scanned_file_count: int
    findings: tuple[tuple[str, str], ...]

    @property
    def ok(self) -> bool:
        return not self.findings and self.scanned_file_count == EXPECTED_ACTUAL_AGENT_COUNT


def scan_agent_sources(root: str | Path) -> AgentSourceScanResult:
    """Scan actual agents without importing or executing their source."""

    repository = Path(root).resolve(strict=True)
    directory = repository / AGENTS_RELATIVE
    if directory.is_symlink() or not directory.is_dir():
        return AgentSourceScanResult(
            0, ((AGENTS_RELATIVE.as_posix(), "invalid_agent_directory"),)
        )
    findings: set[tuple[str, str]] = set()
    paths = sorted(directory.glob("*_agent.py"), key=lambda item: item.name)
    for path in paths:
        relative = path.relative_to(repository).as_posix()
        try:
            inspect_agent_source(path)
        except (CatalogValidationError, OSError, UnicodeError):
            findings.add((relative, "agent_contract"))
            continue
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=path.name)
        if _SECRET_ASSIGNMENT.search(source):
            findings.add((relative, "secret_literal"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            value = node.value
            if _ABSOLUTE_LOCAL_PATH.search(value):
                findings.add((relative, "absolute_local_path"))
            if _SECRET_SHAPE.search(value):
                findings.add((relative, "secret_literal"))
            if ("BEGIN" + " PRIVATE KEY") in value.upper():
                findings.add((relative, "private_key_literal"))
            if _EMAIL_SHAPE.search(value):
                findings.add((relative, "private_identifier"))
            if (
                not any(marker in value for marker in _REGEX_MARKERS)
                and not _PUBLIC_RAPPID_VECTOR.fullmatch(value)
            ):
                if _PHONE_SHAPE.search(value):
                    findings.add((relative, "phone_number"))
    if len(paths) != EXPECTED_ACTUAL_AGENT_COUNT:
        findings.add((AGENTS_RELATIVE.as_posix(), "agent_count"))
    return AgentSourceScanResult(
        scanned_file_count=len(paths),
        findings=tuple(sorted(findings)),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the source scan as a build gate."""

    arguments = _parser().parse_args(argv)
    result = scan_agent_sources(arguments.root)
    if result.ok:
        print(
            "PASS agent source scan: "
            f"{result.scanned_file_count} portable files; "
            "no process/network imports, unsafe calls, secrets, private "
            "identifiers, phone numbers, or absolute local paths"
        )
        return 0
    for path, rule in result.findings:
        print(f"error: {path}: {rule}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
