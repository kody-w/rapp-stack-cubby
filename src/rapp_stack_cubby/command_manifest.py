"""Generate and validate the exact public argparse command surface."""

from __future__ import annotations

import argparse
import json
import shlex
from pathlib import Path
from typing import Any, Final, Sequence

from .errors import RappStackCubbyError

COMMAND_MANIFEST_RELATIVE: Final = Path("COMMAND_MANIFEST.json")
COMMAND_MANIFEST_SCHEMA: Final = "rapp-command-manifest/1.0"
_DOCUMENTS: Final = (
    Path("README.md"),
    Path("RELEASE_CHECKLIST.md"),
    Path("docs/operations/DEVELOPER_SETUP.md"),
    Path("docs/operations/EXACT_COMMIT_PROMOTION.md"),
    Path("docs/operations/HANDOFF.md"),
    Path("docs/operations/IMESSAGE_ONBOARDING.md"),
    Path("docs/operations/ISOLATED_HATCH.md"),
    Path("docs/operations/LOCAL_LIFECYCLE.md"),
    Path("docs/operations/PACKAGING_AND_RELEASE.md"),
)


def build_command_manifest() -> dict[str, Any]:
    from .cli import build_parser

    entries: list[dict[str, Any]] = []
    _walk_parser(build_parser(), (), entries)
    entries.sort(key=lambda item: item["path"])
    return {
        "schema": COMMAND_MANIFEST_SCHEMA,
        "program": "rapp-stack-cubby",
        "commands": entries,
    }


def write_command_manifest(root: Path) -> dict[str, Any]:
    value = build_command_manifest()
    (root / COMMAND_MANIFEST_RELATIVE).write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return value


def validate_command_manifest(root: Path) -> dict[str, Any]:
    expected = build_command_manifest()
    try:
        observed = json.loads(
            (root / COMMAND_MANIFEST_RELATIVE).read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RappStackCubbyError("command manifest is unavailable") from error
    if observed != expected:
        raise RappStackCubbyError(
            "COMMAND_MANIFEST.json is stale; regenerate it"
        )
    return expected


def validate_documented_commands(root: Path) -> tuple[str, ...]:
    manifest = build_command_manifest()
    flags = {
        tuple(command["path"]): {
            flag
            for option in command["options"]
            for flag in option["flags"]
        }
        for command in manifest["commands"]
    }
    aliases = {
        alias: tuple(command["path"])
        for command in manifest["commands"]
        for alias in command.get("aliases", [])
    }
    errors: list[str] = []
    for relative in _DOCUMENTS:
        path = root / relative
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            errors.append(f"{relative}: missing tutorial")
            continue
        for line_number, tokens in _document_invocations(text):
            command_index = _command_index(tokens)
            if command_index is None or command_index >= len(tokens):
                continue
            command = tokens[command_index]
            path_key = aliases.get(command, (command,))
            selected_flags = set(flags.get(path_key, set()))
            for candidate, candidate_flags in flags.items():
                if (
                    len(candidate) == len(path_key) + 1
                    and candidate[: len(path_key)] == path_key
                    and candidate[-1] in tokens[command_index + 1 :]
                ):
                    selected_flags |= candidate_flags
            for token in tokens[command_index + 1 :]:
                flag = token.split("=", 1)[0]
                if flag.startswith("--") and flag not in selected_flags:
                    errors.append(
                        f"{relative}:{line_number}: unsupported flag {flag} "
                        f"for {command}"
                    )
    return tuple(errors)


def _walk_parser(
    parser: argparse.ArgumentParser,
    path: tuple[str, ...],
    entries: list[dict[str, Any]],
) -> None:
    if path:
        entries.append(
            {
                "path": list(path),
                "options": sorted(
                    (
                        _option(action)
                        for action in parser._actions
                        if not isinstance(action, argparse._SubParsersAction)
                    ),
                    key=lambda item: (item["dest"], item["flags"]),
                ),
            }
        )
    for action in parser._actions:
        if not isinstance(action, argparse._SubParsersAction):
            continue
        seen: set[int] = set()
        for name, child in sorted(action.choices.items()):
            identity = id(child)
            if identity in seen:
                continue
            aliases = sorted(
                alias
                for alias, candidate in action.choices.items()
                if candidate is child and alias != name
            )
            entry_path = (*path, name)
            _walk_parser(child, entry_path, entries)
            if aliases:
                entries[-1]["aliases"] = aliases
            seen.add(identity)


def _option(action: argparse.Action) -> dict[str, Any]:
    choices = (
        sorted(str(value) for value in action.choices)
        if action.choices is not None
        else None
    )
    value_type = getattr(action.type, "__name__", None)
    return {
        "action": type(action).__name__,
        "choices": choices,
        "dest": action.dest,
        "flags": list(action.option_strings),
        "nargs": action.nargs,
        "required": bool(action.required),
        "type": value_type,
    }


def _document_invocations(text: str) -> list[tuple[int, list[str]]]:
    invocations: list[tuple[int, list[str]]] = []
    pending = ""
    pending_line = 0
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if pending:
            pending += " " + line.removesuffix("\\").strip()
        elif (
            "rapp_stack_cubby" in line
            or line.startswith("rapp-stack-cubby ")
        ):
            pending = line.removesuffix("\\").strip()
            pending_line = number
        else:
            continue
        if line.endswith("\\"):
            continue
        try:
            tokens = shlex.split(pending)
        except ValueError:
            tokens = []
        if tokens:
            invocations.append((pending_line, tokens))
        pending = ""
    return invocations


def _command_index(tokens: Sequence[str]) -> int | None:
    if "-m" in tokens:
        index = tokens.index("-m")
        if (
            index + 2 < len(tokens)
            and tokens[index + 1] == "rapp_stack_cubby"
        ):
            return index + 2
    for index, token in enumerate(tokens):
        if token == "rapp-stack-cubby" and index + 1 < len(tokens):
            return index + 1
    return None
