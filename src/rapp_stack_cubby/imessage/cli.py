"""CLI integration for the private owner-only iMessage bridge.

The initialization and silent chat-discovery flow is adapted from
``python/openrappter/imessage/cli.py`` at the pinned OpenRappter commit
recorded in ``PROVENANCE.json``.
"""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import stat
import subprocess
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .bridge import IMessageBridge
from .config import (
    CONFIG_SCHEMA,
    IMSG_PINNED_VERSION,
    ConfigError,
    IMessageConfig,
    normalize_handle,
    require_account_id,
    write_config,
)
from .tooling import verify_installed_imsg


LAUNCH_AGENT_LABEL = "dev.rapp-stack-cubby.imessage"
_MAX_CHAT_CATALOG_BYTES = 4 * 1024 * 1024


def add_imessage_parser(subparsers: Any) -> argparse.ArgumentParser:
    parser = subparsers.add_parser(
        "imessage",
        help="install, configure, inspect, or run the owner-only iMessage bridge",
    )
    commands = parser.add_subparsers(dest="imessage_command", required=True)

    install_tool = commands.add_parser(
        "install-tool",
        help="install or verify the immutable signed imsg release",
    )
    install_tool.add_argument("--install-root", required=True, type=str)
    install_tool.add_argument(
        "--verify-only",
        action="store_true",
        help="verify the exact existing install without downloading",
    )
    install_tool.add_argument(
        "--uninstall",
        action="store_true",
        help="remove only the exact pinned tool layout",
    )
    install_tool.add_argument(
        "--dry-run",
        action="store_true",
        help="verify and report the exact uninstall without deleting",
    )

    initialize = commands.add_parser(
        "init",
        help="discover an exact owner self-chat and write mode-0600 config",
    )
    _add_config_argument(initialize)
    initialize.add_argument("--state-dir", required=True)
    initialize.add_argument("--imsg", required=True)
    initialize.add_argument("--global-controller-url", required=True)
    initialize.add_argument("--controller-auth-token-file", required=True)
    initialize.add_argument("--target-rappid", required=True)
    initialize.add_argument("--instance-id")
    initialize.add_argument("--account-id")
    initialize.add_argument("--owner", action="append", required=True)
    initialize.add_argument("--owner-chat", action="append", default=[])
    initialize.add_argument("--reply-prefix", default="")
    initialize.add_argument("--force", action="store_true")

    for name, help_text in (
        ("preflight", "verify config, signed tool, layout, and Messages read access"),
        ("status", "show content-free bridge health"),
        ("run", "run the bridge in the foreground"),
    ):
        command = commands.add_parser(name, help=help_text)
        _add_config_argument(command)

    service_install = commands.add_parser(
        "service-install",
        help="write but do not load a per-user Aqua LaunchAgent",
    )
    _add_config_argument(service_install)
    service_install.add_argument("--python", required=True)
    service_install.add_argument("--source-root", required=True)
    service_install.add_argument("--plist", required=True)

    service_uninstall = commands.add_parser(
        "service-uninstall",
        help="remove the exact unloaded per-user LaunchAgent plist",
    )
    _add_config_argument(service_uninstall)
    service_uninstall.add_argument("--plist", required=True)
    service_uninstall.add_argument(
        "--stop",
        action="store_true",
        help="boot out a loaded agent before removing its owned plist",
    )
    return parser


def _add_config_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--config",
        required=True,
        help="explicit private JSON config path",
    )


def run_imessage_command(args: argparse.Namespace) -> int:
    command = args.imessage_command
    if command == "install-tool":
        return _install_tool(args)
    if command == "init":
        return _initialize(args)
    if command == "service-install":
        return _service_install(args)
    if command == "service-uninstall":
        return _service_uninstall(args)

    config = IMessageConfig.load(_cli_absolute_path(args.config, "config"))
    if command == "preflight":
        bridge = IMessageBridge(config)
        try:
            value = bridge.preflight()
        finally:
            bridge.state.close()
        print(json.dumps(value, indent=2, sort_keys=True))
        return 0 if value.get("ok") is True else 1
    if command == "status":
        value = read_content_free_status(config)
        print(json.dumps(value, indent=2, sort_keys=True))
        return 0 if value["healthy"] else 1
    if command == "run":
        bridge = IMessageBridge(config)
        try:
            bridge.run_forever()
        finally:
            bridge.state.close()
        return 0
    raise ConfigError("unsupported iMessage command")


def _initialize(args: argparse.Namespace) -> int:
    config_path = _cli_absolute_path(args.config, "config")
    state_dir = _cli_absolute_path(args.state_dir, "state-dir")
    imsg_path = _cli_absolute_path(args.imsg, "imsg")
    binding = discover_owner_binding(
        imsg_path,
        list(args.owner),
        selected_chat_ids=list(args.owner_chat),
    )
    if args.account_id is not None:
        supplied_account = require_account_id(args.account_id)
        if supplied_account != binding.account_id:
            raise ConfigError(
                "supplied account-id does not match the discovered owner chat"
            )
    owner_chats = list(binding.chat_ids)
    payload = {
        "account_id": binding.account_id,
        "allowed_dm_handles": [],
        "allowed_group_chat_ids": [],
        "attachments_enabled": False,
        "config_path": str(config_path),
        "controller_auth_token_file": str(
            _cli_absolute_path(
                args.controller_auth_token_file,
                "controller-auth-token-file",
            )
        ),
        "controller_timeout_seconds": 120.0,
        "global_controller_url": args.global_controller_url,
        "group_aliases": {},
        "groups_enabled": False,
        "identity_links": {},
        "imsg_path": str(imsg_path),
        "imsg_version": IMSG_PINNED_VERSION,
        "max_message_chars": 64 * 1024,
        "max_response_chars": 64 * 1024,
        "mention_required": False,
        "mention_tokens": [],
        "owner_chat_ids": owner_chats,
        "owner_handles": list(args.owner),
        "rappter_instance_id": args.instance_id or uuid.uuid4().hex,
        "reactions_enabled": False,
        "reply_prefix": args.reply_prefix,
        "request_timeout_seconds": 30.0,
        "restart_initial_seconds": 0.25,
        "restart_max_seconds": 8.0,
        "schema": CONFIG_SCHEMA,
        "sms_fallback": False,
        "stale_after_seconds": 900.0,
        "state_dir": str(state_dir),
        "target_rappid": args.target_rappid,
        "worker_count": 1,
    }
    write_config(config_path, payload, overwrite=args.force)
    print(
        json.dumps(
            {
                "configured": True,
                "owner_chat_count": len(owner_chats),
                "schema": CONFIG_SCHEMA,
            },
            sort_keys=True,
        )
    )
    return 0


def discover_owner_chats(imsg_path: Path, owners: list[str]) -> list[str]:
    """Compatibility wrapper returning only the selected private identifiers."""

    return list(discover_owner_binding(imsg_path, owners).chat_ids)


@dataclass(frozen=True, slots=True)
class OwnerChatBinding:
    chat_ids: tuple[str, ...]
    account_id: str


def discover_owner_binding(
    imsg_path: Path,
    owners: list[str],
    *,
    selected_chat_ids: Sequence[str] = (),
) -> OwnerChatBinding:
    verified = verify_installed_imsg(imsg_path, probe_messages=False)
    if verified.get("ok") is not True:
        raise ConfigError("owner chat discovery requires a verified pinned imsg install")
    version = _run_bounded(
        [str(imsg_path), "--version"],
        timeout=10.0,
        maximum=64 * 1024,
    )
    if version.returncode != 0 or version.stdout.strip() != IMSG_PINNED_VERSION:
        raise ConfigError("owner chat discovery requires the pinned imsg version")
    result = _run_bounded(
        [str(imsg_path), "chats", "--limit", "1000", "--json"],
        timeout=120.0,
        maximum=_MAX_CHAT_CATALOG_BYTES,
    )
    if result.returncode != 0:
        raise ConfigError("owner chat discovery cannot read Messages")
    chats = _parse_chat_catalog(result.stdout)
    owner_set = {normalize_handle(value) for value in owners}
    if not owner_set or "" in owner_set:
        raise ConfigError("owner chat discovery requires valid owner handles")
    requested = {str(value) for value in selected_chat_ids}
    matches: list[tuple[tuple[str, ...], str]] = []
    for chat in chats:
        if chat.get("is_group") is not False:
            continue
        service = str(chat.get("service") or "").casefold()
        if service != "imessage":
            continue
        identifier = normalize_handle(str(chat.get("identifier") or ""))
        participants_value = chat.get("participants", [])
        if not isinstance(participants_value, Sequence) or isinstance(
            participants_value, (str, bytes)
        ):
            continue
        participants = {
            normalize_handle(str(value))
            for value in participants_value
            if isinstance(value, (str, int)) and not isinstance(value, bool)
        }
        if identifier not in owner_set and participants != owner_set:
            continue
        candidates = {
            str(value)
            for value in (
                chat.get("id"),
                chat.get("guid"),
                chat.get("identifier"),
            )
            if value not in (None, "") and not isinstance(value, bool)
        }
        if requested and not requested.issubset(candidates):
            continue
        account = require_account_id(chat.get("account_id"))
        exact: list[str] = []
        for key in ("id", "guid"):
            value = chat.get(key)
            if (
                value not in (None, "")
                and not isinstance(value, bool)
                and str(value) not in exact
            ):
                exact.append(str(value))
        if exact:
            matches.append((tuple(exact), account))
    if not matches:
        raise ConfigError("no exact owner self-chat was discovered")
    if len(matches) != 1:
        raise ConfigError(
            "multiple owner self-chats matched; use private --owner-chat disambiguation"
        )
    exact, account = matches[0]
    return OwnerChatBinding(exact, account)


def _parse_chat_catalog(text: str) -> list[Mapping[str, Any]]:
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        value = None
    if isinstance(value, Mapping):
        chats = value.get("chats")
        if isinstance(chats, list):
            return [chat for chat in chats if isinstance(chat, Mapping)]
    if isinstance(value, list):
        return [chat for chat in value if isinstance(chat, Mapping)]
    result: list[Mapping[str, Any]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            chat = json.loads(line)
        except (json.JSONDecodeError, RecursionError) as error:
            raise ConfigError("imsg chat discovery returned invalid JSON") from error
        if not isinstance(chat, Mapping):
            raise ConfigError("imsg chat discovery returned an invalid record")
        result.append(chat)
    return result


def read_content_free_status(config: IMessageConfig) -> dict[str, Any]:
    path = config.state_dir / "status.json"
    raw: dict[str, Any] = {}
    try:
        info = path.stat()
        if (
            not path.is_symlink()
            and stat.S_ISREG(info.st_mode)
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_size <= 64 * 1024
        ):
            value = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(value, dict):
                raw = value
    except (OSError, UnicodeError, json.JSONDecodeError):
        raw = {}
    heartbeat = raw.get("heartbeat_at")
    fresh = (
        isinstance(heartbeat, (int, float))
        and not isinstance(heartbeat, bool)
        and 0 <= time.time() - float(heartbeat) < 20.0
    )
    counters: dict[str, int] = {}
    for name in ("processed", "dropped", "failed", "pending", "restart_count"):
        value = raw.get(name)
        counters[name] = (
            value
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0
            else 0
        )
    lifecycle = raw.get("lifecycle")
    if lifecycle not in {"starting", "running", "stopped", "failed"}:
        lifecycle = "unavailable"
    ready = raw.get("ready") is True
    transport_ready = (
        raw.get("transport_ready") is True
        if isinstance(raw.get("transport_ready"), bool)
        else raw.get("read_ready") is True
    )
    controller_ready = (
        raw.get("controller_ready")
        if isinstance(raw.get("controller_ready"), bool)
        else None
    )
    send_ready = (
        raw.get("send_ready")
        if isinstance(raw.get("send_ready"), bool)
        else None
    )
    return {
        **counters,
        "configured": True,
        "controller_ready": controller_ready,
        "healthy": (
            lifecycle == "running"
            and ready
            and fresh
            and transport_ready
            and controller_ready is not False
            and send_ready is not False
        ),
        "heartbeat_fresh": fresh,
        "imsg_version": (
            raw.get("imsg_version")
            if raw.get("imsg_version") == IMSG_PINNED_VERSION
            else IMSG_PINNED_VERSION
        ),
        "lifecycle": lifecycle,
        "read_ready": transport_ready,
        "ready": ready,
        "send_ready": send_ready,
        "transport_ready": transport_ready,
    }


def _install_tool(args: argparse.Namespace) -> int:
    root = _cli_absolute_path(args.install_root, "install-root")
    if args.verify_only and args.uninstall:
        raise ConfigError("--verify-only and --uninstall are mutually exclusive")
    if args.dry_run and not args.uninstall:
        raise ConfigError("--dry-run requires --uninstall")
    repository = Path(__file__).resolve().parents[3]
    script_name = "uninstall-imsg.sh" if args.uninstall else "install-imsg.sh"
    script = repository / "scripts" / script_name
    argv = [str(script), "--root", str(root)]
    if args.verify_only:
        argv.append("--verify")
    if args.dry_run:
        argv.append("--dry-run")
    result = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=300.0,
        check=False,
        shell=False,
    )
    if result.returncode != 0:
        raise ConfigError("pinned imsg operation failed")
    output = {
        "installed": not args.verify_only and not args.uninstall,
        "dry_run": args.dry_run,
        "removed": args.uninstall and not args.dry_run,
        "verified": not args.uninstall,
        "version": IMSG_PINNED_VERSION,
    }
    print(json.dumps(output, sort_keys=True))
    return 0


def _service_install(args: argparse.Namespace) -> int:
    if os.geteuid() == 0:
        raise ConfigError("the iMessage service must never be installed as root")
    config_path = _cli_absolute_path(args.config, "config")
    config = IMessageConfig.load(config_path)
    python = _cli_absolute_path(args.python, "python")
    source_root = _cli_absolute_path(args.source_root, "source-root")
    plist_path = _launch_agent_path(args.plist)
    if not python.is_file() or not os.access(python, os.X_OK):
        raise ConfigError("the fixed Python executable is unavailable")
    python = python.resolve(strict=True)
    _reject_symlink_components(source_root)
    package_root = source_root / "src"
    if not (package_root / "rapp_stack_cubby" / "__init__.py").is_file():
        raise ConfigError("source-root does not contain the expected package")
    config.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(config.state_dir, 0o700)
    stdout_path = config.state_dir / "service.stdout.log"
    stderr_path = config.state_dir / "service.stderr.log"
    for path in (stdout_path, stderr_path):
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.close(descriptor)
        os.chmod(path, 0o600)
    value = {
        "EnvironmentVariables": {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": str(package_root),
        },
        "KeepAlive": {"SuccessfulExit": False},
        "Label": LAUNCH_AGENT_LABEL,
        "LimitLoadToSessionType": "Aqua",
        "ProcessType": "Interactive",
        "ProgramArguments": [
            str(python),
            "-m",
            "rapp_stack_cubby",
            "imessage",
            "run",
            "--config",
            str(config_path),
        ],
        "RunAtLoad": True,
        "StandardErrorPath": str(stderr_path),
        "StandardOutPath": str(stdout_path),
        "ThrottleInterval": 10,
        "Umask": 0o077,
        "WorkingDirectory": str(source_root),
    }
    _atomic_plist(plist_path, value)
    print(
        json.dumps(
            {
                "installed": True,
                "label": LAUNCH_AGENT_LABEL,
                "loaded": False,
                "session_type": "Aqua",
            },
            sort_keys=True,
        )
    )
    return 0


def _service_uninstall(args: argparse.Namespace) -> int:
    if os.geteuid() == 0:
        raise ConfigError("the iMessage service must never be managed as root")
    config_path = _cli_absolute_path(args.config, "config")
    IMessageConfig.load(config_path)
    plist_path = _launch_agent_path(args.plist)
    if not plist_path.exists():
        print(json.dumps({"removed": False, "stopped": False}, sort_keys=True))
        return 0
    try:
        value = plistlib.loads(plist_path.read_bytes())
    except (OSError, plistlib.InvalidFileException) as error:
        raise ConfigError("LaunchAgent plist is invalid") from error
    arguments = value.get("ProgramArguments") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or value.get("Label") != LAUNCH_AGENT_LABEL
        or not isinstance(arguments, list)
        or ["--config", str(config_path)]
        != arguments[-2:]
        or value.get("LimitLoadToSessionType") != "Aqua"
    ):
        raise ConfigError("refusing to remove an unrelated LaunchAgent")
    initial_state = _launch_agent_load_state()
    stopped = False
    if not args.stop:
        if initial_state == "loaded":
            raise ConfigError(
                "LaunchAgent is loaded; rerun with --stop to remove it"
            )
        if initial_state != "not_loaded":
            raise ConfigError(
                "LaunchAgent load state is unknown; plist was preserved"
            )
    elif initial_state != "not_loaded":
        result = subprocess.run(
            [
                "/bin/launchctl",
                "bootout",
                f"gui/{os.getuid()}",
                str(plist_path),
            ],
            capture_output=True,
            text=True,
            timeout=30.0,
            check=False,
            shell=False,
        )
        final_state = _launch_agent_load_state()
        if final_state != "not_loaded":
            raise ConfigError(
                "LaunchAgent stop was not confirmed; plist was preserved"
            )
        stopped = initial_state == "loaded" or result.returncode == 0
    if _launch_agent_load_state() != "not_loaded":
        raise ConfigError(
            "LaunchAgent unload verification failed; plist was preserved"
        )
    plist_path.unlink()
    print(json.dumps({"removed": True, "stopped": stopped}, sort_keys=True))
    return 0


def _launch_agent_load_state() -> str:
    result = subprocess.run(
        [
            "/bin/launchctl",
            "print",
            f"gui/{os.getuid()}/{LAUNCH_AGENT_LABEL}",
        ],
        capture_output=True,
        text=True,
        timeout=30.0,
        check=False,
        shell=False,
    )
    if result.returncode == 0:
        return "loaded"
    diagnostic = (result.stdout + "\n" + result.stderr).casefold()
    if result.returncode == 113 or any(
        marker in diagnostic
        for marker in (
            "could not find service",
            "no such process",
            "service not found",
            "not loaded",
        )
    ):
        return "not_loaded"
    return "unknown"


def _launch_agent_path(value: str) -> Path:
    path = _cli_absolute_path(value, "plist")
    expected_parent = Path.home() / "Library" / "LaunchAgents"
    expected_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if (
        path.parent != expected_parent
        or path.name != LAUNCH_AGENT_LABEL + ".plist"
        or path.is_symlink()
    ):
        raise ConfigError("plist must be the exact per-user LaunchAgent path")
    _reject_symlink_components(path)
    return path


def _atomic_plist(path: Path, value: Mapping[str, Any]) -> None:
    payload = plistlib.dumps(dict(value), fmt=plistlib.FMT_XML, sort_keys=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.new")
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _cli_absolute_path(value: str, name: str) -> Path:
    expanded = Path(os.path.expanduser(value))
    if not expanded.is_absolute() or ".." in expanded.parts:
        raise ConfigError(f"{name} must be an explicit absolute path")
    return expanded


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise ConfigError("path cannot be inspected safely") from error
        if stat.S_ISLNK(info.st_mode):
            raise ConfigError("path must not contain symbolic links")


def _run_bounded(
    argv: list[str],
    *,
    timeout: float,
    maximum: int,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        shell=False,
    )
    if len(result.stdout.encode("utf-8")) > maximum:
        raise ConfigError("imsg command output exceeds the size limit")
    return result
