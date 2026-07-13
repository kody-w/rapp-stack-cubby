"""Private owner-only configuration for the supervised ``imsg`` bridge.

Adapted from ``python/openrappter/imessage/config.py`` at the pinned
OpenRappter commit recorded in ``PROVENANCE.json``.  The local profile removes
multi-principal and group behavior and requires every security-sensitive path.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import stat
import urllib.parse
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


CONFIG_SCHEMA = "rapp-imessage-config/1.0"
IMSG_PINNED_VERSION = "0.12.3"
_OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ACCOUNT_ID_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:@+;-]{0,255}$"
)
_RAPPID_RE = re.compile(
    r"^rappid:@[a-z0-9][a-z0-9-]{0,62}/"
    r"[a-z0-9][a-z0-9-]{0,62}:[0-9a-f]{64}$"
)
_CONFIG_KEYS = frozenset(
    {
        "account_id",
        "allowed_dm_handles",
        "allowed_group_chat_ids",
        "attachments_enabled",
        "config_path",
        "controller_auth_token_file",
        "controller_timeout_seconds",
        "global_controller_url",
        "group_aliases",
        "groups_enabled",
        "identity_links",
        "imsg_path",
        "imsg_version",
        "max_message_chars",
        "max_response_chars",
        "mention_required",
        "mention_tokens",
        "owner_chat_ids",
        "owner_handles",
        "rappter_instance_id",
        "reactions_enabled",
        "reply_prefix",
        "request_timeout_seconds",
        "restart_initial_seconds",
        "restart_max_seconds",
        "schema",
        "sms_fallback",
        "stale_after_seconds",
        "state_dir",
        "target_rappid",
        "worker_count",
    }
)
_REQUIRED_KEYS = frozenset(
    {
        "account_id",
        "config_path",
        "controller_auth_token_file",
        "global_controller_url",
        "imsg_path",
        "imsg_version",
        "owner_chat_ids",
        "owner_handles",
        "rappter_instance_id",
        "schema",
        "state_dir",
        "target_rappid",
    }
)


class ConfigError(ValueError):
    """Raised when an iMessage configuration is unsafe or malformed."""


def normalize_handle(value: str) -> str:
    """Normalize only transport-safe comparison differences."""

    return value.strip().casefold()


def _string_array(value: object, name: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ConfigError(f"{name} must be an array")
    result: list[str] = []
    for item in value:
        if not isinstance(item, (str, int)) or isinstance(item, bool):
            raise ConfigError(f"{name} entries must be strings or integers")
        text = str(item).strip()
        if (
            not text
            or len(text) > 512
            or any(ord(character) < 0x20 for character in text)
        ):
            raise ConfigError(f"{name} contains an invalid entry")
        if text in result:
            raise ConfigError(f"{name} contains a duplicate entry")
        result.append(text)
    return tuple(result)


def _empty_array(raw: Mapping[str, Any], name: str) -> tuple[str, ...]:
    result = _string_array(raw.get(name, []), name)
    if result:
        raise ConfigError(f"{name} must be empty in owner-only v1")
    return result


def _empty_object(raw: Mapping[str, Any], name: str) -> dict[str, object]:
    value = raw.get(name, {})
    if not isinstance(value, Mapping):
        raise ConfigError(f"{name} must be an object")
    if value:
        raise ConfigError(f"{name} must be empty in owner-only v1")
    return {}


def _number(
    raw: Mapping[str, Any],
    name: str,
    default: float,
    *,
    minimum: float,
    maximum: float,
) -> float:
    value = raw.get(name, default)
    if isinstance(value, bool):
        raise ConfigError(f"{name} must be numeric")
    try:
        result = float(value)
    except (TypeError, ValueError) as error:
        raise ConfigError(f"{name} must be numeric") from error
    if not minimum <= result <= maximum:
        raise ConfigError(f"{name} is outside its safe range")
    return result


def _integer(
    raw: Mapping[str, Any],
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
) -> int:
    value = raw.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} is outside its safe range")
    return value


def _absolute_path(value: object, name: str, *, reject_symlinks: bool) -> Path:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ConfigError(f"{name} must be a non-empty absolute path")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or "~" in path.parts:
        raise ConfigError(f"{name} must be an explicit absolute path")
    if reject_symlinks:
        _reject_symlink_components(path, name)
    return path


def _reject_symlink_components(path: Path, name: str) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise ConfigError(f"{name} cannot be inspected safely") from error
        if stat.S_ISLNK(info.st_mode):
            raise ConfigError(f"{name} must not contain symbolic links")


def _loopback_chat_url(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ConfigError("global_controller_url is required")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ConfigError("global_controller_url is invalid") from error
    if (
        parsed.scheme != "http"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path.rstrip("/") != "/chat"
    ):
        raise ConfigError(
            "global_controller_url must be an uncredentialed loopback HTTP /chat URL"
        )
    hostname = parsed.hostname.casefold()
    if hostname != "localhost":
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError as error:
            raise ConfigError("global_controller_url host must be loopback") from error
        if not address.is_loopback:
            raise ConfigError("global_controller_url host must be loopback")
    if port is not None and not 1 <= port <= 65535:
        raise ConfigError("global_controller_url port is invalid")
    host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = host if port is None else f"{host}:{port}"
    return urllib.parse.urlunsplit(("http", netloc, "/chat", "", ""))


def _require_opaque(value: object, name: str) -> str:
    if not isinstance(value, str) or not _OPAQUE_ID_RE.fullmatch(value):
        raise ConfigError(f"{name} must be an opaque identifier")
    return value


def require_account_id(value: object) -> str:
    if not isinstance(value, str) or not _ACCOUNT_ID_RE.fullmatch(value):
        raise ConfigError("account_id must be an opaque Messages account identifier")
    return value


def _atomic_json_write(
    path: Path,
    value: Mapping[str, Any],
    mode: int = 0o600,
) -> None:
    if not path.is_absolute():
        raise ConfigError("configuration path must be absolute")
    _reject_symlink_components(path, "config_path")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.new")
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            mode,
        )
        payload = (
            json.dumps(
                dict(value),
                ensure_ascii=False,
                allow_nan=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        os.chmod(path, mode)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


@dataclass(frozen=True, slots=True)
class IMessageConfig:
    """Validated private configuration for the owner-only bridge."""

    config_path: Path
    state_dir: Path
    imsg_path: Path
    controller_auth_token_file: Path
    global_controller_url: str
    target_rappid: str
    rappter_instance_id: str
    account_id: str
    owner_handles: tuple[str, ...]
    owner_chat_ids: tuple[str, ...]
    reply_prefix: str = ""
    imsg_version: str = IMSG_PINNED_VERSION
    request_timeout_seconds: float = 30.0
    controller_timeout_seconds: float = 120.0
    restart_initial_seconds: float = 0.25
    restart_max_seconds: float = 8.0
    stale_after_seconds: float = 900.0
    max_message_chars: int = 64 * 1024
    max_response_chars: int = 64 * 1024
    worker_count: int = 1
    allowed_dm_handles: tuple[str, ...] = ()
    allowed_group_chat_ids: tuple[str, ...] = ()
    mention_required: bool = False
    mention_tokens: tuple[str, ...] = ()
    groups_enabled: bool = False
    sms_fallback: bool = False
    attachments_enabled: bool = False
    reactions_enabled: bool = False

    def __post_init__(self) -> None:
        _absolute_path(str(self.config_path), "config_path", reject_symlinks=True)
        _absolute_path(str(self.state_dir), "state_dir", reject_symlinks=True)
        _absolute_path(str(self.imsg_path), "imsg_path", reject_symlinks=False)
        from ..runtime.auth import validate_auth_token_file
        from ..runtime.config import RuntimeConfigurationError

        try:
            validate_auth_token_file(self.controller_auth_token_file)
        except RuntimeConfigurationError as error:
            raise ConfigError("controller auth token file is unsafe") from error
        _loopback_chat_url(self.global_controller_url)
        if not _RAPPID_RE.fullmatch(self.target_rappid):
            raise ConfigError("target_rappid must be a canonical RAPPID")
        _require_opaque(self.rappter_instance_id, "rappter_instance_id")
        require_account_id(self.account_id)
        if self.imsg_version != IMSG_PINNED_VERSION:
            raise ConfigError(f"imsg_version must be {IMSG_PINNED_VERSION}")
        if not self.owner_handles:
            raise ConfigError("at least one owner handle is required")
        if not self.owner_chat_ids:
            raise ConfigError("at least one exact owner self-chat id is required")
        for name, values in (
            ("owner_handles", self.owner_handles),
            ("owner_chat_ids", self.owner_chat_ids),
        ):
            if not isinstance(values, tuple):
                raise ConfigError(f"{name} must be an immutable sequence")
            if any(
                not isinstance(value, str)
                or not value
                or len(value) > 512
                or any(ord(character) < 0x20 for character in value)
                for value in values
            ) or len(set(values)) != len(values):
                raise ConfigError(f"{name} contains an invalid entry")
        if (
            self.allowed_dm_handles
            or self.allowed_group_chat_ids
            or self.mention_tokens
            or self.mention_required
            or self.groups_enabled
            or self.sms_fallback
            or self.attachments_enabled
            or self.reactions_enabled
        ):
            raise ConfigError("configuration exceeds owner-only v1")
        if self.worker_count != 1:
            raise ConfigError("worker_count must be 1")
        if not 0.1 <= self.request_timeout_seconds <= 300:
            raise ConfigError("request_timeout_seconds is outside its safe range")
        if not 0.1 <= self.controller_timeout_seconds <= 300:
            raise ConfigError("controller_timeout_seconds is outside its safe range")
        if not (
            0.05 <= self.restart_initial_seconds <= self.restart_max_seconds <= 120
        ):
            raise ConfigError("restart timeout bounds are invalid")
        if not 1 <= self.stale_after_seconds <= 86400:
            raise ConfigError("stale_after_seconds is outside its safe range")
        if not 1 <= self.max_message_chars <= 1024 * 1024:
            raise ConfigError("max_message_chars is outside its safe range")
        if not 1 <= self.max_response_chars <= 1024 * 1024:
            raise ConfigError("max_response_chars is outside its safe range")
        if len(self.reply_prefix) > 64 or any(
            ord(character) < 0x20 and character not in "\t"
            for character in self.reply_prefix
        ):
            raise ConfigError("reply_prefix is invalid")

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "IMessageConfig":
        if not isinstance(raw, Mapping):
            raise ConfigError("configuration must be a JSON object")
        unknown = set(raw) - _CONFIG_KEYS
        missing = _REQUIRED_KEYS - set(raw)
        if unknown:
            raise ConfigError(
                "configuration contains unsupported fields: " + ", ".join(sorted(unknown))
            )
        if missing:
            raise ConfigError(
                "configuration is missing required fields: " + ", ".join(sorted(missing))
            )
        if raw.get("schema") != CONFIG_SCHEMA:
            raise ConfigError(f"schema must be exactly {CONFIG_SCHEMA}")
        target = raw.get("target_rappid")
        if not isinstance(target, str) or not _RAPPID_RE.fullmatch(target):
            raise ConfigError("target_rappid must be a canonical RAPPID")
        reply_prefix = raw.get("reply_prefix", "")
        if not isinstance(reply_prefix, str):
            raise ConfigError("reply_prefix must be a string")
        for name in (
            "groups_enabled",
            "mention_required",
            "sms_fallback",
            "attachments_enabled",
            "reactions_enabled",
        ):
            if not isinstance(raw.get(name, False), bool):
                raise ConfigError(f"{name} must be boolean")
            if raw.get(name, False):
                raise ConfigError(f"{name} must be false in owner-only v1")
        _empty_object(raw, "identity_links")
        _empty_object(raw, "group_aliases")
        return cls(
            config_path=_absolute_path(
                raw["config_path"], "config_path", reject_symlinks=True
            ),
            state_dir=_absolute_path(
                raw["state_dir"], "state_dir", reject_symlinks=True
            ),
            imsg_path=_absolute_path(
                raw["imsg_path"], "imsg_path", reject_symlinks=False
            ),
            controller_auth_token_file=_absolute_path(
                raw["controller_auth_token_file"],
                "controller_auth_token_file",
                reject_symlinks=True,
            ),
            global_controller_url=_loopback_chat_url(raw["global_controller_url"]),
            target_rappid=target,
            rappter_instance_id=_require_opaque(
                raw["rappter_instance_id"], "rappter_instance_id"
            ),
            account_id=require_account_id(raw["account_id"]),
            owner_handles=_string_array(raw["owner_handles"], "owner_handles"),
            owner_chat_ids=_string_array(raw["owner_chat_ids"], "owner_chat_ids"),
            reply_prefix=reply_prefix,
            imsg_version=str(raw["imsg_version"]),
            request_timeout_seconds=_number(
                raw,
                "request_timeout_seconds",
                30.0,
                minimum=0.1,
                maximum=300.0,
            ),
            controller_timeout_seconds=_number(
                raw,
                "controller_timeout_seconds",
                120.0,
                minimum=0.1,
                maximum=300.0,
            ),
            restart_initial_seconds=_number(
                raw,
                "restart_initial_seconds",
                0.25,
                minimum=0.05,
                maximum=30.0,
            ),
            restart_max_seconds=_number(
                raw,
                "restart_max_seconds",
                8.0,
                minimum=0.05,
                maximum=120.0,
            ),
            stale_after_seconds=_number(
                raw,
                "stale_after_seconds",
                900.0,
                minimum=1.0,
                maximum=86400.0,
            ),
            max_message_chars=_integer(
                raw,
                "max_message_chars",
                64 * 1024,
                minimum=1,
                maximum=1024 * 1024,
            ),
            max_response_chars=_integer(
                raw,
                "max_response_chars",
                64 * 1024,
                minimum=1,
                maximum=1024 * 1024,
            ),
            worker_count=_integer(
                raw,
                "worker_count",
                1,
                minimum=1,
                maximum=1,
            ),
            allowed_dm_handles=_empty_array(raw, "allowed_dm_handles"),
            allowed_group_chat_ids=_empty_array(raw, "allowed_group_chat_ids"),
            mention_required=raw.get("mention_required", False),
            mention_tokens=_empty_array(raw, "mention_tokens"),
            groups_enabled=raw.get("groups_enabled", False),
            sms_fallback=raw.get("sms_fallback", False),
            attachments_enabled=raw.get("attachments_enabled", False),
            reactions_enabled=raw.get("reactions_enabled", False),
        )

    @classmethod
    def load(cls, path: Path | str) -> "IMessageConfig":
        config_path = Path(path)
        if not config_path.is_absolute():
            raise ConfigError("configuration path must be explicit and absolute")
        _reject_symlink_components(config_path, "config_path")
        try:
            info = config_path.stat()
            if not stat.S_ISREG(info.st_mode):
                raise ConfigError("configuration must be a regular file")
            if stat.S_IMODE(info.st_mode) != 0o600:
                raise ConfigError("configuration must be mode 0600")
            if info.st_size > 256 * 1024:
                raise ConfigError("configuration exceeds the size limit")
            raw = json.loads(config_path.read_text(encoding="utf-8"))
        except FileNotFoundError as error:
            raise ConfigError("configuration is unavailable") from error
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ConfigError("configuration cannot be read safely") from error
        config = cls.from_dict(raw)
        if config.config_path != config_path:
            raise ConfigError("config_path does not match the loaded configuration")
        return config

    def to_dict(self) -> dict[str, Any]:
        return {
            "account_id": self.account_id,
            "allowed_dm_handles": [],
            "allowed_group_chat_ids": [],
            "attachments_enabled": False,
            "config_path": str(self.config_path),
            "controller_auth_token_file": str(self.controller_auth_token_file),
            "controller_timeout_seconds": self.controller_timeout_seconds,
            "global_controller_url": self.global_controller_url,
            "group_aliases": {},
            "groups_enabled": False,
            "identity_links": {},
            "imsg_path": str(self.imsg_path),
            "imsg_version": self.imsg_version,
            "max_message_chars": self.max_message_chars,
            "max_response_chars": self.max_response_chars,
            "mention_required": False,
            "mention_tokens": [],
            "owner_chat_ids": list(self.owner_chat_ids),
            "owner_handles": list(self.owner_handles),
            "rappter_instance_id": self.rappter_instance_id,
            "reactions_enabled": False,
            "reply_prefix": self.reply_prefix,
            "request_timeout_seconds": self.request_timeout_seconds,
            "restart_initial_seconds": self.restart_initial_seconds,
            "restart_max_seconds": self.restart_max_seconds,
            "schema": CONFIG_SCHEMA,
            "sms_fallback": False,
            "stale_after_seconds": self.stale_after_seconds,
            "state_dir": str(self.state_dir),
            "target_rappid": self.target_rappid,
            "worker_count": 1,
        }

    def operational_errors(self) -> list[str]:
        return []

    @property
    def normalized_owner_handles(self) -> frozenset[str]:
        return frozenset(normalize_handle(item) for item in self.owner_handles)

    def owner_chat_matches(self, value: object) -> bool:
        if value is None or isinstance(value, bool):
            return False
        return str(value) in self.owner_chat_ids

    def write(self, *, overwrite: bool = False) -> None:
        if self.config_path.exists() and not overwrite:
            raise ConfigError("configuration already exists")
        _atomic_json_write(self.config_path, self.to_dict(), 0o600)


def write_config(
    path: Path | str,
    value: Mapping[str, Any],
    *,
    overwrite: bool = False,
) -> IMessageConfig:
    """Validate and atomically persist one private configuration."""

    selected = Path(path)
    if not selected.is_absolute():
        raise ConfigError("configuration path must be explicit and absolute")
    payload = dict(value)
    payload["config_path"] = str(selected)
    config = IMessageConfig.from_dict(payload)
    config.write(overwrite=overwrite)
    return config
