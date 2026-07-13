"""Immutable configuration for one isolated runtime instance."""

from __future__ import annotations

import ipaddress
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from ..errors import RappStackCubbyError
from .provider import ATTESTATION_MODE, ATTESTATION_MODEL

SUPPORTED_PYTHON: Final = (3, 11)
DEFAULT_HOST: Final = "127.0.0.1"
DEFAULT_PORT: Final = 7071
DEFAULT_REQUEST_TIMEOUT: Final = 15.0
DEFAULT_PROVIDER_TIMEOUT: Final = 30.0
_INSTANCE_ID_RE: Final = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
)
_RAPPID_RE: Final = re.compile(
    r"^rappid:@[a-z0-9][a-z0-9-]{0,62}/"
    r"[a-z0-9][a-z0-9-]{0,127}:[0-9a-f]{64}$"
)
_PRINCIPAL_RE: Final = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$"
)


class RuntimeConfigurationError(RappStackCubbyError, ValueError):
    """Raised when runtime configuration is absent or unsafe."""


@dataclass(frozen=True, slots=True)
class SignedIngressConfig:
    """Explicit private paths and paired identities for signed twin ingress."""

    twin_rappid: str
    child_private_key_path: Path
    paired_controller_public_jwk_path: Path
    paired_controller_rappid: str
    replay_db_path: Path
    freshness_seconds: int = 300
    key_epoch: int = 1

    def __post_init__(self) -> None:
        for label, value in (
            ("twin_rappid", self.twin_rappid),
            ("paired_controller_rappid", self.paired_controller_rappid),
        ):
            if not isinstance(value, str) or not _RAPPID_RE.fullmatch(value):
                raise RuntimeConfigurationError(
                    f"{label} must be a canonical RAPPID"
                )
        if (
            not isinstance(self.freshness_seconds, int)
            or isinstance(self.freshness_seconds, bool)
            or not 1 <= self.freshness_seconds <= 3600
        ):
            raise RuntimeConfigurationError(
                "signed-ingress freshness_seconds must be between 1 and 3600"
            )
        if (
            not isinstance(self.key_epoch, int)
            or isinstance(self.key_epoch, bool)
            or not 1 <= self.key_epoch <= 2**31 - 1
        ):
            raise RuntimeConfigurationError(
                "signed-ingress key_epoch must be a positive integer"
            )
        for field in (
            "child_private_key_path",
            "paired_controller_public_jwk_path",
            "replay_db_path",
        ):
            value = Path(getattr(self, field))
            if not value.is_absolute() or ".." in value.parts:
                raise RuntimeConfigurationError(
                    f"signed-ingress {field} must be an absolute contained path"
                )
            object.__setattr__(self, field, value)


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    """Validated paths and limits with no implicit home-directory fallback."""

    soul_path: Path
    agent_directories: tuple[Path, ...]
    data_root: Path
    instance_id: str
    root: Path
    principal: str
    model: str
    attestation_mode: str | None = None
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    request_timeout: float = DEFAULT_REQUEST_TIMEOUT
    provider_timeout: float = DEFAULT_PROVIDER_TIMEOUT
    voice_mode: bool = False
    generated_agents_dir: Path | None = None
    allow_agent_writes: bool = False
    imessage_status_path: Path | None = None
    signed_only: bool = False
    controller_route_enabled: bool = False
    controller_loadout_root: Path | None = None
    auth_token_file: Path | None = None
    github_token_file: Path | None = None
    signed_ingress: SignedIngressConfig | None = None
    # Direct aliases keep fixed-argv and programmatic construction explicit.
    twin_rappid: str | None = None
    child_private_key_path: Path | None = None
    paired_controller_public_jwk_path: Path | None = None
    paired_controller_rappid: str | None = None
    replay_db_path: Path | None = None
    signed_ingress_freshness_seconds: int = 300
    signed_ingress_key_epoch: int = 1

    def __post_init__(self) -> None:
        soul = _existing_path(self.soul_path, "soul", directory=False)
        directories_value = self.agent_directories
        if isinstance(directories_value, (str, os.PathLike)):
            directories_value = (Path(directories_value),)
        else:
            directories_value = tuple(Path(item) for item in directories_value)
        if not directories_value:
            raise RuntimeConfigurationError(
                "at least one explicit agents directory is required"
            )
        directories = tuple(
            _existing_path(path, "agents", directory=True)
            for path in directories_value
        )
        if len(set(directories)) != len(directories):
            raise RuntimeConfigurationError(
                "agents directories must be unique"
            )
        data = _existing_path(self.data_root, "data", directory=True)
        root = _existing_path(self.root, "root", directory=True)
        principal = validate_principal(self.principal)
        host = validate_loopback_host(self.host)
        port = _validate_port(self.port)
        model = _validate_model(self.model)
        attestation_mode = _validate_attestation_mode(
            self.attestation_mode,
            model=model,
        )
        request_timeout = _validate_timeout(
            self.request_timeout, "request_timeout"
        )
        provider_timeout = _validate_timeout(
            self.provider_timeout, "provider_timeout"
        )
        instance_id = validate_instance_id(self.instance_id)
        if not isinstance(self.voice_mode, bool):
            raise RuntimeConfigurationError("voice_mode must be boolean")
        if not isinstance(self.allow_agent_writes, bool):
            raise RuntimeConfigurationError("allow_agent_writes must be boolean")
        if not isinstance(self.signed_only, bool):
            raise RuntimeConfigurationError("signed_only must be boolean")
        if not isinstance(self.controller_route_enabled, bool):
            raise RuntimeConfigurationError(
                "controller_route_enabled must be boolean"
            )
        generated_agents_dir = self._normalize_generated_agents_dir(data)
        imessage_status_path = (
            None
            if self.imessage_status_path is None
            else _private_status_file(
                Path(self.imessage_status_path),
                "iMessage redacted status",
            )
        )
        signed_ingress = self._normalize_signed_ingress(data)
        if self.signed_only and signed_ingress is None:
            raise RuntimeConfigurationError(
                "signed_only requires complete signed ingress configuration"
            )
        if attestation_mode is not None and not self.signed_only:
            raise RuntimeConfigurationError(
                "attestation mode requires signed_only"
            )
        if attestation_mode is not None and self.controller_route_enabled:
            raise RuntimeConfigurationError(
                "attestation mode is only valid for a signed child runtime"
            )
        controller_loadout_root = self._normalize_controller_loadout()
        auth_token_file = self._normalize_auth_token_file()
        github_token_file = self._normalize_github_token_file(
            attestation_mode
        )

        object.__setattr__(self, "soul_path", soul)
        object.__setattr__(self, "agent_directories", directories)
        object.__setattr__(self, "data_root", data)
        object.__setattr__(self, "root", root)
        object.__setattr__(self, "principal", principal)
        object.__setattr__(self, "host", host)
        object.__setattr__(self, "port", port)
        object.__setattr__(self, "model", model)
        object.__setattr__(self, "attestation_mode", attestation_mode)
        object.__setattr__(self, "request_timeout", request_timeout)
        object.__setattr__(self, "provider_timeout", provider_timeout)
        object.__setattr__(self, "instance_id", instance_id)
        object.__setattr__(
            self, "generated_agents_dir", generated_agents_dir
        )
        object.__setattr__(
            self, "imessage_status_path", imessage_status_path
        )
        object.__setattr__(self, "signed_ingress", signed_ingress)
        object.__setattr__(
            self, "controller_loadout_root", controller_loadout_root
        )
        object.__setattr__(self, "auth_token_file", auth_token_file)
        object.__setattr__(self, "github_token_file", github_token_file)
        if signed_ingress is not None:
            object.__setattr__(self, "twin_rappid", signed_ingress.twin_rappid)
            object.__setattr__(
                self,
                "child_private_key_path",
                signed_ingress.child_private_key_path,
            )
            object.__setattr__(
                self,
                "paired_controller_public_jwk_path",
                signed_ingress.paired_controller_public_jwk_path,
            )
            object.__setattr__(
                self,
                "paired_controller_rappid",
                signed_ingress.paired_controller_rappid,
            )
            object.__setattr__(
                self,
                "replay_db_path",
                signed_ingress.replay_db_path,
            )
            object.__setattr__(
                self,
                "signed_ingress_freshness_seconds",
                signed_ingress.freshness_seconds,
            )
            object.__setattr__(
                self,
                "signed_ingress_key_epoch",
                signed_ingress.key_epoch,
            )

    def _normalize_controller_loadout(self) -> Path | None:
        configured = self.controller_loadout_root
        if not self.controller_route_enabled:
            if configured is not None:
                raise RuntimeConfigurationError(
                    "controller_loadout_root requires controller_route_enabled"
                )
            return None
        if configured is None:
            raise RuntimeConfigurationError(
                "controller route requires an explicit controller loadout root"
            )
        return _existing_path(
            configured, "controller loadout", directory=True
        )

    def _normalize_auth_token_file(self) -> Path | None:
        configured = self.auth_token_file
        if configured is None:
            if self.controller_route_enabled:
                raise RuntimeConfigurationError(
                    "controller route requires an explicit auth token file"
                )
            return None
        from .auth import validate_auth_token_file

        return validate_auth_token_file(configured)

    def _normalize_github_token_file(
        self,
        attestation_mode: str | None,
    ) -> Path | None:
        configured = self.github_token_file
        if configured is None:
            return None
        if attestation_mode is not None or self.controller_route_enabled:
            raise RuntimeConfigurationError(
                "github_token_file is only valid for a live provider runtime"
            )
        from .github_auth import (
            GitHubAuthError,
            read_github_token_file,
            validate_github_token_file,
        )

        try:
            path = validate_github_token_file(configured)
            read_github_token_file(path)
        except GitHubAuthError as error:
            raise RuntimeConfigurationError(str(error)) from error
        return path

    def _normalize_generated_agents_dir(
        self, data_root: Path
    ) -> Path | None:
        configured = self.generated_agents_dir
        if configured is None:
            if not self.allow_agent_writes:
                return None
            return _prepare_private_directory(
                data_root / "generated-agents",
                contained_by=data_root,
                label="generated agents",
            )
        directory = _existing_path(
            configured, "generated agents", directory=True
        )
        try:
            os.chmod(directory, 0o700)
        except OSError as error:
            raise RuntimeConfigurationError(
                "generated agents directory permissions cannot be secured"
            ) from error
        if stat.S_IMODE(directory.stat().st_mode) & 0o077:
            raise RuntimeConfigurationError(
                "generated agents directory must have mode 0700 or stricter"
            )
        return directory

    def _normalize_signed_ingress(self, data_root: Path) -> SignedIngressConfig | None:
        direct_values = (
            self.twin_rappid,
            self.child_private_key_path,
            self.paired_controller_public_jwk_path,
            self.paired_controller_rappid,
            self.replay_db_path,
        )
        if self.signed_ingress is not None and any(
            value is not None for value in direct_values
        ):
            raise RuntimeConfigurationError(
                "configure signed ingress either as one object or direct fields, not both"
            )
        if self.signed_ingress is not None:
            if self.signed_ingress_key_epoch != 1:
                raise RuntimeConfigurationError(
                    "signed-ingress key epoch must be set on the ingress object"
                )
            if not isinstance(self.signed_ingress, SignedIngressConfig):
                raise RuntimeConfigurationError(
                    "signed_ingress must be a SignedIngressConfig"
                )
            configured = self.signed_ingress
        elif any(value is not None for value in direct_values):
            if any(value is None for value in direct_values):
                raise RuntimeConfigurationError(
                    "all signed-ingress identity and path fields are required together"
                )
            configured = SignedIngressConfig(
                twin_rappid=self.twin_rappid,  # type: ignore[arg-type]
                child_private_key_path=Path(self.child_private_key_path),  # type: ignore[arg-type]
                paired_controller_public_jwk_path=Path(
                    self.paired_controller_public_jwk_path  # type: ignore[arg-type]
                ),
                paired_controller_rappid=self.paired_controller_rappid,  # type: ignore[arg-type]
                replay_db_path=Path(self.replay_db_path),  # type: ignore[arg-type]
                freshness_seconds=self.signed_ingress_freshness_seconds,
                key_epoch=self.signed_ingress_key_epoch,
            )
        else:
            if self.signed_ingress_freshness_seconds != 300:
                raise RuntimeConfigurationError(
                    "signed-ingress freshness requires signed-ingress paths"
                )
            if self.signed_ingress_key_epoch != 1:
                raise RuntimeConfigurationError(
                    "signed-ingress key epoch requires signed-ingress paths"
                )
            return None

        if stat.S_IMODE(data_root.stat().st_mode) & 0o077:
            raise RuntimeConfigurationError(
                "signed-ingress data root must have mode 0700 or stricter"
            )
        private_key = _contained_file(
            configured.child_private_key_path,
            data_root,
            "child private key",
        )
        if stat.S_IMODE(private_key.stat().st_mode) & 0o077:
            raise RuntimeConfigurationError(
                "child private key must have mode 0600 or stricter"
            )
        controller_jwk = _contained_file(
            configured.paired_controller_public_jwk_path,
            data_root,
            "paired controller public JWK",
        )
        replay = _contained_future_file(
            configured.replay_db_path,
            data_root,
            "replay database",
        )
        return SignedIngressConfig(
            twin_rappid=configured.twin_rappid,
            child_private_key_path=private_key,
            paired_controller_public_jwk_path=controller_jwk,
            paired_controller_rappid=configured.paired_controller_rappid,
            replay_db_path=replay,
            freshness_seconds=configured.freshness_seconds,
            key_epoch=configured.key_epoch,
        )

    @property
    def agents_dir(self) -> Path:
        """Return the first agents directory for single-directory callers."""

        return self.agent_directories[0]

    def loopback_url(self, port: int | None = None) -> str:
        selected_port = self.port if port is None else _validate_port(port)
        rendered_host = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{rendered_host}:{selected_port}"


def validate_python_version() -> None:
    """Fail startup outside the pinned Python 3.11 runtime."""

    if sys.version_info[:2] != SUPPORTED_PYTHON:
        raise RuntimeConfigurationError(
            "the isolated runtime requires Python 3.11"
        )


def validate_loopback_host(host: object) -> str:
    if not isinstance(host, str) or not host.strip():
        raise RuntimeConfigurationError("host must be a loopback address")
    normalized = host.strip().lower()
    if normalized == "localhost":
        return normalized
    if normalized.startswith("[") and normalized.endswith("]"):
        normalized = normalized[1:-1]
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError as error:
        raise RuntimeConfigurationError(
            "host must be localhost or a numeric loopback address"
        ) from error
    if not address.is_loopback:
        raise RuntimeConfigurationError(
            "host must be a loopback address"
        )
    return address.compressed


def _existing_path(
    value: str | os.PathLike[str],
    label: str,
    *,
    directory: bool,
) -> Path:
    path = Path(value)
    _reject_symlink_components(path, f"{label} path")
    if path.is_symlink():
        raise RuntimeConfigurationError(
            f"{label} path must not be a symbolic link"
        )
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise RuntimeConfigurationError(
            f"configured {label} path does not exist"
        ) from error
    expected = resolved.is_dir() if directory else resolved.is_file()
    if not expected:
        kind = "directory" if directory else "file"
        raise RuntimeConfigurationError(
            f"configured {label} path must be a {kind}"
        )
    return resolved


def _prepare_private_directory(
    path: Path,
    *,
    contained_by: Path,
    label: str,
) -> Path:
    _reject_symlink_components(path, label)
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as error:
        raise RuntimeConfigurationError(
            f"{label} parent does not exist"
        ) from error
    if parent != contained_by and contained_by not in parent.parents:
        raise RuntimeConfigurationError(
            f"{label} must be contained by data_root"
        )
    try:
        path.mkdir(mode=0o700, exist_ok=True)
        resolved = path.resolve(strict=True)
        os.chmod(resolved, 0o700)
    except OSError as error:
        raise RuntimeConfigurationError(
            f"{label} directory cannot be prepared"
        ) from error
    if (
        not resolved.is_dir()
        or (resolved != contained_by and contained_by not in resolved.parents)
        or stat.S_IMODE(resolved.stat().st_mode) & 0o077
    ):
        raise RuntimeConfigurationError(
            f"{label} must be a private directory contained by data_root"
        )
    return resolved


def _private_status_file(path: Path, label: str) -> Path:
    _reject_symlink_components(path, label)
    try:
        resolved = path.resolve(strict=True)
        details = resolved.stat()
    except OSError as error:
        raise RuntimeConfigurationError(f"{label} file does not exist") from error
    if not resolved.is_file() or stat.S_IMODE(details.st_mode) != 0o600:
        raise RuntimeConfigurationError(
            f"{label} must be a mode-0600 regular file"
        )
    return resolved


def _contained_file(value: Path, root: Path, label: str) -> Path:
    path = Path(value)
    _reject_symlink_components(path, label)
    if path.is_symlink():
        raise RuntimeConfigurationError(f"{label} must not be a symbolic link")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise RuntimeConfigurationError(f"{label} does not exist") from error
    if not resolved.is_file() or (resolved != root and root not in resolved.parents):
        raise RuntimeConfigurationError(
            f"{label} must be a regular file contained by data_root"
        )
    return resolved


def _contained_future_file(value: Path, root: Path, label: str) -> Path:
    path = Path(value)
    _reject_symlink_components(path, label)
    if path.is_symlink():
        raise RuntimeConfigurationError(f"{label} must not be a symbolic link")
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as error:
        raise RuntimeConfigurationError(f"{label} parent does not exist") from error
    if parent != root and root not in parent.parents:
        raise RuntimeConfigurationError(f"{label} must be contained by data_root")
    if path.exists() and not path.is_file():
        raise RuntimeConfigurationError(f"{label} must be a regular file")
    return parent / path.name


def _reject_symlink_components(path: Path, label: str) -> None:
    if path.is_absolute():
        current = Path(path.anchor)
        parts = path.parts[1:]
    else:
        current = Path.cwd()
        parts = path.parts
    for part in parts:
        current = current / part
        try:
            details = os.lstat(current)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(details.st_mode):
            raise RuntimeConfigurationError(
                f"{label} path must not contain symbolic links"
            )


def _validate_port(port: object) -> int:
    if (
        not isinstance(port, int)
        or isinstance(port, bool)
        or not 0 <= port <= 65535
    ):
        raise RuntimeConfigurationError(
            "port must be an integer between 0 and 65535"
        )
    return port


def _validate_model(model: object) -> str:
    if not isinstance(model, str) or not model.strip():
        raise RuntimeConfigurationError("model must be a non-empty string")
    normalized = model.strip()
    if len(normalized) > 128 or any(ord(character) < 32 for character in normalized):
        raise RuntimeConfigurationError("model contains invalid characters")
    return normalized


def _validate_attestation_mode(
    value: object,
    *,
    model: str,
) -> str | None:
    if value is None:
        if model == ATTESTATION_MODEL:
            raise RuntimeConfigurationError(
                "reserved attestation model requires explicit attestation mode"
            )
        return None
    if value != ATTESTATION_MODE:
        raise RuntimeConfigurationError(
            f"attestation_mode must be {ATTESTATION_MODE!r}"
        )
    if model != ATTESTATION_MODEL:
        raise RuntimeConfigurationError(
            "attestation mode requires its exact reserved model"
        )
    return ATTESTATION_MODE


def _validate_timeout(value: object, label: str) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not 0 < float(value) <= 300
    ):
        raise RuntimeConfigurationError(
            f"{label} must be between 0 and 300 seconds"
        )
    return float(value)


def validate_instance_id(value: object) -> str:
    if not isinstance(value, str) or not _INSTANCE_ID_RE.fullmatch(value):
        raise RuntimeConfigurationError(
            "instance_id must be 1-128 safe ASCII characters"
        )
    return value


def validate_principal(value: object) -> str:
    if (
        not isinstance(value, str)
        or not _PRINCIPAL_RE.fullmatch(value)
        or value in {".", ".."}
    ):
        raise RuntimeConfigurationError(
            "principal must be 1-128 safe ASCII characters"
        )
    return value
