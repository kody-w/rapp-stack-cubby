"""Explicit private GitHub token files and bounded public device OAuth."""

from __future__ import annotations

import contextlib
import json
import os
import re
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

COPILOT_GITHUB_CLIENT_ID: Final = "Iv1.b507a08c87ecfe98"
GITHUB_DEVICE_CODE_URL: Final = "https://github.com/login/device/code"
GITHUB_ACCESS_TOKEN_URL: Final = "https://github.com/login/oauth/access_token"
GITHUB_TOKEN_SCHEMA: Final = "rapp-copilot-token/1.0"
MAX_TOKEN_FILE_BYTES: Final = 64 * 1024
MAX_OAUTH_RESPONSE_BYTES: Final = 64 * 1024
MAX_SECRET_BYTES: Final = 16 * 1024
MAX_DEVICE_POLLS: Final = 300
DEFAULT_DEVICE_TIMEOUT: Final = 900.0
_USER_CODE_RE = re.compile(r"^[A-Za-z0-9-]{4,32}$")


class GitHubAuthError(ValueError):
    """A content-free GitHub authentication or token-file failure."""

    def __init__(self, message: str, *, status: str = "auth_missing") -> None:
        self.status = status
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class GitHubToken:
    """GitHub OAuth material held only for the duration of one operation."""

    access_token: str
    refresh_token: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "access_token",
            _validate_secret(self.access_token, "access token"),
        )
        if self.refresh_token is not None:
            object.__setattr__(
                self,
                "refresh_token",
                _validate_secret(self.refresh_token, "refresh token"),
            )

    def as_file_payload(self) -> dict[str, str]:
        payload = {
            "schema": GITHUB_TOKEN_SCHEMA,
            "access_token": self.access_token,
        }
        if self.refresh_token is not None:
            payload["refresh_token"] = self.refresh_token
        return payload


def validate_github_token_file(value: str | os.PathLike[str]) -> Path:
    """Require one explicit absolute mode-0600 regular file with no symlinks."""

    path = _explicit_absolute_path(value, "GitHub token file")
    _reject_symlink_components(path)
    try:
        details = os.lstat(path)
    except OSError as error:
        raise GitHubAuthError("GitHub token file does not exist") from error
    if not stat.S_ISREG(details.st_mode):
        raise GitHubAuthError("GitHub token file must be a regular file")
    if stat.S_IMODE(details.st_mode) != 0o600:
        raise GitHubAuthError("GitHub token file must have mode 0600")
    try:
        return path.resolve(strict=True)
    except OSError as error:
        raise GitHubAuthError("GitHub token file cannot be resolved") from error


def read_github_token_file(
    value: str | os.PathLike[str],
) -> GitHubToken:
    """Read and validate the bounded versioned or legacy JSON credential."""

    path = validate_github_token_file(value)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or stat.S_IMODE(details.st_mode) != 0o600
        ):
            raise GitHubAuthError(
                "GitHub token file changed during validation"
            )
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_TOKEN_FILE_BYTES:
            chunk = os.read(
                descriptor,
                min(8192, MAX_TOKEN_FILE_BYTES + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        raw = b"".join(chunks)
    except GitHubAuthError:
        raise
    except OSError as error:
        raise GitHubAuthError("GitHub token file cannot be read") from error
    finally:
        if descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(descriptor)
    if len(raw) > MAX_TOKEN_FILE_BYTES:
        raise GitHubAuthError("GitHub token file exceeds the size limit")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise GitHubAuthError("GitHub token file is not valid JSON") from error
    if not isinstance(payload, dict):
        raise GitHubAuthError("GitHub token file must contain a JSON object")
    keys = set(payload)
    if payload.get("schema") == GITHUB_TOKEN_SCHEMA:
        if not {"schema", "access_token"} <= keys or keys - {
            "schema",
            "access_token",
            "refresh_token",
        }:
            raise GitHubAuthError(
                "GitHub token file versioned fields are invalid"
            )
    elif "schema" not in payload:
        if "access_token" not in payload or keys - {
            "access_token",
            "refresh_token",
        }:
            raise GitHubAuthError("legacy GitHub token fields are invalid")
    else:
        raise GitHubAuthError("GitHub token file schema is unsupported")
    return GitHubToken(
        access_token=payload.get("access_token"),
        refresh_token=payload.get("refresh_token"),
    )


def device_login(
    token_file: str | os.PathLike[str],
    *,
    timeout: float = DEFAULT_DEVICE_TIMEOUT,
    urlopen: Callable[..., Any] | None = None,
    sleep: Callable[[float], None] | None = None,
    clock: Callable[[], float] | None = None,
    display: Callable[[str], None] | None = None,
) -> dict[str, object]:
    """Complete GitHub's bounded device flow and atomically write one token."""

    destination = _validate_token_destination(token_file)
    selected_timeout = _validate_device_timeout(timeout)
    opener = urllib.request.urlopen if urlopen is None else urlopen
    sleeper = time.sleep if sleep is None else sleep
    monotonic = time.monotonic if clock is None else clock
    emit = print if display is None else display
    device = _oauth_request(
        opener,
        GITHUB_DEVICE_CODE_URL,
        {
            "client_id": COPILOT_GITHUB_CLIENT_ID,
            "scope": "read:user",
        },
        timeout=min(30.0, selected_timeout),
    )
    required = {
        "device_code": device.get("device_code"),
        "user_code": device.get("user_code"),
        "verification_uri": device.get("verification_uri"),
        "expires_in": device.get("expires_in"),
        "interval": device.get("interval", 5),
    }
    device_code = _validate_secret(required["device_code"], "device code")
    user_code = required["user_code"]
    if not isinstance(user_code, str) or not _USER_CODE_RE.fullmatch(user_code):
        raise GitHubAuthError(
            "GitHub device response has an invalid user code",
            status="endpoint_drift",
        )
    verification_uri = _verification_uri(required["verification_uri"])
    expires_in = _bounded_integer(
        required["expires_in"], "device expiry", minimum=1, maximum=1800
    )
    interval = _bounded_integer(
        required["interval"], "device interval", minimum=1, maximum=60
    )
    emit(f"verification_uri: {verification_uri}")
    emit(f"user_code: {user_code}")

    started = float(monotonic())
    deadline = started + min(float(expires_in), selected_timeout)
    polls = 0
    try:
        while polls < MAX_DEVICE_POLLS:
            now = float(monotonic())
            if now >= deadline:
                raise GitHubAuthError(
                    "GitHub device authorization expired",
                    status="auth_expired",
                )
            sleeper(min(float(interval), max(0.0, deadline - now)))
            if float(monotonic()) >= deadline:
                raise GitHubAuthError(
                    "GitHub device authorization expired",
                    status="auth_expired",
                )
            polls += 1
            response = _oauth_request(
                opener,
                GITHUB_ACCESS_TOKEN_URL,
                {
                    "client_id": COPILOT_GITHUB_CLIENT_ID,
                    "device_code": device_code,
                    "grant_type": (
                        "urn:ietf:params:oauth:grant-type:device_code"
                    ),
                },
                timeout=min(30.0, max(1.0, deadline - float(monotonic()))),
            )
            error = response.get("error")
            if error == "authorization_pending":
                continue
            if error == "slow_down":
                interval = min(60, interval + 5)
                continue
            if error in {"expired_token", "incorrect_device_code"}:
                raise GitHubAuthError(
                    "GitHub device authorization expired",
                    status="auth_expired",
                )
            if error == "access_denied":
                raise GitHubAuthError(
                    "GitHub device authorization was denied",
                    status="auth_cancelled",
                )
            if error is not None:
                raise GitHubAuthError(
                    "GitHub device authorization failed",
                    status="auth_missing",
                )
            credential = _token_from_oauth_response(response)
            _write_github_token_file(destination, credential)
            return {
                "authenticated": True,
                "refresh_token_available": (
                    credential.refresh_token is not None
                ),
                "schema": GITHUB_TOKEN_SCHEMA,
                "status": "ok",
            }
    except KeyboardInterrupt as error:
        raise GitHubAuthError(
            "GitHub device authorization was cancelled",
            status="auth_cancelled",
        ) from error
    raise GitHubAuthError(
        "GitHub device authorization exceeded its poll limit",
        status="auth_expired",
    )


def refresh_token_file(
    token_file: str | os.PathLike[str],
    *,
    timeout: float = 30.0,
    urlopen: Callable[..., Any] | None = None,
) -> dict[str, object]:
    """Refresh a file only when its bounded JSON supplies a refresh token."""

    destination = validate_github_token_file(token_file)
    credential = read_github_token_file(destination)
    if credential.refresh_token is None:
        raise GitHubAuthError(
            "GitHub token file has no refresh token",
            status="refresh_unavailable",
        )
    opener = urllib.request.urlopen if urlopen is None else urlopen
    response = _oauth_request(
        opener,
        GITHUB_ACCESS_TOKEN_URL,
        {
            "client_id": COPILOT_GITHUB_CLIENT_ID,
            "grant_type": "refresh_token",
            "refresh_token": credential.refresh_token,
        },
        timeout=_validate_http_timeout(timeout),
    )
    if response.get("error") is not None:
        raise GitHubAuthError(
            "GitHub token refresh failed",
            status="auth_missing",
        )
    refreshed = _token_from_oauth_response(
        response,
        fallback_refresh=credential.refresh_token,
    )
    _write_github_token_file(destination, refreshed)
    return {
        "authenticated": True,
        "refresh_token_available": refreshed.refresh_token is not None,
        "schema": GITHUB_TOKEN_SCHEMA,
        "status": "ok",
    }


def _oauth_request(
    urlopen: Callable[..., Any],
    url: str,
    fields: Mapping[str, str],
    *,
    timeout: float,
) -> dict[str, Any]:
    data = urllib.parse.urlencode(dict(fields)).encode("ascii")
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "rapp-stack-cubby/provider-auth",
        },
        method="POST",
    )
    try:
        opened = urlopen(request, timeout=timeout)
        with contextlib.ExitStack() as stack:
            if callable(getattr(opened, "__enter__", None)):
                response = stack.enter_context(opened)
            else:
                response = opened
                close = getattr(response, "close", None)
                if callable(close):
                    stack.callback(close)
            raw = response.read(MAX_OAUTH_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        with contextlib.suppress(Exception):
            error.read(MAX_OAUTH_RESPONSE_BYTES + 1)
        raise GitHubAuthError(
            "GitHub OAuth endpoint rejected the request",
            status="transport",
        ) from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise GitHubAuthError(
            "GitHub OAuth transport failed",
            status="transport",
        ) from error
    if not isinstance(raw, bytes) or len(raw) > MAX_OAUTH_RESPONSE_BYTES:
        raise GitHubAuthError(
            "GitHub OAuth response exceeds the size limit",
            status="endpoint_drift",
        )
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise GitHubAuthError(
            "GitHub OAuth response is invalid JSON",
            status="endpoint_drift",
        ) from error
    if not isinstance(payload, dict) or len(payload) > 32:
        raise GitHubAuthError(
            "GitHub OAuth response schema is invalid",
            status="endpoint_drift",
        )
    return payload


def _token_from_oauth_response(
    payload: Mapping[str, Any],
    *,
    fallback_refresh: str | None = None,
) -> GitHubToken:
    refresh = payload.get("refresh_token", fallback_refresh)
    try:
        return GitHubToken(
            access_token=payload.get("access_token"),
            refresh_token=refresh,
        )
    except GitHubAuthError as error:
        raise GitHubAuthError(
            "GitHub OAuth token response schema is invalid",
            status="endpoint_drift",
        ) from error


def _write_github_token_file(path: Path, credential: GitHubToken) -> None:
    destination = _validate_token_destination(path)
    payload = (
        json.dumps(
            credential.as_file_payload(),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")
    if len(payload) > MAX_TOKEN_FILE_BYTES:
        raise GitHubAuthError("GitHub token payload exceeds the size limit")
    stage = destination.parent / (
        f".{destination.name}.stage-{uuid.uuid4().hex}"
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(
            stage,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            descriptor = None
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(stage, destination)
        os.chmod(destination, 0o600)
        directory = os.open(
            destination.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as error:
        raise GitHubAuthError(
            "GitHub token file could not be written atomically"
        ) from error
    finally:
        if descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        with contextlib.suppress(FileNotFoundError):
            stage.unlink()


def _validate_token_destination(
    value: str | os.PathLike[str],
) -> Path:
    path = _explicit_absolute_path(value, "GitHub token file")
    _reject_symlink_components(path)
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as error:
        raise GitHubAuthError(
            "GitHub token file parent does not exist"
        ) from error
    if not parent.is_dir():
        raise GitHubAuthError(
            "GitHub token file parent must be a directory"
        )
    destination = parent / path.name
    if destination.exists():
        details = os.lstat(destination)
        if (
            not stat.S_ISREG(details.st_mode)
            or stat.S_IMODE(details.st_mode) != 0o600
        ):
            raise GitHubAuthError(
                "existing GitHub token file must be mode-0600 regular file"
            )
    return destination


def _explicit_absolute_path(
    value: str | os.PathLike[str],
    label: str,
) -> Path:
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise GitHubAuthError(
            f"{label} must be an explicit absolute path"
        )
    if not path.name:
        raise GitHubAuthError(f"{label} must name a file")
    return path


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            details = os.lstat(current)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise GitHubAuthError(
                "GitHub token path cannot be inspected"
            ) from error
        if stat.S_ISLNK(details.st_mode):
            raise GitHubAuthError(
                "GitHub token path must not contain symbolic links"
            )


def _validate_secret(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise GitHubAuthError(f"{label} must be a string")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError as error:
        raise GitHubAuthError(f"{label} is invalid") from error
    if (
        not value
        or len(encoded) > MAX_SECRET_BYTES
        or value != value.strip()
        or any(ord(character) < 33 or ord(character) == 127 for character in value)
    ):
        raise GitHubAuthError(f"{label} is invalid")
    return value


def _verification_uri(value: object) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise GitHubAuthError(
            "GitHub device response has no verification URI",
            status="endpoint_drift",
        )
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in {"github.com", "www.github.com"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise GitHubAuthError(
            "GitHub device verification URI is invalid",
            status="endpoint_drift",
        )
    return value


def _bounded_integer(
    value: object,
    label: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= maximum
    ):
        raise GitHubAuthError(
            f"GitHub {label} is invalid",
            status="endpoint_drift",
        )
    return value


def _validate_device_timeout(value: object) -> float:
    timeout = _validate_http_timeout(value)
    if timeout < 30.0 or timeout > 1800.0:
        raise GitHubAuthError(
            "device login timeout must be between 30 and 1800 seconds"
        )
    return timeout


def _validate_http_timeout(value: object) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not 0 < float(value) <= 1800
    ):
        raise GitHubAuthError("OAuth timeout is invalid")
    return float(value)
