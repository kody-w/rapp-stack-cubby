"""Private bearer-token handling for loopback runtime IPC."""

from __future__ import annotations

import base64
import binascii
import hmac
import os
import secrets
import stat
import uuid
from pathlib import Path
from typing import Final, Sequence

from .config import RuntimeConfigurationError


AUTH_TOKEN_BYTES: Final = 32
AUTH_TOKEN_NAME: Final = "controller-auth.token"
MAX_AUTHORIZATION_BYTES: Final = 128
AUTH_CHALLENGE_HEADER: Final = "X-Rapp-Auth-Challenge"
AUTH_PROOF_HEADER: Final = "X-Rapp-Auth-Proof"
_AUTH_PROOF_DOMAIN: Final = b"rapp-runtime-auth-challenge/1.0\0"


def validate_auth_token_file(value: str | os.PathLike[str]) -> Path:
    """Return one absolute, non-symlink, mode-0600 32-byte token file."""

    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise RuntimeConfigurationError(
            "auth token file must be an explicit absolute path"
        )
    _reject_symlink_components(path)
    try:
        details = os.lstat(path)
    except OSError as error:
        raise RuntimeConfigurationError("auth token file is unavailable") from error
    if (
        not stat.S_ISREG(details.st_mode)
        or stat.S_IMODE(details.st_mode) != 0o600
        or details.st_size != AUTH_TOKEN_BYTES
    ):
        raise RuntimeConfigurationError(
            "auth token file must be a mode-0600 regular 32-byte file"
        )
    return path


def read_auth_token(value: str | os.PathLike[str]) -> bytes:
    """Read a validated token without following a final-component symlink."""

    path = validate_auth_token_file(value)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or stat.S_IMODE(details.st_mode) != 0o600
            or details.st_size != AUTH_TOKEN_BYTES
        ):
            raise RuntimeConfigurationError("auth token file changed during read")
        token = os.read(descriptor, AUTH_TOKEN_BYTES + 1)
    except OSError as error:
        raise RuntimeConfigurationError("auth token file cannot be read") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(token) != AUTH_TOKEN_BYTES:
        raise RuntimeConfigurationError("auth token file is invalid")
    return token


def bearer_authorization(token: bytes) -> str:
    if not isinstance(token, bytes) or len(token) != AUTH_TOKEN_BYTES:
        raise RuntimeConfigurationError("auth token is invalid")
    encoded = base64.urlsafe_b64encode(token).rstrip(b"=").decode("ascii")
    return "Bearer " + encoded


def verify_bearer_headers(values: Sequence[str], expected_token: bytes) -> bool:
    """Strictly parse one bearer value and compare its bytes in constant time."""

    if (
        not isinstance(expected_token, bytes)
        or len(expected_token) != AUTH_TOKEN_BYTES
        or len(values) != 1
    ):
        return False
    value = values[0]
    try:
        encoded_value = value.encode("ascii", "strict")
    except (AttributeError, UnicodeEncodeError):
        return False
    if (
        len(encoded_value) > MAX_AUTHORIZATION_BYTES
        or not value.startswith("Bearer ")
        or value.count(" ") != 1
    ):
        return False
    encoded = value[7:]
    if len(encoded) != 43 or any(
        character
        not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for character in encoded
    ):
        return False
    try:
        candidate = base64.b64decode(
            encoded + "=",
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error):
        return False
    if (
        len(candidate) != AUTH_TOKEN_BYTES
        or base64.urlsafe_b64encode(candidate).rstrip(b"=").decode("ascii")
        != encoded
    ):
        return False
    return hmac.compare_digest(candidate, expected_token)


def new_auth_challenge() -> bytes:
    return secrets.token_bytes(AUTH_TOKEN_BYTES)


def encode_auth_value(value: bytes) -> str:
    if not isinstance(value, bytes) or len(value) != AUTH_TOKEN_BYTES:
        raise RuntimeConfigurationError("auth challenge value is invalid")
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decode_auth_value(value: object) -> bytes | None:
    if not isinstance(value, str) or len(value) != 43:
        return None
    if any(
        character
        not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for character in value
    ):
        return None
    try:
        decoded = base64.b64decode(
            value + "=",
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error):
        return None
    if (
        len(decoded) != AUTH_TOKEN_BYTES
        or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
        != value
    ):
        return None
    return decoded


def auth_challenge_proof(token: bytes, challenge: bytes) -> str:
    if (
        not isinstance(token, bytes)
        or len(token) != AUTH_TOKEN_BYTES
        or not isinstance(challenge, bytes)
        or len(challenge) != AUTH_TOKEN_BYTES
    ):
        raise RuntimeConfigurationError("auth challenge inputs are invalid")
    digest = hmac.new(
        token,
        _AUTH_PROOF_DOMAIN + challenge,
        "sha256",
    ).digest()
    return encode_auth_value(digest)


def verify_auth_challenge_proof(
    token: bytes,
    challenge: bytes,
    proof: object,
) -> bool:
    candidate = decode_auth_value(proof)
    if candidate is None:
        return False
    expected = hmac.new(
        token,
        _AUTH_PROOF_DOMAIN + challenge,
        "sha256",
    ).digest()
    return hmac.compare_digest(candidate, expected)


def prepare_controller_auth(
    private_dir: str | os.PathLike[str],
    *,
    verify_only: bool = False,
) -> tuple[Path, bool]:
    """Atomically create or verify the fixed token in an explicit private dir."""

    directory = Path(private_dir)
    if not directory.is_absolute() or ".." in directory.parts:
        raise RuntimeConfigurationError(
            "controller auth directory must be an explicit absolute path"
        )
    _reject_symlink_components(directory)
    if not directory.exists():
        try:
            directory.mkdir(mode=0o700)
        except OSError as error:
            raise RuntimeConfigurationError(
                "controller auth directory cannot be created"
            ) from error
    try:
        details = os.lstat(directory)
    except OSError as error:
        raise RuntimeConfigurationError(
            "controller auth directory is unavailable"
        ) from error
    if (
        not stat.S_ISDIR(details.st_mode)
        or stat.S_IMODE(details.st_mode) != 0o700
    ):
        raise RuntimeConfigurationError(
            "controller auth directory must be mode 0700"
        )
    path = directory / AUTH_TOKEN_NAME
    if path.exists() or path.is_symlink():
        read_auth_token(path)
        return path, False
    if verify_only:
        raise RuntimeConfigurationError("controller auth token is unavailable")

    temporary = directory / f".{AUTH_TOKEN_NAME}.{uuid.uuid4().hex}.new"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        token = secrets.token_bytes(AUTH_TOKEN_BYTES)
        offset = 0
        while offset < len(token):
            offset += os.write(descriptor, token[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            read_auth_token(path)
            return path, False
        temporary.unlink()
        os.chmod(path, 0o600)
        parent = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    except OSError as error:
        raise RuntimeConfigurationError(
            "controller auth token cannot be created"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    read_auth_token(path)
    return path, True


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            details = os.lstat(current)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise RuntimeConfigurationError(
                "auth path cannot be inspected safely"
            ) from error
        if stat.S_ISLNK(details.st_mode):
            raise RuntimeConfigurationError(
                "auth path must not contain symbolic links"
            )
