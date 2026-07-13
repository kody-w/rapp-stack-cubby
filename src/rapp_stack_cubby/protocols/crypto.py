"""ECDSA P-256 transport key and signature helpers."""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from .canonical import canonical_json_bytes, parse_json

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_P256_ORDER = (
    0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
)


class KeyMaterialError(ValueError):
    """Raised when transport key material is invalid or unsafe."""


@dataclass(frozen=True, slots=True)
class TransportKeyPair:
    private_key_path: Path
    public_jwk_path: Path
    public_jwk: dict[str, str]
    key_id: str


def b64url_encode(value: bytes) -> str:
    if not isinstance(value, bytes):
        raise KeyMaterialError("base64url input must be bytes")
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_decode(value: str, *, expected_length: int | None = None) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or "=" in value
        or not _B64URL_RE.fullmatch(value)
    ):
        raise KeyMaterialError("base64url value is not canonical")
    try:
        decoded = base64.b64decode(
            value + ("=" * (-len(value) % 4)),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error) as error:
        raise KeyMaterialError("base64url value is invalid") from error
    if b64url_encode(decoded) != value:
        raise KeyMaterialError("base64url value is not canonical")
    if expected_length is not None and len(decoded) != expected_length:
        raise KeyMaterialError("base64url value has the wrong decoded length")
    return decoded


def public_jwk_from_key(
    key: ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey,
) -> dict[str, str]:
    public = key.public_key() if isinstance(key, ec.EllipticCurvePrivateKey) else key
    if not isinstance(public.curve, ec.SECP256R1):
        raise KeyMaterialError("transport key must use P-256")
    numbers = public.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url_encode(numbers.x.to_bytes(32, "big")),
        "y": b64url_encode(numbers.y.to_bytes(32, "big")),
    }


def public_key_from_jwk(jwk: Mapping[str, Any]) -> ec.EllipticCurvePublicKey:
    normalized = validate_public_jwk(jwk)
    x = int.from_bytes(b64url_decode(normalized["x"], expected_length=32), "big")
    y = int.from_bytes(b64url_decode(normalized["y"], expected_length=32), "big")
    try:
        return ec.EllipticCurvePublicNumbers(
            x,
            y,
            ec.SECP256R1(),
        ).public_key()
    except ValueError as error:
        raise KeyMaterialError("JWK coordinates are not a valid P-256 point") from error


def validate_public_jwk(jwk: Mapping[str, Any]) -> dict[str, str]:
    if not isinstance(jwk, Mapping) or set(jwk) != {"kty", "crv", "x", "y"}:
        raise KeyMaterialError("public JWK must contain exactly kty, crv, x, and y")
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise KeyMaterialError("public JWK must be an EC P-256 key")
    x = jwk.get("x")
    y = jwk.get("y")
    if not isinstance(x, str) or not isinstance(y, str):
        raise KeyMaterialError("public JWK coordinates must be strings")
    b64url_decode(x, expected_length=32)
    b64url_decode(y, expected_length=32)
    normalized = {"kty": "EC", "crv": "P-256", "x": x, "y": y}
    # Point validation is deliberately separate from syntax but mandatory here.
    try:
        ec.EllipticCurvePublicNumbers(
            int.from_bytes(b64url_decode(x, expected_length=32), "big"),
            int.from_bytes(b64url_decode(y, expected_length=32), "big"),
            ec.SECP256R1(),
        ).public_key()
    except ValueError as error:
        raise KeyMaterialError("JWK coordinates are not a valid P-256 point") from error
    return normalized


def key_id_for_jwk(jwk: Mapping[str, Any]) -> str:
    normalized = validate_public_jwk(jwk)
    return hashlib.sha256(canonical_json_bytes(normalized)).hexdigest()


def load_public_jwk(path: str | os.PathLike[str]) -> dict[str, str]:
    candidate = _safe_existing_file(path, "public JWK")
    if candidate.stat().st_size > 4096:
        raise KeyMaterialError("public JWK exceeds the size limit")
    try:
        value = parse_json(candidate.read_bytes())
    except (OSError, ValueError) as error:
        raise KeyMaterialError("public JWK cannot be read") from error
    return validate_public_jwk(value)


def load_private_key(
    path: str | os.PathLike[str],
) -> ec.EllipticCurvePrivateKey:
    candidate = _safe_existing_file(path, "private key")
    mode = stat.S_IMODE(candidate.stat().st_mode)
    if mode & 0o077:
        raise KeyMaterialError("private key mode must not grant group or other access")
    if candidate.stat().st_size > 16 * 1024:
        raise KeyMaterialError("private key exceeds the size limit")
    try:
        encoded = candidate.read_bytes()
    except OSError as error:
        raise KeyMaterialError("private key cannot be read") from error
    if (
        not encoded.startswith(b"-----BEGIN PRIVATE KEY-----\n")
        or not encoded.endswith(b"-----END PRIVATE KEY-----\n")
        or encoded.count(b"-----BEGIN ") != 1
        or encoded.count(b"-----END ") != 1
        or b"\r" in encoded
    ):
        raise KeyMaterialError(
            "private key must be exact unencrypted PKCS8 PEM"
        )
    try:
        key = serialization.load_pem_private_key(
            encoded,
            password=None,
        )
    except (OSError, TypeError, ValueError) as error:
        raise KeyMaterialError("private key is not unencrypted PKCS8 PEM") from error
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise KeyMaterialError("private key must be ECDSA P-256")
    return key


def create_transport_keypair(
    private_key_path: str | os.PathLike[str],
    public_jwk_path: str | os.PathLike[str],
) -> TransportKeyPair:
    """Atomically create a non-overwriting PKCS8/JWK key pair."""

    private_path = Path(private_key_path)
    public_path = Path(public_jwk_path)
    if private_path == public_path or private_path.parent != public_path.parent:
        raise KeyMaterialError("transport key files must be distinct siblings")
    parent = _prepare_private_directory(private_path.parent)
    if private_path.exists() or public_path.exists():
        raise FileExistsError("transport key material already exists")
    key = ec.generate_private_key(ec.SECP256R1())
    jwk = public_jwk_from_key(key)
    private_bytes = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_bytes = canonical_json_bytes(jwk) + b"\n"
    private_tmp = parent / f".{private_path.name}.new-{uuid.uuid4().hex}"
    public_tmp = parent / f".{public_path.name}.new-{uuid.uuid4().hex}"
    private_created = False
    public_created = False
    try:
        _write_new_file(private_tmp, private_bytes, 0o600)
        _write_new_file(public_tmp, public_bytes, 0o644)
        if private_path.exists() or public_path.exists():
            raise FileExistsError("transport key material already exists")
        os.link(private_tmp, private_path)
        private_created = True
        try:
            os.link(public_tmp, public_path)
            public_created = True
        except BaseException:
            private_path.unlink(missing_ok=True)
            private_created = False
            raise
        os.chmod(private_path, 0o600)
        os.chmod(public_path, 0o644)
        _fsync_directory(parent)
    except BaseException:
        if private_created:
            private_path.unlink(missing_ok=True)
        if public_created:
            public_path.unlink(missing_ok=True)
        raise
    finally:
        private_tmp.unlink(missing_ok=True)
        public_tmp.unlink(missing_ok=True)
    return TransportKeyPair(
        private_key_path=private_path.resolve(strict=True),
        public_jwk_path=public_path.resolve(strict=True),
        public_jwk=jwk,
        key_id=key_id_for_jwk(jwk),
    )


def sign_object(
    value: Mapping[str, Any],
    private_key: ec.EllipticCurvePrivateKey,
) -> str:
    """Sign canonical object bytes after omitting only top-level ``sig``."""

    if not isinstance(value, Mapping):
        raise KeyMaterialError("signed value must be an object")
    if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(
        private_key.curve, ec.SECP256R1
    ):
        raise KeyMaterialError("signing key must be ECDSA P-256")
    unsigned = dict(value)
    unsigned.pop("sig", None)
    der = private_key.sign(
        canonical_json_bytes(unsigned),
        ec.ECDSA(hashes.SHA256()),
    )
    r, s = decode_dss_signature(der)
    if s > _P256_ORDER // 2:
        s = _P256_ORDER - s
    return b64url_encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def verify_object(
    value: Mapping[str, Any],
    public_jwk: Mapping[str, Any],
) -> None:
    """Verify a canonical raw P1363 signature, rejecting DER on the wire."""

    if not isinstance(value, Mapping):
        raise KeyMaterialError("signed value must be an object")
    signature_text = value.get("sig")
    if not isinstance(signature_text, str):
        raise KeyMaterialError("signed value requires a string sig")
    raw = b64url_decode(signature_text, expected_length=64)
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:], "big")
    if not 1 <= r < _P256_ORDER or not 1 <= s < _P256_ORDER:
        raise KeyMaterialError("P1363 signature scalar is out of range")
    if s > _P256_ORDER // 2:
        raise KeyMaterialError("P1363 signature must use canonical low-S form")
    unsigned = dict(value)
    unsigned.pop("sig", None)
    try:
        public_key_from_jwk(public_jwk).verify(
            encode_dss_signature(r, s),
            canonical_json_bytes(unsigned),
            ec.ECDSA(hashes.SHA256()),
        )
    except InvalidSignature as error:
        raise KeyMaterialError("signature verification failed") from error


def _prepare_private_directory(path: Path) -> Path:
    if not path.is_absolute():
        raise KeyMaterialError("key directory must be absolute")
    _reject_symlink_components(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    _reject_symlink_components(path)
    if path.is_symlink() or not path.is_dir():
        raise KeyMaterialError("key directory must be a regular directory")
    os.chmod(path, 0o700)
    return path


def _safe_existing_file(
    path: str | os.PathLike[str],
    label: str,
) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        raise KeyMaterialError(f"{label} path must be absolute")
    _reject_symlink_components(candidate)
    try:
        resolved = candidate.resolve(strict=True)
        details = resolved.stat()
    except OSError as error:
        raise KeyMaterialError(f"{label} does not exist") from error
    if candidate.is_symlink() or not stat.S_ISREG(details.st_mode):
        raise KeyMaterialError(f"{label} must be a regular non-symlink file")
    return resolved


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            details = os.lstat(current)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(details.st_mode):
            raise KeyMaterialError("key path must not contain symbolic links")


def _write_new_file(path: Path, payload: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, mode)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
