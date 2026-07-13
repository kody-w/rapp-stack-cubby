"""Single-file controller for exact-commit local RAPP twin lifecycles."""

import contextlib
import datetime
import ast
import base64
import binascii
import errno
import fcntl
import hashlib
import http.client
import json
import os
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import threading
import time
import urllib.parse
import uuid
from pathlib import Path

from agents.basic_agent import BasicAgent
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)


__manifest__ = {
    "schema": "rapp-agent/1.0",
    "name": "RappStackCubbyController",
    "version": "1.0.0",
    "description": "Hatch and supervise exact-commit isolated local RAPP twins.",
    "actions": [
        "inspect",
        "verify",
        "adopt_install",
        "hatch_repo",
        "list",
        "status",
        "start",
        "stop",
        "archive",
        "unarchive",
        "purge",
        "rotate_keys",
        "chat",
        "self_test",
        "pack",
        "export",
    ],
    "capability_ids": [
        "agents.controller-child-semantics",
        "chat.complete-twin-envelope",
        "chat.replay-idempotency",
        "chat.signed-commons-wrapper",
        "chat.signed-response",
        "identity.owner-binding",
        "identity.p256-transport-pairing",
        "runtime.streaming-controller",
        "security.signed-twin-traffic",
        "twin.boot-health-stop",
        "twin.global-controller-child",
        "twin.hatch-isolated",
        "twin.mint",
    ],
    "mutability": "guarded_local_lifecycle",
    "enabled_by_default": True,
    "provenance": "original_new",
    "dependencies": [
        "python-stdlib",
        "BasicAgent",
        "git",
        "cryptography==49.0.0",
    ],
}

_ALLOWED_REPOSITORY = "https://github.com/kody-w/rapp-stack-cubby.git"
_ALLOWED_REPOSITORY_PATHS = frozenset(
    {"/kody-w/rapp-stack-cubby", "/kody-w/rapp-stack-cubby.git"}
)
_ACTIONS = tuple(__manifest__["actions"])
_MUTATING_ACTIONS = frozenset(
    {
        "hatch_repo",
        "adopt_install",
        "start",
        "stop",
        "archive",
        "unarchive",
        "purge",
        "rotate_keys",
        "chat",
        "self_test",
    }
)
_LIFECYCLE_ACTIONS = frozenset(
    {
        "hatch_repo",
        "adopt_install",
        "start",
        "stop",
        "archive",
        "unarchive",
        "purge",
        "rotate_keys",
    }
)
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
_RAPPID_RE = re.compile(
    r"^rappid:@(?P<owner>[a-z0-9][a-z0-9-]{0,62})/"
    r"(?P<slug>[a-z0-9][a-z0-9-]{0,62}):(?P<digest>[0-9a-f]{64})$"
)
_IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_AUDIENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")
_INSTANCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_RELEASE_MANIFEST_NAME = "rapp-release-source-manifest.json"
_RELEASE_MANIFEST_SCHEMA = "rapp-release-source-manifest/1.0"
_STATE_SCHEMA = "rapp-controller-twin-state/1.0"
_RECEIPT_SCHEMA = "rapp-controller-receipt/1.0"
_TOMBSTONE_SCHEMA = "rapp-controller-purge-tombstone/1.0"
_JOURNAL_SCHEMA = "rapp-controller-journal/1.0"
_PAIRING_SCHEMA = "rapp-twin-chat-pairing/1.0"
_CONTROLLER_TRANSPORT_SCHEMA = "rapp-controller-transport/1.0"
_OUTBOUND_REQUEST_SCHEMA = "rapp-controller-signed-request/1.0"
_OUTBOUND_RESPONSE_SCHEMA = "rapp-controller-signed-response/1.0"
_INSTALLED_SCHEMA = "rapp-installed-twin/1.1"
_HATCH_RECEIPT_SCHEMA = "rapp-hatch-receipt/1.1"
_TWIN_REQUEST_SCHEMA = "rapp-twin-chat/1.0"
_COMMONS_SCHEMA = "rapp-commons-event/1.0"
_TWIN_RESPONSE_SCHEMA = "rapp-twin-chat-response/1.0"
_TRANSPORT_ALGORITHM = "ecdsa-p256"
_TWIN_CHAT_KIND = "say"
_P256_ORDER = (
    0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
)
_TRANSPORT_INNER_KEYS = frozenset(
    {
        "schema",
        "from_rappid",
        "to_rappid",
        "utc",
        "nonce",
        "key_epoch",
        "kind",
        "payload",
        "facets",
    }
)
_TRANSPORT_WRAPPER_KEYS = frozenset(
    {
        "schema",
        "from",
        "pub",
        "alg",
        "ts",
        "kind",
        "body",
        "key_id",
        "sig",
    }
)
_TRANSPORT_RESPONSE_KEYS = frozenset(
    {
        "schema",
        "from_rappid",
        "to_rappid",
        "utc",
        "request_nonce",
        "request_digest",
        "key_epoch",
        "status",
        "payload",
        "key_id",
        "sig",
    }
)
_TRANSPORT_PAIRING_KEYS = frozenset(
    {
        "schema",
        "twin_rappid",
        "controller_rappid",
        "controller_key_id",
        "controller_public_jwk",
        "child_key_id",
        "child_public_jwk",
        "generation",
        "key_epoch",
        "paired_at",
    }
)
_MAX_SOURCE_FILES = 20000
_MAX_SOURCE_BYTES = 512 * 1024 * 1024
_MAX_SOURCE_FILE_BYTES = 32 * 1024 * 1024
_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_CHAT_BYTES = 2 * 1024 * 1024
_MAX_MESSAGE_CHARS = 1024 * 1024
_MAX_LOG_BYTES = 1024 * 1024
_LOG_BACKUPS = 3
_HEALTH_TIMEOUT = 12.0
_CHILD_PROVIDER_TIMEOUT = 30.0
_ATTESTATION_MODE = "offline-self-test"
_ATTESTATION_MODEL = "attestation-self-test/1.0"
_HTTP_TIMEOUT_MARGIN = 5.0
_HTTP_TIMEOUT = _CHILD_PROVIDER_TIMEOUT + _HTTP_TIMEOUT_MARGIN
_STOP_TIMEOUT = 5.0
_GIT_TIMEOUT = 120.0
_PYTHON_PROBE_TIMEOUT = 10.0
_MODEL_PREFLIGHT_TIMEOUT = 60.0
_TRANSACTION_LEASE_SECONDS = 30
_GIT_EXECUTABLE = "/usr/bin/git"
_PS_EXECUTABLE = "/bin/ps"
_INTERNAL_AGENT_RELATIVE = Path(
    "cubbies/kody-w/rapplications/rapp-stack/twin/agents"
)
_SOUL_RELATIVE = Path(
    "cubbies/kody-w/rapplications/rapp-stack/twin/soul.md"
)
_FORBIDDEN_FILE_NAMES = frozenset(
    {
        ".DS_Store",
        ".env",
        "credentials.json",
        "id_ed25519",
        "id_rsa",
        "secrets.json",
    }
)
_FORBIDDEN_SUFFIXES = (
    ".db",
    ".egg",
    ".journal",
    ".key",
    ".log",
    ".p12",
    ".pem",
    ".pfx",
    ".pid",
    ".pyc",
    ".pyo",
    ".sqlite",
    ".sqlite3",
    ".sqlite-shm",
    ".sqlite-wal",
    ".whl",
    ".zip",
)
_FORBIDDEN_COMPONENTS = frozenset(
    {
        ".git",
        ".rapp-stack-cubby",
        ".venv",
        "__pycache__",
        "node_modules",
        "venv",
    }
)
_FORBIDDEN_TOP_LEVEL = frozenset(
    {"loadout", "locks", "receipts", "sessions", "staging", "state", "twins"}
)
_REJECTED_SOURCE_TOP_LEVEL = frozenset(
    {
        ".check-cache",
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".rapp-stack-cubby",
        ".ruff_cache",
        ".venv",
        "build",
        "cache",
        "dist",
        "loadout",
        "locks",
        "private",
        "receipts",
        "runtime",
        "sessions",
        "staging",
        "state",
        "twins",
        "venv",
    }
)
_SOURCE_SKIPPED_TOP_LEVEL = frozenset(
    {
        ".check-cache",
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".rapp-stack-cubby",
        ".ruff_cache",
        ".venv",
        "build",
        "dist",
        "loadout",
        "locks",
        "receipts",
        "runtime",
        "sessions",
        "staging",
        "state",
        "twins",
        "venv",
    }
)
_SOURCE_SKIPPED_COMPONENTS = frozenset(
    {
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "node_modules",
    }
)
_DEVELOPMENT_EXECUTABLES = frozenset(
    {
        "scripts/attest-installed-offline.sh",
        "scripts/bootstrap-development.sh",
        "scripts/build-release.sh",
        "scripts/check.sh",
        "scripts/context-check.sh",
        "scripts/demo-product.sh",
        "scripts/fetch-dependencies.sh",
        "scripts/hatch.sh",
        "scripts/install-imessage-service.sh",
        "scripts/install-imsg.sh",
        "scripts/rollback-product.sh",
        "scripts/uninstall-imessage-service.sh",
        "scripts/uninstall-imsg.sh",
    }
)
_ERROR_MESSAGES = {
    "archive_exists": "An archived twin with this identity already exists.",
    "adopt_invalid": "The explicit installed twin is not verified and immutable.",
    "busy": "A conflicting controller transition is already in progress.",
    "commit_invalid": "Commit must be exactly 40 lowercase hexadecimal characters.",
    "confirmation_required": "Purge confirmation must equal the full RAPPID.",
    "controller_root_invalid": "The explicit controller data root is invalid or unsafe.",
    "development_digest_required": "Development hatch requires the exact expected tree digest.",
    "development_hatch_disabled": "Production hatch requires a valid release source manifest.",
    "duplicate_identity": "A twin or tombstone with this identity already exists.",
    "health_failed": "The child runtime did not become healthy in time.",
    "http_unavailable": "The local child runtime is unavailable.",
    "idempotency_conflict": "The idempotency key was already used for a different request.",
    "idempotency_key_required": "A valid idempotency key is required.",
    "identity_invalid": "A valid canonical RAPPID is required.",
    "manifest_invalid": "The release source manifest does not match the fetched tree.",
    "message_invalid": "Chat requires a non-empty bounded message.",
    "model_invalid": "Start requires an exact model that passes runtime preflight.",
    "mutation_disabled": "Controller mutations are disabled.",
    "not_archived": "The twin must be archived for this operation.",
    "not_found": "The requested twin does not exist.",
    "not_running": "The twin runtime is not running.",
    "not_stopped": "The twin runtime must be fully stopped for this operation.",
    "provider_auth_invalid": (
        "Live start requires an explicit safe GitHub token file."
    ),
    "process_identity_mismatch": "The recorded process no longer belongs to this twin.",
    "purged": "This identity has a purge tombstone and cannot be reused.",
    "python_invalid": "RAPP_STACK_PYTHON must name an absolute Python 3.11 executable.",
    "repository_invalid": "Only the canonical rapp-stack-cubby HTTPS repository is allowed.",
    "response_invalid": "The local child returned an invalid response.",
    "key_rotation_failed": "The child transport key rotation failed safely.",
    "self_test_failed": "The conversational SelfTest proof was not present.",
    "source_invalid": "The fetched source tree violates the controller source policy.",
    "source_mismatch": "The fetched source tree digest does not match the expected digest.",
    "start_failed": "The child runtime could not be started.",
    "state_invalid": "The stored controller state is invalid.",
    "transition_failed": "The lifecycle transition could not be completed atomically.",
}
_THREAD_LOCK_GUARD = threading.Lock()
_THREAD_LOCKS = {}


def _json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _canonical_bytes(value):
    return _json(value).encode("utf-8")


def _utc_now():
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def _transport_validate_value(value, depth=0, counter=None):
    if counter is None:
        counter = [0]
    counter[0] += 1
    if counter[0] > 4096 or depth > 16:
        _error("response_invalid")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if not -(2**63) <= value <= 2**63 - 1:
            _error("response_invalid")
        return
    if isinstance(value, float):
        _error("response_invalid")
    if isinstance(value, str):
        try:
            size = len(value.encode("utf-8"))
        except UnicodeEncodeError:
            _error("response_invalid")
        if size > 1024 * 1024:
            _error("response_invalid")
        return
    if isinstance(value, list):
        if len(value) > 512:
            _error("response_invalid")
        for item in value:
            _transport_validate_value(item, depth + 1, counter)
        return
    if isinstance(value, dict):
        if len(value) > 256:
            _error("response_invalid")
        for key, item in value.items():
            if not isinstance(key, str):
                _error("response_invalid")
            _transport_validate_value(key, depth + 1, counter)
            _transport_validate_value(item, depth + 1, counter)
        return
    _error("response_invalid")


def _transport_canonical_bytes(value):
    _transport_validate_value(value)
    try:
        payload = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _error("response_invalid")
    if len(payload) > _MAX_CHAT_BYTES:
        _error("response_invalid")
    return payload


def _transport_parse_json(value):
    if not isinstance(value, (str, bytes)):
        _error("response_invalid")
    if isinstance(value, bytes):
        try:
            source = value.decode("utf-8")
        except UnicodeError:
            _error("response_invalid")
    else:
        source = value
    try:
        if len(source.encode("utf-8")) > _MAX_CHAT_BYTES:
            _error("response_invalid")
    except UnicodeError:
        _error("response_invalid")

    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError("duplicate")
            result[key] = item
        return result

    def reject_number(raw):
        raise ValueError(raw)

    def parse_integer(raw):
        parsed = int(raw, 10)
        if not -(2**63) <= parsed <= 2**63 - 1:
            raise ValueError(raw)
        return parsed

    try:
        decoded = json.loads(
            source,
            object_pairs_hook=pairs,
            parse_float=reject_number,
            parse_int=parse_integer,
            parse_constant=reject_number,
        )
    except (ValueError, UnicodeError, RecursionError):
        _error("response_invalid")
    _transport_validate_value(decoded)
    return decoded


def _transport_parse_canonical_wire(value):
    if isinstance(value, bytes):
        received = value
    elif isinstance(value, str):
        try:
            received = value.encode("utf-8")
        except UnicodeError:
            _error("response_invalid")
    else:
        _error("response_invalid")
    decoded = _transport_parse_json(received)
    if received != _transport_canonical_bytes(decoded):
        _error("response_invalid")
    return decoded


def _transport_b64encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _transport_b64decode(value, expected=None):
    if (
        not isinstance(value, str)
        or not value
        or "=" in value
        or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None
    ):
        _error("response_invalid")
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error):
        _error("response_invalid")
    if _transport_b64encode(decoded) != value:
        _error("response_invalid")
    if expected is not None and len(decoded) != expected:
        _error("response_invalid")
    return decoded


def _transport_public_jwk(key):
    public = key.public_key() if isinstance(
        key, ec.EllipticCurvePrivateKey
    ) else key
    if not isinstance(public, ec.EllipticCurvePublicKey) or not isinstance(
        public.curve, ec.SECP256R1
    ):
        _error("state_invalid")
    numbers = public.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _transport_b64encode(numbers.x.to_bytes(32, "big")),
        "y": _transport_b64encode(numbers.y.to_bytes(32, "big")),
    }


def _transport_public_key(jwk):
    if (
        not isinstance(jwk, dict)
        or set(jwk) != {"kty", "crv", "x", "y"}
        or jwk.get("kty") != "EC"
        or jwk.get("crv") != "P-256"
    ):
        _error("response_invalid")
    x = int.from_bytes(_transport_b64decode(jwk.get("x"), 32), "big")
    y = int.from_bytes(_transport_b64decode(jwk.get("y"), 32), "big")
    try:
        return ec.EllipticCurvePublicNumbers(
            x, y, ec.SECP256R1()
        ).public_key()
    except ValueError:
        _error("response_invalid")


def _transport_key_id(jwk):
    _transport_public_key(jwk)
    return hashlib.sha256(_transport_canonical_bytes(jwk)).hexdigest()


def _transport_load_private(path):
    candidate = Path(path)
    _existing_components_are_safe(candidate)
    try:
        details = os.lstat(candidate)
    except OSError:
        _error("state_invalid")
    if (
        not stat.S_ISREG(details.st_mode)
        or stat.S_IMODE(details.st_mode) & 0o077
        or details.st_size > 16 * 1024
    ):
        _error("state_invalid")
    try:
        encoded = candidate.read_bytes()
    except OSError:
        _error("state_invalid")
    if (
        not encoded.startswith(b"-----BEGIN PRIVATE KEY-----\n")
        or not encoded.endswith(b"-----END PRIVATE KEY-----\n")
        or encoded.count(b"-----BEGIN ") != 1
        or encoded.count(b"-----END ") != 1
        or b"\r" in encoded
    ):
        _error("state_invalid")
    try:
        key = serialization.load_pem_private_key(
            encoded, password=None
        )
    except (OSError, TypeError, ValueError):
        _error("state_invalid")
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        _error("state_invalid")
    return key


def _transport_load_public(path):
    candidate = Path(path)
    _existing_components_are_safe(candidate)
    if (
        candidate.is_symlink()
        or not candidate.is_file()
        or candidate.stat().st_size > 4096
    ):
        _error("state_invalid")
    try:
        value = _transport_parse_json(candidate.read_bytes())
        _transport_public_key(value)
    except RuntimeError:
        _error("state_invalid")
    return value


def _transport_write_new(path, payload, mode):
    destination = Path(path)
    parent = _private_directory(destination.parent)
    parent_descriptor = None
    descriptor = None
    try:
        parent_descriptor = os.open(parent, _directory_open_flags())
        descriptor = os.open(
            destination.name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            mode,
            dir_fd=parent_descriptor,
        )
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.chmod(
            destination.name,
            mode,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        os.fsync(parent_descriptor)
    except OSError:
        if descriptor is not None:
            os.close(descriptor)
        with contextlib.suppress(OSError):
            if parent_descriptor is not None:
                os.unlink(destination.name, dir_fd=parent_descriptor)
        _error("transition_failed")
    finally:
        if parent_descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(parent_descriptor)


def _transport_create_keypair(directory):
    parent = Path(directory)
    _private_directory(parent)
    private_path = parent / "private.pem"
    public_path = parent / "public.jwk"
    if private_path.exists() or public_path.exists():
        _error("state_invalid")
    key = ec.generate_private_key(ec.SECP256R1())
    jwk = _transport_public_jwk(key)
    private_bytes = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    try:
        _transport_write_new(private_path, private_bytes, 0o600)
        _transport_write_new(
            public_path,
            _transport_canonical_bytes(jwk) + b"\n",
            0o644,
        )
    except (Exception, SystemExit):
        with contextlib.suppress(OSError):
            private_path.unlink()
        with contextlib.suppress(OSError):
            public_path.unlink()
        raise
    return {
        "private_path": private_path,
        "public_path": public_path,
        "public_jwk": jwk,
        "key_id": _transport_key_id(jwk),
    }


def _transport_sign(value, key):
    unsigned = dict(value)
    unsigned.pop("sig", None)
    der = key.sign(
        _transport_canonical_bytes(unsigned),
        ec.ECDSA(hashes.SHA256()),
    )
    r, s = decode_dss_signature(der)
    if s > _P256_ORDER // 2:
        s = _P256_ORDER - s
    return _transport_b64encode(
        r.to_bytes(32, "big") + s.to_bytes(32, "big")
    )


def _transport_verify(value, jwk):
    if not isinstance(value, dict) or not isinstance(value.get("sig"), str):
        _error("response_invalid")
    raw = _transport_b64decode(value["sig"], 64)
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:], "big")
    if not 1 <= r < _P256_ORDER or not 1 <= s < _P256_ORDER:
        _error("response_invalid")
    if s > _P256_ORDER // 2:
        _error("response_invalid")
    unsigned = dict(value)
    unsigned.pop("sig", None)
    try:
        _transport_public_key(jwk).verify(
            encode_dss_signature(r, s),
            _transport_canonical_bytes(unsigned),
            ec.ECDSA(hashes.SHA256()),
        )
    except InvalidSignature:
        _error("response_invalid")


def _transport_parse_utc(value):
    if (
        not isinstance(value, str)
        or re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value
        )
        is None
    ):
        _error("response_invalid")
    try:
        return datetime.datetime.strptime(
            value, "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        _error("response_invalid")


def _transport_require_fresh(value, seconds=300):
    parsed = _transport_parse_utc(value)
    now = datetime.datetime.now(datetime.timezone.utc)
    if abs((now - parsed).total_seconds()) > seconds:
        _error("response_invalid")


def _transport_secure_remove(path):
    candidate = Path(path)
    _existing_components_are_safe(candidate)
    if not candidate.exists():
        return
    if candidate.is_symlink() or not candidate.is_file():
        _error("state_invalid")
    try:
        size = candidate.stat().st_size
        descriptor = os.open(
            candidate,
            os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            remaining = size
            block = b"\0" * 4096
            while remaining:
                written = os.write(descriptor, block[: min(remaining, 4096)])
                remaining -= written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        candidate.unlink()
    except OSError:
        _error("transition_failed")


def _controller_transport(root):
    directory = root / "transport"
    _private_directory(directory)
    private_path = directory / "private.pem"
    public_path = directory / "public.jwk"
    binding_path = directory / "binding.json"
    present = [
        path.exists() for path in (private_path, public_path, binding_path)
    ]
    if any(present) and not all(present):
        _error("state_invalid")
    if not any(present):
        created = _transport_create_keypair(directory)
        jwk = created["public_jwk"]
        key_id = created["key_id"]
        binding = {
            "schema": _CONTROLLER_TRANSPORT_SCHEMA,
            "controller_rappid": (
                "rappid:@kody-w/rapp-stack-cubby-controller:" + key_id
            ),
            "key_id": key_id,
            "public_jwk": jwk,
            "created_at": _utc_now(),
        }
        try:
            _atomic_json(binding_path, binding)
        except (Exception, SystemExit):
            with contextlib.suppress(OSError):
                private_path.unlink()
            with contextlib.suppress(OSError):
                public_path.unlink()
            raise
    key = _transport_load_private(private_path)
    jwk = _transport_load_public(public_path)
    binding = _read_json_file(binding_path, 16 * 1024)
    key_id = _transport_key_id(jwk)
    expected_rappid = (
        "rappid:@kody-w/rapp-stack-cubby-controller:" + key_id
    )
    if (
        _transport_public_jwk(key) != jwk
        or binding.get("schema") != _CONTROLLER_TRANSPORT_SCHEMA
        or binding.get("controller_rappid") != expected_rappid
        or binding.get("key_id") != key_id
        or binding.get("public_jwk") != jwk
    ):
        _error("state_invalid")
    os.chmod(private_path, 0o600)
    os.chmod(public_path, 0o644)
    return {
        "directory": directory,
        "private_path": private_path,
        "public_path": public_path,
        "private_key": key,
        "public_jwk": jwk,
        "key_id": key_id,
        "rappid": expected_rappid,
    }


def _twin_transport_directory(twin_directory):
    return Path(twin_directory) / "workspace" / "data" / "twin-chat"


def _create_twin_transport(target, state, controller, generation):
    directory = Path(target)
    if directory.exists():
        _error("state_invalid")
    _private_directory(directory)
    key = _transport_create_keypair(directory)
    controller_public_path = directory / "controller-public.jwk"
    _transport_write_new(
        controller_public_path,
        _transport_canonical_bytes(controller["public_jwk"]) + b"\n",
        0o644,
    )
    pairing = {
        "schema": _PAIRING_SCHEMA,
        "twin_rappid": state["rappid"],
        "controller_rappid": controller["rappid"],
        "controller_key_id": controller["key_id"],
        "controller_public_jwk": controller["public_jwk"],
        "child_key_id": key["key_id"],
        "child_public_jwk": key["public_jwk"],
        "generation": generation,
        "key_epoch": generation,
        "paired_at": _utc_now(),
    }
    _atomic_json(directory / "pairing.json", pairing)
    os.chmod(key["private_path"], 0o600)
    os.chmod(key["public_path"], 0o644)
    os.chmod(controller_public_path, 0o644)
    return pairing


def _validate_twin_transport(directory, state, controller):
    target = Path(directory)
    if target.is_symlink() or not target.is_dir():
        _error("state_invalid")
    pairing = _read_json_file(target / "pairing.json", 32 * 1024)
    private_key = _transport_load_private(target / "private.pem")
    child_public = _transport_load_public(target / "public.jwk")
    controller_public = _transport_load_public(
        target / "controller-public.jwk"
    )
    if (
        set(pairing) != _TRANSPORT_PAIRING_KEYS
        or pairing.get("schema") != _PAIRING_SCHEMA
        or pairing.get("twin_rappid") != state["rappid"]
        or pairing.get("controller_rappid") != controller["rappid"]
        or pairing.get("controller_key_id") != controller["key_id"]
        or pairing.get("controller_public_jwk") != controller["public_jwk"]
        or pairing.get("child_key_id")
        != _transport_key_id(child_public)
        or pairing.get("child_public_jwk") != child_public
        or _transport_public_jwk(private_key) != child_public
        or controller_public != controller["public_jwk"]
        or not isinstance(pairing.get("generation"), int)
        or isinstance(pairing.get("generation"), bool)
        or pairing["generation"] < 1
        or pairing.get("key_epoch") != pairing["generation"]
    ):
        _error("state_invalid")
    os.chmod(target / "private.pem", 0o600)
    os.chmod(target / "public.jwk", 0o644)
    os.chmod(target / "controller-public.jwk", 0o644)
    return pairing


def _transport_state(pairing):
    return {
        "profile": "rapp-twin-chat/1.0",
        "child_key_id": pairing["child_key_id"],
        "controller_key_id": pairing["controller_key_id"],
        "controller_rappid": pairing["controller_rappid"],
        "generation": pairing["generation"],
        "key_epoch": pairing["key_epoch"],
    }


def _ensure_twin_transport(root, twin_directory, state):
    controller = _controller_transport(root)
    directory = _twin_transport_directory(twin_directory)
    if not directory.exists():
        generation = 1
        stored = state.get("transport")
        if isinstance(stored, dict) and isinstance(
            stored.get("generation"), int
        ):
            generation = max(1, stored["generation"])
        pairing = _create_twin_transport(
            directory, state, controller, generation
        )
    else:
        pairing = _validate_twin_transport(
            directory, state, controller
        )
    controller_pairing_path = Path(twin_directory) / "pairing.json"
    if controller_pairing_path.exists():
        controller_pairing = _read_json_file(
            controller_pairing_path, 32 * 1024
        )
        if controller_pairing != pairing:
            _error("state_invalid")
    else:
        _atomic_json(controller_pairing_path, pairing)
    return controller, pairing


def _transport_build_request(
    controller,
    pairing,
    state,
    message,
    session_id,
    facet,
):
    timestamp = _utc_now()
    payload = {"user_input": message}
    if session_id is not None:
        payload["session_id"] = session_id
    inner = {
        "schema": _TWIN_REQUEST_SCHEMA,
        "from_rappid": controller["rappid"],
        "to_rappid": state["rappid"],
        "utc": timestamp,
        "nonce": _transport_b64encode(secrets.token_bytes(24)),
        "key_epoch": pairing["key_epoch"],
        "kind": _TWIN_CHAT_KIND,
        "payload": payload,
        "facets": [facet],
    }
    wrapper = {
        "schema": _COMMONS_SCHEMA,
        "from": controller["rappid"],
        "pub": controller["public_jwk"],
        "alg": _TRANSPORT_ALGORITHM,
        "ts": timestamp,
        "kind": _TWIN_CHAT_KIND,
        "body": inner,
        "key_id": controller["key_id"],
    }
    wrapper["sig"] = _transport_sign(wrapper, controller["private_key"])
    digest = hashlib.sha256(
        _transport_canonical_bytes(inner)
    ).hexdigest()
    return wrapper, inner["nonce"], digest


def _transport_verify_response(
    value,
    controller,
    pairing,
    state,
    nonce,
    digest,
    *,
    enforce_freshness=True,
):
    response = _transport_parse_canonical_wire(value)
    if (
        not isinstance(response, dict)
        or set(response) != _TRANSPORT_RESPONSE_KEYS
        or response.get("schema") != _TWIN_RESPONSE_SCHEMA
        or response.get("from_rappid") != state["rappid"]
        or response.get("to_rappid") != controller["rappid"]
        or response.get("request_nonce") != nonce
        or response.get("request_digest") != digest
        or response.get("key_epoch") != pairing["key_epoch"]
        or response.get("key_id") != pairing["child_key_id"]
        or response.get("status") not in {"ok", "rejected"}
    ):
        _error("response_invalid")
    if enforce_freshness:
        _transport_require_fresh(response.get("utc"))
    _transport_verify(response, pairing["child_public_jwk"])
    payload = response.get("payload")
    if response["status"] == "rejected":
        error = payload.get("error") if isinstance(payload, dict) else None
        if (
            not isinstance(payload, dict)
            or set(payload) != {"error"}
            or not isinstance(error, dict)
            or set(error) != {"code", "message"}
            or not isinstance(error.get("code"), str)
            or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", error["code"])
            is None
            or not isinstance(error.get("message"), str)
            or not 1 <= len(error["message"].encode("utf-8")) <= 240
        ):
            _error("response_invalid")
        return "rejected", payload
    if (
        not isinstance(payload, dict)
        or set(payload)
        != {
            "response",
            "session_id",
            "agent_logs",
            "voice_mode",
            "model",
            "requested_model",
        }
        or not isinstance(payload.get("response"), str)
        or not isinstance(payload.get("session_id"), str)
        or re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}",
            payload["session_id"],
        )
        is None
        or not isinstance(payload.get("agent_logs"), str)
        or not isinstance(payload.get("voice_mode"), bool)
        or not isinstance(payload.get("model"), str)
        or not isinstance(payload.get("requested_model"), str)
        or not 1 <= len(payload["model"]) <= 128
        or not 1 <= len(payload["requested_model"]) <= 128
        or any(ord(character) < 32 for character in payload["model"])
        or any(
            ord(character) < 32
            for character in payload["requested_model"]
        )
    ):
        _error("response_invalid")
    return "ok", payload


def _error(code):
    raise RuntimeError(code)


def _response(action, *, ok=True, **values):
    payload = {
        "agent": "RappStackCubbyController",
        "action": action,
        "ok": ok,
    }
    payload.update(values)
    return _json(payload)


def validate_repository_url(value):
    if not isinstance(value, str) or not value:
        _error("repository_invalid")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError):
        _error("repository_invalid")
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.hostname.lower() != "github.com"
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path.rstrip("/") not in _ALLOWED_REPOSITORY_PATHS
        or parsed.netloc.lower() != "github.com"
    ):
        _error("repository_invalid")
    return _ALLOWED_REPOSITORY


def validate_commit(value):
    if not isinstance(value, str) or not _COMMIT_RE.fullmatch(value):
        _error("commit_invalid")
    return value


def parse_rappid(value):
    if not isinstance(value, str):
        _error("identity_invalid")
    match = _RAPPID_RE.fullmatch(value)
    if match is None:
        _error("identity_invalid")
    return {
        "rappid": value,
        "owner": match.group("owner"),
        "slug": match.group("slug"),
        "identity_hash": match.group("digest"),
    }


def workspace_key(value):
    return parse_rappid(value)["identity_hash"]


def _validate_relative_source_path(value):
    if not isinstance(value, str) or not value or "\x00" in value:
        _error("source_invalid")
    path = Path(value)
    if (
        path.is_absolute()
        or ".." in path.parts
        or "." in path.parts
        or value.startswith("/")
        or "\\" in value
        or path.as_posix() != value
    ):
        _error("source_invalid")
    if len(value.encode("utf-8")) > 1024:
        _error("source_invalid")
    return path


def _forbidden_source_path(relative):
    parts = relative.parts
    if not parts:
        return True
    if parts[0] in _FORBIDDEN_TOP_LEVEL or parts[0] in _REJECTED_SOURCE_TOP_LEVEL:
        return True
    for component in parts:
        if component in _FORBIDDEN_COMPONENTS:
            return True
        if component.casefold().endswith(".egg-info"):
            return True
        if component in _FORBIDDEN_FILE_NAMES:
            return True
        lowered = component.lower()
        if lowered in {name.lower() for name in _FORBIDDEN_FILE_NAMES}:
            return True
    name = parts[-1].lower()
    return any(name.endswith(suffix) for suffix in _FORBIDDEN_SUFFIXES)


def _skipped_source_path(relative):
    parts = relative.parts
    if not parts:
        return False
    return any(part in _SOURCE_SKIPPED_COMPONENTS for part in parts)


def _tree_digest(records):
    payload = {
        "schema": "rapp-source-tree/1.0",
        "files": records,
    }
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def scan_source_tree(root, *, excluded_paths=()):
    base = Path(root)
    if base.is_symlink() or not base.is_dir():
        _error("source_invalid")
    try:
        base = base.resolve(strict=True)
    except OSError:
        _error("source_invalid")
    excluded = frozenset(str(item) for item in excluded_paths)
    records = []
    total_bytes = 0
    visited = 0

    def walk(directory, relative_prefix):
        nonlocal total_bytes, visited
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError:
            _error("source_invalid")
        for entry in entries:
            relative = (
                Path(entry.name)
                if relative_prefix is None
                else relative_prefix / entry.name
            )
            text = relative.as_posix()
            _validate_relative_source_path(text)
            if _forbidden_source_path(relative):
                _error("source_invalid")
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError:
                _error("source_invalid")
            if stat.S_ISLNK(info.st_mode):
                _error("source_invalid")
            if _skipped_source_path(relative):
                if not stat.S_ISDIR(info.st_mode):
                    _error("source_invalid")
                continue
            if stat.S_ISDIR(info.st_mode):
                walk(Path(entry.path), relative)
                continue
            if not stat.S_ISREG(info.st_mode):
                _error("source_invalid")
            if text in excluded:
                continue
            visited += 1
            total_bytes += info.st_size
            if (
                visited > _MAX_SOURCE_FILES
                or total_bytes > _MAX_SOURCE_BYTES
                or info.st_size > _MAX_SOURCE_FILE_BYTES
            ):
                _error("source_invalid")
            digest = hashlib.sha256()
            try:
                digest.update(
                    _read_regular_file(
                        Path(entry.path),
                        _MAX_SOURCE_FILE_BYTES,
                        "source_invalid",
                    )
                )
            except RuntimeError:
                _error("source_invalid")
            records.append(
                {
                    "executable": bool(info.st_mode & 0o111),
                    "mode": (
                        "0755" if bool(info.st_mode & 0o111) else "0644"
                    ),
                    "path": text,
                    "sha256": digest.hexdigest(),
                    "size": info.st_size,
                }
            )

    walk(base, None)
    records.sort(key=lambda item: item["path"])
    return {
        "schema": "rapp-source-tree/1.0",
        "file_count": len(records),
        "scanned_file_count": visited,
        "total_bytes": total_bytes,
        "files": records,
        "tree_digest": _tree_digest(records),
    }


def deterministic_tree_digest(root):
    return scan_source_tree(root)["tree_digest"]


def validate_release_source_manifest(root, repository_url, commit):
    repository_url = validate_repository_url(repository_url)
    validate_commit(commit)
    source = Path(root)
    manifest_path = source / _RELEASE_MANIFEST_NAME
    manifest = _read_json_file(manifest_path, _MAX_JSON_BYTES)
    if (
        set(manifest)
        != {
            "exclusions",
            "file_count",
            "files",
            "repository_url",
            "schema",
            "source_tree_digest",
            "total_bytes",
        }
        or "commit" in manifest
        or "source_commit" in manifest
        or
        manifest.get("schema") != _RELEASE_MANIFEST_SCHEMA
        or manifest.get("exclusions")
        != {
            "generated_release_assets": True,
            "manifest_self": _RELEASE_MANIFEST_NAME,
            "private_and_runtime_state": True,
            "repository_metadata_and_caches": True,
        }
        or validate_repository_url(manifest.get("repository_url"))
        != repository_url
    ):
        _error("manifest_invalid")
    declared = manifest.get("files")
    if not isinstance(declared, list):
        _error("manifest_invalid")
    normalized = []
    seen = set()
    for item in declared:
        if not isinstance(item, dict):
            _error("manifest_invalid")
        relative = _validate_relative_source_path(item.get("path"))
        text = relative.as_posix()
        digest = item.get("sha256")
        if text == _RELEASE_MANIFEST_NAME or text in seen:
            _error("manifest_invalid")
        if not isinstance(digest, str) or not _HEX_64_RE.fullmatch(digest):
            _error("manifest_invalid")
        size = item.get("size")
        executable = item.get("executable", False)
        mode = item.get("mode")
        if (
            set(item)
            != {"executable", "mode", "path", "sha256", "size"}
            or
            not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or not isinstance(executable, bool)
            or mode not in {"0644", "0755"}
            or executable != (mode == "0755")
        ):
            _error("manifest_invalid")
        seen.add(text)
        normalized.append(
            {
                "executable": executable,
                "mode": mode,
                "path": text,
                "sha256": digest,
                "size": size,
            }
        )
    if normalized != sorted(normalized, key=lambda item: item["path"]):
        _error("manifest_invalid")
    actual = scan_source_tree(
        source, excluded_paths=(_RELEASE_MANIFEST_NAME,)
    )
    if normalized != actual["files"]:
        _error("manifest_invalid")
    if manifest.get("source_tree_digest") != actual["tree_digest"]:
        _error("manifest_invalid")
    if manifest.get("file_count") != len(normalized):
        _error("manifest_invalid")
    if manifest.get("total_bytes") != actual["total_bytes"]:
        _error("manifest_invalid")
    return {
        "files": normalized,
        "profile": "release",
        "release_manifest_sha256": _sha256_file(manifest_path),
        "source_tree_digest": actual["tree_digest"],
        "source_file_count": actual["file_count"],
        "source_total_bytes": actual["total_bytes"],
    }


def _read_json_file(path, maximum):
    candidate = Path(path)
    raw = _read_regular_file(candidate, maximum, "state_invalid")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        _error("state_invalid")
    if not isinstance(value, dict):
        _error("state_invalid")
    return value


def _read_regular_file(path, maximum, error_code):
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = candidate.absolute()
    _existing_components_are_safe(candidate)
    parent_descriptor = _open_absolute_directory(candidate.parent)
    descriptor = None
    try:
        descriptor = os.open(
            candidate.name,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_descriptor,
        )
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_size < 0
            or details.st_size > maximum
        ):
            _error(error_code)
        chunks = []
        remaining = details.st_size
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                _error(error_code)
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            _error(error_code)
        return b"".join(chunks)
    except OSError:
        _error(error_code)
    finally:
        if descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        with contextlib.suppress(OSError):
            os.close(parent_descriptor)


def _sha256_file(path):
    candidate = Path(path)
    return hashlib.sha256(
        _read_regular_file(candidate, _MAX_SOURCE_FILE_BYTES, "source_invalid")
    ).hexdigest()


def _loaded_source_sha256():
    candidate = Path(__file__)
    if (
        not candidate.is_absolute()
        or candidate.is_symlink()
        or not candidate.is_file()
    ):
        return None
    try:
        return _sha256_file(candidate)
    except RuntimeError:
        return None


def _directory_open_flags():
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _open_absolute_directory(path, *, create=False, mode=0o700):
    candidate = Path(path)
    if not candidate.is_absolute() or ".." in candidate.parts:
        _error("controller_root_invalid")
    descriptor = None
    try:
        descriptor = os.open(candidate.anchor, _directory_open_flags())
        for part in candidate.parts[1:]:
            try:
                child = os.open(
                    part,
                    _directory_open_flags(),
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, mode=mode, dir_fd=descriptor)
                child = os.open(
                    part,
                    _directory_open_flags(),
                    dir_fd=descriptor,
                )
                os.fchmod(child, mode)
                os.fsync(descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except OSError:
        if descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        _error("controller_root_invalid")


def _existing_components_are_safe(path):
    candidate = Path(path)
    if not candidate.is_absolute() or ".." in candidate.parts:
        _error("controller_root_invalid")
    current = Path(candidate.anchor)
    for index, part in enumerate(candidate.parts[1:]):
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            if any(
                (current / suffix).exists()
                for suffix in candidate.parts[index + 2 :]
            ):
                _error("controller_root_invalid")
            return
        except OSError:
            _error("controller_root_invalid")
        if stat.S_ISLNK(info.st_mode) or (
            index < len(candidate.parts[1:]) - 1
            and not stat.S_ISDIR(info.st_mode)
        ):
            _error("controller_root_invalid")


def _relative_to_root(root, path):
    trusted = Path(root)
    candidate = Path(path)
    try:
        relative = candidate.relative_to(trusted)
    except ValueError:
        _error("controller_root_invalid")
    if not relative.parts or any(
        part in {"", ".", ".."} for part in relative.parts
    ):
        _error("controller_root_invalid")
    return relative


def _validate_beneath(
    root,
    path,
    *,
    allow_missing=False,
    expected=None,
):
    relative = _relative_to_root(root, path)
    descriptor = _open_absolute_directory(root)
    try:
        for index, part in enumerate(relative.parts):
            final = index == len(relative.parts) - 1
            if final and expected != "directory":
                try:
                    details = os.stat(
                        part,
                        dir_fd=descriptor,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    if allow_missing:
                        return
                    _error("state_invalid")
                if stat.S_ISLNK(details.st_mode):
                    _error("state_invalid")
                if expected == "file" and not stat.S_ISREG(details.st_mode):
                    _error("state_invalid")
                return
            try:
                child = os.open(
                    part,
                    _directory_open_flags(),
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                if allow_missing:
                    return
                _error("state_invalid")
            except OSError:
                _error("state_invalid")
            os.close(descriptor)
            descriptor = child
        if expected == "directory":
            details = os.fstat(descriptor)
            if not stat.S_ISDIR(details.st_mode):
                _error("state_invalid")
    finally:
        with contextlib.suppress(OSError):
            os.close(descriptor)


def _controller_path_root(path):
    raw = os.environ.get("RAPP_STACK_CONTROLLER_DATA_DIR")
    if not raw:
        return None
    configured = Path(raw)
    candidate = Path(path)
    try:
        candidate.relative_to(configured)
    except ValueError:
        return None
    return configured


def _controller_root(*, create=False, required=True):
    raw = os.environ.get("RAPP_STACK_CONTROLLER_DATA_DIR")
    if not raw:
        if required:
            _error("controller_root_invalid")
        return None
    candidate = Path(raw)
    if (
        not candidate.is_absolute()
        or ".." in candidate.parts
        or candidate == Path(candidate.anchor)
    ):
        _error("controller_root_invalid")
    _existing_components_are_safe(candidate)
    descriptor = None
    if create:
        descriptor = _open_absolute_directory(candidate, create=True)
    try:
        root = candidate.resolve(strict=True)
        if descriptor is None:
            descriptor = _open_absolute_directory(root)
        info = os.fstat(descriptor)
    except OSError:
        if not required:
            return None
        _error("controller_root_invalid")
    finally:
        if descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(descriptor)
    if not stat.S_ISDIR(info.st_mode) or root.is_symlink():
        _error("controller_root_invalid")
    mode = stat.S_IMODE(info.st_mode)
    if create:
        try:
            os.chmod(root, 0o700)
        except OSError:
            _error("controller_root_invalid")
    elif mode & 0o077:
        _error("controller_root_invalid")
    return root


def _private_directory(path):
    candidate = Path(path)
    _existing_components_are_safe(candidate)
    descriptor = _open_absolute_directory(candidate, create=True)
    try:
        os.fchmod(descriptor, 0o700)
    except OSError:
        os.close(descriptor)
        _error("controller_root_invalid")
    os.close(descriptor)
    _existing_components_are_safe(candidate)
    if candidate.is_symlink() or not candidate.is_dir():
        _error("controller_root_invalid")
    root = _controller_path_root(candidate)
    if root is not None and candidate != root:
        _validate_beneath(root.resolve(strict=True), candidate, expected="directory")
    return candidate


def _initialize_layout():
    root = _controller_root(create=True)
    for relative in (
        "twins",
        "twins/active",
        "twins/archive",
        "twins/purged",
        "staging",
        "locks",
        "receipts",
        "receipts/idempotency",
        "sessions",
        "loadout",
        "transport",
        "transactions",
    ):
        _private_directory(root / relative)
    _controller_transport(root)
    return root


def _atomic_json(path, value):
    destination = Path(path)
    parent = _private_directory(destination.parent)
    if destination.parent != parent or destination.name in {"", ".", ".."}:
        _error("controller_root_invalid")
    root = _controller_path_root(destination)
    if root is not None:
        trusted = root.resolve(strict=True)
        _validate_beneath(trusted, parent, expected="directory")
        _validate_beneath(
            trusted, destination, allow_missing=True, expected="file"
        )
    payload = (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")
    if len(payload) > _MAX_JSON_BYTES:
        _error("state_invalid")
    temporary_name = "." + destination.name + ".tmp-" + uuid.uuid4().hex
    descriptor = None
    parent_descriptor = None
    try:
        parent_descriptor = os.open(parent, _directory_open_flags())
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=parent_descriptor,
        )
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.rename(
            temporary_name,
            destination.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        os.chmod(
            destination.name,
            0o600,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        os.fsync(parent_descriptor)
    except OSError:
        if descriptor is not None:
            os.close(descriptor)
        with contextlib.suppress(OSError):
            if parent_descriptor is not None:
                os.unlink(temporary_name, dir_fd=parent_descriptor)
        _error("transition_failed")
    finally:
        if parent_descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(parent_descriptor)


def _safe_exists(root, path, *, expected=None):
    candidate = Path(path)
    relative = _relative_to_root(root, candidate)
    descriptor = _open_absolute_directory(root)
    try:
        for part in relative.parts[:-1]:
            try:
                child = os.open(
                    part, _directory_open_flags(), dir_fd=descriptor
                )
            except FileNotFoundError:
                return False
            except OSError:
                _error("state_invalid")
            os.close(descriptor)
            descriptor = child
        try:
            details = os.stat(
                relative.parts[-1],
                dir_fd=descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return False
        if stat.S_ISLNK(details.st_mode):
            _error("state_invalid")
        if expected == "directory" and not stat.S_ISDIR(details.st_mode):
            _error("state_invalid")
        if expected == "file" and not stat.S_ISREG(details.st_mode):
            _error("state_invalid")
        return True
    finally:
        with contextlib.suppress(OSError):
            os.close(descriptor)


def _safe_replace(root, source, destination):
    trusted = Path(root)
    source_path = Path(source)
    destination_path = Path(destination)
    _validate_beneath(trusted, source_path)
    _validate_beneath(
        trusted, destination_path, allow_missing=True
    )
    source_relative = _relative_to_root(trusted, source_path)
    destination_relative = _relative_to_root(trusted, destination_path)
    source_parent = _open_absolute_directory(source_path.parent)
    destination_parent = _open_absolute_directory(destination_path.parent)
    try:
        os.rename(
            source_relative.name,
            destination_relative.name,
            src_dir_fd=source_parent,
            dst_dir_fd=destination_parent,
        )
        os.fsync(source_parent)
        if destination_parent != source_parent:
            os.fsync(destination_parent)
    except OSError:
        _error("transition_failed")
    finally:
        os.close(source_parent)
        os.close(destination_parent)


def _scan_tree_descriptor(descriptor):
    try:
        entries = sorted(os.scandir(descriptor), key=lambda item: item.name)
    except OSError:
        _error("state_invalid")
    for entry in entries:
        try:
            details = entry.stat(follow_symlinks=False)
        except OSError:
            _error("state_invalid")
        if stat.S_ISLNK(details.st_mode):
            _error("state_invalid")
        if stat.S_ISDIR(details.st_mode):
            try:
                child = os.open(
                    entry.name,
                    _directory_open_flags(),
                    dir_fd=descriptor,
                )
            except OSError:
                _error("state_invalid")
            try:
                _scan_tree_descriptor(child)
            finally:
                os.close(child)
        elif not stat.S_ISREG(details.st_mode):
            _error("state_invalid")


def _delete_tree_descriptor(descriptor):
    entries = sorted(os.scandir(descriptor), key=lambda item: item.name)
    for entry in entries:
        details = entry.stat(follow_symlinks=False)
        if stat.S_ISDIR(details.st_mode):
            child = os.open(
                entry.name,
                _directory_open_flags(),
                dir_fd=descriptor,
            )
            try:
                _delete_tree_descriptor(child)
            finally:
                os.close(child)
            os.rmdir(entry.name, dir_fd=descriptor)
        elif stat.S_ISREG(details.st_mode):
            os.unlink(entry.name, dir_fd=descriptor)
        else:
            _error("state_invalid")
    os.fsync(descriptor)


def _safe_remove_tree(root, path):
    trusted = Path(root)
    candidate = Path(path)
    if not _safe_exists(trusted, candidate):
        return
    _validate_beneath(trusted, candidate, expected="directory")
    parent_descriptor = _open_absolute_directory(candidate.parent)
    descriptor = None
    try:
        descriptor = os.open(
            candidate.name,
            _directory_open_flags(),
            dir_fd=parent_descriptor,
        )
        _scan_tree_descriptor(descriptor)
        _delete_tree_descriptor(descriptor)
        os.close(descriptor)
        descriptor = None
        os.rmdir(candidate.name, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    except OSError:
        _error("transition_failed")
    finally:
        if descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        with contextlib.suppress(OSError):
            os.close(parent_descriptor)


def _thread_lock(path):
    key = os.path.normcase(str(path))
    with _THREAD_LOCK_GUARD:
        lock = _THREAD_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _THREAD_LOCKS[key] = lock
        return lock


@contextlib.contextmanager
def _controller_locks(root, identity_hash=None, *, include_controller=True):
    names = ["controller.lock"] if include_controller else []
    if identity_hash is not None:
        if not _HEX_64_RE.fullmatch(identity_hash):
            _error("identity_invalid")
        names.append(identity_hash + ".lock")
    acquired = []
    descriptors = []
    try:
        for name in names:
            path = root / "locks" / name
            _validate_beneath(root, path.parent, expected="directory")
            _validate_beneath(
                root, path, allow_missing=True, expected="file"
            )
            lock = _thread_lock(path)
            if not lock.acquire(blocking=False):
                _error("busy")
            acquired.append(lock)
            descriptor = None
            parent_descriptor = None
            try:
                parent_descriptor = os.open(
                    path.parent, _directory_open_flags()
                )
                descriptor = os.open(
                    path.name,
                    os.O_RDWR
                    | os.O_CREAT
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                    dir_fd=parent_descriptor,
                )
                os.fchmod(descriptor, 0o600)
                fcntl.flock(
                    descriptor,
                    fcntl.LOCK_EX | fcntl.LOCK_NB,
                )
            except (BlockingIOError, OSError):
                if descriptor is not None:
                    with contextlib.suppress(OSError):
                        os.close(descriptor)
                _error("busy")
            finally:
                if parent_descriptor is not None:
                    with contextlib.suppress(OSError):
                        os.close(parent_descriptor)
            descriptors.append(descriptor)
        yield
    finally:
        for descriptor in reversed(descriptors):
            with contextlib.suppress(OSError):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
        for lock in reversed(acquired):
            if lock.locked():
                lock.release()


def _mutation_root(action):
    if action not in _MUTATING_ACTIONS:
        return _controller_root(required=False)
    if os.environ.get("RAPP_STACK_ALLOW_CONTROLLER_MUTATIONS") != "1":
        _error("mutation_disabled")
    return _initialize_layout()


def _idempotency_key(kwargs):
    value = kwargs.get("idempotency_key")
    if not isinstance(value, str) or not _IDEMPOTENCY_RE.fullmatch(value):
        _error("idempotency_key_required")
    return value


def _request_digest(action, kwargs):
    sanitized = {}
    for key in sorted(kwargs):
        if key == "idempotency_key":
            continue
        value = kwargs[key]
        try:
            _canonical_bytes(value)
        except (TypeError, ValueError):
            _error("idempotency_conflict")
        sanitized[key] = value
    return hashlib.sha256(
        _canonical_bytes({"action": action, "arguments": sanitized})
    ).hexdigest()


def _idempotency_path(root, key):
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return root / "receipts" / "idempotency" / (digest + ".json")


def _transaction_path(root, key):
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return root / "transactions" / (digest + ".json")


def _utc_after(seconds):
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        + datetime.timedelta(seconds=seconds)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


def _lease_owner():
    return {
        "owner_pid": os.getpid(),
        "owner_start_identity": _process_start_identity(os.getpid()),
        "lease_expires_at": _utc_after(_TRANSACTION_LEASE_SECONDS),
    }


def _owner_lease_active(record):
    pid = record.get("owner_pid")
    start_identity = record.get("owner_start_identity")
    expires = record.get("lease_expires_at")
    if (
        not isinstance(pid, int)
        or isinstance(pid, bool)
        or not isinstance(start_identity, str)
        or not isinstance(expires, str)
    ):
        return False
    try:
        expiry = _transport_parse_utc(expires)
    except RuntimeError:
        return False
    if expiry <= datetime.datetime.now(datetime.timezone.utc):
        return False
    return (
        _pid_alive(pid)
        and _process_start_identity(pid) == start_identity
    )


def _idempotency_begin(root, key, action, request_digest):
    path = _idempotency_path(root, key)
    if _safe_exists(root, path, expected="file"):
        record = _read_json_file(path, _MAX_JSON_BYTES)
        if (
            record.get("action") != action
            or record.get("request_digest") != request_digest
        ):
            _error("idempotency_conflict")
        if record.get("status") == "completed":
            result = record.get("result")
            if not isinstance(result, dict):
                _error("state_invalid")
            replay = dict(result)
            replay["idempotent_replay"] = True
            return replay
        if (
            record.get("status") == "in_progress"
            and _owner_lease_active(record)
            and record.get("owner_pid") != os.getpid()
        ):
            _error("busy")
    record = {
        "schema": "rapp-controller-idempotency/1.0",
        "action": action,
        "request_digest": request_digest,
        "status": "in_progress",
        "started_at": _utc_now(),
        **_lease_owner(),
    }
    _atomic_json(path, record)
    return None


def _idempotency_complete(root, key, action, request_digest, result):
    _atomic_json(
        _idempotency_path(root, key),
        {
            "schema": "rapp-controller-idempotency/1.0",
            "action": action,
            "request_digest": request_digest,
            "status": "completed",
            "completed_at": _utc_now(),
            "result": result,
            **_lease_owner(),
        },
    )


def _idempotency_failed(root, key, action, request_digest, code):
    with contextlib.suppress(Exception):
        _atomic_json(
            _idempotency_path(root, key),
            {
                "schema": "rapp-controller-idempotency/1.0",
                "action": action,
                "request_digest": request_digest,
                "status": "failed",
                "failed_at": _utc_now(),
                "error_code": (
                    code if code in _ERROR_MESSAGES else "transition_failed"
                ),
                **_lease_owner(),
            },
        )


def _transaction_load(root, key, action, request_digest):
    path = _transaction_path(root, key)
    if not _safe_exists(root, path, expected="file"):
        return None
    record = _read_json_file(path, _MAX_JSON_BYTES)
    if (
        record.get("schema") != _JOURNAL_SCHEMA
        or record.get("action") != action
        or record.get("request_digest") != request_digest
        or not isinstance(record.get("phase"), str)
    ):
        _error("state_invalid")
    return record


def _transition_boundary(action, phase):
    del action, phase


def _transition_phase(
    root,
    key,
    action,
    request_digest,
    identity_hash,
    phase,
    **values,
):
    previous = _transaction_load(root, key, action, request_digest)
    payload = {
        "schema": _JOURNAL_SCHEMA,
        "action": action,
        "identity_hash": identity_hash,
        "idempotency_key_sha256": hashlib.sha256(
            key.encode("utf-8")
        ).hexdigest(),
        "request_digest": request_digest,
        "status": (
            "completed" if phase == "completed" else "in_progress"
        ),
        "phase": phase,
        "started_at": (
            previous.get("started_at")
            if isinstance(previous, dict)
            else _utc_now()
        ),
        "updated_at": _utc_now(),
        **_lease_owner(),
    }
    if isinstance(previous, dict):
        for name, value in previous.items():
            if name not in payload and name not in {
                "phase",
                "status",
                "updated_at",
                "lease_expires_at",
                "owner_pid",
                "owner_start_identity",
            }:
                payload[name] = value
    payload.update(values)
    _atomic_json(_transaction_path(root, key), payload)
    _journal(
        root,
        action,
        identity_hash,
        payload["status"],
        phase=phase,
        idempotency_key_sha256=payload["idempotency_key_sha256"],
        request_digest=request_digest,
    )
    _transition_boundary(action, phase)
    return payload


def _completed_transaction_replay(
    root, key, action, request_digest
):
    transaction = _transaction_load(root, key, action, request_digest)
    if (
        isinstance(transaction, dict)
        and transaction.get("phase") == "completed"
        and isinstance(transaction.get("result"), dict)
    ):
        result = dict(transaction["result"])
        _idempotency_complete(
            root, key, action, request_digest, result
        )
        result["idempotent_replay"] = True
        return result
    return None


def _journal(root, action, identity_hash, status, **values):
    name = (
        identity_hash
        if isinstance(identity_hash, str) and _HEX_64_RE.fullmatch(identity_hash)
        else "controller"
    )
    payload = {
        "schema": _JOURNAL_SCHEMA,
        "action": action,
        "identity_hash": identity_hash,
        "status": status,
        "phase": values.pop("phase", status),
        "updated_at": _utc_now(),
        **_lease_owner(),
    }
    payload.update(values)
    _atomic_json(root / "locks" / (name + ".journal.json"), payload)


def _git_environment():
    return {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_PROTOCOL_FROM_USER": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def _run_git(arguments):
    argv = [
        _GIT_EXECUTABLE,
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.https.allow=always",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "submodule.recurse=false",
        *arguments,
    ]
    try:
        result = subprocess.run(
            argv,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_git_environment(),
            timeout=_GIT_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        _error("source_invalid")
    if result.returncode != 0:
        _error("source_invalid")
    return result.stdout


def _checkout_exact(destination, repository_url, commit):
    repository_url = validate_repository_url(repository_url)
    commit = validate_commit(commit)
    checkout = Path(destination)
    root = _controller_root(required=True)
    staging = root / "staging"
    try:
        resolved_parent = checkout.parent.resolve(strict=True)
        resolved_staging = staging.resolve(strict=True)
    except OSError:
        _error("source_invalid")
    if resolved_staging not in resolved_parent.parents:
        _error("source_invalid")
    if checkout.exists():
        _error("source_invalid")
    _private_directory(checkout)
    _run_git(["init", "--quiet", str(checkout)])
    _run_git(
        [
            "-C",
            str(checkout),
            "remote",
            "add",
            "origin",
            repository_url,
        ]
    )
    _run_git(
        [
            "-C",
            str(checkout),
            "fetch",
            "--quiet",
            "--no-tags",
            "--depth=1",
            "origin",
            commit,
        ]
    )
    _run_git(
        [
            "-C",
            str(checkout),
            "checkout",
            "--quiet",
            "--detach",
            "FETCH_HEAD",
        ]
    )
    raw_head = _run_git(
        [
            "-C",
            str(checkout),
            "rev-parse",
            "--verify",
            "HEAD^{commit}",
        ]
    )
    try:
        head = raw_head.decode("ascii").strip()
    except UnicodeError:
        _error("source_invalid")
    if head != commit:
        _error("source_mismatch")
    git_metadata = checkout / ".git"
    if git_metadata.is_symlink() or not git_metadata.is_dir():
        _error("source_invalid")
    try:
        shutil.rmtree(git_metadata)
    except OSError:
        _error("source_invalid")


def _source_profile(checkout, repository_url, commit, expected_digest):
    manifest = checkout / _RELEASE_MANIFEST_NAME
    if manifest.exists():
        return validate_release_source_manifest(
            checkout, repository_url, commit
        )
    if os.environ.get("RAPP_STACK_ALLOW_DEVELOPMENT_HATCH") != "1":
        _error("development_hatch_disabled")
    if (
        not isinstance(expected_digest, str)
        or not _HEX_64_RE.fullmatch(expected_digest)
    ):
        _error("development_digest_required")
    scanned = scan_source_tree(checkout)
    for item in scanned["files"]:
        if item["executable"] and item["path"] not in _DEVELOPMENT_EXECUTABLES:
            _error("source_invalid")
    if scanned["tree_digest"] != expected_digest:
        _error("source_mismatch")
    return {
        "files": scanned["files"],
        "profile": "development_non_release",
        "release_manifest_sha256": None,
        "source_tree_digest": scanned["tree_digest"],
        "source_file_count": scanned["file_count"],
        "source_total_bytes": scanned["total_bytes"],
    }


def _product_identity_from_source(checkout, profile, kwargs):
    candidates = [
        checkout / "rappid.json",
        checkout / "cubbies" / "kody-w" / "rappid.json",
        checkout
        / "cubbies"
        / "kody-w"
        / "rapplications"
        / "rapp-stack"
        / "rappid.json",
    ]
    present = [path for path in candidates if path.exists()]
    if len(present) > 1:
        _error("identity_invalid")
    if present:
        data = _read_json_file(present[0], 64 * 1024)
        return parse_rappid(data.get("rappid"))
    if profile != "development_non_release":
        _error("identity_invalid")
    fixture = kwargs.get("birth_fixture")
    direct = kwargs.get("rappid", kwargs.get("development_rappid"))
    if fixture is not None:
        if (
            not isinstance(fixture, dict)
            or fixture.get("schema")
            != "rapp-development-birth-fixture/1.0"
            or set(fixture) != {"schema", "rappid"}
        ):
            _error("identity_invalid")
        direct = fixture.get("rappid")
    return parse_rappid(direct)


def _mint_instance_identity(product_identity, source_revision, source_digest):
    nonce = secrets.token_bytes(32)
    birth = {
        "schema": "rapp-private-instance-birth/1.0",
        "product_rappid": product_identity["rappid"],
        "source_revision": source_revision,
        "source_tree_digest": source_digest,
        "birth_nonce": _transport_b64encode(nonce),
    }
    digest = hashlib.sha256(_canonical_bytes(birth)).hexdigest()
    slug = product_identity["slug"]
    suffix = "-twin"
    slug = slug[: 63 - len(suffix)].rstrip("-") + suffix
    identity = parse_rappid(
        "rappid:@"
        + product_identity["owner"]
        + "/"
        + slug
        + ":"
        + digest
    )
    if identity["rappid"] == product_identity["rappid"]:
        _error("identity_invalid")
    return identity


def _copy_source_records(checkout, destination, profile):
    source_root = Path(checkout)
    target_root = Path(destination)
    if target_root.exists() or target_root.is_symlink():
        _error("transition_failed")
    _private_directory(target_root)
    records = profile.get("files")
    if not isinstance(records, list):
        _error("source_invalid")
    for record in records:
        relative = _validate_relative_source_path(record.get("path"))
        source = source_root / relative
        destination_path = target_root / relative
        _private_directory(destination_path.parent)
        raw = _read_regular_file(
            source, _MAX_SOURCE_FILE_BYTES, "source_invalid"
        )
        if (
            len(raw) != record.get("size")
            or hashlib.sha256(raw).hexdigest() != record.get("sha256")
        ):
            _error("source_invalid")
        _transport_write_new(
            destination_path,
            raw,
            0o755 if record.get("executable") else 0o644,
        )
    if profile.get("profile") == "release":
        manifest_source = source_root / _RELEASE_MANIFEST_NAME
        manifest_raw = _read_regular_file(
            manifest_source, _MAX_JSON_BYTES, "manifest_invalid"
        )
        if (
            hashlib.sha256(manifest_raw).hexdigest()
            != profile.get("release_manifest_sha256")
        ):
            _error("manifest_invalid")
        _transport_write_new(
            target_root / _RELEASE_MANIFEST_NAME,
            manifest_raw,
            0o644,
        )
    copied = scan_source_tree(
        target_root,
        excluded_paths=(
            (_RELEASE_MANIFEST_NAME,)
            if profile.get("profile") == "release"
            else ()
        ),
    )
    if (
        copied["files"] != records
        or copied["tree_digest"] != profile.get("source_tree_digest")
    ):
        _error("transition_failed")
    return target_root


def _installed_logical_records(root, relative_root, prefix):
    base = Path(root) / relative_root
    _existing_components_are_safe(base)
    if base.is_symlink() or not base.is_dir():
        _error("adopt_invalid")
    records = []

    def walk(directory, relative):
        try:
            entries = sorted(
                os.scandir(directory), key=lambda item: item.name
            )
        except OSError:
            _error("adopt_invalid")
        for entry in entries:
            child_relative = (
                Path(entry.name)
                if relative is None
                else relative / entry.name
            )
            try:
                details = entry.stat(follow_symlinks=False)
            except OSError:
                _error("adopt_invalid")
            if stat.S_ISLNK(details.st_mode):
                _error("adopt_invalid")
            if stat.S_ISDIR(details.st_mode):
                walk(Path(entry.path), child_relative)
                continue
            if not stat.S_ISREG(details.st_mode):
                _error("adopt_invalid")
            path = Path(entry.path)
            records.append(
                {
                    "mode": f"{stat.S_IMODE(details.st_mode):04o}",
                    "path": prefix + "/" + child_relative.as_posix(),
                    "sha256": _sha256_file(path),
                    "size": details.st_size,
                    "type": "file",
                }
            )

    walk(base, None)
    return records


def _verify_installed_records(root, records, *, links=False):
    if not isinstance(records, list):
        _error("adopt_invalid")
    for record in records:
        if not isinstance(record, dict):
            _error("adopt_invalid")
        relative = record.get("path")
        if not isinstance(relative, str):
            _error("adopt_invalid")
        try:
            path = Path(root) / _validate_relative_source_path(relative)
            details = os.lstat(path)
        except (OSError, RuntimeError):
            _error("adopt_invalid")
        if f"{stat.S_IMODE(details.st_mode):04o}" != record.get("mode"):
            _error("adopt_invalid")
        kind = record.get("type", "file")
        if kind == "symlink":
            if (
                not links
                or not stat.S_ISLNK(details.st_mode)
                or os.readlink(path) != record.get("target")
            ):
                _error("adopt_invalid")
            continue
        if (
            kind != "file"
            or stat.S_ISLNK(details.st_mode)
            or not stat.S_ISREG(details.st_mode)
            or _sha256_file(path) != record.get("sha256")
            or details.st_size != record.get("size")
        ):
            _error("adopt_invalid")


def _probe_installed_dependencies(python, root):
    expected = {
        "cffi": "2.1.0",
        "cryptography": "49.0.0",
        "pycparser": "3.0",
    }
    environment = {
        "HOME": str(Path(root) / "state" / "home"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": str(Path(root) / "venv" / "bin") + ":/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
    }
    try:
        result = subprocess.run(
            [
                str(python),
                "-I",
                "-c",
                (
                    "import importlib.metadata,json;"
                    "print(json.dumps({n:importlib.metadata.version(n) for n in "
                    "('cffi','cryptography','pycparser')},sort_keys=True))"
                ),
            ],
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        _error("adopt_invalid")
    try:
        observed = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        _error("adopt_invalid")
    if result.returncode != 0 or observed != expected:
        _error("adopt_invalid")
    return expected


def _validate_installed_venv(root):
    base = Path(root) / "venv"
    allowed_links = {
        "bin/python",
        "bin/python3",
        "bin/python3.11",
    }
    try:
        for directory, names, files in os.walk(
            base, topdown=True, followlinks=False
        ):
            current = Path(directory)
            if current.is_symlink():
                _error("adopt_invalid")
            for name in [*names, *files]:
                child = current / name
                details = os.lstat(child)
                relative = child.relative_to(base).as_posix()
                if stat.S_ISLNK(details.st_mode):
                    if relative not in allowed_links:
                        _error("adopt_invalid")
                    try:
                        target = child.resolve(strict=True)
                    except OSError:
                        _error("adopt_invalid")
                    if not target.is_file() or not os.access(target, os.X_OK):
                        _error("adopt_invalid")
                elif not (
                    stat.S_ISDIR(details.st_mode)
                    or stat.S_ISREG(details.st_mode)
                ):
                    _error("adopt_invalid")
    except OSError:
        _error("adopt_invalid")


def _runtime_tree_digest(root):
    base = Path(root)
    if base.is_symlink() or not base.is_dir():
        _error("state_invalid")
    records = []
    total = 0
    for directory, names, files in os.walk(base, topdown=True):
        current = Path(directory)
        if current.is_symlink():
            _error("state_invalid")
        for name in names:
            child = current / name
            if child.is_symlink() or not child.is_dir():
                _error("state_invalid")
        for name in files:
            child = current / name
            if child.is_symlink() or not child.is_file():
                _error("state_invalid")
            details = child.stat()
            total += details.st_size
            if (
                len(records) >= _MAX_SOURCE_FILES
                or total > _MAX_SOURCE_BYTES
                or details.st_size > 128 * 1024 * 1024
            ):
                _error("state_invalid")
            digest = hashlib.sha256()
            try:
                with child.open("rb") as stream:
                    while chunk := stream.read(64 * 1024):
                        digest.update(chunk)
            except OSError:
                _error("state_invalid")
            records.append(
                {
                    "executable": bool(details.st_mode & 0o111),
                    "path": child.relative_to(base).as_posix(),
                    "sha256": digest.hexdigest(),
                    "size": details.st_size,
                }
            )
    records.sort(key=lambda item: item["path"])
    return hashlib.sha256(
        _canonical_bytes(
            {"schema": "rapp-controller-runtime-tree/1.0", "files": records}
        )
    ).hexdigest()


def _copy_installed_runtime(root, ready):
    source = Path(root) / "venv"
    _validate_installed_venv(root)
    runtime = Path(ready) / "runtime"
    _private_directory(runtime)
    target = runtime / "venv"
    if target.exists() or target.is_symlink():
        _error("adopt_invalid")
    try:
        shutil.copytree(
            source,
            target,
            symlinks=False,
            copy_function=shutil.copyfile,
        )
    except OSError:
        _error("adopt_invalid")
    _secure_tree(target)
    for path in target.rglob("*"):
        if path.is_file():
            source_path = source / path.relative_to(target)
            try:
                executable = bool(
                    source_path.resolve(strict=True).stat().st_mode & 0o111
                )
            except OSError:
                _error("adopt_invalid")
            os.chmod(path, 0o700 if executable else 0o600)
    python = target / "bin" / "python"
    if python.is_symlink() or not python.is_file() or not os.access(python, os.X_OK):
        _error("adopt_invalid")
    return {
        "python_relative": "runtime/venv/bin/python",
        "runtime_tree_sha256": _runtime_tree_digest(target),
    }


def _verify_embedded_loadout(root):
    install = Path(root)
    loadout = install / "controller-loadout"
    agent_path = loadout / "agents" / "rapp_stack_cubby_agent.py"
    soul_path = loadout / "soul.md"
    manifest_path = loadout / "controller-loadout.json"
    observed = sorted(
        path.relative_to(loadout).as_posix()
        for path in loadout.rglob("*")
        if path.is_file()
    )
    if observed != [
        "agents/rapp_stack_cubby_agent.py",
        "controller-loadout.json",
        "soul.md",
    ]:
        _error("adopt_invalid")
    try:
        source_text = _read_regular_file(
            agent_path, 1024 * 1024, "adopt_invalid"
        ).decode("utf-8")
        tree = ast.parse(source_text)
    except (UnicodeError, SyntaxError):
        _error("adopt_invalid")
    manifests = [
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name)
            and target.id == "__manifest__"
            for target in node.targets
        )
    ]
    classes = [
        node for node in tree.body if isinstance(node, ast.ClassDef)
    ]
    if len(manifests) != 1 or len(classes) != 1:
        _error("adopt_invalid")
    try:
        native = ast.literal_eval(manifests[0].value)
    except (TypeError, ValueError):
        _error("adopt_invalid")
    required_native = {
        "schema",
        "name",
        "version",
        "description",
        "actions",
        "capability_ids",
        "mutability",
        "enabled_by_default",
        "provenance",
        "dependencies",
    }
    if (
        not isinstance(native, dict)
        or set(native) != required_native
        or native.get("name") != "RappStackCubbyController"
        or native.get("schema") != "rapp-agent/1.0"
        or classes[0].name != native.get("name")
        or not isinstance(native.get("actions"), list)
        or not isinstance(native.get("capability_ids"), list)
        or not isinstance(native.get("dependencies"), list)
    ):
        _error("adopt_invalid")
    source_sha = hashlib.sha256(
        source_text.encode("utf-8")
    ).hexdigest()
    catalog = {
        "schema": "rapp-controller-catalog/1.0",
        "name": native["name"],
        "source": {
            "path": "cubbies/kody-w/agents/rapp_stack_cubby_agent.py",
            "sha256": source_sha,
        },
        "actions": native["actions"],
        "capability_ids": native["capability_ids"],
        "mutability": native["mutability"],
        "dependencies": native["dependencies"],
        "only_streamable_agent": True,
        "determinism": {
            "encoding": "UTF-8",
            "key_order": "lexicographic",
            "indent_spaces": 2,
            "trailing_newline": True,
        },
    }
    manifest = _read_json_file(manifest_path, _MAX_JSON_BYTES)
    soul_sha = _sha256_file(soul_path)
    expected_controller = {
        "name": native["name"],
        "actions": native["actions"],
        "capability_ids": native["capability_ids"],
        "dependencies": native["dependencies"],
        "mutability": native["mutability"],
        "only_streamable_agent": True,
        "path": "agents/rapp_stack_cubby_agent.py",
        "sha256": source_sha,
    }
    catalog_bytes = (
        json.dumps(
            catalog,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")
    if (
        set(manifest)
        != {
            "schema",
            "controller",
            "catalog",
            "files",
            "soul",
            "source",
            "determinism",
        }
        or manifest.get("schema") != "rapp-controller-loadout/1.0"
        or manifest.get("controller") != expected_controller
        or manifest.get("catalog") != catalog
        or manifest.get("files")
        != [
            {
                "path": "agents/rapp_stack_cubby_agent.py",
                "sha256": source_sha,
            },
            {"path": "soul.md", "sha256": soul_sha},
        ]
        or manifest.get("soul")
        != {"path": "soul.md", "sha256": soul_sha}
        or manifest.get("source")
        != {
            "catalog_path": "cubbies/kody-w/catalog/controller-catalog.json",
            "catalog_sha256": hashlib.sha256(catalog_bytes).hexdigest(),
            "catalog_schema": "rapp-controller-catalog/1.0",
            "path": "cubbies/kody-w/agents/rapp_stack_cubby_agent.py",
            "sha256": source_sha,
        }
        or manifest.get("determinism")
        != {
            "encoding": "UTF-8",
            "file_order": "path",
            "key_order": "lexicographic",
            "trailing_newline": True,
        }
    ):
        _error("adopt_invalid")
    source_catalog = _read_json_file(
        install
        / "source"
        / "cubbies"
        / "kody-w"
        / "catalog"
        / "controller-catalog.json",
        _MAX_JSON_BYTES,
    )
    if source_catalog != catalog:
        _error("adopt_invalid")
    return manifest


def _verify_installed_root(
    value,
    expected=None,
    *,
    allow_trusted_development=False,
):
    if not isinstance(value, (str, os.PathLike)):
        _error("adopt_invalid")
    root = Path(value)
    if (
        not root.is_absolute()
        or ".." in root.parts
        or root == Path(root.anchor)
    ):
        _error("adopt_invalid")
    _existing_components_are_safe(root)
    try:
        root = root.resolve(strict=True)
    except OSError:
        _error("adopt_invalid")
    descriptor = _open_absolute_directory(root)
    os.close(descriptor)
    manifest_path = root / "installed-twin.json"
    receipt_path = root / "hatch-receipt.json"
    try:
        manifest = _read_json_file(manifest_path, _MAX_JSON_BYTES)
        receipt = _read_json_file(receipt_path, _MAX_JSON_BYTES)
        manifest_sha = _sha256_file(manifest_path)
    except RuntimeError:
        _error("adopt_invalid")
    if (
        manifest.get("schema") != _INSTALLED_SCHEMA
        or receipt.get("schema") != _HATCH_RECEIPT_SCHEMA
        or receipt.get("rappid") != manifest.get("rappid")
        or receipt.get("instance_rappid")
        != manifest.get("instance_rappid")
        or receipt.get("product_rappid")
        != manifest.get("product_rappid")
        or manifest.get("rappid") != manifest.get("instance_rappid")
        or manifest.get("rappid") == manifest.get("product_rappid")
        or receipt.get("installed_manifest_sha256") != manifest_sha
        or receipt.get("artifact_sha256") != manifest.get("artifact_sha256")
        or manifest.get("started") is not False
        or manifest.get("streamable_agent_count") != 0
        or manifest.get("dependency_versions")
        != {
            "cffi": "2.1.0",
            "cryptography": "49.0.0",
            "pycparser": "3.0",
        }
        or manifest.get("isolation")
        != {
            "dedicated_agent_directory": True,
            "dedicated_state_root": True,
            "dedicated_virtual_environment": True,
            "dedicated_workspace": True,
        }
    ):
        _error("adopt_invalid")
    try:
        product = parse_rappid(manifest.get("product_rappid"))
        installed_instance = parse_rappid(
            manifest.get("instance_rappid")
        )
        if (
            manifest.get("identity_hash")
            != installed_instance["identity_hash"]
        ):
            _error("adopt_invalid")
        revision = manifest.get("source_revision")
        if revision != "WORKTREE":
            revision = validate_commit(revision)
    except RuntimeError:
        _error("adopt_invalid")
    for name in ("source", "controller-loadout", "venv"):
        path = root / name
        _existing_components_are_safe(path)
        if path.is_symlink() or not path.is_dir():
            _error("adopt_invalid")
    for name in ("state", "workspace"):
        path = root / name
        _existing_components_are_safe(path)
        if (
            path.is_symlink()
            or not path.is_dir()
            or stat.S_IMODE(path.stat().st_mode) != 0o700
        ):
            _error("adopt_invalid")
    source = root / "source"
    for directory, names, files in os.walk(source, topdown=True):
        current = Path(directory)
        details = os.lstat(current)
        if stat.S_ISLNK(details.st_mode) or details.st_mode & 0o222:
            _error("adopt_invalid")
        for name in names:
            if (current / name).is_symlink():
                _error("adopt_invalid")
        for name in files:
            path = current / name
            file_details = os.lstat(path)
            if (
                stat.S_ISLNK(file_details.st_mode)
                or not stat.S_ISREG(file_details.st_mode)
                or file_details.st_mode & 0o222
            ):
                _error("adopt_invalid")
    source_profile = validate_release_source_manifest(
        source,
        _ALLOWED_REPOSITORY,
        revision if revision != "WORKTREE" else "0" * 40,
    )
    if source_profile["source_tree_digest"] != manifest.get(
        "source_tree_digest"
    ):
        _error("adopt_invalid")
    actual = _installed_logical_records(root, "source", "source")
    actual.extend(
        _installed_logical_records(
            root, "controller-loadout", "controller-loadout"
        )
    )
    actual.sort(key=lambda item: item["path"].encode("utf-8"))
    if actual != manifest.get("files"):
        _error("adopt_invalid")
    _verify_embedded_loadout(root)
    _verify_installed_records(root, manifest.get("archive_files"))
    requirements = manifest.get("requirements")
    if not isinstance(requirements, dict):
        _error("adopt_invalid")
    _verify_installed_records(root, [requirements])
    distributions = manifest.get("distributions")
    if not isinstance(distributions, list):
        _error("adopt_invalid")
    for distribution in distributions:
        if (
            not isinstance(distribution, dict)
            or distribution.get("name") not in {
                "cffi",
                "cryptography",
                "pycparser",
            }
            or not isinstance(distribution.get("record_path"), str)
            or not isinstance(distribution.get("record_sha256"), str)
            or not _HEX_64_RE.fullmatch(
                distribution["record_sha256"]
            )
            or not isinstance(distribution.get("record_size"), int)
        ):
            _error("adopt_invalid")
        _verify_installed_records(root, distribution.get("files"))
        record_path = root / _validate_relative_source_path(
            distribution["record_path"]
        )
        try:
            if (
                _sha256_file(record_path)
                != distribution["record_sha256"]
                or record_path.stat().st_size
                != distribution["record_size"]
            ):
                _error("adopt_invalid")
        except OSError:
            _error("adopt_invalid")
    if (
        manifest.get("test_only_environment") is not True
        and {
            item.get("name")
            for item in distributions
            if isinstance(item, dict)
        }
        != {"cffi", "cryptography", "pycparser"}
    ):
        _error("adopt_invalid")
    imsg = manifest.get("imsg")
    if (
        not isinstance(imsg, dict)
        or not isinstance(imsg.get("archive_path"), str)
        or not isinstance(imsg.get("archive_sha256"), str)
        or not _HEX_64_RE.fullmatch(imsg["archive_sha256"])
        or not isinstance(imsg.get("archive_size"), int)
    ):
        _error("adopt_invalid")
    archive_path = root / _validate_relative_source_path(
        imsg["archive_path"]
    )
    try:
        if (
            _sha256_file(archive_path) != imsg["archive_sha256"]
            or archive_path.stat().st_size != imsg["archive_size"]
        ):
            _error("adopt_invalid")
    except OSError:
        _error("adopt_invalid")
    _verify_installed_records(root, imsg.get("files"), links=True)
    if (
        not imsg.get("files")
        and not (
            manifest.get("test_only_environment") is True
            and imsg.get("test_only_not_installed") is True
        )
    ):
        _error("adopt_invalid")
    python = root / "venv" / "bin" / "python"
    _existing_components_are_safe(python.parent)
    try:
        python_details = os.lstat(python)
        resolved_python = python.resolve(strict=True)
        real_details = resolved_python.stat()
    except OSError:
        _error("adopt_invalid")
    if not resolved_python.is_file() or not os.access(resolved_python, os.X_OK):
        _error("adopt_invalid")
    python_identity = manifest.get("python")
    python_kind = (
        "symlink" if stat.S_ISLNK(python_details.st_mode) else "file"
    )
    try:
        real_python_identity = resolved_python.relative_to(root).as_posix()
    except ValueError:
        real_python_identity = str(resolved_python)
    if (
        not isinstance(python_identity, dict)
        or python_identity
        != {
            "kind": python_kind,
            "link_mode": f"{stat.S_IMODE(python_details.st_mode):04o}",
            "link_target": (
                os.readlink(python) if python_kind == "symlink" else None
            ),
            "path": "venv/bin/python",
            "real_executable": real_python_identity,
            "real_mode": f"{stat.S_IMODE(real_details.st_mode):04o}",
            "sha256": _sha256_file(resolved_python),
            "size": real_details.st_size,
        }
    ):
        _error("adopt_invalid")
    release_verification = manifest.get("release_verification")
    if (
        not isinstance(release_verification, dict)
        or not isinstance(release_verification.get("verified"), bool)
        or not isinstance(release_verification.get("signed"), bool)
        or not isinstance(release_verification.get("release"), bool)
        or not isinstance(
            release_verification.get("development_only"), bool
        )
    ):
        _error("adopt_invalid")
    release_ready = (
        release_verification.get("verified") is True
        and release_verification.get("signed") is True
        and release_verification.get("release") is True
        and release_verification.get("development_only") is False
    )
    trusted_development = (
        allow_trusted_development is True
        and release_verification.get("verified") is True
        and release_verification.get("signed") is True
        and release_verification.get("release") is False
        and release_verification.get("development_only") is True
    )
    if (
        manifest.get("test_only_environment") is not True
        and not release_ready
        and not trusted_development
    ):
        _error("adopt_invalid")
    _validate_installed_venv(root)
    _probe_installed_dependencies(python, root)
    external_release_digest = release_verification.get(
        "release_manifest_sha256"
    )
    if external_release_digest is not None and (
        not isinstance(external_release_digest, str)
        or not _HEX_64_RE.fullmatch(external_release_digest)
    ):
        _error("adopt_invalid")
    result = {
        "root": str(root),
        "python": str(python),
        "product_identity": product,
        "source_revision": revision,
        "source_tree_digest": source_profile["source_tree_digest"],
        "release_manifest_sha256": source_profile[
            "release_manifest_sha256"
        ],
        "external_release_manifest_sha256": external_release_digest,
        "release_verified": release_verification["verified"],
        "release": release_verification["release"],
        "trusted_development": trusted_development,
        "installed_manifest_sha256": manifest_sha,
        "artifact_sha256": manifest.get("artifact_sha256"),
        "application_manifest_sha256": manifest.get(
            "application_manifest_sha256"
        ),
        "agent_catalog_sha256": manifest.get("agent_catalog_sha256"),
        "files": source_profile["files"],
    }
    for name in (
        "artifact_sha256",
        "application_manifest_sha256",
        "agent_catalog_sha256",
    ):
        if (
            not isinstance(result[name], str)
            or not _HEX_64_RE.fullmatch(result[name])
        ):
            _error("adopt_invalid")
    if expected is not None:
        for name in (
            "installed_manifest_sha256",
            "artifact_sha256",
            "source_tree_digest",
            "source_revision",
            "external_release_manifest_sha256",
        ):
            if result.get(name) != expected.get(name):
                _error("adopt_invalid")
        if result.get("trusted_development") != expected.get(
            "trusted_development"
        ):
            _error("adopt_invalid")
    return result


def _secure_tree(root):
    base = Path(root)
    if base.is_symlink() or not base.is_dir():
        _error("transition_failed")
    try:
        for directory, names, files in os.walk(base, topdown=True):
            current = Path(directory)
            if current.is_symlink():
                _error("transition_failed")
            os.chmod(current, 0o700)
            for name in names:
                child = current / name
                if child.is_symlink():
                    _error("transition_failed")
            for name in files:
                child = current / name
                if child.is_symlink() or not child.is_file():
                    _error("transition_failed")
                os.chmod(child, 0o600)
    except OSError:
        _error("transition_failed")


def _prepare_twin(
    root,
    stage,
    checkout,
    identity,
    profile,
    product_identity,
    repository_url,
    commit,
):
    ready = stage / "ready"
    source = ready / "source"
    workspace = ready / "workspace"
    agents = workspace / "agents"
    data = workspace / "data"
    generated = workspace / "generated-agents"
    logs = workspace / "logs"
    for path in (ready, workspace, agents, data, generated, logs):
        _private_directory(path)
    _copy_source_records(checkout, source, profile)
    source_agents = source / _INTERNAL_AGENT_RELATIVE
    source_soul = source / _SOUL_RELATIVE
    if (
        source_agents.is_symlink()
        or not source_agents.is_dir()
        or source_soul.is_symlink()
        or not source_soul.is_file()
    ):
        _error("source_invalid")
    try:
        for agent_path in sorted(source_agents.glob("*_agent.py")):
            if agent_path.is_symlink() or not agent_path.is_file():
                _error("source_invalid")
            shutil.copyfile(agent_path, agents / agent_path.name)
        shutil.copyfile(source_soul, workspace / "soul.md")
    except OSError:
        _error("transition_failed")
    if not list(agents.glob("*_agent.py")):
        _error("source_invalid")
    created_at = _utc_now()
    state = {
        "schema": _STATE_SCHEMA,
        "rappid": identity["rappid"],
        "instance_rappid": identity["rappid"],
        "product_rappid": product_identity["rappid"],
        "identity_hash": identity["identity_hash"],
        "lifecycle_state": "active",
        "runtime_status": "stopped",
        "repository_url": repository_url,
        "source_commit": commit,
        "source_tree_digest": profile["source_tree_digest"],
        "release_manifest_sha256": profile["release_manifest_sha256"],
        "hatch_profile": profile["profile"],
        "selected_model": None,
        "attestation_mode": None,
        "signed_only": True,
        "created_at": created_at,
        "updated_at": created_at,
        "process": None,
    }
    controller, pairing = _ensure_twin_transport(root, ready, state)
    state["transport"] = _transport_state(pairing)
    _atomic_json(ready / "state.json", state)
    _secure_tree(ready)
    for record in profile["files"]:
        os.chmod(
            source / record["path"],
            0o755 if record["executable"] else 0o644,
        )
    if profile["profile"] == "release":
        os.chmod(source / _RELEASE_MANIFEST_NAME, 0o644)
    os.chmod(_twin_transport_directory(ready) / "public.jwk", 0o644)
    os.chmod(
        _twin_transport_directory(ready) / "controller-public.jwk",
        0o644,
    )
    return ready, state


def _state_path(twin_directory):
    return Path(twin_directory) / "state.json"


def _load_state(twin_directory, expected_hash=None):
    candidate = Path(twin_directory)
    root = _controller_path_root(candidate)
    if root is not None:
        trusted = root.resolve(strict=True)
        _validate_beneath(trusted, candidate, expected="directory")
        for relative in (
            "source",
            "workspace",
            "workspace/agents",
            "workspace/data",
            "workspace/generated-agents",
            "workspace/logs",
        ):
            _validate_beneath(
                trusted,
                candidate / relative,
                expected="directory",
            )
        transport = _twin_transport_directory(candidate)
        if _safe_exists(trusted, transport):
            _validate_beneath(
                trusted, transport, expected="directory"
            )
            for name in (
                "private.pem",
                "public.jwk",
                "controller-public.jwk",
                "pairing.json",
            ):
                _validate_beneath(
                    trusted,
                    transport / name,
                    expected="file",
                )
    state = _read_json_file(_state_path(twin_directory), _MAX_JSON_BYTES)
    try:
        identity = parse_rappid(state.get("rappid"))
        instance_identity = parse_rappid(state.get("instance_rappid"))
        product_identity = parse_rappid(state.get("product_rappid"))
    except RuntimeError:
        _error("state_invalid")
    if (
        state.get("schema") != _STATE_SCHEMA
        or identity != instance_identity
        or product_identity["rappid"] == identity["rappid"]
        or state.get("identity_hash") != identity["identity_hash"]
        or (
            expected_hash is not None
            and identity["identity_hash"] != expected_hash
        )
        or state.get("lifecycle_state") not in {"active", "archived"}
        or state.get("runtime_status")
        not in {"stopped", "starting", "running"}
        or state.get("signed_only") is not True
        or (
            state.get("selected_model") is not None
            and (
                not isinstance(state.get("selected_model"), str)
                or not state["selected_model"].strip()
            )
        )
        or state.get("attestation_mode") not in {
            None,
            _ATTESTATION_MODE,
        }
        or (
            state.get("attestation_mode") == _ATTESTATION_MODE
            and state.get("selected_model") != _ATTESTATION_MODEL
        )
        or (
            state.get("attestation_mode") is None
            and state.get("selected_model") == _ATTESTATION_MODEL
        )
    ):
        _error("state_invalid")
    adoption = state.get("adopted_install")
    if adoption is not None:
        if (
            not isinstance(adoption, dict)
            or set(adoption)
            != {
                "root",
                "installed_manifest_sha256",
                "external_release_manifest_sha256",
                "artifact_sha256",
                "source_tree_digest",
                "source_revision",
                "python_relative",
                "runtime_tree_sha256",
                "trusted_development",
            }
            or adoption.get("python_relative")
            != "runtime/venv/bin/python"
            or not isinstance(adoption.get("trusted_development"), bool)
            or (
                adoption.get("external_release_manifest_sha256") is not None
                and (
                    not isinstance(
                        adoption["external_release_manifest_sha256"], str
                    )
                    or not _HEX_64_RE.fullmatch(
                        adoption["external_release_manifest_sha256"]
                    )
                )
            )
            or any(
                not isinstance(adoption.get(name), str)
                or not _HEX_64_RE.fullmatch(adoption[name])
                for name in (
                    "installed_manifest_sha256",
                    "artifact_sha256",
                    "source_tree_digest",
                    "runtime_tree_sha256",
                )
            )
        ):
            _error("state_invalid")
        if root is not None:
            _validate_beneath(
                root.resolve(strict=True),
                candidate / "runtime/venv",
                expected="directory",
            )
    return state


def _write_state(twin_directory, state):
    value = dict(state)
    value["updated_at"] = _utc_now()
    _atomic_json(_state_path(twin_directory), value)
    return value


def _validate_promoted_source(twin_directory, state):
    source = Path(twin_directory) / "source"
    manifest = source / _RELEASE_MANIFEST_NAME
    scanned = scan_source_tree(
        source,
        excluded_paths=(
            (_RELEASE_MANIFEST_NAME,) if manifest.exists() else ()
        ),
    )
    if scanned["tree_digest"] != state.get("source_tree_digest"):
        _error("source_mismatch")
    if manifest.exists():
        revision = state.get("source_commit")
        validate_release_source_manifest(
            source,
            state.get("repository_url"),
            revision if revision != "WORKTREE" else "0" * 40,
        )
    return scanned


def _identity_paths(root, identity_hash):
    if not isinstance(identity_hash, str) or not _HEX_64_RE.fullmatch(
        identity_hash
    ):
        _error("identity_invalid")
    paths = {
        "active": root / "twins" / "active" / identity_hash,
        "archive": root / "twins" / "archive" / identity_hash,
        "purged": root / "twins" / "purged" / (identity_hash + ".json"),
    }
    for name, path in paths.items():
        _validate_beneath(
            root,
            path,
            allow_missing=True,
            expected="file" if name == "purged" else "directory",
        )
    return paths


def _locate_identity(root, identity_hash):
    paths = _identity_paths(root, identity_hash)
    present = [
        name
        for name in ("active", "archive")
        if _safe_exists(root, paths[name], expected="directory")
    ]
    if _safe_exists(root, paths["purged"], expected="file"):
        present.append("purged")
    if len(present) > 1:
        _error("state_invalid")
    return (present[0], paths[present[0]]) if present else (None, None)


def _identity_for_action(kwargs):
    return parse_rappid(kwargs.get("rappid"))


def _identity_for_status(kwargs):
    rappid = kwargs.get("rappid")
    if rappid is not None:
        return parse_rappid(rappid)
    identity_hash = kwargs.get("identity_hash")
    if not isinstance(identity_hash, str) or not _HEX_64_RE.fullmatch(
        identity_hash
    ):
        _error("identity_invalid")
    return {"rappid": None, "identity_hash": identity_hash}


def _receipt(root, action, identity, state, **values):
    receipt_id = uuid.uuid4().hex
    payload = {
        "schema": _RECEIPT_SCHEMA,
        "receipt_id": receipt_id,
        "action": action,
        "rappid": identity["rappid"],
        "instance_rappid": state.get("instance_rappid", identity["rappid"]),
        "product_rappid": state.get("product_rappid"),
        "identity_hash": identity["identity_hash"],
        "created_at": _utc_now(),
        "source_commit": state.get("source_commit"),
        "source_tree_digest": state.get("source_tree_digest"),
        "release_manifest_sha256": state.get(
            "release_manifest_sha256"
        ),
    }
    payload.update(values)
    _atomic_json(root / "receipts" / (receipt_id + ".json"), payload)
    return receipt_id


def _validate_python(selected=None):
    raw = (
        os.environ.get("RAPP_STACK_PYTHON")
        if selected is None
        else str(selected)
    )
    if not isinstance(raw, str) or not raw:
        _error("python_invalid")
    path = Path(raw)
    if not path.is_absolute() or ".." in path.parts:
        _error("python_invalid")
    try:
        resolved = path.resolve(strict=True)
        info = resolved.stat()
    except OSError:
        _error("python_invalid")
    if not stat.S_ISREG(info.st_mode) or not os.access(resolved, os.X_OK):
        _error("python_invalid")
    try:
        result = subprocess.run(
            [
                str(path),
                "-c",
                "import sys;print(f'{sys.version_info[0]}.{sys.version_info[1]}')",
            ],
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=_PYTHON_PROBE_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        _error("python_invalid")
    if result.returncode != 0 or result.stdout.strip() != b"3.11":
        _error("python_invalid")
    return str(path)


def _validate_model(value):
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value.strip()) > 128
        or any(ord(character) < 32 for character in value)
    ):
        _error("model_invalid")
    return value.strip()


def _validate_provider_selection(model, attestation_mode, *, required):
    if model is None and not required and attestation_mode is None:
        return None, None
    selected_model = _validate_model(model)
    if attestation_mode is None:
        if selected_model == _ATTESTATION_MODEL:
            _error("model_invalid")
        return selected_model, None
    if (
        attestation_mode != _ATTESTATION_MODE
        or selected_model != _ATTESTATION_MODEL
    ):
        _error("model_invalid")
    return selected_model, _ATTESTATION_MODE


def _validate_github_token_file(value, *, required):
    if value is None:
        if required:
            _error("provider_auth_invalid")
        return None
    if not isinstance(value, str) or not value or len(value) > 4096:
        _error("provider_auth_invalid")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        _error("provider_auth_invalid")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            details = os.lstat(current)
        except OSError:
            _error("provider_auth_invalid")
        if stat.S_ISLNK(details.st_mode):
            _error("provider_auth_invalid")
    try:
        details = os.lstat(path)
        resolved = path.resolve(strict=True)
    except OSError:
        _error("provider_auth_invalid")
    if (
        not stat.S_ISREG(details.st_mode)
        or stat.S_IMODE(details.st_mode) != 0o600
        or details.st_size > 64 * 1024
    ):
        _error("provider_auth_invalid")
    return str(resolved)


def _preflight_model(python, source, model, github_token_file):
    environment = {
        key: value
        for key, value in os.environ.items()
        if key
        in {
            "GH_CONFIG_DIR",
            "HOME",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "LOGNAME",
            "PATH",
            "SSH_AUTH_SOCK",
            "TMPDIR",
            "USER",
            "XDG_CONFIG_HOME",
        }
        and isinstance(value, str)
    }
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": str(Path(source) / "src"),
        }
    )
    try:
        result = subprocess.run(
            [
                python,
                "-m",
                "rapp_stack_cubby",
                "provider-preflight",
                "--model",
                model,
                "--github-token-file",
                github_token_file,
                "--json",
            ],
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=source,
            env=environment,
            timeout=_MODEL_PREFLIGHT_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        _error("model_invalid")
    if result.returncode != 0 or len(result.stdout) > 1024 * 1024:
        _error("model_invalid")
    try:
        payload = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        _error("model_invalid")
    if (
        not isinstance(payload, dict)
        or payload.get("status") != "ok"
        or payload.get("authenticated") is not True
        or payload.get("selected_model") != model
        or payload.get("selected_model_valid") is not True
    ):
        _error("model_invalid")
    return model


def _select_port(value=None):
    if value is not None:
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not 1 <= value <= 65535
        ):
            _error("start_failed")
        return value
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])
    except OSError:
        _error("start_failed")
    finally:
        listener.close()


def _child_environment(twin_directory, state):
    allowed = {
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LOGNAME",
        "PATH",
        "TMPDIR",
        "USER",
        "XDG_CONFIG_HOME",
        "GH_CONFIG_DIR",
        "SSH_AUTH_SOCK",
        "RAPP_STACK_IMESSAGE_STATUS",
    }
    environment = {
        key: value
        for key, value in os.environ.items()
        if key in allowed and isinstance(value, str)
    }
    environment.pop("GITHUB_TOKEN", None)
    environment.pop("GH_TOKEN", None)
    environment.pop("RAPP_STACK_IMESSAGE_CONFIG", None)
    source = Path(twin_directory) / "source"
    workspace = Path(twin_directory) / "workspace"
    environment.update(
        {
            "PYTHONPATH": str(source / "src"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "RAPP_STACK_ROOT": str(source),
            "RAPP_STACK_DATA_DIR": str(workspace / "data"),
            "RAPP_STACK_GENERATED_AGENTS_DIR": str(
                workspace / "generated-agents"
            ),
            "RAPP_STACK_PRINCIPAL": state["identity_hash"],
            "RAPP_STACK_ALLOW_AGENT_WRITES": "1",
            "RAPP_STACK_TWIN_CHAT_STATE_DIR": str(
                workspace / "data" / "twin-chat"
            ),
            "RAPP_STACK_TWIN_CHAT_REPLAY_DB": str(
                workspace / "data" / "twin-chat" / "replay.sqlite3"
            ),
        }
    )
    return environment


def _rotate_log(path):
    candidate = Path(path)
    _existing_components_are_safe(candidate.parent)
    if candidate.exists():
        if candidate.is_symlink() or not candidate.is_file():
            _error("state_invalid")
        try:
            if candidate.stat().st_size <= _MAX_LOG_BYTES:
                os.chmod(candidate, 0o600)
                return
            oldest = candidate.with_name(candidate.name + f".{_LOG_BACKUPS}")
            with contextlib.suppress(FileNotFoundError):
                oldest.unlink()
            for index in range(_LOG_BACKUPS - 1, 0, -1):
                source = candidate.with_name(candidate.name + f".{index}")
                target = candidate.with_name(candidate.name + f".{index + 1}")
                if source.exists():
                    os.replace(source, target)
            os.replace(candidate, candidate.with_name(candidate.name + ".1"))
        except OSError:
            _error("transition_failed")


def _open_log(path):
    _rotate_log(path)
    candidate = Path(path)
    parent = _private_directory(candidate.parent)
    parent_descriptor = None
    try:
        parent_descriptor = os.open(parent, _directory_open_flags())
        descriptor = os.open(
            candidate.name,
            os.O_WRONLY
            | os.O_APPEND
            | os.O_CREAT
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=parent_descriptor,
        )
        os.fchmod(descriptor, 0o600)
        return os.fdopen(descriptor, "ab", buffering=0)
    except OSError:
        _error("transition_failed")
    finally:
        if parent_descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(parent_descriptor)


def _http_json(port, method, path, payload=None, timeout=_HTTP_TIMEOUT):
    if (
        not isinstance(port, int)
        or isinstance(port, bool)
        or not 1 <= port <= 65535
        or method not in {"GET", "POST"}
        or path not in {"/health", "/chat"}
    ):
        _error("http_unavailable")
    body = None
    headers = {"Accept": "application/json", "Connection": "close"}
    if method == "POST":
        try:
            body = _canonical_bytes(payload)
        except (TypeError, ValueError):
            _error("response_invalid")
        if len(body) > _MAX_CHAT_BYTES:
            _error("message_invalid")
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(body))
    connection = http.client.HTTPConnection(
        "127.0.0.1", port, timeout=float(timeout)
    )
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        content_type = response.getheader("Content-Type", "")
        raw = response.read(_MAX_CHAT_BYTES + 1)
        status_code = response.status
    except (OSError, TimeoutError, http.client.HTTPException):
        _error("http_unavailable")
    finally:
        connection.close()
    if (
        status_code != 200
        or len(raw) > _MAX_CHAT_BYTES
        or content_type.split(";", 1)[0].strip().lower()
        != "application/json"
    ):
        _error("response_invalid")
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        _error("response_invalid")
    if not isinstance(decoded, dict):
        _error("response_invalid")
    return decoded


def _health_probe(port):
    try:
        payload = _http_json(
            port, "GET", "/health", timeout=min(_HTTP_TIMEOUT, 2.0)
        )
        return payload
    except RuntimeError:
        return None


def _health_matches(process):
    if not isinstance(process, dict):
        return False
    instance_id = process.get("instance_id")
    port = process.get("port")
    if (
        not isinstance(instance_id, str)
        or not _INSTANCE_RE.fullmatch(instance_id)
        or not isinstance(process.get("start_identity"), str)
        or _process_start_identity(process.get("pid"))
        != process.get("start_identity")
    ):
        return False
    payload = _health_probe(port)
    return bool(
        payload
        and payload.get("status") == "ok"
        and payload.get("ready") is True
        and payload.get("instance_id") == instance_id
    )


def _wait_health(port, instance_id, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        payload = _health_probe(port)
        if (
            payload
            and payload.get("status") == "ok"
            and payload.get("ready") is True
            and payload.get("instance_id") == instance_id
        ):
            return True
        time.sleep(0.1)
    return False


def _process_start_identity(pid):
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
        return None
    try:
        result = subprocess.run(
            [
                _PS_EXECUTABLE,
                "-p",
                str(pid),
                "-o",
                "lstart=",
            ],
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3.0,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    raw = result.stdout.strip()
    if result.returncode != 0 or not raw or len(raw) > 256:
        return None
    return hashlib.sha256(raw).hexdigest()


def _pid_alive(pid):
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _process_group(process):
    if not isinstance(process, dict):
        _error("process_identity_mismatch")
    pid = process.get("pid")
    pgid = process.get("pgid")
    if (
        not isinstance(pid, int)
        or isinstance(pid, bool)
        or pid <= 1
        or pgid != pid
    ):
        _error("process_identity_mismatch")
    try:
        observed = os.getpgid(pid)
    except ProcessLookupError:
        if not _group_alive(pgid):
            return None
        if not _command_owns_group(process):
            _error("process_identity_mismatch")
        return pgid
    except OSError:
        _error("process_identity_mismatch")
    if observed != pgid:
        _error("process_identity_mismatch")
    recorded_start = process.get("start_identity")
    if (
        not isinstance(recorded_start, str)
        or _process_start_identity(pid) != recorded_start
    ):
        _error("process_identity_mismatch")
    return pgid


def _command_owns_process(process):
    if not isinstance(process, dict):
        return False
    pid = process.get("pid")
    instance_id = process.get("instance_id")
    if (
        not isinstance(pid, int)
        or not isinstance(instance_id, str)
        or not _INSTANCE_RE.fullmatch(instance_id)
        or not isinstance(process.get("start_identity"), str)
        or _process_start_identity(pid) != process.get("start_identity")
    ):
        return False
    try:
        result = subprocess.run(
            [_PS_EXECUTABLE, "-ww", "-p", str(pid), "-o", "command="],
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3.0,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    if result.returncode != 0:
        return False
    try:
        command = result.stdout.decode("utf-8", "strict")
    except UnicodeError:
        return False
    return (
        instance_id in command
        and "rapp_stack_cubby" in command
        and " serve " in (" " + command + " ")
    )


def _command_owns_group(process):
    pgid = process.get("pgid") if isinstance(process, dict) else None
    instance_id = (
        process.get("instance_id") if isinstance(process, dict) else None
    )
    if (
        not isinstance(pgid, int)
        or isinstance(pgid, bool)
        or pgid <= 1
        or not isinstance(instance_id, str)
        or not _INSTANCE_RE.fullmatch(instance_id)
    ):
        return False
    try:
        result = subprocess.run(
            [_PS_EXECUTABLE, "-ww", "-axo", "pid=,pgid=,command="],
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3.0,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    if result.returncode != 0:
        return False
    try:
        lines = result.stdout.decode("utf-8", "strict").splitlines()
    except UnicodeError:
        return False
    for line in lines:
        parts = line.strip().split(None, 2)
        if len(parts) != 3:
            continue
        try:
            observed_group = int(parts[1])
        except ValueError:
            continue
        command = parts[2]
        if (
            observed_group == pgid
            and instance_id in command
            and "rapp_stack_cubby" in command
            and " serve " in (" " + command + " ")
        ):
            return True
    return False


def _wait_process_exit(pid, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _pid_alive(pid):
            return True
        time.sleep(0.05)
    return not _pid_alive(pid)


def _group_alive(pgid):
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _wait_group_exit(pgid, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _group_alive(pgid):
            return True
        time.sleep(0.05)
    return not _group_alive(pgid)


def _terminate_spawned(process, pgid):
    if process.poll() is not None and not _group_alive(pgid):
        return
    with contextlib.suppress(OSError):
        os.killpg(pgid, signal.SIGTERM)
    try:
        process.wait(timeout=_STOP_TIMEOUT)
        if not _group_alive(pgid):
            return
    except subprocess.TimeoutExpired:
        pass
    with contextlib.suppress(OSError):
        os.killpg(pgid, signal.SIGKILL)
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=_STOP_TIMEOUT)
    _wait_group_exit(pgid, _STOP_TIMEOUT)
    if _group_alive(pgid):
        _error("transition_failed")


def _terminate_recorded(process):
    pgid = _process_group(process)
    if pgid is None:
        return False
    pid = process["pid"]
    health = _health_probe(process.get("port"))
    if health is not None:
        if health.get("instance_id") != process.get("instance_id"):
            _error("process_identity_mismatch")
    elif not _command_owns_process(process):
        _error("process_identity_mismatch")
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return False
    except OSError:
        _error("process_identity_mismatch")
    escalated = False
    process_exited = _wait_process_exit(pid, _STOP_TIMEOUT)
    if not process_exited or _group_alive(pgid):
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            _error("process_identity_mismatch")
        escalated = True
        if (
            not _wait_process_exit(pid, _STOP_TIMEOUT)
            or not _wait_group_exit(pgid, _STOP_TIMEOUT)
        ):
            _error("transition_failed")
    return escalated


def _leader_identity_matches(process):
    if not isinstance(process, dict):
        return False
    pid = process.get("pid")
    if (
        not _pid_alive(pid)
        or not isinstance(process.get("start_identity"), str)
        or _process_start_identity(pid) != process.get("start_identity")
    ):
        return False
    try:
        return os.getpgid(pid) == process.get("pgid")
    except OSError:
        return False


def _observed_runtime(state):
    if state.get("runtime_status") not in {"starting", "running"}:
        return {
            "runtime_status": "stopped",
            "healthy": False,
            "identity_verified": False,
        }
    process = state.get("process")
    if not isinstance(process, dict):
        return {
            "runtime_status": "stopped",
            "healthy": False,
            "identity_verified": False,
        }
    pgid = process.get("pgid")
    leader_alive = _pid_alive(process.get("pid"))
    group_alive = (
        isinstance(pgid, int)
        and not isinstance(pgid, bool)
        and pgid > 1
        and _group_alive(pgid)
    )
    if not leader_alive and not group_alive:
        return {
            "runtime_status": "stopped",
            "healthy": False,
            "identity_verified": False,
        }
    payload = _health_probe(process.get("port"))
    if payload is None:
        owned = (
            _command_owns_process(process)
            if leader_alive
            else _command_owns_group(process)
        )
        return {
            "runtime_status": "running" if owned else "stopped",
            "healthy": False,
            "identity_verified": owned,
        }
    process_identity_matches = (
        (leader_alive and _leader_identity_matches(process))
        or (not leader_alive and _command_owns_group(process))
    )
    matches = (
        payload.get("instance_id") == process.get("instance_id")
        and process_identity_matches
    )
    return {
        "runtime_status": "running" if matches else "stopped",
        "healthy": bool(matches and payload.get("ready") is True),
        "identity_verified": matches,
    }


def _reconcile_runtime(twin_directory, state):
    if state.get("runtime_status") not in {"starting", "running"}:
        return state
    process = state.get("process")
    observed = _observed_runtime(state)
    if observed["runtime_status"] == "running" and observed["healthy"]:
        if state.get("runtime_status") == "starting":
            running = dict(state)
            running["runtime_status"] = "running"
            running.pop("last_start_failure", None)
            return _write_state(twin_directory, running)
        return state
    if isinstance(process, dict):
        pgid = process.get("pgid")
        group_alive = (
            isinstance(pgid, int)
            and not isinstance(pgid, bool)
            and pgid > 1
            and _group_alive(pgid)
        )
        if group_alive:
            _terminate_recorded(process)
            if _group_alive(pgid):
                _error("transition_failed")
    stopped = dict(state)
    stopped["runtime_status"] = "stopped"
    stopped["process"] = None
    stopped["last_start_failure"] = {
        "code": "orphan_reconciled",
        "at": _utc_now(),
    }
    return _write_state(twin_directory, stopped)


def _start_locked(
    root,
    twin_directory,
    state,
    model,
    attestation_mode=None,
    github_token_file=None,
    port=None,
    phase_callback=None,
):
    state = _reconcile_runtime(twin_directory, state)
    observed = _observed_runtime(state)
    if observed["runtime_status"] == "running":
        process = state.get("process") or {}
        if (
            process.get("model") != model
            or process.get("attestation_mode") != attestation_mode
        ):
            _error("model_invalid")
        return state, {
            "status": "running",
            "already_running": True,
            "instance_id": state["process"]["instance_id"],
            "port": state["process"]["port"],
            "model": state["process"]["model"],
            "attestation_mode": state["process"].get(
                "attestation_mode"
            ),
        }
    _validate_promoted_source(twin_directory, state)
    controller, pairing = _ensure_twin_transport(
        root, twin_directory, state
    )
    transport_state = _transport_state(pairing)
    if state.get("transport") != transport_state:
        state = dict(state)
        state["transport"] = transport_state
        state = _write_state(twin_directory, state)
    source = Path(twin_directory) / "source"
    adoption = state.get("adopted_install")
    if isinstance(adoption, dict):
        python_path = (
            Path(twin_directory)
            / adoption.get("python_relative", "")
        )
        runtime_root = python_path.parents[1]
        if (
            adoption.get("python_relative")
            != "runtime/venv/bin/python"
            or not _HEX_64_RE.fullmatch(
                str(adoption.get("runtime_tree_sha256", ""))
            )
            or _runtime_tree_digest(runtime_root)
            != adoption["runtime_tree_sha256"]
        ):
            _error("adopt_invalid")
        python = _validate_python(python_path)
    else:
        python = _validate_python()
    model, attestation_mode = _validate_provider_selection(
        model,
        attestation_mode,
        required=True,
    )
    if attestation_mode is None:
        github_token_file = _validate_github_token_file(
            github_token_file,
            required=True,
        )
        _preflight_model(
            python,
            source,
            model,
            github_token_file,
        )
    elif github_token_file is not None:
        _error("provider_auth_invalid")
    selected_port = _select_port(port)
    instance_id = secrets.token_hex(16)
    if not _INSTANCE_RE.fullmatch(instance_id):
        _error("start_failed")
    workspace = Path(twin_directory) / "workspace"
    command = [
        python,
        "-m",
        "rapp_stack_cubby",
        "serve",
        "--soul",
        str(workspace / "soul.md"),
        "--agents-dir",
        str(workspace / "agents"),
        "--data-dir",
        str(workspace / "data"),
        "--root",
        str(source),
        "--principal",
        state["identity_hash"],
        "--generated-agents-dir",
        str(workspace / "generated-agents"),
        "--allow-agent-writes",
        "--signed-only",
        "--model",
        model,
        "--provider-timeout",
        str(_CHILD_PROVIDER_TIMEOUT),
        "--host",
        "127.0.0.1",
        "--port",
        str(selected_port),
        "--instance-id",
        instance_id,
        "--twin-rappid",
        state["rappid"],
        "--child-private-key",
        str(_twin_transport_directory(twin_directory) / "private.pem"),
        "--paired-controller-public-jwk",
        str(
            _twin_transport_directory(twin_directory)
            / "controller-public.jwk"
        ),
        "--paired-controller-rappid",
        controller["rappid"],
        "--replay-db",
        str(
            _twin_transport_directory(twin_directory)
            / "replay.sqlite3"
        ),
        "--signed-ingress-key-epoch",
        str(pairing["key_epoch"]),
    ]
    if attestation_mode is not None:
        command.extend(["--attestation-mode", attestation_mode])
    else:
        command.extend(
            ["--github-token-file", github_token_file]
        )
    command_digest = hashlib.sha256(_canonical_bytes(command)).hexdigest()
    stdout_file = _open_log(workspace / "logs" / "stdout.log")
    stderr_file = _open_log(workspace / "logs" / "stderr.log")
    child = None
    process = None
    try:
        child = subprocess.Popen(
            command,
            shell=False,
            cwd=source,
            env=_child_environment(twin_directory, state),
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            start_new_session=True,
            close_fds=True,
        )
    except OSError:
        _error("start_failed")
    finally:
        with contextlib.suppress(Exception):
            stdout_file.close()
        with contextlib.suppress(Exception):
            stderr_file.close()
    try:
        start_identity = None
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and start_identity is None:
            start_identity = _process_start_identity(child.pid)
            if start_identity is None:
                time.sleep(0.01)
        if start_identity is None:
            _error("start_failed")
        process = {
            "pid": child.pid,
            "pgid": child.pid,
            "port": selected_port,
            "started_at": _utc_now(),
            "start_identity": start_identity,
            "instance_id": instance_id,
            "command_sha256": command_digest,
            "model": model,
            "attestation_mode": attestation_mode,
            "provider_timeout": _CHILD_PROVIDER_TIMEOUT,
            "signed_only": True,
        }
        starting = dict(state)
        starting["runtime_status"] = "starting"
        starting["process"] = process
        starting["selected_model"] = model
        starting["attestation_mode"] = attestation_mode
        starting.pop("last_start_failure", None)
        starting = _write_state(twin_directory, starting)
        if phase_callback is not None:
            phase_callback("starting", process=process)
        if not _wait_health(selected_port, instance_id, _HEALTH_TIMEOUT):
            _error("health_failed")
        if (
            _process_start_identity(child.pid) != start_identity
            or os.getpgid(child.pid) != child.pid
        ):
            _error("process_identity_mismatch")
        running = dict(starting)
        running["runtime_status"] = "running"
        running = _write_state(twin_directory, running)
    except BaseException as error:
        cleanup_succeeded = False
        if child is not None:
            try:
                _terminate_spawned(child, child.pid)
                cleanup_succeeded = not _group_alive(child.pid)
            except BaseException:
                cleanup_succeeded = False
        if cleanup_succeeded:
            stopped = dict(state)
            stopped["runtime_status"] = "stopped"
            stopped["process"] = None
            stopped["selected_model"] = model
            stopped["attestation_mode"] = attestation_mode
            stopped["last_start_failure"] = {
                "code": _safe_exception_code(error),
                "at": _utc_now(),
            }
            with contextlib.suppress(BaseException):
                _write_state(twin_directory, stopped)
        raise
    return running, {
        "status": "running",
        "already_running": False,
        "instance_id": instance_id,
        "port": selected_port,
        "command_sha256": command_digest,
        "model": model,
        "attestation_mode": attestation_mode,
        "signed_only": True,
    }


def _stop_locked(twin_directory, state):
    if state.get("runtime_status") not in {"starting", "running"}:
        return state, {
            "status": "stopped",
            "already_stopped": True,
            "escalated": False,
        }
    process = state.get("process")
    if not isinstance(process, dict):
        stopped = dict(state)
        stopped["runtime_status"] = "stopped"
        stopped["process"] = None
        stopped = _write_state(twin_directory, stopped)
        return stopped, {
            "status": "stopped",
            "already_stopped": True,
            "escalated": False,
        }
    pgid = process.get("pgid")
    if not _pid_alive(process.get("pid")) and not (
        isinstance(pgid, int) and pgid > 1 and _group_alive(pgid)
    ):
        escalated = False
    else:
        escalated = _terminate_recorded(process)
        if isinstance(pgid, int) and _group_alive(pgid):
            _error("transition_failed")
    stopped = dict(state)
    stopped["runtime_status"] = "stopped"
    stopped["process"] = None
    stopped = _write_state(twin_directory, stopped)
    return stopped, {
        "status": "stopped",
        "already_stopped": False,
        "escalated": escalated,
    }


def _session(root, identity_hash, audience, *, create=True):
    if not isinstance(audience, str) or not _AUDIENCE_RE.fullmatch(audience):
        _error("message_invalid")
    directory = _private_directory(root / "sessions" / identity_hash)
    audience_hash = hashlib.sha256(audience.encode("utf-8")).hexdigest()
    path = directory / (audience_hash + ".json")
    if path.exists():
        record = _read_json_file(path, 64 * 1024)
        if (
            record.get("schema") != "rapp-controller-session/1.0"
            or record.get("audience") != audience
            or not isinstance(record.get("session_id"), str)
        ):
            _error("state_invalid")
        return record["session_id"], False
    if not create:
        return None, False
    session_id = "controller-" + uuid.uuid4().hex
    _atomic_json(
        path,
        {
            "schema": "rapp-controller-session/1.0",
            "audience": audience,
            "session_id": session_id,
            "created_at": _utc_now(),
        },
    )
    return session_id, True


def _record_signed_session(
    root, identity_hash, audience, session_id
):
    if (
        not isinstance(session_id, str)
        or re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", session_id
        )
        is None
    ):
        _error("response_invalid")
    existing, _created = _session(
        root, identity_hash, audience, create=False
    )
    if existing is not None:
        if existing != session_id:
            _error("response_invalid")
        return False
    if not isinstance(audience, str) or not _AUDIENCE_RE.fullmatch(audience):
        _error("message_invalid")
    directory = _private_directory(root / "sessions" / identity_hash)
    audience_hash = hashlib.sha256(audience.encode("utf-8")).hexdigest()
    _atomic_json(
        directory / (audience_hash + ".json"),
        {
            "schema": "rapp-controller-session/1.0",
            "audience": audience,
            "session_id": session_id,
            "created_at": _utc_now(),
            "source": "verified_signed_child_response",
        },
    )
    return True


def _validate_outbound_request_record(record, controller, state):
    required = {
        "schema",
        "wire_b64",
        "wire_sha256",
        "nonce",
        "request_digest",
        "target_rappid",
        "controller_key_id",
        "child_key_id",
        "key_epoch",
        "generation",
        "state",
        "created_at",
    }
    if (
        not isinstance(record, dict)
        or set(record) != required
        or record.get("schema") != _OUTBOUND_REQUEST_SCHEMA
        or record.get("target_rappid") != state["rappid"]
        or record.get("controller_key_id") != controller["key_id"]
        or not isinstance(record.get("wire_sha256"), str)
        or not _HEX_64_RE.fullmatch(record["wire_sha256"])
        or not isinstance(record.get("request_digest"), str)
        or not _HEX_64_RE.fullmatch(record["request_digest"])
        or not isinstance(record.get("child_key_id"), str)
        or not _HEX_64_RE.fullmatch(record["child_key_id"])
        or not isinstance(record.get("nonce"), str)
        or not isinstance(record.get("key_epoch"), int)
        or isinstance(record.get("key_epoch"), bool)
        or not isinstance(record.get("generation"), int)
        or isinstance(record.get("generation"), bool)
        or record.get("key_epoch") != record.get("generation")
        or not 1 <= record.get("key_epoch", 0) <= 2**31 - 1
        or record.get("state")
        not in {"prepared", "dispatch_intent", "response_verified"}
        or not isinstance(record.get("created_at"), str)
    ):
        _error("state_invalid")
    try:
        wire = _transport_b64decode(record.get("wire_b64"))
        wrapper = _transport_parse_canonical_wire(wire)
        inner = wrapper.get("body") if isinstance(wrapper, dict) else None
        if (
            not isinstance(wrapper, dict)
            or set(wrapper) != _TRANSPORT_WRAPPER_KEYS
            or not isinstance(inner, dict)
            or set(inner) != _TRANSPORT_INNER_KEYS
            or wrapper.get("schema") != _COMMONS_SCHEMA
            or wrapper.get("from") != controller["rappid"]
            or wrapper.get("pub") != controller["public_jwk"]
            or wrapper.get("key_id") != controller["key_id"]
            or wrapper.get("alg") != _TRANSPORT_ALGORITHM
            or wrapper.get("ts") != inner.get("utc")
            or wrapper.get("kind") != _TWIN_CHAT_KIND
            or inner.get("schema") != _TWIN_REQUEST_SCHEMA
            or inner.get("from_rappid") != controller["rappid"]
            or inner.get("to_rappid") != state["rappid"]
            or inner.get("nonce") != record["nonce"]
            or inner.get("key_epoch") != record["key_epoch"]
            or inner.get("kind") != _TWIN_CHAT_KIND
            or hashlib.sha256(wire).hexdigest()
            != record["wire_sha256"]
            or hashlib.sha256(
                _transport_canonical_bytes(inner)
            ).hexdigest()
            != record["request_digest"]
        ):
            _error("state_invalid")
        _transport_verify(wrapper, controller["public_jwk"])
    except RuntimeError:
        _error("state_invalid")
    return wire.decode("utf-8")


def _outbound_response_record(wire, status):
    encoded = wire.encode("utf-8")
    return {
        "schema": _OUTBOUND_RESPONSE_SCHEMA,
        "wire_b64": _transport_b64encode(encoded),
        "wire_sha256": hashlib.sha256(encoded).hexdigest(),
        "status": status,
        "verified_at": _utc_now(),
    }


def _load_outbound_response(record):
    if (
        not isinstance(record, dict)
        or set(record)
        != {
            "schema",
            "wire_b64",
            "wire_sha256",
            "status",
            "verified_at",
        }
        or record.get("schema") != _OUTBOUND_RESPONSE_SCHEMA
        or record.get("status") not in {"ok", "rejected"}
        or not isinstance(record.get("wire_sha256"), str)
        or not _HEX_64_RE.fullmatch(record["wire_sha256"])
        or not isinstance(record.get("verified_at"), str)
    ):
        _error("state_invalid")
    try:
        encoded = _transport_b64decode(record.get("wire_b64"))
        wire = encoded.decode("utf-8")
    except (RuntimeError, UnicodeError):
        _error("state_invalid")
    if hashlib.sha256(encoded).hexdigest() != record["wire_sha256"]:
        _error("state_invalid")
    return wire


def _chat_locked(
    root,
    twin_directory,
    state,
    message,
    audience,
    *,
    facet="controller-chat",
    action,
    idempotency_key,
    action_request_digest,
):
    if (
        not isinstance(message, str)
        or not message.strip()
        or len(message) > _MAX_MESSAGE_CHARS
    ):
        _error("message_invalid")
    if state.get("runtime_status") != "running":
        _error("not_running")
    process = state.get("process")
    if not _health_matches(process):
        _error("process_identity_mismatch")
    controller, pairing = _ensure_twin_transport(
        root, twin_directory, state
    )
    transport_state = _transport_state(pairing)
    if state.get("transport") != transport_state:
        state = dict(state)
        state["transport"] = transport_state
        _write_state(twin_directory, state)
    session_id, _unused = _session(
        root, state["identity_hash"], audience, create=False
    )
    transaction = _transaction_load(
        root, idempotency_key, action, action_request_digest
    )
    request_record = (
        transaction.get("signed_request")
        if isinstance(transaction, dict)
        else None
    )
    if request_record is None:
        wrapper, nonce, digest = _transport_build_request(
            controller,
            pairing,
            state,
            message,
            session_id,
            facet,
        )
        wire = _transport_canonical_bytes(wrapper)
        request_record = {
            "schema": _OUTBOUND_REQUEST_SCHEMA,
            "wire_b64": _transport_b64encode(wire),
            "wire_sha256": hashlib.sha256(wire).hexdigest(),
            "nonce": nonce,
            "request_digest": digest,
            "target_rappid": state["rappid"],
            "controller_key_id": controller["key_id"],
            "child_key_id": pairing["child_key_id"],
            "key_epoch": pairing["key_epoch"],
            "generation": pairing["generation"],
            "state": "prepared",
            "created_at": _utc_now(),
        }
        _transition_phase(
            root,
            idempotency_key,
            action,
            action_request_digest,
            state["identity_hash"],
            "request_prepared",
            signed_request=request_record,
        )
        transaction = _transaction_load(
            root, idempotency_key, action, action_request_digest
        )
    wire_text = _validate_outbound_request_record(
        request_record, controller, state
    )
    if (
        request_record["child_key_id"] != pairing["child_key_id"]
        or request_record["key_epoch"] != pairing["key_epoch"]
        or request_record["generation"] != pairing["generation"]
    ):
        return {
            "status": "transport_changed",
            "payload": None,
            "session_id": session_id,
            "session_created": False,
            "signed_request": request_record,
            "signed_response": None,
        }
    response_record = (
        transaction.get("signed_response")
        if isinstance(transaction, dict)
        else None
    )
    if response_record is None:
        retrieval_after_ambiguous_send = (
            request_record.get("state") == "dispatch_intent"
        )
        dispatched_record = dict(request_record)
        dispatched_record["state"] = "dispatch_intent"
        _transition_phase(
            root,
            idempotency_key,
            action,
            action_request_digest,
            state["identity_hash"],
            "dispatch_intent",
            signed_request=dispatched_record,
        )
        request_record = dispatched_record
        provider_timeout = process.get(
            "provider_timeout", _CHILD_PROVIDER_TIMEOUT
        )
        if (
            not isinstance(provider_timeout, (int, float))
            or isinstance(provider_timeout, bool)
            or not 0 < float(provider_timeout) <= 300
        ):
            _error("state_invalid")
        outer = _http_json(
            process["port"],
            "POST",
            "/chat",
            {"user_input": wire_text},
            timeout=float(provider_timeout) + _HTTP_TIMEOUT_MARGIN,
        )
        if not isinstance(outer.get("response"), str):
            _error("response_invalid")
        response_wire = outer["response"]
        response_status, payload = _transport_verify_response(
            response_wire,
            controller,
            pairing,
            state,
            request_record["nonce"],
            request_record["request_digest"],
            enforce_freshness=not retrieval_after_ambiguous_send,
        )
        response_record = _outbound_response_record(
            response_wire, response_status
        )
        verified_record = dict(request_record)
        verified_record["state"] = "response_verified"
        _transition_phase(
            root,
            idempotency_key,
            action,
            action_request_digest,
            state["identity_hash"],
            "response_verified",
            signed_request=verified_record,
            signed_response=response_record,
        )
        request_record = verified_record
    else:
        response_wire = _load_outbound_response(response_record)
        response_status, payload = _transport_verify_response(
            response_wire,
            controller,
            pairing,
            state,
            request_record["nonce"],
            request_record["request_digest"],
            enforce_freshness=False,
        )
        if response_status != response_record["status"]:
            _error("state_invalid")
    if response_status == "rejected":
        return {
            "status": "rejected",
            "payload": payload,
            "session_id": session_id,
            "session_created": False,
            "signed_request": request_record,
            "signed_response": response_record,
        }
    if session_id is not None and payload["session_id"] != session_id:
        _error("response_invalid")
    created = _record_signed_session(
        root,
        state["identity_hash"],
        audience,
        payload["session_id"],
    )
    session_id = payload["session_id"]
    return {
        "status": "ok",
        "payload": payload,
        "session_id": session_id,
        "session_created": created,
        "signed_request": request_record,
        "signed_response": response_record,
    }


def _safe_state_summary(state, location, observed=None):
    if observed is None:
        observed = _observed_runtime(state) if location == "active" else {
            "runtime_status": "stopped",
            "healthy": False,
            "identity_verified": False,
        }
    process = state.get("process") if observed["runtime_status"] == "running" else None
    transport = (
        state.get("transport")
        if isinstance(state.get("transport"), dict)
        else {}
    )
    return {
        "rappid": state["rappid"],
        "instance_rappid": state.get("instance_rappid"),
        "product_rappid": state.get("product_rappid"),
        "identity_hash": state["identity_hash"],
        "lifecycle_state": location,
        "runtime_status": observed["runtime_status"],
        "healthy": observed["healthy"],
        "instance_id": process.get("instance_id") if process else None,
        "port": process.get("port") if process else None,
        "source_commit": state.get("source_commit"),
        "source_tree_digest": state.get("source_tree_digest"),
        "hatch_profile": state.get("hatch_profile"),
        "model": state.get("selected_model"),
        "attestation_mode": state.get("attestation_mode"),
        "signed_only": state.get("signed_only") is True,
        "child_transport_key_id": transport.get("child_key_id"),
        "controller_transport_key_id": transport.get("controller_key_id"),
        "transport_generation": transport.get("generation"),
    }


def _safe_exception_code(error):
    code = str(error)
    return code if code in _ERROR_MESSAGES else "transition_failed"


class RappStackCubbyController(BasicAgent):
    """Own the complete guarded controller lifecycle without package helpers."""

    name = "RappStackCubbyController"
    metadata = {
        "name": "RappStackCubbyController",
        "description": (
            "Inspect, hatch, supervise, archive, purge, and locally chat with "
            "exact-commit isolated RAPP twins."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": [
                        "inspect",
                        "verify",
                        "adopt_install",
                        "hatch_repo",
                        "list",
                        "status",
                        "start",
                        "stop",
                        "archive",
                        "unarchive",
                        "purge",
                        "rotate_keys",
                        "chat",
                        "self_test",
                        "pack",
                        "export",
                    ],
                },
                "repository_url": {"type": "string", "maxLength": 256},
                "install_root": {"type": "string", "maxLength": 4096},
                "commit": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
                "expected_tree_digest": {
                    "type": "string",
                    "pattern": "^[0-9a-f]{64}$",
                },
                "rappid": {"type": "string", "maxLength": 256},
                "development_rappid": {"type": "string", "maxLength": 256},
                "birth_fixture": {"type": "object"},
                "identity_hash": {
                    "type": "string",
                    "pattern": "^[0-9a-f]{64}$",
                },
                "idempotency_key": {
                    "type": "string",
                    "maxLength": 128,
                    "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
                },
                "confirmation": {"type": "string", "maxLength": 256},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "model": {"type": "string", "maxLength": 128},
                "github_token_file": {
                    "type": "string",
                    "maxLength": 4096,
                },
                "attestation_mode": {
                    "type": "string",
                    "enum": ["offline-self-test"],
                },
                "trusted_development": {"type": "boolean"},
                "message": {"type": "string", "maxLength": 1048576},
                "user_input": {"type": "string", "maxLength": 1048576},
                "audience": {"type": "string", "maxLength": 128},
            },
            "required": ["action"],
            "allOf": [
                {
                    "if": {
                        "properties": {
                            "action": {
                                "enum": [
                                    "chat",
                                    "self_test",
                                ]
                            }
                        },
                        "required": ["action"],
                    },
                    "then": {
                        "required": [
                            "action",
                            "idempotency_key",
                        ]
                    },
                }
            ],
            "additionalProperties": False,
        },
    }

    def perform(self, **kwargs):
        action = kwargs.get("action")
        if action not in _ACTIONS:
            return _response(
                str(action or ""),
                ok=False,
                error={
                    "code": "invalid_action",
                    "message": "Unsupported action.",
                },
            )
        try:
            if action == "inspect":
                return _response(action, **self._inspect())
            if action == "verify":
                return _response(action, **self._verify(kwargs))
            if action == "adopt_install":
                return _response(action, **self._adopt_install(kwargs))
            if action == "hatch_repo":
                return _response(action, **self._hatch(kwargs))
            if action == "list":
                return _response(action, **self._list())
            if action == "status":
                return _response(action, **self._status(kwargs))
            if action == "start":
                return _response(action, **self._start(kwargs))
            if action == "stop":
                return _response(action, **self._stop(kwargs))
            if action == "archive":
                return _response(action, **self._archive(kwargs))
            if action == "unarchive":
                return _response(action, **self._unarchive(kwargs))
            if action == "purge":
                return _response(action, **self._purge(kwargs))
            if action == "rotate_keys":
                return _response(action, **self._rotate_keys(kwargs))
            if action == "chat":
                return _response(action, **self._chat(kwargs))
            if action == "self_test":
                return _response(action, **self._self_test(kwargs))
            return _response(
                action,
                status="pending",
                implemented=False,
                artifact_created=False,
                future_owner="release-attestation",
                message=(
                    "Controller package/export mutation remains intentionally "
                    "separate from the local packaging CLI."
                ),
            )
        except (Exception, SystemExit) as error:
            code = _safe_exception_code(error)
            return _response(
                action,
                ok=False,
                error={"code": code, "message": _ERROR_MESSAGES[code]},
            )

    def _inspect(self):
        root = _controller_root(required=False)
        return {
            "schema": "rapp-controller-inspection/1.0",
            "source_sha256": _loaded_source_sha256(),
            "source_hash_available": _loaded_source_sha256() is not None,
            "actions": list(_ACTIONS),
            "capability_ids": list(__manifest__["capability_ids"]),
            "only_streamable_agent": True,
            "mutations_enabled": (
                os.environ.get("RAPP_STACK_ALLOW_CONTROLLER_MUTATIONS") == "1"
            ),
            "controller_data_configured": root is not None,
            "development_hatch_enabled": (
                os.environ.get("RAPP_STACK_ALLOW_DEVELOPMENT_HATCH") == "1"
            ),
            "release_hatch_requires_manifest": True,
            "signed_twin_chat": "implemented_local",
            "verified_install_adoption": "implemented_local",
            "phase_recovery": "implemented_local",
            "private_instance_identity": "implemented_local",
            "deterministic_controller_route": "runtime_configured",
            "imessage": "future",
            "packaging": "future",
        }

    def _verify(self, kwargs):
        repository_url = kwargs.get("repository_url")
        commit = kwargs.get("commit")
        if repository_url is not None:
            validate_repository_url(repository_url)
        if commit is not None:
            validate_commit(commit)
        source_sha = _loaded_source_sha256()
        root = _controller_root(required=False)
        layout_ok = True
        if root is not None:
            for relative in (
                "twins/active",
                "twins/archive",
                "twins/purged",
                "staging",
                "locks",
                "receipts",
                "sessions",
                "loadout",
            ):
                path = root / relative
                if path.exists() and (
                    path.is_symlink()
                    or not path.is_dir()
                    or stat.S_IMODE(path.stat().st_mode) & 0o077
                ):
                    layout_ok = False
        return {
            "verified": layout_ok,
            "source_sha256": source_sha,
            "repository_url_valid": repository_url is None or True,
            "commit_valid": commit is None or True,
            "controller_layout_safe": layout_ok,
            "production_fail_closed": True,
        }

    def _adopt_install(self, kwargs):
        root = _mutation_root("adopt_install")
        selected_model, attestation_mode = _validate_provider_selection(
            kwargs.get("model"),
            kwargs.get("attestation_mode"),
            required=False,
        )
        key = _idempotency_key(kwargs)
        request_digest = _request_digest("adopt_install", kwargs)
        with _controller_locks(root):
            replay = _idempotency_begin(
                root, key, "adopt_install", request_digest
            )
            if replay is not None:
                return replay
            replay = _completed_transaction_replay(
                root, key, "adopt_install", request_digest
            )
            if replay is not None:
                return replay
            stage = root / "staging" / (
                "adopt-" + hashlib.sha256(key.encode("utf-8")).hexdigest()
            )
            promoted = False
            try:
                transaction = _transaction_load(
                    root, key, "adopt_install", request_digest
                )
                if isinstance(transaction, dict):
                    instance_value = transaction.get("instance_rappid")
                    if isinstance(instance_value, str):
                        instance = parse_rappid(instance_value)
                        paths = _identity_paths(
                            root, instance["identity_hash"]
                        )
                        if _safe_exists(
                            root, paths["active"], expected="directory"
                        ):
                            state = _load_state(
                                paths["active"], instance["identity_hash"]
                            )
                            promoted = True
                            return self._finish_install_creation(
                                root,
                                key,
                                "adopt_install",
                                request_digest,
                                instance,
                                state,
                                source_file_count=transaction.get(
                                    "source_file_count"
                                ),
                                source_total_bytes=transaction.get(
                                    "source_total_bytes"
                                ),
                            )
                    if _safe_exists(root, stage, expected="directory"):
                        _safe_remove_tree(root, stage)
                installed = _verify_installed_root(
                    kwargs.get("install_root"),
                    allow_trusted_development=(
                        kwargs.get("trusted_development") is True
                    ),
                )
                product = installed["product_identity"]
                instance = _mint_instance_identity(
                    product,
                    installed["source_revision"],
                    installed["source_tree_digest"],
                )
                profile = {
                    "profile": "release",
                    "release_manifest_sha256": installed[
                        "release_manifest_sha256"
                    ],
                    "source_tree_digest": installed[
                        "source_tree_digest"
                    ],
                    "source_file_count": len(installed["files"]),
                    "source_total_bytes": sum(
                        item["size"] for item in installed["files"]
                    ),
                    "files": installed["files"],
                }
                _transition_phase(
                    root,
                    key,
                    "adopt_install",
                    request_digest,
                    instance["identity_hash"],
                    "verified",
                    instance_rappid=instance["rappid"],
                    product_rappid=product["rappid"],
                    install_root=installed["root"],
                    installed_manifest_sha256=installed[
                        "installed_manifest_sha256"
                    ],
                    artifact_sha256=installed["artifact_sha256"],
                    source_revision=installed["source_revision"],
                    source_tree_digest=installed["source_tree_digest"],
                    source_file_count=profile["source_file_count"],
                    source_total_bytes=profile["source_total_bytes"],
                )
                paths = _identity_paths(root, instance["identity_hash"])
                if any(
                    _safe_exists(
                        root,
                        paths[name],
                        expected=(
                            "file" if name == "purged" else "directory"
                        ),
                    )
                    for name in ("active", "archive", "purged")
                ):
                    _error("duplicate_identity")
                _private_directory(stage)
                ready, state = _prepare_twin(
                    root,
                    stage,
                    Path(installed["root"]) / "source",
                    instance,
                    profile,
                    product,
                    _ALLOWED_REPOSITORY,
                    installed["source_revision"],
                )
                runtime_binding = _copy_installed_runtime(
                    installed["root"], ready
                )
                state = dict(state)
                state["hatch_profile"] = "adopted_verified_install"
                state["selected_model"] = selected_model
                state["attestation_mode"] = attestation_mode
                state["adopted_install"] = {
                    "root": installed["root"],
                    "installed_manifest_sha256": installed[
                        "installed_manifest_sha256"
                    ],
                    "artifact_sha256": installed["artifact_sha256"],
                    "source_tree_digest": installed[
                        "source_tree_digest"
                    ],
                    "source_revision": installed["source_revision"],
                    "external_release_manifest_sha256": installed[
                        "external_release_manifest_sha256"
                    ],
                    "trusted_development": installed[
                        "trusted_development"
                    ],
                    **runtime_binding,
                }
                _write_state(ready, state)
                _transition_phase(
                    root,
                    key,
                    "adopt_install",
                    request_digest,
                    instance["identity_hash"],
                    "prepared",
                )
                _safe_replace(root, ready, paths["active"])
                promoted = True
                _transition_phase(
                    root,
                    key,
                    "adopt_install",
                    request_digest,
                    instance["identity_hash"],
                    "promoted",
                )
                _verify_installed_root(
                    installed["root"],
                    expected=state["adopted_install"],
                    allow_trusted_development=state[
                        "adopted_install"
                    ].get("trusted_development") is True,
                )
                return self._finish_install_creation(
                    root,
                    key,
                    "adopt_install",
                    request_digest,
                    instance,
                    state,
                    source_file_count=profile["source_file_count"],
                    source_total_bytes=profile["source_total_bytes"],
                )
            except (Exception, SystemExit) as error:
                _idempotency_failed(
                    root,
                    key,
                    "adopt_install",
                    request_digest,
                    _safe_exception_code(error),
                )
                raise
            finally:
                if not promoted and _safe_exists(
                    root, stage, expected="directory"
                ):
                    with contextlib.suppress(Exception):
                        _safe_remove_tree(root, stage)

    def _hatch(self, kwargs):
        root = _mutation_root("hatch_repo")
        key = _idempotency_key(kwargs)
        request_digest = _request_digest("hatch_repo", kwargs)
        repository_url = validate_repository_url(
            kwargs.get("repository_url")
        )
        commit = validate_commit(kwargs.get("commit"))
        expected = kwargs.get("expected_tree_digest")
        with _controller_locks(root):
            replay = _idempotency_begin(
                root, key, "hatch_repo", request_digest
            )
            if replay is not None:
                return replay
            replay = _completed_transaction_replay(
                root, key, "hatch_repo", request_digest
            )
            if replay is not None:
                return replay
            stage = root / "staging" / (
                "hatch-" + hashlib.sha256(key.encode("utf-8")).hexdigest()
            )
            promoted = False
            try:
                transaction = _transaction_load(
                    root, key, "hatch_repo", request_digest
                )
                recovered_identity = None
                if isinstance(transaction, dict):
                    if isinstance(
                        transaction.get("instance_rappid"), str
                    ):
                        recovered_identity = parse_rappid(
                            transaction["instance_rappid"]
                        )
                        paths = _identity_paths(
                            root, recovered_identity["identity_hash"]
                        )
                        if _safe_exists(
                            root, paths["active"], expected="directory"
                        ):
                            state = _load_state(
                                paths["active"],
                                recovered_identity["identity_hash"],
                            )
                            promoted = True
                            return self._finish_install_creation(
                                root,
                                key,
                                "hatch_repo",
                                request_digest,
                                recovered_identity,
                                state,
                                source_file_count=transaction.get(
                                    "source_file_count"
                                ),
                                source_total_bytes=transaction.get(
                                    "source_total_bytes"
                                ),
                            )
                    if _safe_exists(root, stage, expected="directory"):
                        _safe_remove_tree(root, stage)
                _private_directory(stage)
                checkout = stage / "checkout"
                _transition_phase(
                    root,
                    key,
                    "hatch_repo",
                    request_digest,
                    None,
                    "checkout_intent",
                    source_commit=commit,
                )
                _checkout_exact(checkout, repository_url, commit)
                profile = _source_profile(
                    checkout, repository_url, commit, expected
                )
                product = _product_identity_from_source(
                    checkout, profile["profile"], kwargs
                )
                identity = recovered_identity or _mint_instance_identity(
                    product, commit, profile["source_tree_digest"]
                )
                _transition_phase(
                    root,
                    key,
                    "hatch_repo",
                    request_digest,
                    identity["identity_hash"],
                    "source_verified",
                    instance_rappid=identity["rappid"],
                    product_rappid=product["rappid"],
                    source_commit=commit,
                    source_tree_digest=profile["source_tree_digest"],
                    source_file_count=profile["source_file_count"],
                    source_total_bytes=profile["source_total_bytes"],
                )
                with _controller_locks(
                    root,
                    identity["identity_hash"],
                    include_controller=False,
                ):
                    paths = _identity_paths(
                        root, identity["identity_hash"]
                    )
                    if any(
                        _safe_exists(
                            root,
                            paths[name],
                            expected=(
                                "file" if name == "purged" else "directory"
                            ),
                        )
                        for name in ("active", "archive", "purged")
                    ):
                        _error("duplicate_identity")
                    ready, state = _prepare_twin(
                        root,
                        stage,
                        checkout,
                        identity,
                        profile,
                        product,
                        repository_url,
                        commit,
                    )
                    _transition_phase(
                        root,
                        key,
                        "hatch_repo",
                        request_digest,
                        identity["identity_hash"],
                        "prepared",
                    )
                    _safe_replace(root, ready, paths["active"])
                    promoted = True
                    _transition_phase(
                        root,
                        key,
                        "hatch_repo",
                        request_digest,
                        identity["identity_hash"],
                        "promoted",
                    )
                return self._finish_install_creation(
                    root,
                    key,
                    "hatch_repo",
                    request_digest,
                    identity,
                    state,
                    source_file_count=profile["source_file_count"],
                    source_total_bytes=profile["source_total_bytes"],
                )
            except (Exception, SystemExit) as error:
                _idempotency_failed(
                    root,
                    key,
                    "hatch_repo",
                    request_digest,
                    _safe_exception_code(error),
                )
                raise
            finally:
                if _safe_exists(root, stage, expected="directory"):
                    with contextlib.suppress(Exception):
                        _safe_remove_tree(root, stage)

    def _finish_install_creation(
        self,
        root,
        key,
        action,
        request_digest,
        identity,
        state,
        *,
        source_file_count,
        source_total_bytes,
    ):
        receipt_id = _receipt(
            root,
            action,
            identity,
            state,
            hatch_profile=state.get("hatch_profile"),
            source_file_count=source_file_count,
            source_total_bytes=source_total_bytes,
            artifact_sha256=(
                state.get("adopted_install") or {}
            ).get("artifact_sha256"),
            installed_manifest_sha256=(
                state.get("adopted_install") or {}
            ).get("installed_manifest_sha256"),
            status="completed",
        )
        result = {
            "status": "stopped",
            "lifecycle_state": "active",
            "rappid": identity["rappid"],
            "instance_rappid": identity["rappid"],
            "product_rappid": state["product_rappid"],
            "identity_hash": identity["identity_hash"],
            "workspace_key": identity["identity_hash"],
            "source_commit": state["source_commit"],
            "source_tree_digest": state["source_tree_digest"],
            "release_manifest_sha256": state[
                "release_manifest_sha256"
            ],
            "hatch_profile": state["hatch_profile"],
            "model": state.get("selected_model"),
            "attestation_mode": state.get("attestation_mode"),
            "release_eligible": (
                state["hatch_profile"] == "release"
                or (
                    state["hatch_profile"]
                    == "adopted_verified_install"
                    and not (state.get("adopted_install") or {}).get(
                        "trusted_development", False
                    )
                )
            ),
            "adopted": action == "adopt_install",
            "receipt_id": receipt_id,
        }
        _transition_phase(
            root,
            key,
            action,
            request_digest,
            identity["identity_hash"],
            "completed",
            receipt_id=receipt_id,
            result=result,
        )
        _idempotency_complete(
            root, key, action, request_digest, result
        )
        return result

    def _list(self):
        root = _controller_root(required=False)
        if root is None:
            return {"controller_data_configured": False, "twins": []}
        twins = []
        for location in ("active", "archive"):
            directory = root / "twins" / location
            if not _safe_exists(root, directory, expected="directory"):
                continue
            for path in sorted(directory.iterdir(), key=lambda item: item.name):
                if (
                    path.is_symlink()
                    or not path.is_dir()
                    or not _HEX_64_RE.fullmatch(path.name)
                ):
                    _error("state_invalid")
                state = _load_state(path, path.name)
                twins.append(_safe_state_summary(state, location))
        purged = root / "twins" / "purged"
        if _safe_exists(root, purged, expected="directory"):
            for path in sorted(purged.glob("*.json"), key=lambda item: item.name):
                tombstone = _read_json_file(path, _MAX_JSON_BYTES)
                if tombstone.get("schema") != _TOMBSTONE_SCHEMA:
                    _error("state_invalid")
                twins.append(
                    {
                        "rappid": tombstone.get("rappid"),
                        "identity_hash": tombstone.get("identity_hash"),
                        "lifecycle_state": "purged",
                        "runtime_status": "stopped",
                        "healthy": False,
                    }
                )
        twins.sort(
            key=lambda item: (
                item.get("identity_hash", ""),
                item.get("lifecycle_state", ""),
            )
        )
        return {"controller_data_configured": True, "twins": twins}

    def _status(self, kwargs):
        root = _controller_root(required=True)
        identity = _identity_for_status(kwargs)
        with _controller_locks(root, identity["identity_hash"]):
            location, path = _locate_identity(
                root, identity["identity_hash"]
            )
            if location is None:
                _error("not_found")
            if location == "purged":
                tombstone = _read_json_file(path, _MAX_JSON_BYTES)
                return {
                    "rappid": tombstone.get("rappid"),
                    "instance_rappid": tombstone.get("instance_rappid"),
                    "product_rappid": tombstone.get("product_rappid"),
                    "identity_hash": identity["identity_hash"],
                    "lifecycle_state": "purged",
                    "runtime_status": "stopped",
                    "healthy": False,
                }
            state = _load_state(path, identity["identity_hash"])
            if (
                identity.get("rappid")
                and state["rappid"] != identity["rappid"]
            ):
                _error("identity_invalid")
            if location == "active":
                state = _reconcile_runtime(path, state)
            return _safe_state_summary(state, location)

    def _start(self, kwargs):
        root = _mutation_root("start")
        identity = _identity_for_action(kwargs)
        model, attestation_mode = _validate_provider_selection(
            kwargs.get("model"),
            kwargs.get("attestation_mode"),
            required=True,
        )
        github_token_file = _validate_github_token_file(
            kwargs.get("github_token_file"),
            required=attestation_mode is None,
        )
        if attestation_mode is not None and github_token_file is not None:
            _error("provider_auth_invalid")
        key = _idempotency_key(kwargs)
        request_digest = _request_digest("start", kwargs)
        with _controller_locks(root, identity["identity_hash"]):
            replay = _idempotency_begin(
                root, key, "start", request_digest
            )
            if replay is not None:
                return replay
            replay = _completed_transaction_replay(
                root, key, "start", request_digest
            )
            if replay is not None:
                return replay
            spawned_here = False
            active_path = None
            try:
                location, path = _locate_identity(
                    root, identity["identity_hash"]
                )
                if location != "active":
                    _error("not_found" if location is None else "not_archived")
                active_path = path
                state = _load_state(path, identity["identity_hash"])
                if state["rappid"] != identity["rappid"]:
                    _error("identity_invalid")
                transaction = _transaction_load(
                    root, key, "start", request_digest
                )
                process_result = (
                    transaction.get("process_result")
                    if isinstance(transaction, dict)
                    and isinstance(
                        transaction.get("process_result"), dict
                    )
                    else None
                )
                _transition_phase(
                    root,
                    key,
                    "start",
                    request_digest,
                    identity["identity_hash"],
                    "spawn_intent",
                    model=model,
                    attestation_mode=attestation_mode,
                )
                def record_start_phase(phase, **values):
                    _transition_phase(
                        root,
                        key,
                        "start",
                        request_digest,
                        identity["identity_hash"],
                        phase,
                        model=model,
                        attestation_mode=attestation_mode,
                        **values,
                    )

                if process_result is None:
                    state, process_result = _start_locked(
                        root,
                        path,
                        state,
                        model,
                        attestation_mode,
                        github_token_file,
                        kwargs.get("port"),
                        record_start_phase,
                    )
                    spawned_here = not process_result.get(
                        "already_running", False
                    )
                    _transition_phase(
                        root,
                        key,
                        "start",
                        request_digest,
                        identity["identity_hash"],
                        "running",
                        process_result=process_result,
                        model=model,
                        attestation_mode=attestation_mode,
                    )
                else:
                    state = _reconcile_runtime(path, state)
                    if state.get("runtime_status") != "running":
                        state, process_result = _start_locked(
                            root,
                            path,
                            state,
                            model,
                            attestation_mode,
                            github_token_file,
                            kwargs.get("port"),
                            record_start_phase,
                        )
                        spawned_here = not process_result.get(
                            "already_running", False
                        )
                receipt_id = _receipt(
                    root,
                    "start",
                    identity,
                    state,
                    status="completed",
                    command_sha256=(
                        state.get("process") or {}
                    ).get("command_sha256"),
                    instance_id=(
                        state.get("process") or {}
                    ).get("instance_id"),
                    port=(state.get("process") or {}).get("port"),
                    model=model,
                    attestation_mode=attestation_mode,
                    signed_only=True,
                )
                result = {
                    "rappid": identity["rappid"],
                    "instance_rappid": state["instance_rappid"],
                    "product_rappid": state["product_rappid"],
                    "identity_hash": identity["identity_hash"],
                    "lifecycle_state": "active",
                    "receipt_id": receipt_id,
                    **process_result,
                }
                _transition_phase(
                    root,
                    key,
                    "start",
                    request_digest,
                    identity["identity_hash"],
                    "completed",
                    receipt_id=receipt_id,
                    result=result,
                )
                _idempotency_complete(
                    root, key, "start", request_digest, result
                )
                return result
            except (Exception, SystemExit) as error:
                if spawned_here and active_path is not None:
                    with contextlib.suppress(BaseException):
                        current = _load_state(
                            active_path, identity["identity_hash"]
                        )
                        current, _unused = _stop_locked(
                            active_path, current
                        )
                        failed = dict(current)
                        failed["last_start_failure"] = {
                            "code": _safe_exception_code(error),
                            "at": _utc_now(),
                        }
                        _write_state(active_path, failed)
                        _transition_phase(
                            root,
                            key,
                            "start",
                            request_digest,
                            identity["identity_hash"],
                            "spawn_cleanup",
                            result=None,
                            process_result=None,
                            failure_code=_safe_exception_code(error),
                        )
                _idempotency_failed(
                    root,
                    key,
                    "start",
                    request_digest,
                    _safe_exception_code(error),
                )
                raise

    def _stop(self, kwargs):
        root = _mutation_root("stop")
        identity = _identity_for_action(kwargs)
        key = _idempotency_key(kwargs)
        request_digest = _request_digest("stop", kwargs)
        with _controller_locks(root, identity["identity_hash"]):
            replay = _idempotency_begin(
                root, key, "stop", request_digest
            )
            if replay is not None:
                return replay
            replay = _completed_transaction_replay(
                root, key, "stop", request_digest
            )
            if replay is not None:
                return replay
            try:
                location, path = _locate_identity(
                    root, identity["identity_hash"]
                )
                if location != "active":
                    _error("not_found")
                state = _load_state(path, identity["identity_hash"])
                if state["rappid"] != identity["rappid"]:
                    _error("identity_invalid")
                transaction = _transaction_load(
                    root, key, "stop", request_digest
                )
                stop_result = (
                    transaction.get("stop_result")
                    if isinstance(transaction, dict)
                    and isinstance(transaction.get("stop_result"), dict)
                    else None
                )
                _transition_phase(
                    root,
                    key,
                    "stop",
                    request_digest,
                    identity["identity_hash"],
                    "stop_intent",
                )
                if stop_result is None:
                    state, stop_result = _stop_locked(path, state)
                    _transition_phase(
                        root,
                        key,
                        "stop",
                        request_digest,
                        identity["identity_hash"],
                        "stopped",
                        stop_result=stop_result,
                    )
                receipt_id = _receipt(
                    root,
                    "stop",
                    identity,
                    state,
                    status="completed",
                    escalated=stop_result["escalated"],
                )
                result = {
                    "rappid": identity["rappid"],
                    "instance_rappid": state["instance_rappid"],
                    "product_rappid": state["product_rappid"],
                    "identity_hash": identity["identity_hash"],
                    "lifecycle_state": "active",
                    "receipt_id": receipt_id,
                    **stop_result,
                }
                _transition_phase(
                    root,
                    key,
                    "stop",
                    request_digest,
                    identity["identity_hash"],
                    "completed",
                    receipt_id=receipt_id,
                    result=result,
                )
                _idempotency_complete(
                    root, key, "stop", request_digest, result
                )
                return result
            except (Exception, SystemExit) as error:
                _idempotency_failed(
                    root,
                    key,
                    "stop",
                    request_digest,
                    _safe_exception_code(error),
                )
                raise

    def _archive(self, kwargs):
        root = _mutation_root("archive")
        identity = _identity_for_action(kwargs)
        key = _idempotency_key(kwargs)
        request_digest = _request_digest("archive", kwargs)
        paths = _identity_paths(root, identity["identity_hash"])
        with _controller_locks(root, identity["identity_hash"]):
            replay = _idempotency_begin(
                root, key, "archive", request_digest
            )
            if replay is not None:
                return replay
            replay = _completed_transaction_replay(
                root, key, "archive", request_digest
            )
            if replay is not None:
                return replay
            try:
                transaction = _transaction_load(
                    root, key, "archive", request_digest
                )
                archive_exists = _safe_exists(
                    root, paths["archive"], expected="directory"
                )
                active_exists = _safe_exists(
                    root, paths["active"], expected="directory"
                )
                if archive_exists and transaction is None:
                    _error("archive_exists")
                if not archive_exists and not active_exists:
                    _error("not_found")
                current = (
                    paths["archive"] if archive_exists else paths["active"]
                )
                state = _load_state(
                    current, identity["identity_hash"]
                )
                if state["rappid"] != identity["rappid"]:
                    _error("identity_invalid")
                stop_result = (
                    transaction.get("stop_result")
                    if isinstance(transaction, dict)
                    and isinstance(transaction.get("stop_result"), dict)
                    else None
                )
                _transition_phase(
                    root,
                    key,
                    "archive",
                    request_digest,
                    identity["identity_hash"],
                    "stop_intent",
                )
                if not archive_exists:
                    _controller, pairing = _ensure_twin_transport(
                        root, paths["active"], state
                    )
                    if state.get("transport") != _transport_state(pairing):
                        state = dict(state)
                        state["transport"] = _transport_state(pairing)
                        state = _write_state(paths["active"], state)
                    if stop_result is None:
                        state, stop_result = _stop_locked(
                            paths["active"], state
                        )
                    archived = dict(state)
                    archived["lifecycle_state"] = "archived"
                    archived = _write_state(paths["active"], archived)
                    _transition_phase(
                        root,
                        key,
                        "archive",
                        request_digest,
                        identity["identity_hash"],
                        "state_archived",
                        stop_result=stop_result,
                    )
                    _safe_replace(
                        root, paths["active"], paths["archive"]
                    )
                    _transition_phase(
                        root,
                        key,
                        "archive",
                        request_digest,
                        identity["identity_hash"],
                        "promoted",
                        stop_result=stop_result,
                    )
                else:
                    archived = state
                    if stop_result is None:
                        stop_result = {
                            "already_stopped": True,
                            "escalated": False,
                        }
                receipt_id = _receipt(
                    root,
                    "archive",
                    identity,
                    archived,
                    status="completed",
                    stopped_first=not stop_result["already_stopped"],
                    escalated=stop_result["escalated"],
                )
                result = {
                    "status": "stopped",
                    "lifecycle_state": "archived",
                    "rappid": identity["rappid"],
                    "instance_rappid": archived["instance_rappid"],
                    "product_rappid": archived["product_rappid"],
                    "identity_hash": identity["identity_hash"],
                    "stopped_first": not stop_result["already_stopped"],
                    "receipt_id": receipt_id,
                }
                _transition_phase(
                    root,
                    key,
                    "archive",
                    request_digest,
                    identity["identity_hash"],
                    "completed",
                    receipt_id=receipt_id,
                    result=result,
                )
                _idempotency_complete(
                    root, key, "archive", request_digest, result
                )
                return result
            except (Exception, SystemExit) as error:
                _idempotency_failed(
                    root,
                    key,
                    "archive",
                    request_digest,
                    _safe_exception_code(error),
                )
                raise

    def _unarchive(self, kwargs):
        root = _mutation_root("unarchive")
        identity = _identity_for_action(kwargs)
        key = _idempotency_key(kwargs)
        request_digest = _request_digest("unarchive", kwargs)
        paths = _identity_paths(root, identity["identity_hash"])
        with _controller_locks(root, identity["identity_hash"]):
            replay = _idempotency_begin(
                root, key, "unarchive", request_digest
            )
            if replay is not None:
                return replay
            replay = _completed_transaction_replay(
                root, key, "unarchive", request_digest
            )
            if replay is not None:
                return replay
            try:
                transaction = _transaction_load(
                    root, key, "unarchive", request_digest
                )
                active_exists = _safe_exists(
                    root, paths["active"], expected="directory"
                )
                archive_exists = _safe_exists(
                    root, paths["archive"], expected="directory"
                )
                if active_exists and transaction is None:
                    _error("duplicate_identity")
                if not active_exists and not archive_exists:
                    _error("not_archived")
                current = (
                    paths["active"] if active_exists else paths["archive"]
                )
                state = _load_state(
                    current, identity["identity_hash"]
                )
                if state["rappid"] != identity["rappid"]:
                    _error("identity_invalid")
                if not active_exists:
                    _transition_phase(
                        root,
                        key,
                        "unarchive",
                        request_digest,
                        identity["identity_hash"],
                        "activate_intent",
                    )
                    active = dict(state)
                    active["lifecycle_state"] = "active"
                    active["runtime_status"] = "stopped"
                    active["process"] = None
                    active = _write_state(paths["archive"], active)
                    _transition_phase(
                        root,
                        key,
                        "unarchive",
                        request_digest,
                        identity["identity_hash"],
                        "state_active",
                    )
                    _safe_replace(
                        root, paths["archive"], paths["active"]
                    )
                    _transition_phase(
                        root,
                        key,
                        "unarchive",
                        request_digest,
                        identity["identity_hash"],
                        "promoted",
                    )
                else:
                    active = state
                receipt_id = _receipt(
                    root,
                    "unarchive",
                    identity,
                    active,
                    status="completed",
                    started=False,
                )
                result = {
                    "status": "stopped",
                    "lifecycle_state": "active",
                    "rappid": identity["rappid"],
                    "instance_rappid": active["instance_rappid"],
                    "product_rappid": active["product_rappid"],
                    "identity_hash": identity["identity_hash"],
                    "started": False,
                    "receipt_id": receipt_id,
                }
                _transition_phase(
                    root,
                    key,
                    "unarchive",
                    request_digest,
                    identity["identity_hash"],
                    "completed",
                    receipt_id=receipt_id,
                    result=result,
                )
                _idempotency_complete(
                    root, key, "unarchive", request_digest, result
                )
                return result
            except (Exception, SystemExit) as error:
                _idempotency_failed(
                    root,
                    key,
                    "unarchive",
                    request_digest,
                    _safe_exception_code(error),
                )
                raise

    def _purge(self, kwargs):
        root = _mutation_root("purge")
        identity = _identity_for_action(kwargs)
        if kwargs.get("confirmation") != identity["rappid"]:
            _error("confirmation_required")
        key = _idempotency_key(kwargs)
        request_digest = _request_digest("purge", kwargs)
        paths = _identity_paths(root, identity["identity_hash"])
        with _controller_locks(root, identity["identity_hash"]):
            replay = _idempotency_begin(
                root, key, "purge", request_digest
            )
            if replay is not None:
                return replay
            replay = _completed_transaction_replay(
                root, key, "purge", request_digest
            )
            if replay is not None:
                return replay
            try:
                transaction = _transaction_load(
                    root, key, "purge", request_digest
                )
                tombstone_exists = _safe_exists(
                    root, paths["purged"], expected="file"
                )
                if tombstone_exists and transaction is None:
                    _error("purged")
                quarantine = root / "staging" / (
                    "purge-"
                    + identity["identity_hash"]
                    + "-"
                    + hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
                )
                if transaction is None:
                    if not _safe_exists(
                        root, paths["archive"], expected="directory"
                    ):
                        _error("not_archived")
                    state = _load_state(
                        paths["archive"], identity["identity_hash"]
                    )
                    if (
                        state["rappid"] != identity["rappid"]
                        or state["runtime_status"] != "stopped"
                    ):
                        _error("not_archived")
                    transport = (
                        state.get("transport")
                        if isinstance(state.get("transport"), dict)
                        else {}
                    )
                    tombstone = {
                        "schema": _TOMBSTONE_SCHEMA,
                        "rappid": identity["rappid"],
                        "instance_rappid": state["instance_rappid"],
                        "product_rappid": state["product_rappid"],
                        "identity_hash": identity["identity_hash"],
                        "purged_at": _utc_now(),
                        "source_commit": state.get("source_commit"),
                        "source_tree_digest": state.get(
                            "source_tree_digest"
                        ),
                        "transport_key_id": transport.get(
                            "child_key_id"
                        ),
                        "transport_generation": transport.get(
                            "generation"
                        ),
                    }
                    receipt_state = {
                        "source_commit": state.get("source_commit"),
                        "source_tree_digest": state.get(
                            "source_tree_digest"
                        ),
                        "release_manifest_sha256": state.get(
                            "release_manifest_sha256"
                        ),
                        "instance_rappid": state["instance_rappid"],
                        "product_rappid": state["product_rappid"],
                    }
                    transaction = _transition_phase(
                        root,
                        key,
                        "purge",
                        request_digest,
                        identity["identity_hash"],
                        "quarantine_intent",
                        tombstone=tombstone,
                        receipt_state=receipt_state,
                        quarantine=quarantine.name,
                    )
                tombstone = transaction.get("tombstone")
                receipt_state = transaction.get("receipt_state")
                if (
                    not isinstance(tombstone, dict)
                    or not isinstance(receipt_state, dict)
                    or tombstone.get("rappid") != identity["rappid"]
                ):
                    _error("state_invalid")
                archive_exists = _safe_exists(
                    root, paths["archive"], expected="directory"
                )
                quarantine_exists = _safe_exists(
                    root, quarantine, expected="directory"
                )
                if (
                    not tombstone_exists
                    and archive_exists
                    and not quarantine_exists
                ):
                    _safe_replace(root, paths["archive"], quarantine)
                    quarantine_exists = True
                    archive_exists = False
                if archive_exists and quarantine_exists:
                    _error("state_invalid")
                if quarantine_exists:
                    _transition_phase(
                        root,
                        key,
                        "purge",
                        request_digest,
                        identity["identity_hash"],
                        "quarantined",
                        tombstone=tombstone,
                        receipt_state=receipt_state,
                        quarantine=quarantine.name,
                    )
                    sessions = root / "sessions" / identity["identity_hash"]
                    if _safe_exists(
                        root, sessions, expected="directory"
                    ):
                        _safe_remove_tree(root, sessions)
                    private_key = (
                        _twin_transport_directory(quarantine)
                        / "private.pem"
                    )
                    if _safe_exists(root, private_key, expected="file"):
                        _transport_secure_remove(private_key)
                    _safe_remove_tree(root, quarantine)
                _transition_phase(
                    root,
                    key,
                    "purge",
                    request_digest,
                    identity["identity_hash"],
                    "deleted",
                    tombstone=tombstone,
                    receipt_state=receipt_state,
                    quarantine=quarantine.name,
                )
                if not tombstone_exists:
                    _atomic_json(paths["purged"], tombstone)
                    tombstone_exists = True
                _transition_phase(
                    root,
                    key,
                    "purge",
                    request_digest,
                    identity["identity_hash"],
                    "tombstone_committed",
                    tombstone=tombstone,
                    receipt_state=receipt_state,
                    quarantine=quarantine.name,
                )
                receipt_id = _receipt(
                    root,
                    "purge",
                    identity,
                    receipt_state,
                    status="completed",
                    confirmation_matched=True,
                )
                result = {
                    "status": "stopped",
                    "lifecycle_state": "purged",
                    "rappid": identity["rappid"],
                    "instance_rappid": receipt_state[
                        "instance_rappid"
                    ],
                    "product_rappid": receipt_state["product_rappid"],
                    "identity_hash": identity["identity_hash"],
                    "tombstone": True,
                    "receipt_id": receipt_id,
                }
                _transition_phase(
                    root,
                    key,
                    "purge",
                    request_digest,
                    identity["identity_hash"],
                    "completed",
                    receipt_id=receipt_id,
                    result=result,
                    tombstone=tombstone,
                    receipt_state=receipt_state,
                )
                _idempotency_complete(
                    root, key, "purge", request_digest, result
                )
                return result
            except (Exception, SystemExit) as error:
                _idempotency_failed(
                    root,
                    key,
                    "purge",
                    request_digest,
                    _safe_exception_code(error),
                )
                raise

    def _rotate_keys(self, kwargs):
        root = _mutation_root("rotate_keys")
        identity = _identity_for_action(kwargs)
        key = _idempotency_key(kwargs)
        request_digest = _request_digest("rotate_keys", kwargs)
        paths = _identity_paths(root, identity["identity_hash"])
        with _controller_locks(root, identity["identity_hash"]):
            replay = _idempotency_begin(
                root, key, "rotate_keys", request_digest
            )
            if replay is not None:
                return replay
            replay = _completed_transaction_replay(
                root, key, "rotate_keys", request_digest
            )
            if replay is not None:
                return replay
            try:
                if not _safe_exists(
                    root, paths["active"], expected="directory"
                ):
                    _error("not_found")
                twin_directory = paths["active"]
                state = _load_state(
                    twin_directory, identity["identity_hash"]
                )
                if state["rappid"] != identity["rappid"]:
                    _error("identity_invalid")
                state = _reconcile_runtime(twin_directory, state)
                if state.get("runtime_status") != "stopped":
                    _error("not_stopped")
                transaction = _transaction_load(
                    root, key, "rotate_keys", request_digest
                )
                controller = _controller_transport(root)
                old_directory = _twin_transport_directory(
                    twin_directory
                )
                suffix = hashlib.sha256(
                    key.encode("utf-8")
                ).hexdigest()[:16]
                staged = old_directory.with_name(
                    ".twin-chat-rotation-" + suffix
                )
                retired = old_directory.with_name(
                    ".twin-chat-retired-" + suffix
                )
                if transaction is None:
                    controller, old_pairing = _ensure_twin_transport(
                        root, twin_directory, state
                    )
                    generation = old_pairing["generation"] + 1
                    if _safe_exists(root, staged, expected="directory"):
                        _safe_remove_tree(root, staged)
                    if _safe_exists(root, retired, expected="directory"):
                        _error("state_invalid")
                    new_pairing = _create_twin_transport(
                        staged, state, controller, generation
                    )
                    transaction = _transition_phase(
                        root,
                        key,
                        "rotate_keys",
                        request_digest,
                        identity["identity_hash"],
                        "staged",
                        old_pairing=old_pairing,
                        new_pairing=new_pairing,
                        generation=generation,
                    )
                old_pairing = transaction.get("old_pairing")
                new_pairing = transaction.get("new_pairing")
                generation = transaction.get("generation")
                if (
                    not isinstance(old_pairing, dict)
                    or not isinstance(new_pairing, dict)
                    or not isinstance(generation, int)
                    or isinstance(generation, bool)
                    or generation
                    != old_pairing.get("generation", 0) + 1
                    or new_pairing.get("generation") != generation
                ):
                    _error("state_invalid")
                current_exists = _safe_exists(
                    root, old_directory, expected="directory"
                )
                staged_exists = _safe_exists(
                    root, staged, expected="directory"
                )
                retired_exists = _safe_exists(
                    root, retired, expected="directory"
                )
                current_pairing = (
                    _read_json_file(
                        old_directory / "pairing.json", 32 * 1024
                    )
                    if current_exists
                    else None
                )
                switched = (
                    current_pairing == new_pairing
                    and state.get("transport")
                    == _transport_state(new_pairing)
                )
                if not switched:
                    _transition_phase(
                        root,
                        key,
                        "rotate_keys",
                        request_digest,
                        identity["identity_hash"],
                        "switch_intent",
                    )
                    if current_pairing == old_pairing:
                        if retired_exists:
                            _error("state_invalid")
                        _safe_replace(root, old_directory, retired)
                        retired_exists = True
                        current_exists = False
                    elif current_exists and current_pairing != new_pairing:
                        _error("state_invalid")
                    if not current_exists:
                        if not staged_exists:
                            _error("key_rotation_failed")
                        _safe_replace(root, staged, old_directory)
                        current_exists = True
                        staged_exists = False
                    current_pairing = _validate_twin_transport(
                        old_directory, state, controller
                    )
                    if current_pairing != new_pairing:
                        _error("key_rotation_failed")
                    _atomic_json(
                        twin_directory / "pairing.json", new_pairing
                    )
                    rotated = dict(state)
                    rotated["transport"] = _transport_state(new_pairing)
                    audit = list(
                        rotated.get("transport_key_audit", [])
                    )
                    if not any(
                        isinstance(item, dict)
                        and item.get("key_id")
                        == old_pairing["child_key_id"]
                        for item in audit
                    ):
                        audit.append(
                            {
                                "key_id": old_pairing["child_key_id"],
                                "retired_at": _utc_now(),
                                "reason": "guarded_rotation",
                            }
                        )
                    rotated["transport_key_audit"] = audit[-32:]
                    rotated = _write_state(
                        twin_directory, rotated
                    )
                    state = rotated
                    _transition_phase(
                        root,
                        key,
                        "rotate_keys",
                        request_digest,
                        identity["identity_hash"],
                        "switched",
                    )
                else:
                    rotated = state
                sessions = root / "sessions" / identity["identity_hash"]
                if _safe_exists(root, sessions, expected="directory"):
                    _safe_remove_tree(root, sessions)
                if _safe_exists(root, retired, expected="directory"):
                    retired_private = retired / "private.pem"
                    if _safe_exists(
                        root, retired_private, expected="file"
                    ):
                        _transport_secure_remove(retired_private)
                    _safe_remove_tree(root, retired)
                if _safe_exists(root, staged, expected="directory"):
                    staged_private = staged / "private.pem"
                    if _safe_exists(
                        root, staged_private, expected="file"
                    ):
                        _transport_secure_remove(staged_private)
                    _safe_remove_tree(root, staged)
                _transition_phase(
                    root,
                    key,
                    "rotate_keys",
                    request_digest,
                    identity["identity_hash"],
                    "cleaned",
                )
                receipt_id = _receipt(
                    root,
                    "rotate_keys",
                    identity,
                    rotated,
                    status="completed",
                    stopped_first=False,
                    old_child_key_id=old_pairing["child_key_id"],
                    new_child_key_id=new_pairing["child_key_id"],
                    generation=generation,
                    sessions_invalidated=True,
                    replay_trust_invalidated=True,
                    auto_started=False,
                )
                result = {
                    "status": "stopped",
                    "lifecycle_state": "active",
                    "rappid": identity["rappid"],
                    "instance_rappid": rotated["instance_rappid"],
                    "product_rappid": rotated["product_rappid"],
                    "identity_hash": identity["identity_hash"],
                    "old_child_key_id": old_pairing["child_key_id"],
                    "new_child_key_id": new_pairing["child_key_id"],
                    "generation": generation,
                    "sessions_invalidated": True,
                    "replay_trust_invalidated": True,
                    "auto_started": False,
                    "receipt_id": receipt_id,
                }
                _transition_phase(
                    root,
                    key,
                    "rotate_keys",
                    request_digest,
                    identity["identity_hash"],
                    "completed",
                    receipt_id=receipt_id,
                    result=result,
                )
                _idempotency_complete(
                    root,
                    key,
                    "rotate_keys",
                    request_digest,
                    result,
                )
                return result
            except (Exception, SystemExit) as error:
                _idempotency_failed(
                    root,
                    key,
                    "rotate_keys",
                    request_digest,
                    _safe_exception_code(error),
                )
                raise

    def _chat(self, kwargs):
        message = kwargs.get("message", kwargs.get("user_input"))
        audience = kwargs.get("audience", "local-owner")
        return self._signed_chat_action(
            kwargs,
            action="chat",
            message=message,
            audience=audience,
            facet="controller-chat",
            require_self_test=False,
        )

    def _self_test(self, kwargs):
        audience = kwargs.get("audience", "local-owner-self-test")
        prompt = (
            "Run the SelfTest agent with exactly action=run. Return a nonempty "
            "summary only after the tool completes."
        )
        return self._signed_chat_action(
            kwargs,
            action="self_test",
            message=prompt,
            audience=audience,
            facet="self-test",
            require_self_test=True,
        )

    def _signed_chat_action(
        self,
        kwargs,
        *,
        action,
        message,
        audience,
        facet,
        require_self_test,
    ):
        root = _mutation_root(action)
        identity = _identity_for_action(kwargs)
        key = _idempotency_key(kwargs)
        action_request_digest = _request_digest(action, kwargs)
        with _controller_locks(root, identity["identity_hash"]):
            replay = _idempotency_begin(
                root, key, action, action_request_digest
            )
            if replay is not None:
                replay.pop("idempotent_replay", None)
                return replay
            replay = _completed_transaction_replay(
                root, key, action, action_request_digest
            )
            if replay is not None:
                replay.pop("idempotent_replay", None)
                return replay
            try:
                location, path = _locate_identity(
                    root, identity["identity_hash"]
                )
                if location != "active":
                    _error("not_found")
                state = _load_state(path, identity["identity_hash"])
                if state["rappid"] != identity["rappid"]:
                    _error("identity_invalid")
                outcome = _chat_locked(
                    root,
                    path,
                    state,
                    message,
                    audience,
                    facet=facet,
                    action=action,
                    idempotency_key=key,
                    action_request_digest=action_request_digest,
                )
                status = outcome["status"]
                payload = outcome["payload"]
                instance_rappid = state["instance_rappid"]
                key_epoch = outcome["signed_request"]["key_epoch"]
                if status == "transport_changed":
                    result = {
                        "ok": False,
                        "rappid": identity["rappid"],
                        "instance_rappid": instance_rappid,
                        "key_epoch": key_epoch,
                        "identity_hash": identity["identity_hash"],
                        "terminal": True,
                        "signed_twin_chat": True,
                        "signed_twin_chat_verified": False,
                        "signed_twin_chat_status": "rejected",
                        "error": {
                            "code": "transport_epoch_changed",
                            "message": (
                                "The persisted request belongs to a retired "
                                "child key epoch and was not dispatched."
                            ),
                        },
                    }
                elif status == "rejected":
                    result = {
                        "ok": False,
                        "rappid": identity["rappid"],
                        "instance_rappid": instance_rappid,
                        "key_epoch": key_epoch,
                        "identity_hash": identity["identity_hash"],
                        "terminal": True,
                        "signed_twin_chat": True,
                        "signed_twin_chat_verified": True,
                        "signed_twin_chat_status": "rejected",
                        "error": {
                            "code": "child_rejected",
                            "message": (
                                "The signed child returned a terminal "
                                "rejection."
                            ),
                        },
                        "child_rejection": payload["error"],
                    }
                elif require_self_test:
                    logs = payload.get("agent_logs")
                    content = payload.get("response")
                    content_valid = (
                        isinstance(content, str)
                        and (
                            bool(content.strip())
                            or state.get("attestation_mode")
                            == _ATTESTATION_MODE
                        )
                    )
                    if (
                        not isinstance(logs, str)
                        or "[SelfTest] completed" not in logs.splitlines()
                        or not content_valid
                    ):
                        result = {
                            "ok": False,
                            "rappid": identity["rappid"],
                            "instance_rappid": instance_rappid,
                            "key_epoch": key_epoch,
                            "identity_hash": identity["identity_hash"],
                            "terminal": True,
                            "signed_twin_chat": True,
                            "signed_twin_chat_verified": True,
                            "signed_twin_chat_status": "verified",
                            "error": {
                                "code": "self_test_failed",
                                "message": _ERROR_MESSAGES[
                                    "self_test_failed"
                                ],
                            },
                            "child": payload,
                        }
                    else:
                        result = {
                            "ok": True,
                            "rappid": identity["rappid"],
                            "instance_rappid": instance_rappid,
                            "key_epoch": key_epoch,
                            "identity_hash": identity["identity_hash"],
                            "session_id": outcome["session_id"],
                            "session_created": outcome[
                                "session_created"
                            ],
                            "passed": True,
                            "proof": (
                                "SelfTest action=run completed through "
                                "signed POST /chat"
                            ),
                            "signed_twin_chat": True,
                            "signed_twin_chat_verified": True,
                            "signed_twin_chat_status": "verified",
                            "child": payload,
                        }
                else:
                    result = {
                        "ok": True,
                        "rappid": identity["rappid"],
                        "instance_rappid": instance_rappid,
                        "key_epoch": key_epoch,
                        "identity_hash": identity["identity_hash"],
                        "session_id": outcome["session_id"],
                        "session_created": outcome["session_created"],
                        "local_owner_direct": False,
                        "signed_twin_chat": True,
                        "signed_twin_chat_verified": True,
                        "signed_twin_chat_status": "verified",
                        "child": payload,
                    }
                _transition_phase(
                    root,
                    key,
                    action,
                    action_request_digest,
                    identity["identity_hash"],
                    "completed",
                    signed_request=outcome["signed_request"],
                    signed_response=outcome["signed_response"],
                    result=result,
                )
                _idempotency_complete(
                    root,
                    key,
                    action,
                    action_request_digest,
                    result,
                )
                return result
            except (Exception, SystemExit) as error:
                _idempotency_failed(
                    root,
                    key,
                    action,
                    action_request_digest,
                    _safe_exception_code(error),
                )
                raise
