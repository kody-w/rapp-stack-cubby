from __future__ import annotations

import shutil
import uuid
import os
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path

from rapp_stack_cubby.imessage.config import IMessageConfig, write_config


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SYNTHETIC_RAPPID = (
    "rappid:@sample-owner/sample-twin:"
    "0000000000000000000000000000000000000000000000000000000000000000"
)


class WorkDirectory:
    def __init__(self) -> None:
        self.path = REPOSITORY_ROOT / f".test-imessage-{uuid.uuid4().hex}"

    def __enter__(self) -> Path:
        self.path.mkdir(mode=0o700)
        return self.path

    def __exit__(self, exc_type, exc, traceback) -> None:
        shutil.rmtree(self.path, ignore_errors=True)


def config_payload(root: Path, **overrides: object) -> dict[str, object]:
    auth_dir = root / "controller-auth"
    auth_dir.mkdir(mode=0o700, exist_ok=True)
    os.chmod(auth_dir, 0o700)
    auth_token = auth_dir / "controller-auth.token"
    if not auth_token.exists():
        auth_token.write_bytes(b"\x42" * 32)
        os.chmod(auth_token, 0o600)
    value: dict[str, object] = {
        "account_id": "primary-account",
        "allowed_dm_handles": [],
        "allowed_group_chat_ids": [],
        "attachments_enabled": False,
        "config_path": str(root / "config.json"),
        "controller_auth_token_file": str(auth_token),
        "controller_timeout_seconds": 5.0,
        "global_controller_url": "http://127.0.0.1:8756/chat",
        "group_aliases": {},
        "groups_enabled": False,
        "identity_links": {},
        "imsg_path": str(root / "tools" / "bin" / "imsg"),
        "imsg_version": "0.12.3",
        "max_message_chars": 4096,
        "max_response_chars": 4096,
        "mention_required": False,
        "mention_tokens": [],
        "owner_chat_ids": ["synthetic-owner-chat"],
        "owner_handles": ["synthetic-owner-handle"],
        "rappter_instance_id": "synthetic-instance",
        "reactions_enabled": False,
        "reply_prefix": "",
        "request_timeout_seconds": 1.0,
        "restart_initial_seconds": 0.05,
        "restart_max_seconds": 0.1,
        "schema": "rapp-imessage-config/1.0",
        "sms_fallback": False,
        "stale_after_seconds": 900.0,
        "state_dir": str(root / "state"),
        "target_rappid": SYNTHETIC_RAPPID,
        "worker_count": 1,
    }
    value.update(overrides)
    return value


def make_config(root: Path, **overrides: object) -> IMessageConfig:
    value = config_payload(root, **overrides)
    return write_config(root / "config.json", value)


def global_response(
    text: str = "synthetic child response",
    *,
    session_id: str = "synthetic-session",
    logs: str = "[RappStackCubbyController] completed",
    request_sha256: str = "a" * 64,
    instance_rappid: str = SYNTHETIC_RAPPID,
) -> dict[str, object]:
    controller_result = {
        "action": "chat",
        "agent": "RappStackCubbyController",
        "child": {"response": text},
        "instance_rappid": instance_rappid,
        "key_epoch": 1,
        "ok": True,
        "rappid": instance_rappid,
        "signed_twin_chat": True,
        "signed_twin_chat_status": "verified",
        "signed_twin_chat_verified": True,
    }
    canonical_result = json.dumps(
        controller_result,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    result_sha256 = hashlib.sha256(canonical_result.encode()).hexdigest()
    return {
        "agent_logs": logs,
        "controller_result": controller_result,
        "model": "synthetic-model",
        "requested_model": "synthetic-model",
        "response": text,
        "result_proof": {
            "schema": "rapp-controller-result-proof/1.0",
            "algorithm": "sha256",
            "tool": "RappStackCubbyController",
            "action": "chat",
            "request_sha256": request_sha256,
            "result_sha256": result_sha256,
            "controller_result_sha256": result_sha256,
            "child_response_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "signed_twin_chat_verified": True,
            "signed_twin_chat_status": "verified",
            "instance_rappid": instance_rappid,
            "key_epoch": 1,
            "status": "ok",
        },
        "session_id": session_id,
        "voice_mode": False,
    }


def global_response_for_call(
    text: str,
    context: Mapping[str, object],
    **overrides: object,
) -> dict[str, object]:
    request = context.get("route_request")
    if not isinstance(request, str):
        raise AssertionError("test route request is unavailable")
    return global_response(
        text,
        request_sha256=hashlib.sha256(request.encode()).hexdigest(),
        **overrides,
    )


def owner_event(
    rowid: int,
    *,
    guid: str | None = None,
    text: str = "synthetic owner turn",
    **overrides: object,
) -> dict[str, object]:
    value: dict[str, object] = {
        "attachments": [],
        "chat_id": "synthetic-owner-chat",
        "created_at": "",
        "guid": guid or f"synthetic-guid-{rowid}",
        "id": rowid,
        "is_from_me": True,
        "is_group": False,
        "participants": ["synthetic-owner-handle"],
        "reactions": [],
        "sender": "synthetic-owner-handle",
        "service": "imessage",
        "text": text,
    }
    value.update(overrides)
    return value


class FakeSupervisor:
    def __init__(self, result: object | BaseException | None = None) -> None:
        self.is_ready = True
        self.restart_count = 0
        self.last_error = None
        self.result = {"ok": True, "guid": "synthetic-outbound-guid"} if result is None else result
        self.requests: list[tuple[str, dict[str, object], float | None]] = []
        self.started = False

    def request(self, method, params=None, timeout=None):
        self.requests.append((method, dict(params or {}), timeout))
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result

    def start(self) -> None:
        self.started = True

    def stop(self) -> None:
        self.started = False

    def restart(self) -> None:
        self.restart_count += 1
