"""Read-only content-free inspection of the private owner iMessage edge."""

import json
import os
import stat
import time
from pathlib import Path

from agents.basic_agent import BasicAgent


__manifest__ = {
    "schema": "rapp-agent/1.0",
    "name": "IMessage",
    "version": "1.0.1",
    "description": "Report content-free iMessage lifecycle and transport readiness.",
    "actions": ["status", "preflight", "tutorial", "transport"],
    "capability_ids": [],
    "mutability": "read_only",
    "enabled_by_default": True,
    "provenance": "original_new",
    "dependencies": ["python-stdlib", "BasicAgent"],
}

_PINNED_VERSION = "0.12.3"
_STATUS_KEYS = {
    "controller_ready",
    "dropped",
    "failed",
    "heartbeat_at",
    "imsg_version",
    "lifecycle",
    "pending",
    "processed",
    "read_ready",
    "ready",
    "restart_count",
    "send_ready",
    "transport_ready",
}


def _response(action, *, ok=True, **values):
    payload = {"action": action, "agent": "IMessage", "ok": ok}
    payload.update(values)
    return json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _private_json(environment_name):
    raw = os.environ.get(environment_name)
    if not raw:
        raise ValueError("explicit private input is required")
    path = Path(raw)
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("private input is unsafe")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.is_symlink():
            raise ValueError("private input is unsafe")
    info = path.stat()
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_size > 256 * 1024
    ):
        raise ValueError("private input is unsafe")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("private input is invalid")
    return value


def _facts():
    status = _private_json("RAPP_STACK_IMESSAGE_STATUS")
    if set(status) - _STATUS_KEYS:
        raise ValueError("status contains unsupported values")
    lifecycle = status.get("lifecycle")
    if lifecycle not in {"starting", "running", "stopped", "failed"}:
        lifecycle = "unavailable"
    counters = {}
    for name in ("processed", "dropped", "failed", "pending", "restart_count"):
        value = status.get(name)
        counters[name] = (
            value
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0
            else 0
        )
    heartbeat = status.get("heartbeat_at")
    heartbeat_fresh = (
        isinstance(heartbeat, (int, float))
        and not isinstance(heartbeat, bool)
        and 0 <= time.time() - float(heartbeat) < 20
    )
    configured = (
        status.get("imsg_version") == _PINNED_VERSION
        and lifecycle != "unavailable"
    )
    transport_ready = (
        status.get("transport_ready") is True
        if isinstance(status.get("transport_ready"), bool)
        else status.get("read_ready") is True
    )
    return {
        **counters,
        "configured": configured,
        "heartbeat_fresh": heartbeat_fresh,
        "imsg_version": _PINNED_VERSION,
        "lifecycle": lifecycle,
        "controller_ready": (
            status.get("controller_ready")
            if isinstance(status.get("controller_ready"), bool)
            else None
        ),
        "read_ready": transport_ready,
        "ready": status.get("ready") is True and heartbeat_fresh,
        "send_ready": (
            status.get("send_ready")
            if isinstance(status.get("send_ready"), bool)
            else None
        ),
        "transport_ready": transport_ready,
    }


class IMessage(BasicAgent):
    """Return only redacted lifecycle facts from explicit private files."""

    name = "IMessage"
    metadata = {
        "name": "IMessage",
        "description": "Inspect content-free owner iMessage bridge readiness.",
        "parameters": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["status", "preflight", "tutorial", "transport"],
                }
            },
            "required": ["action"],
            "additionalProperties": False,
        },
    }

    def perform(self, **kwargs):
        action = kwargs.get("action")
        if action not in __manifest__["actions"]:
            return _response(
                str(action or ""),
                ok=False,
                error={
                    "code": "invalid_action",
                    "message": "Unsupported action.",
                },
            )
        try:
            facts = _facts()
        except Exception:
            return _response(
                action,
                ok=False,
                configured=False,
                heartbeat_fresh=False,
                imsg_version=_PINNED_VERSION,
                lifecycle="unavailable",
                controller_ready=None,
                read_ready=False,
                ready=False,
                send_ready=None,
                transport_ready=False,
            )
        if action == "tutorial":
            return _response(
                action,
                config_private=True,
                dedicated_account_recommended=True,
                full_disk_access_required=True,
                imsg_version=_PINNED_VERSION,
                launch_agent_optional=True,
                lifecycle=facts["lifecycle"],
                owner_enrollment_required=True,
            )
        if action == "preflight":
            return _response(
                action,
                configured=facts["configured"],
                heartbeat_fresh=facts["heartbeat_fresh"],
                imsg_version=facts["imsg_version"],
                lifecycle=facts["lifecycle"],
                controller_ready=facts["controller_ready"],
                read_ready=facts["read_ready"],
                ready=facts["ready"],
                send_ready=facts["send_ready"],
                transport_ready=facts["transport_ready"],
            )
        if action == "transport":
            return _response(
                action,
                imsg_version=facts["imsg_version"],
                lifecycle=facts["lifecycle"],
                controller_ready=facts["controller_ready"],
                read_ready=facts["read_ready"],
                ready=facts["ready"],
                restart_count=facts["restart_count"],
                send_ready=facts["send_ready"],
                transport_ready=facts["transport_ready"],
            )
        return _response(action, **facts)
