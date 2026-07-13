"""Strict chat validation and bounded BasicAgent tool orchestration."""

from __future__ import annotations

import json
import hashlib
import inspect
import math
import os
import re
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

from ..protocols.canonical import (
    CanonicalJSONError,
    canonical_json_bytes,
    canonical_json_text,
    parse_canonical_wire,
    parse_json,
)
from ..protocols.crypto import (
    key_id_for_jwk,
    load_private_key,
    load_public_jwk,
    public_jwk_from_key,
)
from ..protocols.replay import ReplayJournal, ReplayJournalError
from ..protocols.twin_chat import (
    ProtocolError,
    VerifiedRequest,
    classify_protocol_text,
    sign_response,
    validate_freshness,
    verify_request,
)
from .config import SignedIngressConfig
from .provider import Provider, ProviderError, ProviderResponse, ToolCall
from .registry import AgentRegistry, RegistryLoadError, RegistrySnapshot

MAX_SOUL_BYTES: Final = 1024 * 1024
MAX_USER_INPUT_CHARS: Final = 1024 * 1024
MAX_HISTORY_ENTRIES: Final = 512
MAX_HISTORY_CONTENT_CHARS: Final = 1024 * 1024
MAX_TOOL_ARGUMENT_CHARS: Final = 1024 * 1024
MAX_TOOL_RESULT_CHARS: Final = 1024 * 1024
MAX_CHAT_RESULT_BYTES: Final = 1024 * 1024
MAX_SIGNED_OUTER_BYTES: Final = 2 * 1024 * 1024
MAX_TOOL_ROUNDS: Final = 3
VOICE_DELIMITER: Final = "|||VOICE|||"
_SESSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_RAPPID_RE = re.compile(
    r"^rappid:@[a-z0-9][a-z0-9-]{0,62}/"
    r"[a-z0-9][a-z0-9-]{0,127}:[0-9a-f]{64}$"
)
_REQUEST_KEYS = frozenset(
    {"user_input", "conversation_history", "session_id"}
)
_HISTORY_ROLES = frozenset({"user", "assistant", "tool"})
CONTROLLER_ROUTE_PREFIX: Final = "RAPP_CONTROLLER_ROUTE/1.0"
CONTROLLER_ROUTE_SCHEMA: Final = "rapp-controller-route/1.0"
CONTROLLER_TOOL_NAME: Final = "RappStackCubbyController"
_CONTROLLER_ACTION_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_CONTROLLER_KEY_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
)


class OrchestratorError(Exception):
    """Base class for deterministic orchestration failures."""


class RequestValidationError(OrchestratorError, ValueError):
    """Raised when a chat request violates the public wire contract."""


class SoulLoadError(OrchestratorError):
    """Raised when the configured soul cannot be loaded safely."""


class ContextCollectionError(OrchestratorError):
    """Raised when an agent's system context is invalid."""


class OrchestratorProviderError(OrchestratorError):
    """Redacted provider failure at the orchestration boundary."""


class SignedIngressConflictError(OrchestratorError):
    """Raised when a nonce is processing or bound to another digest."""


class AgentOutputError(OrchestratorError):
    """Raised when an agent returns text outside the bounded UTF-8 profile."""


def build_controller_chat_request(
    action: str,
    arguments: Mapping[str, Any],
    idempotency_key: str,
) -> dict[str, str]:
    """Build the sole canonical deterministic controller request for ``/chat``."""

    if (
        not isinstance(action, str)
        or _CONTROLLER_ACTION_RE.fullmatch(action) is None
        or not isinstance(idempotency_key, str)
        or _CONTROLLER_KEY_RE.fullmatch(idempotency_key) is None
        or not isinstance(arguments, Mapping)
        or "action" in arguments
        or "idempotency_key" in arguments
    ):
        raise RequestValidationError(
            "controller action, idempotency key, or arguments are invalid"
        )
    route = {
        "schema": CONTROLLER_ROUTE_SCHEMA,
        "tool": CONTROLLER_TOOL_NAME,
        "action": action,
        "arguments": dict(arguments),
        "idempotency_key": idempotency_key,
    }
    try:
        encoded = canonical_json_text(route)
    except CanonicalJSONError as error:
        raise RequestValidationError(
            "controller arguments must contain only canonical JSON values"
        ) from error
    return {"user_input": CONTROLLER_ROUTE_PREFIX + "\n" + encoded}


def _is_terminal_controller_rejection(value: Mapping[str, Any]) -> bool:
    error = value.get("error")
    if (
        value.get("ok") is not False
        or value.get("terminal") is not True
        or value.get("signed_twin_chat") is not True
        or value.get("signed_twin_chat_verified") is not True
        or value.get("signed_twin_chat_status") != "rejected"
        or not isinstance(value.get("instance_rappid"), str)
        or _RAPPID_RE.fullmatch(value["instance_rappid"]) is None
        or not isinstance(value.get("key_epoch"), int)
        or isinstance(value.get("key_epoch"), bool)
        or not 1 <= value["key_epoch"] <= 2**31 - 1
        or not isinstance(error, Mapping)
        or set(error) != {"code", "message"}
        or not isinstance(error.get("code"), str)
        or _CONTROLLER_ACTION_RE.fullmatch(error["code"]) is None
        or not isinstance(error.get("message"), str)
    ):
        return False
    try:
        return 1 <= len(error["message"].encode("utf-8")) <= 240
    except UnicodeEncodeError:
        return False


class Orchestrator:
    """Loads local context and executes at most three agent-call rounds."""

    def __init__(
        self,
        *,
        soul_path: str | os.PathLike[str],
        registry: AgentRegistry,
        provider: Provider,
        model: str,
        provider_timeout: float = 30.0,
        voice_mode: bool = False,
        max_soul_bytes: int = MAX_SOUL_BYTES,
        signed_ingress: SignedIngressConfig | None = None,
        signed_only: bool = False,
        controller_route_enabled: bool = False,
    ) -> None:
        self.soul_path = Path(soul_path)
        self.registry = registry
        self.provider = provider
        if not isinstance(model, str) or not model.strip():
            raise ValueError("model must be a non-empty string")
        self.model = model.strip()
        if (
            not isinstance(provider_timeout, (int, float))
            or isinstance(provider_timeout, bool)
            or not 0 < float(provider_timeout) <= 300
        ):
            raise ValueError("provider_timeout must be between 0 and 300 seconds")
        self.provider_timeout = float(provider_timeout)
        if not isinstance(voice_mode, bool):
            raise ValueError("voice_mode must be boolean")
        self.voice_mode = voice_mode
        if (
            not isinstance(max_soul_bytes, int)
            or isinstance(max_soul_bytes, bool)
            or max_soul_bytes < 1
        ):
            raise ValueError("max_soul_bytes must be a positive integer")
        self.max_soul_bytes = max_soul_bytes
        self._signed_ingress = (
            None
            if signed_ingress is None
            else _SignedIngressRuntime(
                signed_ingress,
                provider_timeout=self.provider_timeout,
            )
        )
        if not isinstance(signed_only, bool):
            raise ValueError("signed_only must be boolean")
        if not isinstance(controller_route_enabled, bool):
            raise ValueError("controller_route_enabled must be boolean")
        if signed_only and signed_ingress is None:
            raise ValueError("signed_only requires signed ingress")
        self.signed_only = signed_only
        self.controller_route_enabled = controller_route_enabled

    def chat(
        self,
        request: Mapping[str, Any],
        *,
        registry_snapshot: RegistrySnapshot | None = None,
    ) -> dict[str, Any]:
        """Validate a request and return the exact isolated chat result."""

        user_input, history, session_id = validate_chat_request(request)
        if user_input.startswith(CONTROLLER_ROUTE_PREFIX + "\n"):
            if not self.controller_route_enabled:
                raise RequestValidationError(
                    "deterministic controller routing is not enabled"
                )
            if set(request) != {"user_input"}:
                raise RequestValidationError(
                    "controller route request must contain only user_input"
                )
            return self._chat_controller_route(
                user_input,
                registry_snapshot=registry_snapshot,
            )
        try:
            claimed = classify_protocol_text(user_input)
        except ProtocolError as error:
            raise RequestValidationError(str(error)) from error
        if claimed is not None:
            if self._signed_ingress is None:
                raise RequestValidationError(
                    "signed twin-chat ingress is not configured"
                )
            if set(request) != {"user_input"}:
                raise RequestValidationError(
                    "signed twin-chat outer request must contain only user_input"
                )
            return self._chat_signed(
                claimed,
                registry_snapshot=registry_snapshot,
            )
        if self.signed_only:
            raise RequestValidationError(
                "plain chat is disabled by signed_only"
            )
        return self._execute_chat(
            user_input,
            history,
            session_id,
            registry_snapshot=registry_snapshot,
        )

    def _chat_controller_route(
        self,
        user_input: str,
        *,
        registry_snapshot: RegistrySnapshot | None,
    ) -> dict[str, Any]:
        encoded = user_input[len(CONTROLLER_ROUTE_PREFIX) + 1 :]
        if not encoded or "\n" in encoded:
            raise RequestValidationError(
                "controller route must contain one canonical JSON object"
            )
        try:
            route = parse_json(encoded)
        except CanonicalJSONError as error:
            raise RequestValidationError(
                "controller route JSON is invalid"
            ) from error
        if (
            not isinstance(route, Mapping)
            or set(route)
            != {
                "schema",
                "tool",
                "action",
                "arguments",
                "idempotency_key",
            }
            or route.get("schema") != CONTROLLER_ROUTE_SCHEMA
            or route.get("tool") != CONTROLLER_TOOL_NAME
            or canonical_json_text(route) != encoded
        ):
            raise RequestValidationError(
                "controller route envelope is invalid"
            )
        action = route.get("action")
        idempotency_key = route.get("idempotency_key")
        arguments = route.get("arguments")
        if (
            not isinstance(action, str)
            or _CONTROLLER_ACTION_RE.fullmatch(action) is None
            or not isinstance(idempotency_key, str)
            or _CONTROLLER_KEY_RE.fullmatch(idempotency_key) is None
            or not isinstance(arguments, Mapping)
            or "action" in arguments
            or "idempotency_key" in arguments
        ):
            raise RequestValidationError(
                "controller route action or arguments are invalid"
            )
        try:
            snapshot = (
                self.registry.load()
                if registry_snapshot is None
                else registry_snapshot
            )
        except RegistryLoadError:
            raise
        if (
            not isinstance(snapshot, RegistrySnapshot)
            or snapshot.names != (CONTROLLER_TOOL_NAME,)
        ):
            raise RequestValidationError(
                "controller route requires a controller-only registry"
            )
        agent = snapshot[CONTROLLER_TOOL_NAME]
        actions = (
            agent.metadata.get("parameters", {})
            .get("properties", {})
            .get("action", {})
            .get("enum", [])
        )
        if action not in actions:
            raise RequestValidationError(
                "controller route action is unsupported"
            )
        call_arguments = dict(arguments)
        call_arguments["action"] = action
        call_arguments["idempotency_key"] = idempotency_key
        try:
            argument_text = canonical_json_text(call_arguments)
        except CanonicalJSONError as error:
            raise RequestValidationError(
                "controller route arguments are not canonical JSON"
            ) from error
        request_digest = hashlib.sha256(
            user_input.encode("utf-8")
        ).hexdigest()
        result_text, logs = self._execute_tool(
            ToolCall(
                id="controller-" + request_digest[:32],
                name=CONTROLLER_TOOL_NAME,
                arguments=argument_text,
            ),
            snapshot,
        )
        if logs != (f"[{CONTROLLER_TOOL_NAME}] completed",):
            raise RequestValidationError(
                "controller route execution failed"
            )
        try:
            result = parse_json(result_text)
        except CanonicalJSONError as error:
            raise RequestValidationError(
                "controller returned invalid canonical JSON"
            ) from error
        if not isinstance(result, Mapping):
            raise RequestValidationError(
                "controller result must be an object"
            )
        canonical_result = canonical_json_text(result)
        result_digest = hashlib.sha256(
            canonical_result.encode("utf-8")
        ).hexdigest()
        response_text = canonical_result
        signed_verified = False
        proof_status = "ok" if result.get("ok") is True else "rejected"
        signed_status = "not_applicable"
        instance_rappid = result.get("instance_rappid")
        key_epoch = result.get("key_epoch")
        if action == "chat":
            child = result.get("child")
            if (
                result.get("ok") is True
                and result.get("signed_twin_chat") is True
                and result.get("signed_twin_chat_verified") is True
                and result.get("signed_twin_chat_status") == "verified"
                and isinstance(instance_rappid, str)
                and _RAPPID_RE.fullmatch(instance_rappid) is not None
                and instance_rappid == arguments.get("rappid")
                and isinstance(key_epoch, int)
                and not isinstance(key_epoch, bool)
                and 1 <= key_epoch <= 2**31 - 1
                and isinstance(child, Mapping)
                and isinstance(child.get("response"), str)
                and child["response"]
            ):
                response_text = child["response"]
                signed_verified = True
                signed_status = "verified"
                proof_status = "ok"
            elif _is_terminal_controller_rejection(result):
                signed_verified = True
                signed_status = "rejected"
                proof_status = "rejected"
            else:
                raise RequestValidationError(
                    "controller chat result is not a verified signed response"
                )
        elif not isinstance(result.get("ok"), bool):
            raise RequestValidationError(
                "controller result must contain an explicit ok status"
            )
        child_digest = hashlib.sha256(
            response_text.encode("utf-8")
        ).hexdigest()
        return {
            "response": response_text,
            "controller_result": dict(result),
            "session_id": "controller-" + request_digest[:32],
            "agent_logs": logs[0],
            "voice_mode": False,
            "model": "deterministic-controller-route/1.0",
            "requested_model": self.model,
            "result_proof": {
                "schema": "rapp-controller-result-proof/1.0",
                "algorithm": "sha256",
                "tool": CONTROLLER_TOOL_NAME,
                "action": action,
                "request_sha256": request_digest,
                "result_sha256": result_digest,
                "controller_result_sha256": result_digest,
                "child_response_sha256": child_digest,
                "signed_twin_chat_verified": signed_verified,
                "signed_twin_chat_status": signed_status,
                "instance_rappid": (
                    instance_rappid
                    if isinstance(instance_rappid, str)
                    else None
                ),
                "key_epoch": (
                    key_epoch
                    if isinstance(key_epoch, int)
                    and not isinstance(key_epoch, bool)
                    else None
                ),
                "status": proof_status,
            },
        }

    def _execute_chat(
        self,
        user_input: str,
        history: list[dict[str, str]],
        session_id: str,
        *,
        registry_snapshot: RegistrySnapshot | None = None,
    ) -> dict[str, Any]:
        try:
            snapshot = (
                self.registry.load()
                if registry_snapshot is None
                else registry_snapshot
            )
        except RegistryLoadError:
            raise
        if not isinstance(snapshot, RegistrySnapshot):
            raise RequestValidationError(
                "registry_snapshot must be a RegistrySnapshot"
            )

        soul = self.load_soul()
        contexts = self._collect_context(snapshot)
        system_content = _compose_system_content(
            soul,
            contexts,
            voice_mode=self.voice_mode,
        )
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_content},
            *history,
            {"role": "user", "content": user_input},
        ]
        tools = snapshot.tools
        logs: list[str] = []

        response = self._complete(messages, tools)
        responded_model = response.model or self.model
        rounds = 0
        while response.tool_calls and rounds < MAX_TOOL_ROUNDS:
            messages.append(_assistant_tool_message(response))
            for call in response.tool_calls:
                result, call_logs = self._execute_tool(call, snapshot)
                logs.extend(call_logs)
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call.id,
                        "name": call.name,
                        "content": result,
                    }
                )
            rounds += 1
            if rounds >= MAX_TOOL_ROUNDS:
                logs.append("[runtime] tool-call round limit reached")
                response = self._complete(messages, ())
            else:
                response = self._complete(messages, tools)
            responded_model = response.model or responded_model

        reply = response.content
        if VOICE_DELIMITER in reply:
            reply = reply.split(VOICE_DELIMITER, 1)[0].strip()

        agent_logs = "\n".join(logs)
        _validate_utf8_bound(
            reply, "provider response", maximum=MAX_CHAT_RESULT_BYTES
        )
        _validate_utf8_bound(
            agent_logs, "agent logs", maximum=MAX_CHAT_RESULT_BYTES
        )
        return {
            "response": reply,
            "session_id": session_id,
            "agent_logs": agent_logs,
            "voice_mode": self.voice_mode,
            "model": responded_model,
            "requested_model": self.model,
        }

    def _chat_signed(
        self,
        wrapper: Mapping[str, Any] | str | bytes,
        *,
        registry_snapshot: RegistrySnapshot | None,
    ) -> dict[str, Any]:
        ingress = self._signed_ingress
        if ingress is None:
            raise RequestValidationError(
                "signed twin-chat ingress is not configured"
            )
        try:
            verified = ingress.verify(wrapper)
            claim = ingress.journal.claim(
                verified.sender_rappid,
                verified.key_id,
                verified.nonce,
                verified.digest,
            )
            if claim.outcome == "replay":
                assert claim.response_json is not None
                return self._signed_outer(claim.response_json)
            if claim.outcome == "digest_conflict":
                raise SignedIngressConflictError(
                    "nonce is already bound to a different request"
                )
            if claim.outcome == "processing":
                raise SignedIngressConflictError(
                    "identical signed request is already processing"
                )
            if claim.outcome == "terminal_failure":
                return self._recover_signed_failure(ingress, verified)
            if claim.outcome == "ambiguous":
                return self._finish_signed_rejection(
                    ingress,
                    verified,
                    code="dispatch_ambiguous",
                    message=(
                        "A prior dispatch may have occurred; it will not be "
                        "repeated."
                    ),
                )
            if claim.outcome not in {"claimed", "reclaimed"}:
                raise ReplayJournalError(
                    "replay claim returned an invalid outcome"
                )
        except SignedIngressConflictError:
            raise
        except (
            CanonicalJSONError,
            ProtocolError,
            ReplayJournalError,
        ) as error:
            raise RequestValidationError(str(error)) from error

        try:
            validate_freshness(
                verified.inner["utc"],
                freshness_seconds=ingress.config.freshness_seconds,
            )
        except Exception:
            return self._finish_signed_rejection(
                ingress,
                verified,
                code="request_stale",
                message=(
                    "The accepted request is no longer fresh enough for a "
                    "new dispatch."
                ),
            )

        try:
            ingress.journal.mark_dispatched(
                verified.sender_rappid,
                verified.key_id,
                verified.nonce,
                verified.digest,
            )
            payload = verified.payload
            child_result = self._execute_chat(
                payload["user_input"],
                [
                    {"role": item["role"], "content": item["content"]}
                    for item in payload.get("conversation_history", [])
                ],
                payload.get("session_id", str(uuid.uuid4())),
                registry_snapshot=registry_snapshot,
            )
            log_lines = child_result["agent_logs"].splitlines()
            if any(
                " failed (" in line or line.endswith(" unavailable")
                for line in log_lines
            ):
                raise OrchestratorProviderError(
                    "signed tool dispatch did not complete safely"
                )
            signed = ingress.sign(verified, "ok", child_result)
            response_json = canonical_json_text(signed)
            outer = self._signed_outer(response_json)
            self._validate_signed_outer(outer)
            ingress.journal.finish(
                verified.sender_rappid,
                verified.key_id,
                verified.nonce,
                verified.digest,
                response_json,
            )
            return outer
        except Exception:
            return self._finish_signed_rejection(ingress, verified)

    def _finish_signed_rejection(
        self,
        ingress: "_SignedIngressRuntime",
        verified: VerifiedRequest,
        *,
        recover_failed: bool = False,
        code: str = "child_dispatch_failed",
        message: str = "The child could not complete the accepted request.",
    ) -> dict[str, Any]:
        try:
            rejection = ingress.sign(
                verified,
                "rejected",
                {
                    "error": {
                        "code": code,
                        "message": message,
                    }
                },
            )
            response_json = canonical_json_text(rejection)
            outer = self._signed_outer(response_json)
            self._validate_signed_outer(outer)
            if recover_failed:
                ingress.journal.recover_failed(
                    verified.sender_rappid,
                    verified.key_id,
                    verified.nonce,
                    verified.digest,
                    response_json,
                )
            else:
                ingress.journal.finish(
                    verified.sender_rappid,
                    verified.key_id,
                    verified.nonce,
                    verified.digest,
                    response_json,
                    rejected=True,
                )
            return outer
        except Exception as error:
            try:
                current = ingress.journal.lookup(
                    verified.sender_rappid,
                    verified.key_id,
                    verified.nonce,
                    verified.digest,
                )
                if current.outcome == "replay":
                    assert current.response_json is not None
                    outer = self._signed_outer(current.response_json)
                    self._validate_signed_outer(outer)
                    return outer
                if current.outcome != "terminal_failure":
                    ingress.journal.fail(
                        verified.sender_rappid,
                        verified.key_id,
                        verified.nonce,
                        verified.digest,
                    )
            except Exception:
                pass
            raise OrchestratorProviderError(
                "signed request reached a durable terminal failure"
            ) from error

    def _recover_signed_failure(
        self,
        ingress: "_SignedIngressRuntime",
        verified: VerifiedRequest,
    ) -> dict[str, Any]:
        return self._finish_signed_rejection(
            ingress,
            verified,
            recover_failed=True,
            code="terminal_recovery",
            message=(
                "The prior dispatch ended without a storable response and "
                "will not be repeated."
            ),
        )

    @staticmethod
    def _validate_signed_outer(value: Mapping[str, Any]) -> None:
        try:
            encoded = canonical_json_bytes(dict(value))
        except CanonicalJSONError as error:
            raise OrchestratorProviderError(
                "signed response is outside the runtime response profile"
            ) from error
        if len(encoded) > MAX_SIGNED_OUTER_BYTES:
            raise OrchestratorProviderError(
                "signed response exceeds the runtime response profile"
            )

    def _signed_outer(self, response_json: str) -> dict[str, Any]:
        signed = parse_canonical_wire(response_json)
        payload = signed.get("payload", {}) if isinstance(signed, dict) else {}
        if signed.get("status") == "ok" and isinstance(payload, dict):
            return {
                "response": response_json,
                "session_id": payload["session_id"],
                "agent_logs": payload["agent_logs"],
                "voice_mode": payload["voice_mode"],
                "model": payload["model"],
                "requested_model": payload["requested_model"],
            }
        return {
            "response": response_json,
            "session_id": "signed-rejection",
            "agent_logs": "",
            "voice_mode": self.voice_mode,
            "model": self.model,
            "requested_model": self.model,
        }

    handle_chat = chat

    def load_soul(self) -> str:
        """Read the configured soul afresh without following a replaced symlink."""

        if self.soul_path.is_symlink():
            raise SoulLoadError("configured soul must not be a symbolic link")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.soul_path, flags)
        except OSError as error:
            raise SoulLoadError("configured soul cannot be opened") from error
        try:
            size = os.fstat(descriptor).st_size
            if size > self.max_soul_bytes:
                raise SoulLoadError("configured soul exceeds the size limit")
            chunks: list[bytes] = []
            remaining = self.max_soul_bytes + 1
            while remaining:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > self.max_soul_bytes:
                raise SoulLoadError("configured soul exceeds the size limit")
        except OSError as error:
            raise SoulLoadError("configured soul cannot be read") from error
        finally:
            os.close(descriptor)
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise SoulLoadError("configured soul must be UTF-8") from error

    def _collect_context(self, snapshot: RegistrySnapshot) -> tuple[str, ...]:
        contexts: list[str] = []
        total = 0
        for name, agent in snapshot.items():
            try:
                context = agent.system_context()
            except (Exception, SystemExit) as error:
                raise ContextCollectionError(
                    f"agent {name!r} could not provide system context "
                    f"({type(error).__name__})"
                ) from error
            if context is None or context == "":
                continue
            if not isinstance(context, str):
                raise ContextCollectionError(
                    f"agent {name!r} system_context must return a string or None"
                )
            total += len(context)
            if total > MAX_SOUL_BYTES:
                raise ContextCollectionError(
                    "combined agent system context exceeds the size limit"
                )
            contexts.append(context)
        return tuple(contexts)

    def _complete(
        self,
        messages: list[dict[str, Any]],
        tools: tuple[dict[str, Any], ...],
    ) -> ProviderResponse:
        try:
            response = self.provider.complete(
                messages,
                tools=tools,
                model=self.model,
                timeout=self.provider_timeout,
            )
        except ProviderError as error:
            raise OrchestratorProviderError(
                f"provider request failed ({type(error).__name__})"
            ) from error
        if not isinstance(response, ProviderResponse):
            raise OrchestratorProviderError(
                "provider returned an unsupported response type"
            )
        return response

    def _execute_tool(
        self,
        call: ToolCall,
        snapshot: RegistrySnapshot,
    ) -> tuple[str, tuple[str, ...]]:
        logs: list[str] = []
        try:
            if len(call.arguments) > MAX_TOOL_ARGUMENT_CHARS:
                raise json.JSONDecodeError("too large", call.arguments, 0)
            arguments = json.loads(call.arguments)
        except (json.JSONDecodeError, RecursionError):
            arguments = {}
            logs.append(f"[{call.name}] malformed arguments; used empty object")
        if not isinstance(arguments, dict):
            arguments = {}
            logs.append(f"[{call.name}] non-object arguments; used empty object")

        agent = snapshot.get(call.name)
        if agent is None:
            logs.append(f"[{call.name}] unavailable")
            return (
                f"ERROR: tool {call.name!r} is not registered.",
                tuple(logs),
            )

        try:
            result = agent.perform(**arguments)
            if inspect.isawaitable(result):
                if inspect.iscoroutine(result):
                    result.close()
                raise AgentOutputError(
                    "agent returned an awaitable instead of synchronous output"
                )
            result_text = _tool_result_text(result)
        except (Exception, SystemExit) as error:
            error_type = type(error).__name__
            logs.append(f"[{call.name}] failed ({error_type})")
            return (
                f"ERROR: tool {call.name!r} raised {error_type}.",
                tuple(logs),
            )
        logs.append(f"[{call.name}] completed")
        return result_text, tuple(logs)


def validate_chat_request(
    request: Mapping[str, Any],
) -> tuple[str, list[dict[str, str]], str]:
    """Validate and normalize only the public chat fields."""

    if not isinstance(request, Mapping):
        raise RequestValidationError("chat request must be a JSON object")
    unknown = sorted(set(request) - _REQUEST_KEYS)
    if unknown:
        raise RequestValidationError(
            "chat request contains unsupported fields: " + ", ".join(unknown)
        )
    if "user_input" not in request:
        raise RequestValidationError("user_input is required")
    user_input = request["user_input"]
    if not isinstance(user_input, str) or not user_input.strip():
        raise RequestValidationError("user_input must be a non-empty string")
    if len(user_input) > MAX_USER_INPUT_CHARS:
        raise RequestValidationError("user_input exceeds the size limit")

    raw_history = request.get("conversation_history", [])
    if not isinstance(raw_history, list):
        raise RequestValidationError("conversation_history must be an array")
    if len(raw_history) > MAX_HISTORY_ENTRIES:
        raise RequestValidationError("conversation_history has too many entries")
    history: list[dict[str, str]] = []
    total_history = 0
    for index, entry in enumerate(raw_history):
        if not isinstance(entry, Mapping):
            raise RequestValidationError(
                f"conversation_history[{index}] must be an object"
            )
        if set(entry) != {"role", "content"}:
            raise RequestValidationError(
                f"conversation_history[{index}] must contain only role and content"
            )
        role = entry.get("role")
        content = entry.get("content")
        if role not in _HISTORY_ROLES:
            raise RequestValidationError(
                f"conversation_history[{index}].role is invalid"
            )
        if not isinstance(content, str):
            raise RequestValidationError(
                f"conversation_history[{index}].content must be a string"
            )
        total_history += len(content)
        if total_history > MAX_HISTORY_CONTENT_CHARS:
            raise RequestValidationError(
                "conversation_history content exceeds the size limit"
            )
        history.append({"role": role, "content": content})

    if "session_id" not in request:
        session_id = str(uuid.uuid4())
    else:
        supplied_session = request["session_id"]
        if (
            not isinstance(supplied_session, str)
            or not _SESSION_RE.fullmatch(supplied_session)
        ):
            raise RequestValidationError(
                "session_id must be a safe non-empty string of at most 128 characters"
            )
        session_id = supplied_session
    return user_input, history, session_id


def _compose_system_content(
    soul: str,
    contexts: tuple[str, ...],
    *,
    voice_mode: bool,
) -> str:
    sections = [soul.rstrip()]
    sections.extend(context.strip() for context in contexts if context.strip())
    if voice_mode:
        sections.append(
            "Provide a full response, then the delimiter "
            f"{VOICE_DELIMITER}, then a short spoken version."
        )
    return "\n\n".join(section for section in sections if section)


def _assistant_tool_message(response: ProviderResponse) -> dict[str, Any]:
    return {
        "role": "assistant",
        "content": response.content,
        "tool_calls": [call.as_openai() for call in response.tool_calls],
    }


def _tool_result_text(value: Any) -> str:
    if isinstance(value, str):
        result = value
    elif value is None:
        result = ""
    else:
        try:
            result = json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
            )
        except (TypeError, ValueError):
            result = str(value)
    try:
        encoded = result.encode("utf-8")
    except UnicodeEncodeError as error:
        raise AgentOutputError(
            "agent output contains an invalid Unicode scalar"
        ) from error
    if len(encoded) > MAX_TOOL_RESULT_CHARS:
        result = _truncate_utf8(result, MAX_TOOL_RESULT_CHARS - 3) + "…"
    return result


def _truncate_utf8(value: str, maximum: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= maximum:
        return value
    return encoded[:maximum].decode("utf-8", "ignore")


def _validate_utf8_bound(value: object, label: str, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise OrchestratorProviderError(f"{label} must be text")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise OrchestratorProviderError(
            f"{label} contains an invalid Unicode scalar"
        ) from error
    if size > maximum:
        raise OrchestratorProviderError(f"{label} exceeds the size limit")
    return value


class _SignedIngressRuntime:
    __slots__ = (
        "config",
        "child_private_key",
        "child_public_jwk",
        "controller_public_jwk",
        "journal",
    )

    def __init__(
        self,
        config: SignedIngressConfig,
        *,
        provider_timeout: float,
    ) -> None:
        self.config = config
        self.child_private_key = load_private_key(
            config.child_private_key_path
        )
        self.child_public_jwk = public_jwk_from_key(self.child_private_key)
        self.controller_public_jwk = load_public_jwk(
            config.paired_controller_public_jwk_path
        )
        controller_key_id = key_id_for_jwk(self.controller_public_jwk)
        if config.paired_controller_rappid.rsplit(":", 1)[-1] != controller_key_id:
            raise ValueError(
                "paired controller RAPPID is not bound to its public JWK"
            )
        lease_seconds = min(
            3600,
            max(
                60,
                math.ceil(provider_timeout * (MAX_TOOL_ROUNDS + 1) + 30),
            ),
        )
        self.journal = ReplayJournal(
            config.replay_db_path,
            key_epoch=config.key_epoch,
            lease_seconds=lease_seconds,
        )

    def verify(
        self, wrapper: Mapping[str, Any] | str | bytes
    ) -> VerifiedRequest:
        return verify_request(
            wrapper,
            paired_public_jwk=self.controller_public_jwk,
            paired_controller_rappid=self.config.paired_controller_rappid,
            twin_rappid=self.config.twin_rappid,
            freshness_seconds=self.config.freshness_seconds,
            enforce_freshness=False,
            expected_key_epoch=self.config.key_epoch,
        )

    def sign(
        self,
        request: VerifiedRequest,
        status: str,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        return sign_response(
            private_key=self.child_private_key,
            child_public_jwk=self.child_public_jwk,
            from_rappid=self.config.twin_rappid,
            to_rappid=self.config.paired_controller_rappid,
            request_nonce=request.nonce,
            request_digest_value=request.digest,
            status=status,
            payload=payload,
            key_epoch=request.key_epoch,
        )
