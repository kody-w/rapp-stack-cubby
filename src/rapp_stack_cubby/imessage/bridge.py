"""Owner-only Messages-to-global-controller bridge.

Adapted from ``python/openrappter/imessage/service.py`` at the pinned
OpenRappter commit recorded in ``PROVENANCE.json``.  This profile deliberately
removes group, external-DM, mention, consent, and direct-child behavior.
"""

from __future__ import annotations

import datetime as _datetime
import hashlib
import hmac
import http.client
import json
import logging
import os
import re
import threading
import time
import urllib.parse
import uuid
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from ..protocols.canonical import CanonicalJSONError, canonical_json_text
from .config import IMSG_PINNED_VERSION, IMessageConfig, normalize_handle
from .rpc import (
    ImsgRpcAmbiguous,
    ImsgRpcClient,
    ImsgRpcError,
    ImsgRpcNotSent,
    ImsgRpcSupervisor,
)
from .state import IMessageState, StateError
from .tooling import verify_installed_imsg


_SESSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_EVENT_KEYS = frozenset(
    {
        "account_id",
        "associated_message_guid",
        "associated_message_type",
        "attachments",
        "chat_guid",
        "chat_id",
        "chat_identifier",
        "created_at",
        "date",
        "guid",
        "id",
        "is_from_me",
        "is_group",
        "item_type",
        "participants",
        "reactions",
        "sender",
        "service",
        "text",
    }
)
_GLOBAL_RESPONSE_KEYS = frozenset(
    {
        "agent_logs",
        "controller_result",
        "model",
        "requested_model",
        "response",
        "result_proof",
        "session_id",
        "voice_mode",
    }
)
_CONTROLLER_COMPLETION = "[RappStackCubbyController] completed"
_ACCOUNT_REVALIDATE_SECONDS = 30.0

ChatRunner = Callable[
    [str, list[dict[str, str]], str, Mapping[str, Any]],
    Mapping[str, Any],
]


class IMessageBridgeError(RuntimeError):
    """Raised when the bridge cannot continue safely."""


IMessageServiceError = IMessageBridgeError


class GlobalChatError(IMessageBridgeError):
    """Raised when the global controller route is absent or invalid."""


class _RejectedEvent(IMessageBridgeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _identifier_present(value: object) -> bool:
    return (
        isinstance(value, (str, int))
        and not isinstance(value, bool)
        and str(value) != ""
    )


class LoopbackGlobalChatRunner:
    """Call only the configured clean global runtime's loopback ``POST /chat``."""

    def __init__(self, config: IMessageConfig) -> None:
        self.config = config

    def __call__(
        self,
        prompt: str,
        history: list[dict[str, str]],
        session_id: str,
        trust_context: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        if history:
            raise GlobalChatError("global route must use its durable session")
        audience = trust_context.get("audience")
        if not isinstance(audience, str) or not audience:
            raise GlobalChatError("global route audience is unavailable")
        idempotency_key = trust_context.get("idempotency_key")
        if not isinstance(idempotency_key, str):
            raise GlobalChatError("global route idempotency key is unavailable")
        expected_instruction = build_routing_instruction(
            prompt,
            target_rappid=self.config.target_rappid,
            audience=audience,
            idempotency_key=idempotency_key,
            max_chars=self.config.max_message_chars + 4096,
        )
        instruction = trust_context.get("route_request", expected_instruction)
        if instruction != expected_instruction:
            raise GlobalChatError("persisted global route request does not match")
        request_value: dict[str, Any] = {"user_input": instruction}
        if session_id:
            if not _SESSION_RE.fullmatch(session_id):
                raise GlobalChatError("global session is invalid")
        raw_request = json.dumps(
            request_value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        request_digest = hashlib.sha256(
            instruction.encode("utf-8")
        ).hexdigest()
        parsed = urllib.parse.urlsplit(self.config.global_controller_url)
        host = parsed.hostname
        if host is None:
            raise GlobalChatError("global controller URL is invalid")
        port = parsed.port or 80
        host_header = parsed.netloc
        from ..runtime.auth import bearer_authorization, read_auth_token

        token = read_auth_token(self.config.controller_auth_token_file)
        self._authenticate_endpoint(
            host,
            port,
            host_header,
            token,
        )
        connection = http.client.HTTPConnection(
            host,
            port,
            timeout=self.config.controller_timeout_seconds,
        )
        try:
            connection.putrequest(
                "POST",
                "/chat",
                skip_host=True,
                skip_accept_encoding=True,
            )
            connection.putheader("Host", host_header)
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Accept", "application/json")
            connection.putheader(
                "Authorization",
                bearer_authorization(token),
            )
            connection.putheader("Content-Length", str(len(raw_request)))
            connection.putheader("Connection", "close")
            connection.endheaders(raw_request)
            response = connection.getresponse()
            content_type = response.getheader("Content-Type", "")
            raw = response.read(self.config.max_response_chars + 256 * 1024 + 1)
            status = response.status
        except (OSError, http.client.HTTPException) as error:
            raise GlobalChatError("global controller is unavailable") from error
        finally:
            connection.close()
        if status != 200:
            raise GlobalChatError("global controller rejected the route")
        if not content_type.casefold().startswith("application/json"):
            raise GlobalChatError("global controller returned an invalid media type")
        if len(raw) > self.config.max_response_chars + 256 * 1024:
            raise GlobalChatError("global controller response exceeds the size limit")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
            raise GlobalChatError("global controller returned invalid JSON") from error
        return validate_global_chat_response(
            value,
            max_response_chars=self.config.max_response_chars,
            expected_request_sha256=request_digest,
            expected_instance_rappid=self.config.target_rappid,
        )

    def _authenticate_endpoint(
        self,
        host: str,
        port: int,
        host_header: str,
        token: bytes,
    ) -> None:
        from ..runtime.auth import (
            AUTH_CHALLENGE_HEADER,
            AUTH_PROOF_HEADER,
            encode_auth_value,
            new_auth_challenge,
            verify_auth_challenge_proof,
        )

        challenge = new_auth_challenge()
        connection = http.client.HTTPConnection(
            host,
            port,
            timeout=self.config.controller_timeout_seconds,
        )
        try:
            connection.putrequest(
                "GET",
                "/health",
                skip_host=True,
                skip_accept_encoding=True,
            )
            connection.putheader("Host", host_header)
            connection.putheader("Accept", "application/json")
            connection.putheader(
                AUTH_CHALLENGE_HEADER,
                encode_auth_value(challenge),
            )
            connection.putheader("Connection", "close")
            connection.endheaders()
            response = connection.getresponse()
            proof = response.getheader(AUTH_PROOF_HEADER)
            content_type = response.getheader("Content-Type", "")
            raw = response.read(64 * 1024 + 1)
            status = response.status
        except (OSError, http.client.HTTPException) as error:
            raise GlobalChatError(
                "global controller authentication is unavailable"
            ) from error
        finally:
            connection.close()
        if (
            status != 200
            or len(raw) > 64 * 1024
            or not content_type.casefold().startswith("application/json")
            or not verify_auth_challenge_proof(
                token,
                challenge,
                proof,
            )
        ):
            raise GlobalChatError(
                "global controller endpoint authentication failed"
            )
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise GlobalChatError(
                "global controller health response is invalid"
            ) from error
        if (
            not isinstance(payload, Mapping)
            or set(payload) != {"ready", "status", "version"}
            or payload.get("ready") is not True
            or payload.get("status") != "ok"
            or not isinstance(payload.get("version"), str)
        ):
            raise GlobalChatError("global controller is not ready")


def build_routing_instruction(
    owner_message: str,
    *,
    target_rappid: str,
    audience: str,
    max_chars: int,
    idempotency_key: str = "imessage-route",
) -> str:
    """Build one bounded canonical deterministic controller route."""

    from ..runtime.orchestrator import build_controller_chat_request

    request = build_controller_chat_request(
        "chat",
        {
            "audience": audience,
            "message": owner_message,
            "rappid": target_rappid,
        },
        idempotency_key,
    )
    instruction = request["user_input"]
    if len(instruction) > max_chars:
        raise GlobalChatError("global routing instruction exceeds the size limit")
    return instruction


def validate_global_chat_response(
    value: object,
    *,
    max_response_chars: int,
    expected_request_sha256: str | None = None,
    expected_instance_rappid: str | None = None,
) -> dict[str, Any]:
    """Verify the deterministic route, signed result, and exact child response."""

    if not isinstance(value, Mapping) or set(value) != _GLOBAL_RESPONSE_KEYS:
        raise GlobalChatError("global controller response shape is invalid")
    response = value.get("response")
    session_id = value.get("session_id")
    logs = value.get("agent_logs")
    proof = value.get("result_proof")
    controller_result = value.get("controller_result")
    if (
        not isinstance(response, str)
        or not response.strip()
        or len(response) > max_response_chars
        or "\x00" in response
    ):
        raise GlobalChatError("global controller response text is invalid")
    if not isinstance(session_id, str) or not _SESSION_RE.fullmatch(session_id):
        raise GlobalChatError("global controller session is invalid")
    if not isinstance(logs, str) or len(logs) > 256 * 1024:
        raise GlobalChatError("global controller logs are invalid")
    if (
        not isinstance(value.get("voice_mode"), bool)
        or not isinstance(value.get("model"), str)
        or not value["model"]
        or not isinstance(value.get("requested_model"), str)
        or not value["requested_model"]
    ):
        raise GlobalChatError("global controller response metadata is invalid")
    if (
        not isinstance(proof, Mapping)
        or set(proof)
        != {
            "schema",
            "algorithm",
            "tool",
            "action",
            "request_sha256",
            "result_sha256",
            "controller_result_sha256",
            "child_response_sha256",
            "signed_twin_chat_verified",
            "signed_twin_chat_status",
            "instance_rappid",
            "key_epoch",
            "status",
        }
        or proof.get("schema") != "rapp-controller-result-proof/1.0"
        or proof.get("algorithm") != "sha256"
        or proof.get("tool") != "RappStackCubbyController"
        or proof.get("action") != "chat"
        or not all(
            isinstance(proof.get(name), str)
            and re.fullmatch(r"[0-9a-f]{64}", proof[name])
            for name in (
                "request_sha256",
                "result_sha256",
                "controller_result_sha256",
                "child_response_sha256",
            )
        )
        or proof.get("result_sha256")
        != proof.get("controller_result_sha256")
        or proof.get("signed_twin_chat_verified") is not True
        or proof.get("signed_twin_chat_status") not in {"verified", "rejected"}
        or proof.get("status") not in {"ok", "rejected"}
        or not isinstance(proof.get("instance_rappid"), str)
        or not re.fullmatch(
            r"rappid:@[a-z0-9][a-z0-9-]{0,62}/"
            r"[a-z0-9][a-z0-9-]{0,127}:[0-9a-f]{64}",
            proof["instance_rappid"],
        )
        or not isinstance(proof.get("key_epoch"), int)
        or isinstance(proof.get("key_epoch"), bool)
        or not 1 <= proof["key_epoch"] <= 2**31 - 1
    ):
        raise GlobalChatError("global controller result proof is invalid")
    if (
        expected_request_sha256 is not None
        and not hmac.compare_digest(
            proof["request_sha256"], expected_request_sha256
        )
    ):
        raise GlobalChatError("global controller request proof does not match")
    if (
        expected_instance_rappid is not None
        and proof["instance_rappid"] != expected_instance_rappid
    ):
        raise GlobalChatError("global controller instance proof does not match")
    if not isinstance(controller_result, Mapping):
        raise GlobalChatError("global controller canonical result is missing")
    try:
        canonical_result = canonical_json_text(controller_result)
    except CanonicalJSONError as error:
        raise GlobalChatError("global controller result is not canonical") from error
    if hashlib.sha256(canonical_result.encode("utf-8")).hexdigest() != proof[
        "controller_result_sha256"
    ]:
        raise GlobalChatError("global controller result hash does not match")
    if hashlib.sha256(response.encode("utf-8")).hexdigest() != proof[
        "child_response_sha256"
    ]:
        raise GlobalChatError("global controller response hash does not match")
    if (
        controller_result.get("instance_rappid")
        != proof["instance_rappid"]
        or controller_result.get("key_epoch") != proof["key_epoch"]
        or controller_result.get("signed_twin_chat_verified") is not True
        or controller_result.get("signed_twin_chat_status")
        != proof["signed_twin_chat_status"]
    ):
        raise GlobalChatError("global controller signed bindings do not match")
    child = controller_result.get("child")
    if proof["status"] == "ok":
        if (
            controller_result.get("ok") is not True
            or proof["signed_twin_chat_status"] != "verified"
            or not isinstance(child, Mapping)
            or child.get("response") != response
        ):
            raise GlobalChatError(
                "global controller result is not an exact signed child response"
            )
    elif (
        controller_result.get("ok") is not False
        or controller_result.get("terminal") is not True
        or proof["signed_twin_chat_status"] != "rejected"
        or response != canonical_result
    ):
        raise GlobalChatError("global controller terminal rejection is invalid")
    return dict(value)


class IMessageBridge:
    """Supervise ``imsg`` and route one exact owner self-chat via the controller."""

    def __init__(
        self,
        config: IMessageConfig,
        *,
        state: IMessageState | None = None,
        chat_runner: ChatRunner | None = None,
        supervisor: ImsgRpcSupervisor | None = None,
        logger: logging.Logger | None = None,
        transport_verifier: Callable[..., Mapping[str, Any]] = verify_installed_imsg,
        binding_discoverer: Callable[..., Any] | None = None,
    ) -> None:
        self.config = config
        self.state = state or IMessageState(config)
        self.chat_runner = chat_runner or LoopbackGlobalChatRunner(config)
        if logger is None:
            self.log = logging.getLogger("rapp_stack_cubby.imessage")
            if not self.log.handlers:
                self.log.addHandler(logging.NullHandler())
            self.log.propagate = False
        else:
            self.log = logger
        self._transport_verifier = transport_verifier
        self._binding_discoverer = binding_discoverer
        self._stop = threading.Event()
        self._executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="rapp-imessage-worker",
        )
        self._conversation_lock = threading.Lock()
        self._binding_lock = threading.RLock()
        self._binding_verified = False
        self._binding_verified_at: float | None = None
        self._subscription: int | None = None
        self._chat_services: dict[str, str] = {}
        self._chat_accounts: dict[str, str] = {}
        self._chat_aliases: dict[str, frozenset[str]] = {}
        self._lease_holder = uuid.uuid4().hex
        self._processed_count = 0
        self._dropped_count = 0
        self._failed_count = 0
        self._send_ready: bool | None = None
        self._controller_ready: bool | None = None
        self._started = False
        self.supervisor = supervisor or ImsgRpcSupervisor(
            lambda callback: ImsgRpcClient(
                str(config.imsg_path),
                on_notification=callback,
                on_diagnostic=self._diagnostic,
                default_timeout=config.request_timeout_seconds,
            ),
            on_notification=self._on_notification,
            on_ready=self._on_ready,
            restart_initial=config.restart_initial_seconds,
            restart_max=config.restart_max_seconds,
        )

    def preflight(self) -> dict[str, Any]:
        facts = dict(
            self._transport_verifier(
                self.config.imsg_path,
                probe_messages=True,
            )
        )
        account_binding_verified = False
        if facts.get("ok") is True:
            try:
                binding = self._discover_owner_binding()
                account_binding_verified = (
                    binding.account_id == self.config.account_id
                    and set(binding.chat_ids)
                    == set(self.config.owner_chat_ids)
                )
            except Exception:
                account_binding_verified = False
        facts["account_binding_verified"] = account_binding_verified
        facts["ok"] = (
            facts.get("ok") is True and account_binding_verified
        )
        allowed = {
            "account_binding_verified",
            "archive_hash_verified",
            "architectures_verified",
            "codesign_verified",
            "error_codes",
            "layout_verified",
            "ok",
            "read_ready",
            "send_ready",
            "team_verified",
            "version",
            "version_verified",
        }
        return {key: facts.get(key) for key in sorted(allowed)}

    def start(self) -> None:
        if self._started:
            return
        preflight = self.preflight()
        if preflight.get("ok") is not True:
            raise IMessageBridgeError("iMessage preflight failed")
        if not self.state.acquire_lease(self._lease_holder):
            raise IMessageBridgeError("another iMessage writer owns this state")
        self.state.recover_after_restart()
        self._stop.clear()
        self._invalidate_binding()
        self._started = True
        self._publish_status("starting")
        self.supervisor.start()

    def run_forever(self) -> None:
        self.start()
        next_maintenance = time.monotonic()
        next_account_validation = (
            time.monotonic() + _ACCOUNT_REVALIDATE_SECONDS
        )
        try:
            while not self._stop.wait(0.25):
                if getattr(self.supervisor, "terminal", False):
                    self._publish_status("failed")
                    raise IMessageBridgeError(
                        "imsg supervisor exhausted its restart limit"
                    )
                if time.monotonic() < next_maintenance:
                    continue
                next_maintenance = time.monotonic() + 5.0
                if not self.state.refresh_lease(self._lease_holder):
                    raise IMessageBridgeError("the iMessage writer lease was lost")
                connected = getattr(
                    self.supervisor,
                    "is_connected",
                    self.supervisor.is_ready,
                )
                if connected:
                    try:
                        self._refresh_chat_catalog(self.supervisor)
                        if time.monotonic() >= next_account_validation:
                            self._validate_private_binding()
                            next_account_validation = (
                                time.monotonic()
                                + _ACCOUNT_REVALIDATE_SECONDS
                            )
                    except ImsgRpcError:
                        self.supervisor.restart()
                    except Exception as error:
                        self._invalidate_binding()
                        self._publish_status("failed")
                        raise IMessageBridgeError(
                            "owner chat binding revalidation failed"
                        ) from error
                    if self._binding_is_current():
                        self._retry_pending()
                lifecycle = "running" if self.supervisor.is_ready else "starting"
                self._publish_status(lifecycle)
        finally:
            self.stop()

    def stop(self) -> None:
        if self._stop.is_set() and not self._started:
            return
        self._stop.set()
        self._invalidate_binding()
        self.supervisor.stop()
        self._executor.shutdown(wait=True, cancel_futures=False)
        if self._started:
            self._publish_status(
                "failed"
                if getattr(self.supervisor, "terminal", False)
                else "stopped"
            )
            self.state.release_lease(self._lease_holder)
        self._started = False

    def status(self) -> dict[str, Any]:
        counts = self.state.lifecycle_counts()
        transport_ready = self.supervisor.is_ready
        ready = (
            transport_ready
            and self._binding_is_current()
            and self._controller_ready is not False
            and self._send_ready is not False
            and not getattr(self.supervisor, "terminal", False)
        )
        return {
            "controller_ready": self._controller_ready,
            "dropped": counts["dropped"],
            "failed": counts["failed"],
            "imsg_version": IMSG_PINNED_VERSION,
            "pending": counts["pending"],
            "processed": counts["processed"],
            "read_ready": transport_ready,
            "ready": ready,
            "restart_count": self.supervisor.restart_count,
            "send_ready": self._send_ready,
            "transport_ready": transport_ready,
        }

    def process_message(self, message: Mapping[str, Any]) -> str:
        """Synchronously process one live-shaped event and return only an outcome."""

        try:
            with self._binding_lock:
                prepared = self._prepare_message(message)
        except _RejectedEvent as error:
            self._record_rejection(message, error.code)
            self._dropped_count += 1
            return error.code
        event_digest = self.state.claim_event(
            prepared["rowid"],
            prepared["guid"],
            self._private_payload(prepared),
        )
        if event_digest is None:
            return "duplicate"
        return self._process_claim(
            event_digest,
            guid=prepared["guid"],
            created_at=prepared["created_at"],
        )

    def _process_claim(
        self,
        event_digest: str,
        *,
        guid: str | None = None,
        created_at: str | None = None,
    ) -> str:
        with self._conversation_lock:
            self._require_current_binding()
            terminal_outcome = self.state.event_outcome(event_digest)
            if terminal_outcome is not None:
                if terminal_outcome in {
                    "outbound_echo",
                    "ambiguous_outbound_echo",
                }:
                    self._dropped_count += 1
                return terminal_outcome
            event = self.state.claim_for_processing(event_digest)
            if event is None:
                return self.state.event_outcome(event_digest) or "duplicate"
            conversation = self.state.owner_session_key()
            if self.state.consume_outbound_echo_hmac(
                conversation,
                guid_hmac=str(event["guid_hmac"]),
                text=str(event["text"]),
                is_from_me=event["is_from_me"] is True,
                target_hmac=str(event["target_hmac"]),
            ):
                self.state.complete_event(event_digest, "outbound_echo")
                self._dropped_count += 1
                return "outbound_echo"
            age = self._message_age_seconds(created_at or event.get("created_at"))
            if (
                age is not None
                and age > self.config.stale_after_seconds
                and int(event["attempts"]) == 0
            ):
                self.state.complete_event(event_digest, "stale_backlog")
                self._dropped_count += 1
                return "stale_backlog"

            staged = self.state.staged_dispatch(event_digest)
            if staged is None:
                session_id = self.state.get_global_session() or ""
                idempotency_key = str(event["controller_idempotency_key"])
                route_request = build_routing_instruction(
                    str(event["text"]),
                    target_rappid=self.config.target_rappid,
                    audience=self.state.owner_audience_id(),
                    idempotency_key=idempotency_key,
                    max_chars=self.config.max_message_chars + 4096,
                )
                persisted_route = self.state.prepare_controller_route(
                    event_digest,
                    route_request,
                )
                context = {
                    "audience": self.state.owner_audience_id(),
                    "idempotency_key": persisted_route["idempotency_key"],
                    "route": "global-controller-signed-twin-chat",
                    "route_request": persisted_route["route_request"],
                }
                try:
                    result = self.chat_runner(
                        str(event["text"]),
                        [],
                        session_id,
                        context,
                    )
                    validated = validate_global_chat_response(
                        result,
                        max_response_chars=self.config.max_response_chars,
                        expected_request_sha256=persisted_route[
                            "request_sha256"
                        ],
                        expected_instance_rappid=self.config.target_rappid,
                    )
                except Exception:
                    self._controller_ready = False
                    self.state.mark_retryable_event(event_digest)
                    self._failed_count += 1
                    self._diagnostic("global controller route failed")
                    return "controller_failed"
                self._controller_ready = True
                if validated["result_proof"]["status"] == "rejected":
                    self.state.complete_event(
                        event_digest,
                        "controller_rejected",
                    )
                    self._failed_count += 1
                    return "controller_rejected"
                self.state.stage_controller_result(
                    event_digest,
                    conversation_hmac=conversation,
                    target_hmac=str(event["target_hmac"]),
                    target_kind=str(event["target_kind"]),
                    user_text=str(event["text"]),
                    response_text=validated["response"],
                    global_session_id=validated["session_id"],
                )
                staged = self.state.staged_dispatch(event_digest)
                if staged is None:
                    raise IMessageBridgeError("controller response staging failed")

            response_text = str(staged["response"])
            outbound = self.config.reply_prefix + response_text
            record_id = self.state.begin_outbound(
                event_digest,
                conversation,
                outbound,
            )
            record = self.state.outbound_record(record_id)
            if record is None:
                raise IMessageBridgeError("outbox record is unavailable")
            if record["status"] in {"submitted", "unknown", "not_sent"}:
                outcome = {
                    "submitted": "replied",
                    "unknown": "send_unknown",
                    "not_sent": "send_not_sent",
                }[record["status"]]
                self.state.complete_event(event_digest, outcome)
                return outcome
            if record["status"] == "flushed":
                self.state.finish_outbound(record_id, status="unknown")
                self.state.complete_event(event_digest, "send_unknown")
                return "send_unknown"

            target = self.state.resolve_target(str(staged["target_hmac"]))
            if target is None:
                self.state.finish_outbound(record_id, status="not_sent")
                self.state.complete_event(event_digest, "send_not_sent")
                self._failed_count += 1
                return "send_not_sent"
            target_kind = str(staged["target_kind"])
            target_value: object = (
                int(target)
                if target_kind == "chat_id" and target.isdigit()
                else target
            )
            params: dict[str, object] = {
                target_kind: target_value,
                "text": outbound,
                "service": "imessage",
            }
            self.state.mark_outbound_flushed(record_id)
            self._require_current_binding()
            try:
                send_result = self.supervisor.request(
                    "send",
                    params,
                    timeout=self.config.request_timeout_seconds,
                )
            except ImsgRpcNotSent:
                self.state.finish_outbound(record_id, status="not_sent")
                self.state.complete_event(event_digest, "send_not_sent")
                self._failed_count += 1
                self._send_ready = False
                return "send_not_sent"
            except (ImsgRpcAmbiguous, ImsgRpcError):
                self.state.finish_outbound(record_id, status="unknown")
                self.state.complete_event(event_digest, "send_unknown")
                self._failed_count += 1
                self._send_ready = False
                return "send_unknown"

            outbound_guid = self._validated_send_result(
                send_result,
                target_kind=target_kind,
                target_value=str(target),
            )
            if outbound_guid is False:
                self.state.finish_outbound(record_id, status="unknown")
                self.state.complete_event(event_digest, "send_unknown")
                self._failed_count += 1
                self._send_ready = False
                return "send_unknown"
            self.state.finish_outbound(
                record_id,
                status="submitted",
                outbound_guid=(
                    outbound_guid
                    if isinstance(outbound_guid, str)
                    else None
                ),
            )
            self.state.complete_event(event_digest, "replied")
            self._processed_count += 1
            self._send_ready = True
            return "replied"

    def _validated_send_result(
        self,
        value: object,
        *,
        target_kind: str,
        target_value: str,
    ) -> str | bool:
        if not isinstance(value, Mapping) or value.get("ok") is not True:
            return False
        service = value.get("service")
        if service is not None and (
            not isinstance(service, str)
            or service.casefold() != "imessage"
        ):
            return False
        guid_values = [
            value.get(name)
            for name in ("guid", "message_id")
            if value.get(name) is not None
        ]
        if any(
            not isinstance(item, str)
            or not item
            or len(item) > 512
            or any(ord(character) < 0x20 for character in item)
            for item in guid_values
        ) or len(set(guid_values)) > 1:
            return False

        expected_aliases = self._chat_aliases.get(target_value)
        for key in ("chat_id", "chat_guid", "chat_identifier"):
            observed = value.get(key)
            if observed is None:
                continue
            if (
                isinstance(observed, bool)
                or not isinstance(observed, (str, int))
                or not str(observed)
            ):
                return False
            rendered = str(observed)
            if expected_aliases is not None:
                if rendered not in expected_aliases:
                    return False
            elif key == target_kind:
                if rendered != target_value:
                    return False
            else:
                return False
        return guid_values[0] if guid_values else False

    def _on_ready(self, client: Any) -> None:
        self._invalidate_binding()
        try:
            binding = self._discover_owner_binding()
            self._validate_binding_value(binding)
            self._refresh_chat_catalog(client, binding=binding)
            params: dict[str, object] = {
                "attachments": False,
                "debounce_ms": 500,
                "include_reactions": False,
            }
            resume = self.state.watch_resume_rowid
            if resume is not None:
                params["since_rowid"] = resume
            result = client.request(
                "watch.subscribe",
                params,
                self.config.request_timeout_seconds,
            )
            if (
                not isinstance(result, Mapping)
                or isinstance(result.get("subscription"), bool)
                or not isinstance(result.get("subscription"), int)
            ):
                raise IMessageBridgeError("imsg watch subscription is invalid")
            self._subscription = int(result["subscription"])
            with self._binding_lock:
                self._binding_verified = True
                self._binding_verified_at = time.monotonic()
        except Exception:
            self._invalidate_binding()
            raise

    def _on_notification(self, method: str, params: object) -> bool:
        if method == "error":
            subscription = (
                params.get("subscription")
                if isinstance(params, Mapping)
                else None
            )
            if subscription == self._subscription:
                self._invalidate_binding()
                self._diagnostic("imsg watch requested restart")
                self.supervisor.restart()
                return True
            return False
        if (
            method != "message"
            or not isinstance(params, Mapping)
            or not isinstance(params.get("message"), Mapping)
        ):
            return False
        subscription = params.get("subscription")
        if subscription != self._subscription:
            return False
        message = params["message"]
        try:
            with self._binding_lock:
                prepared = self._prepare_message(message)
                event_digest = self.state.claim_event(
                    prepared["rowid"],
                    prepared["guid"],
                    self._private_payload(prepared),
                )
        except _RejectedEvent as error:
            self._record_rejection(message, error.code)
            self._dropped_count += 1
            return True
        except StateError:
            self._record_rejection(message, "invalid_event")
            self._dropped_count += 1
            return True
        if event_digest is None:
            return True
        self._executor.submit(
            self._safe_process_claim,
            event_digest,
            prepared["guid"],
            prepared["created_at"],
        )
        return True

    def _safe_process_claim(
        self,
        event_digest: str,
        guid: str | None,
        created_at: str | None,
    ) -> None:
        try:
            self._process_claim(
                event_digest,
                guid=guid,
                created_at=created_at,
            )
        except Exception:
            self.state.mark_retryable_event(event_digest)
            self._failed_count += 1
            self._diagnostic("claimed event processing failed")

    def _retry_pending(self) -> None:
        for event in self.state.pending_events():
            self._executor.submit(
                self._safe_process_claim,
                event["event_digest"],
                None,
                event.get("created_at"),
            )

    def _prepare_message(self, raw: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(raw, Mapping):
            raise _RejectedEvent("invalid_event")
        if self._started and not self._binding_is_current():
            raise _RejectedEvent("owner_binding_unverified")
        guid, rowid = self._event_identity(raw)
        text = raw.get("text")
        if not isinstance(text, str) or "\x00" in text:
            raise _RejectedEvent("invalid_event")
        if not text.strip():
            raise _RejectedEvent("unsupported_empty_message")
        if len(text) > self.config.max_message_chars:
            raise _RejectedEvent("invalid_event")
        is_from_me = self._strict_bool(raw.get("is_from_me"))
        is_group = self._strict_bool(raw.get("is_group"))
        if is_group:
            raise _RejectedEvent("group_not_allowed")
        attachments = raw.get("attachments", [])
        if not isinstance(attachments, (list, tuple)):
            raise _RejectedEvent("invalid_event")
        if attachments:
            raise _RejectedEvent("attachments_not_allowed")
        reactions = raw.get("reactions", [])
        if not isinstance(reactions, (list, tuple)):
            raise _RejectedEvent("invalid_event")
        if reactions:
            raise _RejectedEvent("reactions_not_allowed")
        associated = raw.get("associated_message_guid")
        if associated is not None and associated != "":
            raise _RejectedEvent("reactions_not_allowed")
        item_type = raw.get("item_type")
        if isinstance(item_type, bool) or not (
            item_type is None
            or item_type == ""
            or item_type == "message"
            or item_type == 0
        ):
            raise _RejectedEvent("unsupported_event")
        is_reaction = raw.get("is_reaction")
        if is_reaction is not None:
            if not isinstance(is_reaction, bool):
                raise _RejectedEvent("invalid_event")
            if is_reaction:
                raise _RejectedEvent("reactions_not_allowed")
        poll = raw.get("poll")
        if poll is not None:
            raise _RejectedEvent("unsupported_event")

        explicit_service = raw.get("service")
        if explicit_service is not None and not isinstance(
            explicit_service, str
        ):
            raise _RejectedEvent("invalid_event")
        for key in ("chat_id", "chat_guid", "chat_identifier"):
            value = raw.get(key)
            if value is not None and not (
                isinstance(value, str)
                and 0 < len(value) <= 512
                and not any(ord(character) < 0x20 for character in value)
                or isinstance(value, int)
                and not isinstance(value, bool)
                and value >= 0
            ):
                raise _RejectedEvent("invalid_event")

        service = self._service_for(raw)
        if service != "imessage":
            raise _RejectedEvent("non_imessage")
        matched: tuple[str, object] | None = None
        for key in ("chat_id", "chat_guid"):
            value = raw.get(key)
            if _identifier_present(value) and self.config.owner_chat_matches(value):
                matched = (key, value)
                break
        if matched is None:
            raise _RejectedEvent("unknown_chat")

        sender_value = raw.get("sender", "")
        if not isinstance(sender_value, (str, int)) or isinstance(sender_value, bool):
            raise _RejectedEvent("owner_mismatch")
        sender = normalize_handle(str(sender_value))
        raw_participants = raw.get("participants", [])
        if not isinstance(raw_participants, (list, tuple)):
            raise _RejectedEvent("owner_mismatch")
        participants: set[str] = set()
        for item in raw_participants:
            if not isinstance(item, (str, int)) or isinstance(item, bool):
                raise _RejectedEvent("owner_mismatch")
            value = normalize_handle(str(item))
            if value:
                participants.add(value)
        owners = self.config.normalized_owner_handles
        if participants and not participants.issubset(owners):
            raise _RejectedEvent("owner_mismatch")
        if is_from_me:
            if sender and sender not in owners:
                raise _RejectedEvent("owner_mismatch")
        elif not sender or sender not in owners:
            raise _RejectedEvent("owner_mismatch")
        account = raw.get("account_id")
        if account is not None and (
            not isinstance(account, str)
            or not account
            or account != self.config.account_id
        ):
            raise _RejectedEvent("owner_mismatch")
        catalog_account = self._chat_accounts.get(str(matched[1]))
        if (
            self._started or catalog_account is not None
        ) and catalog_account != self.config.account_id:
            raise _RejectedEvent("owner_mismatch")

        created_at = raw.get("created_at", raw.get("date", ""))
        if created_at is None:
            created_at = ""
        if not isinstance(created_at, str) or len(created_at) > 64:
            raise _RejectedEvent("invalid_event")
        if created_at and self._message_age_seconds(created_at) is None:
            raise _RejectedEvent("invalid_event")
        target_kind, target_value = matched
        return {
            "created_at": created_at,
            "guid": guid,
            "is_from_me": is_from_me,
            "rowid": rowid,
            "service": service,
            "target_hmac": self.state.target_hmac(target_value),
            "target_kind": target_kind,
            "text": text,
        }

    @staticmethod
    def _event_identity(raw: Mapping[str, Any]) -> tuple[str, int]:
        guid = raw.get("guid")
        rowid = raw.get("id")
        if (
            not isinstance(guid, str)
            or not guid
            or len(guid) > 512
            or isinstance(rowid, bool)
            or not isinstance(rowid, int)
            or rowid < 0
        ):
            raise _RejectedEvent("invalid_event")
        return guid, rowid

    @staticmethod
    def _strict_bool(value: object) -> bool:
        if not isinstance(value, bool):
            raise _RejectedEvent("invalid_event")
        return value

    @staticmethod
    def _private_payload(prepared: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "created_at": prepared["created_at"],
            "is_from_me": prepared["is_from_me"],
            "service": prepared["service"],
            "target_hmac": prepared["target_hmac"],
            "target_kind": prepared["target_kind"],
            "text": prepared["text"],
        }

    def _record_rejection(self, raw: Mapping[str, Any], outcome: str) -> None:
        try:
            guid, rowid = self._event_identity(raw)
            text_value = raw.get("text")
            text = (
                text_value
                if isinstance(text_value, str)
                and text_value
                and len(text_value) <= self.config.max_message_chars
                and "\x00" not in text_value
                else " "
            )
            target_value = next(
                (
                    value
                    for value in (
                        raw.get("chat_id"),
                        raw.get("chat_guid"),
                        raw.get("chat_identifier"),
                    )
                    if _identifier_present(value)
                ),
                "missing",
            )
            service = str(raw.get("service") or "unsupported").casefold()
            if service not in {"imessage", "sms"}:
                service = "unsupported"
            event_digest = self.state.claim_event(
                rowid,
                guid,
                {
                    "created_at": "",
                    "is_from_me": raw.get("is_from_me") is True,
                    "service": service,
                    "target_hmac": self.state.target_hmac(target_value),
                    "target_kind": (
                        "chat_id"
                        if _identifier_present(raw.get("chat_id"))
                        else "chat_guid"
                    ),
                    "text": text,
                },
            )
            if event_digest is not None:
                safe_outcome = (
                    outcome
                    if outcome.replace("_", "").isalnum() and len(outcome) <= 64
                    else "policy_rejected"
                )
                self.state.complete_event(event_digest, safe_outcome)
        except (StateError, _RejectedEvent, TypeError, ValueError):
            return

    def _service_for(self, raw: Mapping[str, Any]) -> str:
        explicit = raw.get("service")
        if isinstance(explicit, str) and explicit:
            return explicit.casefold()
        for value in (
            raw.get("chat_id"),
            raw.get("chat_guid"),
            raw.get("chat_identifier"),
        ):
            if _identifier_present(value):
                service = self._chat_services.get(str(value))
                if service:
                    return service
        return ""

    def _discover_owner_binding(self) -> Any:
        discoverer = self._binding_discoverer
        if discoverer is None:
            from .cli import discover_owner_binding

            discoverer = discover_owner_binding
        return discoverer(
            self.config.imsg_path,
            list(self.config.owner_handles),
            selected_chat_ids=list(self.config.owner_chat_ids),
        )

    def _validate_binding_value(self, binding: Any) -> None:
        if (
            getattr(binding, "account_id", None) != self.config.account_id
            or set(getattr(binding, "chat_ids", ()))
            != set(self.config.owner_chat_ids)
        ):
            raise IMessageBridgeError(
                "configured owner binding does not match the private catalog"
            )

    def _validate_private_binding(self) -> None:
        with self._binding_lock:
            try:
                binding = self._discover_owner_binding()
                self._validate_binding_value(binding)
            except Exception:
                self._binding_verified = False
                self._binding_verified_at = None
                self._subscription = None
                raise
            self._binding_verified = True
            self._binding_verified_at = time.monotonic()

    def _invalidate_binding(self) -> None:
        with self._binding_lock:
            self._binding_verified = False
            self._binding_verified_at = None
            self._subscription = None

    def _binding_is_current(self) -> bool:
        if not self._started:
            return True
        with self._binding_lock:
            return self._binding_verified

    def _require_current_binding(self) -> None:
        if not self._binding_is_current():
            raise IMessageBridgeError("owner chat binding is not verified")

    def _refresh_chat_catalog(
        self,
        client: Any,
        *,
        binding: Any | None = None,
    ) -> None:
        with self._binding_lock:
            try:
                self._refresh_chat_catalog_locked(client, binding=binding)
            except Exception:
                if self._started:
                    self._binding_verified = False
                    self._binding_verified_at = None
                    self._subscription = None
                raise

    def _refresh_chat_catalog_locked(
        self,
        client: Any,
        *,
        binding: Any | None = None,
    ) -> None:
        if binding is not None:
            self._validate_binding_value(binding)
        result = client.request(
            "chats.list",
            {"limit": 1000},
            self.config.request_timeout_seconds,
        )
        chats = result.get("chats") if isinstance(result, Mapping) else None
        if not isinstance(chats, Sequence) or isinstance(chats, (str, bytes)):
            raise IMessageBridgeError("imsg chat catalog is invalid")
        catalog: dict[str, str] = {}
        aliases_by_value: dict[str, frozenset[str]] = {}
        records: list[tuple[frozenset[str], str, str | None]] = []
        for chat in chats:
            if not isinstance(chat, Mapping):
                raise IMessageBridgeError("imsg chat catalog is invalid")
            raw_service = chat.get("service")
            if not isinstance(raw_service, str):
                raise IMessageBridgeError("imsg chat catalog is invalid")
            service = raw_service.casefold()
            if service not in {"imessage", "sms"}:
                continue
            aliases = frozenset(
                str(value)
                for value in (
                    chat.get("id"),
                    chat.get("guid"),
                    chat.get("identifier"),
                )
                if _identifier_present(value)
            )
            account = chat.get("account_id")
            if account is not None and (
                not isinstance(account, str) or not account
            ):
                raise IMessageBridgeError("imsg chat catalog is invalid")
            records.append(
                (
                    aliases,
                    service,
                    account if isinstance(account, str) else None,
                )
            )
            for rendered in aliases:
                catalog[rendered] = service
                aliases_by_value[rendered] = aliases
        configured = set(self.config.owner_chat_ids)
        selected = [
            record for record in records if not configured.isdisjoint(record[0])
        ]
        if len(selected) != 1:
            raise IMessageBridgeError(
                "configured owner chat does not identify exactly one catalog record"
            )
        selected_aliases, selected_service, observed_account = selected[0]
        if (
            not configured.issubset(selected_aliases)
            or selected_service != "imessage"
        ):
            raise IMessageBridgeError(
                "configured owner chat is absent from the imsg catalog"
            )
        if (
            observed_account is not None
            and observed_account != self.config.account_id
        ):
            raise IMessageBridgeError(
                "configured owner account does not match the imsg catalog"
            )
        accounts = {
            alias: self.config.account_id for alias in selected_aliases
        }
        self._chat_services = catalog
        self._chat_accounts = accounts
        self._chat_aliases = aliases_by_value

    @staticmethod
    def _message_age_seconds(value: object) -> float | None:
        if not isinstance(value, str) or not value:
            return None
        try:
            parsed = _datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=_datetime.timezone.utc)
        return max(
            0.0,
            (
                _datetime.datetime.now(_datetime.timezone.utc)
                - parsed.astimezone(_datetime.timezone.utc)
            ).total_seconds(),
        )

    def _publish_status(self, lifecycle: str) -> None:
        value = self.status()
        value["heartbeat_at"] = time.time()
        value["lifecycle"] = lifecycle
        self.state.write_status(value)

    def _diagnostic(self, message: str) -> None:
        allowed = {
            "claimed event processing failed",
            "global controller route failed",
            "imsg rpc diagnostic",
            "imsg rpc stderr unavailable",
            "imsg watch requested restart",
            "imsg notification handler failed",
        }
        selected = message if message in allowed else "imsg transport diagnostic"
        self.log.warning("%s", selected)


IMessageService = IMessageBridge
