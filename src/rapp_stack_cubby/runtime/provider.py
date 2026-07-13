"""Typed LLM providers with an in-memory GitHub Copilot session cache."""

from __future__ import annotations

import copy
import contextlib
import datetime as dt
import json
import os
import re
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Protocol, runtime_checkable

from .basic_agent import AgentValidationError, validate_agent_name
from .github_auth import (
    GitHubAuthError,
    read_github_token_file,
    validate_github_token_file,
)

COPILOT_TOKEN_URL: Final = (
    "https://api.github.com/copilot_internal/v2/token"
)
DEFAULT_PROVIDER_TIMEOUT: Final = 30.0
MAX_PROVIDER_RESPONSE_BYTES: Final = 2 * 1024 * 1024
MAX_PROVIDER_CONTENT_BYTES: Final = 1024 * 1024
MAX_PROVIDER_MODELS: Final = 512
ATTESTATION_MODE: Final = "offline-self-test"
ATTESTATION_MODEL: Final = "attestation-self-test/1.0"
ATTESTATION_TOOL_CALL_ID: Final = "attestation-self-test"
_CACHE_BUFFER_SECONDS: Final = 60.0
_DETAIL_LIMIT: Final = 240
_CREDENTIAL_RE = re.compile(
    r"(?i)(?:bearer|token)\s+[A-Za-z0-9._~+/=-]+|"
    r"gh[oprsu]_[A-Za-z0-9_]{6,}|"
    r"(\"?(?:access_)?token\"?\s*[:=]\s*\"?)[^\",\s}]+"
)
_LOCAL_PATH_RE = re.compile(
    r"(?:/(?:Users|home)/[^/\s]+(?:/[^\s]*)?|"
    r"[A-Za-z]:\\Users\\[^\\\s]+(?:\\[^\s]*)?)"
)


class ProviderError(Exception):
    """Base class for provider failures."""


class ProviderConfigurationError(ProviderError, ValueError):
    """Raised for invalid provider configuration."""


class ProviderAuthenticationError(ProviderError):
    """Raised when GitHub or Copilot authentication cannot be established."""

    def __init__(
        self,
        message: str,
        *,
        preflight_status: str = "auth_missing",
    ) -> None:
        self.preflight_status = preflight_status
        super().__init__(message)


class ProviderTokenCompatibilityError(ProviderAuthenticationError):
    """Raised when a GitHub OAuth token cannot be exchanged for Copilot."""

    def __init__(self) -> None:
        super().__init__(
            "the resolved gho credential is incompatible with Copilot; use "
            "provider-login --token-file with an explicit private file, "
            "then pass that file with --github-token-file",
            preflight_status="incompatible_gho",
        )


class ProviderEntitlementError(ProviderAuthenticationError):
    """Raised when authentication succeeds without Copilot entitlement."""

    def __init__(self) -> None:
        super().__init__(
            "GitHub authentication has no available Copilot entitlement",
            preflight_status="no_copilot_entitlement",
        )


class ProviderEndpointDriftError(ProviderError):
    """Raised when Copilot's advertised endpoint contract has changed."""

    preflight_status = "endpoint_drift"


class ProviderUnsupportedModelError(ProviderConfigurationError):
    """Raised when the exact selected model is absent from the live catalog."""

    preflight_status = "unsupported_model"


class ProviderTransportError(ProviderError):
    """Raised when a bounded provider request cannot be completed."""

    preflight_status = "transport"


class ProviderProtocolError(ProviderError, ValueError):
    """Raised when a provider response violates the expected wire schema."""


class ProviderHTTPError(ProviderTransportError):
    """A redacted HTTP error from a provider endpoint."""

    def __init__(self, status: int, detail: str = "provider request failed") -> None:
        self.status = status
        self.detail = _redact_detail(detail)
        super().__init__(f"provider HTTP {status}: {self.detail}")


@dataclass(frozen=True, slots=True)
class ToolCall:
    """A normalized function call requested by the model."""

    id: str
    name: str
    arguments: str = "{}"

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id or len(self.id) > 256:
            raise ProviderProtocolError(
                "tool call id must be a non-empty string of at most 256 characters"
            )
        _validate_utf8_text(self.id, "tool call id", maximum=1024)
        try:
            validate_agent_name(self.name)
        except AgentValidationError as error:
            raise ProviderProtocolError("tool call name is invalid") from error
        if not isinstance(self.arguments, str):
            raise ProviderProtocolError("tool call arguments must be a string")
        _validate_utf8_text(
            self.arguments,
            "tool call arguments",
            maximum=MAX_PROVIDER_CONTENT_BYTES,
        )

    def as_openai(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": "function",
            "function": {
                "name": self.name,
                "arguments": self.arguments,
            },
        }


@dataclass(frozen=True, slots=True)
class ProviderResponse:
    """Normalized provider output independent of the HTTP implementation."""

    content: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    model: str | None = None
    finish_reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.content, str):
            raise ProviderProtocolError("provider content must be a string")
        _validate_utf8_text(
            self.content,
            "provider content",
            maximum=MAX_PROVIDER_CONTENT_BYTES,
        )
        calls = tuple(self.tool_calls)
        if not all(isinstance(call, ToolCall) for call in calls):
            raise ProviderProtocolError(
                "provider tool_calls must contain ToolCall values"
            )
        object.__setattr__(self, "tool_calls", calls)
        if self.model is not None and (
            not isinstance(self.model, str) or not self.model.strip()
        ):
            raise ProviderProtocolError("provider model must be a non-empty string")
        if self.model is not None:
            _validate_utf8_text(self.model, "provider model", maximum=512)
        if self.finish_reason is not None and not isinstance(
            self.finish_reason, str
        ):
            raise ProviderProtocolError("finish_reason must be a string")
        if self.finish_reason is not None:
            _validate_utf8_text(
                self.finish_reason, "finish_reason", maximum=512
            )


@dataclass(frozen=True, slots=True)
class ProviderModel:
    """A non-sensitive chat-completions model catalog entry."""

    id: str
    name: str
    vendor: str | None
    preview: bool
    tool_calls: bool | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "vendor": self.vendor,
            "preview": self.preview,
            "tool_calls": self.tool_calls,
        }


@runtime_checkable
class Provider(Protocol):
    """Provider protocol consumed by the orchestrator."""

    def complete(
        self,
        messages: Sequence[Mapping[str, Any]],
        *,
        tools: Sequence[Mapping[str, Any]] = (),
        model: str | None = None,
        timeout: float | None = None,
    ) -> ProviderResponse:
        """Return one normalized chat completion."""


@dataclass(frozen=True, slots=True)
class ProviderRequest:
    """An immutable request record exposed by ScriptedProvider tests."""

    messages: tuple[dict[str, Any], ...]
    tools: tuple[dict[str, Any], ...]
    model: str | None
    timeout: float | None


ScriptedItem = (
    ProviderResponse
    | Mapping[str, Any]
    | Exception
    | Callable[[ProviderRequest], ProviderResponse | Mapping[str, Any]]
)


class ScriptedProvider:
    """Deterministic provider that consumes a fixed response script."""

    def __init__(
        self,
        responses: Iterable[ScriptedItem],
        *,
        default_model: str = "scripted",
    ) -> None:
        self._responses = list(responses)
        self._default_model = _validate_model(default_model)
        self._requests: list[ProviderRequest] = []
        self._lock = threading.Lock()

    @property
    def requests(self) -> tuple[ProviderRequest, ...]:
        with self._lock:
            return tuple(self._requests)

    @property
    def remaining(self) -> int:
        with self._lock:
            return len(self._responses)

    def complete(
        self,
        messages: Sequence[Mapping[str, Any]],
        *,
        tools: Sequence[Mapping[str, Any]] = (),
        model: str | None = None,
        timeout: float | None = None,
    ) -> ProviderResponse:
        request = ProviderRequest(
            messages=tuple(copy.deepcopy(dict(message)) for message in messages),
            tools=tuple(copy.deepcopy(dict(tool)) for tool in tools),
            model=model,
            timeout=timeout,
        )
        with self._lock:
            self._requests.append(request)
            if not self._responses:
                raise ProviderProtocolError("scripted provider has no response left")
            item = self._responses.pop(0)

        if isinstance(item, Exception):
            raise item
        if callable(item):
            item = item(request)
        if isinstance(item, ProviderResponse):
            return item
        if isinstance(item, Mapping):
            if "choices" in item:
                return normalize_provider_response(
                    item,
                    requested_model=model or self._default_model,
                )
            return _response_from_mapping(
                item,
                default_model=model or self._default_model,
            )
        raise ProviderProtocolError("unsupported scripted provider response")

    chat = complete
    chat_completion = complete


class AttestationProvider:
    """Offline provider for the one deterministic SelfTest attestation."""

    def __init__(self) -> None:
        self._requests: list[ProviderRequest] = []
        self._lock = threading.Lock()

    @property
    def requests(self) -> tuple[ProviderRequest, ...]:
        with self._lock:
            return tuple(self._requests)

    def complete(
        self,
        messages: Sequence[Mapping[str, Any]],
        *,
        tools: Sequence[Mapping[str, Any]] = (),
        model: str | None = None,
        timeout: float | None = None,
    ) -> ProviderResponse:
        if model != ATTESTATION_MODEL:
            raise ProviderConfigurationError(
                "attestation provider requires its exact reserved model"
            )
        request = ProviderRequest(
            messages=tuple(copy.deepcopy(dict(message)) for message in messages),
            tools=tuple(copy.deepcopy(dict(tool)) for tool in tools),
            model=model,
            timeout=timeout,
        )
        with self._lock:
            self._requests.append(request)

        if _is_attestation_tool_result(request.messages):
            return ProviderResponse(
                content="",
                model=ATTESTATION_MODEL,
                finish_reason="stop",
            )
        if any(message.get("role") == "tool" for message in request.messages):
            raise ProviderProtocolError(
                "attestation provider accepts only its exact SelfTest result"
            )
        if not _has_self_test_run_tool(request.tools):
            raise ProviderProtocolError(
                "attestation provider requires the registered SelfTest run tool"
            )
        return ProviderResponse(
            content="",
            tool_calls=(
                ToolCall(
                    ATTESTATION_TOOL_CALL_ID,
                    "SelfTest",
                    '{"action":"run"}',
                ),
            ),
            model=ATTESTATION_MODEL,
            finish_reason="tool_calls",
        )

    chat = complete
    chat_completion = complete


def _has_self_test_run_tool(
    tools: Sequence[Mapping[str, Any]],
) -> bool:
    matches = []
    for tool in tools:
        function = tool.get("function")
        if (
            tool.get("type") == "function"
            and isinstance(function, Mapping)
            and function.get("name") == "SelfTest"
        ):
            matches.append(function)
    if len(matches) != 1:
        return False
    parameters = matches[0].get("parameters")
    if not isinstance(parameters, Mapping):
        return False
    properties = parameters.get("properties")
    action = (
        properties.get("action")
        if isinstance(properties, Mapping)
        else None
    )
    return (
        isinstance(action, Mapping)
        and isinstance(action.get("enum"), list)
        and "run" in action["enum"]
    )


def _is_attestation_tool_result(
    messages: Sequence[Mapping[str, Any]],
) -> bool:
    if len(messages) < 2:
        return False
    assistant = messages[-2]
    result = messages[-1]
    calls = assistant.get("tool_calls")
    if (
        assistant.get("role") != "assistant"
        or assistant.get("content") != ""
        or not isinstance(calls, list)
        or len(calls) != 1
        or result.get("role") != "tool"
        or result.get("tool_call_id") != ATTESTATION_TOOL_CALL_ID
        or result.get("name") != "SelfTest"
        or not isinstance(result.get("content"), str)
    ):
        return False
    call = calls[0]
    function = call.get("function") if isinstance(call, Mapping) else None
    return (
        isinstance(call, Mapping)
        and call.get("id") == ATTESTATION_TOOL_CALL_ID
        and call.get("type") == "function"
        and isinstance(function, Mapping)
        and function.get("name") == "SelfTest"
        and function.get("arguments") == '{"action":"run"}'
    )


@dataclass(frozen=True, slots=True)
class _CopilotSession:
    token: str
    endpoint: str
    expires_at: float


class CopilotProvider:
    """GitHub Copilot chat provider implemented with the Python standard library."""

    def __init__(
        self,
        *,
        model: str | None,
        timeout: float = DEFAULT_PROVIDER_TIMEOUT,
        environment: Mapping[str, str] | None = None,
        urlopen: Callable[..., Any] | None = None,
        run_command: Callable[..., Any] | None = None,
        clock: Callable[[], float] | None = None,
        github_token_file: str | os.PathLike[str] | None = None,
        token_url: str = COPILOT_TOKEN_URL,
        max_response_bytes: int = MAX_PROVIDER_RESPONSE_BYTES,
    ) -> None:
        self.model = None if model is None else _validate_model(model)
        self.timeout = _validate_timeout(timeout)
        self._environment = os.environ if environment is None else environment
        self._urlopen = urllib.request.urlopen if urlopen is None else urlopen
        self._run_command = subprocess.run if run_command is None else run_command
        self._clock = time.time if clock is None else clock
        try:
            self.github_token_file = (
                None
                if github_token_file is None
                else validate_github_token_file(github_token_file)
            )
        except GitHubAuthError as error:
            raise ProviderConfigurationError(str(error)) from error
        self._token_url = _validate_https_url(token_url, "token URL")
        if (
            not isinstance(max_response_bytes, int)
            or isinstance(max_response_bytes, bool)
            or max_response_bytes < 1
        ):
            raise ProviderConfigurationError(
                "max_response_bytes must be a positive integer"
            )
        self._max_response_bytes = max_response_bytes
        self._cache: _CopilotSession | None = None
        self._cache_lock = threading.RLock()

    def resolve_github_token(self) -> str:
        """Resolve a GitHub token without persisting or displaying it."""

        if self.github_token_file is not None:
            try:
                return read_github_token_file(
                    self.github_token_file
                ).access_token
            except GitHubAuthError as error:
                raise ProviderAuthenticationError(
                    str(error),
                    preflight_status=error.status,
                ) from error

        environment_token = self._environment.get("GITHUB_TOKEN", "")
        if isinstance(environment_token, str) and environment_token.strip():
            return _validate_secret(environment_token)

        try:
            result = self._run_command(
                ["gh", "auth", "token"],
                capture_output=True,
                text=True,
                check=False,
                timeout=self.timeout,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise ProviderAuthenticationError(
                "GitHub authentication is unavailable"
            ) from error
        if getattr(result, "returncode", 1) != 0:
            raise ProviderAuthenticationError(
                "gh auth token did not return a credential"
            )
        output = getattr(result, "stdout", "")
        if not isinstance(output, str) or not output.strip():
            raise ProviderAuthenticationError(
                "gh auth token returned an empty credential"
            )
        return _validate_secret(output)

    def invalidate(self) -> None:
        with self._cache_lock:
            self._cache = None

    def complete(
        self,
        messages: Sequence[Mapping[str, Any]],
        *,
        tools: Sequence[Mapping[str, Any]] = (),
        model: str | None = None,
        timeout: float | None = None,
    ) -> ProviderResponse:
        selected_model = self.model if model is None else _validate_model(model)
        if selected_model is None:
            raise ProviderConfigurationError(
                "a model is required for chat completion"
            )
        selected_timeout = (
            self.timeout if timeout is None else _validate_timeout(timeout)
        )
        payload: dict[str, Any] = {
            "model": selected_model,
            "messages": [copy.deepcopy(dict(message)) for message in messages],
        }
        if tools:
            payload["tools"] = [copy.deepcopy(dict(tool)) for tool in tools]
        _encode_payload(payload)

        for attempt in range(2):
            session = self._copilot_session(selected_timeout)
            endpoint = _chat_endpoint(session.endpoint)
            try:
                body = self._request_json(
                    endpoint,
                    payload,
                    headers={
                        "Authorization": f"Bearer {session.token}",
                        "Accept": "application/json",
                        "Copilot-Integration-Id": "vscode-chat",
                    },
                    timeout=selected_timeout,
                )
            except ProviderHTTPError as error:
                if error.status == 401 and attempt == 0:
                    self.invalidate()
                    continue
                if error.status == 403:
                    raise ProviderEntitlementError() from error
                if error.status == 404:
                    raise ProviderEndpointDriftError(
                        "Copilot chat endpoint is unavailable"
                    ) from error
                raise
            response = normalize_provider_response(
                body,
                requested_model=selected_model,
            )
            if response.model != selected_model:
                raise ProviderProtocolError(
                    "provider returned a model other than the exact selection"
                )
            return response
        raise ProviderAuthenticationError("Copilot authentication retry failed")

    def list_models(
        self, *, timeout: float | None = None
    ) -> tuple[ProviderModel, ...]:
        """List only entitled models advertising chat-completions support."""

        selected_timeout = (
            self.timeout if timeout is None else _validate_timeout(timeout)
        )
        for attempt in range(2):
            session = self._copilot_session(selected_timeout)
            try:
                body = self._request_json(
                    _models_endpoint(session.endpoint),
                    None,
                    headers={
                        "Authorization": f"Bearer {session.token}",
                        "Accept": "application/json",
                        "Copilot-Integration-Id": "vscode-chat",
                    },
                    timeout=selected_timeout,
                )
            except ProviderHTTPError as error:
                if error.status == 401 and attempt == 0:
                    self.invalidate()
                    continue
                if error.status == 403:
                    raise ProviderEntitlementError() from error
                if error.status == 404:
                    raise ProviderEndpointDriftError(
                        "Copilot model endpoint is unavailable"
                    ) from error
                raise
            try:
                return _parse_models(body)
            except ProviderProtocolError as error:
                raise ProviderEndpointDriftError(
                    "Copilot model endpoint contract has changed"
                ) from error
        raise ProviderAuthenticationError("Copilot authentication retry failed")

    def validate_model(
        self,
        model: str | None = None,
        *,
        models: Sequence[ProviderModel] | None = None,
    ) -> ProviderModel:
        """Require an exact advertised chat-completions model identifier."""

        selected = self.model if model is None else _validate_model(model)
        if selected is None:
            raise ProviderConfigurationError(
                "a model is required for provider preflight"
            )
        catalog = self.list_models() if models is None else tuple(models)
        if not all(isinstance(item, ProviderModel) for item in catalog):
            raise ProviderConfigurationError("model catalog is invalid")
        for item in catalog:
            if item.id == selected:
                return item
        raise ProviderUnsupportedModelError(
            "selected model is not available for chat completions"
        )

    chat = complete
    chat_completion = complete

    def _copilot_session(self, timeout: float) -> _CopilotSession:
        with self._cache_lock:
            now = float(self._clock())
            cached = self._cache
            if (
                cached is not None
                and cached.expires_at - _CACHE_BUFFER_SECONDS > now
            ):
                return cached

            github_token = self.resolve_github_token()
            authorization = (
                f"token {github_token}"
                if github_token.startswith("ghu_")
                else f"Bearer {github_token}"
            )
            try:
                body = self._request_json(
                    self._token_url,
                    None,
                    headers={
                        "Authorization": authorization,
                        "Accept": "application/json",
                    },
                    timeout=timeout,
                )
            except ProviderHTTPError as error:
                if (
                    github_token.startswith("gho_")
                    and error.status in {401, 403, 404}
                ):
                    raise ProviderTokenCompatibilityError() from error
                if error.status in {403, 404}:
                    raise ProviderEntitlementError() from error
                if error.status == 401:
                    raise ProviderAuthenticationError(
                        "GitHub credential was rejected"
                    ) from error
                raise
            try:
                session = _parse_copilot_session(body, now)
            except (ProviderConfigurationError, ProviderProtocolError) as error:
                raise ProviderEndpointDriftError(
                    "Copilot token endpoint contract has changed"
                ) from error
            self._cache = session
            return session

    def _request_json(
        self,
        url: str,
        payload: Mapping[str, Any] | None,
        *,
        headers: Mapping[str, str],
        timeout: float,
    ) -> dict[str, Any]:
        request_headers = {
            "User-Agent": "rapp-stack-cubby/isolated-runtime",
            **headers,
        }
        data: bytes | None = None
        if payload is not None:
            data = _encode_payload(payload)
            request_headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            url,
            data=data,
            headers=request_headers,
            method="POST" if data is not None else "GET",
        )
        try:
            opened = self._urlopen(request, timeout=timeout)
            with contextlib.ExitStack() as stack:
                if callable(getattr(opened, "__enter__", None)):
                    response = stack.enter_context(opened)
                else:
                    response = opened
                    close = getattr(response, "close", None)
                    if callable(close):
                        stack.callback(close)
                status = getattr(response, "status", None)
                if status is None and callable(getattr(response, "getcode", None)):
                    status = response.getcode()
                if not isinstance(status, int):
                    status = 200
                raw = _bounded_read(response, self._max_response_bytes)
        except urllib.error.HTTPError as error:
            _discard_http_error_body(error)
            raise ProviderHTTPError(error.code) from error
        except urllib.error.URLError as error:
            raise ProviderTransportError(
                f"provider transport failed ({type(error.reason).__name__})"
            ) from error
        except TimeoutError as error:
            raise ProviderTransportError("provider request timed out") from error
        except OSError as error:
            raise ProviderTransportError(
                f"provider transport failed ({type(error).__name__})"
            ) from error

        if status < 200 or status >= 300:
            raise ProviderHTTPError(status)
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ProviderProtocolError(
                "provider returned invalid JSON"
            ) from error
        if not isinstance(decoded, dict):
            raise ProviderProtocolError(
                "provider response must be a JSON object"
            )
        return decoded


def normalize_provider_response(
    payload: Mapping[str, Any],
    *,
    requested_model: str | None = None,
) -> ProviderResponse:
    """Merge content and split tool-call fragments across response choices."""

    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ProviderProtocolError(
            "provider response choices must be a non-empty array"
        )

    content_parts: list[str] = []
    builders: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    by_index: dict[int, dict[str, Any]] = {}
    finish_reasons: list[str] = []

    for choice_index, choice in enumerate(choices):
        if not isinstance(choice, Mapping):
            raise ProviderProtocolError(
                f"provider choice {choice_index} must be an object"
            )
        message = choice.get("message", choice.get("delta"))
        if not isinstance(message, Mapping):
            raise ProviderProtocolError(
                f"provider choice {choice_index} message must be an object"
            )
        content_parts.extend(_content_fragments(message.get("content")))
        tool_calls = message.get("tool_calls", [])
        if tool_calls is None:
            tool_calls = []
        if not isinstance(tool_calls, list):
            raise ProviderProtocolError("provider tool_calls must be an array")
        for position, raw_call in enumerate(tool_calls):
            if not isinstance(raw_call, Mapping):
                raise ProviderProtocolError("provider tool call must be an object")
            call_id = raw_call.get("id")
            if call_id is not None and not isinstance(call_id, str):
                raise ProviderProtocolError("provider tool call id must be a string")
            index = raw_call.get("index")
            if index is not None and (
                not isinstance(index, int) or isinstance(index, bool) or index < 0
            ):
                raise ProviderProtocolError(
                    "provider tool call index must be a non-negative integer"
                )
            function = raw_call.get("function")
            if not isinstance(function, Mapping):
                raise ProviderProtocolError(
                    "provider tool call function must be an object"
                )
            name = function.get("name", "")
            arguments = function.get("arguments", "")
            if not isinstance(name, str) or not isinstance(arguments, str):
                raise ProviderProtocolError(
                    "provider function name and arguments must be strings"
                )

            builder = None
            if call_id:
                builder = by_id.get(call_id)
            if builder is None and index is not None:
                candidate = by_index.get(index)
                if candidate is not None and (
                    not call_id
                    or not candidate["id"]
                    or candidate["id"] == call_id
                ):
                    builder = candidate
            if builder is None:
                builder = {
                    "id": call_id or "",
                    "name": "",
                    "arguments": "",
                    "order": len(builders),
                }
                builders.append(builder)
                if index is not None and index not in by_index:
                    by_index[index] = builder
            if call_id:
                if not builder["id"]:
                    builder["id"] = call_id
                by_id[call_id] = builder
            builder["name"] = _merge_name(builder["name"], name)
            builder["arguments"] += arguments

        finish_reason = choice.get("finish_reason")
        if finish_reason is not None:
            if not isinstance(finish_reason, str):
                raise ProviderProtocolError("finish_reason must be a string")
            finish_reasons.append(finish_reason)

    calls: list[ToolCall] = []
    for index, builder in enumerate(builders, start=1):
        if not builder["name"]:
            raise ProviderProtocolError("provider tool call has no function name")
        calls.append(
            ToolCall(
                id=builder["id"] or f"call_{index}",
                name=builder["name"],
                arguments=builder["arguments"] or "{}",
            )
        )

    model = payload.get("model", requested_model)
    if model is not None and not isinstance(model, str):
        raise ProviderProtocolError("provider model must be a string")
    return ProviderResponse(
        content="".join(content_parts),
        tool_calls=tuple(calls),
        model=model,
        finish_reason=finish_reasons[-1] if finish_reasons else None,
    )


def _response_from_mapping(
    value: Mapping[str, Any], *, default_model: str
) -> ProviderResponse:
    content = value.get("content", "")
    raw_calls = value.get("tool_calls", ())
    if not isinstance(raw_calls, (list, tuple)):
        raise ProviderProtocolError("scripted tool_calls must be an array")
    calls: list[ToolCall] = []
    for index, raw_call in enumerate(raw_calls, start=1):
        if isinstance(raw_call, ToolCall):
            calls.append(raw_call)
            continue
        if not isinstance(raw_call, Mapping):
            raise ProviderProtocolError("scripted tool call must be an object")
        function = raw_call.get("function")
        if isinstance(function, Mapping):
            name = function.get("name")
            arguments = function.get("arguments", "{}")
        else:
            name = raw_call.get("name")
            arguments = raw_call.get("arguments", "{}")
        calls.append(
            ToolCall(
                id=str(raw_call.get("id") or f"call_{index}"),
                name=name,
                arguments=arguments,
            )
        )
    return ProviderResponse(
        content=content,
        tool_calls=tuple(calls),
        model=value.get("model", default_model),
        finish_reason=value.get("finish_reason"),
    )


def _parse_copilot_session(
    payload: Mapping[str, Any], now: float
) -> _CopilotSession:
    token = payload.get("token")
    if not isinstance(token, str) or not token.strip():
        raise ProviderProtocolError("Copilot token response has no token")
    token = _validate_secret(token)

    endpoint: object = payload.get("endpoint")
    endpoints = payload.get("endpoints")
    if isinstance(endpoints, Mapping):
        endpoint = endpoints.get("api", endpoints.get("proxy", endpoint))
    if not isinstance(endpoint, str):
        raise ProviderProtocolError("Copilot token response has no API endpoint")
    endpoint = _validate_https_url(endpoint, "Copilot API endpoint")

    expires_at = _parse_expiry(payload.get("expires_at"))
    if expires_at <= now:
        raise ProviderProtocolError("Copilot token is already expired")
    return _CopilotSession(token=token, endpoint=endpoint, expires_at=expires_at)


def _parse_expiry(value: object) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        result = float(value)
        if result > 10_000_000_000:
            result /= 1000.0
        return result
    if isinstance(value, str) and value:
        if re.fullmatch(r"\d+(?:\.\d+)?", value):
            result = float(value)
            return result / 1000.0 if result > 10_000_000_000 else result
        try:
            if value.endswith("Z"):
                value = value[:-1] + "+00:00"
            parsed = dt.datetime.fromisoformat(value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt.timezone.utc)
            return parsed.timestamp()
        except ValueError as error:
            raise ProviderProtocolError(
                "Copilot token expiry is invalid"
            ) from error
    raise ProviderProtocolError("Copilot token response has no valid expiry")


def _content_fragments(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        parts: list[str] = []
        for item in value:
            if not isinstance(item, Mapping):
                raise ProviderProtocolError("provider content part must be an object")
            text = item.get("text")
            if isinstance(text, Mapping):
                text = text.get("value")
            if not isinstance(text, str):
                raise ProviderProtocolError(
                    "provider text content part must contain a string"
                )
            parts.append(text)
        return parts
    raise ProviderProtocolError("provider message content must be text or an array")


def _merge_name(existing: str, fragment: str) -> str:
    if not fragment or fragment == existing:
        return existing
    if not existing:
        return fragment
    if fragment.startswith(existing):
        return fragment
    if existing.endswith(fragment):
        return existing
    return existing + fragment


def _chat_endpoint(endpoint: str) -> str:
    parsed = urllib.parse.urlsplit(endpoint)
    path = parsed.path.rstrip("/")
    if path.endswith("/chat/completions"):
        return endpoint
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, path + "/chat/completions", "", "")
    )


def _models_endpoint(endpoint: str) -> str:
    parsed = urllib.parse.urlsplit(endpoint)
    path = parsed.path.rstrip("/")
    for suffix in ("/chat/completions", "/responses", "/v1/messages"):
        if path.endswith(suffix):
            path = path[: -len(suffix)]
            break
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, path + "/models", "", "")
    )


def _parse_models(payload: Mapping[str, Any]) -> tuple[ProviderModel, ...]:
    raw_items = payload.get("data", payload.get("models"))
    if not isinstance(raw_items, list):
        raise ProviderProtocolError(
            "provider model catalog must contain a data array"
        )
    if len(raw_items) > MAX_PROVIDER_MODELS:
        raise ProviderProtocolError("provider model catalog is too large")
    models: dict[str, ProviderModel] = {}
    for raw in raw_items:
        if not isinstance(raw, Mapping):
            raise ProviderProtocolError(
                "provider model catalog entry must be an object"
            )
        capabilities = raw.get("capabilities")
        if (
            not isinstance(capabilities, Mapping)
            or capabilities.get("type") != "chat"
        ):
            continue
        endpoints = raw.get("supported_endpoints")
        if (
            not isinstance(endpoints, list)
            or "/chat/completions" not in endpoints
            or not all(isinstance(item, str) for item in endpoints)
        ):
            continue
        policy = raw.get("policy")
        if isinstance(policy, Mapping) and policy.get("state") == "disabled":
            continue
        identifier = raw.get("id")
        try:
            identifier = _validate_model(identifier)
        except ProviderConfigurationError as error:
            raise ProviderProtocolError(
                "provider model identifier is invalid"
            ) from error
        if identifier in models:
            raise ProviderProtocolError(
                "provider model catalog contains a duplicate identifier"
            )
        raw_name = raw.get("name", identifier)
        name = (
            raw_name.strip()
            if isinstance(raw_name, str) and raw_name.strip()
            else identifier
        )
        _validate_utf8_text(name, "provider model name", maximum=1024)
        raw_vendor = raw.get("vendor")
        vendor = (
            raw_vendor.strip()
            if isinstance(raw_vendor, str) and raw_vendor.strip()
            else None
        )
        if vendor is not None:
            _validate_utf8_text(
                vendor, "provider model vendor", maximum=256
            )
        supports = capabilities.get("supports")
        tool_calls = (
            supports.get("tool_calls")
            if isinstance(supports, Mapping)
            and isinstance(supports.get("tool_calls"), bool)
            else None
        )
        preview = raw.get("preview") is True
        models[identifier] = ProviderModel(
            id=identifier,
            name=name,
            vendor=vendor,
            preview=preview,
            tool_calls=tool_calls,
        )
    return tuple(models[name] for name in sorted(models))


def _encode_payload(payload: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ProviderProtocolError(
            "provider request must contain only finite JSON data"
        ) from error


def _bounded_read(response: Any, maximum: int) -> bytes:
    content_length = None
    headers = getattr(response, "headers", None)
    if headers is not None:
        content_length = headers.get("Content-Length")
    if content_length:
        try:
            declared = int(content_length)
        except (TypeError, ValueError):
            declared = None
        if declared is not None and declared > maximum:
            raise ProviderProtocolError("provider response exceeds the size limit")
    raw = response.read(maximum + 1)
    if not isinstance(raw, bytes):
        raise ProviderProtocolError("provider response body must be bytes")
    if len(raw) > maximum:
        raise ProviderProtocolError("provider response exceeds the size limit")
    return raw


def _discard_http_error_body(error: urllib.error.HTTPError) -> None:
    try:
        error.read(4096)
    except OSError:
        return


def _redact_detail(detail: str) -> str:
    clean = "".join(
        character if character >= " " else " " for character in str(detail)
    )
    clean = _CREDENTIAL_RE.sub("[redacted]", clean)
    clean = _LOCAL_PATH_RE.sub("[private-path]", clean)
    clean = " ".join(clean.split())
    return (clean or "provider request failed")[:_DETAIL_LIMIT]


def _validate_secret(value: str) -> str:
    token = value.strip()
    if (
        not token
        or len(token.encode("utf-8", "ignore")) > 16 * 1024
        or any(character.isspace() for character in token)
    ):
        raise ProviderAuthenticationError("resolved credential has invalid format")
    return token


def _validate_model(model: object) -> str:
    if not isinstance(model, str) or not model.strip():
        raise ProviderConfigurationError("model must be a non-empty string")
    if len(model) > 128 or any(ord(character) < 32 for character in model):
        raise ProviderConfigurationError("model contains invalid characters")
    return model.strip()


def _validate_utf8_text(value: str, label: str, *, maximum: int) -> str:
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ProviderProtocolError(
            f"{label} contains an invalid Unicode scalar"
        ) from error
    if len(encoded) > maximum:
        raise ProviderProtocolError(f"{label} exceeds the size limit")
    return value


def _validate_timeout(timeout: object) -> float:
    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or not 0 < float(timeout) <= 300
    ):
        raise ProviderConfigurationError(
            "provider timeout must be between 0 and 300 seconds"
        )
    return float(timeout)


def _validate_https_url(url: object, label: str) -> str:
    if not isinstance(url, str):
        raise ProviderConfigurationError(f"{label} must be a string")
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ProviderConfigurationError(f"{label} must be an HTTPS URL")
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), parsed.query, "")
    )


def provider_preflight_status(error: ProviderError) -> str:
    """Return one stable content-free preflight failure category."""

    status = getattr(error, "preflight_status", None)
    if isinstance(status, str):
        return status
    if isinstance(error, ProviderProtocolError):
        return "endpoint_drift"
    if isinstance(error, ProviderAuthenticationError):
        return "auth_missing"
    if isinstance(error, ProviderTransportError):
        return "transport"
    if isinstance(error, ProviderConfigurationError):
        return "configuration"
    return "provider_error"


ProviderToolCall = ToolCall
ChatProvider = Provider
