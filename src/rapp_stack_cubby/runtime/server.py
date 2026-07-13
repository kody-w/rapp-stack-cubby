"""Small loopback-only JSON server for health and chat."""

from __future__ import annotations

import json
import socket
import socketserver
import threading
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Final

from ..constants import __version__
from .auth import (
    AUTH_CHALLENGE_HEADER,
    AUTH_PROOF_HEADER,
    AUTH_TOKEN_BYTES,
    auth_challenge_proof,
    decode_auth_value,
    verify_bearer_headers,
)
from .config import (
    RuntimeConfigurationError,
    validate_instance_id,
    validate_loopback_host,
)
from .orchestrator import (
    ContextCollectionError,
    Orchestrator,
    OrchestratorProviderError,
    RequestValidationError,
    SignedIngressConflictError,
    SoulLoadError,
)
from .registry import RegistryLoadError

MAX_REQUEST_BYTES: Final = 1024 * 1024
MAX_RESPONSE_BYTES: Final = 2 * 1024 * 1024
_MAX_CONTENT_LENGTH_DIGITS: Final = 20
_KNOWN_ROUTES = frozenset({"/health", "/chat"})
_METHODS_BY_ROUTE = {"/health": "GET", "/chat": "POST"}


class RuntimeServerError(Exception):
    """Raised when the local HTTP service cannot be managed."""


class _RuntimeHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = True
    allow_reuse_address = False


class _RuntimeIPv6HTTPServer(_RuntimeHTTPServer):
    address_family = socket.AF_INET6


class RuntimeServer:
    """Owns one bounded ThreadingHTTPServer and its graceful lifecycle."""

    def __init__(
        self,
        orchestrator: Orchestrator,
        *,
        host: str = "127.0.0.1",
        port: int = 7071,
        request_timeout: float = 15.0,
        max_request_bytes: int = MAX_REQUEST_BYTES,
        instance_id: str,
        auth_token: bytes | None = None,
    ) -> None:
        self.orchestrator = orchestrator
        self.host = validate_loopback_host(host)
        try:
            self.instance_id = validate_instance_id(instance_id)
        except RuntimeConfigurationError as error:
            raise RuntimeServerError("instance id is invalid") from error
        if (
            not isinstance(port, int)
            or isinstance(port, bool)
            or not 0 <= port <= 65535
        ):
            raise RuntimeServerError(
                "port must be an integer between 0 and 65535"
            )
        if (
            not isinstance(request_timeout, (int, float))
            or isinstance(request_timeout, bool)
            or not 0 < float(request_timeout) <= 300
        ):
            raise RuntimeServerError(
                "request timeout must be between 0 and 300 seconds"
            )
        if (
            not isinstance(max_request_bytes, int)
            or isinstance(max_request_bytes, bool)
            or max_request_bytes < 1
        ):
            raise RuntimeServerError(
                "max request bytes must be a positive integer"
            )
        if auth_token is not None and (
            not isinstance(auth_token, bytes)
            or len(auth_token) != AUTH_TOKEN_BYTES
        ):
            raise RuntimeServerError("auth token must contain exactly 32 bytes")
        self._auth_token = auth_token

        server_class = (
            _RuntimeIPv6HTTPServer if ":" in self.host else _RuntimeHTTPServer
        )
        try:
            server = server_class((self.host, port), _RuntimeRequestHandler)
        except OSError as error:
            raise RuntimeServerError(
                "loopback server could not bind"
            ) from error
        server.runtime = self
        server.request_timeout = float(request_timeout)
        server.max_request_bytes = max_request_bytes
        self._server = server
        self._thread: threading.Thread | None = None
        self._state_lock = threading.Lock()
        self._serving = threading.Event()
        self._closed = False

        bound = server.socket.getsockname()
        self.bound_host = str(bound[0])
        self.port = int(bound[1])
        self._allowed_hosts = _allowed_host_names(self.host, self.bound_host)

    @property
    def url(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{host}:{self.port}"

    @property
    def health_url(self) -> str:
        return self.url + "/health"

    @property
    def allowed_hosts(self) -> frozenset[str]:
        return self._allowed_hosts

    @property
    def running(self) -> bool:
        thread = self._thread
        return thread is not None and thread.is_alive()

    @property
    def authentication_required(self) -> bool:
        return self._auth_token is not None

    def authorize(self, values: list[str]) -> bool:
        token = self._auth_token
        return token is None or verify_bearer_headers(values, token)

    def prove_health_challenge(self, values: list[str]) -> str | None:
        token = self._auth_token
        if token is None or len(values) != 1:
            return None
        challenge = decode_auth_value(values[0])
        if challenge is None:
            return None
        return auth_challenge_proof(token, challenge)

    def health_payload(self) -> tuple[int, dict[str, Any]]:
        try:
            self.orchestrator.load_soul()
            snapshot = self.orchestrator.registry.load()
        except (RegistryLoadError, SoulLoadError):
            return (
                HTTPStatus.SERVICE_UNAVAILABLE,
                {
                    "status": "unavailable",
                    "ready": False,
                    "version": __version__,
                    "model": self.orchestrator.model,
                    "agents": [],
                    "instance_id": self.instance_id,
                    "signed_only": self.orchestrator.signed_only,
                },
            )
        return (
            HTTPStatus.OK,
            {
                "status": "ok",
                "ready": True,
                "version": __version__,
                "model": self.orchestrator.model,
                "agents": list(snapshot.names),
                "instance_id": self.instance_id,
                "signed_only": self.orchestrator.signed_only,
            },
        )

    def serve_forever(self) -> None:
        with self._state_lock:
            if self._closed:
                raise RuntimeServerError("server is closed")
        self._serving.set()
        try:
            self._server.serve_forever(poll_interval=0.1)
        finally:
            self._serving.clear()
            self._server.server_close()
            with self._state_lock:
                self._closed = True

    def start_in_thread(self) -> threading.Thread:
        with self._state_lock:
            if self._closed:
                raise RuntimeServerError("server is closed")
            if self._thread is not None and self._thread.is_alive():
                raise RuntimeServerError("server is already running")
            thread = threading.Thread(
                target=self.serve_forever,
                name="rapp-stack-cubby-http",
                daemon=True,
            )
            self._thread = thread
            thread.start()
        if not self._serving.wait(2.0):
            raise RuntimeServerError("server did not start")
        return thread

    start = start_in_thread

    def shutdown(self, timeout: float = 5.0) -> None:
        with self._state_lock:
            closed = self._closed
            thread = self._thread
        if closed:
            return
        if not self._serving.is_set():
            self._server.server_close()
            with self._state_lock:
                self._closed = True
            return
        if thread is not None and thread is threading.current_thread():
            raise RuntimeServerError(
                "server shutdown must be requested from another thread"
            )
        self._server.shutdown()
        self._server.server_close()
        with self._state_lock:
            self._closed = True
        if thread is not None:
            thread.join(timeout)
            if thread.is_alive():
                raise RuntimeServerError(
                    "server did not stop within the shutdown timeout"
                )

    close = shutdown

    def __enter__(self) -> "RuntimeServer":
        self.start_in_thread()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.shutdown()


class _RuntimeRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "rapp-stack-cubby"
    sys_version = ""

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(self.server.request_timeout)

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_HEAD(self) -> None:
        self._dispatch("HEAD")

    def do_OPTIONS(self) -> None:
        self._dispatch("OPTIONS")

    def do_PUT(self) -> None:
        self._dispatch("PUT")

    def do_PATCH(self) -> None:
        self._dispatch("PATCH")

    def do_DELETE(self) -> None:
        self._dispatch("DELETE")

    def do_TRACE(self) -> None:
        self._dispatch("TRACE")

    def do_CONNECT(self) -> None:
        self._dispatch("CONNECT")

    def __getattr__(self, name: str) -> Any:
        if name.startswith("do_"):
            return lambda: self._dispatch(name[3:])
        raise AttributeError(name)

    def _dispatch(self, method: str) -> None:
        if not self._valid_host():
            self._send_error_json(
                HTTPStatus.FORBIDDEN,
                "invalid_host",
                "Host header is not allowed",
            )
            return
        path = self._request_path()
        if path is None:
            self._send_error_json(
                HTTPStatus.BAD_REQUEST,
                "invalid_target",
                "request target must be origin-form",
            )
            return
        if path not in _KNOWN_ROUTES:
            self._send_error_json(
                HTTPStatus.NOT_FOUND,
                "not_found",
                "route not found",
            )
            return
        expected_method = _METHODS_BY_ROUTE[path]
        if method != expected_method:
            self._send_json(
                HTTPStatus.METHOD_NOT_ALLOWED,
                {
                    "error": {
                        "code": "method_not_allowed",
                        "message": "method not allowed",
                    }
                },
                extra_headers={"Allow": expected_method},
            )
            return
        if path == "/health":
            if self.server.runtime.authentication_required:
                proof = self.server.runtime.prove_health_challenge(
                    self.headers.get_all(AUTH_CHALLENGE_HEADER, [])
                )
                if proof is None:
                    self._send_json(
                        HTTPStatus.UNAUTHORIZED,
                        {
                            "error": {
                                "code": "unauthorized",
                                "message": "authentication challenge is required",
                            }
                        },
                    )
                    return
                status, payload = self.server.runtime.health_payload()
                self._send_json(
                    status,
                    {
                        "ready": payload.get("ready") is True,
                        "status": payload.get("status", "unavailable"),
                        "version": payload.get("version", __version__),
                    },
                    extra_headers={AUTH_PROOF_HEADER: proof},
                )
                return
            status, payload = self.server.runtime.health_payload()
            self._send_json(status, payload)
            return

        if not self.server.runtime.authorize(
            self.headers.get_all("Authorization", [])
        ):
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {
                    "error": {
                        "code": "unauthorized",
                        "message": "authentication is required",
                    }
                },
                extra_headers={"WWW-Authenticate": "Bearer"},
            )
            return

        try:
            payload = self._read_json_body()
            result = self.server.runtime.orchestrator.chat(payload)
        except _HTTPInputError as error:
            self._send_error_json(error.status, error.code, error.message)
            return
        except RequestValidationError as error:
            self._send_error_json(
                HTTPStatus.BAD_REQUEST,
                "invalid_request",
                str(error),
            )
            return
        except SignedIngressConflictError as error:
            self._send_error_json(
                HTTPStatus.CONFLICT,
                "signed_request_conflict",
                str(error),
            )
            return
        except RegistryLoadError:
            self._send_error_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "agent_registry_unavailable",
                "agent registry is unavailable",
            )
            return
        except (SoulLoadError, ContextCollectionError):
            self._send_error_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "runtime_context_unavailable",
                "runtime context is unavailable",
            )
            return
        except OrchestratorProviderError:
            self._send_error_json(
                HTTPStatus.BAD_GATEWAY,
                "provider_unavailable",
                "model provider is unavailable",
            )
            return
        self._send_json(HTTPStatus.OK, result)

    def _read_json_body(self) -> Any:
        transfer_encoding = self.headers.get("Transfer-Encoding")
        if transfer_encoding:
            raise _HTTPInputError(
                HTTPStatus.BAD_REQUEST,
                "unsupported_transfer_encoding",
                "Transfer-Encoding is not supported",
            )
        content_types = self.headers.get_all("Content-Type", [])
        if len(content_types) != 1:
            raise _HTTPInputError(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "invalid_content_type",
                "Content-Type must be application/json",
            )
        media_type = content_types[0].split(";", 1)[0].strip().lower()
        if media_type != "application/json":
            raise _HTTPInputError(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "invalid_content_type",
                "Content-Type must be application/json",
            )
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1:
            raise _HTTPInputError(
                HTTPStatus.BAD_REQUEST,
                "invalid_content_length",
                "a valid Content-Length is required",
            )
        raw_length = lengths[0]
        if (
            not raw_length
            or not all("0" <= character <= "9" for character in raw_length)
        ):
            raise _HTTPInputError(
                HTTPStatus.BAD_REQUEST,
                "invalid_content_length",
                "Content-Length must contain only ASCII decimal digits",
            )
        if len(raw_length) > _MAX_CONTENT_LENGTH_DIGITS:
            raise _HTTPInputError(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "request_too_large",
                "request body exceeds 1 MiB",
            )
        try:
            length = int(raw_length, 10)
        except (TypeError, ValueError, OverflowError) as error:
            raise _HTTPInputError(
                HTTPStatus.BAD_REQUEST,
                "invalid_content_length",
                "Content-Length is invalid",
            ) from error
        if length > self.server.max_request_bytes:
            raise _HTTPInputError(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "request_too_large",
                "request body exceeds 1 MiB",
            )
        if length == 0:
            raise _HTTPInputError(
                HTTPStatus.BAD_REQUEST,
                "malformed_json",
                "request body must contain a JSON object",
            )
        try:
            raw = self.rfile.read(length)
        except (TimeoutError, socket.timeout) as error:
            raise _HTTPInputError(
                HTTPStatus.REQUEST_TIMEOUT,
                "request_timeout",
                "request body timed out",
            ) from error
        if len(raw) != length:
            raise _HTTPInputError(
                HTTPStatus.BAD_REQUEST,
                "incomplete_body",
                "request body is incomplete",
            )
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise _HTTPInputError(
                HTTPStatus.BAD_REQUEST,
                "malformed_json",
                "request body is not valid JSON",
            ) from error

    def _valid_host(self) -> bool:
        values = self.headers.get_all("Host", [])
        if len(values) != 1:
            return False
        value = values[0]
        if any(character.isspace() for character in value):
            return False
        try:
            parsed = urllib.parse.urlsplit("//" + value)
            hostname = parsed.hostname
            port = parsed.port
        except ValueError:
            return False
        if (
            hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or hostname.lower() not in self.server.runtime.allowed_hosts
        ):
            return False
        return port is None or port == self.server.runtime.port

    def _request_path(self) -> str | None:
        try:
            parsed = urllib.parse.urlsplit(self.path)
        except ValueError:
            return None
        if parsed.scheme or parsed.netloc or parsed.fragment:
            return None
        return parsed.path

    def _send_error_json(
        self,
        status: int,
        code: str,
        message: str,
    ) -> None:
        self._send_json(
            status,
            {"error": {"code": code, "message": message}},
        )

    def _send_json(
        self,
        status: int,
        payload: Any,
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        try:
            encoded = json.dumps(
                payload,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
            status = HTTPStatus.INTERNAL_SERVER_ERROR
            encoded = (
                b'{"error":{"code":"invalid_response",'
                b'"message":"runtime response could not be encoded"}}'
            )
            extra_headers = None
        if len(encoded) > MAX_RESPONSE_BYTES:
            status = HTTPStatus.INTERNAL_SERVER_ERROR
            encoded = (
                b'{"error":{"code":"response_too_large",'
                b'"message":"runtime response exceeds the size limit"}}'
            )
            extra_headers = None
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if extra_headers:
            for name, value in extra_headers.items():
                self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(encoded)

    def log_message(self, format: str, *args: object) -> None:
        return


class _HTTPInputError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        self.status = status
        self.code = code
        self.message = message
        super().__init__(message)


def _allowed_host_names(configured: str, bound: str) -> frozenset[str]:
    names = {configured.lower(), bound.lower(), "localhost"}
    if configured == "localhost":
        names.update({"127.0.0.1", "::1"})
    return frozenset(names)


IsolatedRuntimeServer = RuntimeServer
