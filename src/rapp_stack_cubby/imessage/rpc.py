"""Supervised newline-delimited JSON-RPC client for ``imsg rpc`` v0.12.3.

Adapted from ``python/openrappter/imessage/rpc.py`` at the pinned OpenRappter
commit recorded in ``PROVENANCE.json``.
"""

from __future__ import annotations

import json
import subprocess
import threading
import time
from concurrent.futures import Future, TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol


class ImsgRpcError(RuntimeError):
    """Base error for the imsg stdio transport."""


class ImsgRpcTimeout(ImsgRpcError):
    """A request timed out; callers must decide whether the action was ambiguous."""


class ImsgRpcNotSent(ImsgRpcError):
    """A request definitely did not reach the child."""


class ImsgRpcAmbiguous(ImsgRpcError):
    """A mutating request was flushed but its outcome is unknown."""


class ImsgRpcClosed(ImsgRpcError):
    """The child exited or its stdio became unusable."""


class ImsgRpcProtocolError(ImsgRpcError):
    """The child emitted malformed JSON-RPC on stdout."""


class ImsgRpcRemoteError(ImsgRpcError):
    """A structured JSON-RPC error returned by imsg."""

    def __init__(self, message: str, *, code: int | None, data: object, method: str):
        super().__init__(message)
        self.code = code
        self.data = data
        self.method = method


NotificationHandler = Callable[[str, object], bool | None]
DiagnosticHandler = Callable[[str], None]
MAX_RPC_LINE_BYTES = 1024 * 1024
MAX_RPC_REQUEST_BYTES = 256 * 1024
MAX_PREACK_NOTIFICATIONS = 256
MAX_PREACK_BYTES = 4 * 1024 * 1024
MAX_PREACK_AGE_SECONDS = 30.0


class RpcClientLike(Protocol):
    def start(self) -> None: ...

    def stop(self) -> None: ...

    def request(
        self, method: str, params: Mapping[str, object] | None = None, timeout: float | None = None
    ) -> object: ...

    def wait_closed(self, timeout: float | None = None) -> BaseException | None: ...


@dataclass
class _Pending:
    method: str
    future: Future[object]
    flushed: bool = False


@dataclass
class _BufferedNotification:
    method: str
    params: object
    observed_at: float
    size: int


class ImsgRpcClient:
    """One long-lived ``imsg rpc --json`` child.

    Requests are line framed, correlated by monotonically increasing IDs, and
    failed immediately when the child exits. A malformed stdout line is a
    terminal protocol error so a supervisor can replace the child.
    """

    def __init__(
        self,
        imsg_path: str = "imsg",
        *,
        on_notification: NotificationHandler | None = None,
        on_diagnostic: DiagnosticHandler | None = None,
        default_timeout: float = 30.0,
        max_line_bytes: int = MAX_RPC_LINE_BYTES,
        max_request_bytes: int = MAX_RPC_REQUEST_BYTES,
        popen_factory: Callable[..., subprocess.Popen[str]] = subprocess.Popen,
    ) -> None:
        if not isinstance(imsg_path, str) or not imsg_path:
            raise ValueError("imsg_path is required")
        if (
            isinstance(default_timeout, bool)
            or not 0 < float(default_timeout) <= 300
        ):
            raise ValueError("default_timeout must be between 0 and 300 seconds")
        if not isinstance(max_line_bytes, int) or max_line_bytes < 256:
            raise ValueError("max_line_bytes is invalid")
        if not isinstance(max_request_bytes, int) or max_request_bytes < 256:
            raise ValueError("max_request_bytes is invalid")
        self.imsg_path = imsg_path
        self.on_notification = on_notification
        self.on_diagnostic = on_diagnostic
        self.default_timeout = default_timeout
        self.max_line_bytes = max_line_bytes
        self.max_request_bytes = max_request_bytes
        self._popen_factory = popen_factory
        self._process: subprocess.Popen[str] | None = None
        self._pending: dict[str, _Pending] = {}
        self._next_id = 1
        self._lock = threading.RLock()
        self._write_lock = threading.Lock()
        self._closed = threading.Event()
        self._stopping = False
        self._close_error: BaseException | None = None
        self._reader: threading.Thread | None = None
        self._stderr_reader: threading.Thread | None = None

    @property
    def is_running(self) -> bool:
        with self._lock:
            return (
                self._process is not None
                and self._process.poll() is None
                and not self._closed.is_set()
            )

    @property
    def close_error(self) -> BaseException | None:
        return self._close_error

    @property
    def is_closed(self) -> bool:
        return self._closed.is_set()

    def start(self) -> None:
        with self._lock:
            if self.is_running:
                return
            if self._process is not None or self._closed.is_set():
                raise ImsgRpcClosed("an imsg RPC client instance cannot be restarted")
            try:
                process = self._popen_factory(
                    [self.imsg_path, "rpc", "--json"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="strict",
                    bufsize=1,
                    shell=False,
                )
            except (OSError, ValueError) as error:
                raise ImsgRpcClosed("unable to start imsg rpc") from error
            if process.stdin is None or process.stdout is None or process.stderr is None:
                try:
                    process.terminate()
                except (OSError, subprocess.TimeoutExpired):
                    pass
                raise ImsgRpcClosed("imsg rpc stdio pipes are unavailable")
            self._process = process
            self._reader = threading.Thread(
                target=self._read_stdout,
                name="rapp-imsg-stdout",
                daemon=True,
            )
            self._stderr_reader = threading.Thread(
                target=self._read_stderr,
                name="rapp-imsg-stderr",
                daemon=True,
            )
            self._reader.start()
            self._stderr_reader.start()

    def request(
        self,
        method: str,
        params: Mapping[str, object] | None = None,
        timeout: float | None = None,
    ) -> object:
        if (
            not isinstance(method, str)
            or not method
            or len(method) > 128
            or any(ord(character) < 0x21 for character in method)
        ):
            raise ValueError("JSON-RPC method is required")
        if params is not None and not isinstance(params, Mapping):
            raise ValueError("JSON-RPC params must be an object")
        wait_timeout = self.default_timeout if timeout is None else timeout
        if (
            isinstance(wait_timeout, bool)
            or not isinstance(wait_timeout, (int, float))
            or not 0 < float(wait_timeout) <= 300
        ):
            raise ValueError("JSON-RPC timeout must be between 0 and 300 seconds")
        with self._lock:
            process = self._process
            if (
                process is None
                or process.stdin is None
                or process.poll() is not None
                or self._closed.is_set()
            ):
                raise ImsgRpcNotSent("imsg rpc is not running")
            request_id = self._next_id
            self._next_id += 1
            key = str(request_id)
            future: Future[object] = Future()
            self._pending[key] = _Pending(method=method, future=future)

        payload: dict[str, object] = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": dict(params or {}),
        }
        try:
            line = (
                json.dumps(
                    payload,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                )
                + "\n"
            )
        except (TypeError, ValueError) as error:
            self._remove_pending(key)
            raise ImsgRpcNotSent("imsg rpc request is not JSON encodable") from error
        if len(line.encode("utf-8")) > self.max_request_bytes:
            self._remove_pending(key)
            raise ImsgRpcNotSent("imsg rpc request exceeds the size limit")
        try:
            with self._write_lock:
                with self._lock:
                    if (
                        self._process is not process
                        or process.poll() is not None
                        or self._closed.is_set()
                    ):
                        raise BrokenPipeError("imsg rpc closed before write")
                    process.stdin.write(line)
                    process.stdin.flush()
                    pending = self._pending.get(key)
                    if pending is not None:
                        pending.flushed = True
        except (BrokenPipeError, OSError, ValueError) as error:
            self._remove_pending(key)
            not_sent = ImsgRpcNotSent("imsg rpc request was not flushed")
            if not future.done():
                future.set_exception(not_sent)
            self._finish(not_sent)
            self._terminate_process()
            raise not_sent from error

        try:
            return future.result(timeout=float(wait_timeout))
        except FutureTimeoutError as error:
            pending = self._remove_pending(key)
            if pending is not None and not pending.future.done():
                pending.future.cancel()
            if method == "send":
                self._terminate_process(
                    ImsgRpcAmbiguous(f"imsg rpc outcome unknown ({method})")
                )
                raise ImsgRpcAmbiguous(f"imsg rpc outcome unknown ({method})") from error
            self._terminate_process(ImsgRpcTimeout(f"imsg rpc timeout ({method})"))
            raise ImsgRpcTimeout(f"imsg rpc timeout ({method})") from error

    def wait_closed(self, timeout: float | None = None) -> BaseException | None:
        if timeout is not None and (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not 0 <= float(timeout) <= 300
        ):
            raise ValueError("close timeout must be between 0 and 300 seconds")
        if not self._closed.wait(timeout):
            return None
        return self._close_error

    def stop(self) -> None:
        with self._lock:
            if self._stopping:
                return
            self._stopping = True
            process = self._process
        if process is None:
            self._finish(ImsgRpcClosed("imsg rpc stopped"))
            return
        self._close_terminate_kill(process)
        self._finish(ImsgRpcClosed("imsg rpc stopped"))
        self._close_streams_and_join(process)

    def _read_stdout(self) -> None:
        process = self._process
        if process is None or process.stdout is None:
            return
        try:
            while True:
                line = process.stdout.readline(self.max_line_bytes + 1)
                if line == "":
                    break
                if (
                    len(line.encode("utf-8")) > self.max_line_bytes
                    or not line.endswith("\n")
                ):
                    self._protocol_failure("imsg rpc line exceeds the framing bound")
                    return
                if line.strip():
                    self._handle_line(line)
                if self._closed.is_set():
                    return
        except (OSError, UnicodeError, ValueError) as error:
            protocol_error = ImsgRpcProtocolError("imsg rpc stdout framing failed")
            self._finish(protocol_error)
            self._terminate_process(protocol_error)
            if self.on_diagnostic:
                self.on_diagnostic(type(error).__name__)
            return

        try:
            code = process.wait()
        except (OSError, ValueError):
            code = None
        if self._stopping:
            self._finish(ImsgRpcClosed("imsg rpc stopped"))
        elif code in (0, None):
            self._finish(ImsgRpcClosed("imsg rpc closed"))
        else:
            self._finish(ImsgRpcClosed(f"imsg rpc exited (code {code})"))

    def _read_stderr(self) -> None:
        process = self._process
        if process is None or process.stderr is None:
            return
        try:
            for line in process.stderr:
                if line.strip() and self.on_diagnostic:
                    # Never surface raw stderr: it can contain transport data.
                    self.on_diagnostic("imsg rpc diagnostic")
        except (OSError, UnicodeError, ValueError):
            if self.on_diagnostic:
                self.on_diagnostic("imsg rpc stderr unavailable")

    def _handle_line(self, line: str) -> None:
        if len(line.encode("utf-8")) > self.max_line_bytes:
            self._protocol_failure("imsg rpc line exceeds the framing bound")
            return
        try:
            message = json.loads(line)
        except (json.JSONDecodeError, RecursionError) as error:
            self._protocol_failure("imsg rpc emitted malformed JSON", error)
            return
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            self._protocol_failure("imsg rpc emitted an invalid JSON-RPC envelope")
            return

        if "id" in message and message["id"] is not None:
            if set(message) - {"jsonrpc", "id", "result", "error"}:
                self._protocol_failure("imsg rpc response contains unknown fields")
                return
            if ("result" in message) == ("error" in message):
                self._protocol_failure("imsg rpc response result is ambiguous")
                return
            response_id = message["id"]
            if (
                isinstance(response_id, bool)
                or not isinstance(response_id, int)
                or response_id < 1
            ):
                self._protocol_failure("imsg rpc response id is invalid")
                return
            key = str(response_id)
            pending = self._remove_pending(key)
            if pending is None:
                return
            error_value = message.get("error")
            if error_value is not None:
                if isinstance(error_value, Mapping):
                    text = "imsg rpc remote error"
                    code = error_value.get("code")
                    if isinstance(code, int):
                        text = f"{text} (code {code})"
                    else:
                        code = None
                    data = None
                else:
                    text = "imsg rpc error"
                    code = None
                    data = None
                pending.future.set_exception(
                    ImsgRpcRemoteError(
                        text,
                        code=code,
                        data=data,
                        method=pending.method,
                    )
                )
            else:
                pending.future.set_result(message["result"])
            return

        if set(message) - {"jsonrpc", "method", "params"}:
            self._protocol_failure("imsg rpc notification contains unknown fields")
            return
        method = message.get("method")
        if not isinstance(method, str) or not method:
            self._protocol_failure("imsg rpc notification has no method")
            return
        if self.on_notification:
            try:
                self.on_notification(method, message.get("params"))
            except Exception:
                if self.on_diagnostic:
                    self.on_diagnostic("imsg notification handler failed")

    def _protocol_failure(self, message: str, cause: BaseException | None = None) -> None:
        error = ImsgRpcProtocolError(message)
        if cause is not None:
            error.__cause__ = cause
        self._finish(error)
        self._terminate_process(error)

    def _remove_pending(self, key: str) -> _Pending | None:
        with self._lock:
            return self._pending.pop(key, None)

    def _finish(self, error: BaseException) -> None:
        with self._lock:
            if self._closed.is_set():
                return
            self._close_error = error
            pending = list(self._pending.values())
            self._pending.clear()
            self._closed.set()
        for item in pending:
            if not item.future.done():
                if item.method == "send" and item.flushed:
                    item.future.set_exception(
                        ImsgRpcAmbiguous("imsg rpc closed after send was flushed")
                    )
                else:
                    item.future.set_exception(error)

    def _terminate_process(self, error: BaseException | None = None) -> None:
        with self._lock:
            process = self._process
        if process is None:
            if error is not None:
                self._finish(error)
            return
        self._close_terminate_kill(process)
        self._finish(error or ImsgRpcClosed("imsg rpc terminated"))
        self._close_streams_and_join(process)

    @staticmethod
    def _close_terminate_kill(process: subprocess.Popen[str]) -> None:
        try:
            if process.stdin is not None:
                process.stdin.close()
        except OSError:
            pass
        try:
            process.wait(timeout=0.5)
            return
        except (OSError, subprocess.TimeoutExpired):
            pass
        try:
            process.terminate()
        except OSError:
            pass
        try:
            process.wait(timeout=0.5)
            return
        except (OSError, subprocess.TimeoutExpired):
            pass
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=0.5)
        except (OSError, subprocess.TimeoutExpired):
            pass

    def _close_streams_and_join(self, process: subprocess.Popen[str]) -> None:
        for thread in (self._reader, self._stderr_reader):
            if thread is not None and thread is not threading.current_thread():
                thread.join(timeout=0.5)
        for stream, thread in (
            (process.stdout, self._reader),
            (process.stderr, self._stderr_reader),
        ):
            if (
                stream is not None
                and thread is not threading.current_thread()
                and (thread is None or not thread.is_alive())
            ):
                try:
                    stream.close()
                except OSError:
                    pass


class ImsgRpcSupervisor:
    """Own one generation-bound RPC child and its acknowledged watch stream."""

    def __init__(
        self,
        client_factory: Callable[[NotificationHandler], RpcClientLike],
        *,
        on_notification: NotificationHandler,
        on_ready: Callable[[RpcClientLike], None] | None = None,
        restart_initial: float = 0.25,
        restart_max: float = 8.0,
        stable_reset_seconds: float = 30.0,
        max_consecutive_restarts: int = 8,
        activity_timeout: float = 20.0,
        preack_max_count: int = MAX_PREACK_NOTIFICATIONS,
        preack_max_bytes: int = MAX_PREACK_BYTES,
        preack_max_age: float = MAX_PREACK_AGE_SECONDS,
    ) -> None:
        if restart_initial < 0 or restart_max < restart_initial:
            raise ValueError("restart bounds are invalid")
        if not isinstance(max_consecutive_restarts, int) or max_consecutive_restarts < 1:
            raise ValueError("max_consecutive_restarts must be positive")
        for name, value, maximum in (
            ("stable_reset_seconds", stable_reset_seconds, 3600),
            ("activity_timeout", activity_timeout, 3600),
            ("preack_max_age", preack_max_age, 300),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not 0 < float(value) <= maximum
            ):
                raise ValueError(f"{name} is invalid")
        if (
            not isinstance(preack_max_count, int)
            or isinstance(preack_max_count, bool)
            or not 1 <= preack_max_count <= 10000
        ):
            raise ValueError("preack_max_count is invalid")
        if (
            not isinstance(preack_max_bytes, int)
            or isinstance(preack_max_bytes, bool)
            or not 256 <= preack_max_bytes <= 64 * 1024 * 1024
        ):
            raise ValueError("preack_max_bytes is invalid")
        self._client_factory = client_factory
        self._on_notification = on_notification
        self._on_ready = on_ready
        self._restart_initial = restart_initial
        self._restart_max = restart_max
        self._stable_reset_seconds = float(stable_reset_seconds)
        self._max_consecutive_restarts = max_consecutive_restarts
        self._activity_timeout = float(activity_timeout)
        self._preack_max_count = preack_max_count
        self._preack_max_bytes = preack_max_bytes
        self._preack_max_age = float(preack_max_age)
        self._stop_event = threading.Event()
        self._ready_event = threading.Event()
        self._terminal_event = threading.Event()
        self._lock = threading.RLock()
        self._client: RpcClientLike | None = None
        self._thread: threading.Thread | None = None
        self._last_error: str | None = None
        self._restart_count = 0
        self._restart_epoch = 0
        self._generation = 0
        self._active_generation: int | None = None
        self._generation_phase = "idle"
        self._generation_error: BaseException | None = None
        self._preack: list[_BufferedNotification] = []
        self._preack_bytes = 0
        self._last_activity: float | None = None

    @property
    def is_connected(self) -> bool:
        return self._ready_event.is_set()

    @property
    def is_ready(self) -> bool:
        if not self._ready_event.is_set():
            return False
        with self._lock:
            observed = self._last_activity
        return (
            observed is not None
            and time.monotonic() - observed <= self._activity_timeout
        )

    @property
    def restart_count(self) -> int:
        with self._lock:
            return self._restart_count

    @property
    def last_error(self) -> str | None:
        with self._lock:
            return self._last_error

    @property
    def terminal(self) -> bool:
        return self._terminal_event.is_set()

    def start(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._terminal_event.clear()
            self._thread = threading.Thread(
                target=self._run,
                name="rapp-imsg-supervisor",
                daemon=True,
            )
            self._thread.start()

    def request(
        self,
        method: str,
        params: Mapping[str, object] | None = None,
        timeout: float | None = None,
    ) -> object:
        ready_timeout = 30.0 if timeout is None else timeout
        if (
            isinstance(ready_timeout, bool)
            or not isinstance(ready_timeout, (int, float))
            or not 0 < float(ready_timeout) <= 300
        ):
            raise ValueError("RPC timeout must be between 0 and 300 seconds")
        if not self._ready_event.wait(ready_timeout):
            raise ImsgRpcNotSent("imsg rpc transport is not ready")
        with self._lock:
            client = self._client
            generation = self._active_generation
        if client is None or generation is None:
            raise ImsgRpcClosed("imsg rpc transport is not ready")
        # Never retry here. A mutating request may have reached Messages.
        result = client.request(method, params, timeout)
        self._record_activity(generation, client)
        return result

    def stop(self) -> None:
        self._stop_event.set()
        self._ready_event.clear()
        with self._lock:
            self._restart_epoch += 1
            self._generation_phase = "stopping"
            client = self._client
            thread = self._thread
        if client is not None:
            client.stop()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=4.0)

    def restart(self) -> None:
        """Terminate this generation, including while startup is in progress."""

        self._ready_event.clear()
        with self._lock:
            self._restart_epoch += 1
            self._generation_phase = "restarting"
            client = self._client
        if client is not None:
            client.stop()

    def _run(self) -> None:
        backoff = self._restart_initial
        consecutive = 0
        while not self._stop_event.is_set():
            started_at = time.monotonic()
            client: RpcClientLike | None = None
            with self._lock:
                self._generation += 1
                generation = self._generation
                restart_epoch = self._restart_epoch
            try:
                client = self._client_factory(
                    lambda method, params, selected=generation: (
                        self._deliver_notification(selected, method, params)
                    )
                )
                with self._lock:
                    if (
                        self._stop_event.is_set()
                        or restart_epoch != self._restart_epoch
                    ):
                        raise ImsgRpcClosed("imsg rpc startup was cancelled")
                    self._client = client
                    self._active_generation = generation
                    self._generation_phase = "starting"
                    self._generation_error = None
                    self._preack = []
                    self._preack_bytes = 0
                    self._last_activity = None
                client.start()
                self._assert_generation(generation, client, restart_epoch)
                if self._on_ready:
                    self._on_ready(client)
                self._assert_generation(generation, client, restart_epoch)
                self._drain_preack(generation, client, restart_epoch)
                close_error = self._wait_for_close(
                    generation,
                    client,
                    restart_epoch,
                )
                if close_error is not None:
                    raise close_error
            except BaseException as error:
                if self._stop_event.is_set():
                    break
                with self._lock:
                    self._last_error = type(error).__name__
                    self._restart_count += 1
                consecutive += 1
            finally:
                self._ready_event.clear()
                with self._lock:
                    if self._client is client:
                        self._client = None
                        self._active_generation = None
                        self._generation_phase = "idle"
                        self._generation_error = None
                        self._preack = []
                        self._preack_bytes = 0
                        self._last_activity = None
                if client is not None:
                    try:
                        client.stop()
                    except Exception:
                        pass

            if self._stop_event.is_set():
                break
            lifetime = time.monotonic() - started_at
            if lifetime >= self._stable_reset_seconds:
                backoff = self._restart_initial
                consecutive = 0
            if consecutive >= self._max_consecutive_restarts:
                with self._lock:
                    self._last_error = "restart_limit"
                self._terminal_event.set()
                return
            if self._stop_event.wait(backoff):
                break
            backoff = min(self._restart_max, max(self._restart_initial, backoff * 2))

    def _assert_generation(
        self,
        generation: int,
        client: RpcClientLike,
        restart_epoch: int,
    ) -> None:
        with self._lock:
            error = self._generation_error
            current = (
                self._client is client
                and self._active_generation == generation
                and self._restart_epoch == restart_epoch
            )
        if error is not None:
            raise error
        if self._stop_event.is_set() or not current:
            raise ImsgRpcClosed("imsg rpc generation was replaced during startup")

    def _drain_preack(
        self,
        generation: int,
        client: RpcClientLike,
        restart_epoch: int,
    ) -> None:
        while True:
            self._assert_generation(generation, client, restart_epoch)
            with self._lock:
                if self._preack:
                    item = self._preack.pop(0)
                    self._preack_bytes -= item.size
                else:
                    self._generation_phase = "ready"
                    self._last_activity = time.monotonic()
                    self._last_error = None
                    self._ready_event.set()
                    return
            if time.monotonic() - item.observed_at > self._preack_max_age:
                raise ImsgRpcProtocolError(
                    "imsg pre-ack notification exceeded the age bound"
                )
            accepted = self._on_notification(item.method, item.params)
            if accepted is not False:
                self._record_activity(generation, client)

    def _wait_for_close(
        self,
        generation: int,
        client: RpcClientLike,
        restart_epoch: int,
    ) -> BaseException | None:
        while True:
            close_error = client.wait_closed(timeout=0.25)
            if close_error is not None:
                return close_error
            with self._lock:
                current = (
                    self._client is client
                    and self._active_generation == generation
                    and self._restart_epoch == restart_epoch
                )
            if self._stop_event.is_set():
                return None
            if not current:
                return ImsgRpcClosed("imsg rpc generation restart requested")
            if getattr(client, "is_closed", False):
                return ImsgRpcClosed("imsg rpc closed")

    def _deliver_notification(
        self,
        generation: int,
        method: str,
        params: object,
    ) -> None:
        size = self._notification_size(method, params)
        now = time.monotonic()
        stop_client: RpcClientLike | None = None
        deliver = False
        with self._lock:
            if (
                generation != self._active_generation
                or self._client is None
                or self._generation_phase in {"idle", "restarting", "stopping"}
            ):
                return
            if self._generation_phase in {"starting", "draining"}:
                oldest_too_old = bool(
                    self._preack
                    and now - self._preack[0].observed_at > self._preack_max_age
                )
                if (
                    oldest_too_old
                    or len(self._preack) >= self._preack_max_count
                    or self._preack_bytes + size > self._preack_max_bytes
                ):
                    self._generation_error = ImsgRpcProtocolError(
                        "imsg pre-ack notification buffer bound exceeded"
                    )
                    stop_client = self._client
                else:
                    self._preack.append(
                        _BufferedNotification(method, params, now, size)
                    )
                    self._preack_bytes += size
                return_after_lock = True
            else:
                deliver = True
                return_after_lock = False
        if stop_client is not None:
            stop_client.stop()
        if return_after_lock:
            return
        if deliver:
            accepted = self._on_notification(method, params)
            with self._lock:
                client = self._client
            if accepted is not False and client is not None:
                self._record_activity(generation, client)

    def _record_activity(
        self,
        generation: int,
        client: RpcClientLike,
    ) -> None:
        with self._lock:
            if (
                self._client is client
                and self._active_generation == generation
                and self._generation_phase in {"draining", "ready"}
            ):
                self._last_activity = time.monotonic()

    def _notification_size(self, method: str, params: object) -> int:
        try:
            encoded = json.dumps(
                [method, params],
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError, RecursionError):
            return self._preack_max_bytes + 1
        return len(encoded)
