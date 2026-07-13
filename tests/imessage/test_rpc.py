from __future__ import annotations

import json
import os
import threading
import time
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest import mock

from rapp_stack_cubby.imessage.rpc import (
    ImsgRpcAmbiguous,
    ImsgRpcClient,
    ImsgRpcClosed,
    ImsgRpcNotSent,
    ImsgRpcProtocolError,
    ImsgRpcSupervisor,
    ImsgRpcTimeout,
)

from ._support import WorkDirectory


def wait_until(predicate: Callable[[], bool], *, timeout: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def fake_imsg(root: Path, mode: str) -> Path:
    path = root / "fake-imsg"
    path.write_text(
        """#!/usr/bin/env python3
import json
import os
import signal
import sys
import time

mode = os.environ.get("FAKE_IMSG_MODE", "normal")
if sys.argv[1:] != ["rpc", "--json"]:
    raise SystemExit(3)
if mode == "ignore-terminate":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
if mode == "oversized":
    print(json.dumps({"jsonrpc":"2.0","method":"notice","params":"x" * 4096}), flush=True)
    time.sleep(1)
if mode == "reverse":
    first = json.loads(sys.stdin.readline())
    second = json.loads(sys.stdin.readline())
    for request in (second, first):
        print(json.dumps({"jsonrpc":"2.0","id":request["id"],"result":request["method"]}), flush=True)
    time.sleep(0.1)
for line in sys.stdin:
    request = json.loads(line)
    if mode == "malformed":
        print("{", flush=True)
        time.sleep(0.1)
        continue
    if mode == "exit":
        raise SystemExit(7)
    if mode in ("hang", "ignore-terminate"):
        time.sleep(5)
        continue
    print(json.dumps({"jsonrpc":"2.0","method":"notice","params":{"safe":True}}), flush=True)
    print(json.dumps({"jsonrpc":"2.0","id":request["id"],"result":{"method":request["method"]}}), flush=True)
""",
        encoding="utf-8",
    )
    os.chmod(path, 0o700)
    return path


class IMessageRpcTests(unittest.TestCase):
    def test_fixed_argv_framing_notification_and_correlation(self) -> None:
        with WorkDirectory() as root:
            path = fake_imsg(root, "normal")
            notices: list[tuple[str, object]] = []
            with mock.patch.dict(os.environ, {"FAKE_IMSG_MODE": "normal"}):
                client = ImsgRpcClient(
                    str(path),
                    on_notification=lambda method, params: notices.append((method, params)),
                )
                client.start()
                result = client.request("chats.list", {"limit": 1})
                client.stop()
            self.assertEqual(result, {"method": "chats.list"})
            self.assertEqual(notices, [("notice", {"safe": True})])

    def test_reverse_responses_remain_correlated(self) -> None:
        with WorkDirectory() as root:
            path = fake_imsg(root, "reverse")
            values: dict[str, object] = {}
            with mock.patch.dict(os.environ, {"FAKE_IMSG_MODE": "reverse"}):
                client = ImsgRpcClient(str(path), default_timeout=1)
                client.start()
                threads = [
                    threading.Thread(
                        target=lambda name=name: values.setdefault(
                            name, client.request(name)
                        )
                    )
                    for name in ("first", "second")
                ]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()
                client.stop()
            self.assertEqual(values, {"first": "first", "second": "second"})

    def test_malformed_and_oversized_lines_close_the_child(self) -> None:
        with WorkDirectory() as root:
            path = fake_imsg(root, "malformed")
            for mode, maximum in (("malformed", 1024), ("oversized", 512)):
                with self.subTest(mode=mode):
                    with mock.patch.dict(
                        os.environ, {"FAKE_IMSG_MODE": mode}
                    ):
                        client = ImsgRpcClient(
                            str(path),
                            default_timeout=1,
                            max_line_bytes=maximum,
                        )
                        client.start()
                        if mode == "malformed":
                            with self.assertRaises(ImsgRpcProtocolError):
                                client.request("probe")
                        else:
                            error = client.wait_closed(1)
                            self.assertIsInstance(error, ImsgRpcProtocolError)
                        client.stop()

    def test_not_sent_timeout_and_ambiguous_after_flush_are_distinct(self) -> None:
        with WorkDirectory() as root:
            missing = ImsgRpcClient(str(root / "missing"))
            with self.assertRaises(ImsgRpcNotSent):
                missing.request("send")
            with self.assertRaises(ImsgRpcClosed):
                missing.start()
            path = fake_imsg(root, "hang")
            with mock.patch.dict(os.environ, {"FAKE_IMSG_MODE": "hang"}):
                read_client = ImsgRpcClient(str(path), default_timeout=0.05)
                read_client.start()
                with self.assertRaises(ImsgRpcTimeout):
                    read_client.request("chats.list")
                read_client.stop()
            with mock.patch.dict(os.environ, {"FAKE_IMSG_MODE": "hang"}):
                send_client = ImsgRpcClient(str(path), default_timeout=0.05)
                send_client.start()
                with self.assertRaises(ImsgRpcAmbiguous):
                    send_client.request("send")
                send_client.stop()

    def test_send_is_never_retried_by_supervisor(self) -> None:
        class Client:
            def __init__(self) -> None:
                self.calls = 0

            def request(self, method, params=None, timeout=None):
                self.calls += 1
                raise ImsgRpcAmbiguous("unknown")

        client = Client()
        supervisor = ImsgRpcSupervisor(
            lambda callback: client,
            on_notification=lambda method, params: None,
        )
        supervisor._client = client
        supervisor._active_generation = 1
        supervisor._generation_phase = "ready"
        supervisor._ready_event.set()
        with self.assertRaises(ImsgRpcAmbiguous):
            supervisor.request("send", {"text": "synthetic"})
        self.assertEqual(client.calls, 1)

    def test_child_exit_after_flushed_send_is_ambiguous(self) -> None:
        with WorkDirectory() as root:
            path = fake_imsg(root, "exit")
            with mock.patch.dict(os.environ, {"FAKE_IMSG_MODE": "exit"}):
                client = ImsgRpcClient(str(path), default_timeout=1)
                client.start()
                with self.assertRaises(ImsgRpcAmbiguous):
                    client.request("send", {"text": "synthetic"})
                client.stop()

    def test_supervisor_replaces_child_after_restart_signal(self) -> None:
        created: list[object] = []
        ready_twice = threading.Event()

        class Client:
            def __init__(self) -> None:
                self.closed = threading.Event()

            def start(self) -> None:
                return None

            def stop(self) -> None:
                self.closed.set()

            def wait_closed(self, timeout=None):
                self.closed.wait(timeout)
                return ImsgRpcClosed("closed")

            def request(self, method, params=None, timeout=None):
                return {}

        def factory(callback):
            client = Client()
            created.append(client)
            return client

        def on_ready(client):
            if len(created) >= 2:
                ready_twice.set()

        supervisor = ImsgRpcSupervisor(
            factory,
            on_notification=lambda method, params: None,
            on_ready=on_ready,
            restart_initial=0.01,
            restart_max=0.02,
        )
        supervisor.start()
        for _ in range(100):
            if supervisor.is_ready:
                break
            threading.Event().wait(0.01)
        self.assertTrue(supervisor.is_ready)
        supervisor.restart()
        self.assertTrue(ready_twice.wait(1))
        self.assertGreaterEqual(len(created), 2)
        supervisor.stop()

    def test_supervisor_surfaces_terminal_restart_exhaustion(self) -> None:
        class FailingClient:
            def start(self) -> None:
                raise ImsgRpcClosed("synthetic startup failure")

            def stop(self) -> None:
                return None

            def wait_closed(self, timeout=None):
                return ImsgRpcClosed("closed")

            def request(self, method, params=None, timeout=None):
                raise ImsgRpcNotSent("not ready")

        supervisor = ImsgRpcSupervisor(
            lambda callback: FailingClient(),
            on_notification=lambda method, params: None,
            restart_initial=0.01,
            restart_max=0.01,
            max_consecutive_restarts=2,
        )
        supervisor.start()
        for _ in range(100):
            if supervisor.terminal:
                break
            threading.Event().wait(0.01)
        self.assertTrue(supervisor.terminal)
        self.assertFalse(supervisor.is_ready)
        self.assertEqual(supervisor.last_error, "restart_limit")
        supervisor.stop()

    def test_preack_notifications_drain_in_order_after_ack(self) -> None:
        delivered: list[tuple[str, int]] = []
        acknowledged: dict[str, int | None] = {"subscription": None}

        class Client:
            def __init__(self, callback) -> None:
                self.callback = callback
                self.closed = threading.Event()

            def start(self):
                return None

            def stop(self):
                self.closed.set()

            def wait_closed(self, timeout=None):
                if self.closed.wait(timeout):
                    return ImsgRpcClosed("closed")
                return None

            def request(self, method, params=None, timeout=None):
                return {}

        clients: list[Client] = []

        def factory(callback):
            client = Client(callback)
            clients.append(client)
            return client

        def on_ready(client):
            client.callback("message", {"subscription": 7, "sequence": 1})
            client.callback("message", {"subscription": 8, "sequence": 99})
            client.callback("message", {"subscription": 7, "sequence": 2})
            self.assertEqual(delivered, [])
            acknowledged["subscription"] = 7

        def notification(method, params):
            if params["subscription"] == acknowledged["subscription"]:
                delivered.append((method, params["sequence"]))

        supervisor = ImsgRpcSupervisor(
            factory,
            on_notification=notification,
            on_ready=on_ready,
            restart_initial=0.01,
            restart_max=0.01,
        )
        supervisor.start()
        for _ in range(100):
            if supervisor.is_connected:
                break
            time.sleep(0.01)
        self.assertTrue(supervisor.is_connected)
        self.assertEqual(delivered, [("message", 1), ("message", 2)])
        clients[0].callback("message", {"subscription": 7, "sequence": 3})
        self.assertEqual(
            delivered,
            [("message", 1), ("message", 2), ("message", 3)],
        )
        supervisor.stop()

    def test_buffered_matching_error_restarts_but_wrong_error_does_not(self) -> None:
        clients: list[object] = []
        second_ready = threading.Event()
        acknowledged = 0

        class Client:
            def __init__(self, callback) -> None:
                self.callback = callback
                self.closed = threading.Event()

            def start(self):
                return None

            def stop(self):
                self.closed.set()

            def wait_closed(self, timeout=None):
                if self.closed.wait(timeout):
                    return ImsgRpcClosed("closed")
                return None

            def request(self, method, params=None, timeout=None):
                return {}

        def factory(callback):
            client = Client(callback)
            clients.append(client)
            return client

        def on_ready(client):
            nonlocal acknowledged
            acknowledged = len(clients)
            client.callback("error", {"subscription": acknowledged + 100})
            if acknowledged == 1:
                client.callback("error", {"subscription": acknowledged})
            else:
                second_ready.set()

        supervisor: ImsgRpcSupervisor

        def notification(method, params):
            if method == "error" and params["subscription"] == acknowledged:
                supervisor.restart()

        supervisor = ImsgRpcSupervisor(
            factory,
            on_notification=notification,
            on_ready=on_ready,
            restart_initial=0.01,
            restart_max=0.01,
        )
        supervisor.start()
        self.assertTrue(second_ready.wait(1))
        for _ in range(100):
            if supervisor.is_connected:
                break
            time.sleep(0.01)
        self.assertTrue(supervisor.is_connected)
        self.assertEqual(len(clients), 2)
        self.assertEqual(supervisor.restart_count, 1)
        supervisor.stop()

    def test_old_generation_notification_loses_restart_race(self) -> None:
        delivered: list[int] = []
        clients: list[object] = []

        class Client:
            def __init__(self, callback) -> None:
                self.callback = callback
                self.closed = threading.Event()

            def start(self):
                return None

            def stop(self):
                self.closed.set()

            def wait_closed(self, timeout=None):
                if self.closed.wait(timeout):
                    return ImsgRpcClosed("closed")
                return None

            def request(self, method, params=None, timeout=None):
                return {}

        def factory(callback):
            client = Client(callback)
            clients.append(client)
            return client

        supervisor = ImsgRpcSupervisor(
            factory,
            on_notification=lambda method, params: delivered.append(
                params["sequence"]
            ),
            restart_initial=0.01,
            restart_max=0.01,
        )
        supervisor.start()
        for _ in range(100):
            if supervisor.is_connected:
                break
            time.sleep(0.01)
        old_callback = clients[0].callback
        supervisor.restart()
        for _ in range(100):
            if len(clients) >= 2 and supervisor.is_connected:
                break
            time.sleep(0.01)
        self.assertEqual(len(clients), 2)
        old_callback("message", {"sequence": 1})
        clients[1].callback("message", {"sequence": 2})
        self.assertEqual(delivered, [2])
        supervisor.stop()

    def test_preack_buffer_count_bytes_and_age_are_bounded(self) -> None:
        cases = ("count", "bytes", "age")
        for case in cases:
            with self.subTest(case=case):
                class Client:
                    def __init__(self, callback) -> None:
                        self.callback = callback
                        self.closed = threading.Event()

                    def start(self):
                        return None

                    def stop(self):
                        self.closed.set()

                    def wait_closed(self, timeout=None):
                        if self.closed.wait(timeout):
                            return ImsgRpcClosed("closed")
                        return None

                    def request(self, method, params=None, timeout=None):
                        return {}

                def factory(callback):
                    return Client(callback)

                def on_ready(client):
                    if case == "count":
                        client.callback("message", {"sequence": 1})
                        client.callback("message", {"sequence": 2})
                    elif case == "bytes":
                        client.callback("message", {"value": "x" * 512})
                    else:
                        client.callback("message", {"sequence": 1})
                        time.sleep(0.03)

                supervisor = ImsgRpcSupervisor(
                    factory,
                    on_notification=lambda method, params: None,
                    on_ready=on_ready,
                    restart_initial=0,
                    restart_max=0,
                    max_consecutive_restarts=1,
                    preack_max_count=1,
                    preack_max_bytes=256,
                    preack_max_age=0.01,
                )
                supervisor.start()
                for _ in range(100):
                    if supervisor.terminal:
                        break
                    time.sleep(0.01)
                self.assertTrue(supervisor.terminal)
                self.assertFalse(supervisor.is_connected)
                supervisor.stop()

    def test_restart_and_stop_are_honored_during_on_ready(self) -> None:
        for action in ("restart", "stop"):
            with self.subTest(action=action):
                clients: list[object] = []
                completed = threading.Event()

                class Client:
                    def __init__(self) -> None:
                        self.closed = threading.Event()

                    def start(self):
                        return None

                    def stop(self):
                        self.closed.set()

                    def wait_closed(self, timeout=None):
                        if self.closed.wait(timeout):
                            return ImsgRpcClosed("closed")
                        return None

                    def request(self, method, params=None, timeout=None):
                        return {}

                def factory(callback):
                    client = Client()
                    clients.append(client)
                    return client

                supervisor: ImsgRpcSupervisor

                def on_ready(client):
                    if len(clients) == 1:
                        getattr(supervisor, action)()
                    else:
                        completed.set()

                supervisor = ImsgRpcSupervisor(
                    factory,
                    on_notification=lambda method, params: None,
                    on_ready=on_ready,
                    restart_initial=0.01,
                    restart_max=0.01,
                )
                supervisor.start()
                if action == "restart":
                    self.assertTrue(completed.wait(1))
                    self.assertEqual(len(clients), 2)
                    supervisor.stop()
                else:
                    for _ in range(100):
                        thread = supervisor._thread
                        if thread is not None and not thread.is_alive():
                            break
                        time.sleep(0.01)
                    self.assertEqual(len(clients), 1)
                    self.assertFalse(supervisor.is_connected)
                self.assertTrue(clients[0].closed.is_set())

    def test_timeout_kills_child_that_ignores_terminate(self) -> None:
        with WorkDirectory() as root:
            path = fake_imsg(root, "ignore-terminate")
            with mock.patch.dict(
                os.environ,
                {"FAKE_IMSG_MODE": "ignore-terminate"},
            ):
                client = ImsgRpcClient(str(path), default_timeout=0.05)
                client.start()
                started = time.monotonic()
                with self.assertRaises(ImsgRpcTimeout):
                    client.request("chats.list")
                elapsed = time.monotonic() - started
                process = client._process
                self.assertLess(elapsed, 2.5)
                self.assertTrue(client.is_closed)
                self.assertIsNotNone(process)
                self.assertIsNotNone(process.poll())
                client.stop()

    def test_ready_expires_without_recent_activity_and_rpc_refreshes_it(self) -> None:
        class Client:
            is_closed = False

            def __init__(self) -> None:
                self.closed = threading.Event()

            def start(self):
                return None

            def stop(self):
                self.closed.set()
                self.is_closed = True

            def wait_closed(self, timeout=None):
                if self.closed.wait(timeout):
                    return ImsgRpcClosed("closed")
                return None

            def request(self, method, params=None, timeout=None):
                return {"ok": True}

        clients: list[Client] = []
        callbacks: list[object] = []

        def factory(callback):
            client = Client()
            clients.append(client)
            callbacks.append(callback)
            return client

        supervisor = ImsgRpcSupervisor(
            factory,
            on_notification=lambda method, params: False,
            activity_timeout=0.5,
        )
        supervisor.start()
        try:
            self.assertTrue(wait_until(lambda: supervisor.is_ready))
            with supervisor._lock:
                initial_activity = supervisor._last_activity
            callbacks[0]("message", {"subscription": "stale"})
            with supervisor._lock:
                self.assertEqual(supervisor._last_activity, initial_activity)
            self.assertTrue(
                wait_until(lambda: not supervisor.is_ready, timeout=2.0)
            )
            self.assertTrue(supervisor.is_connected)
            self.assertEqual(supervisor.request("chats.list"), {"ok": True})
            self.assertTrue(wait_until(lambda: supervisor.is_ready))
            with supervisor._lock:
                self.assertGreater(supervisor._last_activity, initial_activity)
        finally:
            supervisor.stop()


if __name__ == "__main__":
    unittest.main()
