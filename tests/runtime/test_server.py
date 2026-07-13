from __future__ import annotations

import concurrent.futures
import http.client
import json
import socket
import unittest
from unittest.mock import patch

from rapp_stack_cubby.runtime.orchestrator import Orchestrator
from rapp_stack_cubby.runtime.provider import ProviderResponse, ScriptedProvider
from rapp_stack_cubby.runtime.registry import AgentRegistry
from rapp_stack_cubby.runtime.server import MAX_REQUEST_BYTES, RuntimeServer
from rapp_stack_cubby.runtime.storage import LocalStorage

from ._support import ECHO_AGENT, RuntimeFixture


class LiveServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = RuntimeFixture()
        self.fixture.write_agent("echo_agent.py", ECHO_AGENT)
        self.provider = ScriptedProvider(
            [ProviderResponse(content="ok", model="live-model") for _ in range(64)]
        )
        registry = AgentRegistry(
            self.fixture.agents,
            storage=LocalStorage(self.fixture.data),
            compatibility_mode=True,
        )
        orchestrator = Orchestrator(
            soul_path=self.fixture.soul,
            registry=registry,
            provider=self.provider,
            model="requested-model",
        )
        self.server: RuntimeServer | None = RuntimeServer(
            orchestrator,
            host="127.0.0.1",
            port=0,
            request_timeout=2,
            instance_id="live-test-instance",
        )
        self.server.start()

    def tearDown(self) -> None:
        if self.server is not None:
            self.server.shutdown()
        self.fixture.cleanup()

    def test_health_is_json_and_contains_no_private_paths_or_secrets(self) -> None:
        status, payload, headers = self._request("GET", "/health")

        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")
        self.assertTrue(payload["ready"])
        self.assertEqual(payload["agents"], ["echo"])
        self.assertEqual(payload["instance_id"], "live-test-instance")
        self.assertFalse(payload["signed_only"])
        rendered = json.dumps(payload)
        self.assertNotIn(str(self.fixture.root), rendered)
        self.assertNotIn("token", rendered.lower())
        self.assertTrue(headers["content-type"].startswith("application/json"))
        self.assertNotIn("Python", headers.get("server", ""))

    def test_valid_chat_returns_exact_runtime_result(self) -> None:
        status, payload, _ = self._request(
            "POST",
            "/chat",
            json.dumps({"user_input": "hello"}).encode(),
            {"Content-Type": "application/json"},
        )

        self.assertEqual(status, 200)
        self.assertEqual(payload["response"], "ok")
        self.assertEqual(payload["model"], "live-model")
        self.assertNotIn("assistant_response", payload)

    def test_malformed_json_returns_bounded_json_error(self) -> None:
        status, payload, _ = self._request(
            "POST",
            "/chat",
            b"{",
            {"Content-Type": "application/json"},
        )

        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "malformed_json")

    def test_json_content_type_is_required(self) -> None:
        status, payload, _ = self._request(
            "POST",
            "/chat",
            b"{}",
            {"Content-Type": "text/plain"},
        )

        self.assertEqual(status, 415)
        self.assertEqual(payload["error"]["code"], "invalid_content_type")

    def test_untrusted_host_is_rejected(self) -> None:
        connection = self._connection()
        try:
            connection.putrequest("GET", "/health", skip_host=True)
            connection.putheader("Host", "evil.example")
            connection.endheaders()
            response = connection.getresponse()
            payload = json.loads(response.read())
        finally:
            connection.close()

        self.assertEqual(response.status, 403)
        self.assertEqual(payload["error"]["code"], "invalid_host")

    def test_request_larger_than_one_mib_is_rejected_before_read(self) -> None:
        connection = self._connection()
        try:
            connection.putrequest("POST", "/chat")
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", str(MAX_REQUEST_BYTES + 1))
            connection.endheaders()
            response = connection.getresponse()
            payload = json.loads(response.read())
        finally:
            connection.close()

        self.assertEqual(response.status, 413)
        self.assertEqual(payload["error"]["code"], "request_too_large")

    def test_content_length_accepts_only_one_bounded_ascii_decimal(self):
        cases = (
            (("²",), 400, "invalid_content_length"),
            (("9" * 5000,), 413, "request_too_large"),
            (("2", "2"), 400, "invalid_content_length"),
        )
        for values, expected_status, expected_code in cases:
            with self.subTest(values=len(values)):
                connection = self._connection()
                try:
                    connection.putrequest("POST", "/chat")
                    connection.putheader(
                        "Content-Type", "application/json"
                    )
                    for value in values:
                        connection.putheader("Content-Length", value)
                    connection.endheaders()
                    response = connection.getresponse()
                    raw = response.read()
                    payload = json.loads(raw)
                finally:
                    connection.close()
                self.assertEqual(response.status, expected_status)
                self.assertEqual(payload["error"]["code"], expected_code)
                self.assertLess(len(raw), 1024)

    def test_unencodable_runtime_response_becomes_bounded_json_error(self):
        with patch.object(
            self.server.orchestrator,
            "chat",
            return_value={"response": "\ud800"},
        ):
            status, payload, _ = self._request(
                "POST",
                "/chat",
                b'{"user_input":"synthetic"}',
                {"Content-Type": "application/json"},
            )
        self.assertEqual(status, 500)
        self.assertEqual(payload["error"]["code"], "invalid_response")

    def test_wrong_methods_are_json_405(self) -> None:
        for method, path in (("GET", "/chat"), ("POST", "/health"), ("PUT", "/chat")):
            with self.subTest(method=method, path=path):
                status, payload, headers = self._request(method, path)
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")
                self.assertIn("allow", headers)

    def test_unknown_and_unsafe_routes_are_404(self) -> None:
        for method, path in (
            ("GET", "/missing"),
            ("POST", "/api/agent"),
            ("POST", "/eval"),
            ("GET", "/"),
        ):
            with self.subTest(method=method, path=path):
                status, payload, _ = self._request(method, path)
                self.assertEqual(status, 404)
                self.assertEqual(payload["error"]["code"], "not_found")

    def test_responses_never_emit_cors_headers(self) -> None:
        for method, path in (("GET", "/health"), ("GET", "/missing")):
            with self.subTest(path=path):
                _, _, headers = self._request(method, path)
                self.assertFalse(
                    any(name.startswith("access-control-") for name in headers)
                )

    def test_concurrent_chat_requests_are_isolated(self) -> None:
        def send(index: int) -> tuple[int, str]:
            status, payload, _ = self._request(
                "POST",
                "/chat",
                json.dumps({"user_input": f"message-{index}"}).encode(),
                {"Content-Type": "application/json"},
            )
            return status, payload["response"]

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(send, range(16)))

        self.assertEqual(results, [(200, "ok")] * 16)
        self.assertEqual(len(self.provider.requests), 16)

    def test_shutdown_is_graceful_and_idempotent(self) -> None:
        assert self.server is not None
        port = self.server.port
        self.server.shutdown()
        self.assertFalse(self.server.running)
        self.server.shutdown()
        self.server = None

        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=0.2)

    def _connection(self) -> http.client.HTTPConnection:
        assert self.server is not None
        return http.client.HTTPConnection(
            "127.0.0.1",
            self.server.port,
            timeout=3,
        )

    def _request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict, dict[str, str]]:
        connection = self._connection()
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            raw = response.read()
            return (
                response.status,
                json.loads(raw),
                {name.lower(): value for name, value in response.getheaders()},
            )
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
